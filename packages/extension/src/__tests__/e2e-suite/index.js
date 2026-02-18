const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const vscode = require("vscode");

const REQUIRED_COMMANDS = [
	"sage.enableProtection",
	"sage.disableProtection",
	"sage.openConfig",
	"sage.openAuditLog",
	"sage.showHookHealth",
];

const REQUIRED_CURSOR_EVENTS = [
	"beforeShellExecution",
	"preToolUse",
	"beforeMCPExecution",
	"beforeReadFile",
];

const host = readRequiredEnv("SAGE_E2E_HOST");
const extensionId = readRequiredEnv("SAGE_E2E_EXTENSION_ID");
const scopeSettingKey = readRequiredEnv("SAGE_E2E_SCOPE_SETTING_KEY");
const managedMarker = readRequiredEnv("SAGE_E2E_MANAGED_MARKER");
const hookMode = readRequiredEnv("SAGE_E2E_HOOK_MODE");
const hooksRelativePath = readRequiredEnv("SAGE_E2E_HOOKS_RELATIVE_PATH");
const hookRunnerPath = readRequiredEnv("SAGE_E2E_HOOK_RUNNER_PATH");

const workspacePath = getWorkspacePath();
const hookConfigPath = path.join(workspacePath, hooksRelativePath);

async function run() {
	const failures = [];
	try {
		await runCase("configure workspace scope", configureWorkspaceScope, failures);
		await runCase("extension activates", verifyExtensionActivation, failures);
		await runCase("sage commands are registered", verifyCommandsRegistered, failures);
		await runCase("enable protection writes managed hooks", verifyEnableProtection, failures);
		await runCase("hook health command runs without error", verifyHookHealthCommand, failures);
		await runCase("managed hook blocks dangerous write", verifyHookPipelineBlocksThreat, failures);
		await runCase("disable protection removes managed hooks", verifyDisableProtection, failures);
	} finally {
		cleanupWorkspaceArtifacts();
	}

	if (failures.length > 0) {
		throw new Error(
			`Extension host E2E failed (${failures.length} case(s)):\n\n${failures.join("\n\n")}`,
		);
	}
}

module.exports = { run };

async function runCase(name, work, failures) {
	try {
		await work();
		console.log(`[sage-e2e] PASS: ${name}`);
	} catch (error) {
		const details = formatError(error);
		console.error(`[sage-e2e] FAIL: ${name}\n${details}`);
		failures.push(`${name}\n${details}`);
	}
}

async function configureWorkspaceScope() {
	cleanupWorkspaceArtifacts();
	await vscode.workspace
		.getConfiguration()
		.update(scopeSettingKey, "workspace", vscode.ConfigurationTarget.Workspace);
	await vscode.workspace
		.getConfiguration()
		.update("sage.hookRunnerPath", hookRunnerPath, vscode.ConfigurationTarget.Workspace);
}

async function verifyExtensionActivation() {
	const extension = vscode.extensions.getExtension(extensionId);
	assert.ok(extension, `Expected extension "${extensionId}" to be loaded`);
	await extension.activate();
	assert.equal(extension.isActive, true, `Expected extension "${extensionId}" to be active`);
}

async function verifyCommandsRegistered() {
	const commands = await vscode.commands.getCommands(true);
	for (const commandId of REQUIRED_COMMANDS) {
		assert.ok(commands.includes(commandId), `Expected command "${commandId}" to be registered`);
	}
}

async function verifyEnableProtection() {
	await vscode.commands.executeCommand("sage.enableProtection");
	assert.ok(fs.existsSync(hookConfigPath), `Expected hook config at ${hookConfigPath}`);

	const config = readJsonFile(hookConfigPath);
	if (host === "cursor") {
		verifyCursorManagedHooks(config);
	} else {
		verifyVsCodeManagedHooks(config);
	}

	const managedCommands = collectManagedCommands(config);
	assert.ok(managedCommands.length > 0, "Expected at least one managed hook command");
	assert.ok(
		managedCommands.some(
			(command) => command.includes(` ${hookMode} `) || command.endsWith(` ${hookMode}`),
		),
		`Expected managed command to invoke mode "${hookMode}"`,
	);
}

async function verifyHookHealthCommand() {
	await vscode.commands.executeCommand("sage.showHookHealth");
}

async function verifyHookPipelineBlocksThreat() {
	assert.ok(fs.existsSync(hookRunnerPath), `Expected hook runner at ${hookRunnerPath}`);

	const payload =
		hookMode === "cursor"
			? {
					hook_event_name: "preToolUse",
					tool_name: "Write",
					tool_input: {
						file_path: "/home/user/.ssh/authorized_keys",
						content: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ...",
					},
				}
			: {
					tool_name: "Write",
					tool_input: {
						file_path: "/home/user/.ssh/authorized_keys",
						content: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ...",
					},
				};

	const response = runHook(payload);
	if (hookMode === "cursor") {
		assert.equal(response.decision, "deny", "Expected Cursor hook to deny sensitive write");
		return;
	}

	const hookSpecificOutput = asObject(response.hookSpecificOutput);
	const decision = hookSpecificOutput.permissionDecision;
	assert.ok(
		decision === "deny" || decision === "ask",
		`Expected VS Code hook decision deny|ask, got "${String(decision)}"`,
	);
}

async function verifyDisableProtection() {
	await vscode.commands.executeCommand("sage.disableProtection");
	if (!fs.existsSync(hookConfigPath)) {
		return;
	}

	const config = readJsonFile(hookConfigPath);
	const managedCommands = collectManagedCommands(config);
	assert.equal(managedCommands.length, 0, "Expected no managed hook commands after disable");
}

function verifyCursorManagedHooks(config) {
	const hooks = asObject(config.hooks);
	for (const eventName of REQUIRED_CURSOR_EVENTS) {
		const entries = Array.isArray(hooks[eventName]) ? hooks[eventName] : [];
		const hasManagedEntry = entries.some(
			(entry) =>
				entry &&
				typeof entry === "object" &&
				typeof entry.command === "string" &&
				entry.command.includes(managedMarker),
		);
		assert.ok(hasManagedEntry, `Expected managed Cursor hook for event "${eventName}"`);
	}
}

function verifyVsCodeManagedHooks(config) {
	const hooks = asObject(config.hooks);
	const preToolUse = Array.isArray(hooks.PreToolUse) ? hooks.PreToolUse : [];
	assert.ok(preToolUse.length > 0, "Expected PreToolUse entries in VS Code settings hooks");

	const hasManagedCommand = preToolUse.some((matcherEntry) => {
		const hooksArray =
			matcherEntry && typeof matcherEntry === "object" ? matcherEntry.hooks : undefined;
		if (!Array.isArray(hooksArray)) {
			return false;
		}
		return hooksArray.some(
			(hookEntry) =>
				hookEntry &&
				typeof hookEntry === "object" &&
				typeof hookEntry.command === "string" &&
				hookEntry.command.includes(managedMarker),
		);
	});
	assert.ok(hasManagedCommand, "Expected managed command hook in VS Code PreToolUse entries");
}

function collectManagedCommands(config) {
	if (host === "cursor") {
		const hooks = asObject(config.hooks);
		const commands = [];
		for (const entries of Object.values(hooks)) {
			if (!Array.isArray(entries)) {
				continue;
			}
			for (const entry of entries) {
				if (
					entry &&
					typeof entry === "object" &&
					typeof entry.command === "string" &&
					entry.command.includes(managedMarker)
				) {
					commands.push(entry.command);
				}
			}
		}
		return commands;
	}

	const commands = [];
	const hooks = asObject(config.hooks);
	const preToolUse = Array.isArray(hooks.PreToolUse) ? hooks.PreToolUse : [];
	for (const matcherEntry of preToolUse) {
		if (!matcherEntry || typeof matcherEntry !== "object" || !Array.isArray(matcherEntry.hooks)) {
			continue;
		}
		for (const hookEntry of matcherEntry.hooks) {
			if (
				hookEntry &&
				typeof hookEntry === "object" &&
				typeof hookEntry.command === "string" &&
				hookEntry.command.includes(managedMarker)
			) {
				commands.push(hookEntry.command);
			}
		}
	}
	return commands;
}

function runHook(payload) {
	const nodePath = process.env.VSCODE_NODE_EXEC_PATH || process.execPath;
	const stdout = execFileSync(nodePath, [hookRunnerPath, hookMode], {
		encoding: "utf8",
		input: `${JSON.stringify(payload)}`,
		env: {
			...process.env,
			ELECTRON_RUN_AS_NODE: "1",
		},
	});
	if (!stdout.trim()) {
		return {};
	}
	return JSON.parse(stdout.trim());
}

function readJsonFile(filePath) {
	return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function getWorkspacePath() {
	const folder = vscode.workspace.workspaceFolders?.[0];
	assert.ok(folder, "Expected a workspace folder for extension E2E");
	return folder.uri.fsPath;
}

function cleanupWorkspaceArtifacts() {
	for (const relativePath of [".cursor", ".claude", ".vscode"]) {
		fs.rmSync(path.join(workspacePath, relativePath), { recursive: true, force: true });
	}
}

function asObject(value) {
	return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function readRequiredEnv(name) {
	const value = process.env[name]?.trim();
	if (!value) {
		throw new Error(`Missing required env var: ${name}`);
	}
	return value;
}

function formatError(error) {
	if (error instanceof Error) {
		return error.stack || error.message;
	}
	return String(error);
}
