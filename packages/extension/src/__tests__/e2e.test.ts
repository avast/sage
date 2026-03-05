/**
 * Tier 3 E2E tests: Sage extension running inside installed Cursor / VS Code.
 *
 * Excluded from default `pnpm test`. Run with:
 *
 *   pnpm test:e2e:cursor
 *   pnpm test:e2e:vscode
 *
 * Prerequisites:
 * - Installed Cursor / VS Code executable (no auto-download)
 * - packages/extension already built (handled by Vitest global setup)
 */

import { spawnSync } from "node:child_process";
import {
	cpSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { runTests } from "@vscode/test-electron";
import { beforeAll, describe, it } from "vitest";

type HostName = "cursor" | "vscode";
type CaseStatus = "pass" | "fail";
type JsonRecord = Record<string, unknown>;

interface E2ECase {
	id: string;
	title: string;
}

interface HostMetadata {
	label: string;
	extensionId: string;
	scopeSettingKey: string;
	managedMarker: string;
	hookMode: "cursor" | "vscode";
	hooksRelativePath: string;
}

interface HostResolution {
	executablePath?: string;
	reason?: string;
}

interface AgentResolution {
	command?: string;
	reason?: string;
}

interface CaseOutcome {
	id: string;
	name: string;
	status: CaseStatus;
	error?: string;
	durationMs?: number;
}

interface HostRunSummary {
	orderedOutcomes: CaseOutcome[];
	caseOutcomes: Map<string, CaseOutcome>;
	runError?: string;
}

const EXTENSION_ROOT = path.resolve(__dirname, "..", "..");
const WORKSPACE_FOLDER = path.resolve(EXTENSION_ROOT, "test-workspace");
const EXTENSION_TESTS_PATH = path.resolve(__dirname, "e2e-suite", "index.js");
const HOOK_RUNNER_PATH = path.resolve(EXTENSION_ROOT, "dist", "sage-hook.cjs");
const HEADLESS_WORKSPACE = path.resolve(
	EXTENSION_ROOT,
	".e2e-artifacts",
	"cursor-headless-agent-workspace",
);
const HEADLESS_AGENT_MODEL = process.env.SAGE_HEADLESS_AGENT_MODEL?.trim() || "claude-4.5-sonnet";
const E2E_VERBOSE = resolveE2EVerbose();
const E2E_CASES: readonly E2ECase[] = [
	{ id: "configure-workspace-scope", title: "configure workspace scope" },
	{ id: "extension-activates", title: "extension activates" },
	{ id: "commands-registered", title: "sage commands are registered" },
	{ id: "enable-protection-writes-hooks", title: "enable protection writes managed hooks" },
	{ id: "hook-health-command", title: "hook health command runs without error" },
	{ id: "dangerous-write-blocked", title: "managed hook blocks dangerous write" },
	{
		id: "hook-response-shape-consistent",
		title: "hook responses have consistent shape across event types",
	},
	{ id: "disable-protection-removes-hooks", title: "disable protection removes managed hooks" },
];

const HOST_METADATA: Record<HostName, HostMetadata> = {
	cursor: {
		label: "Cursor",
		extensionId: "Gen.sage-cursor",
		scopeSettingKey: "sage.cursor.scope",
		managedMarker: "--managed-by sage-cursor",
		hookMode: "cursor",
		hooksRelativePath: ".cursor/hooks.json",
	},
	vscode: {
		label: "VS Code",
		extensionId: "Gen.sage-vscode",
		scopeSettingKey: "sage.vscode.scope",
		managedMarker: "--managed-by sage-vscode",
		hookMode: "vscode",
		hooksRelativePath: ".claude/settings.json",
	},
};

const requestedHost = resolveRequestedHost();
const hostsToRun: HostName[] = requestedHost ? [requestedHost] : ["cursor", "vscode"];
const cursorAgentResolution = resolveCursorHeadlessE2E();
if (!cursorAgentResolution.command) {
	console.warn(`Cursor headless agent E2E skipped: ${cursorAgentResolution.reason}`);
}

for (const host of hostsToRun) {
	const metadata = HOST_METADATA[host];
	const resolved = resolveHostExecutable(host);
	const canRun = Boolean(resolved.executablePath);

	if (!canRun) {
		console.warn(`${metadata.label} E2E skipped: ${resolved.reason}`);
	}
	const describeHost = canRun ? describe : describe.skip;

	describeHost(`E2E: Sage extension in ${metadata.label}`, { timeout: 240_000 }, () => {
		let hostRunPromise: Promise<HostRunSummary> | undefined;

		beforeAll(() => {
			if (resolved.executablePath) {
				hostRunPromise = runHostE2E(host, resolved.executablePath);
			}
		});

		for (const testCase of E2E_CASES) {
			it(testCase.title, async () => {
				if (!hostRunPromise) {
					return;
				}

				const summary = await hostRunPromise;
				if (summary.runError && !hasFailedOutcomes(summary)) {
					throw new Error(
						`Extension host run failed before reporting case outcomes:\n${summary.runError}`,
					);
				}

				const outcome = summary.caseOutcomes.get(testCase.id);
				if (!outcome) {
					throw new Error(buildMissingOutcomeMessage(testCase, summary));
				}
				if (outcome.status === "fail") {
					throw new Error(
						outcome.error ? `${outcome.name}\n${outcome.error}` : `${outcome.name} failed`,
					);
				}
			});
		}
	});
}

const describeCursorHeadless = cursorAgentResolution.command ? describe : describe.skip;

describeCursorHeadless("E2E: Cursor headless agent + Sage hooks", { timeout: 240_000 }, () => {
	it("denies write tool call and keeps file absent", () => {
		const agentCommand = cursorAgentResolution.command;
		if (!agentCommand) {
			return;
		}

		const workspace = createFreshHeadlessWorkspace();
		const fixture = createHeadlessSageFixture(workspace);
		const blockedPath = fixture.blockedPath;
		const streamPath = path.join(workspace, "headless-agent-stream.log");
		const auditPath = path.join(workspace, ".sage", "audit.jsonl");

		rmSync(blockedPath, { force: true });
		writeCursorProjectHooks(workspace, fixture);

		const prompt = [
			`This is a safe automated test in a temporary workspace.`,
			`Use the Write tool exactly once.`,
			`Create the file at path "${blockedPath}".`,
			`Write the exact content: "sage-cursor-e2e-write-attempt".`,
			`Do not use shell commands.`,
		].join(" ");

		const run = runCommandWithWindowsFallback(
			agentCommand,
			["-p", "--force", "--model", HEADLESS_AGENT_MODEL, "--output-format", "stream-json", prompt],
			{
				cwd: workspace,
				timeout: 180_000,
				env: {
					...process.env,
					HOME: workspace,
					USERPROFILE: workspace,
				},
			},
		);

		const stdout = run.stdout ?? "";
		const stderr = run.stderr ?? "";
		const stream = `${stdout}\n${stderr}`;
		try {
			writeFileSync(streamPath, stream, "utf8");
		} catch {
			// Best-effort debug artifact.
		}

		if (run.error) {
			throw new Error(
				`Headless agent execution failed: ${formatError(run.error)}\nworkspace: ${workspace}\nstream log: ${streamPath}`,
			);
		}

		if (run.status !== 0) {
			throw new Error(
				`Headless agent exited with code ${String(run.status)}\nworkspace: ${workspace}\nstream log: ${streamPath}`,
			);
		}

		if (!hasWriteOrEditToolCall(stream)) {
			throw new Error(
				`Headless agent did not attempt a Write/Edit tool call.\nworkspace: ${workspace}\nstream log: ${streamPath}`,
			);
		}

		if (!hasSageDeniedTargetInAudit(auditPath, blockedPath)) {
			throw new Error(
				`Sage deny verdict for headless target was not found in audit log.\nworkspace: ${workspace}\nstream log: ${streamPath}\naudit log: ${auditPath}`,
			);
		}

		if (existsSync(blockedPath)) {
			throw new Error(
				`Denied write target exists after run: ${blockedPath}\nworkspace: ${workspace}\nstream log: ${streamPath}\naudit log: ${auditPath}`,
			);
		}
	});
});

async function runHostE2E(host: HostName, executablePath: string): Promise<HostRunSummary> {
	const metadata = HOST_METADATA[host];
	const tempHome = mkdtempSync(path.join(tmpdir(), `sage-${host}-home-`));
	const resultsFilePath = path.join(tempHome, "sage-e2e-results.json");
	let extensionDevelopmentPath = EXTENSION_ROOT;
	let stagedVsCodeExtensionPath: string | undefined;
	let runError: unknown;

	try {
		if (host === "vscode") {
			stagedVsCodeExtensionPath = createVsCodeExtensionDevelopmentPath();
			extensionDevelopmentPath = stagedVsCodeExtensionPath;
		}

		try {
			await runTests({
				vscodeExecutablePath: executablePath,
				extensionDevelopmentPath,
				extensionTestsPath: EXTENSION_TESTS_PATH,
				launchArgs: buildLaunchArgs(),
				extensionTestsEnv: {
					SAGE_E2E_HOST: host,
					SAGE_E2E_EXTENSION_ID: metadata.extensionId,
					SAGE_E2E_SCOPE_SETTING_KEY: metadata.scopeSettingKey,
					SAGE_E2E_MANAGED_MARKER: metadata.managedMarker,
					SAGE_E2E_HOOK_MODE: metadata.hookMode,
					SAGE_E2E_HOOKS_RELATIVE_PATH: metadata.hooksRelativePath,
					SAGE_E2E_HOOK_RUNNER_PATH: HOOK_RUNNER_PATH,
					SAGE_E2E_RESULTS_FILE: resultsFilePath,
					SAGE_E2E_VERBOSE: E2E_VERBOSE ? "1" : "0",
					HOME: tempHome,
					USERPROFILE: tempHome,
					XDG_CONFIG_HOME: path.join(tempHome, ".config"),
					VSCODE_LOG_LEVEL: E2E_VERBOSE ? "info" : "error",
				},
			});
		} catch (error) {
			runError = error;
		}

		const orderedOutcomes = readCaseOutcomes(resultsFilePath);
		return {
			orderedOutcomes,
			caseOutcomes: new Map(orderedOutcomes.map((outcome) => [outcome.id, outcome])),
			runError: runError ? formatError(runError) : undefined,
		};
	} finally {
		rmSync(tempHome, { recursive: true, force: true });
		if (stagedVsCodeExtensionPath) {
			rmSync(stagedVsCodeExtensionPath, { recursive: true, force: true });
		}
	}
}

function buildLaunchArgs(): string[] {
	const launchArgs = [
		WORKSPACE_FOLDER,
		"--disable-extensions",
		"--disable-workspace-trust",
		"--skip-welcome",
		"--skip-release-notes",
	];

	if (!E2E_VERBOSE) {
		launchArgs.push("--log", "off");
	}
	if (process.platform === "darwin") {
		launchArgs.push("--use-mock-keychain");
	}
	return launchArgs;
}

function hasFailedOutcomes(summary: HostRunSummary): boolean {
	return summary.orderedOutcomes.some((outcome) => outcome.status === "fail");
}

function buildMissingOutcomeMessage(testCase: E2ECase, summary: HostRunSummary): string {
	const recorded =
		summary.orderedOutcomes.length > 0
			? summary.orderedOutcomes.map((outcome) => `- ${outcome.id} (${outcome.status})`).join("\n")
			: "No cases were recorded.";
	const runErrorSection = summary.runError ? `\n\nExtension host error:\n${summary.runError}` : "";
	return `Missing result for case "${testCase.title}" (${testCase.id}).\n\nRecorded outcomes:\n${recorded}${runErrorSection}`;
}

function readCaseOutcomes(filePath: string): CaseOutcome[] {
	if (!existsSync(filePath)) {
		return [];
	}

	let parsed: unknown;
	try {
		parsed = JSON.parse(readFileSync(filePath, "utf8"));
	} catch {
		return [];
	}

	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
		return [];
	}
	const rawCases = (parsed as { cases?: unknown }).cases;
	if (!Array.isArray(rawCases)) {
		return [];
	}

	const outcomes: CaseOutcome[] = [];
	for (const rawCase of rawCases) {
		const outcome = parseCaseOutcome(rawCase);
		if (outcome) {
			outcomes.push(outcome);
		}
	}
	return outcomes;
}

function parseCaseOutcome(value: unknown): CaseOutcome | undefined {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		return undefined;
	}

	const record = value as Record<string, unknown>;
	const id = typeof record.id === "string" ? record.id : undefined;
	const name = typeof record.name === "string" ? record.name : undefined;
	const status =
		record.status === "pass" || record.status === "fail"
			? (record.status as CaseStatus)
			: undefined;
	if (!id || !name || !status) {
		return undefined;
	}

	const error = typeof record.error === "string" ? record.error : undefined;
	const durationMs = typeof record.durationMs === "number" ? record.durationMs : undefined;
	return { id, name, status, error, durationMs };
}

function resolveE2EVerbose(): boolean {
	const envValue = process.env.SAGE_E2E_VERBOSE?.trim().toLowerCase();
	if (envValue === "1" || envValue === "true" || envValue === "yes" || envValue === "on") {
		return true;
	}
	if (envValue === "0" || envValue === "false" || envValue === "no" || envValue === "off") {
		return false;
	}

	for (let i = 0; i < process.argv.length; i += 1) {
		const arg = process.argv[i];
		if (arg === "--reporter" && process.argv[i + 1] === "verbose") {
			return true;
		}
		if (
			typeof arg === "string" &&
			arg.startsWith("--reporter=") &&
			arg.slice("--reporter=".length) === "verbose"
		) {
			return true;
		}
	}

	return false;
}

function formatError(error: unknown): string {
	if (error instanceof Error) {
		return error.stack || error.message;
	}
	return String(error);
}

function resolveRequestedHost(): HostName | undefined {
	const envHost = parseHostName(process.env.SAGE_E2E_HOST ?? process.env.SAGE_E2E_TARGET);
	if (envHost) {
		return envHost;
	}

	const lifecycleEvent = process.env.npm_lifecycle_event?.toLowerCase();
	if (lifecycleEvent?.endsWith(":cursor")) {
		return "cursor";
	}
	if (lifecycleEvent?.endsWith(":vscode")) {
		return "vscode";
	}

	const hostArg = readFlagValue("--host");
	if (hostArg) {
		const parsed = parseHostName(hostArg);
		if (!parsed) {
			throw new Error(`Unsupported --host value: "${hostArg}". Expected "cursor" or "vscode".`);
		}
		return parsed;
	}

	return undefined;
}

function readFlagValue(flag: string): string | undefined {
	const index = process.argv.indexOf(flag);
	if (index < 0) {
		return undefined;
	}
	const value = process.argv[index + 1];
	return value?.trim() || undefined;
}

function parseHostName(value: string | undefined): HostName | undefined {
	const normalized = value?.trim().toLowerCase();
	if (normalized === "cursor" || normalized === "vscode") {
		return normalized;
	}
	return undefined;
}

function resolveCursorHeadlessE2E(): AgentResolution {
	if (requestedHost === "vscode") {
		return { reason: "vscode-only run selected" };
	}

	const envCandidates = readEnvCandidates(["SAGE_AGENT_PATH"]);
	const candidates = dedupe([...envCandidates, "agent"]);
	for (const candidate of candidates) {
		if (canExecute(candidate)) {
			const auth = checkAgentAuth(candidate);
			if (auth.ok) {
				return { command: candidate };
			}
			return { reason: auth.reason };
		}
	}

	return {
		reason:
			envCandidates.length > 0
				? `configured agent command is not runnable: ${envCandidates.join(", ")}`
				: "agent CLI not found in PATH (install Cursor headless CLI or set SAGE_AGENT_PATH)",
	};
}

function checkAgentAuth(agentCommand: string): { ok: boolean; reason?: string } {
	const status = runCommandWithWindowsFallback(agentCommand, ["status"], {
		timeout: 20_000,
	});
	if (status.error) {
		return { ok: false, reason: `failed to check agent auth: ${String(status.error)}` };
	}

	const output = `${status.stdout ?? ""}\n${status.stderr ?? ""}`.toLowerCase();
	if (
		output.includes("not authenticated") ||
		output.includes("login required") ||
		output.includes("agent login")
	) {
		return {
			ok: false,
			reason: "agent authentication missing (run `agent login` or set CURSOR_API_KEY)",
		};
	}

	if (status.status !== 0) {
		return {
			ok: false,
			reason: `agent status failed with exit code ${String(status.status)}`,
		};
	}

	return { ok: true };
}

function runCommandWithWindowsFallback(
	command: string,
	args: string[],
	options: { cwd?: string; timeout: number; env?: NodeJS.ProcessEnv },
): ReturnType<typeof spawnSync> {
	const direct = spawnSync(command, args, {
		cwd: options.cwd,
		encoding: "utf8",
		env: options.env,
		timeout: options.timeout,
		windowsHide: true,
	});

	if (!direct.error || process.platform !== "win32") {
		return direct;
	}

	const cmdInvocation = buildCmdInvocation(command, args);
	return spawnSync("cmd.exe", ["/d", "/s", "/c", cmdInvocation], {
		cwd: options.cwd,
		encoding: "utf8",
		env: options.env,
		timeout: options.timeout,
		windowsHide: true,
	});
}

function buildCmdInvocation(command: string, args: string[]): string {
	const cmd = quoteForCmd(command);
	const argv = args.map((arg) => quoteForCmd(arg)).join(" ");
	return argv ? `${cmd} ${argv}` : cmd;
}

function quoteForCmd(value: string): string {
	if (!value.includes(" ") && !value.includes('"') && !value.includes("\t")) {
		return value;
	}
	return `"${value.replace(/"/g, '""')}"`;
}

function createHeadlessSageFixture(workspace: string): {
	blockedPath: string;
	runnerPath: string;
} {
	const fixtureRoot = path.join(workspace, ".sage-headless-fixture");
	const resourcesDir = path.join(fixtureRoot, "resources");
	const threatsDir = path.join(resourcesDir, "threats");
	const blockedPath = path.join(workspace, "tmp", "sage-headless-deny-target.txt");
	const runnerPath = path.join(fixtureRoot, "dist", "sage-hook.cjs");

	mkdirSync(path.dirname(runnerPath), { recursive: true });
	cpSync(path.join(EXTENSION_ROOT, "resources"), resourcesDir, { recursive: true, force: true });
	cpSync(HOOK_RUNNER_PATH, runnerPath, { force: true });
	const runnerSourceMap = `${HOOK_RUNNER_PATH}.map`;
	if (existsSync(runnerSourceMap)) {
		cpSync(runnerSourceMap, `${runnerPath}.map`, { force: true });
	}

	const threatYaml = `- id: "SAGE-HEADLESS-E2E-001"
  category: files
  severity: critical
  confidence: 1.0
  action: block
  pattern: "sage-headless-deny-target\\\\.txt$"
  match_on: file_path
  title: "Block headless E2E deny target"
  expires_at: null
  revoked: false
`;
	writeFileSync(path.join(threatsDir, "headless-e2e.yaml"), threatYaml, "utf8");

	return { blockedPath, runnerPath };
}

function writeCursorProjectHooks(workspace: string, fixture: { runnerPath: string }): void {
	const hooksDir = path.join(workspace, ".cursor");
	mkdirSync(hooksDir, { recursive: true });

	const hookCommand = createHookCommand(fixture);
	const hooks = {
		version: 1,
		hooks: {
			preToolUse: [
				{
					matcher: "Write|Edit|Delete",
					command: hookCommand,
					timeout: 30,
				},
			],
		},
	};

	writeFileSync(path.join(hooksDir, "hooks.json"), `${JSON.stringify(hooks, null, 2)}\n`, "utf8");
}

function createHookCommand(fixture: { runnerPath: string }): string {
	return `node "${fixture.runnerPath}" cursor`;
}

function createFreshHeadlessWorkspace(): string {
	rmSync(HEADLESS_WORKSPACE, { recursive: true, force: true });
	mkdirSync(HEADLESS_WORKSPACE, { recursive: true });
	return HEADLESS_WORKSPACE;
}

function hasWriteOrEditToolCall(output: string): boolean {
	if (/writeToolCall|editToolCall/.test(output)) {
		return true;
	}

	for (const line of output.split(/\r?\n/)) {
		const trimmed = line.trim();
		if (!trimmed) {
			continue;
		}
		try {
			const parsed = JSON.parse(trimmed) as Record<string, unknown>;
			if (parsed.type !== "tool_call") {
				continue;
			}
			const toolCall = parsed.tool_call as Record<string, unknown> | undefined;
			if (toolCall && ("writeToolCall" in toolCall || "editToolCall" in toolCall)) {
				return true;
			}
		} catch {
			// Ignore non-JSON stream lines.
		}
	}
	return false;
}

function readTextIfExists(filePath: string): string {
	if (!existsSync(filePath)) {
		return "(file missing)";
	}
	try {
		return readFileSync(filePath, "utf8");
	} catch (error) {
		return `(failed to read file: ${formatError(error)})`;
	}
}

function hasSageDeniedTargetInAudit(auditPath: string, blockedPath: string): boolean {
	if (!existsSync(auditPath)) {
		return false;
	}

	const targetName = path.basename(blockedPath).toLowerCase();
	const lines = readTextIfExists(auditPath).split(/\r?\n/);
	for (const line of lines) {
		const trimmed = line.trim();
		if (!trimmed) {
			continue;
		}
		try {
			const entry = JSON.parse(trimmed) as JsonRecord;
			const type = typeof entry.type === "string" ? entry.type : undefined;
			const verdict = typeof entry.verdict === "string" ? entry.verdict : undefined;
			const toolName = typeof entry.tool_name === "string" ? entry.tool_name : undefined;
			const summary =
				typeof entry.tool_input_summary === "string"
					? entry.tool_input_summary.toLowerCase()
					: undefined;
			if (
				type === "runtime_verdict" &&
				verdict === "deny" &&
				(toolName === "Write" || toolName === "Edit") &&
				summary?.includes(targetName)
			) {
				return true;
			}
		} catch {
			// Ignore malformed lines.
		}
	}
	return false;
}

function resolveHostExecutable(host: HostName): HostResolution {
	const envCandidates =
		host === "cursor"
			? readEnvCandidates(["SAGE_CURSOR_PATH"])
			: readEnvCandidates(["SAGE_VSCODE_PATH", "VSCODE_EXECUTABLE_PATH"]);
	const candidates = [...envCandidates, ...defaultExecutableCandidates(host)];

	for (const rawCandidate of dedupe(candidates)) {
		const candidate = normalizeExecutableCandidate(host, rawCandidate);
		if (!candidate) {
			continue;
		}
		if (isPathLike(candidate) && existsSync(candidate)) {
			return { executablePath: candidate };
		}
		if (canExecute(candidate)) {
			return { executablePath: candidate };
		}
	}

	const reason =
		envCandidates.length > 0
			? `none of the configured executables were runnable: ${envCandidates.join(", ")}`
			: "no runnable executable found in PATH or common install locations";
	return { reason };
}

function readEnvCandidates(names: string[]): string[] {
	const values: string[] = [];
	for (const name of names) {
		const value = process.env[name]?.trim();
		if (value) {
			values.push(value);
		}
	}
	return values;
}

function defaultExecutableCandidates(host: HostName): string[] {
	const candidates: string[] = [];
	if (host === "cursor") {
		if (process.platform === "win32") {
			pushIfDefined(
				candidates,
				process.env.LOCALAPPDATA &&
					path.join(process.env.LOCALAPPDATA, "Programs", "Cursor", "Cursor.exe"),
			);
			pushIfDefined(
				candidates,
				process.env.ProgramFiles && path.join(process.env.ProgramFiles, "Cursor", "Cursor.exe"),
			);
			candidates.push(
				...resolveWindowsWhereCandidates(["cursor"]).filter((candidate) =>
					isWindowsExecutablePath(candidate),
				),
			);
		}
		if (process.platform === "darwin") {
			candidates.push("/Applications/Cursor.app/Contents/MacOS/Cursor");
		}
		if (process.platform === "linux") {
			candidates.push("/usr/bin/cursor", "/usr/local/bin/cursor", "cursor");
		}
		return candidates;
	}

	if (process.platform === "win32") {
		pushIfDefined(
			candidates,
			process.env.LOCALAPPDATA &&
				path.join(process.env.LOCALAPPDATA, "Programs", "Microsoft VS Code", "Code.exe"),
		);
		pushIfDefined(
			candidates,
			process.env.LOCALAPPDATA &&
				path.join(
					process.env.LOCALAPPDATA,
					"Programs",
					"Microsoft VS Code Insiders",
					"Code - Insiders.exe",
				),
		);
		pushIfDefined(
			candidates,
			process.env.ProgramFiles &&
				path.join(process.env.ProgramFiles, "Microsoft VS Code", "Code.exe"),
		);
		pushIfDefined(
			candidates,
			process.env["ProgramFiles(x86)"] &&
				path.join(process.env["ProgramFiles(x86)"], "Microsoft VS Code", "Code.exe"),
		);
		candidates.push(...resolveWindowsVsCodeExecutablesFromWhere());
	}
	if (process.platform === "darwin") {
		candidates.push(
			"/Applications/Visual Studio Code.app/Contents/MacOS/Electron",
			"/Applications/Visual Studio Code - Insiders.app/Contents/MacOS/Electron",
		);
	}
	if (process.platform === "linux") {
		candidates.push(
			"/usr/bin/code",
			"/usr/local/bin/code",
			"/snap/bin/code",
			"code",
			"code-insiders",
		);
	}
	return candidates;
}

function canExecute(executablePath: string): boolean {
	const baseOptions = {
		encoding: "utf8",
		timeout: 20_000,
		windowsHide: true,
	} as const;
	const direct = spawnSync(executablePath, ["--version"], baseOptions);
	if (!direct.error && direct.status === 0) {
		return true;
	}

	if (process.platform !== "win32") {
		return false;
	}

	const command =
		executablePath.includes("\\") || executablePath.includes("/") || executablePath.includes(" ")
			? `"${executablePath.replace(/"/g, '""')}" --version`
			: `${executablePath} --version`;
	const viaCmd = spawnSync("cmd.exe", ["/d", "/s", "/c", command], baseOptions);
	return !viaCmd.error && viaCmd.status === 0;
}

function normalizeExecutableCandidate(host: HostName, candidate: string): string | undefined {
	const value = candidate.trim();
	if (!value) {
		return undefined;
	}
	if (host !== "vscode" || process.platform !== "win32") {
		return value;
	}

	const normalized = value.toLowerCase();
	if (normalized.endsWith("\\bin\\code") || normalized.endsWith("\\bin\\code.cmd")) {
		return path.resolve(value, "..", "..", "Code.exe");
	}
	if (
		normalized.endsWith("\\bin\\code-insiders") ||
		normalized.endsWith("\\bin\\code-insiders.cmd")
	) {
		return path.resolve(value, "..", "..", "Code - Insiders.exe");
	}
	return value;
}

function isPathLike(value: string): boolean {
	return value.includes("\\") || value.includes("/") || path.isAbsolute(value);
}

function resolveWindowsWhereCandidates(commands: string[]): string[] {
	if (process.platform !== "win32") {
		return [];
	}
	const discovered: string[] = [];
	for (const command of commands) {
		const result = spawnSync("where.exe", [command], {
			encoding: "utf8",
			timeout: 10_000,
			windowsHide: true,
		});
		if (result.error || result.status !== 0 || !result.stdout) {
			continue;
		}
		for (const line of result.stdout.split(/\r?\n/)) {
			const candidate = line.trim();
			if (candidate) {
				discovered.push(candidate);
			}
		}
	}
	return discovered;
}

function resolveWindowsVsCodeExecutablesFromWhere(): string[] {
	if (process.platform !== "win32") {
		return [];
	}
	const paths: string[] = [];
	for (const candidate of resolveWindowsWhereCandidates(["code", "code-insiders"])) {
		const normalized = candidate.toLowerCase();
		if (normalized.endsWith("\\code.exe") || normalized.endsWith("\\code - insiders.exe")) {
			paths.push(candidate);
			continue;
		}
		if (normalized.endsWith("\\bin\\code") || normalized.endsWith("\\bin\\code.cmd")) {
			paths.push(path.resolve(candidate, "..", "..", "Code.exe"));
			continue;
		}
		if (
			normalized.endsWith("\\bin\\code-insiders") ||
			normalized.endsWith("\\bin\\code-insiders.cmd")
		) {
			paths.push(path.resolve(candidate, "..", "..", "Code - Insiders.exe"));
		}
	}
	return paths.filter((candidate) => isWindowsExecutablePath(candidate));
}

function isWindowsExecutablePath(candidate: string): boolean {
	return candidate.toLowerCase().endsWith(".exe");
}

function pushIfDefined(values: string[], value: string | undefined): void {
	if (value) {
		values.push(value);
	}
}

function dedupe(values: string[]): string[] {
	return [...new Set(values)];
}

function createVsCodeExtensionDevelopmentPath(): string {
	const stageDir = mkdtempSync(path.join(tmpdir(), "sage-vscode-e2e-"));
	const baseManifest = readManifest(path.join(EXTENSION_ROOT, "package.json"));
	const vscodeManifest = buildVsCodeManifest(baseManifest);

	cpSync(path.join(EXTENSION_ROOT, "dist"), path.join(stageDir, "dist"), {
		recursive: true,
		force: true,
	});
	cpSync(path.join(EXTENSION_ROOT, "resources"), path.join(stageDir, "resources"), {
		recursive: true,
		force: true,
	});
	cpSync(path.join(EXTENSION_ROOT, "README.md"), path.join(stageDir, "README.md"), { force: true });
	cpSync(path.join(EXTENSION_ROOT, "LICENSE"), path.join(stageDir, "LICENSE"), { force: true });
	writeFileSync(
		path.join(stageDir, "package.json"),
		`${JSON.stringify(vscodeManifest, null, 2)}\n`,
		"utf8",
	);

	return stageDir;
}

function readManifest(filePath: string): Record<string, unknown> {
	return JSON.parse(readFileSync(filePath, "utf8")) as Record<string, unknown>;
}

function buildVsCodeManifest(baseManifest: Record<string, unknown>): Record<string, unknown> {
	const baseContributes = asObject(baseManifest.contributes);
	return {
		...baseManifest,
		name: "sage-vscode",
		displayName: "Sage for VS Code",
		description: "Safety for Agents — ADR layer for VS Code Claude hooks",
		main: "./dist/vscode_extension.js",
		files: [
			"dist/vscode_extension.js",
			"dist/vscode_extension.js.map",
			"dist/sage-hook.cjs",
			"dist/sage-hook.cjs.map",
			"resources/**",
			"package.json",
			"README.md",
			"LICENSE",
		],
		contributes: {
			...baseContributes,
			configuration: {
				title: "Sage",
				properties: {
					"sage.vscode.scope": {
						type: "string",
						default: "user",
						enum: ["workspace", "user"],
						description: "Where Sage installs Claude Code hooks.",
					},
					"sage.hookRunnerPath": {
						type: "string",
						scope: "application",
						default: "",
						description: "Optional absolute path to a sage-hook runner script.",
					},
				},
			},
		},
	};
}

function asObject(value: unknown): Record<string, unknown> {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		return {};
	}
	return value as Record<string, unknown>;
}
