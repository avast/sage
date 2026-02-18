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
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { runTests } from "@vscode/test-electron";
import { describe, it } from "vitest";

type HostName = "cursor" | "vscode";

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

const EXTENSION_ROOT = path.resolve(__dirname, "..", "..");
const WORKSPACE_FOLDER = path.resolve(EXTENSION_ROOT, "test-workspace");
const EXTENSION_TESTS_PATH = path.resolve(__dirname, "e2e-suite", "index.js");
const HOOK_RUNNER_PATH = path.resolve(EXTENSION_ROOT, "dist", "sage-hook.cjs");

const HOST_METADATA: Record<HostName, HostMetadata> = {
	cursor: {
		label: "Cursor",
		extensionId: "gen-digital.sage-cursor-extension",
		scopeSettingKey: "sage.cursor.scope",
		managedMarker: "--managed-by sage-cursor-extension",
		hookMode: "cursor",
		hooksRelativePath: ".cursor/hooks.json",
	},
	vscode: {
		label: "VS Code",
		extensionId: "gen-digital.sage-vscode-extension",
		scopeSettingKey: "sage.vscode.scope",
		managedMarker: "--managed-by sage-vscode-extension",
		hookMode: "vscode",
		hooksRelativePath: ".claude/settings.json",
	},
};

const requestedHost = resolveRequestedHost();
const hostsToRun: HostName[] = requestedHost ? [requestedHost] : ["cursor", "vscode"];

for (const host of hostsToRun) {
	const metadata = HOST_METADATA[host];
	const resolved = resolveHostExecutable(host);
	const canRun = Boolean(resolved.executablePath);

	if (!canRun) {
		console.warn(`${metadata.label} E2E skipped: ${resolved.reason}`);
	}
	const describeHost = canRun ? describe : describe.skip;

	describeHost(`E2E: Sage extension in ${metadata.label}`, { timeout: 240_000 }, () => {
		it("activates and validates managed hook pipeline", async () => {
			if (!resolved.executablePath) {
				return;
			}
			await runHostE2E(host, resolved.executablePath);
		});
	});
}

async function runHostE2E(host: HostName, executablePath: string): Promise<void> {
	const metadata = HOST_METADATA[host];
	const tempHome = mkdtempSync(path.join(tmpdir(), `sage-${host}-home-`));
	let extensionDevelopmentPath = EXTENSION_ROOT;
	let stagedVsCodeExtensionPath: string | undefined;

	try {
		if (host === "vscode") {
			stagedVsCodeExtensionPath = createVsCodeExtensionDevelopmentPath();
			extensionDevelopmentPath = stagedVsCodeExtensionPath;
		}

		await runTests({
			vscodeExecutablePath: executablePath,
			extensionDevelopmentPath,
			extensionTestsPath: EXTENSION_TESTS_PATH,
			launchArgs: [WORKSPACE_FOLDER, "--disable-extensions"],
			extensionTestsEnv: {
				SAGE_E2E_HOST: host,
				SAGE_E2E_EXTENSION_ID: metadata.extensionId,
				SAGE_E2E_SCOPE_SETTING_KEY: metadata.scopeSettingKey,
				SAGE_E2E_MANAGED_MARKER: metadata.managedMarker,
				SAGE_E2E_HOOK_MODE: metadata.hookMode,
				SAGE_E2E_HOOKS_RELATIVE_PATH: metadata.hooksRelativePath,
				SAGE_E2E_HOOK_RUNNER_PATH: HOOK_RUNNER_PATH,
				HOME: tempHome,
				USERPROFILE: tempHome,
			},
		});
	} finally {
		rmSync(tempHome, { recursive: true, force: true });
		if (stagedVsCodeExtensionPath) {
			rmSync(stagedVsCodeExtensionPath, { recursive: true, force: true });
		}
	}
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
	const stageDir = mkdtempSync(path.join(tmpdir(), "sage-vscode-extension-e2e-"));
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
		name: "sage-vscode-extension",
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
