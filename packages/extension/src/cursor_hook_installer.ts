import { access, chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import * as vscode from "vscode";

import type {
	ManagedHookHealth,
	ManagedHookInstallOptions,
	ManagedHookScope,
} from "./managedHooks.js";

const MANAGED_MARKER = "--managed-by sage-cursor";

type HookEntry = Record<string, unknown> & { command?: string };
type HookMap = Record<string, HookEntry[]>;

interface CursorHooksFile {
	version: number;
	hooks: HookMap;
}

export async function installManagedHooks(
	options: ManagedHookInstallOptions,
): Promise<ManagedHookHealth> {
	const configPath = await resolveHooksPath(options.scope);
	await mkdir(path.dirname(configPath), { recursive: true });

	const runnerPath = await resolveRunnerPath(options.context);
	const nodePath = resolveNodeRuntimePath();
	const command = await buildHookCommand(configPath, nodePath, runnerPath);

	const hooksFile = await readHooksFile(configPath);
	const updated = upsertManagedHooks(hooksFile, command);
	await writeHooksFile(configPath, updated);

	const installedEvents = Object.keys(updated.hooks).filter((name) =>
		(updated.hooks[name] ?? []).some((entry) => isManagedEntry(entry)),
	);

	return {
		configPath,
		runnerPath,
		installedEvents,
		managedCommands: collectManagedCommands(updated.hooks),
	};
}

export async function removeManagedHooks(scope: ManagedHookScope): Promise<string> {
	const configPath = await resolveHooksPath(scope);
	const hooksFile = await readHooksFile(configPath);
	const updated = removeManagedEntries(hooksFile);
	await writeHooksFile(configPath, updated);
	return configPath;
}

export async function getHookHealth(
	options: ManagedHookInstallOptions,
): Promise<ManagedHookHealth> {
	const configPath = await resolveHooksPath(options.scope);
	const hooksFile = await readHooksFile(configPath);
	const runnerPath = await resolveRunnerPath(options.context).catch(() => undefined);

	const installedEvents = Object.keys(hooksFile.hooks).filter((eventName) =>
		(hooksFile.hooks[eventName] ?? []).some((entry) => isManagedEntry(entry)),
	);

	return {
		configPath,
		runnerPath,
		installedEvents,
		managedCommands: collectManagedCommands(hooksFile.hooks),
	};
}

async function resolveHooksPath(scope: ManagedHookScope): Promise<string> {
	if (scope === "user") {
		return path.join(os.homedir(), ".cursor", "hooks.json");
	}

	const workspace = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
	if (!workspace) {
		throw new Error("Open a workspace folder to install workspace hooks.");
	}
	return path.join(workspace, ".cursor", "hooks.json");
}

async function resolveRunnerPath(context: vscode.ExtensionContext): Promise<string> {
	const configured =
		vscode.workspace.getConfiguration().get<string>("sage.hookRunnerPath")?.trim() ?? "";
	if (configured) {
		await access(configured);
		return configured;
	}

	const candidates = [
		context.asAbsolutePath(path.join("dist", "sage-hook.cjs")),
		context.asAbsolutePath(path.join("resources", "sage-hook.cjs")),
	];

	for (const candidate of candidates) {
		try {
			await access(candidate);
			return candidate;
		} catch {
			// Try next candidate.
		}
	}

	throw new Error(
		"Unable to locate sage-hook runner. Build packages/extension or set sage.hookRunnerPath.",
	);
}

function resolveNodeRuntimePath(): string {
	const vscodeNode = process.env.VSCODE_NODE_EXEC_PATH?.trim();
	if (vscodeNode) {
		return vscodeNode;
	}
	return process.execPath;
}

async function buildHookCommand(
	configPath: string,
	nodePath: string,
	runnerPath: string,
): Promise<string> {
	const cursorConfigDir = path.dirname(configPath);
	const shimPath = await createHookShim(cursorConfigDir, nodePath, runnerPath);
	if (process.platform === "win32") {
		// Cursor evaluates hook commands in PowerShell pipelines on Windows.
		// A quoted script path must be invoked with `&` to avoid parser errors.
		return `& ${quote(shimPath)} cursor ${MANAGED_MARKER}`;
	}
	return `${quote(shimPath)} cursor ${MANAGED_MARKER}`;
}

async function createHookShim(
	cursorConfigDir: string,
	nodePath: string,
	runnerPath: string,
): Promise<string> {
	const hooksDir = path.join(cursorConfigDir, "hooks");
	const posixShim = path.join(hooksDir, "sage-hook");
	const windowsShim = path.join(hooksDir, "sage-hook.cmd");

	await mkdir(hooksDir, { recursive: true });
	await writeFile(
		posixShim,
		`#!/usr/bin/env sh\nexport ELECTRON_RUN_AS_NODE=1\n"${nodePath}" "${runnerPath}" "$@"\n`,
		"utf8",
	);
	await chmod(posixShim, 0o755);

	await writeFile(
		windowsShim,
		`@echo off\r\nsetlocal\r\nset ELECTRON_RUN_AS_NODE=1\r\n"${nodePath}" "${runnerPath}" %*\r\n`,
		"utf8",
	);

	return process.platform === "win32" ? windowsShim : posixShim;
}

function upsertManagedHooks(existing: CursorHooksFile, command: string): CursorHooksFile {
	const hooks = { ...existing.hooks };

	hooks.beforeShellExecution = appendManaged(hooks.beforeShellExecution, {
		command,
		timeout: 30,
	});
	hooks.preToolUse = appendManaged(hooks.preToolUse, {
		matcher: "Write|Delete|Edit",
		command,
		timeout: 30,
	});
	hooks.beforeMCPExecution = appendManaged(hooks.beforeMCPExecution, {
		command,
		timeout: 30,
	});
	hooks.beforeReadFile = appendManaged(hooks.beforeReadFile, {
		command,
		timeout: 30,
	});

	return {
		version: 1,
		hooks,
	};
}

function removeManagedEntries(existing: CursorHooksFile): CursorHooksFile {
	const hooks: HookMap = {};
	for (const [eventName, entries] of Object.entries(existing.hooks)) {
		const filtered = (entries ?? []).filter((entry) => !isManagedEntry(entry));
		if (filtered.length > 0) {
			hooks[eventName] = filtered;
		}
	}
	return {
		version: existing.version || 1,
		hooks,
	};
}

function appendManaged(entries: HookEntry[] | undefined, managedEntry: HookEntry): HookEntry[] {
	const retained = (entries ?? []).filter((entry) => !isManagedEntry(entry));
	return [...retained, managedEntry];
}

function collectManagedCommands(hooks: HookMap): string[] {
	const commands = new Set<string>();
	for (const entries of Object.values(hooks)) {
		for (const entry of entries ?? []) {
			if (!isManagedEntry(entry) || typeof entry.command !== "string") {
				continue;
			}
			commands.add(entry.command);
		}
	}
	return [...commands];
}

function isManagedEntry(entry: HookEntry): boolean {
	return typeof entry.command === "string" && entry.command.includes(MANAGED_MARKER);
}

async function readHooksFile(filePath: string): Promise<CursorHooksFile> {
	try {
		const parsed = JSON.parse(await readFile(filePath, "utf8")) as Partial<CursorHooksFile>;
		return {
			version: parsed.version ?? 1,
			hooks: parsed.hooks ?? {},
		};
	} catch {
		return {
			version: 1,
			hooks: {},
		};
	}
}

async function writeHooksFile(filePath: string, data: CursorHooksFile): Promise<void> {
	await mkdir(path.dirname(filePath), { recursive: true });
	await writeFile(filePath, `${JSON.stringify(data, null, 2)}\n`, "utf8");
}

function quote(value: string): string {
	return `"${value.replace(/"/g, '\\"')}"`;
}
