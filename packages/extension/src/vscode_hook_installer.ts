import { access, chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import * as vscode from "vscode";

import type {
	ManagedHookHealth,
	ManagedHookInstallOptions,
	ManagedHookScope,
} from "./managedHooks.js";

const MANAGED_MARKER = "--managed-by sage-vscode";

type HookCommandEntry = Record<string, unknown> & { command?: string };
type HookMatcherEntry = Record<string, unknown> & { hooks?: HookCommandEntry[] };
type HookMap = Record<string, HookMatcherEntry[]>;
type SettingsObject = Record<string, unknown>;

export async function installManagedHooks(
	options: ManagedHookInstallOptions,
): Promise<ManagedHookHealth> {
	const configPath = await resolveSettingsPath(options.scope);
	await mkdir(path.dirname(configPath), { recursive: true });

	const runnerPath = await resolveRunnerPath(options.context);
	const nodePath = resolveNodeRuntimePath();
	const command = await buildHookCommand(configPath, nodePath, runnerPath);

	const settings = await readSettingsFile(configPath);
	const updated = upsertManagedHooks(settings, command);
	await writeSettingsFile(configPath, updated);

	const hooks = normalizeHookMap(updated.hooks);
	return {
		configPath,
		runnerPath,
		installedEvents: collectInstalledEvents(hooks),
		managedCommands: collectManagedCommands(hooks),
	};
}

export async function removeManagedHooks(scope: ManagedHookScope): Promise<string> {
	const configPath = await resolveSettingsPath(scope);
	const settings = await readSettingsFile(configPath);
	const updated = removeManagedEntries(settings);
	await writeSettingsFile(configPath, updated);
	return configPath;
}

export async function getHookHealth(
	options: ManagedHookInstallOptions,
): Promise<ManagedHookHealth> {
	const configPath = await resolveSettingsPath(options.scope);
	const settings = await readSettingsFile(configPath);
	const hooks = normalizeHookMap(settings.hooks);
	const runnerPath = await resolveRunnerPath(options.context).catch(() => undefined);

	return {
		configPath,
		runnerPath,
		installedEvents: collectInstalledEvents(hooks),
		managedCommands: collectManagedCommands(hooks),
	};
}

async function resolveSettingsPath(scope: ManagedHookScope): Promise<string> {
	if (scope === "user") {
		return path.join(os.homedir(), ".claude", "settings.json");
	}

	const workspace = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
	if (!workspace) {
		throw new Error("Open a workspace folder to install workspace hooks.");
	}
	return path.join(workspace, ".claude", "settings.json");
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
	const claudeConfigDir = path.dirname(configPath);
	const shimPath = await createHookShim(claudeConfigDir, nodePath, runnerPath);
	if (process.platform === "win32") {
		// Claude hook commands can execute in PowerShell contexts on Windows.
		// A quoted script path must be invoked with `&` to avoid parser errors.
		return `& ${quote(shimPath)} vscode ${MANAGED_MARKER}`;
	}
	return `${quote(shimPath)} vscode ${MANAGED_MARKER}`;
}

async function createHookShim(
	claudeConfigDir: string,
	nodePath: string,
	runnerPath: string,
): Promise<string> {
	const hooksDir = path.join(claudeConfigDir, "hooks");
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

function upsertManagedHooks(existing: SettingsObject, command: string): SettingsObject {
	const hooks = cloneHookSettings(existing.hooks);
	hooks.PreToolUse = appendManaged(asMatcherEntries(hooks.PreToolUse), {
		matcher: "Bash|WebFetch|Write|Edit",
		hooks: [
			{
				type: "command",
				command,
				timeout: 30,
				statusMessage: "Sage: Checking for threats...",
			},
		],
	});

	return {
		...existing,
		hooks,
	};
}

function removeManagedEntries(existing: SettingsObject): SettingsObject {
	const hooks = cloneHookSettings(existing.hooks);
	for (const [eventName, value] of Object.entries(hooks)) {
		if (!Array.isArray(value)) {
			continue;
		}
		const filtered = filterManagedMatcherEntries(asMatcherEntries(value));
		if (filtered.length === 0) {
			delete hooks[eventName];
			continue;
		}
		hooks[eventName] = filtered;
	}

	return {
		...existing,
		hooks,
	};
}

function appendManaged(
	entries: HookMatcherEntry[] | undefined,
	managedEntry: HookMatcherEntry,
): HookMatcherEntry[] {
	const retained = filterManagedMatcherEntries(entries ?? []);
	return [...retained, managedEntry];
}

function filterManagedMatcherEntries(entries: HookMatcherEntry[]): HookMatcherEntry[] {
	const retained: HookMatcherEntry[] = [];
	for (const entry of entries) {
		const commandHooks = asCommandEntries(entry.hooks);
		if (commandHooks.length === 0) {
			retained.push(entry);
			continue;
		}

		const filteredHooks = commandHooks.filter((hook) => !isManagedCommandHook(hook));
		if (filteredHooks.length === 0) {
			continue;
		}
		retained.push({ ...entry, hooks: filteredHooks });
	}
	return retained;
}

function collectInstalledEvents(hooks: HookMap): string[] {
	const events: string[] = [];
	for (const [eventName, entries] of Object.entries(hooks)) {
		if (
			entries.some((entry) =>
				asCommandEntries(entry.hooks).some((hook) => isManagedCommandHook(hook)),
			)
		) {
			events.push(eventName);
		}
	}
	return events;
}

function collectManagedCommands(hooks: HookMap): string[] {
	const commands = new Set<string>();
	for (const entries of Object.values(hooks)) {
		for (const entry of entries) {
			for (const hook of asCommandEntries(entry.hooks)) {
				if (isManagedCommandHook(hook) && typeof hook.command === "string") {
					commands.add(hook.command);
				}
			}
		}
	}
	return [...commands];
}

function isManagedCommandHook(entry: HookCommandEntry): boolean {
	return typeof entry.command === "string" && entry.command.includes(MANAGED_MARKER);
}

async function readSettingsFile(filePath: string): Promise<SettingsObject> {
	try {
		const parsed = JSON.parse(await readFile(filePath, "utf8"));
		if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
			return parsed as SettingsObject;
		}
		return {};
	} catch {
		return {};
	}
}

async function writeSettingsFile(filePath: string, data: SettingsObject): Promise<void> {
	await mkdir(path.dirname(filePath), { recursive: true });
	await writeFile(filePath, `${JSON.stringify(data, null, 2)}\n`, "utf8");
}

function normalizeHookMap(input: unknown): HookMap {
	if (!input || typeof input !== "object" || Array.isArray(input)) {
		return {};
	}
	const output: HookMap = {};
	for (const [eventName, entries] of Object.entries(input as Record<string, unknown>)) {
		if (!Array.isArray(entries)) {
			continue;
		}
		output[eventName] = entries.filter(
			(entry): entry is HookMatcherEntry =>
				!!entry && typeof entry === "object" && !Array.isArray(entry),
		);
	}
	return output;
}

function cloneHookSettings(input: unknown): SettingsObject {
	if (!input || typeof input !== "object" || Array.isArray(input)) {
		return {};
	}
	return { ...(input as SettingsObject) };
}

function asMatcherEntries(entries: unknown): HookMatcherEntry[] {
	if (!Array.isArray(entries)) {
		return [];
	}
	return entries.filter(
		(entry): entry is HookMatcherEntry =>
			!!entry && typeof entry === "object" && !Array.isArray(entry),
	);
}

function asCommandEntries(entries: unknown): HookCommandEntry[] {
	if (!Array.isArray(entries)) {
		return [];
	}
	return entries.filter(
		(entry): entry is HookCommandEntry =>
			!!entry && typeof entry === "object" && !Array.isArray(entry),
	);
}

function quote(value: string): string {
	return `"${value.replace(/"/g, '\\"')}"`;
}
