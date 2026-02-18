import { access, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

import {
	ConfigSchema,
	checkForUpdate,
	getRecentEntries,
	loadConfig,
	resolvePath,
} from "@sage/core";
import * as vscode from "vscode";

import type {
	ManagedHookHealth,
	ManagedHookInstallOptions,
	ManagedHookScope,
} from "./managedHooks.js";

interface ManagedHookInstaller {
	installManagedHooks(options: ManagedHookInstallOptions): Promise<ManagedHookHealth>;
	removeManagedHooks(scope: ManagedHookScope): Promise<string>;
	getHookHealth(options: ManagedHookInstallOptions): Promise<ManagedHookHealth>;
}

interface ExtensionTarget {
	hostName: string;
	scopeSettingKey: string;
	installer: ManagedHookInstaller;
}

export function activateManagedHooksExtension(
	context: vscode.ExtensionContext,
	target: ExtensionTarget,
): void {
	const version = (context.extension.packageJSON as Record<string, unknown>).version as string;
	if (version) {
		checkForUpdate(version)
			.then((result) => {
				if (result?.updateAvailable) {
					void vscode.window.showInformationMessage(
						`Sage: Update available v${result.currentVersion} → v${result.latestVersion} (https://github.com/avast/sage)`,
					);
				}
			})
			.catch(() => {
				// Fail-open: never block extension activation
			});
	}

	context.subscriptions.push(
		vscode.commands.registerCommand("sage.enableProtection", async () => {
			await withErrorBoundary(async () => {
				const scope = getScope(target.scopeSettingKey);
				const health = await target.installer.installManagedHooks({ context, scope });
				vscode.window.showInformationMessage(
					`Sage enabled for ${target.hostName}. Managed hooks configured at ${health.configPath}.`,
				);
			});
		}),
	);

	context.subscriptions.push(
		vscode.commands.registerCommand("sage.disableProtection", async () => {
			await withErrorBoundary(async () => {
				const scope = getScope(target.scopeSettingKey);
				const configPath = await target.installer.removeManagedHooks(scope);
				vscode.window.showInformationMessage(`Sage managed hooks removed from ${configPath}.`);
			});
		}),
	);

	context.subscriptions.push(
		vscode.commands.registerCommand("sage.openConfig", async () => {
			await withErrorBoundary(async () => {
				const configPath = path.join(resolvePath("~/.sage"), "config.json");
				await ensureFile(configPath, `${JSON.stringify(ConfigSchema.parse({}), null, 2)}\n`);
				const document = await vscode.workspace.openTextDocument(configPath);
				await vscode.window.showTextDocument(document);
			});
		}),
	);

	context.subscriptions.push(
		vscode.commands.registerCommand("sage.openAuditLog", async () => {
			await withErrorBoundary(async () => {
				const config = await loadConfig();
				const auditPath = resolvePath(config.logging.path);
				await ensureFile(auditPath, "");
				const document = await vscode.workspace.openTextDocument(auditPath);
				await vscode.window.showTextDocument(document);
			});
		}),
	);

	context.subscriptions.push(
		vscode.commands.registerCommand("sage.showHookHealth", async () => {
			await withErrorBoundary(async () => {
				const scope = getScope(target.scopeSettingKey);
				const health = await target.installer.getHookHealth({ context, scope });
				const config = await loadConfig();
				const recentEntries = await getRecentEntries(config.logging, 1);
				const latest =
					recentEntries.length > 0 &&
					typeof recentEntries[0] === "object" &&
					recentEntries[0] !== null
						? (recentEntries[0] as Record<string, unknown>)
						: undefined;
				const lastVerdict =
					latest && typeof latest.verdict === "string" && typeof latest.severity === "string"
						? `${latest.verdict} (${latest.severity})`
						: "none";

				const message = [
					`target: ${target.hostName}`,
					`hooks config: ${health.configPath}`,
					`hook command: ${
						health.managedCommands.length > 0 ? health.managedCommands.join(" | ") : "none"
					}`,
					`runner bundle: ${health.runnerPath ?? "not found"}`,
					`managed events: ${
						health.installedEvents.length > 0 ? health.installedEvents.join(", ") : "none"
					}`,
					`last verdict: ${lastVerdict}`,
				].join("\n");

				void vscode.window.showInformationMessage(message, { modal: true });
			});
		}),
	);
}

function getScope(scopeSettingKey: string): ManagedHookScope {
	const value = vscode.workspace.getConfiguration().get<string>(scopeSettingKey);
	return value === "workspace" ? "workspace" : "user";
}

async function ensureFile(filePath: string, content: string): Promise<void> {
	try {
		await access(filePath);
	} catch {
		await mkdir(path.dirname(filePath), { recursive: true });
		await writeFile(filePath, content, "utf8");
	}
}

async function withErrorBoundary(work: () => Promise<void>): Promise<void> {
	try {
		await work();
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		void vscode.window.showErrorMessage(`Sage: ${message}`);
	}
}
