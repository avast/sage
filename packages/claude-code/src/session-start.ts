#!/usr/bin/env node
/**
 * Sage SessionStart hook entry point.
 * Scans installed Claude Code plugins for threats at session startup.
 * Always exits 0 — outputs empty JSON on success, status message on findings.
 */

import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
	checkForUpdate,
	formatSessionStartFindings,
	type Logger,
	type PluginScanResult,
	pruneOrphanedTmpFiles,
	resolvePath,
	runSessionStartScan,
} from "@sage/core";
import pino from "pino";
import { pruneStaleSessionFiles } from "./approval-tracker.js";
import { formatStartupClean, formatThreatBanner } from "./format.js";

const logger: Logger = pino({ level: "warn" }, pino.destination(2));

export function formatFindings(results: PluginScanResult[]): string {
	return formatSessionStartFindings(results);
}

function getPluginRoot(): string {
	// When bundled by esbuild into CJS, __dirname points to packages/claude-code/dist/
	// Plugin root is three levels up.
	return resolve(__dirname, "..", "..", "..");
}

function getPluginManifest(pluginRoot: string): { name: string | null; version: string } {
	try {
		const manifest = readFileSync(join(pluginRoot, ".claude-plugin", "plugin.json"), "utf-8");
		const parsed = JSON.parse(manifest) as Record<string, unknown>;
		return {
			name: (parsed.name as string) ?? null,
			version: (parsed.version as string) ?? "0.0.0",
		};
	} catch {
		return { name: null, version: "0.0.0" };
	}
}

async function main(): Promise<void> {
	await pruneStaleSessionFiles(logger);
	await pruneOrphanedTmpFiles(resolvePath("~/.sage"));

	const pluginRoot = getPluginRoot();
	const threatsDir = join(pluginRoot, "threats");
	const allowlistsDir = join(pluginRoot, "allowlists");
	const manifest = getPluginManifest(pluginRoot);

	const [resultsWithFindings, versionCheck] = await Promise.all([
		runSessionStartScan({
			threatsDir,
			allowlistsDir,
			sageVersion: manifest.version,
			excludePluginPrefixes: manifest.name ? [`${manifest.name}@`] : undefined,
			logger,
		}),
		checkForUpdate(manifest.version, logger),
	]);

	if (resultsWithFindings.length === 0) {
		const cleanMsg = formatStartupClean(manifest.version, versionCheck);
		process.stdout.write(`${JSON.stringify({ systemMessage: cleanMsg })}\n`);
		return;
	}

	const statusMsg = formatThreatBanner(manifest.version, resultsWithFindings, versionCheck);
	process.stdout.write(`${JSON.stringify({ systemMessage: statusMsg })}\n`);
}

main().catch(() => {
	process.stdout.write("{}\n");
});
