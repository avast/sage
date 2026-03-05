/**
 * High-level session start orchestrator.
 * Combines plugin scanning, version check, and temp cleanup into a single call.
 */

import { resolvePath } from "./config.js";
import { pruneOrphanedTmpFiles } from "./file-utils.js";
import { getInstallationId } from "./installation-id.js";
import { runSessionStartScan } from "./session-start-scan.js";
import type { AgentRuntime, Logger, PluginInfo, PluginScanResult } from "./types.js";
import { nullLogger } from "./types.js";
import { checkForUpdate, type VersionCheckResult } from "./version-check.js";

export interface SessionStartContext {
	plugins: PluginInfo[];
	threatsDir: string;
	allowlistsDir: string;
	version: string;
	agentRuntime: AgentRuntime;
	logger?: Logger;
	configPath?: string;
	scanCachePath?: string;
	checkUrls?: boolean;
	checkFileHashes?: boolean;
	sageDirPath?: string;
	agentRuntimeVersion?: string;
}

export interface SessionStartResult {
	scanResults: PluginScanResult[];
	versionCheck: VersionCheckResult | null;
}

export async function runSessionStart(ctx: SessionStartContext): Promise<SessionStartResult> {
	const logger = ctx.logger ?? nullLogger;
	const sageDirPath = resolvePath(ctx.sageDirPath ?? "~/.sage");

	// Fire-and-forget temp cleanup
	pruneOrphanedTmpFiles(sageDirPath).catch(() => {});

	// Start installation ID read early so it runs concurrently with the scan
	const iidPromise = getInstallationId(sageDirPath).catch(() => undefined);

	// Parallel: scan + (iid read → version check)
	const [scanResults, versionCheck] = await Promise.all([
		runSessionStartScan({
			plugins: ctx.plugins,
			threatsDir: ctx.threatsDir,
			allowlistsDir: ctx.allowlistsDir,
			sageVersion: ctx.version,
			logger,
			configPath: ctx.configPath,
			scanCachePath: ctx.scanCachePath,
			checkUrls: ctx.checkUrls,
			checkFileHashes: ctx.checkFileHashes,
		}),
		iidPromise
			.then((iid) =>
				checkForUpdate(ctx.version, logger, undefined, {
					agentRuntime: ctx.agentRuntime,
					agentRuntimeVersion: ctx.agentRuntimeVersion,
					iid,
				}),
			)
			.catch(() => null),
	]);

	return { scanResults, versionCheck };
}
