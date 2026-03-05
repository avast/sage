/**
 * Generic scan orchestration for all connectors.
 * Extracts the common runScan + createScanHandler pattern from
 * OpenCode/OpenClaw startup-scan files.
 */

import { formatSessionStartMessage } from "./format.js";
import { runSessionStart } from "./session-start.js";
import type { AgentRuntime, Logger, PluginInfo } from "./types.js";

/**
 * Run a plugin scan with the given plugins and return a formatted status message.
 * Always returns a message (clean or findings) — callers can always show the result.
 */
export async function runPluginScan(
	logger: Logger,
	context: string,
	plugins: PluginInfo[],
	threatsDir: string,
	allowlistsDir: string,
	version: string,
	agentRuntime: AgentRuntime,
): Promise<string> {
	logger.info(`Sage plugin scan started (${context})`, { threatsDir, allowlistsDir });

	const result = await runSessionStart({
		plugins,
		threatsDir,
		allowlistsDir,
		version,
		logger,
		agentRuntime,
	});

	logger.info(`Sage plugin scan (${context}) complete`, {
		findings: result.scanResults.length,
		updateAvailable: result.versionCheck?.updateAvailable ?? false,
	});

	return formatSessionStartMessage(version, result);
}

/**
 * Convenience wrapper for in-process connectors: discovery + self-filter + scan + error handling.
 */
export interface ScanHandlerOptions {
	logger: Logger;
	context: string;
	discoverPlugins: () => Promise<PluginInfo[]>;
	selfPrefix: string;
	threatsDir: string;
	allowlistsDir: string;
	version: string;
	agentRuntime: AgentRuntime;
	onResult?: (msg: string) => void;
}

export function createScanHandler(options: ScanHandlerOptions): () => Promise<void> {
	const {
		logger,
		context,
		discoverPlugins,
		selfPrefix,
		threatsDir,
		allowlistsDir,
		version,
		agentRuntime,
		onResult,
	} = options;

	return async () => {
		try {
			let plugins = await discoverPlugins();
			plugins = plugins.filter((p) => !p.key.startsWith(selfPrefix));

			if (plugins.length === 0) {
				logger.warn(`Sage plugin scan (${context}): no plugins to scan after filtering`);
			}

			const msg = await runPluginScan(
				logger,
				context,
				plugins,
				threatsDir,
				allowlistsDir,
				version,
				agentRuntime,
			);
			onResult?.(msg);
		} catch (e) {
			logger.error(`Sage ${context} scan failed`, { error: String(e) });
		}
	};
}
