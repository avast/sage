/**
 * Startup and session scan handlers for OpenClaw.
 * Thin wrappers over core's createScanHandler.
 */

import { createScanHandler as coreScanHandler, type Logger } from "@sage/core";
import { getBundledDataDirs, getSageVersion } from "./bundled-dirs.js";
import { discoverOpenClawPlugins } from "./plugin-discovery.js";

function createOpenClawScanHandler(
	logger: Logger,
	context: string,
	onResult?: (msg: string) => void,
): () => Promise<void> {
	const { threatsDir, allowlistsDir } = getBundledDataDirs();
	const version = getSageVersion();

	return coreScanHandler({
		logger,
		context,
		discoverPlugins: () => discoverOpenClawPlugins(logger),
		selfPrefix: "sage-openclaw@",
		threatsDir,
		allowlistsDir,
		version,
		agentRuntime: "openclaw",
		onResult,
	});
}

export function createStartupScanHandler(
	logger: Logger,
	onResult?: (msg: string) => void,
): () => Promise<void> {
	return createOpenClawScanHandler(logger, "startup", onResult);
}

export function createSessionScanHandler(
	logger: Logger,
	onResult?: (msg: string) => void,
): () => Promise<void> {
	return createOpenClawScanHandler(logger, "session", onResult);
}

/**
 * Creates a before_agent_start handler that surfaces plugin scan findings
 * as prepended context. One-shot: clears findings after first delivery.
 */
export function createBeforeAgentStartHandler(
	getFindings: () => string | null,
	clearFindings: () => void,
	logger: Logger,
): () => { prependContext: string } | undefined {
	return () => {
		const findings = getFindings();
		if (!findings) return undefined;

		clearFindings();
		logger.info("Sage: surfacing plugin scan findings via before_agent_start");

		const prependContext = [
			'<security-alert source="sage-plugin-scan">',
			findings,
			"",
			"Inform the user about these security findings.",
			"</security-alert>",
		].join("\n");

		return { prependContext };
	};
}
