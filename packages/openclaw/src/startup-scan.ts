/**
 * Startup and session scan handlers for OpenClaw.
 * Scans installed OpenClaw extensions for threats on gateway_start and session_start.
 * Optionally surfaces findings to users via before_agent_start.
 */

import {
	checkForUpdate,
	computeConfigHash,
	formatThreatBanner,
	formatUpdateNotice,
	fromCachedFinding,
	getCached,
	type Logger,
	loadConfig,
	loadScanCache,
	loadThreats,
	loadTrustedDomains,
	logPluginScan,
	type PluginScanResult,
	pruneOrphanedTmpFiles,
	resolvePath,
	saveScanCache,
	scanPlugin,
	storeResult,
	toAuditFindingData,
	toFindingData,
} from "@sage/core";
import { getBundledDataDirs, getSageVersion } from "./bundled-dirs.js";
import { discoverOpenClawPlugins } from "./plugin-discovery.js";

const SAGE_PLUGIN_ID = "sage-openclaw";

/**
 * Run a full plugin scan. Returns the formatted findings banner if threats were
 * found, or null if everything is clean.
 */
async function runScan(logger: Logger, context: string): Promise<string | null> {
	await pruneOrphanedTmpFiles(resolvePath("~/.sage"));

	const { threatsDir, allowlistsDir } = getBundledDataDirs();
	const version = getSageVersion();
	logger.info(`Sage plugin scan started (${context})`, { threatsDir, allowlistsDir });

	const [threats, trustedDomains, versionCheck] = await Promise.all([
		loadThreats(threatsDir, logger),
		loadTrustedDomains(allowlistsDir, logger),
		checkForUpdate(version, logger),
	]);

	const updateNotice = versionCheck?.updateAvailable ? formatUpdateNotice(versionCheck) : null;

	if (threats.length === 0) {
		logger.warn(`Sage plugin scan (${context}): no threats loaded, skipping`);
		return updateNotice;
	}
	logger.info(`Sage plugin scan (${context}): loaded ${threats.length} threat definitions`);

	let plugins = await discoverOpenClawPlugins(logger);

	// Don't scan ourselves
	plugins = plugins.filter((p) => !p.key.startsWith(`${SAGE_PLUGIN_ID}@`));

	if (plugins.length === 0) {
		logger.warn(`Sage plugin scan (${context}): no plugins to scan after filtering`);
		return updateNotice;
	}
	logger.info(`Sage plugin scan (${context}): ${plugins.length} plugin(s) to scan`, {
		keys: plugins.map((p) => p.key),
	});

	const configHash = await computeConfigHash("", threatsDir, allowlistsDir);
	const cache = await loadScanCache(configHash, undefined, logger);
	const resultsWithFindings: PluginScanResult[] = [];
	let cacheModified = false;
	let scannedCount = 0;

	for (const plugin of plugins) {
		const cached = getCached(cache, plugin.key, plugin.version, plugin.lastUpdated);
		if (cached && cached.findings.length === 0) {
			logger.info(`Sage plugin scan (${context}): cache hit (clean) for ${plugin.key}`);
			continue;
		}

		if (cached && cached.findings.length > 0) {
			logger.info(
				`Sage plugin scan (${context}): cache hit with ${cached.findings.length} finding(s) for ${plugin.key}`,
			);
			resultsWithFindings.push({ plugin, findings: cached.findings.map(fromCachedFinding) });
			continue;
		}

		logger.info(`Sage plugin scan (${context}): scanning ${plugin.key}`);
		const result = await scanPlugin(plugin, threats, {
			checkUrls: true,
			trustedDomains,
			logger,
		});
		scannedCount++;

		storeResult(
			cache,
			plugin.key,
			plugin.version,
			plugin.lastUpdated,
			result.findings.map(toFindingData),
		);
		cacheModified = true;

		if (result.findings.length > 0) {
			resultsWithFindings.push(result);
		}
	}

	if (cacheModified) {
		await saveScanCache(cache, undefined, logger);
	}

	logger.info(
		`Sage plugin scan (${context}) complete: ${scannedCount} scanned, ${resultsWithFindings.length} with findings, cache ${cacheModified ? "updated" : "unchanged"}`,
	);

	// Log plugin scan findings to audit log (fail-open)
	try {
		const sageConfig = await loadConfig(undefined, logger);
		for (const result of resultsWithFindings) {
			await logPluginScan(
				sageConfig.logging,
				result.plugin.key,
				result.plugin.version,
				result.findings.map(toAuditFindingData),
			);
		}
	} catch {
		// Logging must never crash the plugin
	}

	if (resultsWithFindings.length > 0) {
		const banner = formatThreatBanner(version, resultsWithFindings, versionCheck);
		logger.warn(`Sage: threat findings detected`, {
			plugins: resultsWithFindings.map((r) => r.plugin.key),
		});
		return banner;
	}

	return updateNotice;
}

function createScanHandler(
	logger: Logger,
	context: string,
	onFindings?: (msg: string | null) => void,
): () => Promise<void> {
	return async () => {
		try {
			const findings = await runScan(logger, context);
			onFindings?.(findings);
		} catch (e) {
			logger.error(`Sage ${context} scan failed`, { error: String(e) });
		}
	};
}

export function createStartupScanHandler(
	logger: Logger,
	onFindings?: (msg: string | null) => void,
): () => Promise<void> {
	return createScanHandler(logger, "startup", onFindings);
}

export function createSessionScanHandler(
	logger: Logger,
	onFindings?: (msg: string | null) => void,
): () => Promise<void> {
	return createScanHandler(logger, "session", onFindings);
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
