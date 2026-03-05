/**
 * Shared SessionStart scanning pipeline for hook entry points.
 * Hooks provide transport-specific paths and output formatting.
 */

import { logPluginScan } from "./audit-log.js";
import { loadConfig } from "./config.js";
import {
	computeConfigHash,
	getCached,
	loadScanCache,
	saveScanCache,
	storeResult,
} from "./plugin-scan-cache.js";
import { scanPlugin } from "./plugin-scanner.js";
import { loadThreats } from "./threat-loader.js";
import { loadTrustedDomains } from "./trusted-domains.js";
import type {
	Logger,
	PluginFinding,
	PluginFindingData,
	PluginInfo,
	PluginScanResult,
} from "./types.js";
import { nullLogger } from "./types.js";

export interface SessionStartScanContext {
	plugins: PluginInfo[];
	threatsDir: string;
	allowlistsDir: string;
	sageVersion?: string;
	logger?: Logger;
	configPath?: string;
	scanCachePath?: string;
	checkUrls?: boolean;
	checkFileHashes?: boolean;
}

export function fromCachedFinding(finding: PluginFindingData): PluginFinding {
	return {
		threatId: finding.threat_id,
		title: finding.title,
		severity: finding.severity,
		confidence: finding.confidence,
		action: finding.action,
		artifact: finding.artifact,
		sourceFile: finding.source_file,
	};
}

export function toFindingData(finding: PluginFinding): PluginFindingData {
	return {
		threat_id: finding.threatId,
		title: finding.title,
		severity: finding.severity,
		confidence: finding.confidence,
		action: finding.action,
		artifact: finding.artifact,
		source_file: finding.sourceFile,
	};
}

export function toAuditFindingData(finding: PluginFinding): Record<string, unknown> {
	const { action: _, ...rest } = toFindingData(finding);
	return rest;
}

export async function runSessionStartScan(
	context: SessionStartScanContext,
): Promise<PluginScanResult[]> {
	const logger = context.logger ?? nullLogger;

	const threats = await loadThreats(context.threatsDir, logger);
	const trustedDomains = await loadTrustedDomains(context.allowlistsDir, logger);
	if (threats.length === 0) {
		return [];
	}

	const plugins = context.plugins;
	if (plugins.length === 0) {
		return [];
	}

	const configHash = await computeConfigHash(
		context.sageVersion ?? "",
		context.threatsDir,
		context.allowlistsDir,
	);
	const cache = await loadScanCache(configHash, context.scanCachePath, logger);
	const resultsWithFindings: PluginScanResult[] = [];
	let cacheModified = false;

	for (const plugin of plugins) {
		const cached = getCached(cache, plugin.key, plugin.version, plugin.lastUpdated);
		if (cached && cached.findings.length === 0) {
			continue;
		}

		if (cached && cached.findings.length > 0) {
			resultsWithFindings.push({
				plugin,
				findings: cached.findings.map(fromCachedFinding),
			});
			continue;
		}

		const result = await scanPlugin(plugin, threats, {
			checkUrls: context.checkUrls ?? true,
			checkFileHashes: context.checkFileHashes ?? true,
			trustedDomains,
			logger,
		});

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
		await saveScanCache(cache, context.scanCachePath, logger);
	}

	try {
		const sageConfig = await loadConfig(context.configPath, logger);
		for (const result of resultsWithFindings) {
			await logPluginScan(
				sageConfig.logging,
				result.plugin.key,
				result.plugin.version,
				result.findings.map(toAuditFindingData),
			);
		}
	} catch {
		// Logging must never crash the hook.
	}

	return resultsWithFindings;
}
