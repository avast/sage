/**
 * Shared runtime evaluation pipeline for hook entry points.
 * Hooks should normalize transport-specific payloads, then call this function.
 */

import { isAllowlisted, loadAllowlist } from "./allowlist.js";
import { logVerdict } from "./audit-log.js";
import { VerdictCache } from "./cache.js";
import { UrlCheckClient } from "./clients/url-check.js";
import { loadConfig } from "./config.js";
import { DecisionEngine } from "./engine.js";
import { HeuristicsEngine } from "./heuristics.js";
import { PackageChecker } from "./package-checker.js";
import {
	extractPackagesFromCommand,
	extractPackagesFromManifest,
	type ParsedPackage,
} from "./package-extractor.js";
import { loadThreats } from "./threat-loader.js";
import { loadTrustedDomains } from "./trusted-domains.js";
import type { Artifact, CachedVerdict, Logger, PackageCheckResult, Verdict } from "./types.js";
import { ConfigSchema, nullLogger } from "./types.js";

export interface ToolEvaluationRequest {
	sessionId: string;
	toolName: string;
	toolInput: Record<string, unknown>;
	artifacts: Artifact[];
}

export interface ToolEvaluationContext {
	threatsDir: string;
	allowlistsDir: string;
	configPath?: string;
	logger?: Logger;
}

export function allowVerdict(source = "none"): Verdict {
	return {
		decision: "allow",
		category: "none",
		confidence: 1.0,
		severity: "info",
		source,
		artifacts: [],
		matchedThreatId: null,
		reasons: [],
	};
}

export async function evaluateToolCall(
	request: ToolEvaluationRequest,
	context: ToolEvaluationContext,
): Promise<Verdict> {
	const logger = context.logger ?? nullLogger;
	const config = await loadConfig(context.configPath, logger).catch(() => ConfigSchema.parse({}));

	if (request.artifacts.length === 0) {
		return allowVerdict("no_artifacts");
	}

	try {
		const allowlist = await loadAllowlist(config.allowlist, logger);
		if (isAllowlisted(allowlist, request.artifacts)) {
			const verdict = allowVerdict("allowlisted");
			await logVerdict(
				config.logging,
				request.sessionId,
				request.toolName,
				request.toolInput,
				verdict,
				true,
			);
			return verdict;
		}
	} catch {
		// Fail open if allowlist loading fails.
	}

	let cache: VerdictCache | null = null;
	try {
		cache = new VerdictCache(config.cache, logger);
		await cache.load();
	} catch {
		cache = null;
	}

	const urls = request.artifacts
		.filter((artifact) => artifact.type === "url")
		.map((artifact) => artifact.value);
	const cachedUrlVerdicts = new Map<string, CachedVerdict>();
	let uncachedUrls: string[] = [];

	if (cache && urls.length > 0) {
		try {
			for (const url of urls) {
				const cached = cache.getUrl(url);
				if (cached !== null) {
					cachedUrlVerdicts.set(url, cached);
				} else {
					uncachedUrls.push(url);
				}
			}
		} catch {
			uncachedUrls = urls;
		}
	}

	let heuristicMatches: ReturnType<HeuristicsEngine["match"]> = [];
	if (config.heuristics_enabled) {
		let threats = await loadThreats(context.threatsDir, logger);
		if (config.disabled_threats.length > 0) {
			const disabledSet = new Set(config.disabled_threats);
			threats = threats.filter((t) => !disabledSet.has(t.id));
		}
		const trustedDomains = await loadTrustedDomains(context.allowlistsDir, logger);
		const heuristics = new HeuristicsEngine(threats, trustedDomains);
		heuristicMatches = heuristics.match(request.artifacts);
	}

	let urlCheckResults: Awaited<ReturnType<UrlCheckClient["checkUrls"]>> = [];
	const urlsToCheck = cache ? uncachedUrls : urls;
	if (urlsToCheck.length > 0 && config.url_check.enabled) {
		try {
			const client = new UrlCheckClient(config.url_check, logger);
			urlCheckResults = await client.checkUrls(urlsToCheck);
		} catch {
			// Fail open.
		}
	}

	// Package supply-chain check
	const packageCheckResults: PackageCheckResult[] = [];
	if (config.package_check.enabled) {
		try {
			let parsedPackages: ParsedPackage[] | undefined;
			if (request.toolName === "Bash") {
				const command = (request.toolInput.command ?? "") as string;
				parsedPackages = extractPackagesFromCommand(command);
			} else if (request.toolName === "Write" || request.toolName === "Edit") {
				const filePath = (request.toolInput.file_path ?? "") as string;
				const content = (request.toolInput.content ?? request.toolInput.new_string ?? "") as string;
				parsedPackages = extractPackagesFromManifest(filePath, content);
			}

			if (parsedPackages && parsedPackages.length > 0) {
				const uncached = [];
				for (const pkg of parsedPackages) {
					const cacheKey = `${pkg.registry}:${pkg.name}${pkg.version ? `@${pkg.version}` : ""}`;
					const cached = cache?.getPackage(cacheKey);
					if (cached && cached.verdict !== "allow") {
						packageCheckResults.push({
							packageName: pkg.name,
							registry: pkg.registry,
							verdict: cached.verdict === "deny" ? "malicious" : "suspicious_age",
							confidence: 1.0,
							details: cached.reasons.join("; "),
						});
					} else if (!cached) {
						uncached.push(pkg);
					}
				}

				if (uncached.length > 0) {
					const checker = new PackageChecker(
						{
							registryTimeoutSeconds: config.package_check.timeout_seconds,
							fileCheckEndpoint: config.file_check.endpoint,
							fileCheckTimeoutSeconds: config.file_check.timeout_seconds,
							fileCheckEnabled: config.file_check.enabled,
						},
						logger,
					);
					const results = await checker.checkPackages(uncached);
					packageCheckResults.push(...results);

					if (cache) {
						for (const result of results) {
							const pkg = uncached.find((p: { name: string }) => p.name === result.packageName);
							const cacheKey = `${result.registry}:${result.packageName}${pkg?.version ? `@${pkg.version}` : ""}`;
							const isCritical = result.verdict === "malicious" || result.verdict === "not_found";
							cache.putPackage(
								cacheKey,
								{
									verdict: result.verdict === "clean" ? "allow" : isCritical ? "deny" : "ask",
									severity: isCritical ? "critical" : "warning",
									reasons: [result.details],
									source: "package_check",
								},
								result.ageDays ?? null,
							);
						}
					}
				}
			}
		} catch {
			// Fail open
		}
	}

	const engine = new DecisionEngine(config.sensitivity);
	let verdict = await engine.decide({
		heuristicMatches,
		urlCheckResults,
		packageCheckResults: packageCheckResults.length > 0 ? packageCheckResults : undefined,
	});

	if (cachedUrlVerdicts.size > 0 && verdict.decision === "allow") {
		for (const [url, cachedVerdict] of cachedUrlVerdicts) {
			if (cachedVerdict.verdict === "allow") {
				continue;
			}
			verdict = {
				decision: cachedVerdict.verdict,
				category: "network_egress",
				confidence: 1.0,
				severity: cachedVerdict.severity,
				source: `cache(${cachedVerdict.source})`,
				artifacts: [url],
				matchedThreatId: null,
				reasons: cachedVerdict.reasons,
			};
			break;
		}
	}

	if (cache) {
		try {
			for (const result of urlCheckResults) {
				let cachedVerdict: CachedVerdict;
				if (result.isMalicious) {
					cachedVerdict = {
						verdict: "deny",
						severity: "critical",
						reasons: [
							`URL check: malicious (${result.findings
								.map((finding) => `${finding.severityName}/${finding.typeName}`)
								.join(", ")})`,
						],
						source: "url_check",
					};
				} else if (result.flags.length > 0) {
					cachedVerdict = {
						verdict: "ask",
						severity: "warning",
						reasons: [`URL check: suspicious (${result.flags.join(", ")})`],
						source: "url_check",
					};
				} else {
					cachedVerdict = {
						verdict: "allow",
						severity: "info",
						reasons: [],
						source: "url_check",
					};
				}
				cache.putUrl(result.url, cachedVerdict, result.isMalicious);
			}
			await cache.save();
		} catch {
			// Fail open.
		}
	}

	try {
		await logVerdict(
			config.logging,
			request.sessionId,
			request.toolName,
			request.toolInput,
			verdict,
		);
	} catch {
		// Fail open.
	}

	return verdict;
}
