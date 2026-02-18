/**
 * before_tool_call handler: extracts artifacts from tool calls,
 * evaluates them through @sage/core, returns block/pass decisions.
 */

import {
	type Artifact,
	type CachedVerdict,
	DecisionEngine,
	extractFromBash,
	extractFromEdit,
	extractFromWebFetch,
	extractFromWrite,
	HeuristicsEngine,
	isAllowlisted,
	type Logger,
	loadAllowlist,
	loadConfig,
	loadThreats,
	loadTrustedDomains,
	logVerdict,
	UrlCheckClient,
	VerdictCache,
} from "@sage/core";
import { ApprovalStore } from "./approval-store.js";
import { getBundledDataDirs } from "./bundled-dirs.js";

export interface ToolCallEvent {
	toolName: string;
	params: Record<string, unknown>;
}

export interface BlockResult {
	block: true;
	blockReason: string;
}

function extractFilePaths(patch: string): Artifact[] {
	// OpenClaw apply_patch uses unified diff format; extract file paths from --- and +++ lines
	const artifacts: Artifact[] = [];
	for (const line of patch.split("\n")) {
		const match = line.match(/^(?:---|\+\+\+)\s+(?:a\/|b\/)?(.+)/);
		if (match?.[1] && match[1] !== "/dev/null") {
			artifacts.push({ type: "file_path", value: match[1], context: "apply_patch" });
		}
	}
	return artifacts;
}

function mapToolToArtifacts(toolName: string, params: Record<string, unknown>): Artifact[] | null {
	switch (toolName) {
		case "exec": {
			const command = (params.command ?? "") as string;
			return command ? extractFromBash(command) : null;
		}
		case "web_fetch":
			return extractFromWebFetch({ url: params.url });
		case "write":
			return extractFromWrite({ file_path: params.path, content: params.content });
		case "edit":
			return extractFromEdit({ file_path: params.path, new_string: params.new_string });
		case "read": {
			const path = (params.path ?? "") as string;
			return path ? [{ type: "file_path", value: path, context: "read" }] : null;
		}
		case "apply_patch": {
			const patch = (params.patch ?? "") as string;
			return patch ? extractFilePaths(patch) : null;
		}
		default:
			return null;
	}
}

export function createToolCallHandler(
	approvalStore: ApprovalStore,
	logger: Logger,
	sessionKey = "unknown",
): (event: ToolCallEvent) => Promise<BlockResult | undefined> {
	return async (event: ToolCallEvent): Promise<BlockResult | undefined> => {
		try {
			const { toolName, params } = event;

			// Map tool → artifacts. No artifacts → pass through.
			const artifacts = mapToolToArtifacts(toolName, params);
			if (!artifacts || artifacts.length === 0) return undefined;

			// Check approval store
			const actionId = ApprovalStore.actionId(toolName, params);
			if (approvalStore.isApproved(actionId)) return undefined;

			// Load config (fail-open defaults)
			const config = await loadConfig(undefined, logger).catch(() =>
				loadConfig("/dev/null", logger),
			);

			// Check allowlist
			try {
				const allowlist = await loadAllowlist(config.allowlist, logger);
				if (isAllowlisted(allowlist, artifacts)) {
					await logVerdict(
						config.logging,
						sessionKey,
						toolName,
						params,
						{
							decision: "allow" as const,
							category: "none" as const,
							confidence: 1.0,
							severity: "info" as const,
							source: "allowlisted",
							artifacts: [],
							matchedThreatId: null,
							reasons: [],
						},
						true,
					);
					return undefined;
				}
			} catch {
				// Fail open
			}

			// Initialize cache
			let cache: VerdictCache | null = null;
			try {
				cache = new VerdictCache(config.cache, logger);
				await cache.load();
			} catch {
				cache = null;
			}

			// Check cache for URL artifacts
			const urls = artifacts.filter((a) => a.type === "url").map((a) => a.value);
			const cachedUrlVerdicts = new Map<string, CachedVerdict>();
			let uncachedUrls: string[] = [];

			if (cache && urls.length > 0) {
				try {
					for (const url of urls) {
						const cached = cache.getUrl(url);
						if (cached) {
							cachedUrlVerdicts.set(url, cached);
						} else {
							uncachedUrls.push(url);
						}
					}
				} catch {
					uncachedUrls = urls;
				}
			}

			// Load threat definitions and run heuristics
			const { threatsDir, allowlistsDir } = getBundledDataDirs();
			let heuristicMatches: ReturnType<HeuristicsEngine["match"]> = [];
			if (config.heuristics_enabled) {
				const threats = await loadThreats(threatsDir, logger);
				const trustedDomains = await loadTrustedDomains(allowlistsDir, logger);
				const heuristics = new HeuristicsEngine(threats, trustedDomains);
				heuristicMatches = heuristics.match(artifacts);
			}

			// Query URL check (only for uncached URLs, if enabled)
			let urlCheckResults: Awaited<ReturnType<UrlCheckClient["checkUrls"]>> = [];
			const urlsToCheck = cache ? uncachedUrls : urls;
			if (urlsToCheck.length > 0 && config.url_check.enabled) {
				try {
					const client = new UrlCheckClient(config.url_check, logger);
					urlCheckResults = await client.checkUrls(urlsToCheck);
				} catch {
					// Fail open
				}
			}

			// Decide
			const engine = new DecisionEngine(config.sensitivity);
			let verdict = await engine.decide(heuristicMatches, urlCheckResults);

			// Merge cached URL verdicts
			if (cachedUrlVerdicts.size > 0 && verdict.decision === "allow") {
				for (const [url, cv] of cachedUrlVerdicts) {
					if (cv.verdict !== "allow") {
						verdict = {
							decision: cv.verdict,
							category: "network_egress",
							confidence: 1.0,
							severity: cv.severity,
							source: `cache(${cv.source})`,
							artifacts: [url],
							matchedThreatId: null,
							reasons: cv.reasons,
						};
						break;
					}
				}
			}

			// Cache new URL verdicts
			if (cache) {
				try {
					for (const result of urlCheckResults) {
						let cv: CachedVerdict;
						if (result.isMalicious) {
							cv = {
								verdict: "deny",
								severity: "critical",
								reasons: [
									`URL check: malicious (${result.findings.map((f) => `${f.severityName}/${f.typeName}`).join(", ")})`,
								],
								source: "url_check",
							};
						} else if (result.flags.length > 0) {
							cv = {
								verdict: "ask",
								severity: "warning",
								reasons: [`URL check: suspicious (${result.flags.join(", ")})`],
								source: "url_check",
							};
						} else {
							cv = {
								verdict: "allow",
								severity: "info",
								reasons: [],
								source: "url_check",
							};
						}
						cache.putUrl(result.url, cv, result.isMalicious);
					}
					await cache.save();
				} catch {
					// Fail open
				}
			}

			// Audit log
			try {
				await logVerdict(config.logging, sessionKey, toolName, params, verdict);
			} catch {
				// Fail open
			}

			// Map verdict → OpenClaw response
			if (verdict.decision === "allow") return undefined;

			const reasonText =
				verdict.reasons.length > 0 ? verdict.reasons.slice(0, 5).join("; ") : verdict.category;

			if (verdict.decision === "deny") {
				return { block: true, blockReason: `Sage blocked: ${reasonText}` };
			}

			// ask verdict — include actionId for gate tool
			return {
				block: true,
				blockReason: `Sage flagged: ${reasonText}. Ask the user whether to proceed — do NOT auto-approve. If the user confirms, call sage_approve({actionId: "${actionId}", approved: true}). If the user declines, call sage_approve({actionId: "${actionId}", approved: false}).`,
			};
		} catch (e) {
			// Fail-open: any unhandled error → pass through
			logger.error("tool-handler error, failing open", { error: String(e) });
			return undefined;
		}
	};
}
