// @sage/core public API

// Allowlist
export {
	addCommand,
	addFilePath,
	addUrl,
	emptyAllowlist,
	isAllowlisted,
	loadAllowlist,
	removeCommand,
	removeFilePath,
	removeUrl,
	saveAllowlist,
} from "./allowlist.js";
export type { ApprovedEntry, PendingEntry } from "./approval-store.js";
// Approval store
export { ApprovalStore } from "./approval-store.js";
// Audit log
export { getRecentEntries, logPluginScan, logVerdict } from "./audit-log.js";
// Cache
export { VerdictCache } from "./cache.js";
// AMSI client
export { AmsiClient, isAmsiSupported } from "./clients/amsi.js";
export type { FileCheckBatchResult, FileCheckResult } from "./clients/file-check.js";
// File-check client
export { FileCheckClient } from "./clients/file-check.js";
export type { PackageMetadata } from "./clients/package-registry.js";
// Registry client
export { RegistryClient } from "./clients/package-registry.js";
// URL check client
export { UrlCheckClient } from "./clients/url-check.js";
// Config
export { loadConfig, resolvePath, SAGE_DIR } from "./config.js";
// Decision engine
export { CONFIDENCE_THRESHOLD, DecisionEngine } from "./engine.js";
// Runtime evaluator
export {
	allowVerdict,
	evaluateToolCall,
	type ToolEvaluationContext,
	type ToolEvaluationRequest,
} from "./evaluator.js";
// Extractors
export {
	extractFromBash,
	extractFromDelete,
	extractFromEdit,
	extractFromRead,
	extractFromWebFetch,
	extractFromWrite,
	extractUrls,
} from "./extractors.js";
// File utilities
export { atomicWriteJson, getFileContent, pruneOrphanedTmpFiles } from "./file-utils.js";
// Format (shared alert formatting)
export {
	formatSessionStartMessage,
	formatStartupClean,
	formatThreatBanner,
	formatUpdateNotice,
	kv,
	PAD,
	SEPARATOR_WIDTH,
	separatorLine,
	severityEmoji,
} from "./format.js";
// Guard (soft-gated connector orchestrator)
export {
	addToAllowlist,
	approveAction,
	formatAskMessage,
	formatDenyMessage,
	type GuardResult,
	guardToolCall,
	removeFromAllowlist,
	summarizeArtifacts,
} from "./guard.js";
// Heuristics
export { HeuristicsEngine } from "./heuristics.js";
// Installation ID
export { getInstallationId } from "./installation-id.js";
export type { PackageCheckerConfig, PackageCheckInput } from "./package-checker.js";
// Package checker
export { PackageChecker } from "./package-checker.js";
export type { ParsedPackage } from "./package-extractor.js";
// Package extractor
export { extractPackagesFromCommand, extractPackagesFromManifest } from "./package-extractor.js";
// Plugin scan cache
export {
	cacheKey,
	computeConfigHash,
	getCached,
	isCached,
	loadScanCache,
	saveScanCache,
	storeResult,
} from "./plugin-scan-cache.js";
// Plugin scanner
export { discoverPlugins, scanPlugin } from "./plugin-scanner.js";
// Scan handler
export { createScanHandler, runPluginScan, type ScanHandlerOptions } from "./scan-handler.js";
// Session start orchestrator
export {
	runSessionStart,
	type SessionStartContext,
	type SessionStartResult,
} from "./session-start.js";
// Session start scan pipeline
export {
	fromCachedFinding,
	runSessionStartScan,
	type SessionStartScanContext,
	toAuditFindingData,
	toFindingData,
} from "./session-start-scan.js";
// Threat loader
export { loadThreats } from "./threat-loader.js";
// Trusted domains
export {
	extractDomain,
	isTrustedDomain,
	loadTrustedDomains,
} from "./trusted-domains.js";
export type {
	AgentRuntime,
	Allowlist,
	AllowlistConfig,
	AllowlistEntry,
	AmsiCheckConfig,
	AmsiCheckResult,
	Artifact,
	CacheConfig,
	CachedEntry,
	CachedPluginScanResult,
	CachedVerdict,
	CacheStore,
	Config,
	Decision,
	FileCheckConfig,
	HeuristicMatch,
	Logger,
	LoggingConfig,
	PackageCheckConfig,
	PackageCheckResult,
	PluginFinding,
	PluginFindingData,
	PluginInfo,
	PluginScanCache,
	PluginScanResult,
	SignalSources,
	Threat,
	ThreatData,
	TrustedDomain,
	UrlCheckConfig,
	UrlCheckFinding,
	UrlCheckResult,
	Verdict,
	VerdictSeverity,
} from "./types.js";
// Types
export {
	ActionSchema,
	AllowlistConfigSchema,
	ArtifactSchema,
	ArtifactTypeSchema,
	CacheConfigSchema,
	ConfigSchema,
	DecisionSchema,
	FileCheckConfigSchema,
	LoggingConfigSchema,
	nullLogger,
	PackageCheckConfigSchema,
	SensitivitySchema,
	SeveritySchema,
	ThreatSchema,
	UrlCheckConfigSchema,
	VerdictSeveritySchema,
} from "./types.js";
// URL utilities
export { hashCommand, normalizeFilePath, normalizeUrl } from "./url-utils.js";
// Version check
export type { VersionCheckContext, VersionCheckResult } from "./version-check.js";
export { checkForUpdate, isNewerVersion } from "./version-check.js";
