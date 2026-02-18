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
// Audit log
export { getRecentEntries, logPluginScan, logVerdict } from "./audit-log.js";
// Cache
export { VerdictCache } from "./cache.js";
export type { FileCheckBatchResult, FileCheckResult } from "./clients/file-check.js";
// File-check client
export { FileCheckClient } from "./clients/file-check.js";
export type { PackageMetadata } from "./clients/package-registry.js";
// Registry client
export { RegistryClient } from "./clients/package-registry.js";
// URL check client
export { UrlCheckClient } from "./clients/url-check.js";
// Config
export { loadConfig, resolvePath } from "./config.js";
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
	extractFromEdit,
	extractFromWebFetch,
	extractFromWrite,
	extractUrls,
} from "./extractors.js";
export { atomicWriteJson, getFileContent } from "./file-utils.js";
// Format (shared alert formatting)
export {
	formatStartupClean,
	formatThreatBanner,
	formatUpdateNotice,
	kv,
	separatorLine,
	severityEmoji,
} from "./format.js";
// Heuristics
export { HeuristicsEngine } from "./heuristics.js";
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
// Session start scan pipeline
export {
	formatSessionStartFindings,
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
	Allowlist,
	AllowlistConfig,
	AllowlistEntry,
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
export type { VersionCheckResult } from "./version-check.js";
export { checkForUpdate, isNewerVersion } from "./version-check.js";
