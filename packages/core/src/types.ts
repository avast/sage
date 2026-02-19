/**
 * Zod schemas and inferred TypeScript types for Sage.
 * Single source of truth for all data structures.
 */

import { z } from "zod";

// ── Logger interface (dependency injection) ─────────────────────────

export interface Logger {
	debug(msg: string, data?: Record<string, unknown>): void;
	info(msg: string, data?: Record<string, unknown>): void;
	warn(msg: string, data?: Record<string, unknown>): void;
	error(msg: string, data?: Record<string, unknown>): void;
}

/** No-op logger for when no logger is provided. */
export const nullLogger: Logger = {
	debug() {},
	info() {},
	warn() {},
	error() {},
};

// ── Artifact ────────────────────────────────────────────────────────

export const ArtifactTypeSchema = z.enum(["url", "command", "file_path", "content"]);

export const ArtifactSchema = z.object({
	type: ArtifactTypeSchema,
	value: z.string(),
	context: z.string().optional(),
});

export type Artifact = z.infer<typeof ArtifactSchema>;

// ── Threat ──────────────────────────────────────────────────────────

export const SeveritySchema = z.enum(["critical", "high", "medium", "low"]);
export const ActionSchema = z.enum(["block", "require_approval", "log"]);

export const ThreatSchema = z.object({
	id: z.string(),
	category: z.string(),
	severity: SeveritySchema,
	confidence: z.number(),
	action: ActionSchema,
	pattern: z.string(),
	match_on: z.union([z.string(), z.array(z.string())]),
	title: z.string(),
	expires_at: z.string().nullable().optional(),
	revoked: z.boolean().optional().default(false),
});

/** Raw threat from YAML (before compilation). */
export type ThreatData = z.infer<typeof ThreatSchema>;

/** Loaded threat with compiled regex and normalized match_on. */
export interface Threat {
	id: string;
	category: string;
	severity: "critical" | "high" | "medium" | "low";
	confidence: number;
	action: "block" | "require_approval" | "log";
	pattern: string;
	compiledPattern: RegExp;
	matchOn: Set<string>;
	title: string;
	expiresAt: Date | null;
	revoked: boolean;
}

// ── Heuristic match ─────────────────────────────────────────────────

export interface HeuristicMatch {
	threat: Threat;
	artifact: string;
	matchValue: string;
}

// ── URL Check ───────────────────────────────────────────────────────

export interface UrlCheckFinding {
	severityName: string;
	typeName: string;
}

export interface UrlCheckResult {
	url: string;
	isMalicious: boolean;
	findings: UrlCheckFinding[];
	flags: string[];
}

// ── Verdict ─────────────────────────────────────────────────────────

export const DecisionSchema = z.enum(["allow", "deny", "ask"]);
export const VerdictSeveritySchema = z.enum(["info", "warning", "critical"]);

export type Decision = z.infer<typeof DecisionSchema>;
export type VerdictSeverity = z.infer<typeof VerdictSeveritySchema>;

export interface Verdict {
	decision: Decision;
	category: string;
	confidence: number;
	severity: VerdictSeverity;
	source: string;
	artifacts: string[];
	matchedThreatId: string | null;
	reasons: string[];
}

// ── Package check ──────────────────────────────────────────────────

export interface PackageCheckResult {
	packageName: string;
	registry: "npm" | "pypi";
	verdict: "clean" | "not_found" | "suspicious_age" | "malicious" | "unknown";
	confidence: number;
	details: string;
	fileCheckSeverity?: string;
	ageDays?: number;
}

export interface SignalSources {
	heuristicMatches: HeuristicMatch[];
	urlCheckResults: UrlCheckResult[];
	packageCheckResults?: PackageCheckResult[];
}

// ── Cache ───────────────────────────────────────────────────────────

export interface CachedVerdict {
	verdict: Decision;
	severity: VerdictSeverity;
	reasons: string[];
	source: string;
}

export interface CachedEntry extends CachedVerdict {
	checkedAt: string;
	expiresAt: string;
}

export interface CacheStore {
	urls: Record<string, CachedEntry>;
	commands: Record<string, CachedEntry>;
	packages: Record<string, CachedEntry>;
}

// ── Config ──────────────────────────────────────────────────────────

export const SensitivitySchema = z.enum(["paranoid", "balanced", "relaxed"]);

export const UrlCheckConfigSchema = z.object({
	endpoint: z.string().optional(),
	timeout_seconds: z.number().default(5.0),
	enabled: z.boolean().default(true),
});

export const CacheConfigSchema = z.object({
	enabled: z.boolean().default(true),
	ttl_malicious_seconds: z.number().default(3600),
	ttl_clean_seconds: z.number().default(86400),
	path: z.string().default("~/.sage/cache.json"),
});

export const AllowlistConfigSchema = z.object({
	path: z.string().default("~/.sage/allowlist.json"),
});

export const LoggingConfigSchema = z.object({
	enabled: z.boolean().default(true),
	log_clean: z.boolean().default(false),
	path: z.string().default("~/.sage/audit.jsonl"),
	max_bytes: z
		.number()
		.int()
		.min(0)
		.default(5 * 1024 * 1024),
	max_files: z.number().int().min(0).default(3),
});

export const FileCheckConfigSchema = z.object({
	endpoint: z.string().optional(),
	timeout_seconds: z.number().default(5.0),
	enabled: z.boolean().default(true),
});

export const PackageCheckConfigSchema = z.object({
	enabled: z.boolean().default(true),
	timeout_seconds: z.number().default(5.0),
	// v1: all scoped packages (@scope/pkg) are skipped automatically.
	// Future: add private_scopes / public_scopes config for fine-grained control.
});

export const ConfigSchema = z.object({
	url_check: UrlCheckConfigSchema.default({}),
	file_check: FileCheckConfigSchema.default({}),
	package_check: PackageCheckConfigSchema.default({}),
	heuristics_enabled: z.boolean().default(true),
	cache: CacheConfigSchema.default({}),
	allowlist: AllowlistConfigSchema.default({}),
	logging: LoggingConfigSchema.default({}),
	sensitivity: SensitivitySchema.default("balanced"),
	disabled_threats: z.array(z.string()).default([]),
});

export type UrlCheckConfig = z.infer<typeof UrlCheckConfigSchema>;
export type FileCheckConfig = z.infer<typeof FileCheckConfigSchema>;
export type PackageCheckConfig = z.infer<typeof PackageCheckConfigSchema>;
export type CacheConfig = z.infer<typeof CacheConfigSchema>;
export type AllowlistConfig = z.infer<typeof AllowlistConfigSchema>;
export type LoggingConfig = z.infer<typeof LoggingConfigSchema>;
export type Config = z.infer<typeof ConfigSchema>;

// ── Allowlist ───────────────────────────────────────────────────────

export interface AllowlistEntry {
	addedAt: string;
	reason: string;
	originalVerdict: string;
}

export interface Allowlist {
	urls: Record<string, AllowlistEntry>;
	commands: Record<string, AllowlistEntry>;
	filePaths: Record<string, AllowlistEntry>;
}

// ── Trusted domains ─────────────────────────────────────────────────

export interface TrustedDomain {
	domain: string;
	reason: string;
}

// ── Plugin scanner ──────────────────────────────────────────────────

export interface PluginInfo {
	key: string;
	installPath: string;
	version: string;
	lastUpdated: string;
}

export interface PluginFinding {
	threatId: string;
	title: string;
	severity: string;
	confidence: number;
	action: string;
	artifact: string;
	sourceFile: string;
}

export interface PluginScanResult {
	plugin: PluginInfo;
	findings: PluginFinding[];
}

// ── Plugin scan cache ───────────────────────────────────────────────

export interface CachedPluginScanResult {
	pluginKey: string;
	version: string;
	scannedAt: string;
	findings: PluginFindingData[];
}

export interface PluginFindingData {
	threat_id: string;
	title: string;
	severity: string;
	confidence: number;
	action: string;
	artifact: string;
	source_file: string;
}

export interface PluginScanCache {
	configHash: string;
	entries: Record<string, CachedPluginScanResult>;
}
