/**
 * Audit logger for Sage verdicts.
 * Appends JSON Lines entries to ~/.sage/audit.jsonl for forensics and debugging.
 */

import { appendFile, mkdir, rename, stat, unlink } from "node:fs/promises";
import { dirname } from "node:path";
import { resolvePath } from "./config.js";
import { getFileContent } from "./file-utils.js";
import type { LoggingConfig, Verdict } from "./types.js";

const MAX_SUMMARY_LEN = 200;

function toolInputSummary(toolName: string, toolInput: Record<string, unknown>): string {
	if (toolName === "Bash") {
		return String(toolInput.command ?? "").slice(0, MAX_SUMMARY_LEN);
	}
	if (toolName === "WebFetch") {
		return String(toolInput.url ?? "").slice(0, MAX_SUMMARY_LEN);
	}
	if (toolName === "Write" || toolName === "Edit") {
		return String(toolInput.file_path ?? "").slice(0, MAX_SUMMARY_LEN);
	}
	return JSON.stringify(toolInput).slice(0, MAX_SUMMARY_LEN);
}

/**
 * Classic logrotate: shift numbered backups and rename active file to .1.
 * All renames wrapped in try/catch ignoring ENOENT for race safety.
 */
async function rotateIfNeeded(filePath: string, maxBytes: number, maxFiles: number): Promise<void> {
	if (maxBytes <= 0 || maxFiles <= 0) return;

	let size: number;
	try {
		const s = await stat(filePath);
		size = s.size;
	} catch {
		return; // File doesn't exist yet
	}

	if (size < maxBytes) return;

	// Delete oldest backup
	try {
		await unlink(`${filePath}.${maxFiles}`);
	} catch {
		// ENOENT OK
	}

	// Shift .N-1 → .N down to .1 → .2
	for (let i = maxFiles - 1; i >= 1; i--) {
		try {
			await rename(`${filePath}.${i}`, `${filePath}.${i + 1}`);
		} catch {
			// ENOENT OK
		}
	}

	// Active → .1
	try {
		await rename(filePath, `${filePath}.1`);
	} catch {
		// ENOENT OK (race: another process already renamed)
	}
}

async function appendEntry(config: LoggingConfig, entry: Record<string, unknown>): Promise<void> {
	const path = resolvePath(config.path);
	await mkdir(dirname(path), { recursive: true });
	await rotateIfNeeded(path, config.max_bytes, config.max_files);
	await appendFile(path, `${JSON.stringify(entry)}\n`);
}

export async function logVerdict(
	config: LoggingConfig,
	sessionId: string,
	toolName: string,
	toolInput: Record<string, unknown>,
	verdict: Verdict,
	userOverride = false,
): Promise<void> {
	if (!config.enabled) return;

	// Skip clean verdicts unless log_clean is on or this is a user override
	if (verdict.decision === "allow" && !config.log_clean && !userOverride) return;

	const entry = {
		type: "runtime_verdict",
		timestamp: new Date().toISOString(),
		session_id: sessionId,
		tool_name: toolName,
		tool_input_summary: toolInputSummary(toolName, toolInput),
		artifacts: verdict.artifacts,
		verdict: verdict.decision,
		severity: verdict.severity,
		reasons: verdict.reasons,
		source: verdict.source,
		user_override: userOverride,
	};

	try {
		await appendEntry(config, entry);
	} catch {
		// Fail-open: logging errors swallowed
	}
}

export async function logPluginScan(
	config: LoggingConfig,
	pluginKey: string,
	pluginVersion: string,
	findings: Record<string, unknown>[],
): Promise<void> {
	if (!config.enabled) return;

	const entry = {
		type: "plugin_scan",
		timestamp: new Date().toISOString(),
		plugin_key: pluginKey,
		plugin_version: pluginVersion,
		findings_count: findings.length,
		findings,
	};

	try {
		await appendEntry(config, entry);
	} catch {
		// Fail-open
	}
}

export async function getRecentEntries(config: LoggingConfig, limit = 100): Promise<unknown[]> {
	const path = resolvePath(config.path);

	try {
		const content = await getFileContent(path);
		const lines = content.trim().split("\n");
		const recent = lines.slice(-limit);
		const entries: unknown[] = [];
		for (const line of recent) {
			try {
				entries.push(JSON.parse(line));
			} catch {}
		}
		return entries;
	} catch {
		return [];
	}
}
