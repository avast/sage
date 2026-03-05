/**
 * Shared visual formatting for Sage alerts.
 * Plain text + Unicode only — no ANSI escape codes.
 * Follows Gen AV product alert patterns (shield icon, headline, key-value details).
 */

import type { SessionStartResult } from "./session-start.js";
import type { PluginScanResult } from "./types.js";
import type { VersionCheckResult } from "./version-check.js";

export const PAD = 12;
export const SEPARATOR_WIDTH = 48;

export function severityEmoji(severity: string): string {
	const s = severity.toLowerCase();
	if (s === "critical" || s === "high") return "🚨";
	if (s === "medium" || s === "warn" || s === "warning") return "⚠️";
	return "ℹ️";
}

export function kv(key: string, value: string): string {
	return `   ${key.padEnd(PAD)}${value}`;
}

export function separatorLine(headerLength: number): string {
	return "━".repeat(headerLength);
}

export function formatUpdateNotice(result: VersionCheckResult): string {
	return `⬆️  Update available: v${result.currentVersion} → v${result.latestVersion} (https://github.com/avast/sage)`;
}

export function formatStartupClean(
	version: string,
	versionCheck?: VersionCheckResult | null,
): string {
	const base = `🛡️ Sage v${version} by Gen Digital ✅ No threats found`;
	if (versionCheck?.updateAvailable) {
		return `${base}\n${formatUpdateNotice(versionCheck)}`;
	}
	return base;
}

export function formatThreatBanner(
	version: string,
	results: PluginScanResult[],
	versionCheck?: VersionCheckResult | null,
): string {
	const header = `🛡️ Sage v${version} by Gen Digital — Threat Detected`;
	const lines: string[] = [" ", header, separatorLine(SEPARATOR_WIDTH)];

	const MAX_FINDINGS = 5;
	let first = true;

	for (const result of results) {
		const highCrit = result.findings.filter(
			(f) => f.severity === "critical" || f.severity === "high",
		);
		if (highCrit.length === 0) continue;

		for (const f of highCrit.slice(0, MAX_FINDINGS)) {
			if (!first) lines.push("");
			first = false;

			const emoji = severityEmoji(f.severity);
			lines.push(`${emoji} ${`Plugin`.padEnd(PAD)}${result.plugin.key}`);
			lines.push(kv("Threat", f.title));
			lines.push(kv("Severity", f.severity.toUpperCase()));
			if (f.artifact) {
				lines.push(kv("Artifact", f.artifact));
			}
			lines.push(kv("Source", f.sourceFile));
			const actionLabel = f.action === "block" ? "Blocked" : "Flagged";
			lines.push(kv("Action", actionLabel));
		}

		const overflow = highCrit.length - MAX_FINDINGS;
		if (overflow > 0) {
			lines.push("");
			lines.push(`   ... and ${overflow} more findings`);
		}
	}

	if (versionCheck?.updateAvailable) {
		lines.push("");
		lines.push(formatUpdateNotice(versionCheck));
	}

	return lines.join("\n");
}

export function formatSessionStartMessage(version: string, result: SessionStartResult): string {
	if (result.scanResults.length > 0) {
		return formatThreatBanner(version, result.scanResults, result.versionCheck);
	}
	return formatStartupClean(version, result.versionCheck);
}
