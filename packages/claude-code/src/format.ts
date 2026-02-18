/**
 * Formatting for Sage Claude Code alerts.
 * Shared formatting (severityEmoji, formatThreatBanner, etc.) lives in @sage/core.
 * This file keeps Claude Code-specific verdict formatting and re-exports shared utilities.
 */

import type { Verdict } from "@sage/core";
import {
	formatStartupClean,
	formatThreatBanner,
	kv,
	separatorLine,
	severityEmoji,
} from "@sage/core";

// Re-export shared formatting so existing callers are unaffected
export { formatStartupClean, formatThreatBanner, severityEmoji };

const PAD = 12;
const SEPARATOR_WIDTH = 48;

/** Append category and artifact details to lines array. */
function appendVerdictDetails(lines: string[], verdict: Verdict): void {
	lines.push(kv("Severity", verdict.severity.toUpperCase()));
	if (verdict.artifacts.length > 0) {
		// biome-ignore lint/style/noNonNullAssertion: length check above guarantees index 0 exists
		lines.push(kv("Artifact", verdict.artifacts[0]!));
		for (const a of verdict.artifacts.slice(1)) {
			lines.push(kv("", a));
		}
	}
	if (verdict.source && verdict.source !== "none") {
		lines.push(kv("Source", verdict.source));
	}
}

/**
 * Format block/ask reason for PreToolUse verdicts.
 * For deny: details-only block (branding goes in permissionDecisionReason, this goes in systemMessage).
 * For ask: full branded banner with separator (shown once in confirmation dialog).
 */
export function formatBlockReason(verdict: Verdict): string {
	const isDeny = verdict.decision === "deny";
	const emoji = severityEmoji(verdict.severity);
	const reasonText = verdict.reasons.length > 0 ? verdict.reasons[0] : verdict.category;

	if (isDeny) {
		const lines: string[] = [" "];
		lines.push(`${emoji} ${"Threat".padEnd(PAD)}${reasonText}`);
		appendVerdictDetails(lines, verdict);
		lines.push(kv("Action", "Blocked"));
		return lines.join("\n");
	}

	const header = `🛡️ Sage by Gen Digital: Suspicious Activity Detected`;
	const lines: string[] = [header, separatorLine(SEPARATOR_WIDTH)];
	lines.push(`${emoji} ${"Threat".padEnd(PAD)}${reasonText}`);
	appendVerdictDetails(lines, verdict);
	lines.push(kv("Action", "Requires confirmation"));
	return lines.join("\n");
}
