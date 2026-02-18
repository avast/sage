/**
 * URL, command, and file path normalization utilities.
 * Used by cache, allowlist, and other modules that need consistent keys.
 */

import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { normalize } from "node:path";

/** Normalize URL for consistent keys: lowercase scheme+host, remove fragment, sort params. */
export function normalizeUrl(raw: string): string {
	try {
		const u = new URL(raw);
		// URL constructor already lowercases protocol and hostname
		// Remove fragment (#...) since it's not sent to server
		u.hash = "";
		u.searchParams.sort();
		return u.toString();
	} catch {
		// If URL is malformed, use as-is (lowercase for best effort)
		return raw.toLowerCase();
	}
}

export function hashCommand(command: string): string {
	return createHash("sha256").update(command).digest("hex");
}

/** Normalize file path for consistent allowlist keys: resolve ~, normalize . and .. */
export function normalizeFilePath(raw: string): string {
	const expanded = raw.startsWith("~/") || raw === "~" ? `${homedir()}${raw.slice(1)}` : raw;
	return normalize(expanded);
}
