/**
 * User-managed allowlist for overriding false positives.
 * JSON file at ~/.sage/allowlist.json containing URLs and command hashes
 * that the user has explicitly approved.
 */

import { resolvePath } from "./config.js";
import { atomicWriteJson, getFileContent } from "./file-utils.js";
import type { Allowlist, AllowlistConfig, AllowlistEntry, Artifact, Logger } from "./types.js";
import { nullLogger } from "./types.js";
import { hashCommand, normalizeUrl } from "./url-utils.js";

function parseEntries(raw: Record<string, unknown>): Record<string, AllowlistEntry> {
	const entries: Record<string, AllowlistEntry> = {};
	for (const [key, entryData] of Object.entries(raw)) {
		if (typeof entryData !== "object" || entryData === null) continue;
		const data = entryData as Record<string, unknown>;
		if (
			typeof data.added_at === "string" &&
			typeof data.reason === "string" &&
			typeof data.original_verdict === "string"
		) {
			entries[key] = {
				addedAt: data.added_at,
				reason: data.reason,
				originalVerdict: data.original_verdict,
			};
		}
	}
	return entries;
}

export async function loadAllowlist(
	config: AllowlistConfig,
	logger: Logger = nullLogger,
): Promise<Allowlist> {
	const path = resolvePath(config.path);

	let raw: string;
	try {
		raw = await getFileContent(path);
	} catch {
		return { urls: {}, commands: {} };
	}

	let data: unknown;
	try {
		data = JSON.parse(raw);
	} catch (e) {
		logger.warn(`Failed to load allowlist from ${path}`, { error: String(e) });
		return { urls: {}, commands: {} };
	}

	if (typeof data !== "object" || data === null || Array.isArray(data)) {
		logger.warn(`Allowlist file ${path} does not contain a JSON object`);
		return { urls: {}, commands: {} };
	}

	const record = data as Record<string, unknown>;
	const rawUrls = parseEntries((record.urls ?? {}) as Record<string, unknown>);
	// Normalize URL keys on load for backward compatibility with pre-normalization data
	const urls: Record<string, AllowlistEntry> = {};
	for (const [key, entry] of Object.entries(rawUrls)) {
		urls[normalizeUrl(key)] = entry;
	}
	return {
		urls,
		commands: parseEntries((record.commands ?? {}) as Record<string, unknown>),
	};
}

export async function saveAllowlist(
	allowlist: Allowlist,
	config: AllowlistConfig,
	logger: Logger = nullLogger,
): Promise<void> {
	const path = resolvePath(config.path);

	const data = {
		urls: Object.fromEntries(
			Object.entries(allowlist.urls).map(([url, entry]) => [
				url,
				{
					added_at: entry.addedAt,
					reason: entry.reason,
					original_verdict: entry.originalVerdict,
				},
			]),
		),
		commands: Object.fromEntries(
			Object.entries(allowlist.commands).map(([hash, entry]) => [
				hash,
				{
					added_at: entry.addedAt,
					reason: entry.reason,
					original_verdict: entry.originalVerdict,
				},
			]),
		),
	};

	try {
		await atomicWriteJson(path, data);
	} catch (e) {
		logger.warn(`Failed to save allowlist to ${path}`, { error: String(e) });
	}
}

export function isAllowlisted(allowlist: Allowlist, artifacts: Artifact[]): boolean {
	for (const artifact of artifacts) {
		if (artifact.type === "url" && normalizeUrl(artifact.value) in allowlist.urls) return true;
		if (artifact.type === "command") {
			const cmdHash = hashCommand(artifact.value);
			if (cmdHash in allowlist.commands) return true;
		}
	}
	return false;
}

export function addUrl(
	allowlist: Allowlist,
	url: string,
	reason: string,
	originalVerdict: string,
): void {
	allowlist.urls[normalizeUrl(url)] = {
		addedAt: new Date().toISOString(),
		reason,
		originalVerdict,
	};
}

export function addCommand(
	allowlist: Allowlist,
	command: string,
	reason: string,
	originalVerdict: string,
): void {
	const cmdHash = hashCommand(command);
	allowlist.commands[cmdHash] = {
		addedAt: new Date().toISOString(),
		reason,
		originalVerdict,
	};
}

export function removeUrl(allowlist: Allowlist, url: string): boolean {
	const normalized = normalizeUrl(url);
	if (normalized in allowlist.urls) {
		delete allowlist.urls[normalized];
		return true;
	}
	return false;
}

export function removeCommand(allowlist: Allowlist, commandHash: string): boolean {
	if (commandHash in allowlist.commands) {
		delete allowlist.commands[commandHash];
		return true;
	}
	return false;
}
