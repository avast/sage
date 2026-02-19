/**
 * File-based cache for plugin scan results.
 */

import { createHash } from "node:crypto";
import { readdir } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { atomicWriteJson, getFileContent } from "./file-utils.js";
import type {
	CachedPluginScanResult,
	Logger,
	PluginFindingData,
	PluginScanCache,
} from "./types.js";
import { nullLogger } from "./types.js";

const DEFAULT_CACHE_PATH = join(homedir(), ".sage", "plugin_scan_cache.json");
const CACHE_TTL_DAYS = 7;

export function cacheKey(pluginKey: string, version: string, lastUpdated: string): string {
	return `${pluginKey}:${version}:${lastUpdated}`;
}

export async function computeConfigHash(sageVersion: string, ...dirs: string[]): Promise<string> {
	const h = createHash("sha256");
	if (sageVersion) h.update(sageVersion);
	for (const dir of dirs) {
		let files: string[];
		try {
			files = (await readdir(dir)).filter((f) => f.endsWith(".yaml")).sort();
		} catch {
			continue;
		}
		for (const file of files) {
			try {
				const content = await getFileContent(join(dir, file));
				h.update(content);
			} catch {}
		}
	}
	return h.digest("hex").slice(0, 16);
}

export async function loadScanCache(
	configHash = "",
	cachePath = DEFAULT_CACHE_PATH,
	logger: Logger = nullLogger,
): Promise<PluginScanCache> {
	let raw: string;
	try {
		raw = await getFileContent(cachePath);
	} catch {
		return { configHash, entries: {} };
	}

	try {
		const data = JSON.parse(raw) as Record<string, unknown>;
		const storedHash = (data.config_hash ?? "") as string;

		if (configHash && storedHash !== configHash) {
			logger.info("Config hash changed, invalidating plugin scan cache", {
				from: storedHash,
				to: configHash,
			});
			return { configHash, entries: {} };
		}

		const entries: Record<string, CachedPluginScanResult> = {};
		const rawEntries = (data.entries ?? {}) as Record<string, Record<string, unknown>>;
		for (const [key, entryData] of Object.entries(rawEntries)) {
			entries[key] = {
				pluginKey: entryData.plugin_key as string,
				version: entryData.version as string,
				scannedAt: entryData.scanned_at as string,
				findings: (entryData.findings ?? []) as PluginFindingData[],
			};
		}

		return { configHash: configHash || storedHash, entries };
	} catch (e) {
		logger.warn(`Failed to load scan cache from ${cachePath}`, { error: String(e) });
		return { configHash, entries: {} };
	}
}

export async function saveScanCache(
	cache: PluginScanCache,
	cachePath = DEFAULT_CACHE_PATH,
	logger: Logger = nullLogger,
): Promise<void> {
	try {
		const data = {
			config_hash: cache.configHash,
			entries: Object.fromEntries(
				Object.entries(cache.entries).map(([key, entry]) => [
					key,
					{
						plugin_key: entry.pluginKey,
						version: entry.version,
						scanned_at: entry.scannedAt,
						findings: entry.findings,
					},
				]),
			),
		};
		await atomicWriteJson(cachePath, data);
	} catch (e) {
		logger.warn(`Failed to save scan cache to ${cachePath}`, { error: String(e) });
	}
}

export function isCached(
	cache: PluginScanCache,
	pluginKey: string,
	version: string,
	lastUpdated: string,
): boolean {
	const key = cacheKey(pluginKey, version, lastUpdated);
	const entry = cache.entries[key];
	if (!entry) return false;

	try {
		const scannedAt = new Date(entry.scannedAt);
		const age = Date.now() - scannedAt.getTime();
		return age < CACHE_TTL_DAYS * 24 * 60 * 60 * 1000;
	} catch {
		return false;
	}
}

export function getCached(
	cache: PluginScanCache,
	pluginKey: string,
	version: string,
	lastUpdated: string,
): CachedPluginScanResult | null {
	if (!isCached(cache, pluginKey, version, lastUpdated)) return null;
	const key = cacheKey(pluginKey, version, lastUpdated);
	return cache.entries[key] ?? null;
}

export function storeResult(
	cache: PluginScanCache,
	pluginKey: string,
	version: string,
	lastUpdated: string,
	findings: PluginFindingData[],
): void {
	const key = cacheKey(pluginKey, version, lastUpdated);
	cache.entries[key] = {
		pluginKey,
		version,
		scannedAt: new Date().toISOString(),
		findings,
	};
}
