/**
 * JSON file-based verdict cache for Sage.
 * Replaces the Python SQLite implementation.
 */

import { resolvePath } from "./config.js";
import { atomicWriteJson, getFileContent } from "./file-utils.js";
import type { CacheConfig, CachedVerdict, CacheStore, Logger } from "./types.js";
import { nullLogger } from "./types.js";
import { normalizeUrl } from "./url-utils.js";

const ONE_HOUR = 3600;
const TWENTY_FOUR_HOURS = 86400;
const FAR_FUTURE = "9999-12-31T23:59:59+00:00";

export class VerdictCache {
	private store: CacheStore = { urls: {}, commands: {}, packages: {} };
	private readonly path: string;
	private readonly config: CacheConfig;
	private readonly logger: Logger;

	constructor(config: CacheConfig, logger: Logger = nullLogger) {
		this.config = config;
		this.logger = logger;
		this.path = resolvePath(config.path);
	}

	async load(): Promise<void> {
		if (!this.config.enabled) return;

		try {
			const raw = await getFileContent(this.path);
			const data = JSON.parse(raw) as CacheStore;
			this.store = {
				urls: data.urls ?? {},
				commands: data.commands ?? {},
				packages: data.packages ?? {},
			};
		} catch {
			// Missing or corrupt file — start with empty cache
			this.store = { urls: {}, commands: {}, packages: {} };
		}
	}

	getUrl(url: string): CachedVerdict | null {
		if (!this.config.enabled) return null;
		const key = normalizeUrl(url);
		const entry = this.store.urls[key];
		if (!entry) return null;

		if (new Date(entry.expiresAt).getTime() <= Date.now()) {
			delete this.store.urls[key];
			return null;
		}

		return {
			verdict: entry.verdict,
			severity: entry.severity,
			reasons: entry.reasons,
			source: entry.source,
		};
	}

	putUrl(url: string, verdict: CachedVerdict, isMalicious: boolean): void {
		if (!this.config.enabled) return;

		const key = normalizeUrl(url);
		const now = new Date();
		const ttl = isMalicious ? this.config.ttl_malicious_seconds : this.config.ttl_clean_seconds;
		const expiresAt = new Date(now.getTime() + ttl * 1000);

		this.store.urls[key] = {
			...verdict,
			checkedAt: now.toISOString(),
			expiresAt: expiresAt.toISOString(),
		};
	}

	getCommand(commandHash: string): CachedVerdict | null {
		if (!this.config.enabled) return null;
		const entry = this.store.commands[commandHash];
		if (!entry) return null;

		if (new Date(entry.expiresAt).getTime() <= Date.now()) {
			delete this.store.commands[commandHash];
			return null;
		}

		return {
			verdict: entry.verdict,
			severity: entry.severity,
			reasons: entry.reasons,
			source: entry.source,
		};
	}

	putCommand(commandHash: string, verdict: CachedVerdict): void {
		if (!this.config.enabled) return;

		const now = new Date();
		this.store.commands[commandHash] = {
			...verdict,
			checkedAt: now.toISOString(),
			expiresAt: FAR_FUTURE,
		};
	}

	getPackage(key: string): CachedVerdict | null {
		if (!this.config.enabled) return null;
		const entry = this.store.packages[key];
		if (!entry) return null;

		if (new Date(entry.expiresAt).getTime() <= Date.now()) {
			delete this.store.packages[key];
			return null;
		}

		return {
			verdict: entry.verdict,
			severity: entry.severity,
			reasons: entry.reasons,
			source: entry.source,
		};
	}

	putPackage(key: string, verdict: CachedVerdict, packageAgeDays: number | null): void {
		if (!this.config.enabled) return;

		const ttlSeconds = this.computePackageTtl(verdict.verdict, packageAgeDays);
		const now = new Date();
		const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);

		this.store.packages[key] = {
			...verdict,
			checkedAt: now.toISOString(),
			expiresAt: expiresAt.toISOString(),
		};
	}

	private computePackageTtl(verdict: string, packageAgeDays: number | null): number {
		const isFresh = packageAgeDays !== null && packageAgeDays < 7;

		switch (verdict) {
			case "deny":
				return TWENTY_FOUR_HOURS;
			case "allow":
				return isFresh ? ONE_HOUR : TWENTY_FOUR_HOURS;
			default:
				return ONE_HOUR;
		}
	}

	async save(): Promise<void> {
		if (!this.config.enabled) return;

		try {
			await atomicWriteJson(this.path, this.store);
		} catch (e) {
			this.logger.warn(`Failed to save cache to ${this.path}`, { error: String(e) });
		}
	}
}
