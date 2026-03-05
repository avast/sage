/**
 * Registry client for npm and PyPI.
 * Fetches package metadata (existence, hashes, release dates) — no tarball downloads.
 * Returns null on 404 or error (fail-open at client level).
 */

import type { Logger } from "../types.js";
import { nullLogger } from "../types.js";

const NPM_REGISTRY = "https://registry.npmjs.org";
const PYPI_REGISTRY = "https://pypi.org/pypi";
const DEFAULT_TIMEOUT = 5.0;

/** Package name validation — prevents SSRF via crafted names. */
const NPM_NAME_RE = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;
const PYPI_NAME_RE = /^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$/;

export interface PackageMetadata {
	name: string;
	resolvedVersion: string;
	latestHash: string;
	hashAlgorithm: "sha1" | "sha256";
	firstReleaseDate: Date | null;
	/** False when a specific version was requested but not found in the registry. */
	requestedVersionFound: boolean;
}

export class RegistryClient {
	private readonly timeoutMs: number;
	private readonly logger: Logger;

	constructor(config?: { timeout_seconds?: number }, logger: Logger = nullLogger) {
		this.timeoutMs = (config?.timeout_seconds ?? DEFAULT_TIMEOUT) * 1000;
		this.logger = logger;
	}

	async getPackageMetadata(
		name: string,
		registry: "npm" | "pypi",
		version?: string,
	): Promise<PackageMetadata | null> {
		if (registry === "npm") return this.getNpmMetadata(name, version);
		return this.getPypiMetadata(name, version);
	}

	private async getNpmMetadata(name: string, version?: string): Promise<PackageMetadata | null> {
		if (!NPM_NAME_RE.test(name)) {
			this.logger.warn("Invalid npm package name rejected", { name });
			return null;
		}

		// Scoped packages: @scope/pkg → @scope%2fpkg in URL
		const encodedName = name.includes("/") ? `${name.split("/")[0]}%2f${name.split("/")[1]}` : name;
		const url = `${NPM_REGISTRY}/${encodedName}`;

		try {
			const response = await fetch(url, {
				signal: AbortSignal.timeout(this.timeoutMs),
			});

			if (response.status === 404) return null;
			if (!response.ok) {
				this.logger.warn(`npm registry HTTP error: ${response.status}`, { name });
				throw new Error(`npm registry HTTP ${response.status}`);
			}

			const data = (await response.json()) as Record<string, unknown>;
			return this.parseNpmResponse(name, data, version);
		} catch (e) {
			this.logger.warn("npm registry request failed", { name, error: String(e) });
			throw e;
		}
	}

	private parseNpmResponse(
		name: string,
		data: Record<string, unknown>,
		requestedVersion?: string,
	): PackageMetadata | null {
		try {
			const distTags = (data["dist-tags"] ?? {}) as Record<string, string>;
			const latestTag = distTags.latest;
			if (!latestTag) return null;

			const versions = (data.versions ?? {}) as Record<string, Record<string, unknown>>;
			// Resolve dist-tags (e.g. "latest", "next", "canary") to actual version strings
			const effectiveVersion =
				requestedVersion && distTags[requestedVersion]
					? distTags[requestedVersion]
					: requestedVersion;
			// Use requested version if specified and exists, otherwise fall back to latest
			const requestedVersionFound = !effectiveVersion || Boolean(versions[effectiveVersion]);
			const resolvedVersion =
				effectiveVersion && versions[effectiveVersion] ? effectiveVersion : latestTag;
			const resolvedVersionData = versions[resolvedVersion];
			if (!resolvedVersionData) return null;

			const dist = (resolvedVersionData.dist ?? {}) as Record<string, unknown>;
			const shasum = (dist.shasum ?? "") as string;
			const integrity = (dist.integrity ?? "") as string;

			// Prefer sha256 from integrity (format: "sha512-..." or "sha256-...")
			let latestHash = shasum;
			let hashAlgorithm: "sha1" | "sha256" = "sha1";
			if (integrity.startsWith("sha256-")) {
				// base64-encoded sha256
				latestHash = Buffer.from(integrity.slice(7), "base64").toString("hex");
				hashAlgorithm = "sha256";
			}

			// Find first release date from `time` field
			const time = (data.time ?? {}) as Record<string, string>;
			let firstReleaseDate: Date | null = null;
			const created = time.created;
			if (created) {
				firstReleaseDate = new Date(created);
			}

			return {
				name,
				resolvedVersion: resolvedVersion,
				latestHash,
				hashAlgorithm,
				firstReleaseDate,
				requestedVersionFound,
			};
		} catch (e) {
			this.logger.warn("Failed to parse npm response", { name, error: String(e) });
			return null;
		}
	}

	private async getPypiMetadata(name: string, version?: string): Promise<PackageMetadata | null> {
		if (!PYPI_NAME_RE.test(name)) {
			this.logger.warn("Invalid PyPI package name rejected", { name });
			return null;
		}

		const url = `${PYPI_REGISTRY}/${name}/json`;

		try {
			const response = await fetch(url, {
				signal: AbortSignal.timeout(this.timeoutMs),
			});

			if (response.status === 404) return null;
			if (!response.ok) {
				this.logger.warn(`PyPI registry HTTP error: ${response.status}`, { name });
				throw new Error(`PyPI registry HTTP ${response.status}`);
			}

			const data = (await response.json()) as Record<string, unknown>;
			return this.parsePypiResponse(name, data, version);
		} catch (e) {
			this.logger.warn("PyPI registry request failed", { name, error: String(e) });
			throw e;
		}
	}

	private parsePypiResponse(
		name: string,
		data: Record<string, unknown>,
		requestedVersion?: string,
	): PackageMetadata | null {
		try {
			const info = (data.info ?? {}) as Record<string, unknown>;
			const latestTag = (info.version ?? "") as string;
			if (!latestTag) return null;

			const releases = (data.releases ?? {}) as Record<string, Record<string, unknown>[]>;
			const requestedVersionFound =
				!requestedVersion || Boolean(releases[requestedVersion]?.length);
			const resolvedVersion =
				requestedVersion && releases[requestedVersion]?.length ? requestedVersion : latestTag;

			// Get hash from resolved version's first file
			let latestHash = "";
			const latestFiles = releases[resolvedVersion] ?? [];
			for (const file of latestFiles) {
				const digests = (file.digests ?? {}) as Record<string, string>;
				if (digests.sha256) {
					latestHash = digests.sha256;
					break;
				}
			}

			// Find first release date (earliest version upload)
			let firstReleaseDate: Date | null = null;
			for (const [, files] of Object.entries(releases)) {
				for (const file of files) {
					const uploadTime = file.upload_time_iso_8601 as string | undefined;
					if (uploadTime) {
						const date = new Date(uploadTime);
						if (!firstReleaseDate || date < firstReleaseDate) {
							firstReleaseDate = date;
						}
					}
				}
			}

			return {
				name,
				resolvedVersion: resolvedVersion,
				latestHash,
				hashAlgorithm: "sha256",
				firstReleaseDate,
				requestedVersionFound,
			};
		} catch (e) {
			this.logger.warn("Failed to parse PyPI response", { name, error: String(e) });
			return null;
		}
	}
}
