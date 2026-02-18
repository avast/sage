/**
 * Version check — fetches latest Sage version from the GitHub repository
 * and compares it against the locally running version.
 * Fail-open: returns null on any error so it never blocks startup.
 */

import type { Logger } from "./types.js";
import { nullLogger } from "./types.js";

const GITHUB_RAW_URL =
	"https://raw.githubusercontent.com/avast/sage/main/packages/core/package.json";

const DEFAULT_TIMEOUT_MS = 5_000;

export interface VersionCheckResult {
	currentVersion: string;
	latestVersion: string;
	updateAvailable: boolean;
}

/**
 * Compare two semver strings (major.minor.patch).
 * Returns true if `latest` is newer than `current`.
 */
export function isNewerVersion(current: string, latest: string): boolean {
	const parse = (v: string): number[] =>
		v
			.replace(/^v/, "")
			.split(".")
			.map((n) => Number.parseInt(n, 10) || 0);

	const cur = parse(current);
	const lat = parse(latest);

	for (let i = 0; i < 3; i++) {
		const c = cur[i] ?? 0;
		const l = lat[i] ?? 0;
		if (l > c) return true;
		if (l < c) return false;
	}
	return false;
}

/**
 * Fetch the latest published version from the GitHub repository.
 * Returns null on any failure (network, parse, timeout).
 */
export async function checkForUpdate(
	currentVersion: string,
	logger: Logger = nullLogger,
	timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<VersionCheckResult | null> {
	if (currentVersion === "dev") {
		logger.debug("Skipping version check for dev build");
		return null;
	}

	try {
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), timeoutMs);

		const response = await fetch(GITHUB_RAW_URL, {
			signal: controller.signal,
			headers: { Accept: "application/json" },
		});
		clearTimeout(timer);

		if (!response.ok) {
			logger.debug(`Version check HTTP ${response.status}`);
			return null;
		}

		const body = (await response.json()) as Record<string, unknown>;
		const latestVersion = body.version;
		if (typeof latestVersion !== "string") {
			logger.debug("Version check: no version field in response");
			return null;
		}

		return {
			currentVersion,
			latestVersion,
			updateAvailable: isNewerVersion(currentVersion, latestVersion),
		};
	} catch (err) {
		logger.debug(`Version check failed: ${err}`);
		return null;
	}
}
