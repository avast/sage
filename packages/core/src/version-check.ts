/**
 * Version check — POSTs environment context to the Sage version-check
 * endpoint to receive platform-aware update guidance.
 * Fail-open: returns null on any error so it never blocks startup.
 */

import { release } from "node:os";
import { resolveEndpoint } from "./clients/url-check.js";
import type { AgentRuntime, Logger } from "./types.js";
import { nullLogger } from "./types.js";

const DEFAULT_TIMEOUT_MS = 5_000;

/** Environment context sent alongside the version check for platform-aware responses. */
export interface VersionCheckContext {
	agentRuntime: AgentRuntime;
	agentRuntimeVersion?: string;
	iid?: string;
}

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
 * Fetch the latest published version from the version-check endpoint.
 * Sends environment context so the backend can serve platform-specific guidance.
 * Returns null on any failure (network, parse, timeout).
 */
export async function checkForUpdate(
	currentVersion: string,
	logger: Logger = nullLogger,
	timeoutMs: number = DEFAULT_TIMEOUT_MS,
	context?: VersionCheckContext,
): Promise<VersionCheckResult | null> {
	if (currentVersion === "dev") {
		logger.debug("Skipping version check for dev build");
		return null;
	}

	try {
		const response = await fetch(resolveEndpoint("/v1/version-check"), {
			method: "POST",
			signal: AbortSignal.timeout(timeoutMs),
			headers: {
				Accept: "application/json",
				"Content-Type": "application/json",
			},
			body: JSON.stringify({
				sage_version: currentVersion,
				agent_runtime: context?.agentRuntime,
				agent_runtime_version: context?.agentRuntimeVersion,
				os: process.platform,
				os_version: release(),
				arch: process.arch,
				iid: context?.iid,
			}),
		});

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
