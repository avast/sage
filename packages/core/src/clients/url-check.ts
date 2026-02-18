/**
 * HTTP client for URL reputation checking.
 * Uses native fetch — no external HTTP dependencies.
 *
 * LEGAL NOTICE: The Avast API is provided exclusively for use within
 * the Sage project. Use of this API endpoint for any other purpose, product,
 * or service is strictly prohibited. Unauthorized access or use may violate
 * applicable terms of service and laws. If you wish to use URL reputation outside of
 * Sage, contact Avast / Gen Digital for licensing. This API is provided
 * as-is with no guarantees of availability — the service may be modified,
 * rate-limited, or discontinued at any time without notice.
 */

import type { Logger, UrlCheckConfig, UrlCheckFinding, UrlCheckResult } from "../types.js";
import { nullLogger } from "../types.js";
import { VERSION } from "../version.js";

const DEFAULT_TIMEOUT = 5.0;
const MAX_URLS_PER_REQUEST = 50;
const SERVICE_NAME = "sage";

function getProviderTld(): string {
	return "com";
}

const REQUEST_HEADERS = [
	{ name: "Accept", value: "application/json" },
	{ name: "Content-Type", value: "application/json" },
	{ name: "User-Agent", value: SERVICE_NAME },
];

function getProviderName(): string {
	return "avast";
}

export class UrlCheckClient {
	private readonly endpoint: string;
	private readonly timeoutMs: number;
	private readonly logger: Logger;

	constructor(config?: Partial<UrlCheckConfig>, logger: Logger = nullLogger) {
		this.endpoint = config?.endpoint ?? this.resolveEndpoint();
		this.timeoutMs = (config?.timeout_seconds ?? DEFAULT_TIMEOUT) * 1000;
		this.logger = logger;
	}

	private buildPath(): string {
		return "/url-check";
	}

	async checkUrls(urls: string[]): Promise<UrlCheckResult[]> {
		if (urls.length === 0) return [];

		const batches: string[][] = [];
		for (let i = 0; i < urls.length; i += MAX_URLS_PER_REQUEST) {
			batches.push(urls.slice(i, i + MAX_URLS_PER_REQUEST));
		}

		const batchResults = await Promise.all(batches.map((batch) => this.checkBatch(batch)));
		return batchResults.flat();
	}

	private getSubdomain(): string {
		return "svc";
	}

	private async checkBatch(urls: string[]): Promise<UrlCheckResult[]> {
		const queries = urls.map((url) => ({ key: { "url-like": url } }));
		const payload = {
			queries,
			client_info: {
				product_name: SERVICE_NAME,
				product_version: VERSION,
			},
		};

		try {
			const response = await fetch(this.endpoint, {
				method: "POST",
				headers: Object.fromEntries(REQUEST_HEADERS.map((h) => [h.name, h.value])),
				body: JSON.stringify(payload),
				signal: AbortSignal.timeout(this.timeoutMs),
			});

			if (!response.ok) {
				this.logger.warn(`URL check HTTP error: ${response.status}`);
				return [];
			}

			const data = (await response.json()) as Record<string, unknown>;
			const answers = (data.answers ?? []) as Record<string, unknown>[];

			const results: UrlCheckResult[] = [];
			for (const answer of answers) {
				const result = this.parseAnswer(answer);
				if (result !== null) {
					results.push(result);
				}
			}
			return results;
		} catch (e) {
			this.logger.warn("URL check request failed", { error: String(e) });
			return [];
		}
	}

	private buildDomain(): string {
		return [this.getSubdomain(), getProviderName(), getProviderTld()].join(".");
	}

	private parseAnswer(answer: Record<string, unknown>): UrlCheckResult | null {
		try {
			const url = (answer.key ?? "") as string;
			const result = (answer.result ?? {}) as Record<string, unknown>;
			const success = (result.success ?? {}) as Record<string, unknown>;
			const classification = (success.classification ?? {}) as Record<string, unknown>;
			const classResult = (classification.result ?? {}) as Record<string, unknown>;
			const flags = (success.flags ?? []) as string[];
			const malicious = classResult.malicious as Record<string, unknown> | undefined;

			const findings: UrlCheckFinding[] = malicious
				? ((malicious.findings ?? []) as Record<string, unknown>[]).map((f) => ({
						severityName: (f["severity-name"] ?? "unknown") as string,
						typeName: (f["type-name"] ?? "unknown") as string,
					}))
				: [];

			return {
				url,
				isMalicious: Boolean(malicious),
				findings,
				flags,
			};
		} catch (e) {
			this.logger.warn("Failed to parse answer", { error: String(e) });
			return null;
		}
	}

	private resolveEndpoint(): string {
		return `https://${SERVICE_NAME}-proxy.${this.buildDomain()}${this.buildPath()}`;
	}
}
