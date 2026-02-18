/**
 * Heuristics engine — matches artifacts against loaded threat definitions.
 */

import { extractUrls } from "./extractors.js";
import { extractDomain, isTrustedDomain } from "./trusted-domains.js";
import type { Artifact, HeuristicMatch, Threat, TrustedDomain } from "./types.js";

/** Threat IDs where trusted installer domains suppress matches. */
const TRUSTED_DOMAIN_SUPPRESSIBLE = new Set([
	"CLT-CMD-001",
	"CLT-CMD-002",
	"CLT-SUPPLY-001",
	"CLT-SUPPLY-004",
]);

export class HeuristicsEngine {
	private readonly threatMap: Map<string, Threat[]> = new Map();
	private readonly trustedDomains: TrustedDomain[];

	constructor(threats: Threat[], trustedDomains?: TrustedDomain[]) {
		this.trustedDomains = trustedDomains ?? [];

		for (const threat of threats) {
			for (const matchType of threat.matchOn) {
				// Route domain threats to url artifact type
				const artifactType = matchType === "domain" ? "url" : matchType;
				const existing = this.threatMap.get(artifactType);
				if (existing) {
					existing.push(threat);
				} else {
					this.threatMap.set(artifactType, [threat]);
				}
			}
		}
	}

	private isSuppressedByTrustedDomain(match: HeuristicMatch): boolean {
		if (this.trustedDomains.length === 0) return false;
		if (!TRUSTED_DOMAIN_SUPPRESSIBLE.has(match.threat.id)) return false;

		const urls = extractUrls(match.artifact);
		for (const url of urls) {
			const domain = extractDomain(url);
			if (domain && isTrustedDomain(domain, this.trustedDomains)) {
				return true;
			}
		}
		return false;
	}

	match(artifacts: Artifact[]): HeuristicMatch[] {
		const matches: HeuristicMatch[] = [];

		for (const artifact of artifacts) {
			const threats = this.threatMap.get(artifact.type) ?? [];
			for (const threat of threats) {
				const m = threat.compiledPattern.exec(artifact.value);
				if (m) {
					matches.push({
						threat,
						artifact: artifact.value,
						matchValue: m[0],
					});
				}
			}
		}

		// Post-filter: suppress matches for trusted installer domains
		if (this.trustedDomains.length > 0) {
			return matches.filter((m) => !this.isSuppressedByTrustedDomain(m));
		}

		return matches;
	}
}
