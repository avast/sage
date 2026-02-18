import type {
	PluginFinding,
	PluginInfo,
	PluginScanResult,
	Verdict,
	VersionCheckResult,
} from "@sage/core";
import { describe, expect, it } from "vitest";
import {
	formatBlockReason,
	formatStartupClean,
	formatThreatBanner,
	severityEmoji,
} from "../format.js";

function makePlugin(key = "test-plugin@marketplace"): PluginInfo {
	return { key, installPath: "/tmp/test", version: "1.0.0", lastUpdated: "" };
}

function makeFinding(overrides: Partial<PluginFinding> = {}): PluginFinding {
	return {
		threatId: "CLT-CMD-001",
		title: "Pipe to shell",
		severity: "high",
		confidence: 0.9,
		action: "block",
		artifact: "curl ... | bash",
		sourceFile: "setup.sh",
		...overrides,
	};
}

function makeVerdict(overrides: Partial<Verdict> = {}): Verdict {
	return {
		decision: "deny",
		category: "malware/bot, malware/backdoor",
		confidence: 1.0,
		severity: "critical",
		source: "url_check",
		artifacts: ["http://evil.com"],
		matchedThreatId: null,
		reasons: ["URL check: malicious"],
		...overrides,
	};
}

describe("severityEmoji", () => {
	it("returns alert emoji for critical/high", () => {
		expect(severityEmoji("critical")).toBe("🚨");
		expect(severityEmoji("high")).toBe("🚨");
		expect(severityEmoji("CRITICAL")).toBe("🚨");
	});

	it("returns warning emoji for medium/warn", () => {
		expect(severityEmoji("medium")).toBe("⚠️");
		expect(severityEmoji("warn")).toBe("⚠️");
		expect(severityEmoji("warning")).toBe("⚠️");
	});

	it("returns info emoji for low/info/unknown", () => {
		expect(severityEmoji("low")).toBe("ℹ️");
		expect(severityEmoji("info")).toBe("ℹ️");
		expect(severityEmoji("unknown")).toBe("ℹ️");
	});
});

describe("formatStartupClean", () => {
	it("includes version and clean status", () => {
		const msg = formatStartupClean("0.3.1");
		expect(msg).toContain("Sage v0.3.1");
		expect(msg).toContain("Gen Digital");
		expect(msg).toContain("No threats found");
		expect(msg).toContain("🛡️");
		expect(msg).toContain("✅");
	});

	it("appends update notice when update is available", () => {
		const vc: VersionCheckResult = {
			currentVersion: "0.4.0",
			latestVersion: "0.5.0",
			updateAvailable: true,
		};
		const msg = formatStartupClean("0.4.0", vc);
		expect(msg).toContain("No threats found");
		expect(msg).toContain("Update available");
		expect(msg).toContain("v0.4.0");
		expect(msg).toContain("v0.5.0");
		expect(msg).toContain("github.com/avast/sage");
	});

	it("does not append update notice when up to date", () => {
		const vc: VersionCheckResult = {
			currentVersion: "0.4.0",
			latestVersion: "0.4.0",
			updateAvailable: false,
		};
		const msg = formatStartupClean("0.4.0", vc);
		expect(msg).not.toContain("Update available");
	});

	it("does not append update notice when version check is null", () => {
		const msg = formatStartupClean("0.4.0", null);
		expect(msg).not.toContain("Update available");
	});
});

describe("formatThreatBanner", () => {
	it("renders single finding with structured layout", () => {
		const result: PluginScanResult = {
			plugin: makePlugin("cto-knowledge-base@cto-marketplace"),
			findings: [
				makeFinding({
					severity: "critical",
					threatId: "URL-CHECK",
					title: "Malicious URL (malware/misc)",
					sourceFile: "URL check",
				}),
			],
		};
		const msg = formatThreatBanner("0.3.1", [result]);
		expect(msg).toContain("🛡️ Sage v0.3.1 by Gen Digital — Threat Detected");
		expect(msg).toContain("━");
		expect(msg).toContain("🚨");
		expect(msg).toContain("cto-knowledge-base@cto-marketplace");
		expect(msg).toContain("Malicious URL (malware/misc)");
		expect(msg).toContain("CRITICAL");
		expect(msg).toContain("URL check");
	});

	it("renders multiple findings with blank line separator", () => {
		const results: PluginScanResult[] = [
			{ plugin: makePlugin("plugin-a@mp"), findings: [makeFinding({ severity: "critical" })] },
			{ plugin: makePlugin("plugin-b@mp"), findings: [makeFinding({ severity: "high" })] },
		];
		const msg = formatThreatBanner("0.3.1", results);
		expect(msg).toContain("plugin-a@mp");
		expect(msg).toContain("plugin-b@mp");
		// Blank line between groups
		expect(msg).toContain("\n\n");
	});

	it("skips low severity findings", () => {
		const result: PluginScanResult = {
			plugin: makePlugin(),
			findings: [makeFinding({ severity: "low" })],
		};
		const msg = formatThreatBanner("0.3.1", [result]);
		expect(msg).not.toContain("Plugin");
	});

	it("includes artifact when present", () => {
		const result: PluginScanResult = {
			plugin: makePlugin(),
			findings: [makeFinding({ severity: "critical", artifact: "http://evil.com/payload" })],
		};
		const msg = formatThreatBanner("0.3.1", [result]);
		expect(msg).toContain("Artifact");
		expect(msg).toContain("http://evil.com/payload");
	});

	it("omits artifact line when empty", () => {
		const result: PluginScanResult = {
			plugin: makePlugin(),
			findings: [makeFinding({ severity: "critical", artifact: "" })],
		};
		const msg = formatThreatBanner("0.3.1", [result]);
		expect(msg).not.toContain("Artifact");
	});

	it("caps findings at 5 per plugin", () => {
		const findings = Array.from({ length: 8 }, (_, i) =>
			makeFinding({ threatId: `CLT-${i}`, severity: "high" }),
		);
		const result: PluginScanResult = { plugin: makePlugin(), findings };
		const msg = formatThreatBanner("0.3.1", [result]);
		expect(msg).toContain("... and 3 more");
	});

	it("appends update notice when update is available", () => {
		const result: PluginScanResult = {
			plugin: makePlugin(),
			findings: [makeFinding({ severity: "critical" })],
		};
		const vc: VersionCheckResult = {
			currentVersion: "0.4.0",
			latestVersion: "0.5.0",
			updateAvailable: true,
		};
		const msg = formatThreatBanner("0.4.0", [result], vc);
		expect(msg).toContain("Threat Detected");
		expect(msg).toContain("Update available");
		expect(msg).toContain("v0.5.0");
	});

	it("does not append update notice when up to date", () => {
		const result: PluginScanResult = {
			plugin: makePlugin(),
			findings: [makeFinding({ severity: "critical" })],
		};
		const vc: VersionCheckResult = {
			currentVersion: "0.4.0",
			latestVersion: "0.4.0",
			updateAvailable: false,
		};
		const msg = formatThreatBanner("0.4.0", [result], vc);
		expect(msg).not.toContain("Update available");
	});
});

describe("formatBlockReason", () => {
	it("renders deny verdict with structured details", () => {
		const msg = formatBlockReason(makeVerdict());
		expect(msg).toContain("🚨");
		expect(msg).toContain("URL check: malicious");
		expect(msg).toContain("Blocked");
		expect(msg).toContain("http://evil.com");
		// Deny banner is details-only (branding in permissionDecisionReason)
		expect(msg).not.toContain("Sage by Gen Digital");
		expect(msg).not.toContain("━");
	});

	it("renders ask verdict as Suspicious Activity with artifact", () => {
		const msg = formatBlockReason(
			makeVerdict({
				decision: "ask",
				severity: "warning",
				reasons: ["Overly permissive file permissions"],
				artifacts: ["/etc/shadow"],
			}),
		);
		expect(msg).toContain("Suspicious Activity Detected");
		expect(msg).toContain("⚠️");
		expect(msg).toContain("Requires confirmation");
		expect(msg).toContain("/etc/shadow");
		expect(msg).toContain("━");
	});

	it("falls back to category when no reasons", () => {
		const msg = formatBlockReason(makeVerdict({ reasons: [] }));
		expect(msg).toContain("malware/bot, malware/backdoor");
	});

	it("renders multiple artifacts", () => {
		const msg = formatBlockReason(
			makeVerdict({
				artifacts: ["http://evil.com", "http://also-evil.com"],
			}),
		);
		expect(msg).toContain("http://evil.com");
		expect(msg).toContain("http://also-evil.com");
	});
});
