import type { PluginFinding, PluginInfo, PluginScanResult, VersionCheckResult } from "@sage/core";
import { formatStartupClean, formatThreatBanner } from "@sage/core";
import { describe, expect, it } from "vitest";

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

describe("visual formatters integration", () => {
	it("formatStartupClean produces branded one-liner", () => {
		const msg = formatStartupClean("0.3.1");
		expect(msg).toMatch(/Sage v0\.3\.1.*Gen Digital.*No threats found/);
	});

	it("formatThreatBanner produces structured output for session-start", () => {
		const result: PluginScanResult = {
			plugin: makePlugin("evil-plugin@marketplace"),
			findings: [makeFinding({ severity: "critical" })],
		};
		const msg = formatThreatBanner("0.3.1", [result]);
		expect(msg).toContain("Threat Detected");
		expect(msg).toContain("evil-plugin@marketplace");
		expect(msg).toContain("━");
	});

	it("formatStartupClean includes update notice when available", () => {
		const vc: VersionCheckResult = {
			currentVersion: "0.3.1",
			latestVersion: "0.5.0",
			updateAvailable: true,
		};
		const msg = formatStartupClean("0.3.1", vc);
		expect(msg).toMatch(/No threats found/);
		expect(msg).toContain("Update available");
		expect(msg).toContain("v0.5.0");
	});
});
