import type { PluginFinding, PluginInfo, PluginScanResult, VersionCheckResult } from "@sage/core";
import { describe, expect, it } from "vitest";
import { formatStartupClean, formatThreatBanner } from "../format.js";
import { formatFindings } from "../session-start.js";

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

describe("formatFindings (legacy)", () => {
	it("includes threat details", () => {
		const result: PluginScanResult = {
			plugin: makePlugin(),
			findings: [makeFinding()],
		};
		const msg = formatFindings([result]);
		expect(msg).toContain("CLT-CMD-001");
		expect(msg).toContain("HIGH");
		expect(msg).toContain("Pipe to shell");
		expect(msg).toContain("setup.sh");
		expect(msg).toContain("test-plugin@marketplace");
	});

	it("caps at five findings per plugin", () => {
		const findings = Array.from({ length: 8 }, (_, i) =>
			makeFinding({ threatId: `CLT-CMD-${String(i).padStart(3, "0")}`, sourceFile: `file${i}.sh` }),
		);
		const result: PluginScanResult = { plugin: makePlugin(), findings };
		const msg = formatFindings([result]);
		expect(msg).toContain("... and 3 more");
		expect(msg).toContain("CLT-CMD-000");
		expect(msg).toContain("CLT-CMD-004");
		expect(msg).not.toContain("CLT-CMD-005");
	});

	it("returns empty string for empty findings", () => {
		const result: PluginScanResult = { plugin: makePlugin(), findings: [] };
		expect(formatFindings([result])).toBe("");
	});

	it("skips low severity findings", () => {
		const result: PluginScanResult = {
			plugin: makePlugin(),
			findings: [makeFinding({ severity: "low" })],
		};
		expect(formatFindings([result])).toBe("");
	});

	it("formats multiple plugins", () => {
		const r1: PluginScanResult = {
			plugin: makePlugin("plugin-a@marketplace"),
			findings: [makeFinding({ threatId: "CLT-A-001" })],
		};
		const r2: PluginScanResult = {
			plugin: makePlugin("plugin-b@marketplace"),
			findings: [makeFinding({ threatId: "CLT-B-001" })],
		};
		const msg = formatFindings([r1, r2]);
		expect(msg).toContain("plugin-a@marketplace");
		expect(msg).toContain("plugin-b@marketplace");
		expect(msg).toContain("CLT-A-001");
		expect(msg).toContain("CLT-B-001");
		expect(msg).toContain("\n");
	});
});

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
