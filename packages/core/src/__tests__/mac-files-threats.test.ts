import { beforeAll, describe, expect, it } from "vitest";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchFilePath = createMatcher("file_path");

describe("macOS file path threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	// --- LaunchAgent/LaunchDaemon plist (CLT-MAC-FILE-001, migrated from CLT-FILE-005) ---

	it("detects LaunchAgents plist (001)", () => {
		expect(matchFilePath(engine, "~/Library/LaunchAgents/com.evil.agent.plist")).toContain(
			"CLT-MAC-FILE-001",
		);
	});

	it("detects LaunchDaemons plist (001)", () => {
		expect(matchFilePath(engine, "/Library/LaunchDaemons/com.evil.daemon.plist")).toContain(
			"CLT-MAC-FILE-001",
		);
	});

	it("detects system LaunchAgents plist (001)", () => {
		expect(matchFilePath(engine, "/System/Library/LaunchAgents/com.evil.plist")).toContain(
			"CLT-MAC-FILE-001",
		);
	});

	// --- TCC database (CLT-MAC-FILE-002) ---

	it("detects TCC.db write (002)", () => {
		expect(matchFilePath(engine, "/Library/Application Support/com.apple.TCC/TCC.db")).toContain(
			"CLT-MAC-FILE-002",
		);
	});

	// --- Authorization database (CLT-MAC-FILE-003) ---

	it("detects /etc/authorization write (003)", () => {
		expect(matchFilePath(engine, "/etc/authorization")).toContain("CLT-MAC-FILE-003");
	});

	it("detects /var/db/auth.db write (003)", () => {
		expect(matchFilePath(engine, "/var/db/auth.db")).toContain("CLT-MAC-FILE-003");
	});

	// --- Kernel extensions (CLT-MAC-FILE-004) ---

	it("detects kernel extension write (004)", () => {
		expect(matchFilePath(engine, "/Library/Extensions/evil.kext")).toContain("CLT-MAC-FILE-004");
	});

	it("detects system kernel extension write (004)", () => {
		expect(matchFilePath(engine, "/System/Library/Extensions/evil.kext")).toContain(
			"CLT-MAC-FILE-004",
		);
	});

	// --- SecurityAgentPlugins (CLT-MAC-FILE-005) ---

	it("detects SecurityAgentPlugins write (005)", () => {
		expect(matchFilePath(engine, "/Library/Security/SecurityAgentPlugins/evil.bundle")).toContain(
			"CLT-MAC-FILE-005",
		);
	});

	// --- Periodic scripts (CLT-MAC-FILE-006) ---

	it("detects periodic daily script write (006)", () => {
		expect(matchFilePath(engine, "/etc/periodic/daily/999.evil")).toContain("CLT-MAC-FILE-006");
	});

	it("detects periodic weekly script write (006)", () => {
		expect(matchFilePath(engine, "/etc/periodic/weekly/backdoor")).toContain("CLT-MAC-FILE-006");
	});

	// --- Emond rules (CLT-MAC-FILE-007) ---

	it("detects emond rules write (007)", () => {
		expect(matchFilePath(engine, "/etc/emond.d/rules/evil.plist")).toContain("CLT-MAC-FILE-007");
	});

	// --- Safari credential stores (CLT-MAC-FILE-008) ---

	it("detects Safari Cookies.binarycookies write (008)", () => {
		expect(matchFilePath(engine, "~/Library/Safari/Cookies.binarycookies")).toContain(
			"CLT-MAC-FILE-008",
		);
	});

	it("detects Safari LocalStorage write (008)", () => {
		expect(matchFilePath(engine, "~/Library/Safari/LocalStorage/evil.localstorage")).toContain(
			"CLT-MAC-FILE-008",
		);
	});

	// --- Managed Preferences (CLT-MAC-FILE-009) ---

	it("detects Managed Preferences write (009)", () => {
		expect(matchFilePath(engine, "/Library/Managed Preferences/com.evil.plist")).toContain(
			"CLT-MAC-FILE-009",
		);
	});

	// --- Keychain files (CLT-MAC-FILE-010) ---

	it("detects system Keychain file write (010)", () => {
		expect(matchFilePath(engine, "/Library/Keychains/System.keychain")).toContain(
			"CLT-MAC-FILE-010",
		);
	});

	// --- Negative cases ---

	it("does not match normal macOS app file", () => {
		const ids = matchFilePath(engine, "/Applications/Safari.app/Contents/Info.plist");
		expect(ids.filter((id) => id.startsWith("CLT-MAC-FILE"))).toEqual([]);
	});

	it("does not match user Documents folder", () => {
		const ids = matchFilePath(engine, "~/Documents/notes.txt");
		expect(ids.filter((id) => id.startsWith("CLT-MAC-FILE"))).toEqual([]);
	});

	it("does not match normal Library file", () => {
		const ids = matchFilePath(engine, "~/Library/Preferences/com.apple.Finder.plist");
		expect(ids.filter((id) => id.startsWith("CLT-MAC-FILE"))).toEqual([]);
	});
});
