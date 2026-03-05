import { beforeAll, describe, expect, it } from "vitest";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchCommand = createMatcher("command");

describe("macOS persistence threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	// --- LaunchAgent/LaunchDaemon (CLT-MAC-PERSIST-001, migrated from CLT-PERSIST-004) ---

	it("detects cp to LaunchAgents plist (001)", () => {
		expect(
			matchCommand(engine, "cp evil.plist ~/Library/LaunchAgents/com.evil.agent.plist"),
		).toContain("CLT-MAC-PERSIST-001");
	});

	it("detects cp to LaunchDaemons plist (001)", () => {
		expect(
			matchCommand(engine, "cp evil.plist /Library/LaunchDaemons/com.evil.daemon.plist"),
		).toContain("CLT-MAC-PERSIST-001");
	});

	// --- Login Items via osascript (CLT-MAC-PERSIST-002) ---

	it("detects osascript login item (002)", () => {
		expect(
			matchCommand(
				engine,
				'osascript -e \'tell application "System Events" to make login item at end with properties {path:"/tmp/evil.app"}\'',
			),
		).toContain("CLT-MAC-PERSIST-002");
	});

	// --- Login window manipulation (CLT-MAC-PERSIST-003) ---

	it("detects defaults write loginwindow LoginHook (003)", () => {
		expect(
			matchCommand(engine, "defaults write com.apple.loginwindow LoginHook /tmp/hook.sh"),
		).toContain("CLT-MAC-PERSIST-003");
	});

	it("detects defaults write loginwindow AutoLaunch (003)", () => {
		expect(
			matchCommand(
				engine,
				"defaults write com.apple.loginwindow AutoLaunchedApplicationDictionary -array-add",
			),
		).toContain("CLT-MAC-PERSIST-003");
	});

	// --- Authorization plugin (CLT-MAC-PERSIST-004) ---

	it("detects SecurityAgentPlugins drop (004)", () => {
		expect(
			matchCommand(engine, "cp evil.bundle /Library/Security/SecurityAgentPlugins/evil.bundle"),
		).toContain("CLT-MAC-PERSIST-004");
	});

	// --- Periodic script (CLT-MAC-PERSIST-005) ---

	it("detects periodic daily script (005)", () => {
		expect(matchCommand(engine, "cp backdoor.sh /etc/periodic/daily/999.backdoor")).toContain(
			"CLT-MAC-PERSIST-005",
		);
	});

	it("detects periodic weekly script (005)", () => {
		expect(matchCommand(engine, "cp evil.sh /etc/periodic/weekly/evil")).toContain(
			"CLT-MAC-PERSIST-005",
		);
	});

	// at job scheduling moved to persistence-threats.test.ts (CLT-PERSIST-008)

	// --- Emond rules (CLT-MAC-PERSIST-006) ---

	it("detects emond rules drop (006)", () => {
		expect(matchCommand(engine, "cp evil.plist /etc/emond.d/rules/evil.plist")).toContain(
			"CLT-MAC-PERSIST-006",
		);
	});

	// --- DYLD_INSERT_LIBRARIES (CLT-MAC-PERSIST-007) ---

	it("detects DYLD_INSERT_LIBRARIES (007)", () => {
		expect(
			matchCommand(
				engine,
				"DYLD_INSERT_LIBRARIES=/tmp/evil.dylib /Applications/Target.app/Contents/MacOS/Target",
			),
		).toContain("CLT-MAC-PERSIST-007");
	});

	// --- Folder Actions (CLT-MAC-PERSIST-008) ---

	it("detects folder action via osascript (008)", () => {
		expect(
			matchCommand(
				engine,
				'osascript -e \'tell application "System Events" to set folder action scripts of folder "/tmp" to {POSIX file "/tmp/evil.scpt"}\'',
			),
		).toContain("CLT-MAC-PERSIST-008");
	});

	// --- launchctl load (CLT-MAC-PERSIST-009) ---

	it("detects launchctl load (009)", () => {
		expect(
			matchCommand(engine, "launchctl load ~/Library/LaunchAgents/com.evil.agent.plist"),
		).toContain("CLT-MAC-PERSIST-009");
	});

	it("detects launchctl bootstrap (009)", () => {
		expect(matchCommand(engine, "launchctl bootstrap gui/501 /tmp/evil.plist")).toContain(
			"CLT-MAC-PERSIST-009",
		);
	});

	// --- Negative cases ---

	it("does not match launchctl list (harmless)", () => {
		const ids = matchCommand(engine, "launchctl list");
		expect(ids.filter((id) => id.startsWith("CLT-MAC-PERSIST"))).toEqual([]);
	});

	it("does not match defaults read loginwindow (harmless read)", () => {
		const ids = matchCommand(engine, "defaults read com.apple.loginwindow");
		expect(ids.filter((id) => id === "CLT-MAC-PERSIST-003")).toEqual([]);
	});

	// at -l negative case moved to persistence-threats.test.ts
});
