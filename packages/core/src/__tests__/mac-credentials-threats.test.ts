import { beforeAll, describe, expect, it } from "vitest";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchCommand = createMatcher("command");

describe("macOS credential threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	// --- Keychain extraction (CLT-MAC-CRED-001..002) ---

	it("detects security find-generic-password -w (001)", () => {
		expect(
			matchCommand(engine, "security find-generic-password -wa 'Chrome Safe Storage'"),
		).toContain("CLT-MAC-CRED-001");
	});

	it("detects security find-internet-password -w (002)", () => {
		expect(matchCommand(engine, "security find-internet-password -wa user@example.com")).toContain(
			"CLT-MAC-CRED-002",
		);
	});

	// --- Keychain dump (CLT-MAC-CRED-003) ---

	it("detects security dump-keychain (003)", () => {
		expect(matchCommand(engine, "security dump-keychain -d login.keychain")).toContain(
			"CLT-MAC-CRED-003",
		);
	});

	// --- Keychain unlock with password (CLT-MAC-CRED-004) ---

	it("detects security unlock-keychain -p (004)", () => {
		expect(
			matchCommand(engine, "security unlock-keychain -p 'password123' login.keychain"),
		).toContain("CLT-MAC-CRED-004");
	});

	// --- Keychain export (CLT-MAC-CRED-005) ---

	it("detects security export -k (005)", () => {
		expect(matchCommand(engine, "security export -k login.keychain -o /tmp/keys.pem")).toContain(
			"CLT-MAC-CRED-005",
		);
	});

	// --- Keychain deletion (CLT-MAC-CRED-006) ---

	it("detects security delete-keychain (006)", () => {
		expect(matchCommand(engine, "security delete-keychain login.keychain")).toContain(
			"CLT-MAC-CRED-006",
		);
	});

	// --- Directory Services auth data read (CLT-MAC-CRED-007) ---

	it("detects dscl -read AuthenticationAuthority (007)", () => {
		expect(matchCommand(engine, "dscl . -read /Users/admin AuthenticationAuthority")).toContain(
			"CLT-MAC-CRED-007",
		);
	});

	it("detects dscl -read ShadowHash (007)", () => {
		expect(matchCommand(engine, "dscl . -read /Users/admin ShadowHashData")).toContain(
			"CLT-MAC-CRED-007",
		);
	});

	// --- Direct keychain DB access (CLT-MAC-CRED-008) ---

	it("detects sqlite3 keychain access (008)", () => {
		expect(matchCommand(engine, "sqlite3 ~/Library/Keychains/login.keychain-db")).toContain(
			"CLT-MAC-CRED-008",
		);
	});

	// --- Negative cases ---

	it("does not match security list-keychains (harmless)", () => {
		const ids = matchCommand(engine, "security list-keychains");
		expect(ids.filter((id) => id.startsWith("CLT-MAC-CRED"))).toEqual([]);
	});

	it("does not match security find-generic-password without -w (no extraction)", () => {
		const ids = matchCommand(engine, "security find-generic-password -l 'Wi-Fi'");
		expect(ids.filter((id) => id === "CLT-MAC-CRED-001")).toEqual([]);
	});

	it("does not match dscl -read without auth data", () => {
		const ids = matchCommand(engine, "dscl . -read /Users/admin RealName");
		expect(ids.filter((id) => id === "CLT-MAC-CRED-007")).toEqual([]);
	});
});
