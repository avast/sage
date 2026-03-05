import { beforeAll, describe, expect, it } from "vitest";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchCommand = createMatcher("command");

describe("Windows credential threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	// --- Positive cases ---

	it("detects cmdkey /add (WIN-CRED-001)", () => {
		expect(matchCommand(engine, "cmdkey /add:server /user:admin /pass:secret123")).toContain(
			"CLT-WIN-CRED-001",
		);
	});

	it("detects ConvertTo-SecureString -AsPlainText (WIN-CRED-002)", () => {
		expect(matchCommand(engine, "ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force")).toContain(
			"CLT-WIN-CRED-002",
		);
	});

	it("detects type .env (WIN-CRED-003)", () => {
		expect(matchCommand(engine, "type .env")).toContain("CLT-WIN-CRED-003");
	});

	it("detects Get-Content .credentials (WIN-CRED-003)", () => {
		expect(matchCommand(engine, "Get-Content C:\\Users\\user\\.credentials")).toContain(
			"CLT-WIN-CRED-003",
		);
	});

	it("detects [Environment]::SetEnvironmentVariable with Password (WIN-CRED-004)", () => {
		expect(
			matchCommand(
				engine,
				"[Environment]::SetEnvironmentVariable('DB_Password', 'secret', 'User')",
			),
		).toContain("CLT-WIN-CRED-004");
	});

	it("detects $env:ApiKey assignment (WIN-CRED-005)", () => {
		expect(matchCommand(engine, "$env:ApiKey = 'sk-1234567890'")).toContain("CLT-WIN-CRED-005");
	});

	it("detects $env:Password assignment (WIN-CRED-005)", () => {
		expect(matchCommand(engine, "$env:Password = 'hunter2'")).toContain("CLT-WIN-CRED-005");
	});

	it("detects mimikatz (WIN-CRED-006)", () => {
		expect(matchCommand(engine, "mimikatz.exe")).toContain("CLT-WIN-CRED-006");
	});

	it("detects sekurlsa:: (WIN-CRED-006)", () => {
		expect(matchCommand(engine, "sekurlsa::logonpasswords")).toContain("CLT-WIN-CRED-006");
	});

	// --- Negative cases ---

	it("does not match type for normal file", () => {
		const ids = matchCommand(engine, "type readme.txt");
		expect(ids.filter((id) => id.startsWith("CLT-WIN-CRED"))).toEqual([]);
	});

	it("does not match $env:PATH assignment", () => {
		const ids = matchCommand(engine, "$env:PATH = 'C:\\bin;' + $env:PATH");
		expect(ids.filter((id) => id.startsWith("CLT-WIN-CRED"))).toEqual([]);
	});

	it("does not match Get-Content for normal file", () => {
		const ids = matchCommand(engine, "Get-Content C:\\logs\\app.log");
		expect(ids.filter((id) => id.startsWith("CLT-WIN-CRED"))).toEqual([]);
	});

	// --- Registry hive export (CRED-007) ---

	it("detects reg save HKLM\\SAM (WIN-CRED-007)", () => {
		expect(matchCommand(engine, "reg save HKLM\\SAM C:\\temp\\sam.hiv")).toContain(
			"CLT-WIN-CRED-007",
		);
	});

	it("detects reg save HKLM\\SYSTEM (WIN-CRED-007)", () => {
		expect(matchCommand(engine, "reg save HKLM\\SYSTEM C:\\temp\\system.hiv")).toContain(
			"CLT-WIN-CRED-007",
		);
	});

	it("detects reg save HKLM\\SECURITY (WIN-CRED-007)", () => {
		expect(matchCommand(engine, "reg save HKLM\\SECURITY C:\\temp\\security.hiv")).toContain(
			"CLT-WIN-CRED-007",
		);
	});

	it("does not match reg save for other hives (WIN-CRED-007)", () => {
		const ids = matchCommand(engine, "reg save HKCU\\Software C:\\temp\\software.hiv");
		expect(ids.filter((id) => id === "CLT-WIN-CRED-007")).toEqual([]);
	});

	// --- LSASS credential dumping (CRED-008) ---

	it("detects procdump lsass (WIN-CRED-008)", () => {
		expect(matchCommand(engine, "procdump -ma lsass.exe lsassdump.dmp")).toContain(
			"CLT-WIN-CRED-008",
		);
	});

	it("detects procdump64 lsass (WIN-CRED-008)", () => {
		expect(matchCommand(engine, "procdump64 -ma lsass.exe C:\\temp\\lsass.dmp")).toContain(
			"CLT-WIN-CRED-008",
		);
	});

	it("detects rundll32 comsvcs MiniDump (WIN-CRED-008)", () => {
		expect(
			matchCommand(
				engine,
				"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 672 C:\\temp\\lsass.dmp full",
			),
		).toContain("CLT-WIN-CRED-008");
	});

	it("does not match procdump for other processes (WIN-CRED-008)", () => {
		const ids = matchCommand(engine, "procdump -ma myapp.exe appdump.dmp");
		expect(ids.filter((id) => id === "CLT-WIN-CRED-008")).toEqual([]);
	});

	// --- WLAN password extraction (CRED-009) ---

	it("detects netsh wlan show profiles key=clear (WIN-CRED-009)", () => {
		expect(matchCommand(engine, "netsh wlan show profiles name=MyWifi key=clear")).toContain(
			"CLT-WIN-CRED-009",
		);
	});

	it("does not match netsh wlan show profiles without key=clear (WIN-CRED-009)", () => {
		const ids = matchCommand(engine, "netsh wlan show profiles");
		expect(ids.filter((id) => id === "CLT-WIN-CRED-009")).toEqual([]);
	});

	// --- Additional FP coverage ---

	it("does not match cmdkey /list (001 FP)", () => {
		const ids = matchCommand(engine, "cmdkey /list");
		expect(ids).not.toContain("CLT-WIN-CRED-001");
	});

	it("does not match ConvertTo-SecureString without -AsPlainText (002 FP)", () => {
		const ids = matchCommand(engine, "ConvertTo-SecureString (Read-Host -AsSecureString)");
		expect(ids).not.toContain("CLT-WIN-CRED-002");
	});

	it("does not match type for .txt file (003 FP)", () => {
		const ids = matchCommand(engine, "type config.txt");
		expect(ids).not.toContain("CLT-WIN-CRED-003");
	});

	it("does not match Get-Content for .log file (003 FP)", () => {
		const ids = matchCommand(engine, "Get-Content app.log");
		expect(ids).not.toContain("CLT-WIN-CRED-003");
	});

	it("does not match [Environment]::GetEnvironmentVariable (004 FP)", () => {
		const ids = matchCommand(engine, "[Environment]::GetEnvironmentVariable('PATH')");
		expect(ids).not.toContain("CLT-WIN-CRED-004");
	});

	it("does not match $env:GOPATH assignment (005 FP)", () => {
		const ids = matchCommand(engine, "$env:GOPATH = '/home/user/go'");
		expect(ids).not.toContain("CLT-WIN-CRED-005");
	});

	it("does not match $env:NODE_ENV assignment (005 FP)", () => {
		const ids = matchCommand(engine, "$env:NODE_ENV = 'production'");
		expect(ids).not.toContain("CLT-WIN-CRED-005");
	});

	it("does not match reg query HKLM\\SAM (007 FP)", () => {
		const ids = matchCommand(engine, "reg query HKLM\\SAM");
		expect(ids).not.toContain("CLT-WIN-CRED-007");
	});
});
