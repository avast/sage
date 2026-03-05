import { beforeAll, describe, expect, it } from "vitest";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchCommand = createMatcher("command");

describe("Windows persistence threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	// --- Positive cases ---

	it("detects reg add Run key (WIN-PERSIST-001)", () => {
		expect(
			matchCommand(
				engine,
				'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ /v evil /d "C:\\evil.exe"',
			),
		).toContain("CLT-WIN-PERSIST-001");
	});

	it("detects reg add RunOnce key (WIN-PERSIST-001)", () => {
		expect(
			matchCommand(
				engine,
				"reg ADD HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\ /v payload /d cmd.exe",
			),
		).toContain("CLT-WIN-PERSIST-001");
	});

	it("detects sc create (WIN-PERSIST-002)", () => {
		expect(matchCommand(engine, 'sc create evilsvc binpath= "C:\\evil.exe"')).toContain(
			"CLT-WIN-PERSIST-002",
		);
	});

	it("detects sc config (WIN-PERSIST-002)", () => {
		expect(matchCommand(engine, 'sc config legitsvc binpath= "C:\\evil.exe"')).toContain(
			"CLT-WIN-PERSIST-002",
		);
	});

	it("detects schtasks /create (WIN-PERSIST-003)", () => {
		expect(
			matchCommand(engine, 'schtasks /Create /tn "EvilTask" /tr "C:\\evil.exe" /sc onlogon'),
		).toContain("CLT-WIN-PERSIST-003");
	});

	it("detects New-ScheduledTask (WIN-PERSIST-004)", () => {
		expect(
			matchCommand(
				engine,
				"New-ScheduledTask -Action (New-ScheduledTaskAction -Execute 'evil.exe')",
			),
		).toContain("CLT-WIN-PERSIST-004");
	});

	it("detects Set-ItemProperty Run key (WIN-PERSIST-005)", () => {
		expect(
			matchCommand(
				engine,
				"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\' -Name evil -Value 'C:\\evil.exe'",
			),
		).toContain("CLT-WIN-PERSIST-005");
	});

	it("detects New-Service (WIN-PERSIST-006)", () => {
		expect(
			matchCommand(engine, "New-Service -Name evilsvc -BinaryPathName 'C:\\evil.exe'"),
		).toContain("CLT-WIN-PERSIST-006");
	});

	it("detects Startup folder path (WIN-PERSIST-007)", () => {
		expect(
			matchCommand(
				engine,
				'copy evil.exe "C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.exe"',
			),
		).toContain("CLT-WIN-PERSIST-007");
	});

	// --- Negative cases ---

	it("does not match reg query", () => {
		const ids = matchCommand(
			engine,
			"reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		);
		expect(ids.filter((id) => id.startsWith("CLT-WIN-PERSIST"))).toEqual([]);
	});

	it("does not match sc query", () => {
		const ids = matchCommand(engine, "sc query wuauserv");
		expect(ids.filter((id) => id.startsWith("CLT-WIN-PERSIST"))).toEqual([]);
	});

	it("does not match schtasks /query", () => {
		const ids = matchCommand(engine, "schtasks /Query /tn MyTask");
		expect(ids.filter((id) => id.startsWith("CLT-WIN-PERSIST"))).toEqual([]);
	});

	// --- WMI event subscription persistence (PERSIST-008) ---

	it("detects CommandLineEventConsumer (WIN-PERSIST-008)", () => {
		expect(
			matchCommand(
				engine,
				'Set-WmiInstance -Class CommandLineEventConsumer -Arguments @{Name="Evil"; CommandLineTemplate="cmd.exe /c calc.exe"}',
			),
		).toContain("CLT-WIN-PERSIST-008");
	});

	it("detects ActiveScriptEventConsumer (WIN-PERSIST-008)", () => {
		expect(
			matchCommand(
				engine,
				'Set-WmiInstance -Class ActiveScriptEventConsumer -Arguments @{Name="Evil"; ScriptText="malicious"}',
			),
		).toContain("CLT-WIN-PERSIST-008");
	});

	it("does not match Get-WmiObject __EventFilter (WIN-PERSIST-008 neg)", () => {
		const ids = matchCommand(engine, "Get-WmiObject -Class __EventFilter");
		expect(ids.filter((id) => id === "CLT-WIN-PERSIST-008")).toEqual([]);
	});

	// --- Additional FP coverage ---

	it("does not match reg query RunOnce (001 FP)", () => {
		const ids = matchCommand(
			engine,
			"reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\",
		);
		expect(ids).not.toContain("CLT-WIN-PERSIST-001");
	});

	it("does not match sc query service (002 FP)", () => {
		const ids = matchCommand(engine, "sc query wuauserv");
		expect(ids).not.toContain("CLT-WIN-PERSIST-002");
	});

	it("does not match schtasks /Delete (003 FP)", () => {
		const ids = matchCommand(engine, "schtasks /Delete /tn OldTask /f");
		expect(ids).not.toContain("CLT-WIN-PERSIST-003");
	});

	it("does not match Get-ScheduledTask (004 FP)", () => {
		const ids = matchCommand(engine, "Get-ScheduledTask -TaskName MyTask");
		expect(ids).not.toContain("CLT-WIN-PERSIST-004");
	});

	it("does not match Get-ItemProperty Run key (005 FP)", () => {
		const ids = matchCommand(
			engine,
			"Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\'",
		);
		expect(ids).not.toContain("CLT-WIN-PERSIST-005");
	});

	it("does not match Get-Service (006 FP)", () => {
		const ids = matchCommand(engine, "Get-Service -Name wuauserv");
		expect(ids).not.toContain("CLT-WIN-PERSIST-006");
	});
});
