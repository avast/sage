import { beforeAll, describe, expect, it } from "vitest";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchFilePath = createMatcher("file_path");

describe("Windows file path threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	// --- Positive cases ---

	it("detects SAM hive (WIN-FILE-001)", () => {
		expect(matchFilePath(engine, "C:\\Windows\\System32\\config\\SAM")).toContain(
			"CLT-WIN-FILE-001",
		);
	});

	it("detects SECURITY hive (WIN-FILE-001)", () => {
		expect(matchFilePath(engine, "C:\\Windows\\System32\\config\\SECURITY")).toContain(
			"CLT-WIN-FILE-001",
		);
	});

	it("detects SYSTEM hive (WIN-FILE-001)", () => {
		expect(matchFilePath(engine, "C:\\Windows\\System32\\config\\SYSTEM")).toContain(
			"CLT-WIN-FILE-001",
		);
	});

	it("detects SAM with forward slashes (WIN-FILE-001)", () => {
		expect(matchFilePath(engine, "C:/Windows/System32/config/SAM")).toContain("CLT-WIN-FILE-001");
	});

	it("detects NTDS.dit (WIN-FILE-002)", () => {
		expect(matchFilePath(engine, "C:\\Windows\\NTDS\\ntds.dit")).toContain("CLT-WIN-FILE-002");
	});

	it("detects hosts file (WIN-FILE-003)", () => {
		expect(matchFilePath(engine, "C:\\Windows\\System32\\drivers\\etc\\hosts")).toContain(
			"CLT-WIN-FILE-003",
		);
	});

	it("detects hosts with forward slashes (WIN-FILE-003)", () => {
		expect(matchFilePath(engine, "C:/Windows/System32/drivers/etc/hosts")).toContain(
			"CLT-WIN-FILE-003",
		);
	});

	it("detects Startup folder (WIN-FILE-004)", () => {
		expect(
			matchFilePath(
				engine,
				"C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.exe",
			),
		).toContain("CLT-WIN-FILE-004");
	});

	it("detects bat in System32 (WIN-FILE-005)", () => {
		expect(matchFilePath(engine, "C:\\Windows\\System32\\evil.bat")).toContain("CLT-WIN-FILE-005");
	});

	it("detects ps1 in SysWOW64 (WIN-FILE-005)", () => {
		expect(matchFilePath(engine, "C:\\Windows\\SysWOW64\\payload.ps1")).toContain(
			"CLT-WIN-FILE-005",
		);
	});

	it("detects sys driver file (WIN-FILE-006)", () => {
		expect(matchFilePath(engine, "C:\\Windows\\System32\\drivers\\evil.sys")).toContain(
			"CLT-WIN-FILE-006",
		);
	});

	// --- Negative cases ---

	it("does not match normal Program Files path", () => {
		const ids = matchFilePath(engine, "C:\\Program Files\\MyApp\\app.exe");
		expect(ids.filter((id) => id.startsWith("CLT-WIN-FILE"))).toEqual([]);
	});

	it("does not match Users document", () => {
		const ids = matchFilePath(engine, "C:\\Users\\user\\Documents\\readme.txt");
		expect(ids.filter((id) => id.startsWith("CLT-WIN-FILE"))).toEqual([]);
	});

	it("does not match normal source file", () => {
		const ids = matchFilePath(engine, "src\\app.ts");
		expect(ids.filter((id) => id.startsWith("CLT-WIN-FILE"))).toEqual([]);
	});

	// --- Task Scheduler directory (FILE-007) ---

	it("detects Task Scheduler directory write (WIN-FILE-007)", () => {
		expect(matchFilePath(engine, "C:\\Windows\\System32\\Tasks\\EvilTask")).toContain(
			"CLT-WIN-FILE-007",
		);
	});

	// --- SSH keys Windows path (FILE-008) ---

	it("detects SSH id_rsa write (WIN-FILE-008)", () => {
		expect(matchFilePath(engine, "C:\\Users\\user\\.ssh\\id_rsa")).toContain("CLT-WIN-FILE-008");
	});

	it("detects SSH id_ed25519 write (WIN-FILE-008)", () => {
		expect(matchFilePath(engine, "C:\\Users\\user\\.ssh\\id_ed25519")).toContain(
			"CLT-WIN-FILE-008",
		);
	});

	it("detects SSH authorized_keys write (WIN-FILE-008)", () => {
		expect(matchFilePath(engine, "C:\\Users\\user\\.ssh\\authorized_keys")).toContain(
			"CLT-WIN-FILE-008",
		);
	});

	// --- AWS credentials Windows path (FILE-009) ---

	it("detects AWS credentials write (WIN-FILE-009)", () => {
		expect(matchFilePath(engine, "C:\\Users\\user\\.aws\\credentials")).toContain(
			"CLT-WIN-FILE-009",
		);
	});

	// --- Browser credential stores (FILE-010) ---

	it("detects Chrome Login Data write (WIN-FILE-010)", () => {
		expect(
			matchFilePath(
				engine,
				"C:\\Users\\user\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
			),
		).toContain("CLT-WIN-FILE-010");
	});

	it("detects Firefox logins.json write (WIN-FILE-010)", () => {
		expect(
			matchFilePath(
				engine,
				"C:\\Users\\user\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\abc.default\\logins.json",
			),
		).toContain("CLT-WIN-FILE-010");
	});

	it("detects Edge Cookies write (WIN-FILE-010)", () => {
		expect(
			matchFilePath(
				engine,
				"C:\\Users\\user\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cookies",
			),
		).toContain("CLT-WIN-FILE-010");
	});

	it("does not match normal AppData file (WIN-FILE-010 neg)", () => {
		const ids = matchFilePath(
			engine,
			"C:\\Users\\user\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Preferences",
		);
		expect(ids.filter((id) => id === "CLT-WIN-FILE-010")).toEqual([]);
	});

	// --- Additional FP coverage ---

	it("does not match System32\\config\\SOFTWARE (001 FP)", () => {
		const ids = matchFilePath(engine, "C:\\Windows\\System32\\config\\SOFTWARE");
		expect(ids).not.toContain("CLT-WIN-FILE-001");
	});

	it("does not match drivers\\etc\\services (003 FP)", () => {
		const ids = matchFilePath(engine, "C:\\Windows\\System32\\drivers\\etc\\services");
		expect(ids).not.toContain("CLT-WIN-FILE-003");
	});

	it("does not match exe in System32 (005 FP — only scripts)", () => {
		const ids = matchFilePath(engine, "C:\\Windows\\System32\\notepad.exe");
		expect(ids).not.toContain("CLT-WIN-FILE-005");
	});

	it("does not match drivers\\normal.dll (006 FP — only .sys)", () => {
		const ids = matchFilePath(engine, "C:\\Windows\\System32\\drivers\\normal.dll");
		expect(ids).not.toContain("CLT-WIN-FILE-006");
	});

	it("does not match .ssh\\known_hosts (008 FP)", () => {
		const ids = matchFilePath(engine, "C:\\Users\\user\\.ssh\\known_hosts");
		expect(ids).not.toContain("CLT-WIN-FILE-008");
	});

	it("does not match .aws\\config (009 FP — only credentials)", () => {
		const ids = matchFilePath(engine, "C:\\Users\\user\\.aws\\config");
		expect(ids).not.toContain("CLT-WIN-FILE-009");
	});
});
