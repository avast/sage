/**
 * AMSI (Antimalware Scan Interface) client.
 * Tries koffi FFI first, then PowerShell P/Invoke as fallback.
 * Fail-open: returns null/safe defaults on any error.
 */

import { type ChildProcess, spawn } from "node:child_process";
import type { AmsiCheckResult, Logger } from "../types.js";
import { nullLogger } from "../types.js";

/** AMSI_RESULT thresholds */
const AMSI_RESULT_DETECTED = 32768; // 0x8000
const AMSI_RESULT_BLOCKED_BY_ADMIN_START = 16384; // 0x4000

/** Max content length to scan (AMSI has practical limits). */
const MAX_SCAN_LENGTH = 1_048_576; // 1 MB

/** Timeout for PowerShell operations (ms). */
const PS_TIMEOUT = 15_000;

/** Detect whether we're running inside WSL (Windows Subsystem for Linux). */
function isWSL(): boolean {
	if (process.platform !== "linux") return false;
	return !!process.env.WSL_DISTRO_NAME;
}

/** Check whether the current platform supports AMSI scanning (native Windows or WSL). */
export function isAmsiSupported(): boolean {
	return process.platform === "win32" || isWSL();
}

/** Interpret a numeric AMSI result into the standard result fields. */
function interpretAmsiResult(
	amsiResult: number,
	content: string,
	contentName: string,
): AmsiCheckResult {
	return {
		content: content.length > 200 ? `${content.slice(0, 200)}...` : content,
		contentName,
		amsiResult,
		isDetected: amsiResult >= AMSI_RESULT_DETECTED,
		isBlockedByAdmin:
			amsiResult >= AMSI_RESULT_BLOCKED_BY_ADMIN_START && amsiResult < AMSI_RESULT_DETECTED,
	};
}

/** Backend interface for AMSI implementations. */
interface AmsiBackend {
	readonly isAvailable: boolean;
	init(): Promise<void>;
	scanString(content: string, contentName: string): Promise<AmsiCheckResult | null>;
	close(): void;
}

// ---------------------------------------------------------------------------
// Koffi FFI backend (native, fast — requires koffi)
// ---------------------------------------------------------------------------

class KoffiAmsiBackend implements AmsiBackend {
	private readonly logger: Logger;
	private context: unknown = null;
	private session: unknown = null;
	private available = false;

	/* biome-ignore lint/suspicious/noExplicitAny: koffi FFI functions have dynamic signatures */
	private fnScanBuffer: ((...args: any[]) => number) | null = null;
	/* biome-ignore lint/suspicious/noExplicitAny: koffi FFI functions have dynamic signatures */
	private fnCloseSession: ((...args: any[]) => void) | null = null;
	/* biome-ignore lint/suspicious/noExplicitAny: koffi FFI functions have dynamic signatures */
	private fnUninitialize: ((...args: any[]) => void) | null = null;

	constructor(logger: Logger) {
		this.logger = logger;
	}

	get isAvailable(): boolean {
		return this.available;
	}

	async init(): Promise<void> {
		try {
			const koffiModule = await import("koffi");
			// unwrap CJS module if needed
			const koffi = koffiModule.default ?? koffiModule;

			const lib = koffi.load("amsi.dll");

			// define opaque handle types matching the Win32 AMSI API
			const _HAMSICONTEXT = koffi.pointer("HAMSICONTEXT", koffi.opaque());
			const _HAMSISESSION = koffi.pointer("HAMSISESSION", koffi.opaque());

			const AmsiInitialize = lib.func(
				"int32 __stdcall AmsiInitialize(str16 appName, _Out_ HAMSICONTEXT *ctx)",
			);
			const AmsiOpenSession = lib.func(
				"int32 __stdcall AmsiOpenSession(HAMSICONTEXT ctx, _Out_ HAMSISESSION *session)",
			);

			this.fnScanBuffer = lib.func(
				"int32 __stdcall AmsiScanBuffer(HAMSICONTEXT ctx, void *buf, uint32 len, str16 contentName, HAMSISESSION session, _Out_ int32 *result)",
			);
			this.fnCloseSession = lib.func(
				"void __stdcall AmsiCloseSession(HAMSICONTEXT ctx, HAMSISESSION session)",
			);
			this.fnUninitialize = lib.func("void __stdcall AmsiUninitialize(HAMSICONTEXT ctx)");

			const ctxOut: unknown[] = [null];
			const hr = AmsiInitialize("Sage", ctxOut);
			if (hr !== 0) {
				this.logger.warn("AMSI: koffi AmsiInitialize failed", { hr });
				return;
			}
			this.context = ctxOut[0];

			const sessOut: unknown[] = [null];
			const hr2 = AmsiOpenSession(this.context, sessOut);
			if (hr2 !== 0) {
				this.logger.warn("AMSI: koffi AmsiOpenSession failed", { hr: hr2 });
				try {
					if (this.fnUninitialize) {
						this.fnUninitialize(this.context);
					}
				} catch {
					/* best effort */
				}
				this.context = null;
				return;
			}
			this.session = sessOut[0];

			this.available = true;
			this.logger.debug("AMSI: koffi backend initialized");
		} catch (e) {
			this.logger.debug("AMSI: koffi backend init failed", { error: String(e) });
			this.available = false;
		}
	}

	async scanString(content: string, contentName: string): Promise<AmsiCheckResult | null> {
		if (!this.available || !this.fnScanBuffer || !this.context || !this.session) {
			return null;
		}

		try {
			const truncated =
				content.length > MAX_SCAN_LENGTH ? content.slice(0, MAX_SCAN_LENGTH) : content;
			const buf = Buffer.from(truncated, "utf-8");
			const resultOut = [0];

			const hr = this.fnScanBuffer(
				this.context,
				buf,
				buf.length,
				contentName,
				this.session,
				resultOut,
			);
			if (hr !== 0) {
				this.logger.warn("AMSI: koffi AmsiScanBuffer failed", { hr, contentName });
				return null;
			}

			const amsiResult = resultOut[0] ?? 0;
			this.logger.debug("AMSI: koffi scan result", { contentName, amsiResult });
			return interpretAmsiResult(amsiResult, content, contentName);
		} catch (e) {
			this.logger.warn("AMSI: koffi scanBuffer failed", { error: String(e), contentName });
			return null;
		}
	}

	close(): void {
		try {
			if (this.session && this.context && this.fnCloseSession) {
				this.fnCloseSession(this.context, this.session);
			}
		} catch {
			/* best effort */
		}

		try {
			if (this.context && this.fnUninitialize) {
				this.fnUninitialize(this.context);
			}
		} catch {
			/* best effort */
		}

		this.session = null;
		this.context = null;
		this.available = false;
	}
}

// ---------------------------------------------------------------------------
// PowerShell P/Invoke backend
// ---------------------------------------------------------------------------

/** Shared C# AMSI interop type compiled once by Add-Type in each script. */
const AMSI_CSHARP_TYPE = `
using System;
using System.Runtime.InteropServices;
using System.Text;

public class SageAmsi {
    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    static extern int AmsiInitialize(string appName, out IntPtr ctx);

    [DllImport("amsi.dll")]
    static extern int AmsiOpenSession(IntPtr ctx, out IntPtr session);

    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    static extern int AmsiScanBuffer(
        IntPtr ctx, byte[] buf, uint len,
        string contentName, IntPtr session, out int result);

    [DllImport("amsi.dll")]
    static extern void AmsiCloseSession(IntPtr ctx, IntPtr session);

    [DllImport("amsi.dll")]
    static extern void AmsiUninitialize(IntPtr ctx);

    private static IntPtr _ctx;
    private static IntPtr _session;
    private static bool _initialized;

    public static bool Init() {
        int hr = AmsiInitialize("Sage", out _ctx);
        if (hr != 0) return false;
        hr = AmsiOpenSession(_ctx, out _session);
        if (hr != 0) {
            AmsiUninitialize(_ctx);
            return false;
        }
        _initialized = true;
        return true;
    }

    public static int Scan(string content, string contentName) {
        if (!_initialized) return -1;
        byte[] bytes = Encoding.UTF8.GetBytes(content);
        int result;
        int hr = AmsiScanBuffer(_ctx, bytes, (uint)bytes.Length,
                                contentName, _session, out result);
        if (hr != 0) return -1;
        return result;
    }

    public static void Shutdown() {
        if (!_initialized) return;
        AmsiCloseSession(_ctx, _session);
        AmsiUninitialize(_ctx);
        _initialized = false;
    }
}
`;

/**
 * Persistent PowerShell script: compiles the interop type once, initializes
 * AMSI once, then enters a read loop. Used on native Windows where stdin
 * piping is reliable.
 */
const PS_PERSISTENT_SCRIPT = `
$ErrorActionPreference = 'Stop'
try {
    Add-Type -TypeDefinition @'
${AMSI_CSHARP_TYPE}
'@

    if (-not [SageAmsi]::Init()) {
        [Console]::Error.Write("AMSI initialization failed")
        exit 1
    }

    [Console]::Out.WriteLine("READY")
    [Console]::Out.Flush()

    while ($null -ne ($line = [Console]::In.ReadLine())) {
        try {
            $req = $line | ConvertFrom-Json
            $content = $req.content
            $cname = $req.contentName
            if (-not $cname) { $cname = 'sage:test' }
            $result = [SageAmsi]::Scan($content, $cname)
            [Console]::Out.WriteLine($result)
            [Console]::Out.Flush()
        } catch {
            [Console]::Out.WriteLine("-1")
            [Console]::Out.Flush()
        }
    }

    [SageAmsi]::Shutdown()
} catch {
    [Console]::Error.Write($_.Exception.Message)
    exit 1
}
`;

/**
 * One-shot PowerShell script: reads a single JSON line from stdin, scans,
 * outputs result, and exits. Used under WSL where stdin pipes to Windows
 * executables are unreliable for persistent processes (data written after
 * the first read may never be delivered).
 */
const PS_ONESHOT_SCRIPT = `
$ErrorActionPreference = 'Stop'
try {
    Add-Type -TypeDefinition @'
${AMSI_CSHARP_TYPE}
'@

    if (-not [SageAmsi]::Init()) {
        [Console]::Out.WriteLine("-1")
        exit
    }

    $line = [Console]::In.ReadLine()
    $req = $line | ConvertFrom-Json
    $content = $req.content
    $cname = $req.contentName
    if (-not $cname) { $cname = 'sage:scan' }
    $result = [SageAmsi]::Scan($content, $cname)
    [SageAmsi]::Shutdown()
    [Console]::Out.WriteLine($result)
    [Console]::Out.Flush()
} catch {
    [Console]::Out.WriteLine("-1")
}
`;

/**
 * Persistent PowerShell AMSI backend for native Windows.
 * Spawns a single long-lived PowerShell process with a stdin/stdout loop.
 */
class PersistentPowershellAmsiBackend implements AmsiBackend {
	private readonly logger: Logger;
	private process: ChildProcess | null = null;
	private available = false;
	private stdoutBuffer = "";
	private pendingResponse: {
		resolve: (line: string) => void;
		reject: (err: Error) => void;
		timer: ReturnType<typeof setTimeout>;
	} | null = null;

	constructor(logger: Logger) {
		this.logger = logger;
	}

	get isAvailable(): boolean {
		return this.available;
	}

	private waitForLine(timeout: number): Promise<string> {
		return new Promise<string>((resolve, reject) => {
			const timer = setTimeout(() => {
				this.pendingResponse = null;
				reject(new Error("timeout"));
			}, timeout);

			this.pendingResponse = { resolve, reject, timer };
		});
	}

	async init(): Promise<void> {
		try {
			this.process = spawn(
				"powershell.exe",
				["-NoProfile", "-NonInteractive", "-Command", PS_PERSISTENT_SCRIPT],
				{
					stdio: ["pipe", "pipe", "pipe"],
					windowsHide: true,
				},
			);

			this.process.on("error", (err) => {
				this.logger.debug("AMSI: PowerShell process error", { error: String(err) });
				this.available = false;
				if (this.pendingResponse) {
					const { reject, timer } = this.pendingResponse;
					this.pendingResponse = null;
					clearTimeout(timer);
					reject(err);
				}
			});

			this.process.on("exit", () => {
				this.available = false;
				if (this.pendingResponse) {
					const { reject, timer } = this.pendingResponse;
					this.pendingResponse = null;
					clearTimeout(timer);
					reject(new Error("process exited"));
				}
			});

			this.process.stdout?.on("data", (chunk: Buffer) => {
				this.stdoutBuffer += chunk.toString();
				let idx = this.stdoutBuffer.indexOf("\n");
				while (idx !== -1) {
					const line = this.stdoutBuffer.slice(0, idx).trim();
					this.stdoutBuffer = this.stdoutBuffer.slice(idx + 1);
					if (this.pendingResponse) {
						const { resolve, timer } = this.pendingResponse;
						this.pendingResponse = null;
						clearTimeout(timer);
						resolve(line);
					}
					idx = this.stdoutBuffer.indexOf("\n");
				}
			});

			this.process.stdin?.on("error", () => {
				/* ignore write errors on closed pipe */
			});

			this.process.stderr?.on("data", (chunk: Buffer) => {
				this.logger.debug("AMSI: PowerShell stderr", {
					data: chunk.toString().slice(0, 200),
				});
			});

			const readyLine = await this.waitForLine(PS_TIMEOUT);
			if (readyLine === "READY") {
				this.available = true;
				this.logger.debug("AMSI: PowerShell persistent backend initialized");
			} else {
				this.logger.debug("AMSI: PowerShell unexpected ready signal", { readyLine });
				this.close();
			}
		} catch (e) {
			this.logger.debug("AMSI: PowerShell persistent backend init failed", {
				error: String(e),
			});
			this.close();
		}
	}

	async scanString(content: string, contentName: string): Promise<AmsiCheckResult | null> {
		if (!this.available || !this.process) return null;

		const truncated =
			content.length > MAX_SCAN_LENGTH ? content.slice(0, MAX_SCAN_LENGTH) : content;

		try {
			const req = JSON.stringify({ content: truncated, contentName });
			this.process.stdin?.write(`${req}\n`);

			const line = await this.waitForLine(PS_TIMEOUT);
			const amsiResult = parseInt(line, 10);

			if (Number.isNaN(amsiResult) || amsiResult < 0) {
				this.logger.warn("AMSI: PowerShell scan returned invalid result", {
					stdout: line.slice(0, 100),
					contentName,
				});
				return null;
			}

			this.logger.debug("AMSI: PowerShell scan result", { contentName, amsiResult });
			return interpretAmsiResult(amsiResult, content, contentName);
		} catch (e) {
			this.logger.warn("AMSI: PowerShell scan failed", { error: String(e), contentName });
			return null;
		}
	}

	close(): void {
		if (this.process) {
			try {
				this.process.stdin?.end();
			} catch {
				/* best effort */
			}
			try {
				this.process.kill();
			} catch {
				/* best effort */
			}
			this.process = null;
		}
		if (this.pendingResponse) {
			const { reject, timer } = this.pendingResponse;
			this.pendingResponse = null;
			clearTimeout(timer);
			reject(new Error("closed"));
		}
		this.available = false;
	}
}

/**
 * One-shot PowerShell AMSI backend for WSL.
 * Spawns a fresh powershell.exe per scan and closes stdin after writing to
 * flush the WSL interop pipe. Stateless — no persistent process.
 */
class WslPowershellAmsiBackend implements AmsiBackend {
	private readonly logger: Logger;
	private available = false;

	constructor(logger: Logger) {
		this.logger = logger;
	}

	get isAvailable(): boolean {
		return this.available;
	}

	async init(): Promise<void> {
		this.available = true;
		this.logger.debug("AMSI: PowerShell one-shot backend ready (WSL)");
	}

	async scanString(content: string, contentName: string): Promise<AmsiCheckResult | null> {
		if (!this.available) return null;

		const truncated =
			content.length > MAX_SCAN_LENGTH ? content.slice(0, MAX_SCAN_LENGTH) : content;

		return new Promise((resolve) => {
			try {
				const ps = spawn(
					"powershell.exe",
					["-NoProfile", "-NonInteractive", "-Command", PS_ONESHOT_SCRIPT],
					{ stdio: ["pipe", "pipe", "pipe"] },
				);

				let stdout = "";
				const timer = setTimeout(() => {
					this.logger.warn("AMSI: PowerShell one-shot timeout", { contentName });
					try {
						ps.kill();
					} catch {
						/* best effort */
					}
					resolve(null);
				}, PS_TIMEOUT);

				ps.stdout?.on("data", (chunk: Buffer) => {
					stdout += chunk.toString();
				});
				ps.stderr?.on("data", (chunk: Buffer) => {
					this.logger.debug("AMSI: PowerShell one-shot stderr", {
						data: chunk.toString().slice(0, 200),
					});
				});
				ps.on("error", (err) => {
					clearTimeout(timer);
					this.logger.debug("AMSI: PowerShell one-shot error", { error: String(err) });
					resolve(null);
				});
				ps.on("exit", () => {
					clearTimeout(timer);
					const amsiResult = parseInt(stdout.trim(), 10);
					if (Number.isNaN(amsiResult) || amsiResult < 0) {
						this.logger.warn("AMSI: PowerShell one-shot invalid result", {
							stdout: stdout.slice(0, 100),
							contentName,
						});
						resolve(null);
						return;
					}
					this.logger.debug("AMSI: PowerShell one-shot result", { contentName, amsiResult });
					resolve(interpretAmsiResult(amsiResult, content, contentName));
				});

				const req = JSON.stringify({ content: truncated, contentName });
				ps.stdin?.write(`${req}\n`);
				ps.stdin?.end();
			} catch (e) {
				this.logger.warn("AMSI: PowerShell one-shot failed", { error: String(e), contentName });
				resolve(null);
			}
		});
	}

	close(): void {
		this.available = false;
	}
}

// ---------------------------------------------------------------------------
// Exported facade — tries koffi, then PowerShell, then gives up
// ---------------------------------------------------------------------------

export class AmsiClient {
	private readonly logger: Logger;
	private backend: AmsiBackend | null = null;

	constructor(logger: Logger = nullLogger) {
		this.logger = logger;
	}

	get isAvailable(): boolean {
		return this.backend?.isAvailable ?? false;
	}

	async init(): Promise<void> {
		const wsl = isWSL();

		if (process.platform !== "win32" && !wsl) {
			this.logger.debug("AMSI: skipping, not Windows");
			return;
		}

		// Koffi (native FFI) — only viable on native Windows (can't load
		// Windows DLLs from Linux userspace, even under WSL).
		if (!wsl) {
			const koffi = new KoffiAmsiBackend(this.logger);
			await koffi.init();
			if (koffi.isAvailable) {
				this.backend = koffi;
				return;
			}
		}

		// PowerShell P/Invoke — works on native Windows and WSL (WSL interop
		// routes powershell.exe to the Windows-side binary).
		const ps = wsl
			? new WslPowershellAmsiBackend(this.logger)
			: new PersistentPowershellAmsiBackend(this.logger);
		await ps.init();
		if (ps.isAvailable) {
			this.backend = ps;
			return;
		}

		this.logger.debug("AMSI: no backend available");
	}

	async scanString(content: string, contentName: string): Promise<AmsiCheckResult | null> {
		return (await this.backend?.scanString(content, contentName)) ?? null;
	}

	close(): void {
		this.backend?.close();
		this.backend = null;
	}
}
