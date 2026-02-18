/**
 * AMSI (Antimalware Scan Interface) client.
 * Uses koffi FFI to call amsi.dll on Windows.
 * Fail-open: returns null/safe defaults on any error.
 */

import type { AmsiCheckResult, Logger } from "../types.js";
import { nullLogger } from "../types.js";

/** AMSI_RESULT thresholds */
const AMSI_RESULT_DETECTED = 32768; // 0x8000
const AMSI_RESULT_BLOCKED_BY_ADMIN_START = 16384; // 0x4000

/** Max content length to scan (AMSI has practical limits). */
const MAX_SCAN_LENGTH = 1_048_576; // 1 MB

export class AmsiClient {
	private readonly logger: Logger;
	private context: unknown = null;
	private session: unknown = null;
	private available = false;

	// koffi function references
	private fnScanBuffer: ((...args: unknown[]) => number) | null = null;
	private fnCloseSession: ((...args: unknown[]) => void) | null = null;
	private fnUninitialize: ((...args: unknown[]) => void) | null = null;

	constructor(logger: Logger = nullLogger) {
		this.logger = logger;
	}

	get isAvailable(): boolean {
		return this.available;
	}

	async init(): Promise<void> {
		if (process.platform !== "win32") {
			this.logger.debug("AMSI: skipping, not Windows");
			return;
		}

		try {
			// Dynamic import so koffi is only loaded when needed
			const koffi = await import("koffi");

			const lib = koffi.load("amsi.dll");

			// HRESULT AmsiInitialize(LPCWSTR appName, HAMSICONTEXT *amsiContext)
			const AmsiInitialize = lib.func("AmsiInitialize", "int32", ["str16", "*"]);

			// HRESULT AmsiOpenSession(HAMSICONTEXT amsiContext, HAMSISESSION *amsiSession)
			const AmsiOpenSession = lib.func("AmsiOpenSession", "int32", ["*", "*"]);

			// HRESULT AmsiScanBuffer(HAMSICONTEXT amsiContext, PVOID buffer,
			//   ULONG length, LPCWSTR contentName, HAMSISESSION amsiSession,
			//   AMSI_RESULT *result)
			this.fnScanBuffer = lib.func("AmsiScanBuffer", "int32", [
				"*",
				"*",
				"uint32",
				"str16",
				"*",
				"*",
			]);

			// void AmsiCloseSession(HAMSICONTEXT amsiContext, HAMSISESSION amsiSession)
			this.fnCloseSession = lib.func("AmsiCloseSession", "void", ["*", "*"]);

			// void AmsiUninitialize(HAMSICONTEXT amsiContext)
			this.fnUninitialize = lib.func("AmsiUninitialize", "void", ["*"]);

			// Allocate output pointers
			const contextPtr = Buffer.alloc(8); // pointer-sized
			const hr = AmsiInitialize("Sage", contextPtr);
			if (hr !== 0) {
				this.logger.warn("AMSI: AmsiInitialize failed", { hr });
				return;
			}
			this.context = contextPtr;

			const sessionPtr = Buffer.alloc(8);
			const hr2 = AmsiOpenSession(contextPtr, sessionPtr);
			if (hr2 !== 0) {
				this.logger.warn("AMSI: AmsiOpenSession failed", { hr: hr2 });
				// Clean up context
				try {
					this.fnUninitialize(contextPtr);
				} catch { /* best effort */ }
				this.context = null;
				return;
			}
			this.session = sessionPtr;

			this.available = true;
			this.logger.debug("AMSI: initialized successfully");
		} catch (e) {
			this.logger.debug("AMSI: initialization failed", { error: String(e) });
			this.available = false;
		}
	}

	scanString(content: string, contentName: string): AmsiCheckResult | null {
		if (!this.available || !this.fnScanBuffer || !this.context || !this.session) {
			return null;
		}

		try {
			const truncated = content.length > MAX_SCAN_LENGTH ? content.slice(0, MAX_SCAN_LENGTH) : content;
			const buf = Buffer.from(truncated, "utf-8");
			const resultBuf = Buffer.alloc(4); // AMSI_RESULT is a 32-bit int

			const hr = this.fnScanBuffer(
				this.context,
				buf,
				buf.length,
				contentName,
				this.session,
				resultBuf,
			);
			if (hr !== 0) {
				this.logger.warn("AMSI: AmsiScanBuffer failed", { hr, contentName });
				return null;
			}

			const amsiResult = resultBuf.readInt32LE(0);
			const isDetected = amsiResult >= AMSI_RESULT_DETECTED;
			const isBlockedByAdmin =
				amsiResult >= AMSI_RESULT_BLOCKED_BY_ADMIN_START && amsiResult < AMSI_RESULT_DETECTED;

			this.logger.debug("AMSI: scan result", { contentName, amsiResult, isDetected, isBlockedByAdmin });

			return {
				content: content.length > 200 ? `${content.slice(0, 200)}...` : content,
				contentName,
				amsiResult,
				isDetected,
				isBlockedByAdmin,
			};
		} catch (e) {
			this.logger.warn("AMSI: scanBuffer failed", { error: String(e), contentName });
			return null;
		}
	}

	close(): void {
		try {
			if (this.session && this.context && this.fnCloseSession) {
				this.fnCloseSession(this.context, this.session);
			}
		} catch { /* best effort */ }

		try {
			if (this.context && this.fnUninitialize) {
				this.fnUninitialize(this.context);
			}
		} catch { /* best effort */ }

		this.session = null;
		this.context = null;
		this.available = false;
	}
}
