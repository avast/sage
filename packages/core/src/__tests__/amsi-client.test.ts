import { EventEmitter } from "node:events";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock koffi so the koffi backend always fails, forcing PowerShell fallback
vi.mock("koffi", () => {
	throw new Error("koffi not available in test");
});

// Mock child_process so the PowerShell backend can be controlled in tests
vi.mock("node:child_process", () => ({
	spawn: vi.fn(),
}));

import { spawn } from "node:child_process";
import { AmsiClient } from "../clients/amsi.js";
import type { Logger } from "../types.js";
import { nullLogger } from "../types.js";

const mockSpawn = vi.mocked(spawn);

interface MockProcess extends EventEmitter {
	stdin: {
		write: ReturnType<typeof vi.fn>;
		end: ReturnType<typeof vi.fn>;
		on: ReturnType<typeof vi.fn>;
	};
	stdout: EventEmitter;
	stderr: EventEmitter;
	kill: ReturnType<typeof vi.fn>;
	exitCode: number | null;
}

function createMockProcess(): MockProcess {
	const proc = new EventEmitter() as MockProcess;
	proc.stdout = new EventEmitter();
	proc.stderr = new EventEmitter();
	proc.stdin = { write: vi.fn(() => true), end: vi.fn(), on: vi.fn() };
	proc.kill = vi.fn();
	proc.exitCode = null;
	return proc;
}

/**
 * Schedule READY emission when the stdout 'data' listener is registered.
 * Uses newListener to ensure emission happens after the handler is set up,
 * avoiding a race with the async koffi init that runs first.
 */
function emitReady(proc: MockProcess): void {
	let emitted = false;
	proc.stdout.on("newListener", (event: string) => {
		if (event === "data" && !emitted) {
			emitted = true;
			queueMicrotask(() => proc.stdout.emit("data", Buffer.from("READY\n")));
		}
	});
}

/** Schedule process exit when the stdout 'data' listener is registered. */
function emitExit(proc: MockProcess, code = 1): void {
	let fired = false;
	proc.stdout.on("newListener", (event: string) => {
		if (event === "data" && !fired) {
			fired = true;
			queueMicrotask(() => proc.emit("exit", code, null));
		}
	});
}

/** Make stdin.write emit a scan result line for each call. */
function mockScanResult(proc: MockProcess, result: string): void {
	proc.stdin.write.mockImplementation(() => {
		queueMicrotask(() => proc.stdout.emit("data", Buffer.from(`${result}\n`)));
		return true;
	});
}

const mockLogger: Logger = {
	debug: vi.fn(),
	info: vi.fn(),
	warn: vi.fn(),
	error: vi.fn(),
};

describe("AmsiClient", () => {
	beforeEach(() => {
		vi.restoreAllMocks();
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("isAvailable is false before init", () => {
		const client = new AmsiClient(nullLogger);
		expect(client.isAvailable).toBe(false);
	});

	it("isAvailable is false on non-Windows", async () => {
		vi.spyOn(process, "platform", "get").mockReturnValue("linux" as NodeJS.Platform);
		const client = new AmsiClient(mockLogger);
		await client.init();
		expect(client.isAvailable).toBe(false);
		// spawn should not have been attempted on non-Windows
		expect(mockSpawn).not.toHaveBeenCalled();
	});

	it("isAvailable is false when all backends fail", async () => {
		vi.spyOn(process, "platform", "get").mockReturnValue("win32" as NodeJS.Platform);
		const proc = createMockProcess();
		mockSpawn.mockReturnValue(proc as never);
		// Process exits immediately when exit listener is registered
		emitExit(proc);

		const client = new AmsiClient(mockLogger);
		await client.init();
		expect(client.isAvailable).toBe(false);
	});

	it("falls back to PowerShell when koffi fails", async () => {
		vi.spyOn(process, "platform", "get").mockReturnValue("win32" as NodeJS.Platform);
		const proc = createMockProcess();
		mockSpawn.mockReturnValue(proc as never);
		emitReady(proc);

		const client = new AmsiClient(mockLogger);
		await client.init();
		expect(client.isAvailable).toBe(true);
		expect(mockSpawn).toHaveBeenCalled();
		client.close();
	});

	it("PowerShell scanString returns result for clean content", async () => {
		vi.spyOn(process, "platform", "get").mockReturnValue("win32" as NodeJS.Platform);
		const proc = createMockProcess();
		mockSpawn.mockReturnValue(proc as never);
		emitReady(proc);

		const client = new AmsiClient(mockLogger);
		await client.init();
		expect(client.isAvailable).toBe(true);

		// Scan returns clean (0)
		mockScanResult(proc, "0");
		const result = await client.scanString("safe content", "test:name");
		expect(result).not.toBeNull();
		expect(result?.isDetected).toBe(false);
		expect(result?.isBlockedByAdmin).toBe(false);
		expect(result?.amsiResult).toBe(0);
		expect(result?.contentName).toBe("test:name");
		client.close();
	});

	it("PowerShell scanString detects malware", async () => {
		vi.spyOn(process, "platform", "get").mockReturnValue("win32" as NodeJS.Platform);
		const proc = createMockProcess();
		mockSpawn.mockReturnValue(proc as never);
		emitReady(proc);

		const client = new AmsiClient(mockLogger);
		await client.init();

		// 32768 = AMSI_RESULT_DETECTED
		mockScanResult(proc, "32768");
		const result = await client.scanString("malicious", "test:malware");
		expect(result).not.toBeNull();
		expect(result?.isDetected).toBe(true);
		expect(result?.isBlockedByAdmin).toBe(false);
		expect(result?.amsiResult).toBe(32768);
		client.close();
	});

	it("PowerShell scanString detects blocked-by-admin", async () => {
		vi.spyOn(process, "platform", "get").mockReturnValue("win32" as NodeJS.Platform);
		const proc = createMockProcess();
		mockSpawn.mockReturnValue(proc as never);
		emitReady(proc);

		const client = new AmsiClient(mockLogger);
		await client.init();

		// 16384 = AMSI_RESULT_BLOCKED_BY_ADMIN_START
		mockScanResult(proc, "16384");
		const result = await client.scanString("blocked content", "test:blocked");
		expect(result).not.toBeNull();
		expect(result?.isDetected).toBe(false);
		expect(result?.isBlockedByAdmin).toBe(true);
		client.close();
	});

	it("PowerShell scanString returns null on scan failure", async () => {
		vi.spyOn(process, "platform", "get").mockReturnValue("win32" as NodeJS.Platform);
		const proc = createMockProcess();
		mockSpawn.mockReturnValue(proc as never);
		emitReady(proc);

		const client = new AmsiClient(mockLogger);
		await client.init();

		// Process exits during scan
		proc.stdin.write.mockImplementation(() => {
			queueMicrotask(() => proc.emit("exit", 1, null));
			return true;
		});
		const result = await client.scanString("content", "test:fail");
		expect(result).toBeNull();
	});

	it("PowerShell scanString returns null on invalid output", async () => {
		vi.spyOn(process, "platform", "get").mockReturnValue("win32" as NodeJS.Platform);
		const proc = createMockProcess();
		mockSpawn.mockReturnValue(proc as never);
		emitReady(proc);

		const client = new AmsiClient(mockLogger);
		await client.init();

		mockScanResult(proc, "not-a-number");
		const result = await client.scanString("content", "test:invalid");
		expect(result).toBeNull();
		client.close();
	});

	it("PowerShell scanString truncates long content in result", async () => {
		vi.spyOn(process, "platform", "get").mockReturnValue("win32" as NodeJS.Platform);
		const proc = createMockProcess();
		mockSpawn.mockReturnValue(proc as never);
		emitReady(proc);

		const client = new AmsiClient(mockLogger);
		await client.init();

		mockScanResult(proc, "0");
		const longContent = "x".repeat(300);
		const result = await client.scanString(longContent, "test:long");
		expect(result).not.toBeNull();
		expect(result?.content).toHaveLength(203); // 200 + "..."
		expect(result?.content.endsWith("...")).toBe(true);
		client.close();
	});

	it("scanString returns null when not available", async () => {
		const client = new AmsiClient(nullLogger);
		const result = await client.scanString("test content", "test:name");
		expect(result).toBeNull();
	});

	it("close is safe when not initialized", () => {
		const client = new AmsiClient(nullLogger);
		expect(() => client.close()).not.toThrow();
	});

	it("close is safe when called multiple times", () => {
		const client = new AmsiClient(nullLogger);
		expect(() => {
			client.close();
			client.close();
			client.close();
		}).not.toThrow();
	});

	it("close sets isAvailable to false", async () => {
		vi.spyOn(process, "platform", "get").mockReturnValue("win32" as NodeJS.Platform);
		const proc = createMockProcess();
		mockSpawn.mockReturnValue(proc as never);
		emitReady(proc);

		const client = new AmsiClient(mockLogger);
		await client.init();
		expect(client.isAvailable).toBe(true);
		client.close();
		expect(client.isAvailable).toBe(false);
	});

	it("scanString returns null after close", async () => {
		vi.spyOn(process, "platform", "get").mockReturnValue("win32" as NodeJS.Platform);
		const proc = createMockProcess();
		mockSpawn.mockReturnValue(proc as never);
		emitReady(proc);

		const client = new AmsiClient(mockLogger);
		await client.init();
		client.close();
		const result = await client.scanString("content", "test:closed");
		expect(result).toBeNull();
	});

	it("close terminates the PowerShell process", async () => {
		vi.spyOn(process, "platform", "get").mockReturnValue("win32" as NodeJS.Platform);
		const proc = createMockProcess();
		mockSpawn.mockReturnValue(proc as never);
		emitReady(proc);

		const client = new AmsiClient(mockLogger);
		await client.init();
		expect(client.isAvailable).toBe(true);

		client.close();
		expect(proc.stdin.end).toHaveBeenCalled();
		expect(proc.kill).toHaveBeenCalled();
	});
});
