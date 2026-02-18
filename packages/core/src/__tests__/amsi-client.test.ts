import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AmsiClient } from "../clients/amsi.js";
import type { Logger } from "../types.js";
import { nullLogger } from "../types.js";

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
	});

	it("isAvailable is false when koffi import fails", async () => {
		vi.spyOn(process, "platform", "get").mockReturnValue("win32" as NodeJS.Platform);
		// koffi is not installed in test environment, so import will fail
		const client = new AmsiClient(mockLogger);
		await client.init();
		expect(client.isAvailable).toBe(false);
	});

	it("scanString returns null when not available", () => {
		const client = new AmsiClient(nullLogger);
		const result = client.scanString("test content", "test:name");
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
		const client = new AmsiClient(nullLogger);
		// Not initialized, but close should still work
		client.close();
		expect(client.isAvailable).toBe(false);
	});
});
