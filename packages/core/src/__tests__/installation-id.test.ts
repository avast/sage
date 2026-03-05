import { randomBytes } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { getInstallationId } from "../installation-id.js";

describe("getInstallationId", () => {
	let testDir: string;

	beforeEach(async () => {
		testDir = join(tmpdir(), `sage-test-${randomBytes(6).toString("hex")}`);
		await mkdir(testDir, { recursive: true });
	});

	afterEach(async () => {
		await rm(testDir, { recursive: true, force: true });
	});

	it("generates a new UUID when no file exists", async () => {
		const id = await getInstallationId(testDir);
		expect(id).toBeDefined();
		expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
	});

	it("persists the UUID to disk", async () => {
		const id = await getInstallationId(testDir);
		const onDisk = await readFile(join(testDir, "installation-id"), "utf-8");
		expect(onDisk.trim()).toBe(id);
	});

	it("returns the same UUID on subsequent calls", async () => {
		const id1 = await getInstallationId(testDir);
		const id2 = await getInstallationId(testDir);
		expect(id1).toBe(id2);
	});

	it("reads an existing installation ID from disk", async () => {
		const existingId = "550e8400-e29b-41d4-a716-446655440000";
		await writeFile(join(testDir, "installation-id"), existingId, "utf-8");

		const id = await getInstallationId(testDir);
		expect(id).toBe(existingId);
	});

	it("generates a new UUID if file is empty", async () => {
		await writeFile(join(testDir, "installation-id"), "", "utf-8");

		const id = await getInstallationId(testDir);
		expect(id).toBeDefined();
		expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
	});

	it("creates the .sage directory if it does not exist", async () => {
		const nestedDir = join(testDir, "nested", "sage");
		const id = await getInstallationId(nestedDir);
		expect(id).toBeDefined();

		const onDisk = await readFile(join(nestedDir, "installation-id"), "utf-8");
		expect(onDisk.trim()).toBe(id);
	});
});
