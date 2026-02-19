import { mkdir, readdir, readFile, stat, utimes, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { atomicWriteJson, pruneOrphanedTmpFiles } from "../file-utils.js";
import { makeTmpDir } from "./test-utils.js";

describe("atomicWriteJson", () => {
	let dir: string;

	beforeEach(async () => {
		dir = await makeTmpDir();
	});

	it("writes JSON and leaves no temp on success", async () => {
		const target = join(dir, "data.json");
		await atomicWriteJson(target, { key: "value" });

		const content = await readFile(target, "utf-8");
		expect(JSON.parse(content)).toEqual({ key: "value" });

		// No .tmp files left behind
		const files = await readdir(dir);
		expect(files.filter((f) => f.endsWith(".tmp"))).toHaveLength(0);
	});

	it("cleans temp file on rename failure", async () => {
		// Write to a path where the final rename will fail (target is a directory)
		const target = join(dir, "subdir");
		await mkdir(target);

		await expect(atomicWriteJson(target, { x: 1 })).rejects.toThrow();

		// No .tmp files should remain in the parent dir
		const files = await readdir(dir);
		expect(files.filter((f) => f.endsWith(".tmp"))).toHaveLength(0);
	});

	it("creates parent directories", async () => {
		const target = join(dir, "nested", "deep", "data.json");
		await atomicWriteJson(target, [1, 2, 3]);

		const content = await readFile(target, "utf-8");
		expect(JSON.parse(content)).toEqual([1, 2, 3]);
	});
});

describe("pruneOrphanedTmpFiles", () => {
	let dir: string;

	beforeEach(async () => {
		dir = await makeTmpDir();
	});

	it("removes old .tmp files", async () => {
		const tmpFile = join(dir, "cache.json.abc123.tmp");
		await writeFile(tmpFile, "orphaned");

		// Set mtime to 10 minutes ago
		const past = new Date(Date.now() - 600_000);
		await utimes(tmpFile, past, past);

		await pruneOrphanedTmpFiles(dir, 300_000);

		await expect(stat(tmpFile)).rejects.toThrow();
	});

	it("preserves recent .tmp files", async () => {
		const tmpFile = join(dir, "cache.json.abc123.tmp");
		await writeFile(tmpFile, "recent");
		// mtime is now, which is within the 5-minute window

		await pruneOrphanedTmpFiles(dir, 300_000);

		// File should still exist
		const content = await readFile(tmpFile, "utf-8");
		expect(content).toBe("recent");
	});

	it("ignores non-.tmp files", async () => {
		const normalFile = join(dir, "config.json");
		await writeFile(normalFile, "keep me");

		const past = new Date(Date.now() - 600_000);
		await utimes(normalFile, past, past);

		await pruneOrphanedTmpFiles(dir, 300_000);

		const content = await readFile(normalFile, "utf-8");
		expect(content).toBe("keep me");
	});

	it("handles nonexistent directory gracefully", async () => {
		// Should not throw
		await pruneOrphanedTmpFiles(join(dir, "does-not-exist"), 300_000);
	});
});
