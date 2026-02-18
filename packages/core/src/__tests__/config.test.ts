import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadConfig, resolvePath } from "../config.js";
import { makeTmpDir } from "./test-utils.js";

describe("resolvePath", () => {
	it("expands ~ prefix", () => {
		const resolved = resolvePath("~/foo/bar");
		expect(resolved).not.toContain("~");
		expect(resolved).toContain(join("foo", "bar"));
	});

	it("leaves absolute paths unchanged", () => {
		expect(resolvePath("/absolute/path")).toBe("/absolute/path");
	});
});

describe("loadConfig", () => {
	it("returns defaults for missing file", async () => {
		const config = await loadConfig("/nonexistent/config.json");
		expect(config.sensitivity).toBe("balanced");
		expect(config.heuristics_enabled).toBe(true);
		expect(config.url_check.enabled).toBe(true);
		expect(config.url_check.timeout_seconds).toBe(5.0);
		expect(config.cache.enabled).toBe(true);
		expect(config.cache.ttl_malicious_seconds).toBe(3600);
		expect(config.cache.ttl_clean_seconds).toBe(86400);
	});

	it("loads valid config", async () => {
		const dir = await makeTmpDir();
		const configPath = join(dir, "config.json");
		await writeFile(
			configPath,
			JSON.stringify({
				sensitivity: "paranoid",
				heuristics_enabled: false,
				url_check: { timeout_seconds: 10 },
			}),
		);
		const config = await loadConfig(configPath);
		expect(config.sensitivity).toBe("paranoid");
		expect(config.heuristics_enabled).toBe(false);
		expect(config.url_check.timeout_seconds).toBe(10);
		// Defaults preserved for unset fields
		expect(config.url_check.enabled).toBe(true);
		expect(config.cache.enabled).toBe(true);
	});

	it("returns defaults for malformed JSON", async () => {
		const dir = await makeTmpDir();
		const configPath = join(dir, "config.json");
		await writeFile(configPath, "not json");
		const config = await loadConfig(configPath);
		expect(config.sensitivity).toBe("balanced");
	});

	it("returns defaults for non-object JSON", async () => {
		const dir = await makeTmpDir();
		const configPath = join(dir, "config.json");
		await writeFile(configPath, JSON.stringify([1, 2, 3]));
		const config = await loadConfig(configPath);
		expect(config.sensitivity).toBe("balanced");
	});

	it("defaults disabled_threats to empty array when missing", async () => {
		const config = await loadConfig("/nonexistent/config.json");
		expect(config.disabled_threats).toEqual([]);
	});

	it("parses disabled_threats string array", async () => {
		const dir = await makeTmpDir();
		const configPath = join(dir, "config.json");
		await writeFile(
			configPath,
			JSON.stringify({ disabled_threats: ["CLT-CMD-001", "CLT-CMD-002"] }),
		);
		const config = await loadConfig(configPath);
		expect(config.disabled_threats).toEqual(["CLT-CMD-001", "CLT-CMD-002"]);
	});
});
