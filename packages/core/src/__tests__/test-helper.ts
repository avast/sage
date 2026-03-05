import { resolve } from "node:path";
import { HeuristicsEngine } from "../heuristics.js";
import { loadThreats } from "../threat-loader.js";
import type { Artifact, HeuristicMatch, Threat } from "../types.js";

const THREATS_DIR = resolve(__dirname, "..", "..", "..", "..", "threats");

export async function loadEngine(): Promise<HeuristicsEngine> {
	const threats = await loadThreats(THREATS_DIR);
	return new HeuristicsEngine(threats);
}

export function makeThreat(overrides: Partial<Threat> = {}): Threat {
	return {
		id: "CLT-TEST-001",
		category: "tool",
		severity: "critical",
		confidence: 0.95,
		action: "block",
		pattern: "test",
		compiledPattern: new RegExp(overrides.pattern ?? "test"),
		matchOn: new Set(["command"]),
		title: "Test threat",
		expiresAt: null,
		revoked: false,
		...overrides,
	};
}

export function makeMatch(overrides: Partial<Threat> = {}): HeuristicMatch {
	return {
		threat: makeThreat(overrides),
		artifact: "test_command",
		matchValue: "test",
	};
}

export function createMatcher(
	artifactType: "command" | "content" | "file_path",
): (engine: HeuristicsEngine, value: string) => string[] {
	return (engine: HeuristicsEngine, value: string): string[] => {
		const artifacts: Artifact[] = [{ type: artifactType, value }];
		return engine.match(artifacts).map((m) => m.threat.id);
	};
}
