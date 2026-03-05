import { describe, expect, it } from "vitest";
import { CONFIDENCE_THRESHOLD, DecisionEngine } from "../engine.js";
import type { AmsiCheckResult, PackageCheckResult, UrlCheckResult } from "../types.js";
import { makeMatch } from "./test-helper.js";

describe("DecisionEngine", () => {
	it("returns allow for no signals", async () => {
		const engine = new DecisionEngine();
		const verdict = await engine.decide({ heuristicMatches: [], urlCheckResults: [] });
		expect(verdict.decision).toBe("allow");
		expect(verdict.category).toBe("none");
		expect(verdict.confidence).toBe(1.0);
	});

	it("returns deny for heuristic block", async () => {
		const engine = new DecisionEngine();
		const match = makeMatch({ action: "block", confidence: 0.95, severity: "critical" });
		const verdict = await engine.decide({ heuristicMatches: [match], urlCheckResults: [] });
		expect(verdict.decision).toBe("deny");
		expect(verdict.severity).toBe("critical");
		expect(verdict.source).toBe("heuristic");
	});

	it("returns ask for require_approval", async () => {
		const engine = new DecisionEngine();
		const match = makeMatch({ action: "require_approval", confidence: 0.9, severity: "high" });
		const verdict = await engine.decide({ heuristicMatches: [match], urlCheckResults: [] });
		expect(verdict.decision).toBe("ask");
		expect(verdict.severity).toBe("warning");
	});

	it("returns allow for log action", async () => {
		const engine = new DecisionEngine();
		const match = makeMatch({ action: "log", confidence: 0.9, severity: "low" });
		const verdict = await engine.decide({ heuristicMatches: [match], urlCheckResults: [] });
		expect(verdict.decision).toBe("allow");
		expect(verdict.severity).toBe("info");
	});

	it("returns deny for malicious URL check", async () => {
		const engine = new DecisionEngine();
		const result: UrlCheckResult = {
			url: "http://untrusted.test",
			isMalicious: true,
			findings: [{ severityName: "malware", typeName: "trojan" }],
			flags: [],
		};
		const verdict = await engine.decide({ heuristicMatches: [], urlCheckResults: [result] });
		expect(verdict.decision).toBe("deny");
		expect(verdict.confidence).toBe(1.0);
		expect(verdict.severity).toBe("critical");
		expect(verdict.source).toBe("url_check");
	});

	it("returns ask for URL check flag", async () => {
		const engine = new DecisionEngine();
		const result: UrlCheckResult = {
			url: "http://g00gle.test",
			isMalicious: false,
			findings: [],
			flags: ["TYPOSQUATTING"],
		};
		const verdict = await engine.decide({ heuristicMatches: [], urlCheckResults: [result] });
		expect(verdict.decision).toBe("ask");
		expect(verdict.severity).toBe("warning");
		expect(verdict.confidence).toBe(0.75);
	});

	it("deny wins over ask in merge", async () => {
		const engine = new DecisionEngine();
		const askMatch = makeMatch({
			id: "CLT-ASK",
			action: "require_approval",
			confidence: 0.9,
			severity: "high",
		});
		const denyMatch = makeMatch({
			id: "CLT-DENY",
			action: "block",
			confidence: 0.95,
			severity: "critical",
		});
		const verdict = await engine.decide({
			heuristicMatches: [askMatch, denyMatch],
			urlCheckResults: [],
		});
		expect(verdict.decision).toBe("deny");
	});

	it("keeps deny at exact threshold", async () => {
		const engine = new DecisionEngine();
		const match = makeMatch({
			action: "block",
			confidence: CONFIDENCE_THRESHOLD,
			severity: "critical",
		});
		const verdict = await engine.decide({ heuristicMatches: [match], urlCheckResults: [] });
		expect(verdict.decision).toBe("deny");
	});

	it("softens deny to ask below threshold", async () => {
		const engine = new DecisionEngine();
		const match = makeMatch({ action: "block", confidence: 0.8, severity: "critical" });
		const verdict = await engine.decide({ heuristicMatches: [match], urlCheckResults: [] });
		expect(verdict.decision).toBe("ask");
	});

	it("maps high severity to warning", async () => {
		const engine = new DecisionEngine();
		const match = makeMatch({ action: "block", confidence: 0.95, severity: "high" });
		const verdict = await engine.decide({ heuristicMatches: [match], urlCheckResults: [] });
		expect(verdict.severity).toBe("warning");
	});

	it("maps medium severity to warning", async () => {
		const engine = new DecisionEngine();
		const match = makeMatch({
			action: "require_approval",
			confidence: 0.9,
			severity: "medium",
		});
		const verdict = await engine.decide({ heuristicMatches: [match], urlCheckResults: [] });
		expect(verdict.severity).toBe("warning");
	});

	it("maps low severity to info", async () => {
		const engine = new DecisionEngine();
		const match = makeMatch({ action: "log", confidence: 0.9, severity: "low" });
		const verdict = await engine.decide({ heuristicMatches: [match], urlCheckResults: [] });
		expect(verdict.severity).toBe("info");
	});

	it("collects all reasons from multiple signals", async () => {
		const engine = new DecisionEngine();
		const m1 = makeMatch({ id: "CLT-1", action: "block", confidence: 0.95, title: "Reason A" });
		const m2 = makeMatch({
			id: "CLT-2",
			action: "require_approval",
			confidence: 0.9,
			title: "Reason B",
		});
		const verdict = await engine.decide({ heuristicMatches: [m1, m2], urlCheckResults: [] });
		expect(verdict.reasons).toHaveLength(2);
	});

	it("malicious URL check wins combined verdict", async () => {
		const engine = new DecisionEngine();
		const match = makeMatch({
			action: "require_approval",
			confidence: 0.9,
			severity: "high",
		});
		const urlCheck: UrlCheckResult = {
			url: "http://untrusted.test",
			isMalicious: true,
			findings: [{ severityName: "malware", typeName: "trojan" }],
			flags: [],
		};
		const verdict = await engine.decide({
			heuristicMatches: [match],
			urlCheckResults: [urlCheck],
		});
		expect(verdict.decision).toBe("deny");
		expect(verdict.confidence).toBe(1.0);
	});

	it("includes matched threat ID", async () => {
		const engine = new DecisionEngine();
		const match = makeMatch({ id: "CLT-CMD-001", action: "block", confidence: 0.95 });
		const verdict = await engine.decide({ heuristicMatches: [match], urlCheckResults: [] });
		expect(verdict.matchedThreatId).toBe("CLT-CMD-001");
	});
});

describe("PackageCheckSignals", () => {
	it("package not_found produces deny/critical", async () => {
		const engine = new DecisionEngine();
		const pkg: PackageCheckResult = {
			packageName: "hallucinated-pkg",
			registry: "npm",
			verdict: "not_found",
			confidence: 0.95,
			details: "Package does not exist on npm.",
		};
		const verdict = await engine.decide({
			heuristicMatches: [],
			urlCheckResults: [],
			packageCheckResults: [pkg],
		});
		expect(verdict.decision).toBe("deny");
		expect(verdict.severity).toBe("critical");
		expect(verdict.confidence).toBe(0.95);
		expect(verdict.source).toBe("package_check");
	});

	it("package malicious produces deny/critical at 1.0", async () => {
		const engine = new DecisionEngine();
		const pkg: PackageCheckResult = {
			packageName: "malicious-pkg",
			registry: "npm",
			verdict: "malicious",
			confidence: 1.0,
			details: "Package flagged as malicious.",
		};
		const verdict = await engine.decide({
			heuristicMatches: [],
			urlCheckResults: [],
			packageCheckResults: [pkg],
		});
		expect(verdict.decision).toBe("deny");
		expect(verdict.severity).toBe("critical");
		expect(verdict.confidence).toBe(1.0);
	});

	it("package suspicious_age produces ask/warning", async () => {
		const engine = new DecisionEngine();
		const pkg: PackageCheckResult = {
			packageName: "new-pkg",
			registry: "npm",
			verdict: "suspicious_age",
			confidence: 0.75,
			details: "Package first published 2 days ago.",
		};
		const verdict = await engine.decide({
			heuristicMatches: [],
			urlCheckResults: [],
			packageCheckResults: [pkg],
		});
		expect(verdict.decision).toBe("ask");
		expect(verdict.severity).toBe("warning");
	});

	it("package clean produces no signal (allow)", async () => {
		const engine = new DecisionEngine();
		const pkg: PackageCheckResult = {
			packageName: "express",
			registry: "npm",
			verdict: "clean",
			confidence: 1.0,
			details: "Package verified.",
		};
		const verdict = await engine.decide({
			heuristicMatches: [],
			urlCheckResults: [],
			packageCheckResults: [pkg],
		});
		expect(verdict.decision).toBe("allow");
	});

	it("package signal combined with heuristic — highest priority wins", async () => {
		const engine = new DecisionEngine();
		const match = makeMatch({ action: "require_approval", confidence: 0.9, severity: "high" });
		const pkg: PackageCheckResult = {
			packageName: "malicious-pkg",
			registry: "npm",
			verdict: "malicious",
			confidence: 1.0,
			details: "Malicious.",
		};
		const verdict = await engine.decide({
			heuristicMatches: [match],
			urlCheckResults: [],
			packageCheckResults: [pkg],
		});
		expect(verdict.decision).toBe("deny");
		expect(verdict.confidence).toBe(1.0);
	});

	it("SignalSources object format works correctly", async () => {
		const engine = new DecisionEngine();
		const verdict = await engine.decide({
			heuristicMatches: [],
			urlCheckResults: [],
			packageCheckResults: [],
		});
		expect(verdict.decision).toBe("allow");
	});
});

describe("SensitivityPresets", () => {
	it("paranoid does not soften at 0.75", async () => {
		const engine = new DecisionEngine("paranoid");
		const match = makeMatch({ action: "block", confidence: 0.75, severity: "critical" });
		const verdict = await engine.decide({ heuristicMatches: [match], urlCheckResults: [] });
		expect(verdict.decision).toBe("deny");
	});

	it("paranoid softens below 0.70", async () => {
		const engine = new DecisionEngine("paranoid");
		const match = makeMatch({ action: "block", confidence: 0.65, severity: "critical" });
		const verdict = await engine.decide({ heuristicMatches: [match], urlCheckResults: [] });
		expect(verdict.decision).toBe("ask");
	});

	it("relaxed softens below 0.95", async () => {
		const engine = new DecisionEngine("relaxed");
		const match = makeMatch({ action: "block", confidence: 0.9, severity: "critical" });
		const verdict = await engine.decide({ heuristicMatches: [match], urlCheckResults: [] });
		expect(verdict.decision).toBe("ask");
	});

	it("relaxed keeps deny at 0.95", async () => {
		const engine = new DecisionEngine("relaxed");
		const match = makeMatch({ action: "block", confidence: 0.95, severity: "critical" });
		const verdict = await engine.decide({ heuristicMatches: [match], urlCheckResults: [] });
		expect(verdict.decision).toBe("deny");
	});

	it("balanced is default", async () => {
		const engine = new DecisionEngine();
		const match = makeMatch({ action: "block", confidence: 0.84, severity: "critical" });
		const verdict = await engine.decide({ heuristicMatches: [match], urlCheckResults: [] });
		expect(verdict.decision).toBe("ask");
	});

	it("unknown sensitivity falls back to default", async () => {
		const engine = new DecisionEngine("unknown");
		const match = makeMatch({ action: "block", confidence: 0.84, severity: "critical" });
		const verdict = await engine.decide({ heuristicMatches: [match], urlCheckResults: [] });
		expect(verdict.decision).toBe("ask");
	});
});

describe("AmsiCheckSignals", () => {
	it("AMSI detected produces deny/critical at 1.0", async () => {
		const engine = new DecisionEngine();
		const amsi: AmsiCheckResult = {
			content: "malicious content",
			contentName: "Bash:command",
			amsiResult: 32768,
			isDetected: true,
			isBlockedByAdmin: false,
		};
		const verdict = await engine.decide({
			heuristicMatches: [],
			urlCheckResults: [],
			amsiCheckResults: [amsi],
		});
		expect(verdict.decision).toBe("deny");
		expect(verdict.severity).toBe("critical");
		expect(verdict.confidence).toBe(1.0);
		expect(verdict.source).toBe("amsi");
		expect(verdict.category).toBe("malware");
	});

	it("AMSI blocked by admin produces deny/critical at 0.9", async () => {
		const engine = new DecisionEngine();
		const amsi: AmsiCheckResult = {
			content: "blocked content",
			contentName: "Write:/tmp/test.ps1",
			amsiResult: 16384,
			isDetected: false,
			isBlockedByAdmin: true,
		};
		const verdict = await engine.decide({
			heuristicMatches: [],
			urlCheckResults: [],
			amsiCheckResults: [amsi],
		});
		expect(verdict.decision).toBe("deny");
		expect(verdict.severity).toBe("critical");
		expect(verdict.confidence).toBe(0.9);
		expect(verdict.source).toBe("amsi");
	});

	it("AMSI clean produces no signal (allow)", async () => {
		const engine = new DecisionEngine();
		const amsi: AmsiCheckResult = {
			content: "echo hello",
			contentName: "Bash:command",
			amsiResult: 0,
			isDetected: false,
			isBlockedByAdmin: false,
		};
		const verdict = await engine.decide({
			heuristicMatches: [],
			urlCheckResults: [],
			amsiCheckResults: [amsi],
		});
		expect(verdict.decision).toBe("allow");
	});

	it("AMSI detected wins over heuristic ask (merge precedence)", async () => {
		const engine = new DecisionEngine();
		const match = makeMatch({ action: "require_approval", confidence: 0.9, severity: "high" });
		const amsi: AmsiCheckResult = {
			content: "malicious",
			contentName: "Bash:command",
			amsiResult: 32768,
			isDetected: true,
			isBlockedByAdmin: false,
		};
		const verdict = await engine.decide({
			heuristicMatches: [match],
			urlCheckResults: [],
			amsiCheckResults: [amsi],
		});
		expect(verdict.decision).toBe("deny");
		expect(verdict.confidence).toBe(1.0);
	});
});
