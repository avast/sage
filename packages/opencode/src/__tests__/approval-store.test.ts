import { describe, expect, it } from "vitest";
import { ApprovalStore } from "../approval-store.js";

describe("ApprovalStore", () => {
	it("stores and approves pending actions", () => {
		const store = new ApprovalStore();
		store.setPending("a1", {
			sessionId: "s1",
			artifacts: [{ type: "command", value: "chmod 777 ./x.sh" }],
			verdict: {
				decision: "ask",
				category: "risky_permissions",
				confidence: 0.8,
				severity: "warning",
				source: "heuristics",
				artifacts: ["chmod 777 ./x.sh"],
				matchedThreatId: "CLT-CMD-011",
				reasons: ["World-writable permissions"],
			},
			createdAt: Date.now(),
		});

		expect(store.isApproved("a1")).toBe(false);
		const approved = store.approve("a1");
		expect(approved).toBeTruthy();
		expect(store.isApproved("a1")).toBe(true);
	});

	it("actionId is stable for identical tool payloads", () => {
		const one = ApprovalStore.actionId("bash", { command: "ls -la" });
		const two = ApprovalStore.actionId("bash", { command: "ls -la" });
		expect(one).toBe(two);
	});

	it("cleanup removes stale pending approvals", () => {
		const store = new ApprovalStore();
		store.setPending("a1", {
			sessionId: "s1",
			artifacts: [{ type: "url", value: "http://test" }],
			verdict: {
				decision: "ask",
				category: "network_egress",
				confidence: 0.8,
				severity: "warning",
				source: "heuristics",
				artifacts: ["http://test"],
				matchedThreatId: "T1",
				reasons: ["r"],
			},
			createdAt: Date.now() - 2 * 60 * 60 * 1000,
		});
		store.cleanup();
		expect(store.getPending("a1")).toBeUndefined();
	});

	it("consumeApprovedArtifact is single-use", () => {
		const store = new ApprovalStore();
		store.setPending("a1", {
			sessionId: "s1",
			artifacts: [{ type: "url", value: "https://example.com" }],
			verdict: {
				decision: "ask",
				category: "network_egress",
				confidence: 0.8,
				severity: "warning",
				source: "heuristics",
				artifacts: ["https://example.com"],
				matchedThreatId: "T1",
				reasons: ["r"],
			},
			createdAt: Date.now(),
		});
		store.approve("a1");

		expect(store.hasApprovedArtifact("url", "https://example.com")).toBe(true);
		expect(store.consumeApprovedArtifact("url", "https://example.com")).toBe(true);
		expect(store.hasApprovedArtifact("url", "https://example.com")).toBe(false);
	});
});
