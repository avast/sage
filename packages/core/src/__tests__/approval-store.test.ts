import { describe, expect, it } from "vitest";
import { ApprovalStore } from "../approval-store.js";

describe("ApprovalStore", () => {
	it("setPending / approve / isApproved workflow", () => {
		const store = new ApprovalStore();
		store.setPending("a1", {
			artifacts: [{ type: "command", value: "chmod 777 ./x.sh" }],
			createdAt: Date.now(),
		});

		expect(store.isApproved("a1")).toBe(false);
		const entry = store.approve("a1");
		expect(entry).toBeTruthy();
		expect(entry?.artifacts[0].value).toBe("chmod 777 ./x.sh");
		expect(store.isApproved("a1")).toBe(true);
	});

	it("approve returns null for unknown actionId", () => {
		const store = new ApprovalStore();
		expect(store.approve("nonexistent")).toBeNull();
	});

	it("actionId produces stable full SHA256 hashes", () => {
		const one = ApprovalStore.actionId("bash", { command: "ls -la" }, "s1");
		const two = ApprovalStore.actionId("bash", { command: "ls -la" }, "s1");
		expect(one).toBe(two);
		expect(one).toHaveLength(64); // full SHA256 hex
	});

	it("actionId differs for different inputs", () => {
		const a = ApprovalStore.actionId("bash", { command: "ls" }, "s1");
		const b = ApprovalStore.actionId("bash", { command: "pwd" }, "s1");
		expect(a).not.toBe(b);
	});

	it("actionId differs for different sessions", () => {
		const a = ApprovalStore.actionId("bash", { command: "ls" }, "s1");
		const b = ApprovalStore.actionId("bash", { command: "ls" }, "s2");
		expect(a).not.toBe(b);
	});

	it("isApproved returns false after TTL expiry", () => {
		const store = new ApprovalStore();
		store.setPending("a1", {
			artifacts: [{ type: "url", value: "http://test" }],
			createdAt: Date.now(),
		});
		store.approve("a1");
		expect(store.isApproved("a1")).toBe(true);

		// Simulate expiry by manipulating the entry
		// Access private field for testing
		const approved = (store as unknown as { approved: Map<string, { expiresAt: number }> })
			.approved;
		const entry = approved.get("a1");
		expect(entry).toBeDefined();
		if (entry) entry.expiresAt = Date.now() - 1;

		expect(store.isApproved("a1")).toBe(false);
	});

	it("hasApprovedArtifact finds matching artifact", () => {
		const store = new ApprovalStore();
		store.setPending("a1", {
			artifacts: [
				{ type: "url", value: "https://example.com" },
				{ type: "command", value: "curl http://x" },
			],
			createdAt: Date.now(),
		});
		store.approve("a1");

		expect(store.hasApprovedArtifact("url", "https://example.com")).toBe(true);
		expect(store.hasApprovedArtifact("command", "curl http://x")).toBe(true);
		expect(store.hasApprovedArtifact("url", "https://other.com")).toBe(false);
	});

	it("consumeApprovedArtifact is single-use", () => {
		const store = new ApprovalStore();
		store.setPending("a1", {
			artifacts: [{ type: "url", value: "https://example.com" }],
			createdAt: Date.now(),
		});
		store.approve("a1");

		expect(store.hasApprovedArtifact("url", "https://example.com")).toBe(true);
		expect(store.consumeApprovedArtifact("url", "https://example.com")).toBe(true);
		expect(store.hasApprovedArtifact("url", "https://example.com")).toBe(false);
		expect(store.consumeApprovedArtifact("url", "https://example.com")).toBe(false);
	});

	it("consumeApprovedArtifact removes only the matched artifact, leaving others", () => {
		const store = new ApprovalStore();
		store.setPending("a1", {
			artifacts: [
				{ type: "url", value: "https://example.com" },
				{ type: "command", value: "curl http://x" },
			],
			createdAt: Date.now(),
		});
		store.approve("a1");

		// Consuming the URL should leave the command intact
		expect(store.consumeApprovedArtifact("url", "https://example.com")).toBe(true);
		expect(store.hasApprovedArtifact("url", "https://example.com")).toBe(false);
		expect(store.hasApprovedArtifact("command", "curl http://x")).toBe(true);

		// Consuming the command removes the last artifact and the entire entry
		expect(store.consumeApprovedArtifact("command", "curl http://x")).toBe(true);
		expect(store.hasApprovedArtifact("command", "curl http://x")).toBe(false);
	});

	it("cleanup prunes stale pending entries", () => {
		const store = new ApprovalStore();
		store.setPending("a1", {
			artifacts: [{ type: "url", value: "http://test" }],
			createdAt: Date.now() - 2 * 60 * 60 * 1000, // 2 hours ago
		});
		store.cleanup();

		// Verify pending was removed (approve returns null)
		expect(store.approve("a1")).toBeNull();
	});

	it("cleanup prunes expired approved entries", () => {
		const store = new ApprovalStore();
		store.setPending("a1", {
			artifacts: [{ type: "url", value: "http://test" }],
			createdAt: Date.now(),
		});
		store.approve("a1");

		// Simulate expiry
		const approved = (store as unknown as { approved: Map<string, { expiresAt: number }> })
			.approved;
		const entry = approved.get("a1");
		expect(entry).toBeDefined();
		if (entry) entry.expiresAt = Date.now() - 1;

		store.cleanup();
		expect(store.isApproved("a1")).toBe(false);
	});

	it("deletePending removes pending entry", () => {
		const store = new ApprovalStore();
		store.setPending("a1", {
			artifacts: [{ type: "command", value: "rm -rf /" }],
			createdAt: Date.now(),
		});
		store.deletePending("a1");
		expect(store.approve("a1")).toBeNull();
	});

	it("artifactId format is type:value", () => {
		expect(ApprovalStore.artifactId("url", "https://x.com")).toBe("url:https://x.com");
		expect(ApprovalStore.artifactId("command", "ls")).toBe("command:ls");
	});

	it("setPending and approve clone artifacts to prevent shared mutation", () => {
		const store = new ApprovalStore();
		const artifacts = [{ type: "command" as const, value: "rm -rf /" }];

		store.setPending("a1", { artifacts, createdAt: Date.now() });

		// Mutating the original array should not affect the stored entry
		artifacts.push({ type: "url" as const, value: "https://evil.test" });

		const entry = store.approve("a1");
		expect(entry).toBeTruthy();
		expect(entry?.artifacts).toHaveLength(1);
		expect(entry?.artifacts[0].value).toBe("rm -rf /");

		// Mutating the returned pending entry should not affect the approved entry
		entry?.artifacts.push({ type: "url", value: "https://sneaky.test" });
		expect(store.hasApprovedArtifact("url", "https://sneaky.test")).toBe(false);
	});
});
