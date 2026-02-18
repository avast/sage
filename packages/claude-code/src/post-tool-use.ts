#!/usr/bin/env node
/**
 * Sage PostToolUse hook entry point.
 * Detects user approvals of ask verdicts and records them for MCP allowlist flow.
 * Always exits 0 and returns valid JSON.
 */

import { readFileSync } from "node:fs";
import type { Logger } from "@sage/core";
import pino from "pino";
import { consumePendingApproval } from "./approval-tracker.js";
import { artifactTypeLabel } from "./format.js";

const logger: Logger = pino({ level: "warn" }, pino.destination(2));

async function main(): Promise<void> {
	let rawInput: string;
	try {
		rawInput = readFileSync(0, "utf-8");
	} catch {
		process.stdout.write("{}\n");
		return;
	}

	let hookInput: Record<string, unknown>;
	try {
		hookInput = JSON.parse(rawInput) as Record<string, unknown>;
	} catch {
		process.stdout.write("{}\n");
		return;
	}

	const toolUseId = (hookInput.tool_use_id ?? "") as string;
	const sessionId = (hookInput.session_id ?? "unknown") as string;
	if (!toolUseId) {
		process.stdout.write("{}\n");
		return;
	}

	const entry = await consumePendingApproval(sessionId, toolUseId, logger);
	if (!entry) {
		// No pending approval for this tool call — most calls hit this path.
		process.stdout.write("{}\n");
		return;
	}

	const artifactList = entry.artifacts
		.map((a) => `${artifactTypeLabel(a.type)} '${a.value}'`)
		.join(", ");

	const typeSet = [...new Set(entry.artifacts.map((a) => artifactTypeLabel(a.type)))];
	const typeStr = typeSet.join("/");

	const response = {
		hookSpecificOutput: {
			hookEventName: "PostToolUse",
			additionalContext: `Sage: The user approved a flagged action (threat ${entry.threatId}: ${entry.threatTitle}, artifacts: ${artifactList}). To permanently allow ${typeStr === "URL" ? "these URLs" : typeStr === "command" ? "these commands" : `these ${typeStr}s`} in the future, you can use the sage_allowlist_add MCP tool.`,
		},
	};

	process.stdout.write(`${JSON.stringify(response)}\n`);
}

main().catch(() => {
	process.stdout.write("{}\n");
});
