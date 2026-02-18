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
	if (!toolUseId) {
		process.stdout.write("{}\n");
		return;
	}

	const entry = await consumePendingApproval(toolUseId, logger);
	if (!entry) {
		// No pending approval for this tool call — most calls hit this path.
		process.stdout.write("{}\n");
		return;
	}

	const typeLabels: Record<string, string> = {
		url: "URL",
		command: "command",
		file_path: "file path",
	};
	const label = typeLabels[entry.artifactType] ?? entry.artifactType;

	const response = {
		hookSpecificOutput: {
			hookEventName: "PostToolUse",
			additionalContext: `Sage: The user approved a flagged action (threat ${entry.threatId}: ${entry.threatTitle}, artifact: '${entry.artifact}'). To permanently allow this specific ${label} in the future, you can use the sage_allowlist_add MCP tool.`,
		},
	};

	process.stdout.write(`${JSON.stringify(response)}\n`);
}

main().catch(() => {
	process.stdout.write("{}\n");
});
