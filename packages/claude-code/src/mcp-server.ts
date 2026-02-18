#!/usr/bin/env node

/**
 * Sage MCP server for Claude Code.
 * Provides two tools:
 * - sage_allowlist_add: Add a URL, command, or file path to the allowlist (requires prior user approval)
 * - sage_allowlist_remove: Remove a URL, command, or file path from the allowlist (ungated)
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
	addCommand,
	addFilePath,
	addUrl,
	hashCommand,
	type Logger,
	loadAllowlist,
	loadConfig,
	normalizeFilePath,
	normalizeUrl,
	removeCommand,
	removeFilePath,
	removeUrl,
	saveAllowlist,
} from "@sage/core";
import pino from "pino";
import { z } from "zod";
import { findConsumedApproval, removeConsumedApproval } from "./approval-tracker.js";

const logger: Logger = pino({ level: "warn" }, pino.destination(2));

const server = new McpServer({
	name: "sage",
	version: __SAGE_VERSION__,
});

declare const __SAGE_VERSION__: string;

const ARTIFACT_TYPE = z
	.enum(["url", "command", "file_path"])
	.describe("Type of artifact: url, command, or file_path");

function displayValue(type: "url" | "command" | "file_path", value: string): string {
	if (type === "url") return normalizeUrl(value);
	if (type === "command") return `command hash ${hashCommand(value).slice(0, 12)}...`;
	return normalizeFilePath(value);
}

function typeLabel(type: "url" | "command" | "file_path"): string {
	if (type === "url") return "URL";
	if (type === "command") return "command";
	return "file path";
}

server.registerTool(
	"sage_allowlist_add",
	{
		title: "Sage: Add to Allowlist",
		description:
			"Permanently allow a specific URL, command, or file path that was previously flagged by Sage. " +
			"Requires the user to have recently approved this exact artifact through Sage's security dialog.",
		inputSchema: z.object({
			type: ARTIFACT_TYPE,
			value: z.string().describe("The exact URL, command, or file path to allowlist"),
			reason: z.string().optional().describe("Why this is being allowlisted"),
		}),
	},
	async ({ type, value, reason }) => {
		try {
			const consumed = await findConsumedApproval(type, value, logger);
			if (!consumed) {
				return {
					content: [
						{
							type: "text" as const,
							text: "Cannot add to allowlist: no recent user approval found for this artifact. The user must first encounter and approve this action through Sage's security dialog, then you can permanently allowlist it.",
						},
					],
					isError: true,
				};
			}

			const config = await loadConfig(undefined, logger);
			const allowlist = await loadAllowlist(config.allowlist, logger);
			const entryReason = reason ?? `Approved by user (threat: ${consumed.threatId})`;

			if (type === "url") {
				addUrl(allowlist, value, entryReason, "ask");
			} else if (type === "command") {
				addCommand(allowlist, value, entryReason, "ask");
			} else {
				addFilePath(allowlist, value, entryReason, "ask");
			}

			await saveAllowlist(allowlist, config.allowlist, logger);
			await removeConsumedApproval(type, value, logger);

			const label = typeLabel(type);
			return {
				content: [
					{
						type: "text" as const,
						text: `Added ${label} to Sage allowlist: ${displayValue(type, value)}. This ${label} will no longer trigger security alerts.`,
					},
				],
			};
		} catch (e) {
			return {
				content: [{ type: "text" as const, text: `Failed to add to allowlist: ${e}` }],
				isError: true,
			};
		}
	},
);

server.registerTool(
	"sage_allowlist_remove",
	{
		title: "Sage: Remove from Allowlist",
		description:
			"Remove a URL, command, or file path from the Sage allowlist, restoring security checks for it.",
		inputSchema: z.object({
			type: ARTIFACT_TYPE,
			value: z
				.string()
				.describe(
					"The URL or file path to remove, or for commands: the command text or its SHA-256 hash",
				),
		}),
	},
	async ({ type, value }) => {
		try {
			const config = await loadConfig(undefined, logger);
			const allowlist = await loadAllowlist(config.allowlist, logger);

			let removed: boolean;
			if (type === "url") {
				removed = removeUrl(allowlist, value);
			} else if (type === "command") {
				// Try as hash first, then as command text
				removed = removeCommand(allowlist, value);
				if (!removed) {
					removed = removeCommand(allowlist, hashCommand(value));
				}
			} else {
				removed = removeFilePath(allowlist, value);
			}

			const label = typeLabel(type);
			if (!removed) {
				return {
					content: [
						{
							type: "text" as const,
							text: `${label} not found in the allowlist.`,
						},
					],
				};
			}

			await saveAllowlist(allowlist, config.allowlist, logger);
			return {
				content: [
					{
						type: "text" as const,
						text: `Removed ${label} from Sage allowlist. Security checks will apply to this ${label} again.`,
					},
				],
			};
		} catch (e) {
			return {
				content: [{ type: "text" as const, text: `Failed to remove from allowlist: ${e}` }],
				isError: true,
			};
		}
	},
);

async function main(): Promise<void> {
	const transport = new StdioServerTransport();
	await server.connect(transport);
}

main().catch((e) => {
	logger.error("MCP server failed", { error: String(e) });
	process.exit(1);
});
