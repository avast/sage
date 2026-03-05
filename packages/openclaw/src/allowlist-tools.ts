/**
 * sage_allowlist_add and sage_allowlist_remove tools for OpenClaw.
 */

import { type ApprovalStore, addToAllowlist, type Logger, removeFromAllowlist } from "@sage/core";
import type { ToolDefinition } from "./gate-tool.js";

export function createAllowlistAddTool(
	approvalStore: ApprovalStore,
	logger?: Logger,
): ToolDefinition {
	return {
		name: "sage_allowlist_add",
		description:
			"Permanently allow a URL, command, or file path after recent user approval through Sage.",
		parameters: {
			type: "object",
			properties: {
				type: {
					type: "string",
					enum: ["url", "command", "file_path"],
					description: "Artifact type",
				},
				value: {
					type: "string",
					description: "Exact URL, command, or file path to allowlist",
				},
				reason: {
					type: "string",
					description: "Optional reason for allowlist entry",
				},
			},
			required: ["type", "value"],
		},
		async execute(_toolCallId, params) {
			const { type, value, reason } = params as unknown as {
				type: "url" | "command" | "file_path";
				value: string;
				reason?: string;
			};
			const msg = await addToAllowlist(approvalStore, type, value, reason, undefined, logger);
			return { content: [{ type: "text", text: msg }] };
		},
	};
}

export function createAllowlistRemoveTool(logger?: Logger): ToolDefinition {
	return {
		name: "sage_allowlist_remove",
		description: "Remove a URL, command, or file path from the Sage allowlist.",
		parameters: {
			type: "object",
			properties: {
				type: {
					type: "string",
					enum: ["url", "command", "file_path"],
					description: "Artifact type",
				},
				value: {
					type: "string",
					description: "URL/file path, or command text/command hash for command entries",
				},
			},
			required: ["type", "value"],
		},
		async execute(_toolCallId, params) {
			const { type, value } = params as unknown as {
				type: "url" | "command" | "file_path";
				value: string;
			};
			const msg = await removeFromAllowlist(type, value, undefined, logger);
			return { content: [{ type: "text", text: msg }] };
		},
	};
}
