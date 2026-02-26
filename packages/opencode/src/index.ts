/**
 * Sage OpenCode plugin.
 * Intercepts tool calls and uses @sage/core to enforce security verdicts.
 */

import type { Plugin } from "@opencode-ai/plugin";
import { tool } from "@opencode-ai/plugin/tool";
import {
	addCommand,
	addFilePath,
	addUrl,
	hashCommand,
	loadAllowlist,
	loadConfig,
	normalizeFilePath,
	normalizeUrl,
	removeCommand,
	removeFilePath,
	removeUrl,
	saveAllowlist,
} from "@sage/core";
import { ApprovalStore } from "./approval-store.js";
import { getBundledDataDirs } from "./bundled-dirs.js";
import { formatApprovalSuccess } from "./format.js";
import { OpencodeLogger } from "./logger-adaptor.js";
import { createSessionScanHandler } from "./startup-scan.js";
import { createToolHanlders } from "./tool-handler.js";

const APPROVAL_STORE_CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

export const SagePlugin: Plugin = async ({ client, directory }) => {
	const logger = new OpencodeLogger(client);
	const { threatsDir, allowlistsDir } = getBundledDataDirs();
	const approvalStore = new ApprovalStore();

	// State: track findings per session for one-shot injection
	let pendingFindings: string | null = null;

	// Set up the cron job that cleans up the approval store.
	const interval = setInterval(() => {
		approvalStore.cleanup();
	}, APPROVAL_STORE_CLEANUP_INTERVAL_MS);
	interval.unref?.();

	const ARTIFACT_TYPE = tool.schema.enum(["url", "command", "file_path"]);

	const toolHanlders = createToolHanlders(logger, approvalStore, threatsDir, allowlistsDir);

	return {
		"tool.execute.before": toolHanlders["tool.execute.before"],
		"tool.execute.after": toolHanlders["tool.execute.after"],

		/**
			* Inject plugin scan findings into first user message as <system-reminder>.
			* This approach leverages OpenCode's existing pattern of appending system
			* reminders to user messages (e.g., plan mode constraints), enabling the
			* agent to reason about security findings before tool execution. Appending
			* to assistant messages or system prompts was less effective.
		*/
		"experimental.chat.messages.transform": async (input, output) => {
			if (!pendingFindings) return;
			const userMessage = output.messages.filter(m => m.info.role === "user");

			const message = userMessage[0];
			if (!message) return; // We append the scan result to the first user message

			const textPart = {
				id: crypto.randomUUID(),
				sessionID: message.info.sessionID,
				messageID: message.info.id,
				type: "text" as const,
				text: [
					`<system-reminder>`,
					pendingFindings,
					"",
					"Inform the user about these security findings.",
					`<system-reminder>`,
				].join("\n"),
				synthetic: true  // Mark as synthetic/injected
			};
			message.parts.push(textPart);

			logger.info(`Injected sage plugin scan findings to user message`, { findings: pendingFindings});
			pendingFindings = null;
		},

		// Event hook for session.created
		event: async ({ event }) => {
			// Only scan on session.created (not session.updated)
			if (event.type === "session.created") {
				// biome-ignore lint/suspicious/noExplicitAny: Event types from SDK not fully typed
				const sessionID = (event as any).sessionID ?? (event as any).id ?? "unknown";

				try {
					logger.debug("Sage: starting session scan", { sessionID });

					// Run scan with callback to capture findings
					await createSessionScanHandler(logger, directory, (findings) => {
						pendingFindings = findings;
					})();
				} catch (error) {
					logger.error("Sage session scan failed (fail-open)", {
						sessionID,
						error: String(error),
					});
				}
			}
		},

		tool: {
			sage_approve: tool({
				description:
					"Approve or reject a Sage-flagged tool call. IMPORTANT: you MUST ask the user for explicit confirmation in the conversation BEFORE calling this tool. Never auto-approve - always present the flagged action and wait for the user to response.",
				args: {
					actionId: tool.schema.string().describe("Action ID from Sage blocked message"),
					approved: tool.schema.boolean().describe("true to approve, false to reject"),
				},
				async execute(args: { actionId: string; approved: boolean }, _context) {
					if (!args.approved) {
						approvalStore.deletePending(args.actionId);
						return "Rejected by user.";
					}

					const entry = approvalStore.approve(args.actionId);
					if (!entry) {
						return "No pending Sage approval found for this action ID.";
					}

					return formatApprovalSuccess(args.actionId);
				},
			}),
			sage_allowlist_add: tool({
				description:
					"Permanently allow a URL, command, or file path after recent user approval through Sage.",
				args: {
					type: ARTIFACT_TYPE,
					value: tool.schema.string().describe("Exact URL, command, or file path to allowlist"),
					reason: tool.schema.string().optional().describe("Optional reason for allowlist entry"),
				},
				async execute(args: {
					type: "url" | "command" | "file_path";
					value: string;
					reason?: string;
				}) {
					if (!approvalStore.hasApprovedArtifact(args.type, args.value)) {
						return "Cannot add to allowlist: no recent user approval found for this artifact.";
					}

					const config = await loadConfig(undefined, logger);
					const allowlist = await loadAllowlist(config.allowlist, logger);
					const reason = args.reason ?? "Approved by user via sage_approve";

					if (args.type === "url") {
						addUrl(allowlist, args.value, reason, "ask");
					} else if (args.type === "command") {
						addCommand(allowlist, args.value, reason, "ask");
					} else {
						addFilePath(allowlist, args.value, reason, "ask");
					}

					await saveAllowlist(allowlist, config.allowlist, logger);
					approvalStore.consumeApprovedArtifact(args.type, args.value);
					return `Added ${args.type} to Sage allowlist.`;
				},
			}),
			sage_allowlist_remove: tool({
				description: "Remove a URL, command, or file path from the Sage allowlist.",
				args: {
					type: ARTIFACT_TYPE,
					value: tool.schema
						.string()
						.describe("URL/file path, or command text/command hash for command entries"),
				},
				async execute(args: { type: "url" | "command" | "file_path"; value: string }) {
					const config = await loadConfig(undefined, logger);
					const allowlist = await loadAllowlist(config.allowlist, logger);

					let removed = false;
					if (args.type === "url") {
						removed = removeUrl(allowlist, args.value);
					} else if (args.type === "command") {
						removed = removeCommand(allowlist, args.value);
						if (!removed) {
							removed = removeCommand(allowlist, hashCommand(args.value));
						}
					} else {
						removed = removeFilePath(allowlist, args.value);
					}

					if (!removed) {
						return "Artifact not found in Sage allowlist.";
					}

					await saveAllowlist(allowlist, config.allowlist, logger);
					const rendered =
						args.type === "url"
							? normalizeUrl(args.value)
							: args.type === "command"
								? `${hashCommand(args.value).slice(0, 12)}...`
								: normalizeFilePath(args.value);
					return `Removed ${args.type} from Sage allowlist: ${rendered}`;
				},
			}),
		},
	};
};

export default SagePlugin;
