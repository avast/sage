/**
 * Sage OpenCode plugin.
 * Intercepts tool calls and uses @sage/core to enforce security verdicts.
 */

import type { Plugin } from "@opencode-ai/plugin";
import { tool } from "@opencode-ai/plugin/tool";
import { ApprovalStore, addToAllowlist, approveAction, removeFromAllowlist } from "@sage/core";
import { getBundledDataDirs } from "./bundled-dirs.js";
import { OpencodeLogger } from "./logger-adaptor.js";
import { createSessionScanHandler } from "./startup-scan.js";
import { createToolHandlers } from "./tool-handler.js";

const APPROVAL_STORE_CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

export const SagePlugin: Plugin = async ({ client, directory }) => {
	const logger = new OpencodeLogger(client);
	const { threatsDir, allowlistsDir } = getBundledDataDirs();
	const approvalStore = new ApprovalStore();

	// State: track findings per session for one-shot injection
	const pendingFindingsBySession = new Map<string, string>();

	// Set up the cron job that cleans up the approval store.
	const interval = setInterval(() => {
		approvalStore.cleanup();
	}, APPROVAL_STORE_CLEANUP_INTERVAL_MS);
	interval.unref?.();

	const ARTIFACT_TYPE = tool.schema.enum(["url", "command", "file_path"]);

	const toolHandlers = createToolHandlers(logger, approvalStore, threatsDir, allowlistsDir);

	return {
		"tool.execute.before": toolHandlers["tool.execute.before"],

		/**
		 * Inject plugin scan findings into first user message as <system-reminder>.
		 * This approach leverages OpenCode's existing pattern of appending system
		 * reminders to user messages (e.g., plan mode constraints), enabling the
		 * agent to reason about security findings before tool execution. Appending
		 * to assistant messages or system prompts was less effective.
		 */
		"experimental.chat.messages.transform": async (_input, output) => {
			if (pendingFindingsBySession.size === 0) return;

			const userMessage = output.messages.filter((m) => m.info.role === "user");
			const message = userMessage[0];
			if (!message) return;

			const sessionID = message.info.sessionID;
			const findings = pendingFindingsBySession.get(sessionID);
			if (!findings) return;

			const textPart = {
				id: crypto.randomUUID(),
				sessionID,
				messageID: message.info.id,
				type: "text" as const,
				text: [
					`<system-reminder>`,
					findings,
					"",
					"Inform the user about these security findings.",
					`</system-reminder>`,
				].join("\n"),
				synthetic: true,
			};
			message.parts.push(textPart);

			logger.info(`Injected sage plugin scan findings to user message`, {
				findings,
			});
			pendingFindingsBySession.delete(sessionID);
		},

		// Event hook for session.created
		event: async ({ event }) => {
			if (event.type === "session.created") {
				// biome-ignore lint/suspicious/noExplicitAny: Event types from SDK not fully typed
				const sessionID = (event as any).sessionID ?? (event as any).id ?? "unknown";

				try {
					logger.debug("Sage: starting session scan", { sessionID });

					await createSessionScanHandler(logger, directory, (msg) => {
						pendingFindingsBySession.set(sessionID, msg);
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
			// TODO: After the following PR merged to support client V2 in Opencode Plugin, gitleaks:allow
			// use QuestionTools.ask to replace sage_approve tool
			// PR: https://github.com/anomalyco/opencode/pull/12046
			// Discussion: https://github.com/avast/sage/pull/21#discussion_r2873812399
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
					return approveAction(approvalStore, args.actionId);
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
					return addToAllowlist(
						approvalStore,
						args.type,
						args.value,
						args.reason,
						undefined,
						logger,
					);
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
					return removeFromAllowlist(args.type, args.value, undefined, logger);
				},
			}),
		},
	};
};

export default SagePlugin;
