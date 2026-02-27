import {
	evaluateToolCall,
	isAllowlisted,
	type Logger,
	loadAllowlist,
	loadConfig,
} from "@sage/core";
import { ApprovalStore } from "./approval-store.js";
import { extractFromOpenCodeTool } from "./extractors.js";
import { artifactTypeLabel, formatAskMessage, formatDenyMessage } from "./format.js";

export const createToolHandlers = (
	logger: Logger,
	approvalStore: ApprovalStore,
	threatsDir: string,
	allowlistsDir: string,
) => {
	const beforeToolUse = async (
		input: { tool: string; sessionID: string; callID: string },
		output: { args: Record<string, unknown> },
	): Promise<void> => {
		logger.debug(`tool.execute.before hook invoked (tool=${input.tool})`);

		try {
			const args = output.args ?? {};
			const actionId = ApprovalStore.actionId(input.tool, args);
			if (approvalStore.isApproved(actionId)) {
				return;
			}

			const artifacts = extractFromOpenCodeTool(input.tool, args);

			// Tool not mapped -> pass through
			if (!artifacts || artifacts.length === 0) {
				return;
			}

			const config = await loadConfig(undefined, logger);
			const allowlist = await loadAllowlist(config.allowlist, logger);
			if (isAllowlisted(allowlist, artifacts)) {
				return;
			}

			const verdict = await evaluateToolCall(
				{
					sessionId: input.sessionID,
					toolName: input.tool,
					toolInput: args,
					artifacts,
				},
				{
					threatsDir,
					allowlistsDir,
					logger,
				},
			);

			if (verdict.decision === "allow") {
				return;
			}

			if (verdict.decision === "deny") {
				throw new Error(formatDenyMessage(verdict));
			}

			approvalStore.setPending(actionId, {
				sessionId: input.sessionID,
				artifacts,
				verdict,
				createdAt: Date.now(),
			});

			throw new Error(formatAskMessage(actionId, verdict, artifacts));
		} catch (error) {
			if (error instanceof Error && error.message.startsWith("Sage")) {
				throw error;
			}
			logger.error("Sage opencode hook failed open", { error: String(error), tool: input.tool });
		}
	};

	const afterToolUse = async (
		input: { tool: string; sessionID: string; callID: string; args: Record<string, unknown> },
		output: { title: string; output: string; metadata: unknown },
	): Promise<void> => {
		logger.debug(`tool.execute.after hook invoked (tool=${input.tool})`);

		try {
			const actionId = ApprovalStore.actionId(input.tool, input.args);

			// Get the approved entry (includes artifacts and verdict)
			const entry = approvalStore.getApproved(actionId);
			if (!entry) {
				return;
			}

			// Format the artifacts list for the message
			const artifactList = entry.artifacts
				.map((a) => `${artifactTypeLabel(a.type)} '${a.value}'`)
				.join(", ");

			// Determine the artifact type(s) for the suggestion message
			const typeSet = [...new Set(entry.artifacts.map((a) => artifactTypeLabel(a.type)))];
			const typeStr = typeSet.join("/");

			// Build the suggestion message
			const suggestionText = `To permanently allow ${
				typeStr === "URL"
					? "these URLs"
					: typeStr === "command"
						? "these commands"
						: `these ${typeStr}s`
			} in the future, you can use the sage_allowlist_add tool.`;

			const threatReason = entry.verdict.reasons.at(0) ?? entry.verdict.category;
			const message = [
				`Sage: The user approved a flagged action.`,
				`Threat: ${threatReason}`,
				`Artifacts: ${artifactList}`,
				suggestionText,
			].join("\n");

			// Append to the output
			output.output = output.output ? `${output.output}\n\n${message}` : message;
		} catch (error) {
			logger.error("Sage afterToolUse hook failed", { error: String(error), tool: input.tool });
		}
	};

	return {
		"tool.execute.before": beforeToolUse,
		"tool.execute.after": afterToolUse,
	};
};
