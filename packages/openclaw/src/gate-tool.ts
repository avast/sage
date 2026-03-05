/**
 * sage_approve gate tool — allows the agent to approve or reject
 * Sage-flagged tool calls after user confirmation.
 */

import { type ApprovalStore, approveAction } from "@sage/core";

export interface ToolDefinition {
	name: string;
	description: string;
	parameters: Record<string, unknown>;
	execute(
		toolCallId: string,
		params: { actionId: string; approved: boolean },
	): Promise<{ content: Array<{ type: string; text: string }> }>;
}

export function createSageApproveTool(approvalStore: ApprovalStore): ToolDefinition {
	return {
		name: "sage_approve",
		description:
			"Approve or reject a Sage-flagged tool call. IMPORTANT: You MUST ask the user for explicit confirmation in the conversation BEFORE calling this tool. Never auto-approve — always present the flagged action and wait for the user to respond.",
		parameters: {
			type: "object",
			properties: {
				actionId: {
					type: "string",
					description: "Action ID from Sage block reason",
				},
				approved: {
					type: "boolean",
					description: "true to approve, false to reject",
				},
			},
			required: ["actionId", "approved"],
		},
		async execute(_toolCallId, params) {
			if (!params.approved) {
				approvalStore.deletePending(params.actionId);
				return {
					content: [{ type: "text", text: "Rejected by user." }],
				};
			}
			const msg = await approveAction(approvalStore, params.actionId);
			return {
				content: [{ type: "text", text: msg }],
			};
		},
	};
}
