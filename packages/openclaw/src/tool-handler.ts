/**
 * before_tool_call handler: extracts artifacts from tool calls,
 * evaluates them through guardToolCall, returns block/pass decisions.
 */

import {
	type ApprovalStore,
	type Artifact,
	extractFromBash,
	extractFromEdit,
	extractFromWebFetch,
	extractFromWrite,
	formatAskMessage,
	formatDenyMessage,
	guardToolCall,
	type Logger,
} from "@sage/core";

export interface ToolCallEvent {
	toolName: string;
	params: Record<string, unknown>;
}

export interface ToolCallContext {
	sessionKey?: string;
}

export interface BlockResult {
	block: true;
	blockReason: string;
}

function extractFilePaths(patch: string): Artifact[] {
	// OpenClaw apply_patch uses unified diff format; extract file paths from --- and +++ lines
	const artifacts: Artifact[] = [];
	for (const line of patch.split("\n")) {
		const match = line.match(/^(?:---|\+\+\+)\s+(?:a\/|b\/)?(.+)/);
		if (match?.[1] && match[1] !== "/dev/null") {
			artifacts.push({ type: "file_path", value: match[1], context: "apply_patch" });
		}
	}
	return artifacts;
}

function mapToolToArtifacts(toolName: string, params: Record<string, unknown>): Artifact[] | null {
	switch (toolName) {
		case "exec": {
			const command = (params.command ?? "") as string;
			return command ? extractFromBash(command) : null;
		}
		case "web_fetch":
			return extractFromWebFetch({ url: params.url });
		case "write":
			return extractFromWrite({ file_path: params.path, content: params.content });
		case "edit":
			return extractFromEdit({ file_path: params.path, new_string: params.new_string });
		case "read": {
			const path = (params.path ?? "") as string;
			return path ? [{ type: "file_path", value: path, context: "read" }] : null;
		}
		case "apply_patch": {
			const patch = (params.patch ?? "") as string;
			return patch ? extractFilePaths(patch) : null;
		}
		default:
			return null;
	}
}

export function createToolCallHandler(
	approvalStore: ApprovalStore,
	logger: Logger,
	threatsDir: string,
	allowlistsDir: string,
): (event: ToolCallEvent, ctx?: ToolCallContext) => Promise<BlockResult | undefined> {
	async function handleToolCall(
		event: ToolCallEvent,
		ctx?: ToolCallContext,
	): Promise<BlockResult | undefined> {
		try {
			const { toolName, params } = event;

			// Map tool → artifacts. No artifacts → pass through.
			const artifacts = mapToolToArtifacts(toolName, params);
			if (!artifacts || artifacts.length === 0) return undefined;

			const sessionId = ctx?.sessionKey ?? "unknown";
			const { verdict, actionId } = await guardToolCall(
				{ sessionId, toolName, toolInput: params, artifacts },
				{ threatsDir, allowlistsDir, logger },
				approvalStore,
			);

			if (verdict.decision === "allow") return undefined;

			if (verdict.decision === "deny") {
				return { block: true, blockReason: formatDenyMessage(verdict) };
			}

			// ask — actionId is always set for ask verdicts
			return {
				block: true,
				blockReason: formatAskMessage(actionId as string, verdict, artifacts),
			};
		} catch (e) {
			// Fail-open: any unhandled error → pass through
			logger.error("tool-handler error, failing open", { error: String(e) });
			return undefined;
		}
	}

	return handleToolCall;
}
