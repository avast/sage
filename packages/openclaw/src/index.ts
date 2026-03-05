/**
 * Sage OpenClaw plugin entry point.
 * Registers before_tool_call handler, sage_approve tool, allowlist tools,
 * startup/session scan hooks, and before_agent_start handler.
 */

import { ApprovalStore } from "@sage/core";
import { createAllowlistAddTool, createAllowlistRemoveTool } from "./allowlist-tools.js";
import { getBundledDataDirs } from "./bundled-dirs.js";
import { createSageApproveTool } from "./gate-tool.js";
import { createLogger, type PluginLogger } from "./logger-adapter.js";
import {
	createBeforeAgentStartHandler,
	createSessionScanHandler,
	createStartupScanHandler,
} from "./startup-scan.js";
import { createToolCallHandler } from "./tool-handler.js";

interface PluginApi {
	logger: PluginLogger;
	// biome-ignore lint/suspicious/noExplicitAny: OpenClaw handler signatures vary by event
	on(event: string, handler: (...args: any[]) => any, options?: { priority?: number }): void;
	registerTool(tool: Record<string, unknown>): void;
}

export default {
	id: "sage-openclaw",
	name: "Sage",
	description: "Safety for Agents — ADR layer that guards commands, files, and web requests",
	configSchema: {
		jsonSchema: { type: "object", additionalProperties: false, properties: {} },
	},
	register(api: PluginApi) {
		const logger = createLogger(api.logger);
		const approvalStore = new ApprovalStore();
		const { threatsDir, allowlistsDir } = getBundledDataDirs();

		const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;
		const interval = setInterval(() => approvalStore.cleanup(), CLEANUP_INTERVAL_MS);
		if (typeof interval.unref === "function") interval.unref();

		// Shared state: scan findings waiting to be surfaced to the user
		let pendingFindings: string | null = null;
		const onFindings = (msg: string) => {
			pendingFindings = msg;
		};

		api.on(
			"before_tool_call",
			createToolCallHandler(approvalStore, logger, threatsDir, allowlistsDir),
			{ priority: 100 },
		);
		api.registerTool(createSageApproveTool(approvalStore) as unknown as Record<string, unknown>);
		api.registerTool(
			createAllowlistAddTool(approvalStore, logger) as unknown as Record<string, unknown>,
		);
		api.registerTool(createAllowlistRemoveTool(logger) as unknown as Record<string, unknown>);
		api.on("gateway_start", createStartupScanHandler(logger, onFindings));
		api.on("session_start", createSessionScanHandler(logger, onFindings));
		api.on(
			"before_agent_start",
			createBeforeAgentStartHandler(
				() => pendingFindings,
				() => {
					pendingFindings = null;
				},
				logger,
			),
		);
	},
};
