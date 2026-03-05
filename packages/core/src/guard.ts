/**
 * Guard orchestrator for soft-gated connectors (OpenCode, OpenClaw).
 * Wraps evaluateToolCall with approval store checks, paranoid promotion,
 * and shared message formatting / allowlist operations.
 */

import {
	addCommand,
	addFilePath,
	addUrl,
	loadAllowlist,
	removeCommand,
	removeFilePath,
	removeUrl,
	saveAllowlist,
} from "./allowlist.js";
import { ApprovalStore } from "./approval-store.js";
import { loadConfig } from "./config.js";
import type { ToolEvaluationContext, ToolEvaluationRequest } from "./evaluator.js";
import { allowVerdict, evaluateToolCall } from "./evaluator.js";
import type { Artifact, Logger, Verdict } from "./types.js";
import { nullLogger } from "./types.js";
import { hashCommand, normalizeFilePath, normalizeUrl } from "./url-utils.js";

// ── guardToolCall ──────────────────────────────────────────────────

export interface GuardResult {
	verdict: Verdict;
	actionId?: string;
}

export async function guardToolCall(
	request: ToolEvaluationRequest,
	context: ToolEvaluationContext,
	approvalStore: ApprovalStore,
): Promise<GuardResult> {
	const actionId = ApprovalStore.actionId(request.toolName, request.toolInput, request.sessionId);

	if (approvalStore.isApproved(actionId)) {
		return { verdict: allowVerdict("approved") };
	}

	const verdict = await evaluateToolCall(request, context);

	if (verdict.decision === "allow" || verdict.decision === "deny") {
		return { verdict };
	}

	// ask verdict — check paranoid mode
	const logger = context.logger ?? nullLogger;
	const config = await loadConfig(context.configPath, logger);
	if (config.sensitivity === "paranoid") {
		return { verdict: { ...verdict, decision: "deny" } };
	}

	approvalStore.setPending(actionId, {
		artifacts: request.artifacts,
		createdAt: Date.now(),
	});

	return { verdict, actionId };
}

// ── Message formatting ─────────────────────────────────────────────

const MAX_ARTIFACT_VALUE_LEN = 120;

function truncateValue(value: string): string {
	const singleLine = value.replaceAll("\n", "\\n");
	if (singleLine.length <= MAX_ARTIFACT_VALUE_LEN) return singleLine;
	return `${singleLine.slice(0, MAX_ARTIFACT_VALUE_LEN)}…`;
}

export function summarizeArtifacts(artifacts: Artifact[]): string {
	if (artifacts.length === 0) return "none";
	return artifacts
		.slice(0, 3)
		.map((artifact) => `${artifact.type} '${truncateValue(artifact.value)}'`)
		.join(", ");
}

export function formatDenyMessage(verdict: Verdict): string {
	const reasons =
		verdict.reasons.length > 0 ? verdict.reasons.slice(0, 5).join("; ") : verdict.category;

	return [
		"Sage blocked this action.",
		`Severity: ${verdict.severity}`,
		`Category: ${verdict.category}`,
		`Reason: ${reasons}`,
	].join("\n");
}

export function formatAskMessage(
	actionId: string,
	verdict: Verdict,
	artifacts: Artifact[],
): string {
	const reasons =
		verdict.reasons.length > 0 ? verdict.reasons.slice(0, 3).join("; ") : verdict.category;

	return [
		"Sage flagged this action and requires explicit user approval.",
		`Severity: ${verdict.severity}`,
		`Category: ${verdict.category}`,
		`Reason: ${reasons}`,
		`Artifacts: ${summarizeArtifacts(artifacts)}`,
		"",
		"Ask the user for confirmation to proceed, DO NOT auto-approve.",
		`if the user confirms, call:`,
		`  sage_approve({ actionId: "${actionId}", approved: true })`,
		"If the user declines, call:",
		`  sage_approve({ actionId: "${actionId}", approved: false })`,
	].join("\n");
}

// ── Allowlist tool logic ───────────────────────────────────────────

export async function approveAction(store: ApprovalStore, actionId: string): Promise<string> {
	const entry = store.approve(actionId);
	if (!entry) {
		return "No pending Sage approval found for this action ID.";
	}
	return [
		`Approved action ${actionId}. Retry the original tool call now.`,
		"",
		"Inform the user that they can ask you to permanently allowlist this artifact. Do NOT add it to the allowlist unless the user explicitly requests it.",
	].join("\n");
}

export async function addToAllowlist(
	store: ApprovalStore,
	type: "url" | "command" | "file_path",
	value: string,
	reason?: string,
	configPath?: string,
	logger: Logger = nullLogger,
): Promise<string> {
	if (!store.hasApprovedArtifact(type, value)) {
		return "Cannot add to allowlist: no recent user approval found for this artifact.";
	}

	const config = await loadConfig(configPath, logger);
	const allowlist = await loadAllowlist(config.allowlist, logger);
	const entryReason = reason ?? "Approved by user via sage_approve";

	if (type === "url") {
		addUrl(allowlist, value, entryReason, "ask");
	} else if (type === "command") {
		addCommand(allowlist, value, entryReason, "ask");
	} else {
		addFilePath(allowlist, value, entryReason, "ask");
	}

	const saved = await saveAllowlist(allowlist, config.allowlist, logger);
	if (!saved) {
		return "Failed to save allowlist. Approval preserved — retry is safe.";
	}
	store.consumeApprovedArtifact(type, value);
	return `Added ${type} to Sage allowlist.`;
}

export async function removeFromAllowlist(
	type: "url" | "command" | "file_path",
	value: string,
	configPath?: string,
	logger: Logger = nullLogger,
): Promise<string> {
	const config = await loadConfig(configPath, logger);
	const allowlist = await loadAllowlist(config.allowlist, logger);

	let removed: boolean;
	let removedViaHash = false;
	switch (type) {
		case "url":
			removed = removeUrl(allowlist, value);
			break;
		case "command":
			removed = removeCommand(allowlist, value);
			if (!removed) {
				removed = removeCommand(allowlist, hashCommand(value));
				removedViaHash = true;
			}
			break;
		case "file_path":
			removed = removeFilePath(allowlist, value);
			break;
	}

	if (!removed) {
		return "Artifact not found in Sage allowlist.";
	}

	const saved = await saveAllowlist(allowlist, config.allowlist, logger);
	if (!saved) {
		return "Failed to save allowlist after removal. Please retry.";
	}
	let rendered: string;
	switch (type) {
		case "url":
			rendered = normalizeUrl(value);
			break;
		case "command":
			rendered = `${(removedViaHash ? hashCommand(value) : value).slice(0, 12)}...`;
			break;
		case "file_path":
			rendered = normalizeFilePath(value);
			break;
	}
	return `Removed ${type} from Sage allowlist: ${rendered}`;
}
