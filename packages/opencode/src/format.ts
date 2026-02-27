import type { Artifact, Verdict } from "@sage/core";

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

function summarizeArtifacts(artifacts: Artifact[]): string {
	if (artifacts.length === 0) return "none";
	return artifacts
		.slice(0, 3)
		.map((artifact) => `${artifact.type} '${artifact.value}'`)
		.join(", ");
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

export function formatApprovalSuccess(actionId: string): string {
	return `Approved action ${actionId}. Retry the original tool call now.`;
}

export function artifactTypeLabel(type: string): string {
	if (type === "url") return "URL";
	if (type === "command") return "command";
	if (type === "file_path") return "file path";
	return type;
}
