import type { Artifact } from "@sage/core";

export function formatApprovalSuccess(actionId: string): string {
	return `Approved action ${actionId}. Retry the original tool call now.`;
}

export function artifactTypeLabel(type: string): string {
	if (type === "url") return "URL";
	if (type === "command") return "command";
	if (type === "file_path") return "file path";
	return type;
}

export function summarizeArtifacts(artifacts: Artifact[]): string {
	if (artifacts.length === 0) return "none";
	return artifacts
		.slice(0, 3)
		.map((artifact) => `${artifact.type} '${artifact.value}'`)
		.join(", ");
}
