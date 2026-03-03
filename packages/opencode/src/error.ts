import type { Artifact, Verdict } from "@sage/core";
import { summarizeArtifacts } from "./format.js";

export abstract class SageVerdictError extends Error {
	constructor(message: string, name?: string) {
		super(message);
		this.name = name ?? "SageVerdictError";
	}
}

export class SageVerdictBlockError extends SageVerdictError {
	constructor(verdict: Verdict) {
		const reasons =
			verdict.reasons.length > 0 ? verdict.reasons.slice(0, 5).join("; ") : verdict.category;

		const message = [
			"Sage blocked this action.",
			`Severity: ${verdict.severity}`,
			`Category: ${verdict.category}`,
			`Reason: ${reasons}`,
		].join("\n");

		super(message, "SageVerdictBlockError");
	}
}

// TODO: After the following PR merged to support client V2 in Opencode Plugin,
// Invoke QueestionTool.ask instead and deprecate this error
// PR: https://github.com/anomalyco/opencode/pull/12046
export class SageVerdictAskError extends SageVerdictError {
	constructor(actionId: string, verdict: Verdict, artifacts: Artifact[]) {
		const reasons =
			verdict.reasons.length > 0 ? verdict.reasons.slice(0, 3).join("; ") : verdict.category;
		const message = [
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

		super(message, "SageVerdictAskError");
	}
}
