/**
 * In-memory approval store for OpenCode ask-flow.
 */

import { createHash } from "node:crypto";
import type { Artifact, Verdict } from "@sage/core";

const PENDING_STALE_MS = 60 * 60 * 1000;
const APPROVED_TTL_MS = 10 * 60 * 1000;

export interface PendingApproval {
	sessionId: string;
	artifacts: Artifact[];
	verdict: Verdict;
	createdAt: number;
}

export interface ApprovedAction {
	sessionId: string;
	artifacts: Artifact[];
	verdict: Verdict;
	approvedAt: number;
	expiresAt: number;
}

/**
 * An in-memory approval store for a given opencode session.
 */
export class ApprovalStore {
	private readonly pending = new Map<string, PendingApproval>();
	private readonly approved = new Map<string, ApprovedAction>();

	static actionId(toolName: string, params: Record<string, unknown>): string {
		const payload = JSON.stringify({ toolName, params });
		return createHash("sha256").update(payload).digest("hex").slice(0, 24);
	}

	static artifactId(type: string, value: string): string {
		return `${type}:${value}`;
	}

	setPending(actionId: string, approval: PendingApproval): void {
		this.pending.set(actionId, approval);
	}

	getPending(actionId: string): PendingApproval | undefined {
		return this.pending.get(actionId);
	}

	deletePending(actionId: string): void {
		this.pending.delete(actionId);
	}

	approve(actionId: string): PendingApproval | null {
		const pending = this.pending.get(actionId);
		if (!pending) return null;

		const now = Date.now();
		this.approved.set(actionId, {
			sessionId: pending.sessionId,
			artifacts: pending.artifacts,
			verdict: pending.verdict,
			approvedAt: now,
			expiresAt: now + APPROVED_TTL_MS,
		});
		this.pending.delete(actionId);
		return pending;
	}

	isApproved(actionId: string): boolean {
		const entry = this.approved.get(actionId);
		if (!entry) return false;
		if (Date.now() >= entry.expiresAt) {
			this.approved.delete(actionId);
			return false;
		}
		return true;
	}

	getApproved(actionId: string): ApprovedAction | null {
		const entry = this.approved.get(actionId);
		if (!entry) return null;
		if (Date.now() >= entry.expiresAt) {
			this.approved.delete(actionId);
			return null;
		}
		return entry;
	}

	hasApprovedArtifact(type: string, value: string): boolean {
		const id = ApprovalStore.artifactId(type, value);
		for (const [actionId, entry] of this.approved.entries()) {
			if (Date.now() >= entry.expiresAt) {
				this.approved.delete(actionId);
				continue;
			}
			if (
				entry.artifacts.some(
					(artifact) => ApprovalStore.artifactId(artifact.type, artifact.value) === id,
				)
			) {
				return true;
			}
		}
		return false;
	}

	consumeApprovedArtifact(type: string, value: string): boolean {
		const id = ApprovalStore.artifactId(type, value);
		for (const [actionId, entry] of this.approved.entries()) {
			if (Date.now() >= entry.expiresAt) {
				this.approved.delete(actionId);
				continue;
			}
			if (
				entry.artifacts.some(
					(artifact) => ApprovalStore.artifactId(artifact.type, artifact.value) === id,
				)
			) {
				this.approved.delete(actionId);
				return true;
			}
		}
		return false;
	}

	cleanup(now = Date.now()): void {
		for (const [actionId, entry] of this.pending.entries()) {
			if (now - entry.createdAt >= PENDING_STALE_MS) {
				this.pending.delete(actionId);
			}
		}
		for (const [actionId, entry] of this.approved.entries()) {
			if (now >= entry.expiresAt) {
				this.approved.delete(actionId);
			}
		}
	}
}
