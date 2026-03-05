/**
 * In-memory approval store for soft-gated connectors (OpenCode, OpenClaw).
 * Tracks pending→approved flow with artifact tracking and TTL expiry.
 */

import { createHash } from "node:crypto";
import type { Artifact } from "./types.js";

const PENDING_STALE_MS = 60 * 60 * 1000;
const APPROVED_TTL_MS = 10 * 60 * 1000;

export interface PendingEntry {
	artifacts: Artifact[];
	createdAt: number;
}

export interface ApprovedEntry {
	artifacts: Artifact[];
	approvedAt: number;
	expiresAt: number;
}

export class ApprovalStore {
	private readonly pending = new Map<string, PendingEntry>();
	private readonly approved = new Map<string, ApprovedEntry>();

	static actionId(toolName: string, params: Record<string, unknown>, sessionId: string): string {
		const payload = JSON.stringify({ toolName, params, sessionId });
		return createHash("sha256").update(payload).digest("hex");
	}

	static artifactId(type: string, value: string): string {
		return `${type}:${value}`;
	}

	setPending(actionId: string, entry: PendingEntry): void {
		this.pending.set(actionId, { ...entry, artifacts: [...entry.artifacts] });
	}

	deletePending(actionId: string): void {
		this.pending.delete(actionId);
	}

	approve(actionId: string): PendingEntry | null {
		const entry = this.pending.get(actionId);
		if (!entry) return null;

		const now = Date.now();
		this.approved.set(actionId, {
			artifacts: [...entry.artifacts],
			approvedAt: now,
			expiresAt: now + APPROVED_TTL_MS,
		});
		this.pending.delete(actionId);
		return entry;
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

	hasApprovedArtifact(type: string, value: string): boolean {
		return this.findApprovedAction(type, value) !== null;
	}

	consumeApprovedArtifact(type: string, value: string): boolean {
		const id = ApprovalStore.artifactId(type, value);
		for (const [actionId, entry] of this.approved.entries()) {
			if (Date.now() >= entry.expiresAt) {
				this.approved.delete(actionId);
				continue;
			}
			const idx = entry.artifacts.findIndex(
				(a) => ApprovalStore.artifactId(a.type, a.value) === id,
			);
			if (idx !== -1) {
				entry.artifacts.splice(idx, 1);
				if (entry.artifacts.length === 0) {
					this.approved.delete(actionId);
				}
				return true;
			}
		}
		return false;
	}

	private findApprovedAction(type: string, value: string): string | null {
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
				return actionId;
			}
		}
		return null;
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
