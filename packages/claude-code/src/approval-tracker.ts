/**
 * Approval tracker for Sage PostToolUse → MCP allowlist flow.
 *
 * Per-session files:
 * - pending-approvals-{sessionId}.json: Written by PreToolUse on `ask`, keyed by tool_use_id.
 * - consumed-approvals-{sessionId}.json: Written by PostToolUse after user approves, keyed by artifact hash.
 *
 * Pending entries are pruned after 1 hour. Consumed entries expire after 10 minutes.
 */

import { readdir, stat, unlink } from "node:fs/promises";
import { atomicWriteJson, getFileContent, type Logger, nullLogger, resolvePath } from "@sage/core";

const SAGE_DIR = "~/.sage";

const PENDING_STALE_MS = 60 * 60 * 1000; // 1 hour
const CONSUMED_TTL_MS = 10 * 60 * 1000; // 10 minutes
const STALE_FILE_MS = 2 * 60 * 60 * 1000; // 2 hours

export interface PendingArtifact {
	value: string;
	type: string;
}

export interface PendingApproval {
	threatId: string;
	threatTitle: string;
	artifacts: PendingArtifact[];
	createdAt: string;
}

export interface ConsumedApproval {
	threatId: string;
	threatTitle: string;
	artifact: string;
	artifactType: string;
	approvedAt: string;
	expiresAt: string;
}

type PendingStore = Record<string, PendingApproval>;
type ConsumedStore = Record<string, ConsumedApproval>;

function sanitizeSessionId(sessionId: string): string {
	return sessionId.replace(/[^a-zA-Z0-9-]/g, "_");
}

function pendingPath(sessionId: string): string {
	return `${SAGE_DIR}/pending-approvals-${sanitizeSessionId(sessionId)}.json`;
}

function consumedPath(sessionId: string): string {
	return `${SAGE_DIR}/consumed-approvals-${sanitizeSessionId(sessionId)}.json`;
}

async function loadJson<T>(path: string): Promise<T | null> {
	try {
		const raw = await getFileContent(resolvePath(path));
		return JSON.parse(raw) as T;
	} catch {
		return null;
	}
}

async function saveOrDelete(path: string, data: Record<string, unknown>): Promise<void> {
	const resolved = resolvePath(path);
	if (Object.keys(data).length === 0) {
		try {
			await unlink(resolved);
		} catch {
			// File may not exist — that's fine
		}
	} else {
		await atomicWriteJson(resolved, data);
	}
}

function pruneStalePending(store: PendingStore): PendingStore {
	const now = Date.now();
	const result: PendingStore = {};
	for (const [key, entry] of Object.entries(store)) {
		if (now - new Date(entry.createdAt).getTime() < PENDING_STALE_MS) {
			result[key] = entry;
		}
	}
	return result;
}

function pruneExpiredConsumed(store: ConsumedStore): ConsumedStore {
	const now = Date.now();
	const result: ConsumedStore = {};
	for (const [key, entry] of Object.entries(store)) {
		if (new Date(entry.expiresAt).getTime() > now) {
			result[key] = entry;
		}
	}
	return result;
}

/** Stable key for consumed-approvals lookup. */
function consumedKey(artifactType: string, artifact: string): string {
	return `${artifactType}:${artifact}`;
}

export async function addPendingApproval(
	sessionId: string,
	toolUseId: string,
	approval: Omit<PendingApproval, "createdAt">,
	logger: Logger = nullLogger,
): Promise<void> {
	try {
		let store = (await loadJson<PendingStore>(pendingPath(sessionId))) ?? {};
		store = pruneStalePending(store);
		store[toolUseId] = { ...approval, createdAt: new Date().toISOString() };
		await saveOrDelete(pendingPath(sessionId), store);
	} catch (e) {
		logger.warn("Failed to write pending approval", { error: String(e) });
	}
}

export async function consumePendingApproval(
	sessionId: string,
	toolUseId: string,
	logger: Logger = nullLogger,
): Promise<PendingApproval | null> {
	try {
		let store = (await loadJson<PendingStore>(pendingPath(sessionId))) ?? {};
		store = pruneStalePending(store);
		const entry = store[toolUseId];
		if (!entry) return null;

		// Remove from pending
		delete store[toolUseId];
		await saveOrDelete(pendingPath(sessionId), store);

		// Write one consumed entry per artifact
		let consumed = (await loadJson<ConsumedStore>(consumedPath(sessionId))) ?? {};
		consumed = pruneExpiredConsumed(consumed);
		const now = new Date();
		for (const art of entry.artifacts) {
			const key = consumedKey(art.type, art.value);
			consumed[key] = {
				threatId: entry.threatId,
				threatTitle: entry.threatTitle,
				artifact: art.value,
				artifactType: art.type,
				approvedAt: now.toISOString(),
				expiresAt: new Date(now.getTime() + CONSUMED_TTL_MS).toISOString(),
			};
		}
		await saveOrDelete(consumedPath(sessionId), consumed);

		return entry;
	} catch (e) {
		logger.warn("Failed to consume pending approval", { error: String(e) });
		return null;
	}
}

export async function findConsumedApproval(
	sessionId: string,
	artifactType: string,
	artifact: string,
	logger: Logger = nullLogger,
): Promise<ConsumedApproval | null> {
	try {
		let store = (await loadJson<ConsumedStore>(consumedPath(sessionId))) ?? {};
		store = pruneExpiredConsumed(store);
		// Write back if pruning removed anything
		await saveOrDelete(consumedPath(sessionId), store);

		const key = consumedKey(artifactType, artifact);
		return store[key] ?? null;
	} catch (e) {
		logger.warn("Failed to read consumed approvals", { error: String(e) });
		return null;
	}
}

export async function removeConsumedApproval(
	sessionId: string,
	artifactType: string,
	artifact: string,
	logger: Logger = nullLogger,
): Promise<void> {
	try {
		let store = (await loadJson<ConsumedStore>(consumedPath(sessionId))) ?? {};
		store = pruneExpiredConsumed(store);
		const key = consumedKey(artifactType, artifact);
		delete store[key];
		await saveOrDelete(consumedPath(sessionId), store);
	} catch (e) {
		logger.warn("Failed to remove consumed approval", { error: String(e) });
	}
}

// --- Cross-session functions (for MCP server, which has no session_id) ---

async function listSessionFiles(prefix: string): Promise<string[]> {
	try {
		const dir = resolvePath(SAGE_DIR);
		const entries = await readdir(dir);
		return entries.filter((f) => f.startsWith(prefix) && f.endsWith(".json"));
	} catch {
		return [];
	}
}

export async function findConsumedApprovalAcrossSessions(
	artifactType: string,
	artifact: string,
	_logger: Logger = nullLogger,
): Promise<ConsumedApproval | null> {
	const files = await listSessionFiles("consumed-approvals-");
	const key = consumedKey(artifactType, artifact);

	for (const file of files) {
		try {
			const path = `${SAGE_DIR}/${file}`;
			let store = (await loadJson<ConsumedStore>(path)) ?? {};
			store = pruneExpiredConsumed(store);
			await saveOrDelete(path, store);

			const entry = store[key];
			if (entry) return entry;
		} catch {
			// Best-effort — continue to next file
		}
	}
	return null;
}

export async function removeConsumedApprovalAcrossSessions(
	artifactType: string,
	artifact: string,
	_logger: Logger = nullLogger,
): Promise<void> {
	const files = await listSessionFiles("consumed-approvals-");
	const key = consumedKey(artifactType, artifact);

	for (const file of files) {
		try {
			const path = `${SAGE_DIR}/${file}`;
			let store = (await loadJson<ConsumedStore>(path)) ?? {};
			store = pruneExpiredConsumed(store);
			if (key in store) {
				delete store[key];
				await saveOrDelete(path, store);
			}
		} catch {
			// Best-effort — continue to next file
		}
	}
}

// --- Stale file cleanup ---

export async function pruneStaleSessionFiles(logger: Logger = nullLogger): Promise<void> {
	try {
		const dir = resolvePath(SAGE_DIR);
		const entries = await readdir(dir);
		const now = Date.now();

		for (const file of entries) {
			if (
				!(file.startsWith("pending-approvals-") || file.startsWith("consumed-approvals-")) ||
				!file.endsWith(".json")
			) {
				continue;
			}

			try {
				const fullPath = `${dir}/${file}`;
				const info = await stat(fullPath);
				if (now - info.mtimeMs < STALE_FILE_MS) continue;

				const path = `${SAGE_DIR}/${file}`;
				if (file.startsWith("pending-approvals-")) {
					let store = (await loadJson<PendingStore>(path)) ?? {};
					store = pruneStalePending(store);
					await saveOrDelete(path, store);
				} else {
					let store = (await loadJson<ConsumedStore>(path)) ?? {};
					store = pruneExpiredConsumed(store);
					await saveOrDelete(path, store);
				}
			} catch {
				// Best-effort per file
			}
		}
	} catch (e) {
		logger.warn("Failed to prune stale session files", { error: String(e) });
	}
}
