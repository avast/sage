/**
 * File-backed approval persistence for the sage_approve gate tool.
 * Stores action approvals with TTL expiration at ~/.sage/approvals.json.
 */

import { createHash } from "node:crypto";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { Logger } from "@sage/core";
import { getFileContent } from "@sage/core";

const DEFAULT_PATH = join(homedir(), ".sage", "approvals.json");
const DEFAULT_TTL_SECONDS = 300;

interface ApprovalEntry {
	approvedAt: string;
	expiresAt: string;
}

type ApprovalData = Record<string, ApprovalEntry>;

export class ApprovalStore {
	private data: ApprovalData = {};
	private readonly path: string;
	private readonly logger: Logger;

	constructor(logger: Logger, path = DEFAULT_PATH) {
		this.logger = logger;
		this.path = path;
	}

	async load(): Promise<void> {
		try {
			const raw = await getFileContent(this.path);
			const parsed = JSON.parse(raw) as ApprovalData;
			const now = Date.now();
			this.data = {};
			for (const [id, entry] of Object.entries(parsed)) {
				// Only keep non-expired entries
				if (entry && new Date(entry.expiresAt).getTime() > now) {
					this.data[id] = entry;
				}
			}
		} catch {
			// Missing or corrupt file — start empty
			this.data = {};
		}
	}

	isApproved(actionId: string): boolean {
		const entry = this.data[actionId];
		if (!entry) return false;
		if (new Date(entry.expiresAt).getTime() <= Date.now()) {
			delete this.data[actionId];
			return false;
		}
		return true;
	}

	async approve(actionId: string, ttlSeconds = DEFAULT_TTL_SECONDS): Promise<void> {
		const now = new Date();
		this.data[actionId] = {
			approvedAt: now.toISOString(),
			expiresAt: new Date(now.getTime() + ttlSeconds * 1000).toISOString(),
		};
		await this.save();
	}

	private async save(): Promise<void> {
		try {
			await mkdir(dirname(this.path), { recursive: true });
			await writeFile(this.path, JSON.stringify(this.data, null, 2));
			try {
				await chmod(this.path, 0o600);
			} catch {
				// Ignore chmod errors
			}
		} catch (e) {
			this.logger.warn(`Failed to save approvals to ${this.path}`, { error: String(e) });
		}
	}

	static actionId(toolName: string, params: Record<string, unknown>): string {
		const payload = JSON.stringify({ toolName, params });
		return createHash("sha256").update(payload).digest("hex");
	}
}
