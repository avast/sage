/**
 * Installation ID — a random UUID persisted at ~/.sage/installation-id.
 * Generated once on first session start via crypto.randomUUID() and reused
 * thereafter. A fresh ~/.sage directory produces a new UUID.
 * Fail-open: returns undefined on any error.
 */

import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { resolvePath } from "./config.js";

/**
 * Read the installation ID from disk, generating a new one if it doesn't exist.
 * Returns undefined on unrecoverable error (fail-open).
 */
export async function getInstallationId(sageDirPath?: string): Promise<string | undefined> {
	const sageDir = sageDirPath ?? resolvePath("~/.sage");
	const idPath = join(sageDir, "installation-id");

	let fileExists = false;
	try {
		const existing = await readFile(idPath, "utf-8");
		const trimmed = existing.trim();
		if (trimmed.length > 0) return trimmed;
		fileExists = true;
	} catch {
		// File doesn't exist — fall through to generate
	}

	try {
		const id = randomUUID();
		await mkdir(sageDir, { recursive: true, mode: 0o700 });
		await writeFile(idPath, id, { encoding: "utf-8", mode: 0o600, flag: fileExists ? "w" : "wx" });
		return id;
	} catch (err: unknown) {
		if ((err as NodeJS.ErrnoException).code === "EEXIST") {
			try {
				const existing = await readFile(idPath, "utf-8");
				return existing.trim() || undefined;
			} catch {
				return undefined;
			}
		}
		return undefined;
	}
}
