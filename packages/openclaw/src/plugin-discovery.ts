/**
 * Discovers installed OpenClaw extensions for plugin scanning.
 * Walks ~/.openclaw/extensions/ for directories with package.json.
 */

import { readdir, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Logger, PluginInfo } from "@sage/core";
import { getFileContent } from "@sage/core";

const DEFAULT_EXTENSIONS_DIR = join(homedir(), ".openclaw", "extensions");

export async function discoverOpenClawPlugins(
	logger: Logger,
	extensionsDir = DEFAULT_EXTENSIONS_DIR,
): Promise<PluginInfo[]> {
	logger.info("Sage plugin discovery: scanning extensions directory", { path: extensionsDir });

	let entries: string[];
	try {
		entries = await readdir(extensionsDir);
	} catch {
		logger.debug("OpenClaw extensions directory not found", { path: extensionsDir });
		return [];
	}

	const plugins: PluginInfo[] = [];

	for (const entry of entries) {
		const extDir = join(extensionsDir, entry);

		// Skip non-directories
		let stats: Awaited<ReturnType<typeof stat>>;
		try {
			stats = await stat(extDir);
			if (!stats.isDirectory()) continue;
		} catch {
			continue;
		}

		// Load and parse package.json
		let pkg: Record<string, unknown>;
		try {
			const pkgPath = join(extDir, "package.json");
			const raw = await getFileContent(pkgPath);
			pkg = JSON.parse(raw) as Record<string, unknown>;
		} catch {
			logger.warn("Invalid or missing package.json in extension", { path: extDir });
			continue;
		}

		const name = (pkg.name ?? entry) as string;
		const version = (pkg.version ?? "unknown") as string;

		const key = `${name}@${version}`;
		logger.debug("Sage plugin discovery: found extension", { key, path: extDir });
		plugins.push({
			key,
			installPath: extDir,
			version,
			lastUpdated: stats.mtime.toISOString(),
		});
	}

	logger.info(`Sage plugin discovery: found ${plugins.length} extension(s)`);
	return plugins;
}
