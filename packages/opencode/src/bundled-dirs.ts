/**
 * Bundled directory and version helpers for OpenCode plugin.
 * Centralizes package path resolution for reuse across modules.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export function getBundledDataDirs(): {
	pluginDir: string;
	packageRoot: string;
	threatsDir: string;
	allowlistsDir: string;
} {
	const pluginDir = dirname(fileURLToPath(import.meta.url));
	const packageRoot = join(pluginDir, "..");
	return {
		pluginDir,
		packageRoot,
		threatsDir: join(packageRoot, "resources", "threats"),
		allowlistsDir: join(packageRoot, "resources", "allowlists"),
	};
}

export function getSageVersion(): string {
	try {
		const { packageRoot } = getBundledDataDirs();
		const pkgPath = join(packageRoot, "package.json");
		const pkg = JSON.parse(readFileSync(pkgPath, "utf-8")) as Record<string, unknown>;
		return (pkg.version as string) ?? "0.0.0";
	} catch {
		return "0.0.0";
	}
}
