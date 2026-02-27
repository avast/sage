/**
 * Discovers installed OpenCode plugins for plugin scanning.
 * Scans NPM packages from config files and local plugin files.
 */

import { readdir, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import type { Logger, PluginInfo } from "@sage/core";
import { getFileContent } from "@sage/core";

const GLOBAL_CONFIG_PATH = join(homedir(), ".config", "opencode", "opencode.json");
const PROJECT_CONFIG_NAME = "opencode.json";
const GLOBAL_PLUGINS_DIR = join(homedir(), ".config", "opencode", "plugins");
const NPM_CACHE_DIR = join(homedir(), ".cache", "opencode", "node_modules");

/**
 * Discover OpenCode plugins from all sources:
 * 1. NPM packages from config files
 * 2. Local plugin files (global + project)
 */
export async function discoverOpenCodePlugins(
	logger: Logger,
	projectDir?: string,
): Promise<PluginInfo[]> {
	logger.debug("Sage plugin discovery: scanning OpenCode plugins");

	const plugins: PluginInfo[] = [];

	// 1. Discover NPM plugins from config files
	const npmPlugins = await discoverNpmPlugins(logger, projectDir);
	plugins.push(...npmPlugins);

	// 2. Discover local plugin files (global)
	const globalPlugins = await discoverLocalPlugins(GLOBAL_PLUGINS_DIR, "global", logger);
	plugins.push(...globalPlugins);

	// 3. Discover local plugin files (project)
	if (projectDir) {
		const projectPluginsDir = join(projectDir, ".opencode", "plugins");
		const projectPlugins = await discoverLocalPlugins(projectPluginsDir, "project", logger);
		plugins.push(...projectPlugins);
	}

	logger.info(`Sage plugin discovery: found ${plugins.length} plugin(s)`);
	return plugins;
}

/**
 * Discover NPM plugins listed in config files
 */
async function discoverNpmPlugins(logger: Logger, projectDir?: string): Promise<PluginInfo[]> {
	const plugins: PluginInfo[] = [];
	const pluginNames = new Set<string>();

	// Read global config
	try {
		const globalConfig = JSON.parse(await getFileContent(GLOBAL_CONFIG_PATH)) as Record<
			string,
			unknown
		>;
		const globalPlugins = (globalConfig.plugin ?? []) as string[];
		for (const name of globalPlugins) {
			pluginNames.add(name);
		}
	} catch {
		logger.debug("Global OpenCode config not found or invalid");
	}

	// Read project config (overrides global)
	if (projectDir) {
		try {
			const projectConfigPath = join(projectDir, PROJECT_CONFIG_NAME);
			const projectConfig = JSON.parse(await getFileContent(projectConfigPath)) as Record<
				string,
				unknown
			>;
			const projectPlugins = (projectConfig.plugin ?? []) as string[];
			for (const name of projectPlugins) {
				pluginNames.add(name);
			}
		} catch {
			logger.debug("Project OpenCode config not found or invalid");
		}
	}

	// For each plugin name, find it in node_modules
	for (const pluginName of pluginNames) {
		try {
			const installPath = join(NPM_CACHE_DIR, pluginName);
			const pkgJsonPath = join(installPath, "package.json");
			const pkgJson = JSON.parse(await getFileContent(pkgJsonPath)) as Record<string, unknown>;

			const stats = await stat(installPath);
			const version = (pkgJson.version as string) ?? "unknown";
			const key = `${pluginName}@${version}`;

			plugins.push({
				key,
				installPath,
				version,
				lastUpdated: stats.mtime.toISOString(),
			});

			logger.debug(`Discovered NPM plugin: ${key}`, { installPath });
		} catch {
			logger.warn(`NPM plugin listed in config but not found: ${pluginName}`);
		}
	}

	return plugins;
}

/**
 * Discover local plugin files (.js/.ts) in a directory
 */
async function discoverLocalPlugins(
	pluginsDir: string,
	context: string,
	logger: Logger,
): Promise<PluginInfo[]> {
	const plugins: PluginInfo[] = [];

	let entries: string[];
	try {
		entries = await readdir(pluginsDir);
	} catch {
		logger.debug(`${context} plugins directory not found: ${pluginsDir}`);
		return [];
	}

	for (const entry of entries) {
		const fullPath = join(pluginsDir, entry);

		// Only scan .js and .ts files
		if (!(entry.endsWith(".js") || entry.endsWith(".ts"))) {
			continue;
		}

		try {
			const stats = await stat(fullPath);
			if (!stats.isFile()) continue;

			// Use filename as plugin name
			const name = basename(entry, entry.endsWith(".ts") ? ".ts" : ".js");
			const version = `local-${stats.mtime.getTime()}`; // Synthetic version from mtime
			const key = `${context}/${name}@${version}`;

			plugins.push({
				key,
				installPath: fullPath,
				version,
				lastUpdated: stats.mtime.toISOString(),
			});

			logger.debug(`Discovered local plugin: ${key}`, { path: fullPath });
		} catch {
			logger.warn(`Failed to read local plugin: ${entry}`);
		}
	}

	return plugins;
}
