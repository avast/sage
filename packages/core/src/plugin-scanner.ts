/**
 * Plugin scanner — discovers and scans installed Claude Code plugins for threats.
 */

import { createHash } from "node:crypto";
import { readdir, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { extname, join, relative } from "node:path";
import { FileCheckClient } from "./clients/file-check.js";
import { UrlCheckClient } from "./clients/url-check.js";
import { extractUrls } from "./extractors.js";
import { getFileContent, getFileContentRaw } from "./file-utils.js";
import { HeuristicsEngine } from "./heuristics.js";
import type {
	Artifact,
	Logger,
	PluginInfo,
	PluginScanResult,
	Threat,
	TrustedDomain,
} from "./types.js";
import { nullLogger } from "./types.js";

const DEFAULT_PLUGINS_REGISTRY = join(homedir(), ".claude", "plugins", "installed_plugins.json");

const SCANNABLE_EXTENSIONS = new Set([
	".py",
	".js",
	".ts",
	".sh",
	".bash",
	".zsh",
	".json",
	".yaml",
	".yml",
	".md",
	".toml",
	".txt",
	".cfg",
	".ini",
	".conf",
]);

const SKIP_DIRS = new Set(["node_modules", ".git", "__pycache__"]);

/** Max file size to scan (skip large files). */
const MAX_FILE_SIZE = 512 * 1024;

export async function discoverPlugins(
	registryPath = DEFAULT_PLUGINS_REGISTRY,
	logger: Logger = nullLogger,
): Promise<PluginInfo[]> {
	let raw: string;
	try {
		raw = await getFileContent(registryPath);
	} catch {
		logger.debug("Plugin registry not found", { path: registryPath });
		return [];
	}

	let data: Record<string, unknown>;
	try {
		data = JSON.parse(raw) as Record<string, unknown>;
	} catch (e) {
		logger.warn("Failed to read plugin registry", { error: String(e) });
		return [];
	}

	const plugins: PluginInfo[] = [];
	const pluginEntries = (data.plugins ?? {}) as Record<string, unknown>;

	for (const [pluginKey, versions] of Object.entries(pluginEntries)) {
		if (!Array.isArray(versions) || versions.length === 0) continue;
		const entry = versions[versions.length - 1] as Record<string, unknown>;
		const installPath = (entry.installPath ?? "") as string;
		const version = (entry.version ?? "unknown") as string;
		const lastUpdated = (entry.lastUpdated ?? "") as string;

		if (!installPath) continue;

		plugins.push({ key: pluginKey, installPath, version, lastUpdated });
	}

	return plugins;
}

async function walkPluginFiles(installPath: string, logger: Logger): Promise<string[]> {
	const files: string[] = [];

	async function walk(dir: string): Promise<void> {
		let entries: string[];
		try {
			entries = await readdir(dir);
		} catch {
			return;
		}

		for (const entry of entries) {
			if (SKIP_DIRS.has(entry)) continue;
			const fullPath = join(dir, entry);

			let stats: Awaited<ReturnType<typeof stat>>;
			try {
				stats = await stat(fullPath);
			} catch {
				continue;
			}

			if (stats.isDirectory()) {
				await walk(fullPath);
			} else if (stats.isFile()) {
				if (!SCANNABLE_EXTENSIONS.has(extname(fullPath).toLowerCase())) continue;
				if (stats.size > MAX_FILE_SIZE) continue;
				files.push(fullPath);
			}
		}
	}

	try {
		await walk(installPath);
	} catch (e) {
		logger.warn(`Error walking plugin directory ${installPath}`, { error: String(e) });
	}

	return files;
}

/**
 * Returns true if the line is an echo/printf statement where all pipe characters
 * are inside quotes (i.e., just printing text, not piping to another command).
 */
function isHarmlessEcho(line: string): boolean {
	if (!/^(echo|printf)\b/.test(line)) return false;
	// Strip quoted strings, then check for remaining unquoted pipes
	const withoutQuotes = line.replace(/"(?:[^"\\]|\\.)*"|'[^']*'/g, "");
	return !withoutQuotes.includes("|");
}

function extractArtifactsFromFile(filePath: string, content: string): Artifact[] {
	const artifacts: Artifact[] = [];
	const fileName = filePath.split("/").pop() ?? filePath;

	// Extract URLs (skip localhost)
	for (const url of extractUrls(content)) {
		if (url.includes("://127.0.0.1") || url.includes("://localhost")) continue;
		artifacts.push({ type: "url", value: url, context: `plugin_file:${fileName}` });
	}

	// For script files, treat content as potential commands
	const ext = extname(filePath).toLowerCase();
	if ([".sh", ".bash", ".zsh", ".py"].includes(ext)) {
		for (const line of content.split("\n")) {
			const trimmed = line.trim();
			if (
				trimmed &&
				!trimmed.startsWith("#") &&
				!trimmed.startsWith("//") &&
				!isHarmlessEcho(trimmed)
			) {
				artifacts.push({
					type: "command",
					value: trimmed,
					context: `plugin_file:${fileName}`,
				});
			}
		}
	}

	return artifacts;
}

export async function scanPlugin(
	plugin: PluginInfo,
	threats: Threat[],
	options: {
		checkUrls?: boolean;
		checkFileHashes?: boolean;
		trustedDomains?: TrustedDomain[];
		logger?: Logger;
	} = {},
): Promise<PluginScanResult> {
	const { checkUrls = true, checkFileHashes = true, trustedDomains, logger = nullLogger } = options;
	const result: PluginScanResult = { plugin, findings: [] };

	const files = await walkPluginFiles(plugin.installPath, logger);
	if (files.length === 0) return result;

	// Only run command-type heuristics on plugin files
	const commandThreats = threats.filter((t) => t.matchOn.has("command"));
	const heuristics = new HeuristicsEngine(commandThreats, trustedDomains);

	const allUrls: string[] = [];
	const hashToFiles = new Map<string, string[]>();

	for (const filePath of files) {
		let content: string;
		let rawBytes: Buffer;
		try {
			rawBytes = await getFileContentRaw(filePath);
			content = rawBytes.toString("utf-8");
		} catch {
			continue;
		}

		// Heuristic matching
		const artifacts = extractArtifactsFromFile(filePath, content);
		if (artifacts.length > 0) {
			const matches = heuristics.match(artifacts);
			for (const match of matches) {
				result.findings.push({
					threatId: match.threat.id,
					title: match.threat.title,
					severity: match.threat.severity,
					confidence: match.threat.confidence,
					action: match.threat.action,
					artifact: match.artifact.slice(0, 200),
					sourceFile: relative(plugin.installPath, filePath),
				});
			}
		}

		// Collect URLs for URL check
		if (checkUrls) {
			allUrls.push(...extractUrls(content));
		}

		// Compute file hash for reputation check
		if (checkFileHashes) {
			const sha256 = createHash("sha256").update(rawBytes).digest("hex");
			const existing = hashToFiles.get(sha256);
			if (existing) {
				existing.push(filePath);
			} else {
				hashToFiles.set(sha256, [filePath]);
			}
		}
	}

	// Run URL check and file hash check in parallel
	const urlCheckPromise =
		checkUrls && allUrls.length > 0
			? (async () => {
					try {
						const uniqueUrls = [...new Set(allUrls)];
						const client = new UrlCheckClient();
						const checkResults = await client.checkUrls(uniqueUrls);
						for (const ur of checkResults) {
							if (ur.isMalicious) {
								const findingDetails = ur.findings
									.map((f) => `${f.severityName}/${f.typeName}`)
									.join(", ");
								result.findings.push({
									threatId: "URL_CHECK",
									title: `Malicious URL (${findingDetails})`,
									severity: "critical",
									confidence: 1.0,
									action: "block",
									artifact: ur.url.slice(0, 200),
									sourceFile: "URL check",
								});
							}
						}
					} catch {
						// Fail open
					}
				})()
			: Promise.resolve();

	const fileCheckPromise =
		checkFileHashes && hashToFiles.size > 0
			? (async () => {
					try {
						const client = new FileCheckClient();
						const uniqueHashes = [...hashToFiles.keys()];
						const checkResults = await client.checkHashes(uniqueHashes);
						for (const fr of checkResults) {
							if (fr.severity === "SEVERITY_MALWARE") {
								const filePaths = hashToFiles.get(fr.sha256) ?? [];
								for (const filePath of filePaths) {
									result.findings.push({
										threatId: "FILE_CHECK",
										title: `Malicious file (${fr.detectionNames.join(", ") || "unknown"})`,
										severity: "critical",
										confidence: 1.0,
										action: "block",
										artifact: fr.sha256,
										sourceFile: relative(plugin.installPath, filePath),
									});
								}
							}
						}
					} catch {
						// Fail open
					}
				})()
			: Promise.resolve();

	await Promise.all([urlCheckPromise, fileCheckPromise]);

	return result;
}
