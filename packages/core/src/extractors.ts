/**
 * Extract security-relevant artifacts from tool inputs.
 */

import type { Artifact } from "./types.js";

/** Regex for extracting URLs — matches http/https followed by non-whitespace, non-quote chars. */
const URL_PATTERN = /https?:\/\/[^\s"')<>[\]{}]+/g;

/** Trailing punctuation that's likely not part of the URL. */
const TRAILING_PUNCT = /[.,;:!?]+$/;

/** Maximum content size to scan (64KB). */
const MAX_CONTENT_SIZE = 64 * 1024;

/** Detect base64-decode piped to execution: echo "..." | base64 -d | bash */
const BASE64_DECODE_EXEC =
	/\b(echo|printf|cat)\b[^|]*\|\s*base64\s+(-d|--decode)[^|]*\|\s*(bash|sh|zsh|ksh|dash|python|perl|ruby|node)\b/;

/** Detect hex/octal printf piped to shell: printf '\x41\x42' | bash */
const PRINTF_ENCODE_EXEC =
	/\bprintf\b\s+['"](\\x[0-9a-fA-F]{2}|\\[0-7]{3})[^|]*\|\s*(bash|sh|zsh|ksh|dash)\b/;

/** Detect shell variable interpolation hiding a domain: $HOST.$DOMAIN or ${HOST}.${DOMAIN} */
const VAR_INTERPOLATION_URL =
	/\b(curl|wget|fetch)\b[^|;]*(\$\{?\w+\}?\.\$\{?\w+\}?|\$\{?\w+\}?:\/\/)/;

/** Shell names used as pipe targets */
const SHELLS = "bash|sh|zsh|ksh|dash";

export function extractUrls(text: string): string[] {
	const seen = new Set<string>();
	const urls: string[] = [];
	for (const match of text.matchAll(URL_PATTERN)) {
		const url = match[0].replace(TRAILING_PUNCT, "");
		if (!seen.has(url)) {
			seen.add(url);
			urls.push(url);
		}
	}
	return urls;
}

function escapeRegExp(str: string): string {
	const regExpEscape = (RegExp as unknown as { escape?: (s: string) => string }).escape;
	if (regExpEscape) {
		return regExpEscape(str);
	}
	return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Strip heredoc bodies from a command string. Heredoc content is inline text
 * data (commit messages, config files, etc.), not executable shell commands.
 */
function stripHeredocs(command: string): string {
	return command.replace(/<<-?\s*['"]?(\w+)['"]?\n[\s\S]*?\n[ \t]*\1\b/g, "<<$1");
}

export function extractFromBash(command: string): Artifact[] {
	const artifacts: Artifact[] = [];

	// Strip heredoc bodies — they're data, not executable commands
	const effective = stripHeredocs(command);

	// Include the effective command for heuristic matching
	artifacts.push({ type: "command", value: effective });

	// Detect encoding bypass techniques
	if (BASE64_DECODE_EXEC.test(effective)) {
		artifacts.push({ type: "command", value: effective, context: "base64_decode_exec" });
	}
	if (PRINTF_ENCODE_EXEC.test(effective)) {
		artifacts.push({ type: "command", value: effective, context: "printf_encode_exec" });
	}
	if (VAR_INTERPOLATION_URL.test(effective)) {
		artifacts.push({ type: "command", value: effective, context: "variable_interpolation_url" });
	}

	// Extract URLs from the FULL command (heredoc content may contain relevant URLs)
	for (const url of extractUrls(command)) {
		let context: string | undefined;
		const escaped = escapeRegExp(url);
		// Direct pipe to shell: curl URL | sh
		const directPipe = new RegExp(escaped + String.raw`[^|]*\|\s*(${SHELLS})\b`);
		// Pipe through wrapper to shell: curl URL | timeout 5 bash, curl URL | xargs sh -c
		const wrappedPipe = new RegExp(escaped + String.raw`[^|]*\|\s*\S+\s+(\S+\s+)?(${SHELLS})\b`);
		// Subshell/backtick execution: $(curl URL | sh) or `curl URL | sh`
		const subshellExec = new RegExp(
			`${String.raw`(\$\(|`}\`)${escaped}[^)\`]*${String.raw`\|\s*(${SHELLS})\b`}`,
		);
		if (directPipe.test(command) || wrappedPipe.test(command) || subshellExec.test(command)) {
			context = "piped to shell";
		}
		artifacts.push({ type: "url", value: url, context });
	}

	return artifacts;
}

export function extractFromWebFetch(toolInput: Record<string, unknown>): Artifact[] {
	const url = toolInput.url;
	if (url && typeof url === "string") {
		return [{ type: "url", value: url, context: "webfetch" }];
	}
	return [];
}

function extractFileArtifacts(
	toolInput: Record<string, unknown>,
	filePathKey: string,
	contentKey: string,
	contextName: string,
	urlContextName: string,
): Artifact[] {
	const artifacts: Artifact[] = [];

	const filePath = toolInput[filePathKey];
	if (filePath && typeof filePath === "string") {
		artifacts.push({ type: "file_path", value: filePath, context: contextName });
	}

	const content = toolInput[contentKey];
	if (content && typeof content === "string" && content.trim()) {
		const capped = content.slice(0, MAX_CONTENT_SIZE);
		artifacts.push({ type: "content", value: capped, context: contextName });

		for (const url of extractUrls(capped)) {
			artifacts.push({ type: "url", value: url, context: urlContextName });
		}
	}

	return artifacts;
}

export function extractFromWrite(toolInput: Record<string, unknown>): Artifact[] {
	return extractFileArtifacts(toolInput, "file_path", "content", "write", "from_file_content");
}

export function extractFromEdit(toolInput: Record<string, unknown>): Artifact[] {
	return extractFileArtifacts(toolInput, "file_path", "new_string", "edit", "from_edit_content");
}

export function extractFromRead(toolInput: Record<string, unknown>): Artifact[] {
	return extractFileArtifacts(toolInput, "file_path", "content", "read", "from_read_content");
}

export function extractFromDelete(toolInput: Record<string, unknown>): Artifact[] {
	const filePath = toolInput.file_path;
	if (filePath && typeof filePath === "string") {
		return [{ type: "file_path", value: filePath, context: "delete" }];
	}
	return [];
}
