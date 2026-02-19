#!/usr/bin/env node

import { join, resolve } from "node:path";
import {
	type Artifact,
	evaluateToolCall,
	extractFromBash,
	extractFromEdit,
	extractFromWebFetch,
	extractFromWrite,
	extractUrls,
	type Verdict,
} from "@sage/core";

type CursorEventName =
	| "preToolUse"
	| "beforeShellExecution"
	| "beforeMCPExecution"
	| "beforeReadFile";
type HookMode = "cursor" | "vscode";

interface NormalizedHookCall {
	sessionId: string;
	toolName: string;
	toolInput: Record<string, unknown>;
	artifacts: Artifact[];
}

const MAX_CONTENT_SIZE = 64 * 1024;

export async function runCli(argv: string[] = process.argv.slice(2)): Promise<void> {
	const mode = argv[0] as HookMode | undefined;
	const payload = await readStdinJson();

	if (mode === "cursor") {
		await handleCursor(payload);
		return;
	}

	if (mode === "vscode") {
		await handleVsCode(payload);
		return;
	}

	writeJson({});
}

async function handleCursor(payload: unknown): Promise<void> {
	const eventName = detectCursorEvent(payload);
	if (!eventName) {
		writeJson({});
		return;
	}

	const normalized = normalizeCursorCall(payload, eventName);
	if (!normalized) {
		writeJson(internalCursorResponse(eventName, "allow", "Sage could not normalize hook payload."));
		return;
	}

	try {
		const verdict = await evaluateNormalizedCall(normalized);
		writeJson(toCursorResponse(eventName, verdict));
	} catch {
		writeJson(
			internalCursorResponse(
				eventName,
				"allow",
				"Sage internal error; default allow policy applied.",
			),
		);
	}
}

async function handleVsCode(payload: unknown): Promise<void> {
	const normalized = normalizeVsCodeCall(payload);
	if (!normalized) {
		writeJson({});
		return;
	}

	try {
		const verdict = await evaluateNormalizedCall(normalized);
		writeJson(toVsCodeResponse(verdict));
	} catch {
		writeJson({});
	}
}

async function evaluateNormalizedCall(call: NormalizedHookCall): Promise<Verdict> {
	const { threatsDir, allowlistsDir } = getBundledDataDirs();
	return evaluateToolCall(
		{
			sessionId: call.sessionId,
			toolName: call.toolName,
			toolInput: call.toolInput,
			artifacts: call.artifacts,
		},
		{ threatsDir, allowlistsDir },
	);
}

function detectCursorEvent(payload: unknown): CursorEventName | undefined {
	if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
		return undefined;
	}
	const input = payload as Record<string, unknown>;
	const fromField = asString(input.hook_event_name) ?? asString(input.hookEventName);
	if (fromField && isCursorEvent(fromField)) {
		return fromField;
	}
	if (typeof input.command === "string" && input.tool_name === undefined) {
		return "beforeShellExecution";
	}
	if (typeof input.file_path === "string" && input.tool_name === undefined) {
		return "beforeReadFile";
	}
	if (input.tool_name !== undefined && input.tool_input !== undefined) {
		const toolName = asString(input.tool_name) ?? "";
		if (toolName === "MCP") {
			return "beforeMCPExecution";
		}
		return "preToolUse";
	}
	return undefined;
}

function normalizeCursorCall(
	payload: unknown,
	eventName?: CursorEventName,
): NormalizedHookCall | undefined {
	if (!payload || typeof payload !== "object" || Array.isArray(payload) || !eventName) {
		return undefined;
	}

	const input = payload as Record<string, unknown>;
	const sessionId =
		asString(input.conversation_id) ??
		asString(input.conversationId) ??
		asString(input.session_id) ??
		asString(input.sessionId) ??
		"cursor";

	if (eventName === "beforeShellExecution") {
		const command = asString(input.command) ?? "";
		const toolInput: Record<string, unknown> = {
			command,
			cwd: asString(input.cwd),
		};
		return {
			sessionId,
			toolName: "Bash",
			toolInput,
			artifacts: command ? extractFromBash(command) : [],
		};
	}

	if (eventName === "beforeReadFile") {
		const filePath = readFilePath(input);
		const content = asString(input.content);
		const toolInput: Record<string, unknown> = {
			file_path: filePath ?? "",
			content: content ?? "",
			attachments: Array.isArray(input.attachments) ? input.attachments : [],
		};
		return {
			sessionId,
			toolName: "Read",
			toolInput,
			artifacts: extractFromRead(toolInput),
		};
	}

	if (eventName === "beforeMCPExecution") {
		const parsedToolInput = parseUnknownObject(input.tool_input);
		const toolInput: Record<string, unknown> = {
			tool_name: asString(input.tool_name),
			tool_input: parsedToolInput,
			command: asString(input.command),
			url: asString(input.url),
			server: asString(input.server),
		};
		return {
			sessionId,
			toolName: "MCP",
			toolInput,
			artifacts: extractFromMcp(toolInput),
		};
	}

	const toolName = asString(input.tool_name) ?? "";
	const toolInput = parseUnknownObject(input.tool_input);
	return {
		sessionId,
		toolName: mapCursorToolToClaudeTool(toolName),
		toolInput,
		artifacts: extractFromCursorTool(toolName, toolInput),
	};
}

function normalizeVsCodeCall(payload: unknown): NormalizedHookCall | undefined {
	if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
		return undefined;
	}

	const input = payload as Record<string, unknown>;
	const toolName = asString(input.tool_name);
	if (!toolName) {
		return undefined;
	}

	const toolInput = parseUnknownObject(input.tool_input);
	const sessionId =
		asString(input.session_id) ??
		asString(input.sessionId) ??
		asString(input.conversation_id) ??
		asString(input.conversationId) ??
		"vscode";

	return {
		sessionId,
		toolName,
		toolInput,
		artifacts: extractFromVsCodeTool(toolName, toolInput),
	};
}

function extractFromVsCodeTool(toolName: string, toolInput: Record<string, unknown>): Artifact[] {
	switch (toolName) {
		case "Bash":
			return extractFromBash(asString(toolInput.command) ?? "");
		case "WebFetch":
			return extractFromWebFetch(toolInput);
		case "Write":
			return extractFromWrite(toolInput);
		case "Edit":
			return extractFromEdit(toolInput);
		default:
			return [];
	}
}

function mapCursorToolToClaudeTool(toolName: string): string {
	switch (toolName) {
		case "Shell":
			return "Bash";
		case "Write":
			return "Write";
		case "Read":
			return "Read";
		case "Delete":
			return "Delete";
		case "MCP":
			return "MCP";
		default:
			return toolName || "Unknown";
	}
}

function extractFromCursorTool(toolName: string, toolInput: Record<string, unknown>): Artifact[] {
	switch (toolName) {
		case "Shell":
			return extractFromBash(asString(toolInput.command) ?? "");
		case "WebFetch":
			return extractFromWebFetch(toolInput);
		case "Write": {
			const normalized = normalizeWriteLikeInput(toolInput);
			return extractFromWrite(normalized);
		}
		case "Edit": {
			const normalized = normalizeEditLikeInput(toolInput);
			return extractFromEdit(normalized);
		}
		case "Read":
			return extractFromRead(toolInput);
		case "Delete":
			return extractFromDelete(toolInput);
		case "MCP":
			return extractFromMcp(toolInput);
		default:
			return [];
	}
}

function normalizeWriteLikeInput(toolInput: Record<string, unknown>): Record<string, unknown> {
	const filePath = readFilePath(toolInput);
	const content = asString(toolInput.content) ?? asString(toolInput.new_string) ?? "";
	return {
		...toolInput,
		file_path: filePath ?? "",
		content,
	};
}

function normalizeEditLikeInput(toolInput: Record<string, unknown>): Record<string, unknown> {
	const filePath = readFilePath(toolInput);
	const newString = asString(toolInput.new_string) ?? asString(toolInput.content) ?? "";
	return {
		...toolInput,
		file_path: filePath ?? "",
		new_string: newString,
	};
}

function extractFromRead(toolInput: Record<string, unknown>): Artifact[] {
	const artifacts: Artifact[] = [];
	const filePath = readFilePath(toolInput);
	if (filePath) {
		artifacts.push({ type: "file_path", value: filePath, context: "read" });
	}

	const content = asString(toolInput.content);
	if (content?.trim()) {
		const capped = content.slice(0, MAX_CONTENT_SIZE);
		artifacts.push({ type: "content", value: capped, context: "read" });
		for (const url of extractUrls(capped)) {
			artifacts.push({ type: "url", value: url, context: "from_read_content" });
		}
	}

	return artifacts;
}

function extractFromDelete(toolInput: Record<string, unknown>): Artifact[] {
	const filePath = readFilePath(toolInput);
	if (!filePath) {
		return [];
	}
	return [{ type: "file_path", value: filePath, context: "delete" }];
}

function extractFromMcp(toolInput: Record<string, unknown>): Artifact[] {
	const artifacts: Artifact[] = [];

	const mcpPayload = parseUnknownObject(toolInput.tool_input ?? toolInput.toolInput);
	const mergedInput: Record<string, unknown> = {
		...mcpPayload,
		...toolInput,
	};

	const directUrl = asString(mergedInput.url);
	if (directUrl) {
		artifacts.push({ type: "url", value: directUrl, context: "mcp" });
	}

	const directCommand = asString(mergedInput.command) ?? asString(mergedInput.cmd);
	if (directCommand) {
		artifacts.push({ type: "command", value: directCommand, context: "mcp" });
	}

	const directPath = readFilePath(mergedInput);
	if (directPath) {
		artifacts.push({ type: "file_path", value: directPath, context: "mcp" });
	}

	for (const value of collectStrings(mergedInput, 0)) {
		for (const url of extractUrls(value)) {
			artifacts.push({ type: "url", value: url, context: "mcp" });
		}
	}

	return dedupeArtifacts(artifacts);
}

function collectStrings(value: unknown, depth: number): string[] {
	if (depth > 4) {
		return [];
	}
	if (typeof value === "string") {
		return [value.slice(0, MAX_CONTENT_SIZE)];
	}
	if (Array.isArray(value)) {
		return value.flatMap((entry) => collectStrings(entry, depth + 1));
	}
	if (value && typeof value === "object") {
		return Object.values(value).flatMap((entry) => collectStrings(entry, depth + 1));
	}
	return [];
}

function dedupeArtifacts(artifacts: Artifact[]): Artifact[] {
	const seen = new Set<string>();
	const output: Artifact[] = [];
	for (const artifact of artifacts) {
		const key = `${artifact.type}:${artifact.value}`;
		if (seen.has(key)) {
			continue;
		}
		seen.add(key);
		output.push(artifact);
	}
	return output;
}

function readFilePath(toolInput: Record<string, unknown>): string | undefined {
	return (
		asString(toolInput.file_path) ??
		asString(toolInput.path) ??
		asString(toolInput.filePath) ??
		asString(toolInput.target_file) ??
		asString(toolInput.filename)
	);
}

function toCursorResponse(eventName: CursorEventName, verdict: Verdict): Record<string, unknown> {
	const reason = truncateReason(verdict);

	if (eventName === "preToolUse") {
		if (verdict.decision === "allow") {
			return { decision: "allow" };
		}
		return { decision: "deny", reason };
	}

	if (eventName === "beforeReadFile") {
		if (verdict.decision === "allow") {
			return { permission: "allow" };
		}
		return { permission: "deny", user_message: reason };
	}

	return {
		permission: verdict.decision,
		user_message: verdict.decision === "allow" ? undefined : reason,
		agent_message:
			verdict.decision === "allow"
				? undefined
				: `Sage ${verdict.decision === "deny" ? "blocked" : "flagged"} this action (${verdict.severity}).`,
	};
}

function toVsCodeResponse(verdict: Verdict): Record<string, unknown> {
	if (verdict.decision === "allow") {
		return {};
	}

	return {
		hookSpecificOutput: {
			hookEventName: "PreToolUse",
			permissionDecision: verdict.decision,
			permissionDecisionReason: truncateReason(verdict),
		},
	};
}

function internalCursorResponse(
	eventName: CursorEventName,
	decision: "allow" | "deny",
	reason: string,
): Record<string, unknown> {
	if (eventName === "preToolUse") {
		return { decision, reason };
	}
	if (eventName === "beforeReadFile") {
		return { permission: decision, user_message: reason };
	}
	return {
		permission: decision,
		user_message: reason,
		agent_message: "Sage internal error policy applied.",
	};
}

function truncateReason(verdict: Verdict): string {
	if (verdict.reasons.length === 0) {
		return `Sage flagged this action (${verdict.category}).`;
	}
	const joined = verdict.reasons.slice(0, 5).join("; ");
	return joined.length <= 350 ? joined : `${joined.slice(0, 347)}...`;
}

function getBundledDataDirs(): { threatsDir: string; allowlistsDir: string } {
	const extensionRoot = resolve(__dirname, "..");
	return {
		threatsDir: join(extensionRoot, "resources", "threats"),
		allowlistsDir: join(extensionRoot, "resources", "allowlists"),
	};
}

function isCursorEvent(value: string): value is CursorEventName {
	return (
		value === "preToolUse" ||
		value === "beforeShellExecution" ||
		value === "beforeMCPExecution" ||
		value === "beforeReadFile"
	);
}

function asString(value: unknown): string | undefined {
	return typeof value === "string" ? value : undefined;
}

function parseUnknownObject(value: unknown): Record<string, unknown> {
	if (value && typeof value === "object" && !Array.isArray(value)) {
		return value as Record<string, unknown>;
	}
	if (typeof value === "string") {
		try {
			const parsed = JSON.parse(value);
			if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
				return parsed as Record<string, unknown>;
			}
		} catch {
			// Ignore parse errors.
		}
	}
	return {};
}

async function readStdinJson(): Promise<unknown> {
	// Cursor hooks on Windows can deliver stdin as UTF-16LE (PowerShell pipeline encoding),
	// which breaks JSON.parse if we assume UTF-8. Read bytes and attempt both decodings.
	const raw = await new Promise<Buffer>((resolve) => {
		const chunks: Buffer[] = [];
		process.stdin.on("data", (chunk) => {
			// Node normally gives Buffer chunks when no encoding is set, but be defensive.
			chunks.push(typeof chunk === "string" ? Buffer.from(chunk, "utf8") : chunk);
		});
		process.stdin.on("end", () => resolve(Buffer.concat(chunks)));
	});

	function stripBom(value: string): string {
		return value.charCodeAt(0) === 0xfeff ? value.slice(1) : value;
	}

	function tryParseJson(value: string): unknown | undefined {
		const trimmed = stripBom(value).trim();
		if (!trimmed) {
			return {};
		}
		try {
			return JSON.parse(trimmed);
		} catch {
			return undefined;
		}
	}

	const asUtf8 = raw.toString("utf8");
	const parsedUtf8 = tryParseJson(asUtf8);
	if (parsedUtf8 !== undefined) {
		return parsedUtf8;
	}

	const asUtf16le = raw.toString("utf16le");
	const parsedUtf16le = tryParseJson(asUtf16le);
	if (parsedUtf16le !== undefined) {
		return parsedUtf16le;
	}

	return {};
}

function writeJson(payload: Record<string, unknown>): void {
	process.stdout.write(`${JSON.stringify(payload)}\n`);
}

if (require.main === module) {
	runCli().catch(() => {
		// Protocol safety: emit valid JSON and never fail with non-JSON output.
		writeJson({});
	});
}
