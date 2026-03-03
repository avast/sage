/**
 * OpenCode tool input extraction mapped onto @sage/core artifact extractors.
 */

import {
	type Artifact,
	extractFromBash,
	extractFromEdit,
	extractFromWebFetch,
	extractFromWrite,
} from "@sage/core";

function asString(value: unknown): string | undefined {
	return typeof value === "string" ? value : undefined;
}

function asNumber(value: unknown): number | undefined {
	return typeof value === "number" ? value : undefined;
}

export function extractFromOpenCodeTool(
	toolName: string,
	args: Record<string, unknown>,
): Artifact[] | null {
	switch (toolName) {
		case "bash": {
			const command = asString(args.command) ?? "";
			return command ? extractFromBash(command) : null;
		}
		case "webfetch": {
			const url = asString(args.url) ?? "";
			return url ? extractFromWebFetch({ url }) : null;
		}
		case "write": {
			const filePath = asString(args.filePath) ?? "";
			if (!filePath) return null;
			return extractFromWrite({
				file_path: filePath,
				content: asString(args.content) ?? "",
			});
		}
		case "edit": {
			const filePath = asString(args.filePath) ?? "";
			if (!filePath) return null;
			return extractFromEdit({
				file_path: filePath,
				old_string: asString(args.oldString) ?? "",
				new_string: asString(args.newString) ?? "",
			});
		}
		case "read": {
			const filePath = asString(args.filePath) ?? "";
			if (!filePath) return null;
			return [{ type: "file_path", value: filePath, context: "read" }];
		}
		case "glob": {
			const pattern = asString(args.pattern) ?? "";
			if (!pattern) return null;
			return [{ type: "file_path", value: pattern, context: "glob_pattern" }];
		}
		case "grep": {
			const pattern = asString(args.pattern) ?? "";
			if (!pattern) return null;
			const artifacts: Artifact[] = [{ type: "content", value: pattern, context: "grep_pattern" }];
			const include = asString(args.include);
			if (include) {
				artifacts.push({ type: "file_path", value: include, context: "grep_include" });
			}
			return artifacts;
		}
		case "ls": {
			const dir = asString(args.path) ?? asString(args.directoryPath) ?? "";
			if (!dir) return null;
			return [{ type: "file_path", value: dir, context: "list" }];
		}
		case "codesearch": {
			const query = asString(args.query) ?? "";
			return query ? [{ type: "content", value: query, context: "codesearch_query" }] : null;
		}
		case "websearch": {
			const query = asString(args.query) ?? "";
			return query ? [{ type: "content", value: query, context: "websearch_query" }] : null;
		}
		case "question": {
			const selected = Array.isArray(args.selected) ? args.selected : [];
			const joined = selected
				.map((item) => (typeof item === "string" ? item : null))
				.filter((item): item is string => item !== null)
				.join("\n");
			if (!joined) return null;
			return [{ type: "content", value: joined, context: "question_options" }];
		}
		case "task": {
			const prompt = asString(args.prompt) ?? "";
			const desc = asString(args.description) ?? "";
			const payload = [desc, prompt].filter(Boolean).join("\n\n");
			return payload ? [{ type: "content", value: payload, context: "task" }] : null;
		}
		case "read_lines": {
			const filePath = asString(args.filePath) ?? "";
			if (!filePath) return null;
			const offset = asNumber(args.offset);
			const limit = asNumber(args.limit);
			return [
				{
					type: "file_path",
					value: `${filePath}:${offset ?? 1}:${limit ?? 0}`,
					context: "read_lines",
				},
			];
		}
		default:
			return null;
	}
}
