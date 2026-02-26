/**
 * Bridges OpenCode's client logger to Sage's Logger interface.
 */

import type { PluginInput } from "@opencode-ai/plugin";
import type { Logger } from "@sage/core";

export class OpencodeLogger implements Logger {
	private client: PluginInput["client"];

	constructor(client: PluginInput["client"]) {
		this.client = client;
	}

	public async debug(msg: string, data?: Record<string, unknown>) {
		await this.write("debug", msg, data).catch(() => {});
	}

	public async info(msg: string, data?: Record<string, unknown>) {
		await this.write("info", msg, data).catch(() => {});
	}

	public async warn(msg: string, data?: Record<string, unknown>) {
		await this.write("warn", msg, data).catch(() => {});
	}

	public async error(msg: string, data?: Record<string, unknown>) {
		await this.write("error", msg, data).catch(() => {});
	}

	private async write(level: "debug" | "info" | "warn" | "error", msg: string, data?: unknown) {
		await this.client.app.log({
			body: {
				service: "sage-opencode",
				level,
				message: msg,
				extra: data && typeof data === "object" ? (data as Record<string, unknown>) : undefined,
			},
		});
	}
}
