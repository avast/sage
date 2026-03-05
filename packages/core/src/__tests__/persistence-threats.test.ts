import { beforeAll, describe, expect, it } from "vitest";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchCommand = createMatcher("command");

describe("persistence threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	// --- Positive cases ---

	it("detects bashrc append", () => {
		const ids = matchCommand(engine, 'echo "export PATH=/evil" >> ~/.bashrc');
		expect(ids).toContain("CLT-PERSIST-007");
	});

	it("detects zshrc redirect", () => {
		const ids = matchCommand(engine, "echo alias evil=hack >> ~/.zshrc");
		expect(ids).toContain("CLT-PERSIST-007");
	});

	it("detects crontab -e", () => {
		const ids = matchCommand(engine, "crontab -e");
		expect(ids).toContain("CLT-PERSIST-002");
	});

	it("does NOT detect crontab -l (harmless listing)", () => {
		const ids = matchCommand(engine, "crontab -l");
		expect(ids).not.toContain("CLT-PERSIST-002");
	});

	it("detects cron.daily write", () => {
		const ids = matchCommand(engine, "cp backdoor.sh /etc/cron.daily/cleanup");
		expect(ids).toContain("CLT-PERSIST-003");
	});

	// LaunchAgent/LaunchDaemon tests moved to mac-persistence-threats.test.ts (CLT-MAC-PERSIST-001)

	it("detects systemctl enable", () => {
		const ids = matchCommand(engine, "systemctl enable evil-service");
		expect(ids).toContain("CLT-PERSIST-005");
	});

	it("detects systemd unit write", () => {
		const ids = matchCommand(engine, "cp evil.service /etc/systemd/system/evil.service");
		expect(ids).toContain("CLT-PERSIST-005");
	});

	it("detects SSH authorized_keys append", () => {
		const ids = matchCommand(engine, "echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys");
		expect(ids).toContain("CLT-PERSIST-006");
	});

	it("detects profile write", () => {
		const ids = matchCommand(engine, "echo 'export FOO=bar' >> ~/.profile");
		expect(ids).toContain("CLT-PERSIST-007");
	});

	// --- Negative cases ---

	it("does not match source bashrc", () => {
		const ids = matchCommand(engine, "source ~/.bashrc");
		expect(ids.filter((id) => id.startsWith("CLT-PERSIST"))).toEqual([]);
	});

	it("does not match cat bashrc", () => {
		const ids = matchCommand(engine, "cat ~/.bashrc");
		expect(ids.filter((id) => id.startsWith("CLT-PERSIST"))).toEqual([]);
	});

	it("does not match echo hello", () => {
		const ids = matchCommand(engine, "echo hello world");
		expect(ids.filter((id) => id.startsWith("CLT-PERSIST"))).toEqual([]);
	});

	// --- at job scheduling (CLT-PERSIST-008) ---

	it("detects at -f scheduling (008)", () => {
		expect(matchCommand(engine, "at -f /tmp/evil.sh now + 1 minute")).toContain("CLT-PERSIST-008");
	});

	it("detects at midnight (008)", () => {
		expect(matchCommand(engine, "at midnight -f /tmp/evil.sh")).toContain("CLT-PERSIST-008");
	});

	it("does not match atq (list jobs, harmless) (008 neg)", () => {
		const ids = matchCommand(engine, "atq");
		expect(ids.filter((id) => id === "CLT-PERSIST-008")).toEqual([]);
	});

	// --- FN coverage ---

	// CLT-PERSIST-001: write/append to shell RC file
	it("detects echo append to $HOME/.bashrc (001)", () => {
		const ids = matchCommand(engine, 'echo "evil" >> $HOME/.bashrc');
		expect(ids).toContain("CLT-PERSIST-001");
	});

	it("detects cat redirect to ~/.zshenv (001)", () => {
		const ids = matchCommand(engine, "cat payload > ~/.zshenv");
		expect(ids).toContain("CLT-PERSIST-001");
	});

	// CLT-PERSIST-007: additional variants
	it("detects printf append to ~/.profile (007)", () => {
		const ids = matchCommand(engine, "printf '%s\\n' 'export PATH=/evil' >> ~/.profile");
		expect(ids).toContain("CLT-PERSIST-007");
	});

	it("detects echo append to ~/.bash_profile (007)", () => {
		const ids = matchCommand(engine, 'echo "backdoor" >> ~/.bash_profile');
		expect(ids).toContain("CLT-PERSIST-007");
	});

	// --- FP coverage ---

	it("does not match grep on bashrc (001 FP)", () => {
		const ids = matchCommand(engine, "grep PATH ~/.bashrc");
		expect(ids).not.toContain("CLT-PERSIST-001");
	});

	it("does not match echo to non-RC file (007 FP)", () => {
		const ids = matchCommand(engine, 'echo "hello" >> /tmp/output.txt');
		expect(ids).not.toContain("CLT-PERSIST-007");
	});
});
