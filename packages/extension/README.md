# Gen Sage — Safety for Agents

Sage is a lightweight Agent Detection & Response (ADR) layer that protects AI agents from executing dangerous actions on your machine.

## What it does

When an AI agent makes a tool call — running a shell command, writing a file, or fetching a URL — Sage intercepts it and checks for threats before it executes.

### Detection layers

- **URL reputation** — cloud-based lookup for malware, phishing, and scam URLs
- **Local heuristics** — pattern matching against dangerous commands, suspicious URLs, sensitive file paths, credential exposure, and obfuscation techniques
- **Package supply-chain checks** — registry existence, file reputation, and age analysis for npm/PyPI packages

### Verdicts

| Decision | Meaning |
|----------|---------|
| **Allow** | No threats detected — tool call proceeds |
| **Ask** | Suspicious activity — you are prompted for approval |
| **Deny** | Threat detected — tool call is blocked |

## Getting started

1. Install the extension
2. Open the command palette (`Ctrl+Shift+P` / `Cmd+Shift+P`)
3. Run **Sage: Enable Protection**

That's it. Sage now monitors all agent tool calls.

## Commands

| Command | Description |
|---------|-------------|
| `Sage: Enable Protection` | Install managed hooks |
| `Sage: Disable Protection` | Remove managed hooks |
| `Sage: Open Config` | Open `~/.sage/config.json` |
| `Sage: Open Audit Log` | View the verdict audit trail |
| `Sage: Show Hook Health` | Check hook installation status |

## Privacy

Sage sends URL hashes and package hashes to Gen Digital reputation APIs. File content, commands, and source code stay local. Both services can be disabled for fully offline operation.

## Links

- [GitHub](https://github.com/avast/sage)
- [Configuration docs](https://github.com/avast/sage/blob/main/docs/configuration.md)
- [Threat rules](https://github.com/avast/sage/blob/main/docs/threat-rules.md)
- [Privacy](https://github.com/avast/sage/blob/main/docs/privacy.md)
