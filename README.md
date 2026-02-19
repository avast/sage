# Sage

**Safety for Agents** - a lightweight Agent Detection & Response (ADR) layer for AI agents that guards commands, files, and web requests.

<p align="center">
  <img src="images/sage-logo-shaded.png" alt="Sage" width="50%">
</p>

Sage intercepts tool calls (Bash commands, URL fetches, file writes) via hook systems in [Claude Code](docs/platform-guides/claude-code.md), [Cursor / VS Code](docs/platform-guides/cursor.md), and [OpenClaw](docs/platform-guides/openclaw.md), and checks them against:

- **URL reputation** - cloud-based malware, phishing, and scam detection
- **Local heuristics** - YAML-based threat definitions for dangerous patterns
- **Package supply-chain checks** - registry existence, file reputation, and age analysis for npm/PyPI packages
- **Plugin scanning** - scans other installed plugins for threats at session start

## Quick Start

### Claude Code

Requires [Node.js >= 18](https://nodejs.org/).

```
/plugin marketplace add https://github.com/avast/sage.git
/plugin install sage@sage
```

### Cursor

Build and install the extension, then run `Sage: Enable Protection` from the command palette.

```bash
pnpm install && pnpm -C packages/extension run package:cursor:vsix
```

### OpenClaw

```bash
# From npm (recommended)
openclaw plugins install @gendigital/sage-openclaw

# From source
pnpm install && pnpm build
cp -r packages/openclaw sage && openclaw plugins install ./sage
```

See [Getting Started](docs/getting-started.md) for detailed instructions.

## Documentation

| Document                                         | Description                                    |
| ------------------------------------------------ | ---------------------------------------------- |
| [Getting Started](docs/getting-started.md)       | Installation for all platforms                 |
| [How It Works](docs/how-it-works.md)             | Detection layers, data flow, verdicts          |
| [Configuration](docs/configuration.md)           | All config options and file paths              |
| [Threat Rules](docs/threat-rules.md)             | YAML rule format and what gets checked         |
| [Package Protection](docs/package-protection.md) | npm/PyPI supply-chain checks                   |
| [Plugin Scanning](docs/plugin-scanning.md)       | Session-start plugin scanning                  |
| [Architecture](docs/architecture.md)             | Monorepo structure, packages, design decisions |
| [Development](docs/development.md)               | Building, testing, tooling, conventions        |
| [FAQ](docs/faq.md)                               | Common questions                               |
| [Privacy](docs/privacy.md)                       | What data is sent, what stays local            |

**Platform guides:** [Claude Code](docs/platform-guides/claude-code.md) · [Cursor / VS Code](docs/platform-guides/cursor.md) · [OpenClaw](docs/platform-guides/openclaw.md)

## Current Limitations

- MCP tool call interception (`mcp__*`) is not yet implemented
- Custom user threat definitions (`~/.sage/threats/`) are not yet implemented

## Privacy

Sage sends URL hashes and package hashes to Gen Digital reputation APIs. File content, commands, and source code stay local. Both services can be disabled for fully offline operation. See [Privacy](docs/privacy.md) for details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding conventions, and the threat rule contribution process.

## License

Copyright 2026 Gen Digital Inc.

- Source code: [Apache License 2.0](LICENSE)
- Threat detection rules (`threats/`): [Detection Rule License 1.1](threats/LICENSE)
