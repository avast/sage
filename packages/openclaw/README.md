# @gendigital/sage-openclaw

**Safety for Agents** - Agent Detection & Response (ADR) plugin for [OpenClaw](https://openclaw.dev).

Sage intercepts tool calls (shell commands, URL fetches, file writes) and checks them against URL reputation services, local heuristic threat rules, and package supply-chain checks before they execute.

## Installation

```bash
openclaw plugins install @gendigital/sage-openclaw
```

## What It Does

- Intercepts `exec`, `web_fetch`, `write`, `edit`, `read`, and `apply_patch` tool calls
- Checks URLs against cloud-based malware/phishing detection
- Matches commands and file paths against YAML-based threat definitions
- Validates npm/PyPI packages against supply-chain risks
- Scans installed plugins for threats at session start
- Provides a `sage_approve` gate tool for interactive approval of flagged actions

## Configuration

Sage works out of the box with no configuration. Optional config file at `~/.sage/config.yaml`:

```yaml
sensitivity: balanced   # paranoid | balanced | relaxed
url_check: true
file_check: true
```

## Links

- [Source & documentation](https://github.com/avast/sage)
- [OpenClaw platform guide](https://github.com/avast/sage/blob/main/docs/platform-guides/openclaw.md)
- [Privacy policy](https://github.com/avast/sage/blob/main/docs/privacy.md)

## License

Apache License 2.0 - Copyright 2026 Gen Digital Inc.
