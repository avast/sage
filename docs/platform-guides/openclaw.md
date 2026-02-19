# OpenClaw

## Installation

Install from npm or build from source:

```bash
# From npm (recommended)
openclaw plugins install @gendigital/sage-openclaw

# From source
pnpm install && pnpm build
cp -r packages/openclaw sage
openclaw plugins install ./sage
```

The build copies threat definitions, allowlists, and skills into `packages/openclaw/resources/`.

## How It Works

The OpenClaw connector runs in-process using the OpenClaw plugin API:

- **`before_tool_call`** - Intercepts `exec`, `web_fetch`, `write`, `edit`, `read`, and `apply_patch`. Runs the full detection pipeline.
- **`sage_approve`** - A gate tool that lets users approve flagged actions by action ID.
- **`gateway_start` / `session_start`** - Scans installed plugins for threats.

## Intercepted Tools

| OpenClaw Tool | Maps To |
|---------------|---------|
| `exec` | Bash command extraction |
| `web_fetch` | URL extraction |
| `write` | File path + content extraction |
| `edit` | File path + content extraction |
| `read` | File path extraction |
| `apply_patch` | File path extraction from diffs |

## Gate Tool

When Sage blocks a tool call, it returns an `actionId` in the block reason. The model can then call `sage_approve` to ask the user for approval:

```json
{
  "actionId": "abc-123",
  "approved": true
}
```

Approvals are stored per-session and not persisted across restarts.

## Security Awareness Skill

The skill is registered in `openclaw.plugin.json` and bundled into `resources/skills/` during build.

## Code Safety Warning

OpenClaw's `plugins.code_safety` audit will flag Sage with a `potential-exfiltration` warning. This is a false positive - `readFile` and `fetch` coexist in the same bundle because Sage reads local config/cache files and separately sends URL hashes to a reputation API. No file content is transmitted.
