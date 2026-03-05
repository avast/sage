# How It Works

Sage intercepts tool calls made by AI agents, extracts security-relevant artifacts, and checks them against multiple threat detection layers.

## Detection Layers

1. **URL reputation** - Cloud-based lookup for malware, phishing, and scam URLs. Works without an API key.
2. **Local heuristics** - YAML-based regex patterns matching dangerous commands, suspicious URLs, sensitive file paths, credential exposure, and obfuscation techniques.
3. **Package supply-chain checks** - Registry existence, file reputation, and age analysis for npm/PyPI packages. See [Package Protection](package-protection.md).
4. **Plugin scanning** - Scans other installed plugins for threats at session start. See [Plugin Scanning](plugin-scanning.md).

## Intercepted Tools

| Platform | Hooks / Tools |
|----------|---------------|
| Claude Code | `PreToolUse` on `Bash`, `WebFetch`, `Write`, `Edit`, `Read` |
| Cursor | `beforeShellExecution`, `preToolUse` (Write, Edit, Delete, WebFetch), `beforeMCPExecution`, `beforeReadFile` |
| VS Code | `PreToolUse` on `Bash`, `WebFetch`, `Write`, `Edit`, `Read`, `Delete` |
| OpenClaw | `exec`, `web_fetch`, `write`, `edit`, `read`, `apply_patch` |

## Data Flow

```
Tool call received
  │
  ├─ Extract artifacts (URLs, commands, file paths, content)
  │
  ├─ Check allowlist → if allowlisted → allow
  │
  ├─ Check cache → if cached → use cached verdict
  │
  ├─ Run local heuristics (pattern matching against threat definitions)
  │
  ├─ Query URL reputation (for extracted URLs)
  │
  ├─ Check packages (for install commands / manifest writes)
  │
  ├─ Decision engine combines all signals → verdict
  │
  ├─ Cache result
  │
  └─ Audit log → return verdict
```

## Verdicts

| Decision | Meaning |
|----------|---------|
| `allow`  | No threats detected, tool call proceeds |
| `ask`    | Suspicious - user prompted for approval |
| `deny`   | Confirmed threat - tool call blocked |

When multiple signals fire, merge precedence is: `deny > ask > allow`.

## Fail-Open Design

Sage is designed to never break the agent. Every internal error path returns an `allow` verdict. Extension hooks (Cursor / VS Code) always exit with code `0`; the host uses the JSON response to decide whether to block the tool call. If the URL reputation API is down or times out, Sage falls back to heuristics only.

## Sensitivity Presets

The confidence threshold determines when a detection escalates from `ask` to `deny`:

| Preset | Threshold | Behavior |
|--------|-----------|----------|
| `paranoid` | 0.70 | Blocks on any suspicion |
| `balanced` | 0.85 | Blocks confirmed threats, warns on suspicious (default) |
| `relaxed` | 0.95 | Only blocks high-confidence malware |

Configure in `~/.sage/config.json` with `"sensitivity": "paranoid"`.

On text-based connectors (OpenClaw, OpenCode), `paranoid` mode also promotes all `ask` verdicts to `deny`. These connectors rely on the agent to relay approval prompts, which is susceptible to prompt-injection auto-approval. Claude Code and Cursor use modal dialogs and are unaffected.
