# Configuration

Sage reads configuration from `~/.sage/config.json`. All fields are optional - defaults are applied automatically.

## Full Config

```json
{
  "url_check": {
    "timeout_seconds": 5,
    "enabled": true
  },
  "file_check": {
    "timeout_seconds": 5,
    "enabled": true
  },
  "package_check": {
    "enabled": true,
    "timeout_seconds": 5
  },
  "amsi_check": {
    "enabled": true
  },
  "heuristics_enabled": true,
  "cache": {
    "enabled": true,
    "ttl_malicious_seconds": 3600,
    "ttl_clean_seconds": 86400,
    "path": "~/.sage/cache.json"
  },
  "allowlist": {
    "path": "~/.sage/allowlist.json"
  },
  "logging": {
    "enabled": true,
    "log_clean": false,
    "path": "~/.sage/audit.jsonl"
  },
  "sensitivity": "balanced",
  "disabled_threats": []
}
```

## Options

### `url_check`

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Enable URL reputation lookups |
| `timeout_seconds` | `5` | Request timeout |

### `file_check`

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Enable file reputation checks for packages |
| `timeout_seconds` | `5` | Request timeout |

### `package_check`

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Enable package supply-chain checks |
| `timeout_seconds` | `5` | Request timeout |

### `amsi_check`

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Enable AMSI (Antimalware Scan Interface) scanning on Windows and WSL |

When enabled, Sage scans tool inputs (commands, file content, edits) through the Windows AMSI API before execution. This integrates with any installed antimalware provider (Windows Defender, etc.) to detect malicious content. AMSI scanning is automatically skipped on unsupported platforms (macOS, non-WSL Linux). See [AMSI Scanning](amsi-scanning.md) for details.

### `heuristics_enabled`

Boolean, default `true`. Set to `false` to disable all local pattern matching.

### `cache`

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Enable verdict caching |
| `ttl_malicious_seconds` | `3600` | Cache TTL for malicious verdicts (1 hour) |
| `ttl_clean_seconds` | `86400` | Cache TTL for clean verdicts (24 hours) |
| `path` | `~/.sage/cache.json` | Cache file location (must remain under `~/.sage`) |

### `allowlist`

| Field | Default | Description |
|-------|---------|-------------|
| `path` | `~/.sage/allowlist.json` | Allowlist file location (must remain under `~/.sage`) |

The allowlist stores user overrides for false positives. When Sage returns an `ask` verdict and the user proceeds, the artifact can be allowlisted for future sessions.

### `logging`

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Enable JSONL audit logging |
| `log_clean` | `false` | Also log `allow` verdicts |
| `path` | `~/.sage/audit.jsonl` | Log file location (must remain under `~/.sage`) |

Relative `path` values are resolved under `~/.sage`. Paths that escape that directory (or resolve to the `~/.sage` directory itself) are ignored and fall back to defaults.

### `sensitivity`

One of `"paranoid"`, `"balanced"`, or `"relaxed"`. Default: `"balanced"`. See [How It Works](how-it-works.md#sensitivity-presets).

In `paranoid` mode, `ask` verdicts are promoted to `deny` on OpenClaw and OpenCode connectors. These connectors rely on the agent to relay approval prompts, making them vulnerable to prompt-injection attacks that could persuade the agent to auto-approve. Claude Code and Cursor are unaffected — they use modal dialogs that require direct user interaction.

### `disabled_threats`

Array of threat IDs to skip during heuristic matching. Default: `[]`.

Use this to permanently suppress specific rules that don't apply to your workflow. Threat IDs are listed in the YAML files under `threats/` (e.g. `CLT-CMD-001`).

```json
{
  "disabled_threats": ["CLT-CMD-001", "CLT-FILE-003"]
}
```

## Files on Disk

| Path | Purpose |
|------|---------|
| `~/.sage/config.json` | Configuration |
| `~/.sage/cache.json` | Verdict cache |
| `~/.sage/allowlist.json` | User allowlist |
| `~/.sage/audit.jsonl` | Audit log |
| `~/.sage/installation-id` | Random UUID identifying this installation |
| `~/.sage/pending-approvals.json` | Pending approval state (transient, managed by PreToolUse hook) |
| `~/.sage/consumed-approvals.json` | Consumed approvals for MCP allowlist flow (10-min TTL entries) |
