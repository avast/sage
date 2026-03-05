# Architecture

Sage is a TypeScript monorepo with a shared core library and platform-specific connectors.

## Packages

```
packages/
├── core/          @sage/core        Platform-agnostic detection engine
├── claude-code/   @sage/claude-code  Claude Code hook entry points
├── openclaw/      sage              OpenClaw plugin connector
└── extension/                       Cursor and VS Code extensions
```

### `@sage/core`

The core library contains all detection logic. It has no platform dependencies and is imported by all connectors.

| Module | Purpose |
|--------|---------|
| `extractors.ts` | Extracts URLs, commands, file paths from tool inputs |
| `heuristics.ts` | Matches artifacts against YAML threat patterns |
| `engine.ts` | Decision engine - combines signals into a Verdict |
| `threat-loader.ts` | Loads YAML threat definitions |
| `config.ts` | Config loading and validation (Zod schemas) |
| `cache.ts` | JSON file verdict cache with TTLs |
| `allowlist.ts` | User allowlist management |
| `audit-log.ts` | JSONL audit logging |
| `trusted-domains.ts` | Trusted domain loading and matching |
| `plugin-scanner.ts` | Plugin file scanning |
| `package-checker.ts` | npm/PyPI supply-chain checks |
| `installation-id.ts` | Persistent installation UUID (`~/.sage/installation-id`) |
| `version-check.ts` | Version check via POST with environment context |
| `session-start.ts` | Session start orchestrator (scan + version check) |
| `clients/url-check.ts` | URL reputation API client and endpoint resolver |
| `clients/file-check.ts` | File reputation API client |
| `clients/package-registry.ts` | npm/PyPI registry client |

### `@sage/claude-code`

Two entry points, each bundled by esbuild into a single CJS file:

- **`pre-tool-use.ts`** - Reads tool call JSON from stdin, orchestrates core, outputs verdict JSON to stdout.
- **`session-start.ts`** - Scans installed plugins for threats.

Registered via `hooks/hooks.json`.

### `sage` (OpenClaw)

In-process plugin using `api.on('before_tool_call')`. Includes:

- **`tool-handler.ts`** - Intercepts tool calls, runs detection pipeline
- **`gate-tool.ts`** - `sage_approve` tool for interactive approval of flagged actions
- **`approval-store.ts`** - Tracks per-session approvals
- **`startup-scan.ts`** - Plugin scanning at gateway/session start

### Extension (Cursor / VS Code)

VS Code API extension with platform-specific installers:

- **`shared_extension.ts`** - Registers commands: enable/disable protection, open config, show hook health
- **`cursor_hook_installer.ts`** / **`vscode_hook_installer.ts`** - Install managed hooks into Cursor or VS Code

## Data Flow

### Claude Code

```
Hook stdin (JSON) -> extract artifacts -> check allowlist -> check cache
  -> heuristics + URL check + package check -> DecisionEngine
  -> cache result -> audit log -> hook stdout (JSON)
```

Claude Code hooks exit 0. Errors return an `allow` verdict.

### OpenClaw

```
before_tool_call event -> extract artifacts -> check approval store
  -> check allowlist -> check cache -> heuristics + URL check + package check
  -> DecisionEngine -> cache result -> audit log -> block/pass
```

Blocked actions return an `actionId` that users can approve via the `sage_approve` gate tool.

### Cursor / VS Code

```
Managed hook intercepts tool call -> spawns sage-hook.cjs subprocess
  -> extract artifacts -> check allowlist -> check cache
  -> heuristics + URL check + package check -> DecisionEngine
  -> cache result -> audit log -> return verdict
```

Extension hooks (Cursor / VS Code) always exit with code `0`; the host reads the JSON response to enforce blocking.

## Key Design Decisions

- **All patterns are data.** Detection rules live in `threats/*.yaml`, not in code. This makes rules easy to review, contribute, and update independently.
- **Fail-open.** Every error path returns `allow`. Sage should never break the agent.
- **Shared core.** All platforms use the same `@sage/core` library, ensuring consistent detection regardless of connector.
- **No runtime dependencies beyond Node.js.** The core uses native `fetch`, `yaml` for YAML parsing, and `zod` for validation. Connectors are bundled into single CJS files.
