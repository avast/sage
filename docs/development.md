# Development

## Setup

```bash
git clone https://github.com/avast/sage
cd sage
pnpm install
pnpm build
```

Requires Node.js >= 18 and pnpm >= 9.

## Commands

| Command | Description |
|---------|-------------|
| `pnpm build` | Build all packages (tsc + esbuild) |
| `pnpm test` | Run unit + integration tests (builds automatically) |
| `pnpm test -- --reporter=verbose` | Verbose test output |
| `pnpm test -- <file>` | Run a single test file |
| `pnpm test -- -t "name"` | Run tests matching name |
| `pnpm test:e2e` | All E2E tests (Claude Code + OpenClaw + OpenCode + Cursor + VS Code) |
| `pnpm test:e2e:claude` | Claude Code E2E tests only |
| `pnpm test:e2e:openclaw` | OpenClaw E2E tests only |
| `pnpm test:e2e:opencode` | OpenCode E2E tests only |
| `pnpm test:e2e:cursor` | Cursor extension E2E tests only |
| `pnpm test:e2e:vscode` | VS Code extension E2E tests only |
| `pnpm build:sea` | Build standalone SEA binaries |
| `pnpm lint` | Lint with Biome |
| `pnpm lint:fix` | Lint + auto-fix |
| `pnpm check` | Type check all packages |
| `pnpm bump <version>` | Sync version across all manifests |

## Test Tiers

| Tier | Scope | Files | Requires |
|------|-------|-------|----------|
| Unit | Core library | `packages/core/src/__tests__/*.test.ts` | dev deps only |
| Integration | Hook/plugin entry points | `packages/claude-code/src/__tests__/`, `packages/openclaw/src/__tests__/e2e-integration.test.ts`, `packages/opencode/src/__tests__/integration.test.ts` | dev deps only |
| E2E (Claude Code) | Full plugin in Claude CLI | `packages/claude-code/src/__tests__/e2e.test.ts` | `claude` CLI + `ANTHROPIC_API_KEY` |
| E2E (OpenClaw) | Full plugin in OpenClaw gateway | `packages/openclaw/src/__tests__/e2e.test.ts` | OpenClaw gateway + `OPENCLAW_GATEWAY_TOKEN` |
| E2E (OpenCode) | OpenCode CLI smoke test | `packages/opencode/src/__tests__/e2e.test.ts` | OpenCode CLI executable |
| E2E (Cursor extension) | Sage extension in Cursor Extension Host | `packages/extension/src/__tests__/e2e.test.ts` | Installed Cursor executable |
| E2E (VS Code extension) | Sage extension in VS Code Extension Host | `packages/extension/src/__tests__/e2e.test.ts` | Installed VS Code executable |

`pnpm test` runs unit and integration tests. E2E is excluded — run separately with `pnpm test:e2e` (all), `pnpm test:e2e:claude`, `pnpm test:e2e:openclaw`, `pnpm test:e2e:opencode`, `pnpm test:e2e:cursor`, or `pnpm test:e2e:vscode`.

**Claude Code E2E prerequisites:** `claude` CLI in PATH, valid `ANTHROPIC_API_KEY`, and Sage must **not** be installed via the Claude Code marketplace (duplicate-plugin conflict with `--plugin-dir`).

### Cursor / VS Code E2E Setup

The extension E2E tests run inside a real Extension Host process using installed IDE binaries. They do not download IDEs.

**Prerequisites:**

- Cursor E2E: installed Cursor executable
- VS Code E2E: installed VS Code executable
- Extension must be built (handled by Vitest `globalSetup`)

**Optional executable overrides:**

| Variable | Description |
|----------|-------------|
| `SAGE_CURSOR_PATH` | Absolute path to the Cursor executable |
| `SAGE_VSCODE_PATH` | Absolute path to the VS Code executable |
| `VSCODE_EXECUTABLE_PATH` | Alternate VS Code executable override |

If a requested host executable is unavailable, that host's E2E suite is skipped.

**Running the tests:**

```bash
pnpm test:e2e:cursor
pnpm test:e2e:vscode
```

### OpenClaw E2E Setup

The OpenClaw E2E tests connect to a running OpenClaw gateway with Sage installed.

**Prerequisites:** The tests read `~/.openclaw/openclaw.json` for the auth token and check that the chat completions endpoint is enabled. Tests skip automatically if either is missing.

Enable the endpoint in `~/.openclaw/openclaw.json`:

```json
{
  "gateway": {
    "http": {
      "endpoints": {
        "chatCompletions": { "enabled": true }
      }
    }
  }
}
```

**Optional environment variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENCLAW_GATEWAY_TOKEN` | read from `~/.openclaw/openclaw.json` | Override the gateway auth token |
| `OPENCLAW_E2E_HOST` | `http://localhost:18789` | Gateway URL |
| `OPENCLAW_E2E_MODEL` | `claude-3-5-haiku-latest` | Model to use |

**Running the gateway with Docker:**

Use OpenClaw's `OPENCLAW_EXTRA_MOUNTS` to mount the built Sage plugin into the gateway container. Set the variable before running `docker-setup.sh`, which generates `docker-compose.extra.yml` with the mount:

```bash
# Build Sage first
pnpm build

# Set the mount and run setup (generates docker-compose.extra.yml)
export OPENCLAW_EXTRA_MOUNTS="$PWD/packages/openclaw:/home/node/.openclaw/extensions/sage:ro"
./docker-setup.sh

# If the gateway is already set up, re-run docker-setup.sh to regenerate
# the extra compose file, then restart:
docker compose up -d
```

This mounts the built `packages/openclaw/` directory (containing `dist/`, `resources/`, `package.json`, and `openclaw.plugin.json`) into the gateway's extensions directory where plugin discovery finds it. See the [OpenClaw Docker guide](https://docs.openclaw.ai/install/docker) for details.

**Tip:** Disable the security awareness skill on the gateway agent during E2E testing. The skill teaches the model to recognise dangerous patterns, which can cause it to self-refuse commands instead of calling the tool and letting Sage's `before_tool_call` hook handle them.

**Running the tests:**

```bash
pnpm test:e2e:openclaw
```

## Project Layout

```
sage/
├── packages/
│   ├── core/           @sage/core - detection engine
│   ├── claude-code/    @sage/claude-code - Claude Code hooks
│   ├── openclaw/       sage - OpenClaw connector
│   ├── opencode/       @sage/opencode - OpenCode plugin
│   └── extension/      Cursor and VS Code extensions
├── threats/            YAML threat definitions
├── allowlists/         Trusted domain allowlists
├── hooks/              hooks.json for Claude Code
├── skills/             Security awareness skill
├── scripts/            Build utilities
└── doc/                Internal specs and plans
```

## Tooling

| Tool | Version | Purpose |
|------|---------|---------|
| Node.js | >= 18 | Runtime |
| pnpm | >= 9 | Workspace management |
| TypeScript | ^5.9 | Type checking |
| esbuild | ^0.25 | Bundle hooks into single CJS files |
| Biome | ^1.9 | Linting + formatting |
| vitest | ^4.0 | Test runner |
| zod | ^3.24 | Schema validation |
| yaml | ^2.7 | YAML parsing |

## Conventions

- **Naming split:** YAML/JSON data uses `snake_case` (`threat_id`, `source_file`). TypeScript uses `camelCase` (`threatId`, `sourceFile`). Conversion functions handle the boundary.
- **Fail-open:** Every error path must return an `allow` verdict. Hooks must always exit 0.
- **Detection patterns are data.** No hardcoded patterns - all rules live in `threats/*.yaml`.
- **Versioning:** Use `pnpm bump <version>` to update all manifests at once. Never edit version strings by hand.

## Building the Extension

See [Building the Extension](../doc/build_extension.md) for Cursor/VS Code VSIX packaging instructions.
