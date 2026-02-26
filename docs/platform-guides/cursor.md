# Cursor / VS Code

## Installation

### Cursor

```bash
pnpm install
pnpm -C packages/extension run package:cursor:vsix
```

This produces `sage-cursor.vsix` in the repo root. Install it via `Extensions > Install from VSIX`.

### VS Code

```bash
pnpm install
pnpm -C packages/extension run package:vscode:vsix
```

This produces `sage-vscode.vsix` in the repo root. Install it via `Extensions > Install from VSIX`.

> **Tip:** To build both VSIX packages at once, use `pnpm -C packages/extension run package:vsix`.

## Usage

Open the command palette (`Ctrl+Shift+P`) and use:

| Command | Description |
|---------|-------------|
| `Sage: Enable Protection` | Install managed hooks |
| `Sage: Disable Protection` | Remove managed hooks |
| `Sage: Open Config` | Open `~/.sage/config.json` |
| `Sage: Open Audit Log` | Open the audit log file |
| `Sage: Show Hook Health` | Display hook status |

## How It Works

The extension installs managed hooks into the Cursor/VS Code agent system. When a tool call is intercepted, the hook spawns `sage-hook.cjs` as a subprocess, which runs the same detection pipeline as the Claude Code connector.

## Scope

The extension supports a configurable scope setting:

- **User** - Hooks apply globally for the current user
- **Workspace** - Hooks apply only to the current workspace

Configure via `sage.cursor.scope` (Cursor) or `sage.vscode.scope` (VS Code) in settings.

## E2E Testing

Extension E2E tests run inside installed IDE hosts (no IDE auto-download):

```bash
pnpm test:e2e:cursor
pnpm test:e2e:vscode
```

Optional executable overrides:

- `SAGE_CURSOR_PATH` - absolute path to Cursor executable
- `SAGE_VSCODE_PATH` - absolute path to VS Code executable
- `VSCODE_EXECUTABLE_PATH` - alternate VS Code executable override

## Build Details

The extension bundles `threats/` and `allowlists/` from the repo root into `packages/extension/resources/` during build (via `sync-assets.mjs`). These are not checked into git.

See [Building the Extension](../../doc/build_extension.md) for platform-specific build instructions.
