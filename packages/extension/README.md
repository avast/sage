# Sage Editor Extensions

Build targets for Sage extensions that install and manage managed hooks for Cursor and VS Code.

## Local development

```bash
pnpm -C packages/extension build
pnpm -C packages/extension test
pnpm test:e2e:cursor
pnpm test:e2e:vscode
pnpm -C packages/extension package:cursor:vsix
pnpm -C packages/extension package:vscode:vsix
pnpm -C packages/extension package:vsix
```

Extension E2E tests run in real IDE hosts and require installed Cursor / VS Code binaries (no auto-download).

Packaged VSIX files are written to:

- `sage-cursor.vsix`
- `sage-vscode.vsix`

## Commands

- `Sage: Enable protection`
- `Sage: Disable protection`
- `Sage: Open config`
- `Sage: Open audit log`
- `Sage: Show hook health`
