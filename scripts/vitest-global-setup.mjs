import { execSync } from "node:child_process";

const run = (cmd, cwd) => execSync(cmd, { stdio: "inherit", cwd });

export function setup() {
	// Build core first (needed by all other packages)
	run("pnpm --filter @sage/core run build");
	// Build claude-code and openclaw (no corepack dependency)
	run("pnpm --filter @sage/claude-code --filter sage run build");
	// Build extension manually (its build script uses corepack which may not be available)
	run("node scripts/sync-assets.mjs", "packages/extension");
	run("node esbuild.config.cjs", "packages/extension");
	// Build opencode plugin bundle used by integration tests
	run("pnpm --filter @sage/opencode run build");
}
