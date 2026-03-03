import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		globalSetup: ["./scripts/vitest-global-setup.mjs"],
		include: [
			"packages/claude-code/src/__tests__/e2e.test.ts",
			"packages/openclaw/src/__tests__/e2e.test.ts",
			"packages/opencode/src/__tests__/e2e.test.ts",
			"packages/extension/src/__tests__/e2e.test.ts",
		],
	},
});
