import { configDefaults, defineProject } from "vitest/config";

export default defineProject({
	test: {
		name: "opencode",
		environment: "node",
		exclude: [...configDefaults.exclude, "src/__tests__/e2e.test.ts"],
	},
});
