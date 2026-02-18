import * as esbuild from "esbuild";
import { readFileSync } from "node:fs";

const pkg = JSON.parse(readFileSync("../core/package.json", "utf-8"));

const shared = {
	bundle: true,
	platform: "node",
	target: "node22",
	format: "cjs",
	external: [],
	sourcemap: true,
	define: { __SAGE_VERSION__: JSON.stringify(pkg.version) },
};

await Promise.all([
	esbuild.build({ ...shared, entryPoints: ["src/pre-tool-use.ts"], outfile: "dist/pre-tool-use.cjs" }),
	esbuild.build({ ...shared, entryPoints: ["src/post-tool-use.ts"], outfile: "dist/post-tool-use.cjs" }),
	esbuild.build({ ...shared, entryPoints: ["src/mcp-server.ts"], outfile: "dist/mcp-server.cjs" }),
	esbuild.build({ ...shared, entryPoints: ["src/session-start.ts"], outfile: "dist/session-start.cjs" }),
]);

console.log("Build complete.");
