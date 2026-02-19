const esbuild = require("esbuild");
const { readFileSync } = require("node:fs");

const pkg = JSON.parse(readFileSync("../core/package.json", "utf-8"));

const shared = {
	bundle: true,
	platform: "node",
	target: "node18",
	format: "cjs",
	sourcemap: true,
	define: { __SAGE_VERSION__: JSON.stringify(pkg.version) },
};

async function build() {
	await esbuild.build({
		...shared,
		entryPoints: ["src/cursor_extension.ts"],
		outfile: "dist/cursor_extension.js",
		external: ["vscode"],
	});

	await esbuild.build({
		...shared,
		entryPoints: ["src/vscode_extension.ts"],
		outfile: "dist/vscode_extension.js",
		external: ["vscode"],
	});

	await esbuild.build({
		...shared,
		entryPoints: ["src/sage-hook.ts"],
		outfile: "dist/sage-hook.cjs",
	});
}

build().then(
	() => {
		console.log("Build complete.");
	},
	(error) => {
		console.error(error);
		process.exitCode = 1;
	},
);
