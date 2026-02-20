import { spawn } from "node:child_process";
import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const extensionRoot = resolve(scriptDir, "..");
const repoRoot = resolve(extensionRoot, "..", "..");

const stageDir = join(extensionRoot, ".vsce", "vscode_extension");
const outputVsix = join(repoRoot, "sage-vscode.vsix");

const baseManifest = JSON.parse(await readFile(join(extensionRoot, "package.json"), "utf8"));
const vscodeManifest = buildVsCodeManifest(baseManifest);

await rm(stageDir, { recursive: true, force: true });
await mkdir(stageDir, { recursive: true });
await cp(join(extensionRoot, "dist"), join(stageDir, "dist"), { recursive: true, force: true });
await cp(join(extensionRoot, "resources"), join(stageDir, "resources"), {
	recursive: true,
	force: true,
});
await cp(join(extensionRoot, "README.md"), join(stageDir, "README.md"), { force: true });
await cp(join(extensionRoot, "LICENSE"), join(stageDir, "LICENSE"), { force: true });
await writeFile(join(stageDir, "package.json"), `${JSON.stringify(vscodeManifest, null, 2)}\n`, "utf8");

await runVscePackage(stageDir, outputVsix);

function buildVsCodeManifest(base) {
	const manifest = { ...base };
	manifest.name = "sage-vscode";
	manifest.displayName = "Sage for VS Code";
	manifest.description = "Safety for Agents — ADR layer for VS Code Claude hooks";
	manifest.main = "./dist/vscode_extension.js";
	manifest.files = [
		"dist/vscode_extension.js",
		"dist/vscode_extension.js.map",
		"dist/sage-hook.cjs",
		"dist/sage-hook.cjs.map",
		"resources/**",
		"package.json",
		"README.md",
		"LICENSE",
	];
	manifest.contributes = {
		...base.contributes,
		configuration: {
			title: "Sage",
			properties: {
				"sage.vscode.scope": {
					type: "string",
					default: "user",
					enum: ["workspace", "user"],
					description: "Where Sage installs Claude Code hooks.",
				},
				"sage.hookRunnerPath": {
					type: "string",
					default: "",
					description: "Optional absolute path to a sage-hook runner script.",
				},
			},
		},
	};
	return manifest;
}

function runVscePackage(workingDirectory, outputPath) {
	return new Promise((resolveRun, rejectRun) => {
		const child = spawn(
			"corepack",
			[
				"pnpm",
				"dlx",
				"@vscode/vsce",
				"package",
				"-o",
				outputPath,
				"--no-dependencies",
				"--allow-package-secrets",
				"github",
				"--allow-package-secrets",
				"slack",
			],
			{
				cwd: workingDirectory,
				stdio: "inherit",
				shell: process.platform === "win32",
			},
		);
		child.on("error", rejectRun);
		child.on("exit", (code) => {
			if (code === 0) {
				resolveRun(undefined);
				return;
			}
			rejectRun(new Error(`vsce exited with code ${code ?? "unknown"}`));
		});
	});
}
