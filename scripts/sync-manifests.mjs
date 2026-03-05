#!/usr/bin/env node

/**
 * Syncs versions from package.json files (already bumped by Changesets)
 * into non-standard manifest files that Changesets doesn't know about.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf-8"));
}

function writeJson(path, json) {
  writeFileSync(path, `${JSON.stringify(json, null, 2)}\n`);
}

const SYNCS = [
  {
    source: resolve(ROOT, "packages/claude-code/package.json"),
    target: resolve(ROOT, ".claude-plugin/plugin.json"),
    apply(version, json) {
      json.version = version;
    },
  },
  {
    source: resolve(ROOT, "packages/claude-code/package.json"),
    target: resolve(ROOT, ".claude-plugin/marketplace.json"),
    apply(version, json) {
      json.version = version;
      for (const plugin of json.plugins ?? []) {
        plugin.version = version;
      }
    },
  },
  {
    source: resolve(ROOT, "packages/openclaw/package.json"),
    target: resolve(ROOT, "packages/openclaw/openclaw.plugin.json"),
    apply(version, json) {
      json.version = version;
    },
  },
];

let synced = 0;

for (const { source, target, apply } of SYNCS) {
  const { version } = readJson(source);
  const json = readJson(target);

  if (json.version === version) continue;

  const prev = json.version;
  apply(version, json);
  writeJson(target, json);

  const rel = target.replace(`${ROOT}/`, "");
  console.log(`${rel}  ${prev} -> ${version}`);
  synced++;
}

if (synced === 0) {
  console.log("All manifests already in sync.");
} else {
  console.log(`\nSynced ${synced} manifest(s).`);
}
