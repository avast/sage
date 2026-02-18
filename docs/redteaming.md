# Sage Red Team Attack Catalog

Date: 2026-02-18  
Scope: `packages/core`, `packages/claude-code`, `packages/openclaw`, `packages/extension`, `threats`, `allowlists`, `hooks`

This document captures a first-pass catalog of plausible attacks that could make Sage ineffective, bypass detection, reduce coverage, or degrade reliability.

Notes:
- This is a candidate attack list from code review; items are not yet exploit-verified.
- Priorities indicate likely security impact and bypass potential.

## P0 - High-Impact Bypass Attacks

### ATK-01: Allowlist Smuggling via Any-Match Logic
- **Hypothesis**: If any artifact in a tool call is allowlisted, the whole call is allowed.
- **Potential abuse**: Include one allowlisted URL plus a malicious command/URL in the same request.
- **Impact**: High-confidence bypass of protective decisions.
- **Relevant code**: `packages/core/src/allowlist.ts`, `packages/core/src/evaluator.ts`
- **Verification**:
  - Unrelated allowlisted URL artifact can bypass deny for a malicious command.
  - Same bypass works when the allowlisted URL is smuggled into the command text.
  - Clean URL can be poisoned in cache when first seen in a denied command, then later denied from cache in a benign call.
- **Tests created**: `packages/core/src/__tests__/evaluator.test.ts`
  - Baseline deny test (passes).
  - `ATK-01: malicious command is not bypassed by unrelated allowlisted URL artifact` (currently red, expected secure behavior).
  - `ATK-01: malicious command is not bypassed when allowlisted URL is smuggled in command text` (currently red).
  - `ATK-01: clean URL is poisoned in cache when first seen and then leads to denial of safe command` (currently red).

### ATK-02: Trusted-Domain Decoy Suppression
- **Hypothesis**: Trusted-domain suppression can remove dangerous pipe-to-shell matches if a trusted domain appears in the same matched artifact.
- **Potential abuse**: Blend trusted installer domain references with hostile pipeline behavior.
- **Impact**: Critical command patterns may be suppressed.
- **Relevant code**: `packages/core/src/heuristics.ts`, `allowlists/trusted-installer-domains.yaml`
- **Verification**:
  - Trusted domain in the same command artifact suppresses detection even when an untrusted malicious URL is present.
  - Trusted + untrusted pipe-to-shell in one command artifact is fully suppressed for suppressible threat IDs.
- **Tests created**: `packages/core/src/__tests__/heuristics.test.ts`
  - `ATK-02: unrelated trusted URL in same command does not suppress untrusted pipe-to-shell match` (currently red, expected secure behavior).
  - `ATK-02: trusted and untrusted pipe-to-shell in one command still flags untrusted execution` (currently red).

### ATK-03: Unprotected Tool Surfaces (Claude Hook Matcher Gap)
- **Hypothesis**: Claude hook matcher only covers `Bash|WebFetch|Write|Edit`.
- **Potential abuse**: Use other tools or call shapes not routed through evaluation.
- **Impact**: Full bypass for uncovered tool families.
- **Relevant code**: `hooks/hooks.json`, `packages/claude-code/src/pre-tool-use.ts`

### ATK-04: OpenClaw `apply_patch` Body Blind Spot
- **Hypothesis**: OpenClaw path extracts only file paths from patch headers, not patch body content.
- **Potential abuse**: Insert malicious content/commands/URLs in patch body without triggering content heuristics.
- **Impact**: Substantial detection blind spot for code edits.
- **Relevant code**: `packages/openclaw/src/tool-handler.ts`

### ATK-05: Heredoc Execution Bypass
- **Hypothesis**: Heredoc bodies are stripped before command heuristics.
- **Potential abuse**: Hide executable payloads in heredoc-fed shell logic.
- **Impact**: Core command threat signatures can be bypassed.
- **Relevant code**: `packages/core/src/extractors.ts`

### ATK-06: Local Poisoning of Config / Allowlist / Cache
- **Hypothesis**: Local state files under `~/.sage` are trusted without integrity/ownership checks.
- **Potential abuse**: Pre-poison allowlist/cache, or weaken config to disable checks.
- **Impact**: Persistent local bypass or silent policy degradation.
- **Relevant code**: `packages/core/src/config.ts`, `packages/core/src/allowlist.ts`, `packages/core/src/cache.ts`

## P1 - Evasion and Coverage-Gap Attacks

### ATK-07: 64KB Truncation Evasion
- **Hypothesis**: Content scanning is capped at 64KB.
- **Potential abuse**: Place malicious payload beyond cap.
- **Impact**: Content and URL artifacts can be missed.
- **Relevant code**: `packages/core/src/extractors.ts`, `packages/extension/src/sage-hook.ts`

### ATK-08: Regex Obfuscation Bypass
- **Hypothesis**: Threat detection depends heavily on static regex signatures.
- **Potential abuse**: Variable indirection, concatenation, encoding variants, atypical quoting.
- **Impact**: Evasion against pattern-based detection.
- **Relevant code**: `threats/commands.yaml`, `threats/obfuscation.yaml`, `threats/win-commands.yaml`, `threats/win-obfuscation.yaml`

### ATK-09: Package-Check Blind Spots
- **Hypothesis**: Scoped npm packages are skipped; some dependency declaration formats are unparsed.
- **Potential abuse**: Deliver risky dependencies through skipped/unsupported channels.
- **Impact**: Supply-chain checks under-report risk.
- **Relevant code**: `packages/core/src/package-checker.ts`, `packages/core/src/package-extractor.ts`

### ATK-10: URL Extraction Blind Spots
- **Hypothesis**: URL checks rely on extracting literal URLs.
- **Potential abuse**: Build URLs dynamically or obfuscate construction.
- **Impact**: Reputation checks never run for hidden endpoints.
- **Relevant code**: `packages/core/src/extractors.ts`, `packages/core/src/clients/url-check.ts`

### ATK-11: Tool-Name Mapping Drift
- **Hypothesis**: Tool extraction routing is name/schema-sensitive.
- **Potential abuse**: Introduce tool names/payload variants that map to no artifacts.
- **Impact**: Silent allow due to empty artifact extraction.
- **Relevant code**: `packages/claude-code/src/pre-tool-use.ts`, `packages/openclaw/src/tool-handler.ts`, `packages/extension/src/sage-hook.ts`
- **Finding summary**:
  - If connectors cannot map an action to artifacts, core evaluation can fall back to allow (`no_artifacts` behavior).
  - This can happen from platform/tool schema drift, unsupported tool names, or payload shape mismatch.
  - Risk is silent coverage loss: dangerous actions may pass without threat evaluation.
- **Test status**: No dedicated ATK-11 red tests added yet.
- **Proposed mitigation direction**:
  - In `paranoid` mode, default unknown/unsupported actions to `ask` instead of allow.
  - Add an explicit strict option (for all modes) to default unknown/unsupported actions to `ask` (or `deny`), so behavior is policy-controlled.

### ATK-12: Safety Downgrade Through Config Knobs
- **Hypothesis**: Disabling heuristics/URL/package checks or relaxed sensitivity significantly weakens coverage.
- **Potential abuse**: Intentional or accidental config downgrades.
- **Impact**: System remains "on" but with materially reduced protection.
- **Relevant code**: `packages/core/src/config.ts`, `threats/self-defense.yaml`

### ATK-13: Threat-Load Failure Fallback
- **Hypothesis**: Unreadable/missing threat directories produce empty threat sets.
- **Potential abuse**: Break threat file access path or deployment packaging.
- **Impact**: Heuristic layer effectively disabled.
- **Relevant code**: `packages/core/src/threat-loader.ts`, `packages/core/src/evaluator.ts`

## P2 - Reliability / DoS Attacks

### ATK-14: Dependency-Bomb DoS in Package Checker
- **Hypothesis**: Concurrency-limiter logic can accumulate excessive pending promises under load.
- **Potential abuse**: Very large package sets in command/manifests.
- **Impact**: Latency spikes, degraded responsiveness, potential timeout cascade.
- **Relevant code**: `packages/core/src/package-checker.ts`

### ATK-15: Regex / Compute Pressure DoS
- **Hypothesis**: Many regex evaluations over large adversarial inputs can increase CPU cost.
- **Potential abuse**: Feed pathological command/content inputs designed to maximize matching work.
- **Impact**: Throughput reduction and timeout pressure.
- **Relevant code**: `packages/core/src/heuristics.ts`, `threats/*.yaml`

### ATK-16: Plugin Scan Recursion / Scale DoS
- **Hypothesis**: Plugin scanner recursively walks plugin trees and may face scale/pathological directory structures.
- **Potential abuse**: Large trees, complex nested content, edge-case filesystem constructs.
- **Impact**: Slow startup/session scans and degraded UX.
- **Relevant code**: `packages/core/src/plugin-scanner.ts`

### ATK-17: Forensics Suppression via Logging Path Failure
- **Hypothesis**: Logging errors are swallowed (fail-open).
- **Potential abuse**: Make audit path invalid/unwritable.
- **Impact**: Actions continue but forensic trail is lost.
- **Relevant code**: `packages/core/src/audit-log.ts`

### ATK-18: OpenClaw Approval Replay Window
- **Hypothesis**: Approved action IDs remain valid for TTL and are reusable for identical payloads.
- **Potential abuse**: Re-run same malicious call after single approval.
- **Impact**: Temporary bypass window after one user approval.
- **Relevant code**: `packages/openclaw/src/approval-store.ts`, `packages/openclaw/src/gate-tool.ts`

## Suggested Investigation Order

1. `ATK-01` (allowlist smuggling)
2. `ATK-03` (tool coverage gap)
3. `ATK-04` (OpenClaw patch-body blind spot)
4. `ATK-05` (heredoc bypass)
5. `ATK-06` (local poisoning hardening)
6. `ATK-14` (package-check DoS path)
