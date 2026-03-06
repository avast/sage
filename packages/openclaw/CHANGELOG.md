# @gendigital/sage-openclaw

## 0.5.3

### Patch Changes

- Fix the configuration instructions inside README. Add an ask->deny promotion integration test.

## 0.5.2

### Patch Changes

- Updated dependencies
  - @sage/core@0.5.2

## 0.5.0

### Minor Changes

- Unify approval store, guard orchestrator, and allowlist tool logic into core. Add allowlist tools to OpenClaw.

### Patch Changes

- Extend version check to allow for finer-grained version checking based on individual packages.
- Promote ask verdicts to deny in paranoid mode to prevent prompt-injection auto-approval
