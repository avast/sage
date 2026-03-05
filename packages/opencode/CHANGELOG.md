# @sage/opencode

## 0.5.0

### Minor Changes

- OpenCode connector, co-authored by FeiyouG
- Unify approval store, guard orchestrator, and allowlist tool logic into core. Fix OpenCode pendingFindings race condition.

### Patch Changes

- Extend version check to allow for finer-grained version checking based on individual packages.
- Promote ask verdicts to deny in paranoid mode to prevent prompt-injection auto-approval
