# @sage/core

## 0.5.1

### Patch Changes

- Fixed cursor hooks not working in some cases.

## 0.5.0

### Minor Changes

- Intercept Read and Delete tools for security checks
- Add `extractFromRead` and `extractFromDelete` to core extractors
- Anti-malware Scan Interface (AMSI) integration on Windows
- 64 macOS-specific threat rules
- Unify approval store, guard orchestrator, and allowlist tool logic into core

### Patch Changes

- Guard fnUninitialize call during AMSI session open failure cleanup
- Fix CLT-CMD-006 false positives on `rm -rf /absolute/path` and add CLT-CMD-026 for critical system directory protection.
- Extend version check to allow for finer-grained version checking based on individual packages.
- Hardened config path resolution to prevent config directory escapes.
- Add FN/FP test coverage for threat detection rules; tighten CLT-CRED-003 to exclude .env.example, .env.sample, .env.template, and .env.dist writes (including compound forms like .env.local.example) while adding .prod, .stage, .dev, .test suffix coverage; align CLT-FILE-008 with path-segment boundary to avoid matching non-dotfile paths; exclude template suffixes from CLT-CRED-004 reads
