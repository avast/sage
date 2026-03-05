# Privacy

## What Data Is Sent

Sage uses Gen Digital cloud services for three purposes:

1. **URL reputation** — URLs extracted from tool calls are sent to a reputation API for malware/phishing/scam classification.
2. **File reputation** — Package hashes (SHA-256) from npm/PyPI registries are checked against a file reputation service.
3. **Version check** — On session start, Sage sends a POST request to a version-check endpoint with:
   - Sage version
   - Agent runtime (e.g. `claude-code`, `cursor`, `openclaw`, `opencode`, `vscode`)
   - Agent runtime version (when available)
   - OS, OS version, and architecture
   - Installation ID — a random UUID persisted at `~/.sage/installation-id`, generated once and reused across sessions

## What Data Stays Local

- Source code and file contents are never transmitted
- Commands and command arguments stay local
- File paths stay local
- Threat definition matching (heuristics) runs entirely locally
- The verdict cache, allowlist, and audit log are local files

## Configuration

URL and file reputation checks can be disabled in `~/.sage/config.json`:

```json
{
  "url_check": { "enabled": false },
  "file_check": { "enabled": false }
}
```

With both disabled, Sage operates fully offline using only local heuristics.

## More Information

- [Gen Digital Products Privacy Policy](https://www.avast.com/products-policy)
- [Gen Digital Privacy Center](https://www.gendigital.com/privacy/)
