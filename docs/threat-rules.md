# Threat Rules

Sage uses YAML-based threat definitions to match tool call artifacts against known dangerous patterns. All detection logic is data - no patterns are hardcoded.

## Rule Files

Rules ship in the `threats/` directory at the repository root:

| File | Scope |
|------|-------|
| `commands.yaml` | Dangerous command patterns (pipe-to-shell, reverse shells, destructive ops) |
| `urls.yaml` | Malicious URL and domain patterns |
| `files.yaml` | Sensitive file path writes |
| `credentials.yaml` | Credential exposure patterns |
| `persistence.yaml` | Persistence mechanisms (cron, systemd, shell RC, LaunchAgents) |
| `obfuscation.yaml` | Encoding and obfuscation techniques |
| `supply_chain.yaml` | Supply chain risk patterns |
| `self-defense.yaml` | Attempts to disable or bypass Sage |
| `mitre.yaml` | MITRE ATT&CK technique mappings |
| `win-*.yaml` | Windows-specific variants of the above |
| `mac-*.yaml` | macOS-specific variants (osascript, Keychain, LOLBins, defense evasion) |

## Rule Schema

```yaml
- id: "CLT-CMD-001"
  category: tool
  severity: critical
  confidence: 0.95
  action: block
  pattern: "curl\\s[^|]*\\|\\s*(bash|sh|zsh|ksh|dash)"
  match_on: command
  title: "Remote code execution via curl pipe to shell"
  expires_at: null
  revoked: false
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier (e.g. `CLT-CMD-001`) |
| `category` | string | Threat category (`tool`, `network_egress`, `secrets`, `supply_chain`) |
| `severity` | enum | `critical`, `high`, `medium`, or `low` |
| `confidence` | float | 0.0-1.0, used with sensitivity threshold |
| `action` | enum | `block`, `require_approval`, or `log` |
| `pattern` | string | Regex pattern |
| `match_on` | string or list | `command`, `url`, `file_path`, `content`, or `domain` |
| `title` | string | Human-readable description |
| `expires_at` | string or null | ISO 8601 expiration date, or `null` for permanent |
| `revoked` | boolean | Set `true` to disable a rule without removing it |
| `case_insensitive` | boolean | *(optional)* Match pattern case-insensitively (default: `false`) |

`match_on` accepts a single value or a list. For example, credential patterns may match on both `command` and `content`:

```yaml
  match_on: [command, content]
```

## What Gets Checked

**Bash commands (cross-platform):**
- Pipe-to-shell attacks, reverse shell patterns (incl. Python/Ruby/zsh socket shells), destructive operations
- Download-and-execute chains, privilege escalation
- Data exfiltration, persistence mechanisms (cron, systemd, shell RC, `at` jobs), credential exposure
- Obfuscation (base64-decode-exec, hex escapes, eval-decode, Python encoded payloads)
- Python one-liners with dangerous imports

**Bash commands (macOS-specific):**
- osascript RCE (AppleScript `do shell script`, JXA execution, piped/remote scripts)
- macOS LOLBins (`dscl`, `networksetup`, `systemsetup`, `kickstart`, `installer`, `hdiutil`, `pkgutil`)
- Keychain attacks (`security find-generic-password`, `dump-keychain`, `unlock-keychain`, `delete-keychain`, direct SQLite access)
- Defense evasion (Gatekeeper disable via `spctl`, SIP disable via `csrutil`, quarantine removal, firewall disable via `pfctl`, TCC reset via `tccutil`, security daemon unloading)
- Privilege escalation (`dscl -passwd`, `dseditgroup` admin group add)
- Destructive operations (`diskutil eraseDisk`, `tmutil delete` — ransomware indicator)
- Persistence (LaunchAgents via `osascript`/`launchctl`, login items, SecurityAgentPlugins, emond rules, `DYLD_INSERT_LIBRARIES`, Folder Actions, periodic scripts)
- Obfuscation (base64-to-osascript, DYLD injection, binary plist conversion via `plutil`, Swift inline execution)
- Supply chain (Homebrew install without version pin, remote `.pkg` install, cask installs)

**File writes/edits:**
- System authentication files, SSH keys and config, shell RC files
- macOS LaunchAgents/LaunchDaemons, TCC.db, authorization DB, kernel extensions, SecurityAgentPlugins, emond rules, Safari credential stores, Managed Preferences, Keychain files
- Cron directories, systemd unit files
- Credential files (`.env`, `.aws/credentials`, `.netrc`)
- Git hooks, URLs and credentials embedded in content

**URLs:**
- Known malware/phishing/scam patterns
- Paste sites used for C2, direct IP address URLs
- Executable file downloads

## Trusted Installer Domains

Pipe-to-shell commands targeting known installer domains are suppressed from heuristic matches. The allowlist lives in `allowlists/trusted-installer-domains.yaml`:

```yaml
- domain: bun.sh
  reason: Bun JavaScript runtime installer
- domain: brew.sh
  reason: Homebrew package manager installer
```

Domains are matched by suffix with dot boundary (e.g. `bun.sh` matches `cdn.bun.sh` but not `notbun.sh`).

## Licensing

Threat rules are licensed under the [Detection Rule License 1.1](../threats/LICENSE), separate from the Apache 2.0 source code license. See [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution guidelines.
