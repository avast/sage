#!/usr/bin/env bash
# Pre-release content audit for Sage.
# Runs gitleaks on the full repo using .gitleaks.toml (which must be symlinked
# from the sage-internal repo). All detection logic lives in the config — this
# script is just orchestration.
#
# Exit codes: 0 = pass, 1 = violation found, 2 = script error
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
RESET='\033[0m'

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="$REPO_ROOT/.gitleaks.toml"

# ── Phase 1: Check prerequisites ──────────────────────────────────────────────

if ! command -v gitleaks &>/dev/null; then
  echo -e "${RED}ERROR:${RESET} gitleaks is not installed."
  echo "  Install: brew install gitleaks  (or see https://github.com/gitleaks/gitleaks)"
  exit 2
fi

if [[ ! -f "$CONFIG" ]]; then
  echo -e "${RED}ERROR:${RESET} .gitleaks.toml not found at ${CONFIG}"
  echo ""
  echo "  The gitleaks config is required for this audit. Without it, internal"
  echo "  infrastructure patterns and content rules are not loaded."
  echo ""
  echo "  Setup:"
  echo "    git clone <sage-internal repo> ../sage-internal"
  echo "    ln -s ../sage-internal/.gitleaks.toml .gitleaks.toml"
  exit 1
fi

# ── Phase 2: Run gitleaks ─────────────────────────────────────────────────────

echo -e "${BOLD}Pre-release audit${RESET}"
echo "  Config: $CONFIG"
echo "  Source: $REPO_ROOT"
echo ""

if gitleaks detect --source "$REPO_ROOT" --config "$CONFIG" --no-git --verbose; then
  echo ""
  echo -e "${GREEN}PASS${RESET} — no violations found."
  exit 0
else
  status=$?
  echo ""
  echo -e "${RED}FAIL${RESET} — gitleaks found violations (exit code $status)."
  echo "  Fix the issues above, or add inline '# gitleaks:allow' for false positives."
  exit 1
fi
