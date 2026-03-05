#!/usr/bin/env bash
#
# Pre-push hook: warns when user-facing files changed on the branch without a changeset.
# Bypassable with git push --no-verify.

BASE_BRANCH="main"

# Paths that affect shipped artifacts
WATCHED_PATTERNS=(
  'packages/[^/]+/src/'
  'threats/'
  'allowlists/'
  'hooks/'
  'skills/'
  '\.claude-plugin/'
)

# Find the merge base with the target branch
merge_base=$(git merge-base "origin/${BASE_BRANCH}" HEAD 2>/dev/null)
if [ -z "$merge_base" ]; then
  echo "No merge base found. If this is not a new repo, then the clone is not correct (missing branches, shallow?)"
  exit 1
fi

# If we're on the base branch itself, nothing to check
if [ "$(git rev-parse HEAD)" = "$(git rev-parse "origin/${BASE_BRANCH}" 2>/dev/null)" ]; then
  exit 0
fi

# Get all files changed on this branch relative to the base
changed=$(git diff --name-only "${merge_base}...HEAD")
[ -z "$changed" ] && exit 0

# Check if any changed files match watched patterns
matched=false
for pattern in "${WATCHED_PATTERNS[@]}"; do
  if echo "$changed" | grep -qE "^${pattern}"; then
    matched=true
    break
  fi
done

[ "$matched" = false ] && exit 0

# Check if a changeset file is included in the branch diff
if echo "$changed" | grep -qE '^\.changeset/.*\.md$'; then
  exit 0
fi

echo ""
echo "⚠  Branch contains changes to shipped artifacts but no changeset was found."
echo "   Create one with: pnpm changeset"
echo "   Skip this check: git push --no-verify"
echo ""
exit 1
