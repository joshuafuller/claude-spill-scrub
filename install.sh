#!/usr/bin/env bash
# Manual install: symlink this repo's skill into ~/.claude/skills.
# Prefer the plugin marketplace instead (see README) - this is the fallback for
# an air-gapped box or a checkout you want to edit in place.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${CLAUDE_SKILLS_DIR:-$HOME/.claude/skills}/spill-scrub"

mkdir -p "$(dirname "$DEST")"
if [ -e "$DEST" ] && [ ! -L "$DEST" ]; then
  echo "refusing to overwrite non-symlink: $DEST" >&2
  exit 1
fi
ln -sfn "$REPO/skills/spill-scrub" "$DEST"
echo "installed: $DEST -> $REPO/skills/spill-scrub"
echo "restart Claude Code, then use /spill-scrub"
