#!/usr/bin/env bash
# Install spill-scrub as a Claude Code skill by symlinking this repo's skill/
# directory into ~/.claude/skills. Pulling the repo then updates the skill.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${CLAUDE_SKILLS_DIR:-$HOME/.claude/skills}/spill-scrub"

mkdir -p "$(dirname "$DEST")"
if [ -e "$DEST" ] && [ ! -L "$DEST" ]; then
  echo "refusing to overwrite non-symlink: $DEST" >&2
  exit 1
fi
ln -sfn "$REPO/skill" "$DEST"
echo "installed: $DEST -> $REPO/skill"
echo "restart Claude Code, then use /spill-scrub"
