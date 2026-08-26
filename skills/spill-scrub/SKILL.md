---
name: spill-scrub
description: Find and scrub credentials that leaked into Claude Code's own local logs (transcripts, paste-cache, shell snapshots, ~/.claude.json). Use when the user mentions a spillage, a leaked or pasted secret, "clean the logs", "scrub my transcripts", "I pasted a key", "did a token get logged", or after any incident where a credential reached a chat window. Also use before sharing, syncing, or archiving a machine's ~/.claude directory.
---

# spill-scrub

Claude Code will tell you that you just pasted a live token. It does not clean up
after itself. The token stays in the session transcript on disk and is read back
into context every time that session is resumed. This skill does the cleanup.

## The rule that governs everything here

**Scrubbing is not remediation.** Deleting a key from a log does not revoke the
key. Every run ends by telling the user to rotate. Never let a user finish this
workflow believing the incident is closed because the files are clean.

## Workflow

### 1. Scan first. Always.

```bash
python3 <skill_dir>/spillscrub.py scan --context --manifest ~/spill-manifest.json
```

Scan is read-only. It takes about 15 seconds over a 600 MB corpus on a many-core
box. Never jump straight to `scrub`.

### 2. Read the two tiers differently

- **CERTAIN (tier 1)** — vendor-prefixed credentials (`sk-ant-`, `ghp_`, `AKIA`,
  `glpat-`, private key blocks, passwords inside URLs). Treat every one as a real
  leaked credential. Do not ask the user to confirm these one by one.
- **REVIEW (tier 2)** — shape-based hits (`DB_PASSWORD=…`, `sshpass -p …`,
  `Authorization: Bearer …`). These carry false positives. Use `--context` to
  show the masked surrounding text and triage them **with** the user. The context
  string never contains the value.

Report counts and rules. **Never print a secret back to the user** — it would land
straight back in the transcript you are trying to clean. The manifest is keyed by
SHA-256 prefix for the same reason.

### 3. Tell them to quit Claude Code before scrubbing

Rewriting a transcript that a running session holds open corrupts it or gets
clobbered. The tool defaults to skipping anything modified in the last 15 minutes,
which means **the current session's own transcript will not be cleaned**. Say so
explicitly, and tell the user to re-run after quitting.

### 4. Get explicit go-ahead, then scrub

Scrubbing is irreversible and touches hundreds of files. Confirm before running it,
even if the user asked for a cleanup up front — confirm *what* will be rewritten.

```bash
python3 <skill_dir>/spillscrub.py scrub --yes             # tier 1 only (default)
python3 <skill_dir>/spillscrub.py scrub --yes --tier 0    # include tier 2
```

`scrub` deliberately defaults to tier 1. Only reach for `--tier 0` after the user
has triaged the review hits, and expect most of them to be false positives —
Kubernetes manifests and source code full of `secret: value` lines. Offer `--backup-dir` only with the warning
that the backups still contain the plaintext, so they are a new spillage unless
deleted after rotation.

### 5. Close the loop

Hand back the deduplicated rotation list and say plainly:

1. Rotate every CERTAIN secret. The scrub did not revoke anything.
2. Check where else the value went — shell history, git history, `~/.aws`,
   `~/.config`, CI variables, ticket comments.
3. Report it if the organisation requires that.

## Where the leaks actually are

In practice the heaviest concentrations are, in order:

1. `~/.claude/history.jsonl` — prompt history. Everything ever typed, in one file.
2. `~/.claude.json` and `~/.claude/backups/.claude.json.backup.*` — MCP server
   `env` blocks hold API keys in plaintext, and every backup holds an old copy.
3. `~/.claude/projects/**/*.jsonl` — session transcripts, the bulk by volume.
4. `~/.claude/paste-cache/` — pasted content, the most common entry route.
5. `~/.claude/file-history/` — pre-edit copies, so any `.env` Claude ever edited
   is here in full.
6. `~/.claude/shell-snapshots/` — exported environment variables.

Check the backups. Users clean `.claude.json` and leave ten timestamped copies of
it next door.

## Do not

- Do not print a matched secret, in chat or in a file. Use the hash and context.
- Do not run `scrub` without a `scan` the user has seen.
- Do not use `--include-live`. It exists for tests.
- Do not describe the job as done when the files are clean. It is done when the
  credentials are rotated.
- Do not treat a clean scan as proof there is nothing there. Detection is regex
  and entropy based; a bare passphrase in a sentence has no shape to match.

## Reference

`README.md` next to this file covers the flags, the target list, the rule tiers,
and how to add a rule. `python3 spillscrub.py --help` lists everything.
