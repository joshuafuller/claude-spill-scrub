# spillscrub

Find and scrub credentials that leaked into Claude Code's local logs.

Claude Code is very good at telling you that you just pasted a live token. It does
not clean up after you. The token stays in the session transcript on disk, and it
gets read back into context every time that session is resumed or searched. In DoD
terms that is a **spillage**: classified or sensitive data written to a place that
was not approved to hold it. This tool does the cleanup half.

---

## What this is

- A **local disk cleaner**. It rewrites files under `~/.claude` (and `~/.claude.json`)
  in place, replacing each secret with `[REDACTED rule=<rule> sha=<hash>]`.
- A **detector**. Two tiers: high-precision vendor prefixes (`sk-ant-`, `ghp_`,
  `AKIA`, `glpat-`, private key blocks, …) and contextual shapes
  (`DB_PASSWORD=…`, `sshpass -p …`, `Authorization: Bearer …`) behind an entropy
  floor and a placeholder denylist.
- A **rotation checklist generator**. The JSON manifest lists each *distinct*
  secret by SHA-256 prefix, how many times it appears, and in which files. One
  leaked key usually appears in dozens of transcripts, so the deduplicated list is
  what you actually work from.
- **Read-only by default.** `scan` never writes. Scrubbing needs `scrub --yes`.
- **Safe with JSONL.** Only the matched span in a line is replaced, then the line
  is re-parsed as JSON before it is accepted. A file with no findings comes out
  byte-for-byte identical.

## What this is NOT

- **Not remediation.** Deleting a key from a log file does not revoke the key.
  If a credential reached a transcript, treat it as compromised and **rotate it**.
  The manifest exists for exactly this. Scrubbing without rotating is theatre.
- **Not a prevention control.** It runs after the fact. It does not stop the next
  paste. Use a pre-commit secret scanner, a secrets manager, and `.env` files that
  Claude is not pointed at.
- **Not a guarantee of complete removal.** It is regex and entropy based. It will
  miss secrets with no recognisable shape — a bare passphrase in a sentence, an
  internal hostname, a name, a CUI paragraph. Assume false negatives.
- **Not a classified-spillage remediation procedure.** If actual classified or CUI
  material reached these logs, follow your organisation's incident process. Media
  sanitisation, custody, and reporting are not a Python script's job.
- **Not a reach beyond your disk.** It cannot touch anything already transmitted.
  Transcript content is sent to Anthropic as part of normal operation, and cloud
  sessions, telemetry, and any synced backup are outside its scope. Local cleanup
  reduces re-exposure from resumed sessions and from anyone with access to the box.
  It does not undo a disclosure.
- **Not a git history rewriter.** If a secret is committed, this tool will not help.
- **Not tested against every Claude Code version.** The on-disk layout is not a
  stable public interface. Re-check the target list after an upgrade.

---

## Install

Python 3.10+, standard library only. No dependencies.

```bash
git clone https://github.com/joshuafuller/claude-spill-scrub
cd claude-spill-scrub
./spillscrub.py scan
```

As a Claude Code skill (`/spill-scrub`):

```bash
./install.sh      # symlinks skill/ into ~/.claude/skills/spill-scrub
```

The skill wraps the same script with the workflow that matters: scan before
scrub, treat the two tiers differently, never print a secret back into the
transcript you are cleaning, and end on rotation rather than on a clean file.

## Use

```bash
# 1. Look. Nothing is written.
./spillscrub.py scan

# 2. Keep the rotation checklist (contains hashes and paths, never the secrets).
./spillscrub.py scan --manifest ~/spill-manifest.json

# 3. High-precision rules only, if tier 2 is noisy for you.
./spillscrub.py scan --tier 1

# 4. Clean. Irreversible.
./spillscrub.py scrub --yes

# 5. Clean, but keep the originals somewhere (the backups still hold the plaintext).
./spillscrub.py scrub --yes --backup-dir ~/spill-backup

# 6. Point it somewhere else entirely.
./spillscrub.py scan --only ./some/log/dir
```

**Quit Claude Code before scrubbing.** By default `scrub` skips any file modified
in the last 15 minutes (`--quiet-seconds`) and any session id in
`$CLAUDE_SESSION_ID`, because rewriting a transcript a running session holds open
either corrupts it or gets clobbered. `--include-live` overrides that. Do not.

Exit codes: `0` clean, `1` findings, `2` usage error.

## What it looks at

Under `~/.claude`: `projects/**/*.jsonl` (session transcripts), `projects/**/*.md`
(memory files), `shell-snapshots/` (exported env vars), `paste-cache/` (pasted
content — a very common way a token gets in), `file-history/` and `backups/`
(pre-edit copies, so a `.env` Claude once edited is here in plaintext),
`session-env/`, `sessions/`, `debug/`, `todos/`, `history.jsonl`, `daemon.log`.
Plus `~/.claude.json`, where MCP server `env` blocks keep API keys.

Add more with `--path`. Binary files and anything over 512 MB are skipped.

## After you scrub

1. **Rotate every secret in the manifest.** Not optional.
2. Check where else it went: shell history, git history, `~/.aws`, `~/.config`, CI
   variables, ticket comments.
3. Report it if your organisation requires that. A spillage you cleaned quietly is
   still a spillage.

## Speed

Whole-corpus scan, not line-by-line. Each rule carries a literal anchor
(`sk-ant-`, `AKIA`, `password`, …) checked with `str.find` before its regex runs,
so most files skip most rules. Work is fanned across one process per CPU, largest
file first. Two hot patterns were rewritten to lead with a literal alternation
instead of a character class, which alone took the URL-credential rule from 46 s
to 2.3 s over a 250 MB corpus.

Measured: **598 MB in 13.4 s on 32 cores (45 MB/s)**. The first working version
took over eight minutes on the same corpus. Use `-j` to change the worker count.

## Tests

```bash
python3 tests/test_spillscrub.py
```

24 tests. They plant fake-but-correctly-shaped credentials alongside benign
lookalikes and assert both directions: every planted secret is caught, no benign
line is flagged, JSONL still parses after a scrub, a clean file is byte-identical,
permissions and line endings survive, and the manifest never contains a secret.

## Adding a rule

Append a `R(name, tier, pattern, group=…, min_entropy=…)` to `TIER1` or `TIER2` in
`spillscrub.py`, add a fixture to `PLANTED` or `BENIGN` in the test file, and run
the suite. Tier 1 is for patterns you would auto-scrub without looking. Everything
else is tier 2.

## Licence

MIT.
