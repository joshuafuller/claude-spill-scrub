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

As a Claude Code plugin, from the marketplace:

```
/plugin marketplace add joshuafuller/claude-spill-scrub
/plugin install spill-scrub@claude-spill-scrub
```

While the repo is private, `marketplace add` needs git credentials for it — a
`gh auth login` or an SSH key that can clone it. For a public fork, neither is
needed. You can also point it at a local checkout:

```
/plugin marketplace add ~/development/claude-spill-scrub
```

Or install the skill by hand, without the plugin system:

```bash
./install.sh      # symlinks skills/spill-scrub into ~/.claude/skills/
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

# 4. Clean. Irreversible. Defaults to tier 1; add --tier 0 to include tier 2.
./spillscrub.py scrub --yes

# 5. Clean, but keep the originals somewhere (the backups still hold the plaintext).
./spillscrub.py scrub --yes --backup-dir ~/spill-backup

# 6. Point it somewhere else entirely.
./spillscrub.py scan --only ./some/log/dir
```

Exit codes: `0` clean, `1` findings, `2` usage error.

## You have to run it twice

This is the part that surprises people, so it gets its own heading.

`scrub` skips any file modified in the last 15 minutes (`--quiet-seconds`) and any
session id in `$CLAUDE_SESSION_ID`. Rewriting a file a running session holds open
either corrupts it or gets clobbered on the next write.

The catch: **the files with the most secrets in them are always the live ones.**
On a real run against a 600 MB corpus, the first pass cleaned 15 files and left 42
credentials behind — every one of them in a file Claude Code was actively writing:

```
25  ~/.claude/history.jsonl                     <- prompt history, the worst offender
14  ~/.claude/projects/<current-session>.jsonl
10  ~/.claude/file-history/<current-session>/...
 2  ~/.claude.json
 2  x5  ~/.claude/backups/.claude.json.backup.*  <- one copy per config change
```

So the workflow is:

1. `./spillscrub.py scrub --yes` — cleans everything dormant.
2. **Quit Claude Code.**
3. `./spillscrub.py scrub --yes` again — this pass gets `history.jsonl`,
   `~/.claude.json`, and the config backups.
4. `./spillscrub.py scan --tier 1` — confirm it comes back clean.

Do not reach for `--include-live` to skip step 2. It exists for the test suite.

Note the `backups/.claude.json.backup.*` pile. Claude Code writes a new one on
every config change, so a single MCP API key can sit in ten files. Cleaning
`~/.claude.json` alone accomplishes very little.

## What it looks at

Under `~/.claude`: `projects/**/*.jsonl` (session transcripts), `projects/**/*.md`
(memory files), `shell-snapshots/` (exported env vars), `paste-cache/` (pasted
content — a very common way a token gets in), `file-history/` and `backups/`
(pre-edit copies, so a `.env` Claude once edited is here in plaintext),
`session-env/`, `sessions/`, `debug/`, `todos/`, `history.jsonl`, `daemon.log`.
Plus `~/.claude.json`, where MCP server `env` blocks keep API keys.

Add more with `--path`. Binary files and anything over 512 MB are skipped.

## After you scrub

1. **Rotate every secret in the manifest.** Not optional. The scrub removed the
   value from your disk; it revoked nothing.
2. Check where else it went: shell history, git history, `~/.aws`, `~/.config`, CI
   variables, ticket comments.
3. Report it if your organisation requires that. A spillage you cleaned quietly is
   still a spillage.
4. Delete the manifest and any `--backup-dir` once you have rotated. The manifest
   holds only hashes and paths, but the backups hold the plaintext, which makes
   them a fresh spillage in a new location. Write both outside `~/.claude` so the
   next scan does not pick them up.

## Verification

Correctness here means "did not destroy 600 MB of transcripts", so the scrub was
rehearsed against a full copy of a real `~/.claude` before it was trusted:

```
1781 MB, 19,964 files, 909 rewritten, 5,270 redactions
3,215 files that parsed as JSON or JSONL before  ->  0 corrupted after
0 leftover .tmp files, 0 write errors
residual tier-1 secrets after the scrub: 0
```

The first real run against a live `~/.claude`, after the rehearsal:

```
588 MB, 2,786 files examined, 15 rewritten, 77 redactions, 18 distinct secrets
12 files skipped as live
all rewritten .jsonl re-parsed clean, 0 write errors, 0 leftover .tmp files
```

That rehearsal is also what caught the worst bug in this tool: multi-line PEM
blocks were being *detected and reported* but never actually removed, because the
rewrite worked line by line. The unit tests could not see it — they all used
single-line fixtures. If you change the scrub path, rehearse on a copy:

```bash
cp -a ~/.claude /tmp/rehearse/.claude && cp ~/.claude.json /tmp/rehearse/
./spillscrub.py scrub --yes --tier 0 --include-live --only /tmp/rehearse
```

## Some of your .jsonl files were already invalid

Worth knowing before you blame this tool. Claude Code occasionally writes a
transcript record containing literal newlines inside a JSON string, which splits
one record across several lines and makes those lines unparseable as JSONL. A real
corpus here had three such lines out of 12,167 in one file.

spillscrub leaves them exactly as it found them — the guard only rewrites a line
if it parsed as JSON before *and* still parses after. If you validate your
transcripts after a scrub and find a broken line, check it for a
`[REDACTED rule=… sha=…]` marker first. No marker means the tool never touched it.

## On tier 2

Be honest about the noise. On a real 600 MB corpus, tier 1 found 75 credentials
and every one was genuine. Tier 2 found ~1,140 candidates, and the large majority
were Kubernetes manifests, YAML keys, and source code that merely *look* like
`secret: value`. That is why `scrub` defaults to tier 1 and you must ask for
`--tier 0` explicitly. Use `--context` to triage tier 2 by hand; the context
string shows the surrounding line with the value replaced by its length.

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

37 tests. They plant fake-but-correctly-shaped credentials alongside benign
lookalikes and assert both directions: every planted secret is caught, no benign
line is flagged, JSONL still parses after a scrub, a clean file is byte-identical,
the scrub is idempotent, multi-line PEM blocks are actually removed, pretty-printed
~/.claude.json survives, the masked context never leaks the value,
permissions and line endings survive, and the manifest never contains a secret.

## Adding a rule

Append a `R(name, tier, pattern, group=…, min_entropy=…)` to `TIER1` or `TIER2` in
`spillscrub.py`, add a fixture to `PLANTED` or `BENIGN` in the test file, and run
the suite. Tier 1 is for patterns you would auto-scrub without looking. Everything
else is tier 2.

## Licence

MIT.
