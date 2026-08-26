# claude-spill-scrub

**Find and scrub credentials that leaked into Claude Code's own local logs.**

Claude Code is very good at telling you that you just pasted a live token. It does
not clean up after you. The token stays in the session transcript on disk, and it
is read back into context every time that session is resumed or searched. One
careless paste becomes a live credential in plaintext, in a file you will never
think to open, in a directory that gets backed up, synced, and copied to your next
machine. This tool does the cleanup half.

> **Scrubbing is not remediation.** Deleting a key from a log does not revoke the
> key. Every run ends with a rotation checklist. Work that list, or you have
> cleaned a file and closed nothing.

## Quickstart

Python 3.10+, standard library only. No dependencies.

```bash
git clone https://github.com/joshuafuller/claude-spill-scrub
cd claude-spill-scrub

./spillscrub.py scan --context            # read-only. nothing is written.
./spillscrub.py scrub --yes               # irreversible. tier 1 only by default.
```

Then **quit Claude Code and run `scrub` again** — the files holding the most
secrets are the ones Claude Code has open. See [Run it twice](#run-it-twice).

Three names, one thing:

| | |
|---|---|
| repo / marketplace | `claude-spill-scrub` |
| command | `spillscrub.py` |
| skill / plugin | `spill-scrub` |

## What it finds

Real output, on a throwaway directory with planted keys:

```
======================================================================
  SPILLSCRUB SCAN REPORT
======================================================================
  files examined      : 2
  files with findings : 2
  distinct secrets    : 4  (tier1 certain: 4, tier2 review: 0)
  total occurrences   : 4

  DISTINCT SECRETS (rotate these - scrubbing does not revoke them)
  ------------------------------------------------------------------
  [CERTAIN] github-pat                   c156389f7087  x1 in 1 file(s)
  [CERTAIN] url-basic-auth               a574f6cc055a  x1 in 1 file(s)
  [CERTAIN] anthropic-api-key            4d2892d592d4  x1 in 1 file(s)
  [CERTAIN] huggingface-token            cee93ba7c938  x1 in 1 file(s)

  FILES
  ------------------------------------------------------------------
  FOUND           3  ~/.claude/projects/-home-user-myapp/a1b2c3d4.jsonl
               anthropic-api-key, github-pat, url-basic-auth
  FOUND           1  ~/.claude/history.jsonl
               huggingface-token

  Nothing was changed. To scrub:
    ./spillscrub.py scrub --yes

  ROTATE every secret listed above. Scrubbing a log does not revoke a key.
```

Secrets are identified by a SHA-256 prefix, never printed. The same key appears in
dozens of transcripts, so the deduplicated list is what you actually work from.

## What a scrub does to a line

Before:

```
here is the deploy key: ghp_aB3dE5gH7jK9lM1nO3pQ5rS7tU9vW1xY3zA5 use it for CI
git clone https://joshua:Sup3rS3cr3tPw@gitlab.example.com/team/repo.git
nothing sensitive on this line at all
```

After:

```
here is the deploy key: [REDACTED rule=github-pat sha=c156389f7087] use it for CI
git clone https://joshua:[REDACTED rule=url-basic-auth sha=a574f6cc055a]@gitlab.example.com/team/repo.git
nothing sensitive on this line at all
```

Only the matched span changes. The username survives, the URL still works as a
URL, the third line is untouched, and the record still parses as JSON. A file with
no findings comes out byte-for-byte identical.

## Run it twice

This is the part that surprises people.

`scrub` skips any file modified in the last 15 minutes (`--quiet-seconds`) and any
session id in `$CLAUDE_SESSION_ID`. Rewriting a file a running session holds open
either corrupts it or gets clobbered on the next write.

The catch: **the files with the most secrets are always the live ones.** On a real
first pass, 15 files were cleaned and 42 credentials were left behind — every one
in a file Claude Code was actively writing:

```
25  ~/.claude/history.jsonl                     <- prompt history, the worst offender
14  ~/.claude/projects/<current-session>.jsonl
10  ~/.claude/file-history/<current-session>/...
 2  ~/.claude.json
 2  x5  ~/.claude/backups/.claude.json.backup.*  <- one copy per config change
```

So:

1. `./spillscrub.py scrub --yes` — cleans everything dormant.
2. **Quit Claude Code.**
3. `./spillscrub.py scrub --yes` again — gets `history.jsonl`, `~/.claude.json`,
   and the config backups.
4. `./spillscrub.py scan --tier 1` — confirm it comes back clean.

Do not reach for `--include-live` to skip step 2. It exists for the test suite.

Note the `backups/.claude.json.backup.*` pile: Claude Code writes a new one on
every config change, so a single MCP API key can sit in ten files. Cleaning
`~/.claude.json` alone accomplishes very little.

## Install as a Claude Code skill

Two steps either way — `install` needs the marketplace registered first.

In a Claude Code session:

```
/plugin marketplace add joshuafuller/claude-spill-scrub
/plugin install spill-scrub@claude-spill-scrub
```

From a terminal:

```bash
claude plugin marketplace add joshuafuller/claude-spill-scrub
claude plugin install spill-scrub@claude-spill-scrub
```

Then `/reload-skills` picks it up live — no restart. Invoke it with
`/spill-scrub`.

While the repo is private, `marketplace add` needs credentials that can clone it —
`gh auth login` or an SSH key. Once it is public, neither is needed. A local
checkout works too, which is the fastest way to iterate on the skill itself:

```bash
claude plugin marketplace add ~/development/claude-spill-scrub
```

Without the plugin system at all: `./install.sh` symlinks `skills/spill-scrub`
into `~/.claude/skills/`.

The skill wraps the same script with the workflow that matters — scan before
scrub, treat the two tiers differently, never print a secret back into the
transcript you are cleaning, and end on rotation rather than on a clean file.

## Command reference

```bash
./spillscrub.py scan                       # read-only sweep of ~/.claude
./spillscrub.py scan --context             # + masked surrounding text, for triage
./spillscrub.py scan --manifest ~/rot.json # write the rotation checklist
./spillscrub.py scan --tier 1              # certain hits only
./spillscrub.py scrub --yes                # rewrite in place (tier 1)
./spillscrub.py scrub --yes --tier 0       # rewrite in place (both tiers)
./spillscrub.py scrub --yes --backup-dir ~/spill-backup
./spillscrub.py scan --only ./some/dir     # point it somewhere else entirely
```

| flag | effect |
|---|---|
| `--tier 0\|1\|2` | 1 = certain, 2 = contextual, 0 = both. `scan` defaults to both, `scrub` to 1. |
| `--context` | show the matched line with the value replaced by `<N chars>` |
| `--manifest PATH` | write the JSON rotation checklist (hashes and paths, never values) |
| `--backup-dir DIR` | copy originals before rewriting — **the copies still hold the plaintext** |
| `--quiet-seconds N` | how recent counts as live (default 900) |
| `--only PATH` | scan this path instead of the `~/.claude` target list; walks everything |
| `--root DIR` | treat DIR as the Claude config root (also redirects `.claude.json`) |
| `-j N` | worker processes (default: one per CPU, capped at 32) |

Exit codes: `0` clean, `1` findings, `2` usage error.

## The two tiers

**Tier 1 — certain.** Vendor-prefixed credentials: `sk-ant-`, `ghp_`,
`github_pat_`, `glpat-`, `AKIA`, `xoxb-`, `AIza`, `hf_`, `tskey-`, `eyJ…` JWTs,
`-----BEGIN … PRIVATE KEY-----` blocks, and passwords embedded in URLs. On a real
600 MB corpus, tier 1 found 75 credentials and every one was genuine. Treat each as
compromised.

**Tier 2 — review.** Shape-based: `DB_PASSWORD=…`, `sshpass -p …`,
`Authorization: Bearer …`, behind an entropy floor and a placeholder denylist that
drops `changeme`, `<your-key>`, `${VAR}` and friends.

Be honest about tier 2's noise. On that same corpus it produced ~1,140 candidates
and the large majority were Kubernetes manifests, YAML keys, and source code that
merely *look* like `secret: value`. That is why `scrub` defaults to tier 1 and
`--tier 0` must be asked for. Triage tier 2 with `--context` before widening.

## What it looks at

Under `~/.claude`: `projects/**/*.jsonl` (transcripts), `projects/**/*.md` (memory
files), `shell-snapshots/` (exported env vars), `paste-cache/` (pasted content — a
very common way a token gets in), `file-history/` and `backups/` (pre-edit copies,
so a `.env` Claude once edited is here in plaintext), `session-env/`, `sessions/`,
`debug/`, `todos/`, `history.jsonl`, `daemon.log`. Plus `~/.claude.json`, where MCP
server `env` blocks keep API keys.

Add more with `--path`. Binary files and anything over 512 MB are skipped.

## After you scrub

1. **Rotate every secret in the manifest.** The scrub removed the value from your
   disk; it revoked nothing.
2. Check where else it went: shell history, git history, `~/.aws`, `~/.config`, CI
   variables, ticket comments.
3. Report it if your organisation requires that. A spillage you cleaned quietly is
   still a spillage.
4. Delete the manifest and any `--backup-dir` afterwards. The manifest holds only
   hashes and paths, but the backups hold plaintext, which makes them a fresh
   spillage in a new location. Write both outside `~/.claude` so the next scan does
   not pick them up.

## What this is NOT

- **Not remediation.** See the callout at the top. Scrubbing without rotating is
  theatre.
- **Not a prevention control.** It runs after the fact and does not stop the next
  paste. Use a pre-commit secret scanner, a secrets manager, and `.env` files
  Claude is not pointed at.
- **Not complete.** Regex and entropy based. It misses secrets with no recognisable
  shape — a bare passphrase in a sentence, an internal hostname, a CUI paragraph.
  Assume false negatives.
- **Not a classified-spillage procedure.** If genuinely classified or CUI material
  reached these logs, follow your organisation's incident process. Media
  sanitisation, custody, and reporting are not a Python script's job.
- **Not a reach beyond your disk.** Transcript content is sent to Anthropic as part
  of normal operation; cloud sessions, telemetry, and synced backups are out of
  scope. Local cleanup reduces re-exposure from resumed sessions and from anyone
  with access to the box. It does not undo a disclosure.
- **Not a git history rewriter.** If a secret is committed, this will not help.
- **Not version-locked to Claude Code.** The on-disk layout is not a stable public
  interface. Re-check the target list after an upgrade.

## Evidence

Correctness here means "did not destroy 600 MB of transcripts". Three separate
runs, because the scopes differ and the numbers otherwise look contradictory.

**Run A — rehearsal on a full copy**, `--only` (walks every file in the tree, not
just the target list), both tiers, live files included:

```
1,781 MB, 19,964 files examined, 909 rewritten, 5,270 redactions
1,218 distinct secrets (75 tier 1, 1,143 tier 2)          18.4 s
3,215 files that parsed as JSON or JSONL before  ->  0 corrupted after
0 leftover .tmp files, 0 write errors
```

**Run B — first real scrub**, default target list, tier 1, live files skipped:

```
588 MB, 2,786 files examined, 15 rewritten, 77 redactions
18 distinct secrets, 12 files skipped as live              9.9 s
all rewritten .jsonl re-parsed clean, 0 write errors
```

**Run C — scan afterwards**, default target list, both tiers:

```
599 MB, 2,799 files examined, 349 with findings
425 distinct secrets (42 tier 1, 383 tier 2)              14.6 s
```

Run A is also what caught the worst bug in this tool: multi-line PEM blocks were
being *detected and reported* but never removed, because the rewrite worked line by
line. All 37 unit tests passed while that was broken — every fixture was
single-line. **If you change the scrub path, rehearse on a copy:**

```bash
mkdir -p /tmp/rehearse && cp -a ~/.claude /tmp/rehearse/.claude && cp ~/.claude.json /tmp/rehearse/
./spillscrub.py scrub --yes --tier 0 --include-live --only /tmp/rehearse
```

### Speed

Whole-corpus scan, not line-by-line. Each rule carries a literal anchor (`sk-ant-`,
`AKIA`, `password`, …) checked with `str.find` before its regex runs, so most files
skip most rules. Work fans across one process per CPU, largest file first. Two hot
patterns were rewritten to lead with a literal alternation instead of a character
class, which alone took the URL-credential rule from 46 s to 2.3 s over a 250 MB
corpus.

~600 MB scans in **13–15 s on 32 cores** for both tiers, 6–10 s for tier 1 alone.
The first working version took over eight minutes on the same corpus. `-j` sets the
worker count.

## Troubleshooting

**"It broke my transcript."** Check the line for a `[REDACTED rule=… sha=…]`
marker. No marker means this tool never touched it. Claude Code occasionally writes
a record containing literal newlines inside a JSON string, which splits it across
several lines and makes those lines unparseable as JSONL — a real corpus here had
three such lines out of 12,167 in one file. spillscrub leaves them exactly as it
found them: a line is only rewritten if it parsed as JSON before *and* still parses
after, and a pretty-printed JSON document is validated as a whole before it is
written.

**"I scrubbed and I want it back."** You cannot, unless you used `--backup-dir`.
Redaction markers are permanent and the original values are gone from those files.
This is the intended behaviour — but it is why `scan` is the default, `scrub`
requires `--yes`, and tier 2 requires `--tier 0` on top of that.

**"The scan found my own test fixtures."** Anything that reads a file full of
example credentials puts them in a transcript. They redact like anything else.

## Tests

```bash
python3 tests/test_spillscrub.py
```

37 tests, no pytest needed. They plant fake-but-correctly-shaped credentials
alongside benign lookalikes and assert both directions: every planted secret is
caught, no benign line is flagged, JSONL still parses after a scrub, a clean file
is byte-identical, the scrub is idempotent, multi-line PEM blocks are actually
removed, pretty-printed `~/.claude.json` survives, `--root` does not reach the real
config, `scrub` defaults to tier 1, permissions and line endings survive, and the
manifest never contains a secret.

## Adding a rule

Append `R(name, tier, pattern, group=…, min_entropy=…, anchors=…)` to `TIER1` or
`TIER2` in `spillscrub.py`, add a fixture to `PLANTED` or `BENIGN` in the test
file, and run the suite. Give every rule a literal `anchors=` tuple or it will scan
the whole corpus on its own. Tier 1 is for patterns you would auto-scrub without
looking; everything else is tier 2.

## Licence

MIT. See [LICENSE](LICENSE).
