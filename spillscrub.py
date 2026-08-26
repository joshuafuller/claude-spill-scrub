#!/usr/bin/env python3
"""spillscrub - find and scrub secrets that leaked into Claude Code local logs.

Default mode is SCAN (read-only). Scrubbing rewrites files in place and is
irreversible, so it must be requested explicitly with `scrub --yes`.

Scrubbing does NOT remediate. A leaked credential stays live until it is
rotated. The manifest this tool emits is the rotation checklist.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

VERSION = "1.0.0"

# --------------------------------------------------------------------------
# What we look at
# --------------------------------------------------------------------------

# Relative to the Claude config root (~/.claude) unless noted.
DEFAULT_TARGETS = [
    ("projects", "**/*.jsonl"),          # session transcripts (the bulk)
    ("projects", "**/*.md"),             # memory files live here
    ("shell-snapshots", "*.sh"),         # captured shell state / exported env
    ("paste-cache", "**/*"),             # pasted content
    ("file-history", "**/*"),            # pre-edit copies of edited files
    ("backups", "**/*"),
    ("session-env", "**/*"),
    ("sessions", "**/*"),
    ("debug", "**/*"),
    ("todos", "**/*"),
    (".", "history.jsonl"),
    (".", "daemon.log"),
]

SKIP_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".zip", ".gz", ".tar",
    ".bz2", ".xz", ".7z", ".mp4", ".mov", ".mp3", ".wav", ".ico", ".woff",
    ".woff2", ".ttf", ".otf", ".so", ".dylib", ".dll", ".class", ".jar",
    ".pyc", ".bin", ".wasm",
}

MAX_FILE_BYTES = 512 * 1024 * 1024

# --------------------------------------------------------------------------
# Detection rules
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    name: str
    tier: int          # 1 = high precision (auto-scrub), 2 = contextual (review)
    pattern: re.Pattern
    group: int = 0     # which capture group is the actual secret
    min_entropy: float = 0.0


def R(name, tier, pattern, group=0, min_entropy=0.0, flags=0):
    return Rule(name, tier, re.compile(pattern, flags), group, min_entropy)


# Tier 1: unambiguous vendor-prefixed credentials. Near-zero false positives.
TIER1 = [
    R("anthropic-api-key", 1, r"sk-ant-[A-Za-z0-9_\-]{20,120}"),
    R("openai-api-key", 1, r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,120}"),
    R("github-pat", 1, r"gh[pousr]_[A-Za-z0-9]{36,255}"),
    R("github-fine-grained-pat", 1, r"github_pat_[A-Za-z0-9_]{60,255}"),
    R("gitlab-pat", 1, r"glpat-[A-Za-z0-9_\-]{20,80}"),
    R("gitlab-other-token", 1, r"gl(?:cbt|ptt|dt|soat|feed|rt|agent)-[A-Za-z0-9_\-]{20,80}"),
    R("aws-access-key-id", 1, r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"),
    R("slack-token", 1, r"xox[abposr]-[A-Za-z0-9\-]{10,250}"),
    R("slack-webhook", 1, r"https://hooks\.slack\.com/services/[A-Za-z0-9/+]{40,}"),
    R("google-api-key", 1, r"\bAIza[A-Za-z0-9_\-]{35}\b"),
    R("google-oauth-token", 1, r"\bya29\.[A-Za-z0-9_\-]{20,}"),
    R("huggingface-token", 1, r"\bhf_[A-Za-z0-9]{30,}\b"),
    R("tailscale-key", 1, r"\btskey-(?:auth|api|client)-[A-Za-z0-9\-]{10,}"),
    R("netbird-setup-key", 1, r"\bnb[a-z]*_[A-Za-z0-9]{30,}\b"),
    R("stripe-key", 1, r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{20,}\b"),
    R("npm-token", 1, r"\bnpm_[A-Za-z0-9]{36}\b"),
    R("pypi-token", 1, r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}"),
    R("sendgrid-key", 1, r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    R("twilio-key", 1, r"\bSK[0-9a-fA-F]{32}\b"),
    R("digitalocean-token", 1, r"\bdop_v1_[a-f0-9]{64}\b"),
    R("cloudflare-token", 1, r"\bv1\.0-[A-Za-z0-9\-]{20,}-[A-Za-z0-9\-]{40,}"),
    R("jwt", 1, r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    R("private-key-block", 1,
      r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
      r"[\s\S]{0,20000}?-----END (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
    # user:pass embedded in a URL -> scrub only the password span
    R("url-basic-auth", 1,
      r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@\"']{1,64}:([^\s@\"'\\]{3,128})@", group=1),
]

# Tier 2: shape/context based. Needs an entropy floor and a placeholder denylist.
TIER2 = [
    R("env-assigned-secret", 2,
      r"(?i)\b(?:[A-Z0-9_]*(?:PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|APIKEY|API_KEY|"
      r"ACCESS_KEY|PRIVATE_KEY|CLIENT_SECRET|AUTH_KEY|CREDENTIAL)[A-Z0-9_]*)"
      r"\s*[:=]\s*[\"']?([^\s\"'{}$,;\\]{8,200})[\"']?", group=1, min_entropy=2.6),
    R("cli-password-flag", 2,
      r"(?i)--?(?:password|passwd|pass|token|api-key|apikey|secret)[=\s]+[\"']?"
      r"([^\s\"'\\]{6,200})[\"']?", group=1, min_entropy=2.3),
    R("sshpass", 2, r"sshpass\s+-p\s*[\"']?([^\s\"'\\]{3,200})[\"']?", group=1, min_entropy=1.5),
    R("authorization-header", 2,
      r"(?i)authorization[\"']?\s*[:=]\s*[\"']?(?:Bearer|Basic|Token)\s+([A-Za-z0-9_\-\.=+/]{16,500})",
      group=1, min_entropy=3.0),
    R("aws-secret-access-key", 2,
      r"(?i)aws_?secret_?access_?key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?",
      group=1, min_entropy=3.5),
    R("mysql-pg-cli-password", 2,
      r"(?i)\b(?:mysql|psql|mongo|redis-cli)\b[^\n]{0,120}?-p\s*([^\s\"'\\]{6,120})",
      group=1, min_entropy=2.3),
]

ALL_RULES = TIER1 + TIER2

# Values that look like secrets but are not.
PLACEHOLDER_WORDS = {
    "your", "yours", "my", "our", "the", "a", "an", "some", "insert", "enter",
    "put", "add", "set", "replace", "with", "own", "real", "actual", "valid",
    "generate", "generated", "goes", "here", "there", "this", "that",
    "api", "key", "keys", "token", "tokens", "secret", "secrets", "password",
    "passwd", "pass", "passphrase", "credential", "credentials", "auth", "id",
    "client", "access", "private", "public", "value", "string", "name", "user",
    "username", "login", "account",
    "changeme", "change", "me", "redacted", "removed", "scrubbed", "masked",
    "placeholder", "example", "sample", "dummy", "fake", "mock", "test",
    "testing", "todo", "tbd", "fixme", "xxx", "yyy", "zzz", "abc", "abcd",
    "none", "null", "nil", "undefined", "unset", "empty", "blank", "n/a", "na",
    "foo", "bar", "baz", "qux", "hunter2", "letmein", "admin", "root",
    "default", "optional", "required", "omitted", "hidden", "notset",
}

# Reject anything already redacted (by us or by anyone else).
REDACTED_SPAN_RE = re.compile(r"\[REDACTED[^\]]{0,300}\]")
REDACT_MARKERS = ("[REDACTED", "***", "<redacted>", "<REDACTED>")


def _tokens(value: str) -> list[str]:
    return [t for t in re.split(r"[^A-Za-z0-9]+", value.lower()) if t]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = defaultdict(int)
    for ch in s:
        counts[ch] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_placeholder(value: str) -> bool:
    """True if the value is a template, an example, or an already-masked value."""
    v = value.strip()
    if len(v) < 6:
        return True
    if any(m in v for m in REDACT_MARKERS):
        return True
    if v[0] in "$%<[{(":                        # ${VAR}, $VAR, %VAR%, <token>, {{key}}
        return True
    if re.fullmatch(r"[\W_]+", v):               # punctuation only
        return True
    if len(set(v)) <= 2:                        # xxxxxxxx, aaaaaaaa, ********
        return True
    if re.fullmatch(r"(?:true|false|null|none|yes|no|on|off|\d+(?:\.\d+)?)", v, re.I):
        return True
    # Every word is drawn from the placeholder vocabulary -> it is a template.
    toks = _tokens(v)
    if toks and all(t in PLACEHOLDER_WORDS or t.isdigit() or len(t) <= 2 for t in toks):
        return True
    return False


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------


@dataclass
class Match:
    rule: str
    tier: int
    start: int
    end: int
    secret: str

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.secret.encode("utf-8", "surrogateescape")).hexdigest()[:12]


def find_matches(text: str, rules) -> list[Match]:
    # Spans that are already redacted are off limits, so scrubbing is idempotent.
    masked = [mm.span() for mm in REDACTED_SPAN_RE.finditer(text)]

    def in_masked(a: int, b: int) -> bool:
        return any(a < e and b > s for s, e in masked)

    out: list[Match] = []
    for rule in rules:
        for m in rule.pattern.finditer(text):
            try:
                secret = m.group(rule.group)
            except IndexError:
                continue
            if secret is None:
                continue
            start, end = m.span(rule.group)
            if in_masked(start, end):
                continue
            if rule.tier == 2:
                if is_placeholder(secret):
                    continue
                if shannon_entropy(secret) < rule.min_entropy:
                    continue
            else:
                if any(mk in secret for mk in REDACT_MARKERS):
                    continue
            out.append(Match(rule.name, rule.tier, start, end, secret))

    # Resolve overlaps: prefer tier 1, then the longer span.
    out.sort(key=lambda m: (m.start, m.tier, -(m.end - m.start)))
    kept: list[Match] = []
    last_end = -1
    for m in out:
        if m.start < last_end:
            continue
        kept.append(m)
        last_end = m.end
    return kept


def placeholder_for(m: Match) -> str:
    return f"[REDACTED rule={m.rule} sha={m.digest}]"


def redact_text(text: str, matches: list[Match]) -> str:
    """Replace only the matched spans. Everything else is byte-for-byte untouched."""
    if not matches:
        return text
    parts = []
    cursor = 0
    for m in sorted(matches, key=lambda x: x.start):
        parts.append(text[cursor:m.start])
        parts.append(placeholder_for(m))
        cursor = m.end
    parts.append(text[cursor:])
    return "".join(parts)


# --------------------------------------------------------------------------
# File walking
# --------------------------------------------------------------------------


def iter_target_files(root: Path, home: Path, extra_paths: list[Path]) -> list[Path]:
    seen: set[Path] = set()
    files: list[Path] = []

    def add(p: Path):
        try:
            rp = p.resolve()
        except OSError:
            return
        if rp in seen or not p.is_file() or p.is_symlink():
            return
        if p.suffix.lower() in SKIP_SUFFIXES:
            return
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                return
        except OSError:
            return
        seen.add(rp)
        files.append(p)

    for sub, pattern in DEFAULT_TARGETS:
        base = root if sub == "." else root / sub
        if not base.exists():
            continue
        for p in base.glob(pattern):
            add(p)

    top = home / ".claude.json"
    if top.is_file():
        add(top)

    for p in extra_paths:
        if p.is_dir():
            for q in p.rglob("*"):
                add(q)
        else:
            add(p)

    return sorted(files)


def read_text(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None                       # binary
    return data.decode("utf-8", "surrogateescape")


def is_live(path: Path, quiet_seconds: int, skip_ids: set[str]) -> bool:
    if any(sid and sid in path.name for sid in skip_ids):
        return True
    try:
        return (time.time() - path.stat().st_mtime) < quiet_seconds
    except OSError:
        return True


# --------------------------------------------------------------------------
# Scan / scrub
# --------------------------------------------------------------------------


@dataclass
class FileResult:
    path: Path
    matches: list[Match] = field(default_factory=list)
    skipped_reason: str | None = None
    scrubbed: bool = False
    error: str | None = None


def scan_file(path: Path, rules) -> FileResult:
    res = FileResult(path=path)
    text = read_text(path)
    if text is None:
        res.skipped_reason = "binary-or-unreadable"
        return res
    res.matches = find_matches(text, rules)
    return res


def scrub_file(path: Path, rules, backup_dir: Path | None) -> FileResult:
    """Rewrite in place. Lines with no match are preserved byte-for-byte.

    For .jsonl the rewritten line must still parse as JSON, or the line is
    left untouched and reported as an error.
    """
    res = FileResult(path=path)
    original = read_text(path)
    if original is None:
        res.skipped_reason = "binary-or-unreadable"
        return res

    is_jsonl = path.suffix == ".jsonl"
    out_lines = []
    all_matches: list[Match] = []
    bad_lines = 0

    for line in original.splitlines(keepends=True):
        matches = find_matches(line, rules)
        if not matches:
            out_lines.append(line)
            continue
        new_line = redact_text(line, matches)
        if is_jsonl:
            stripped = new_line.strip()
            if stripped:
                try:
                    json.loads(stripped)
                except (ValueError, RecursionError):
                    out_lines.append(line)       # refuse to corrupt
                    bad_lines += 1
                    continue
        out_lines.append(new_line)
        all_matches.extend(matches)

    res.matches = all_matches
    if bad_lines:
        res.error = f"{bad_lines} line(s) left untouched: redaction would break JSON"

    new_text = "".join(out_lines)
    if new_text == original:
        return res

    if backup_dir is not None:
        dest = backup_dir / path.resolve().relative_to("/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(original.encode("utf-8", "surrogateescape"))

    tmp = path.with_name(path.name + ".spillscrub.tmp")
    try:
        st = path.stat()
        tmp.write_bytes(new_text.encode("utf-8", "surrogateescape"))
        os.chmod(tmp, st.st_mode & 0o7777)
        os.replace(tmp, path)
        res.scrubbed = True
    except OSError as e:
        res.error = f"write failed: {e}"
        tmp.unlink(missing_ok=True)
    return res


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def build_manifest(results: list[FileResult]) -> dict:
    by_secret: dict[str, dict] = {}
    for r in results:
        for m in r.matches:
            entry = by_secret.setdefault(m.digest, {
                "sha256_prefix": m.digest,
                "rule": m.rule,
                "tier": m.tier,
                "length": len(m.secret),
                "occurrences": 0,
                "files": set(),
            })
            entry["occurrences"] += 1
            entry["files"].add(str(r.path))
    secrets = []
    for e in by_secret.values():
        e = dict(e)
        e["files"] = sorted(e["files"])
        e["file_count"] = len(e["files"])
        secrets.append(e)
    secrets.sort(key=lambda e: (e["tier"], -e["occurrences"]))
    return {
        "tool": "spillscrub",
        "version": VERSION,
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "distinct_secrets": len(secrets),
        "total_occurrences": sum(e["occurrences"] for e in secrets),
        "secrets": secrets,
    }


def print_report(results: list[FileResult], manifest: dict, mode: str, skipped: list[tuple[Path, str]]):
    hits = [r for r in results if r.matches]
    t1 = sum(1 for e in manifest["secrets"] if e["tier"] == 1)
    t2 = sum(1 for e in manifest["secrets"] if e["tier"] == 2)

    print()
    print("=" * 70)
    print(f"  SPILLSCRUB {mode.upper()} REPORT")
    print("=" * 70)
    print(f"  files examined      : {len(results)}")
    print(f"  files with findings : {len(hits)}")
    print(f"  distinct secrets    : {manifest['distinct_secrets']}  "
          f"(tier1 certain: {t1}, tier2 review: {t2})")
    print(f"  total occurrences   : {manifest['total_occurrences']}")
    if mode == "scrub":
        print(f"  files rewritten     : {sum(1 for r in results if r.scrubbed)}")
    if skipped:
        print(f"  files skipped (live): {len(skipped)}")
    print()

    if manifest["secrets"]:
        print("  DISTINCT SECRETS (rotate these - scrubbing does not revoke them)")
        print("  " + "-" * 66)
        for e in manifest["secrets"]:
            tag = "CERTAIN" if e["tier"] == 1 else "REVIEW "
            print(f"  [{tag}] {e['rule']:<28} {e['sha256_prefix']}  "
                  f"x{e['occurrences']} in {e['file_count']} file(s)")
        print()

    if hits:
        print("  FILES")
        print("  " + "-" * 66)
        for r in sorted(hits, key=lambda r: -len(r.matches))[:60]:
            rules = sorted({m.rule for m in r.matches})
            flag = "scrubbed" if r.scrubbed else ("FOUND" if mode == "scan" else "not-written")
            print(f"  {flag:<12} {len(r.matches):>4}  {r.path}")
            print(f"               {', '.join(rules)}")
            if r.error:
                print(f"               !! {r.error}")
        if len(hits) > 60:
            print(f"  ... and {len(hits) - 60} more file(s); see the JSON manifest")
        print()

    errs = [r for r in results if r.error]
    if errs:
        print(f"  ERRORS: {len(errs)}")
        for r in errs[:20]:
            print(f"    {r.path}: {r.error}")
        print()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="spillscrub",
        description="Find and scrub secrets that leaked into Claude Code local logs.",
    )
    p.add_argument("mode", nargs="?", default="scan", choices=["scan", "scrub"],
                   help="scan = read-only (default); scrub = rewrite files in place")
    p.add_argument("--root", default=str(Path.home() / ".claude"),
                   help="Claude config root (default: ~/.claude)")
    p.add_argument("--path", action="append", default=[],
                   help="extra file or directory to include (repeatable)")
    p.add_argument("--only", action="append", default=[],
                   help="restrict to these targets; skips the default ~/.claude sweep")
    p.add_argument("--tier", type=int, choices=[1, 2], default=None,
                   help="1 = high-precision rules only; 2 = tier2 only; default both")
    p.add_argument("--yes", action="store_true",
                   help="required for scrub: confirm irreversible in-place rewrite")
    p.add_argument("--backup-dir", default=None,
                   help="copy originals here before rewriting (WARNING: backups still "
                        "contain the plaintext secrets)")
    p.add_argument("--quiet-seconds", type=int, default=900,
                   help="skip files modified more recently than this (default 900)")
    p.add_argument("--skip-session", action="append", default=[],
                   help="session id substring to skip (repeatable)")
    p.add_argument("--manifest", default=None, help="write the JSON manifest here")
    p.add_argument("--include-live", action="store_true",
                   help="do not skip recently-modified files (unsafe while Claude runs)")
    p.add_argument("--version", action="version", version=VERSION)
    args = p.parse_args(argv)

    root = Path(args.root).expanduser()
    home = Path.home()

    if args.tier == 1:
        rules = TIER1
    elif args.tier == 2:
        rules = TIER2
    else:
        rules = ALL_RULES

    if args.only:
        files = []
        for t in args.only:
            tp = Path(t).expanduser()
            if tp.is_dir():
                files.extend(q for q in tp.rglob("*")
                             if q.is_file() and q.suffix.lower() not in SKIP_SUFFIXES)
            elif tp.is_file():
                files.append(tp)
        files = sorted(set(files))
    else:
        if not root.is_dir():
            print(f"error: root not found: {root}", file=sys.stderr)
            return 2
        files = iter_target_files(root, home, [Path(x).expanduser() for x in args.path])

    skip_ids = set(args.skip_session)
    env_sid = os.environ.get("CLAUDE_SESSION_ID")
    if env_sid:
        skip_ids.add(env_sid)

    if args.mode == "scrub" and not args.yes:
        print("refusing to scrub without --yes (this rewrites files in place, "
              "and the originals are gone unless you pass --backup-dir)", file=sys.stderr)
        return 2

    backup_dir = Path(args.backup_dir).expanduser() if args.backup_dir else None
    if backup_dir:
        backup_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(backup_dir, 0o700)

    results: list[FileResult] = []
    skipped: list[tuple[Path, str]] = []

    for i, f in enumerate(files, 1):
        if sys.stderr.isatty() and i % 25 == 0:
            print(f"\r  {i}/{len(files)}", end="", file=sys.stderr)
        if args.mode == "scrub" and not args.include_live and is_live(f, args.quiet_seconds, skip_ids):
            skipped.append((f, "live-or-recent"))
            continue
        if args.mode == "scan":
            results.append(scan_file(f, rules))
        else:
            results.append(scrub_file(f, rules, backup_dir))
    if sys.stderr.isatty():
        print("\r" + " " * 30 + "\r", end="", file=sys.stderr)

    manifest = build_manifest(results)
    manifest["mode"] = args.mode
    manifest["files_examined"] = len(results)
    manifest["files_skipped_live"] = [str(p) for p, _ in skipped]

    print_report(results, manifest, args.mode, skipped)

    if args.manifest:
        mp = Path(args.manifest).expanduser()
        mp.write_text(json.dumps(manifest, indent=2))
        os.chmod(mp, 0o600)
        print(f"  manifest written: {mp}")

    if args.mode == "scan":
        print("  Nothing was changed. To scrub:")
        print("    ./spillscrub.py scrub --yes")
        print()
    if manifest["secrets"]:
        print("  ROTATE every secret listed above. Scrubbing a log does not revoke a key.")
        print()

    return 1 if manifest["secrets"] else 0


if __name__ == "__main__":
    sys.exit(main())
