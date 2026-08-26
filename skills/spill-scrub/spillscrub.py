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

VERSION = "1.2.1"

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
    anchors: tuple = ()   # literal substrings; at least one must be present
    ci_anchors: bool = False  # match anchors case-insensitively

    def possible_in(self, text: str, lowered: str | None) -> bool:
        """Cheap literal pre-check. Running a regex over 600 MB of transcript is
        ~2 s per rule; a str.find over the same text is ~30 ms. Almost every rule
        has an unambiguous literal prefix, so most files skip most rules."""
        if not self.anchors:
            return True
        hay = (lowered if lowered is not None else text.lower()) if self.ci_anchors else text
        return any(a in hay for a in self.anchors)


def R(name, tier, pattern, group=0, min_entropy=0.0, flags=0,
      anchors=(), ci_anchors=False):
    return Rule(name, tier, re.compile(pattern, flags), group, min_entropy,
                tuple(anchors), ci_anchors)


# Tier 1: unambiguous vendor-prefixed credentials. Near-zero false positives.
TIER1 = [
    R("anthropic-api-key", 1, r"sk-ant-[A-Za-z0-9_\-]{20,120}",
      anchors=("sk-ant-",)),
    R("openai-api-key", 1, r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,120}",
      anchors=("sk-",)),
    R("github-pat", 1, r"gh[pousr]_[A-Za-z0-9]{36,255}",
      anchors=("ghp_", "gho_", "ghu_", "ghs_", "ghr_")),
    R("github-fine-grained-pat", 1, r"github_pat_[A-Za-z0-9_]{60,255}",
      anchors=("github_pat_",)),
    R("gitlab-pat", 1, r"glpat-[A-Za-z0-9_\-]{20,80}",
      anchors=("glpat-",)),
    R("gitlab-other-token", 1, r"gl(?:cbt|ptt|dt|soat|feed|rt|agent)-[A-Za-z0-9_\-]{20,80}",
      anchors=("glcbt-", "glptt-", "gldt-", "glsoat-", "glfeed-", "glrt-", "glagent-")),
    R("aws-access-key-id", 1, r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b",
      anchors=("AKIA", "ASIA", "ABIA", "ACCA")),
    R("slack-token", 1, r"xox[abposr]-[A-Za-z0-9\-]{10,250}",
      anchors=("xoxa-", "xoxb-", "xoxp-", "xoxo-", "xoxs-", "xoxr-")),
    R("slack-webhook", 1, r"https://hooks\.slack\.com/services/[A-Za-z0-9/+]{40,}",
      anchors=("hooks.slack.com",)),
    R("google-api-key", 1, r"\bAIza[A-Za-z0-9_\-]{35}\b", anchors=("AIza",)),
    R("google-oauth-token", 1, r"\bya29\.[A-Za-z0-9_\-]{20,}", anchors=("ya29.",)),
    R("huggingface-token", 1, r"\bhf_[A-Za-z0-9]{30,}\b", anchors=("hf_",)),
    R("tailscale-key", 1, r"\btskey-(?:auth|api|client)-[A-Za-z0-9\-]{10,}",
      anchors=("tskey-",)),
    R("stripe-key", 1, r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{20,}\b",
      anchors=("sk_live_", "sk_test_", "rk_live_", "rk_test_")),
    R("npm-token", 1, r"\bnpm_[A-Za-z0-9]{36}\b", anchors=("npm_",)),
    R("pypi-token", 1, r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}",
      anchors=("pypi-AgEIcHlwaS5vcmc",)),
    R("sendgrid-key", 1, r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
      anchors=("SG.",)),
    R("twilio-key", 1, r"\bSK[0-9a-fA-F]{32}\b", anchors=("SK",)),
    R("digitalocean-token", 1, r"\bdop_v1_[a-f0-9]{64}\b", anchors=("dop_v1_",)),
    R("cloudflare-token", 1, r"\bv1\.0-[A-Za-z0-9\-]{20,}-[A-Za-z0-9\-]{40,}",
      anchors=("v1.0-",)),
    R("jwt", 1, r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
      anchors=("eyJ",)),
    R("private-key-block", 1,
      r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
      r"[\s\S]{0,20000}?-----END (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
      anchors=("-----BEGIN",)),
    # user:pass inside a URL -> redact only the password span.
    # The scheme is a literal alternation on purpose: a leading character class
    # here costs ~46 s over a 250 MB corpus, the literal list costs ~1 s.
    R("url-basic-auth", 1,
      r"\b(?:https?|ftps?|ssh|sftp|git|svn|mongodb(?:\+srv)?|postgres(?:ql)?|mysql|"
      r"redis[s]?|amqps?|smtps?|imaps?|ldaps?|rtsps?|wss?)://"
      r"[^\s:/@\"'<>]{1,64}:([^\s@\"'<>\\]{3,128})@", group=1,
      anchors=("://",)),
]

# Tier 2: shape/context based. Needs an entropy floor and a placeholder denylist.
_SECRETISH = ("password", "passwd", "passphrase", "secret", "token", "apikey",
              "api_key", "access_key", "private_key", "client_secret",
              "auth_key", "credential")

TIER2 = [
    # Anchored on the literal keyword, not on a leading character class, for the
    # same performance reason as url-basic-auth.
    R("env-assigned-secret", 2,
      r"(?i)(?:PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY|"
      r"PRIVATE_KEY|CLIENT_SECRET|AUTH_KEY|CREDENTIAL)[A-Z0-9_]*"
      r"\s*[:=]\s*[\"']?([^\s\"'{}$,;\\]{8,200})[\"']?",
      group=1, min_entropy=2.6, anchors=_SECRETISH, ci_anchors=True),
    R("cli-password-flag", 2,
      r"(?i)--?(?:password|passwd|pass|token|api-key|apikey|secret)[=\s]+[\"']?"
      r"([^\s\"'\\]{6,200})[\"']?", group=1, min_entropy=2.3,
      anchors=("-password", "-passwd", "-pass", "-token", "-api-key", "-apikey",
               "-secret"), ci_anchors=True),
    R("sshpass", 2, r"sshpass\s+-p\s*[\"']?([^\s\"'\\]{3,200})[\"']?",
      group=1, min_entropy=1.5, anchors=("sshpass",), ci_anchors=True),
    R("authorization-header", 2,
      r"(?i)authorization[\"']?\s*[:=]\s*[\"']?(?:Bearer|Basic|Token)\s+"
      r"([A-Za-z0-9_\-\.=+/]{16,500})",
      group=1, min_entropy=3.0, anchors=("authorization",), ci_anchors=True),
    R("aws-secret-access-key", 2,
      r"(?i)aws_?secret_?access_?key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?",
      group=1, min_entropy=3.5, anchors=("secret",), ci_anchors=True),
    R("mysql-pg-cli-password", 2,
      r"(?i)\b(?:mysql|psql|mongo|redis-cli)\b[^\n]{0,120}?-p\s*([^\s\"'\\]{6,120})",
      group=1, min_entropy=2.3, anchors=("mysql", "psql", "mongo", "redis-cli"),
      ci_anchors=True),
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
    context: str = ""      # surrounding text, secret already masked

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.secret.encode("utf-8", "surrogateescape")).hexdigest()[:12]


def _context(text: str, start: int, end: int, secret: str, width: int = 45) -> str:
    """Surrounding text with the secret replaced by a length marker.

    Tier-2 hits need a human decision, and that decision needs the key name and
    the line around it. It must never need the value itself.
    """
    left = text[max(0, start - width):start].replace("\n", " ")
    right = text[end:end + width].replace("\n", " ")
    return f"{left}<{len(secret)} chars>{right}".strip()


def find_matches(text: str, rules, lowered: str | None = None) -> list[Match]:
    rules = [r for r in rules if r.possible_in(text, lowered)]
    if not rules:
        return []

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
            out.append(Match(rule.name, rule.tier, start, end, secret,
                             _context(text, start, end, secret)))

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
    """`home` is only used to locate <home>/.claude.json. It is derived from
    `root` by the caller so that --root actually redirects everything."""
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


def _was_json(line: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped[0] not in "{[":
        return False
    try:
        json.loads(stripped)
        return True
    except (ValueError, RecursionError):
        return False


def _needs_lower(rules) -> bool:
    return any(r.ci_anchors for r in rules)


def scan_file(path: Path, rules) -> FileResult:
    res = FileResult(path=path)
    text = read_text(path)
    if text is None:
        res.skipped_reason = "binary-or-unreadable"
        return res
    lowered = text.lower() if _needs_lower(rules) else None
    res.matches = find_matches(text, rules, lowered)
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

    # Whole-file pass first. Most files have nothing, and this avoids paying the
    # per-line regex setup cost across millions of transcript lines.
    lowered = original.lower() if _needs_lower(rules) else None
    whole = find_matches(original, rules, lowered)
    if not whole:
        return res

    # A PEM block spans lines, so the line-by-line rewrite below can never see
    # it. Redact those spans against the whole document first. This cannot break
    # a .jsonl file - a JSONL record has no literal newline in it, so no match
    # there is ever multi-line - and the whole-document JSON guard further down
    # catches a pretty-printed file.
    multiline = [m for m in whole if "\n" in original[m.start:m.end]]
    working = original
    ml_matches: list[Match] = []
    if multiline:
        working = redact_text(original, multiline)
        ml_matches = multiline

    out_lines = []
    all_matches: list[Match] = []
    bad_lines = 0

    for line in working.splitlines(keepends=True):
        matches = find_matches(line, rules)
        if not matches:
            out_lines.append(line)
            continue
        new_line = redact_text(line, matches)
        # If the line parsed as JSON before the edit it must still parse after.
        # Keyed on the content, not on the file suffix: ~/.claude.json and the
        # timestamped .claude.json.backup.* files are JSON too, and they are
        # exactly where a corrupted rewrite hurts most.
        if _was_json(line) and not _was_json(new_line):
            out_lines.append(line)               # refuse to corrupt
            bad_lines += 1
            continue
        out_lines.append(new_line)
        all_matches.extend(matches)

    res.matches = ml_matches + all_matches
    if bad_lines:
        res.error = f"{bad_lines} line(s) left untouched: redaction would break JSON"

    new_text = "".join(out_lines)
    if new_text == original:
        return res

    # Pretty-printed JSON spans many lines, so the per-line guard above never
    # fires for it. Validate the whole document instead and abort if we broke it.
    stripped = original.strip()
    if stripped and stripped[0] in "{[":
        try:
            json.loads(stripped)
        except (ValueError, RecursionError):
            pass                                  # was not valid JSON to begin with
        else:
            try:
                json.loads(new_text.strip())
            except (ValueError, RecursionError):
                res.error = "aborted: redaction would break this JSON document"
                res.matches = []
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


# Worker entry point. Module level so it is picklable by ProcessPoolExecutor.
_W = {}


def _worker_init(tier, mode, backup_dir):
    _W["rules"] = {1: TIER1, 2: TIER2}.get(tier, ALL_RULES)
    _W["mode"] = mode
    _W["backup"] = Path(backup_dir) if backup_dir else None


def _worker(path_str: str) -> FileResult:
    path = Path(path_str)
    try:
        if _W["mode"] == "scan":
            return scan_file(path, _W["rules"])
        return scrub_file(path, _W["rules"], _W["backup"])
    except Exception as e:                      # never let one file kill the run
        return FileResult(path=path, error=f"{type(e).__name__}: {e}")


def process_files(files, tier, mode, backup_dir, jobs, progress=True):
    """Fan the file list across worker processes, largest file first.

    Transcript corpora are heavily skewed - a handful of 50 MB sessions next to
    hundreds of tiny ones - so scheduling the big ones first keeps every core
    busy to the end instead of leaving one worker chewing a giant file alone.
    """
    rules = {1: TIER1, 2: TIER2}.get(tier, ALL_RULES)
    ordered = sorted(files, key=lambda p: -_safe_size(p))

    if jobs <= 1 or len(ordered) < 2:
        results = []
        for i, f in enumerate(ordered, 1):
            _tick(progress, i, len(ordered))
            results.append(scan_file(f, rules) if mode == "scan"
                           else scrub_file(f, rules, backup_dir))
        _untick(progress)
        return results

    from concurrent.futures import ProcessPoolExecutor

    results = []
    with ProcessPoolExecutor(max_workers=jobs, initializer=_worker_init,
                             initargs=(tier, mode,
                                       str(backup_dir) if backup_dir else None)) as ex:
        for i, r in enumerate(ex.map(_worker, [str(f) for f in ordered], chunksize=1), 1):
            _tick(progress, i, len(ordered))
            results.append(r)
    _untick(progress)
    return results


def _safe_size(p: Path) -> int:
    try:
        return p.stat().st_size
    except OSError:
        return 0


def _tick(on: bool, i: int, total: int):
    if on and sys.stderr.isatty() and (i % 5 == 0 or i == total):
        pct = 100 * i // max(total, 1)
        print(f"\r  {i}/{total} files ({pct}%)", end="", file=sys.stderr, flush=True)


def _untick(on: bool):
    if on and sys.stderr.isatty():
        print("\r" + " " * 40 + "\r", end="", file=sys.stderr, flush=True)


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
                "context": m.context,
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


def print_report(results: list[FileResult], manifest: dict, mode: str,
                 skipped: list[tuple[Path, str]], show_context: bool = False):
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
            if show_context and e.get("context"):
                print(f"           ... {e['context']} ...")
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
    p.add_argument("--tier", type=int, choices=[0, 1, 2], default=None,
                   help="1 = high-precision only, 2 = contextual only, 0 = both. "
                        "scan defaults to both; scrub defaults to 1, because tier 2 "
                        "carries false positives and scrubbing is irreversible")
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
    p.add_argument("--context", action="store_true",
                   help="show masked surrounding text for each finding "
                        "(the secret itself is never printed)")
    p.add_argument("-j", "--jobs", type=int, default=0,
                   help="worker processes (default: one per CPU, capped at 32)")
    p.add_argument("--version", action="version", version=VERSION)
    args = p.parse_args(argv)

    root = Path(args.root).expanduser()
    home = Path.home()

    tier = args.tier
    if tier is None:
        # Scanning both tiers costs nothing. Rewriting on the back of an
        # untriaged tier-2 hit is how you lose data you cannot get back.
        tier = 0 if args.mode == "scan" else 1
        if args.mode == "scrub":
            print("  tier not given: scrubbing tier 1 (certain) only. "
                  "Use --tier 0 to include contextual hits.")
    rules = {1: TIER1, 2: TIER2}.get(tier, ALL_RULES)

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
            # .claude.json sits next to the .claude directory, so a redirected
        # --root must move it too. Otherwise --root looks like a safe rehearsal
        # and still rewrites the real config.
        files = iter_target_files(root, root.parent,
                                  [Path(x).expanduser() for x in args.path])

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

    skipped: list[tuple[Path, str]] = []
    if args.mode == "scrub" and not args.include_live:
        live = [f for f in files if is_live(f, args.quiet_seconds, skip_ids)]
        skipped = [(f, "live-or-recent") for f in live]
        live_set = set(live)
        files = [f for f in files if f not in live_set]

    jobs = args.jobs or min(32, os.cpu_count() or 1)
    t0 = time.time()
    results = process_files(files, tier, args.mode, backup_dir, jobs)
    elapsed = time.time() - t0

    manifest = build_manifest(results)
    manifest["mode"] = args.mode
    manifest["files_examined"] = len(results)
    manifest["files_skipped_live"] = [str(p) for p, _ in skipped]
    manifest["elapsed_seconds"] = round(elapsed, 2)
    manifest["jobs"] = jobs
    manifest["tier"] = tier

    total_mb = sum(_safe_size(r.path) for r in results) / 1e6
    print(f"  {total_mb:.0f} MB in {elapsed:.1f}s on {jobs} worker(s) "
          f"({total_mb / max(elapsed, 0.01):.0f} MB/s)")
    print_report(results, manifest, args.mode, skipped, args.context)

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
