#!/usr/bin/env python3
"""Self-contained test suite. No pytest needed:  python3 tests/test_spillscrub.py"""

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import spillscrub as ss  # noqa: E402


# Fake but correctly-shaped credentials. None of these are real.
PLANTED = {
    "anthropic-api-key": "sk-ant-api03-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0",
    "github-pat": "ghp_" + "aB3dE5gH7jK9lM1nO3pQ5rS7tU9vW1xY3zA5",
    "gitlab-pat": "glpat-" + "xY3zA5bC7dE9fG1hJ3kL",
    "aws-access-key-id": "AKIAQ7WZ3PLMN4RTUV6X",
    "slack-token": "xoxb-2847361920384-2847361920999-Xy7Kq2Lm9Pz4Rw8Tn3Vb6Hd1",
    "google-api-key": "AIzaSyD4x7Kq2Lm9Pz4Rw8Tn3Vb6Hd1Jf5Gc0Qa",
    "huggingface-token": "hf_QwErTyUiOpAsDfGhJkLzXcVbNmQwErTy",
    "tailscale-key": "tskey-auth-k7Qm2Lz9Pw4Rn8Td3Vb-Hd1Jf5Gc0QaXy7Kq2Lm",
    "stripe-key": "sk_live_51QwErTyUiOpAsDfGhJkLzXcVbNm",
    "npm-token": "npm_QwErTyUiOpAsDfGhJkLzXcVbNmQwErTyUiOp",
}

BENIGN = [
    'ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}',
    'export API_KEY="your-api-key-here"',
    'password = "changeme"',
    'DB_PASSWORD=<password>',
    'TOKEN=xxxxxxxxxxxx',
    'api_key: TODO',
    'SECRET_KEY=REDACTED',
    'psql -h localhost -U postgres -p 5432',
    'AKIAIOSFODNN7EXAMPLE_but_not_a_key_because_lowercase',
    'password: null',
    'const secret = "aaaaaaaaaaaa";',
    '# set GITHUB_TOKEN=<your token>',
    'AUTH_TOKEN=$GITHUB_TOKEN',
]


def jline(text, role="user"):
    return json.dumps({
        "type": "user",
        "message": {"role": role, "content": [{"type": "text", "text": text}]},
        "uuid": "0000-1111",
    })


class TestDetection(unittest.TestCase):
    def test_tier1_secrets_are_all_detected(self):
        for rule_name, secret in PLANTED.items():
            with self.subTest(rule=rule_name):
                found = ss.find_matches(f"here is the key: {secret} ok", ss.ALL_RULES)
                self.assertTrue(found, f"{rule_name} not detected at all")
                self.assertIn(secret, [m.secret for m in found],
                              f"{rule_name}: matched span is not the full secret")

    def test_private_key_block_detected(self):
        blob = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
                "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz\n"
                "-----END OPENSSH PRIVATE KEY-----")
        found = ss.find_matches(blob, ss.ALL_RULES)
        self.assertTrue(any(m.rule == "private-key-block" for m in found))

    def test_url_basic_auth_scrubs_only_the_password(self):
        text = "git clone https://joshua:Sup3rS3cr3tPw@gitlab.com/olympus/repo.git"
        found = ss.find_matches(text, ss.ALL_RULES)
        self.assertTrue(found)
        m = found[0]
        self.assertEqual(m.secret, "Sup3rS3cr3tPw")
        out = ss.redact_text(text, found)
        self.assertIn("https://joshua:[REDACTED rule=url-basic-auth", out)
        self.assertIn("@gitlab.com/olympus/repo.git", out)
        self.assertNotIn("Sup3rS3cr3tPw", out)

    def test_benign_lookalikes_are_not_flagged(self):
        for line in BENIGN:
            with self.subTest(line=line):
                found = ss.find_matches(line, ss.ALL_RULES)
                self.assertEqual(found, [], f"false positive on: {line!r} -> {found}")

    def test_real_password_assignment_is_flagged(self):
        found = ss.find_matches('DB_PASSWORD="Kq2Lm9Pz4Rw8Tn3V"', ss.ALL_RULES)
        self.assertTrue(found)
        self.assertEqual(found[0].secret, "Kq2Lm9Pz4Rw8Tn3V")

    def test_sshpass_is_flagged(self):
        found = ss.find_matches("sshpass -p 'Tr0ub4dor&3' ssh root@10.10.10.5", ss.ALL_RULES)
        self.assertTrue(any(m.rule == "sshpass" for m in found))

    def test_already_redacted_text_is_not_rematched(self):
        once = ss.redact_text(
            f"key {PLANTED['github-pat']} end",
            ss.find_matches(f"key {PLANTED['github-pat']} end", ss.ALL_RULES))
        self.assertEqual(ss.find_matches(once, ss.ALL_RULES), [])

    def test_same_secret_yields_same_digest(self):
        a = ss.find_matches(f"x {PLANTED['github-pat']}", ss.ALL_RULES)[0]
        b = ss.find_matches(f"y {PLANTED['github-pat']}", ss.ALL_RULES)[0]
        self.assertEqual(a.digest, b.digest)

    def test_digest_is_not_the_secret(self):
        m = ss.find_matches(f"x {PLANTED['github-pat']}", ss.ALL_RULES)[0]
        self.assertNotIn(m.secret, ss.placeholder_for(m))
        self.assertEqual(len(m.digest), 12)


class TestScrubIntegrity(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="spillscrub-test-"))

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_clean_file_is_byte_identical(self):
        f = self.d / "clean.jsonl"
        body = "\n".join(jline(t) for t in BENIGN) + "\n"
        f.write_text(body)
        before = f.read_bytes()
        res = ss.scrub_file(f, ss.ALL_RULES, None)
        self.assertEqual(res.matches, [])
        self.assertFalse(res.scrubbed)
        self.assertEqual(f.read_bytes(), before, "clean file was modified")

    def test_jsonl_stays_valid_after_scrub(self):
        f = self.d / "dirty.jsonl"
        lines = [jline(f"my key is {s}") for s in PLANTED.values()]
        lines.append(jline("nothing to see here"))
        f.write_text("\n".join(lines) + "\n")

        res = ss.scrub_file(f, ss.ALL_RULES, None)
        self.assertTrue(res.scrubbed)
        self.assertIsNone(res.error)

        text = f.read_text()
        for secret in PLANTED.values():
            self.assertNotIn(secret, text, "secret survived the scrub")
        for line in text.splitlines():
            json.loads(line)          # raises if we broke the JSON

    def test_secret_with_json_escapes_around_it(self):
        f = self.d / "escaped.jsonl"
        payload = ('line1\nline2 "quoted" \\ backslash\ttab '
                   f'token={PLANTED["anthropic-api-key"]} unicode: é —')
        f.write_text(jline(payload) + "\n")
        res = ss.scrub_file(f, ss.ALL_RULES, None)
        self.assertTrue(res.scrubbed)
        obj = json.loads(f.read_text().strip())
        got = obj["message"]["content"][0]["text"]
        self.assertNotIn(PLANTED["anthropic-api-key"], got)
        self.assertIn("[REDACTED rule=anthropic-api-key", got)
        self.assertIn('"quoted"', got)
        self.assertIn("—", got)

    def test_trailing_newline_preserved(self):
        for body in (jline("x") + "\n", jline("x")):
            f = self.d / "nl.jsonl"
            f.write_text(body)
            ss.scrub_file(f, ss.ALL_RULES, None)
            self.assertEqual(f.read_text(), body)

    def test_crlf_preserved(self):
        f = self.d / "crlf.jsonl"
        body = jline(f"k {PLANTED['github-pat']}") + "\r\n" + jline("clean") + "\r\n"
        f.write_bytes(body.encode())
        ss.scrub_file(f, ss.ALL_RULES, None)
        out = f.read_bytes()
        self.assertEqual(out.count(b"\r\n"), 2)
        self.assertNotIn(PLANTED["github-pat"].encode(), out)

    def test_non_jsonl_plain_file_is_scrubbed(self):
        f = self.d / "snapshot.sh"
        f.write_text(f"export GH_TOKEN={PLANTED['github-pat']}\nalias ll='ls -la'\n")
        res = ss.scrub_file(f, ss.ALL_RULES, None)
        self.assertTrue(res.scrubbed)
        out = f.read_text()
        self.assertNotIn(PLANTED["github-pat"], out)
        self.assertIn("alias ll='ls -la'", out)

    def test_file_permissions_preserved(self):
        f = self.d / "perm.jsonl"
        f.write_text(jline(f"k {PLANTED['github-pat']}") + "\n")
        os.chmod(f, 0o600)
        ss.scrub_file(f, ss.ALL_RULES, None)
        self.assertEqual(os.stat(f).st_mode & 0o777, 0o600)

    def test_backup_dir_keeps_original(self):
        f = self.d / "b.jsonl"
        original = jline(f"k {PLANTED['github-pat']}") + "\n"
        f.write_text(original)
        backup = self.d / "bk"
        ss.scrub_file(f, ss.ALL_RULES, backup)
        saved = backup / f.resolve().relative_to("/")
        self.assertTrue(saved.is_file())
        self.assertEqual(saved.read_text(), original)

    def test_scrub_is_idempotent(self):
        f = self.d / "idem.jsonl"
        f.write_text("\n".join(jline(f"k {s}") for s in PLANTED.values()) + "\n")
        ss.scrub_file(f, ss.ALL_RULES, None)
        once = f.read_bytes()
        res2 = ss.scrub_file(f, ss.ALL_RULES, None)
        self.assertFalse(res2.scrubbed)
        self.assertEqual(f.read_bytes(), once)


class TestManifest(unittest.TestCase):
    def test_manifest_dedups_and_never_contains_the_secret(self):
        secret = PLANTED["github-pat"]
        results = [
            ss.FileResult(Path("/a.jsonl"), ss.find_matches(f"x {secret}", ss.ALL_RULES)),
            ss.FileResult(Path("/b.jsonl"), ss.find_matches(f"y {secret}", ss.ALL_RULES)),
        ]
        man = ss.build_manifest(results)
        self.assertEqual(man["distinct_secrets"], 1)
        self.assertEqual(man["total_occurrences"], 2)
        self.assertEqual(man["secrets"][0]["file_count"], 2)
        self.assertNotIn(secret, json.dumps(man))


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="spillscrub-cli-"))

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_scan_does_not_modify(self):
        f = self.d / "s.jsonl"
        f.write_text(jline(f"k {PLANTED['github-pat']}") + "\n")
        before = f.read_bytes()
        rc = ss.main(["scan", "--only", str(self.d)])
        self.assertEqual(rc, 1)                    # 1 = findings
        self.assertEqual(f.read_bytes(), before)

    def test_scrub_requires_yes(self):
        f = self.d / "s.jsonl"
        f.write_text(jline(f"k {PLANTED['github-pat']}") + "\n")
        before = f.read_bytes()
        rc = ss.main(["scrub", "--only", str(self.d)])
        self.assertEqual(rc, 2)
        self.assertEqual(f.read_bytes(), before)

    def test_scrub_skips_recently_modified(self):
        f = self.d / "live.jsonl"
        f.write_text(jline(f"k {PLANTED['github-pat']}") + "\n")
        before = f.read_bytes()
        ss.main(["scrub", "--yes", "--only", str(self.d)])
        self.assertEqual(f.read_bytes(), before, "a live file was rewritten")

    def test_scrub_with_include_live_writes(self):
        f = self.d / "x.jsonl"
        f.write_text(jline(f"k {PLANTED['github-pat']}") + "\n")
        ss.main(["scrub", "--yes", "--include-live", "--only", str(self.d)])
        self.assertNotIn(PLANTED["github-pat"], f.read_text())

    def test_clean_tree_returns_zero(self):
        (self.d / "c.jsonl").write_text(jline("all good") + "\n")
        self.assertEqual(ss.main(["scan", "--only", str(self.d)]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
