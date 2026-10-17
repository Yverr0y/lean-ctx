import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("history_gate", ROOT / "scripts/history-policy-gate.py")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)
REPO_SECRET_RULE = json.loads((ROOT / "security/history-policy-v1.json").read_text())["secret_rule"]

# Fake credentials are assembled at runtime so this file never holds a literal
# that a scanner (this gate, push protection, the CI pattern scan) would match.
MARKER = "DONOTPRINTTHISVALUE"
STRIPE_LIVE = "sk" + "_live_" + MARKER + "Q1w2E3r4T5"


def fake_stripe(tag):
    # No ascending runs: those mark a fixture as synthetic (synthetic_run_length).
    return "sk" + "_live_" + tag + "Q1w2E3r4T5y6U7i8O9p0A1s2"


class HistoryPolicyGateTests(unittest.TestCase):
    def setUp(self):
        # `gc.auto=0`: the fixture's commits can otherwise spawn a background
        # `git gc --auto` that still holds a handle inside `.git` when the
        # directory is torn down, and CI then fails with
        # "Directory not empty: '.git'" — a red build that says nothing about
        # the gate under test. `tearDown` tolerates whatever residue remains.
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "gc.auto", "0")
        self.git("config", "user.email", "test@leanctx.invalid")
        self.git("config", "user.name", "LeanCTX Test")
        (self.repo / "README.md").write_text("public\n")
        (self.repo / "scanner.py").write_text("# bounded scanner\n")
        self.commit("baseline")
        # Keep checkout -b main portable when git init defaults to main.
        self.git("branch", "-M", "base")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.report_path = self.repo / "baseline.json"
        report = {
            "schema_version": "leanctx.full-history-evidence/v1",
            "audited_commit": self.base,
            "policy_sha256": "0" * 64,
            "scanner_versions": GATE.BASELINE_SCANNER_VERSIONS,
            "counts": {"commits": 1, "objects": 3, "findings": 0},
            "audit_status": "rotation-and-rewrite-decision-pending",
            "current_tree_finding_ids": [],
            "finding_set_sha256": hashlib.sha256(GATE.canonical([])).hexdigest(),
            "findings": [],
        }
        self.report_path.write_bytes(GATE.canonical(report))
        self.policy_path = self.repo / "policy.json"
        self.write_policy(self.base, "0" * 64)
        report["policy_sha256"] = GATE.policy_fingerprint(self.policy())
        self.report_path.write_bytes(GATE.canonical(report))
        self.write_policy(self.base, hashlib.sha256(self.report_path.read_bytes()).hexdigest())

    def tearDown(self):
        # The fixture is a temp directory: if the platform still holds a handle
        # inside `.git`, the OS reclaims the leftovers. Failing the test over it
        # would report a filesystem race as a policy-gate defect.
        try:
            self.temp.cleanup()
        except OSError:
            shutil.rmtree(self.temp.name, ignore_errors=True)

    def git(self, *args):
        result = subprocess.run(["git", "-C", str(self.repo), *args], capture_output=True, text=True, check=True)
        return result.stdout

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)

    def write_policy(self, commit, digest, report="baseline.json"):
        policy = {
            "schema_version": "leanctx.history-policy/v1",
            "limits": {"max_commits": 50, "max_objects": 500, "max_findings": 100, "command_timeout_seconds": 10},
            "forbidden_paths": [{"id": "IP001", "prefix": "private/"}],
            "secret_rule": REPO_SECRET_RULE,
            "policy_source_path": "policy.json",
            "scanner_source_paths": ["policy.json", "scanner.py"],
            "scanner_source_sha256": {"scanner.py": hashlib.sha256((self.repo / "scanner.py").read_bytes()).hexdigest()},
            "baseline": {"commit": commit, "report": report, "report_sha256": digest},
        }
        self.policy_path.write_bytes(GATE.canonical(policy))

    def policy(self):
        return GATE.load_policy(self.policy_path)

    def test_full_audit_is_bounded_and_redacted(self):
        secret = STRIPE_LIVE
        (self.repo / "leak.txt").write_text(secret + "\n")
        (self.repo / "private").mkdir()
        (self.repo / "private/data.txt").write_text("internal\n")
        self.commit("introduce fixtures")
        report = GATE.full_audit(self.repo, self.policy())
        encoded = GATE.canonical(report)
        self.assertGreaterEqual(len(report["findings"]), 2)
        self.assertNotIn(secret.encode(), encoded)
        self.assertTrue(all(set(item) == {"id", "scanner", "rule", "path", "object"} for item in report["findings"]))
        self.assertEqual(report["scanner_versions"], GATE.BASELINE_SCANNER_VERSIONS)
        self.assertEqual(report["finding_set_sha256"], hashlib.sha256(GATE.canonical(report["findings"])).hexdigest())
        self.assertEqual(report["current_tree_finding_ids"], sorted(item["id"] for item in GATE.current_tree_scan(self.repo, self.policy())))

    def test_clean_current_and_delta_pass(self):
        report = GATE.gate(self.repo, self.policy())
        self.assertEqual(report["findings"], [])

    def test_current_and_delta_secret_fail_closed(self):
        (self.repo / "leak.txt").write_text(STRIPE_LIVE + "\n")
        self.commit("secret delta")
        report = GATE.gate(self.repo, self.policy())
        scanners = {item["scanner"] for item in report["findings"]}
        self.assertEqual(scanners, {"current-secret", "delta-secret"})
        self.assertNotIn(MARKER.encode(), GATE.canonical(report))

    def test_current_and_delta_private_path_fail_closed(self):
        (self.repo / "private").mkdir()
        (self.repo / "private/data.txt").write_text("internal\n")
        self.commit("private delta")
        scanners = {item["scanner"] for item in GATE.gate(self.repo, self.policy())["findings"]}
        self.assertEqual(scanners, {"current-path", "delta-path"})

    def test_missing_or_modified_baseline_fails(self):
        self.report_path.unlink()
        with self.assertRaises(GATE.GateError):
            GATE.gate(self.repo, self.policy())
        self.report_path.write_text("{}\n")
        with self.assertRaises(GATE.GateError):
            GATE.gate(self.repo, self.policy())

    def test_unreachable_baseline_fails(self):
        self.write_policy("0" * 40, hashlib.sha256(self.report_path.read_bytes()).hexdigest())
        with self.assertRaises(GATE.GateError):
            GATE.gate(self.repo, self.policy())

    def test_present_non_ancestor_baseline_is_accepted(self):
        self.git("checkout", "-b", "main")
        self.git("checkout", "--orphan", "feature")
        (self.repo / "README.md").write_text("public feature\n")
        self.commit("feature root")
        self.git("update-ref", "refs/remotes/origin/main", "main")
        previous = os.environ.get("GITHUB_BASE_REF")
        os.environ["GITHUB_BASE_REF"] = "main"
        try:
            report = GATE.gate(self.repo, self.policy())
        finally:
            if previous is None:
                os.environ.pop("GITHUB_BASE_REF", None)
            else:
                os.environ["GITHUB_BASE_REF"] = previous
        self.assertEqual(report["baseline_commit"], self.base)

    def test_pr_base_current_findings_are_inherited(self):
        self.git("checkout", "-b", "main")
        (self.repo / "leak.txt").write_text(fake_stripe("BASE") + "\n")
        self.commit("base branch fixture")
        self.git("update-ref", "refs/remotes/origin/main", "main")
        self.git("checkout", "-b", "feature")
        (self.repo / "README.md").write_text("public feature\n")
        self.commit("feature change")
        previous = os.environ.get("GITHUB_BASE_REF")
        os.environ["GITHUB_BASE_REF"] = "main"
        try:
            report = GATE.gate(self.repo, self.policy())
        finally:
            if previous is None:
                os.environ.pop("GITHUB_BASE_REF", None)
            else:
                os.environ["GITHUB_BASE_REF"] = previous
        self.assertEqual(report["findings"], [])

    def test_policy_rule_drift_fails(self):
        value = json.loads(self.policy_path.read_text())
        value["forbidden_paths"].append({"id": "IP002", "prefix": "new-private/"})
        self.policy_path.write_bytes(GATE.canonical(value))
        with self.assertRaises(GATE.GateError):
            GATE.gate(self.repo, self.policy())

    def test_scanner_version_drift_fails(self):
        report = json.loads(self.report_path.read_text())
        report["scanner_versions"] = ["obsolete/v1"]
        self.report_path.write_bytes(GATE.canonical(report))
        self.write_policy(self.base, hashlib.sha256(self.report_path.read_bytes()).hexdigest())
        with self.assertRaises(GATE.GateError):
            GATE.gate(self.repo, self.policy())

    def test_scanner_source_drift_fails(self):
        (self.repo / "scanner.py").write_text("# modified scanner\n")
        with self.assertRaises(GATE.GateError):
            GATE.gate(self.repo, self.policy())

    def test_scanner_source_path_hash_set_drift_fails(self):
        value = json.loads(self.policy_path.read_text())
        value["scanner_source_paths"].append("missing.py")
        self.policy_path.write_bytes(GATE.canonical(value))
        with self.assertRaises(GATE.GateError):
            GATE.load_policy(self.policy_path)

        value = json.loads(self.policy_path.read_text())
        value["scanner_source_paths"].remove("missing.py")
        value["scanner_source_sha256"]["missing.py"] = "0" * 64
        self.policy_path.write_bytes(GATE.canonical(value))
        with self.assertRaises(GATE.GateError):
            GATE.load_policy(self.policy_path)

    def test_baseline_report_symlink_fails(self):
        target = self.repo / "baseline-target.json"
        self.report_path.rename(target)
        self.report_path.symlink_to(target.name)
        self.write_policy(self.base, hashlib.sha256(target.read_bytes()).hexdigest())
        with self.assertRaises(GATE.GateError):
            GATE.gate(self.repo, self.policy())

    def test_policy_fingerprint_mismatch_fails(self):
        report = json.loads(self.report_path.read_text())
        report["policy_sha256"] = "f" * 64
        self.report_path.write_bytes(GATE.canonical(report))
        self.write_policy(self.base, hashlib.sha256(self.report_path.read_bytes()).hexdigest())
        with self.assertRaises(GATE.GateError):
            GATE.gate(self.repo, self.policy())

    def test_bounds_fail_closed(self):
        policy = self.policy()
        policy["limits"]["max_commits"] = 0
        with self.assertRaises(GATE.GateError):
            GATE.full_audit(self.repo, policy)



    def _rebaseline_current_tree(self):
        """Freeze baseline at HEAD with current-tree finding IDs accepted."""
        commit = self.git("rev-parse", "HEAD").strip()
        policy = self.policy()
        findings = GATE.current_tree_scan(self.repo, policy)
        ids = [item["id"] for item in findings]
        report_rel = policy["baseline"]["report"]
        # Fingerprint includes baseline.commit — update that before hashing.
        policy["baseline"] = {
            "commit": commit,
            "report": report_rel,
            "report_sha256": "0" * 64,
        }
        report = {
            "schema_version": "leanctx.full-history-evidence/v1",
            "audited_commit": commit,
            "policy_sha256": GATE.policy_fingerprint(policy),
            "scanner_versions": GATE.BASELINE_SCANNER_VERSIONS,
            "counts": {"commits": 1, "objects": 1, "findings": len(ids)},
            "current_tree_finding_ids": ids,
            "finding_set_sha256": hashlib.sha256(GATE.canonical(ids)).hexdigest(),
            "audit_status": "rotation-and-rewrite-decision-pending",
        }
        report_path = self.repo / report_rel
        report_path.write_bytes(GATE.canonical(report))
        policy["baseline"]["report_sha256"] = hashlib.sha256(report_path.read_bytes()).hexdigest()
        self.policy_path.write_bytes(GATE.canonical(policy))

    def test_edit_baselined_secret_path_still_passes(self):
        """Content churn on a path already known at baseline must not fail the gate."""
        (self.repo / "docs").mkdir(exist_ok=True)
        (self.repo / "docs/readme.md").write_text("token = " + fake_stripe("BASELINE") + "\n")
        self.commit("baseline secret example")
        self._rebaseline_current_tree()
        # Edit same file (new blob) while keeping a matching pattern.
        (self.repo / "docs/readme.md").write_text(
            "# note\ntoken = " + fake_stripe("BASELINE") + "\nmore\n"
        )
        self.commit("docs edit keeping secret-like example")
        report = GATE.gate(self.repo, self.policy())
        self.assertEqual(report["findings"], [])

    def test_remove_baselined_secret_passes(self):
        """Removing a baselined secret-like example must not fail via delta pickaxe."""
        (self.repo / "docs").mkdir(exist_ok=True)
        (self.repo / "docs/readme.md").write_text("token = " + fake_stripe("BASELINE") + "\n")
        self.commit("baseline secret example")
        self._rebaseline_current_tree()
        (self.repo / "docs/readme.md").write_text("token = <redacted>\n")
        self.commit("remove secret-like example")
        report = GATE.gate(self.repo, self.policy())
        self.assertEqual(report["findings"], [])

    def test_every_credential_shape_fails_current_and_delta(self):
        for name, text in POSITIVE_FIXTURES.items():
            (self.repo / f"{name}.txt").write_text(text)
        self.commit("credential fixtures")
        findings = GATE.gate(self.repo, self.policy())["findings"]
        for name in POSITIVE_FIXTURES:
            scanners = {item["scanner"] for item in findings if item["path"] == f"{name}.txt"}
            self.assertEqual(scanners, {"current-secret", "delta-secret"}, name)
        self.assertNotIn(MARKER.encode(), GATE.canonical(findings))

    def test_false_positive_classes_pass_gate_and_full_audit(self):
        for name, text in NEGATIVE_FIXTURES.items():
            (self.repo / f"{name}.txt").write_text(text)
        self.commit("detectors, tests and warning docs")
        self.assertEqual(GATE.gate(self.repo, self.policy())["findings"], [])
        secrets = [item for item in GATE.full_audit(self.repo, self.policy())["findings"] if item["rule"] == "SEC001"]
        self.assertEqual(secrets, [])

    def test_full_audit_reports_introduction_not_removal(self):
        (self.repo / "leak.txt").write_text(fake_stripe("INTRO") + "\n")
        self.commit("introduce")
        introduced = self.git("rev-parse", "HEAD").strip()
        (self.repo / "leak.txt").write_text("token = <redacted>\n")
        self.commit("remove")
        secrets = [item for item in GATE.full_audit(self.repo, self.policy())["findings"] if item["rule"] == "SEC001"]
        self.assertEqual([(item["path"], item["object"]) for item in secrets], [("leak.txt", introduced)])

    def test_reviewed_blob_exemption_is_bound_to_exact_content(self):
        key = BEGIN.format("") + "\n" + B64 + "\n" + END + "\n"
        (self.repo / "fixtures").mkdir()
        (self.repo / "fixtures/loopback-key.pem").write_text(key)
        self.commit("reviewed self-signed fixture")
        blob = self.git("rev-parse", "HEAD:fixtures/loopback-key.pem").strip()
        policy = self.policy()
        self.assertEqual({item["path"] for item in GATE.current_tree_scan(self.repo, policy)}, {"fixtures/loopback-key.pem"})
        policy["secret_rule"] = dict(policy["secret_rule"], reviewed_blobs=[{"blob": blob, "reason": "self-signed loopback test key"}])
        self.assertEqual(GATE.current_tree_scan(self.repo, policy), [])
        self.assertEqual([item for item in GATE.full_audit(self.repo, policy)["findings"] if item["rule"] == "SEC001"], [])
        # Any edit is a new blob: the exemption no longer applies. The BEGIN line
        # is untouched, so the pickaxe candidate count does not change; the
        # current-tree scan is the stage that re-reports it.
        (self.repo / "fixtures/loopback-key.pem").write_text(key + B64 + "\n")
        self.commit("edit reviewed fixture")
        self.assertEqual({item["path"] for item in GATE.current_tree_scan(self.repo, policy)}, {"fixtures/loopback-key.pem"})

    def test_secret_rule_contract_is_strict(self):
        for mutate in (
            lambda rule: rule.pop("credential_patterns"),
            lambda rule: rule.update(credential_patterns=[]),
            lambda rule: rule["credential_patterns"].append({"id": "broken", "regex": "("}),
            lambda rule: rule["credential_patterns"].append({"id": "named", "regex": "(?P<user>x)"}),
            lambda rule: rule["password_policy"].update(min_length=0),
            lambda rule: rule["password_policy"]["dev_default_passwords"].append("UPPER"),
            lambda rule: rule.update(extra="field"),
            lambda rule: rule.update(synthetic_run_length=3),
            lambda rule: rule.update(reviewed_blobs=[{"blob": "not-a-blob-id", "reason": "x"}]),
            lambda rule: rule.update(reviewed_blobs=[{"blob": "a" * 40, "reason": " "}]),
        ):
            value = json.loads(self.policy_path.read_text())
            mutate(value["secret_rule"])
            self.policy_path.write_bytes(GATE.canonical(value))
            with self.assertRaises(GATE.GateError):
                GATE.load_policy(self.policy_path)


def _fixture_values():
    alnum36 = "A1b2C3d4" * 4 + "E5f6"
    b64 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC" + "x7Kp" * 3 + "Ab"
    begin = "-----BEGIN " + "{}PRIVATE KEY-----"
    end = "-----END " + "PRIVATE KEY-----"
    scheme = "postgres" + "://"
    return alnum36, b64, begin, end, scheme


ALNUM36, B64, BEGIN, END, PG = _fixture_values()

POSITIVE_FIXTURES = {
    "github-classic": "token = " + "gh" + "p_" + ALNUM36 + "\n",
    "github-oauth": "gh" + "o_" + ALNUM36 + "\n",
    "github-server": "gh" + "s_" + ALNUM36 + "\n",
    "github-user": "gh" + "u_" + ALNUM36 + "\n",
    "github-refresh": "gh" + "r_" + ALNUM36 + "\n",
    "github-fine-grained": "github" + "_pat_" + "11AQ7XK2M0" + "Zr5Tq8Wn3Lp4" + "_" + "Zx9" * 20 + "\n",
    "aws-access-key": "aws_access_key_id = " + "AK" + "IA" + "Z7QW3RTY5UIOP2LK" + "\n",
    "aws-session-key": "AS" + "IA" + "Q4WE8RTY2UIO6PLK" + "\n",
    "stripe-secret": "STRIPE_KEY=" + fake_stripe(MARKER) + "\n",
    "stripe-restricted": "rk" + "_live_" + "Q1w2E3r4T5y6U7i8O9p0A1s2D3f4" + "\n",
    "pem-pkcs8": BEGIN.format("") + "\n" + B64 + "\n" + B64 + "\n" + END + "\n",
    "pem-rsa-encrypted": BEGIN.format("RSA ") + "\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0A1B2C3D\n\n" + B64 + "\n",
    "pem-openssh-indented": "key: |\n  " + BEGIN.format("OPENSSH ") + "\n  b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\n",
    "pem-json-escaped": '{"key": "' + BEGIN.format("EC ") + "\\n" + B64 + "\\n" + END + '"}\n',
    "db-postgres": "DATABASE_URL=" + PG + "app:Zq8vN2kLm4Rt@db.prod.internal:5432/app\n",
    "db-postgresql-driver": "postgresql" + "+psycopg2://svc:Hk3mP9qL2wXv@10.0.0.5/db\n",
    "db-mysql": "my" + "sql://root:7dF4gH2jK9lQ@mysql.internal:3306/app\n",
}

NEGATIVE_FIXTURES = {
    "detector-prefixes": "PREFIXES = ['" + "gh" + "p_', '" + "gh" + "o_', '" + "github" + "_pat_', '" + "AK" + "IA', '" + "sk" + "_live_']\n",
    "detector-short-values": "assert redact('" + "gh" + "p_abc') and redact('" + "AK" + "IA1234') and redact('" + "sk" + "_live_abc')\n",
    "warning-doc": "Never commit " + "sk" + "_live_" + " keys. Use test keys in CI; " + "gh" + "p_" + " tokens belong in secrets.\n",
    "aws-documentation-example": "aws_access_key_id = " + "AK" + "IA" + "IOSFODNN7" + "EXAMPLE\n",
    "pem-detector": 'if line.startswith("' + BEGIN.format("RSA ") + '"):\n    return True\n',
    "pem-doc": "A key starts with `" + BEGIN.format("") + "` and ends with `" + END + "`.\n",
    "pem-placeholder": BEGIN.format("") + "\n<your key material here>\n" + END + "\n",
    "pem-bare-suffix": "matches 'PRIVATE " + "KEY-----' markers\n",
    "db-env-placeholder": "url: " + PG + "leanctx_ent:${LEANCTX_DB_PASSWORD}@db:5432/app\n",
    "db-format-placeholder": 'f"' + PG + '{role}:{password}@127.0.0.1:{port}/db"\n',
    "db-angle-placeholder": PG + "leanctx_engine:<password>@db:5432/app\n",
    "db-bracket-placeholder": PG + "app:[REDACTED]@db:5432/app\n",
    "db-masked": PG + "app:********@db:5432/app\n",
    "db-short-literal": PG + "leanctx:leanctx@localhost:5432/leanctx\n" + PG + "u:p@db.example.com:5432\n",
    "db-dev-default": PG + "leanctx:leanctx-dev@localhost:5432/leanctx\n",
    "synthetic-sequence-token": 'classify("key = ' + "gh" + "p_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789" + '")\n',
    "synthetic-sequence-aws": "AK" + "IA" + "ABCDEFGHIJKLMNOP" + "\n",
}


class CredentialPatternTests(unittest.TestCase):
    def test_positive_fixtures_match_precise_and_candidate_stage(self):
        # The ERE is interval-free; only its POSIX class needs a Python spelling.
        self.assertNotRegex(REPO_SECRET_RULE["pickaxe_regex"], r"\{\d")
        candidate = GATE.re.compile(REPO_SECRET_RULE["pickaxe_regex"].replace("[:space:]", r"\s"))
        for name, text in POSITIVE_FIXTURES.items():
            self.assertGreaterEqual(GATE.credential_count(text, REPO_SECRET_RULE), 1, name)
            self.assertTrue(candidate.search(text), name)

    def test_negative_fixtures_never_match(self):
        for name, text in NEGATIVE_FIXTURES.items():
            self.assertEqual(GATE.credential_count(text, REPO_SECRET_RULE), 0, name)


if __name__ == "__main__":
    unittest.main()
