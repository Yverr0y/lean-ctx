import datetime as dt
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("secret_expiry", ROOT / "scripts/check-secret-expiry.py")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class _Response:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, *_):
        return self.payload


class SecretExpiryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "security").mkdir()
        (self.root / "scripts").mkdir()
        (self.root / ".github/workflows").mkdir(parents=True)
        (self.root / "scripts/check-secret-expiry.py").write_text("# scanner\n")
        (self.root / ".github/workflows/secret-rotation-check.yml").write_text("# workflow\n")
        self.policy_path = self.root / "security/secret-rotation-policy-v1.json"
        self.write_policy()

    def tearDown(self):
        self.temp.cleanup()

    def write_policy(self):
        paths = [
            "security/secret-rotation-policy-v1.json",
            "scripts/check-secret-expiry.py",
            ".github/workflows/secret-rotation-check.yml",
        ]
        policy = {
            "schema_version": CHECKER.POLICY_SCHEMA,
            "rotation_defaults": {"max_age_days": 90, "warning_days": 14, "critical_days": 7},
            "secrets": [{"name": "NPM_TOKEN", "owner": "test@lean-ctx", "max_age_days": 90, "category": "package-registry", "rotation_url": "https://example.invalid/rotate"}],
            "scanner_source_paths": paths,
            "scanner_source_sha256": {
                item: hashlib.sha256((self.root / item).read_bytes()).hexdigest()
                for item in paths[1:]
            },
        }
        self.policy_path.write_bytes(CHECKER.canonical(policy))

    def policy(self):
        return CHECKER.load_policy(self.policy_path)

    def test_policy_loading_validation_and_source_hashes(self):
        policy = self.policy()
        CHECKER.validate_scanner_sources(self.root, policy)
        policy["secrets"][0]["rotation_url"] = "http://invalid"
        self.policy_path.write_bytes(CHECKER.canonical(policy))
        with self.assertRaises(CHECKER.GateError):
            CHECKER.load_policy(self.policy_path)

    def test_repository_policy_declares_and_hashes_all_secrets(self):
        policy = CHECKER.load_policy(ROOT / "security/secret-rotation-policy-v1.json")
        CHECKER.validate_scanner_sources(ROOT, policy)
        self.assertCountEqual(
            [item["name"] for item in policy["secrets"]],
            [
                "AUR_SSH_KEY", "CARGO_REGISTRY_TOKEN", "CLA_SIGNATURES_TOKEN",
                "HOMEBREW_SSH_KEY",
                "TWITTER_ACCESS_SECRET", "TWITTER_ACCESS_TOKEN", "TWITTER_CONSUMER_KEY",
                "TWITTER_CONSUMER_SECRET",
            ],
        )

    def test_age_computation_from_iso_timestamps(self):
        now = dt.datetime(2026, 7, 29, tzinfo=dt.timezone.utc)
        self.assertEqual(CHECKER.age_days("2026-07-15T23:59:59Z", now), 13)
        self.assertEqual(CHECKER.age_days("2026-07-15T00:00:00+00:00", now), 14)
        with self.assertRaises(CHECKER.GateError):
            CHECKER.age_days("not-a-timestamp", now)

    def test_classification_logic(self):
        self.assertEqual(CHECKER.classify_age(75, 90, 14, 7), "OK")
        self.assertEqual(CHECKER.classify_age(76, 90, 14, 7), "WARNING")
        self.assertEqual(CHECKER.classify_age(83, 90, 14, 7), "CRITICAL")
        self.assertEqual(CHECKER.classify_age(91, 90, 14, 7), "EXPIRED")

    def test_report_formatting(self):
        report = CHECKER.build_report(
            self.policy(),
            {"NPM_TOKEN": {"name": "NPM_TOKEN", "updated_at": "2026-05-10T00:00:00Z"}},
            dt.datetime(2026, 7, 29, tzinfo=dt.timezone.utc),
        )
        rendered = CHECKER.render_report(report)
        self.assertIn("## Secret Rotation Status", rendered)
        self.assertIn("| NPM_TOKEN | WARNING | 80 | 10 |", rendered)
        self.assertFalse(report["blocking"])

    @patch.object(CHECKER.urllib.request, "urlopen")
    def test_github_api_response_is_mocked(self, urlopen):
        urlopen.return_value = _Response({"total_count": 1, "secrets": [{"name": "NPM_TOKEN", "updated_at": "2026-07-15T00:00:00Z"}]})
        values = CHECKER.github_secrets("yvgude/lean-ctx", "test-token")
        self.assertEqual(values["NPM_TOKEN"]["updated_at"], "2026-07-15T00:00:00Z")
        request = urlopen.call_args.args[0]
        self.assertNotIn("test-token", request.full_url)

    def test_request_failures_never_echo_the_token(self):
        # CodeQL py/clear-text-logging-sensitive-data: http.client rejects a
        # header with a control character by raising ValueError that quotes
        # the header value, and main() printed every ValueError to stderr —
        # i.e. into the CI log. Both the malformed-token path and an unexpected
        # failure inside the request must surface only a fixed message.
        # A sentinel, deliberately not credential-shaped: the history policy
        # gate (SEC001) refuses any commit that adds a GitHub token prefix.
        token = "test-token-SENTINEL-1234567890"
        with self.assertRaises(CHECKER.GateError) as malformed:
            CHECKER.github_secrets("yvgude/lean-ctx", token + "\r\nX-Injected: 1")
        self.assertNotIn(token, str(malformed.exception))

        leak = ValueError(f"Invalid header value b'Bearer {token}'")
        with patch.object(CHECKER.urllib.request, "urlopen", side_effect=leak):
            with self.assertRaises(CHECKER.GateError) as failed:
                CHECKER.github_secrets("yvgude/lean-ctx", token)
        self.assertNotIn(token, str(failed.exception))
        self.assertIsNone(failed.exception.__cause__)
        self.assertTrue(failed.exception.__suppress_context__)

        # A trailing newline from a token file is trimmed, not rejected.
        with patch.object(CHECKER.urllib.request, "urlopen") as urlopen:
            urlopen.return_value = _Response({"secrets": []})
            self.assertEqual(CHECKER.github_secrets("yvgude/lean-ctx", token + "\n"), {})
            self.assertEqual(urlopen.call_args.args[0].get_header("Authorization"), f"Bearer {token}")


if __name__ == "__main__":
    unittest.main()
