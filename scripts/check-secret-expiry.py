#!/usr/bin/env python3
"""Check GitHub Actions secret ages against the secret rotation policy."""

import argparse
import datetime as dt
import hashlib
import http.client
import json
import os
import re
import sys
import urllib.request
from pathlib import Path


class GateError(RuntimeError):
    """Raised when a policy or secret-rotation check cannot be trusted."""


POLICY_SCHEMA = "leanctx.secret-rotation-policy/v1"
POLICY_PATH = "security/secret-rotation-policy-v1.json"
NAME_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{1,127}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


def canonical(value):
    """Return a stable JSON representation for reports and tests."""
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def repository_file(root, relative, label):
    """Resolve one regular, non-symlink file beneath *root*."""
    value = Path(relative)
    if value.is_absolute() or not value.parts or ".." in value.parts:
        raise GateError(f"{label} path is unsafe")
    current = root.resolve()
    for segment in value.parts:
        current /= segment
        if current.is_symlink():
            raise GateError(f"{label} symlink is forbidden")
    try:
        resolved = current.resolve(strict=True)
        resolved.relative_to(root.resolve())
    except (FileNotFoundError, ValueError) as exc:
        raise GateError(f"{label} missing or escapes repository") from exc
    if not resolved.is_file():
        raise GateError(f"{label} is not a regular file")
    return resolved


def load_policy(path):
    """Load and validate the declarative rotation-policy contract."""
    try:
        policy = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise GateError("policy is unreadable or invalid JSON") from exc
    expected = {
        "schema_version",
        "rotation_defaults",
        "secrets",
        "scanner_source_paths",
        "scanner_source_sha256",
    }
    if not isinstance(policy, dict) or set(policy) != expected:
        raise GateError("invalid policy contract")
    if policy["schema_version"] != POLICY_SCHEMA:
        raise GateError("unsupported policy schema")
    defaults = policy["rotation_defaults"]
    if (
        not isinstance(defaults, dict)
        or set(defaults) != {"max_age_days", "warning_days", "critical_days"}
        or not all(isinstance(value, int) and value > 0 for value in defaults.values())
        or not defaults["critical_days"] <= defaults["warning_days"] < defaults["max_age_days"]
    ):
        raise GateError("invalid rotation defaults")
    secrets = policy["secrets"]
    required_secret_keys = {"name", "owner", "max_age_days", "category", "rotation_url"}
    if not isinstance(secrets, list) or not secrets:
        raise GateError("policy must declare secrets")
    names = []
    for secret in secrets:
        if not isinstance(secret, dict) or set(secret) != required_secret_keys:
            raise GateError("invalid secret entry")
        if (
            not isinstance(secret["name"], str)
            or not NAME_PATTERN.fullmatch(secret["name"])
            or not isinstance(secret["owner"], str)
            or not secret["owner"]
            or not isinstance(secret["category"], str)
            or not secret["category"]
            or not isinstance(secret["rotation_url"], str)
            or not secret["rotation_url"].startswith("https://")
            or not isinstance(secret["max_age_days"], int)
            or secret["max_age_days"] <= defaults["warning_days"]
        ):
            raise GateError("invalid secret rotation entry")
        names.append(secret["name"])
    if len(names) != len(set(names)):
        raise GateError("secret names must be unique")
    paths = policy["scanner_source_paths"]
    hashes = policy["scanner_source_sha256"]
    if (
        not isinstance(paths, list)
        or len(paths) != len(set(paths))
        or POLICY_PATH not in paths
        or not all(isinstance(value, str) and value for value in paths)
        or not isinstance(hashes, dict)
        or set(hashes) != set(paths) - {POLICY_PATH}
        or not all(isinstance(value, str) and SHA256_PATTERN.fullmatch(value) for value in hashes.values())
    ):
        raise GateError("invalid scanner-source contract")
    return policy


def validate_scanner_sources(root, policy):
    """Fail if a policy-enforcing source no longer matches its policy digest."""
    for relative, expected in policy["scanner_source_sha256"].items():
        actual = hashlib.sha256(repository_file(root, relative, "scanner source").read_bytes()).hexdigest()
        if actual != expected:
            raise GateError(f"scanner source digest mismatch: {relative}")


def parse_timestamp(value):
    """Parse the GitHub API's ISO-8601 timestamps as UTC datetimes."""
    if not isinstance(value, str):
        raise GateError("secret timestamp is missing")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GateError("secret timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise GateError("secret timestamp lacks timezone")
    return parsed.astimezone(dt.timezone.utc)


def age_days(updated_at, now=None):
    """Return completed UTC days since a secret was last updated."""
    current = now or dt.datetime.now(dt.timezone.utc)
    if current.tzinfo is None:
        raise GateError("current time lacks timezone")
    age = current.astimezone(dt.timezone.utc) - parse_timestamp(updated_at)
    if age.total_seconds() < 0:
        raise GateError("secret timestamp is in the future")
    return age.days


def classify_age(age, max_age_days, warning_days, critical_days):
    """Classify one age using the policy's inclusive warning thresholds."""
    if not all(isinstance(value, int) and value >= 0 for value in (age, max_age_days, warning_days, critical_days)):
        raise GateError("rotation ages must be non-negative integers")
    if not critical_days <= warning_days < max_age_days:
        raise GateError("invalid rotation thresholds")
    if age > max_age_days:
        return "EXPIRED"
    remaining = max_age_days - age
    if remaining <= critical_days:
        return "CRITICAL"
    if remaining <= warning_days:
        return "WARNING"
    return "OK"


def github_secrets(repo, token):
    """Fetch GitHub Actions secret metadata without exposing token material."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise GateError("repository must be OWNER/REPOSITORY")
    # A token read from a file or env var often carries a trailing newline.
    token = (token or "").strip()
    if not token:
        raise GateError("GitHub token is required")
    # http.client rejects a header with whitespace or control characters by
    # raising ValueError("Invalid header value b'Bearer <token>…'"), which
    # quotes the token. Refuse it here, with a message that never echoes it.
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in token):
        raise GateError("GitHub token contains whitespace or control characters")
    url = f"https://api.github.com/repos/{repo}/actions/secrets?per_page=100"
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "lean-ctx-secret-rotation-check",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.load(response)
    except (OSError, ValueError, http.client.HTTPException) as exc:
        # Any failure while sending the request may carry the Authorization
        # header in its text; only a fixed message leaves this function.
        # (URLError, HTTPError and TimeoutError are OSError subclasses;
        # JSONDecodeError is a ValueError.)
        raise GateError(f"GitHub secret metadata request failed ({type(exc).__name__})") from None
    if not isinstance(payload, dict) or not isinstance(payload.get("secrets"), list):
        raise GateError("GitHub secret metadata response is invalid")
    values = {}
    for secret in payload["secrets"]:
        if not isinstance(secret, dict) or not isinstance(secret.get("name"), str):
            raise GateError("GitHub secret metadata entry is invalid")
        if secret["name"] in values:
            raise GateError("GitHub secret metadata contains duplicate names")
        values[secret["name"]] = secret
    return values


def build_report(policy, metadata, now=None):
    """Build a redacted rotation report from GitHub's metadata response."""
    defaults = policy["rotation_defaults"]
    entries = []
    for declaration in policy["secrets"]:
        item = metadata.get(declaration["name"])
        maximum = declaration["max_age_days"]
        if item is None:
            entries.append({
                "name": declaration["name"],
                "owner": declaration["owner"],
                "category": declaration["category"],
                "rotation_url": declaration["rotation_url"],
                "max_age_days": maximum,
                "status": "CRITICAL",
                "reason": "secret is not configured in GitHub Actions",
            })
            continue
        updated_at = item.get("updated_at")
        age = age_days(updated_at, now)
        status = classify_age(age, maximum, defaults["warning_days"], defaults["critical_days"])
        entries.append({
            "name": declaration["name"],
            "owner": declaration["owner"],
            "category": declaration["category"],
            "rotation_url": declaration["rotation_url"],
            "updated_at": updated_at,
            "age_days": age,
            "max_age_days": maximum,
            "days_remaining": maximum - age,
            "status": status,
        })
    counts = {status: sum(item["status"] == status for item in entries) for status in ("OK", "WARNING", "CRITICAL", "EXPIRED")}
    return {
        "schema_version": "leanctx.secret-rotation-report/v1",
        "policy_schema_version": policy["schema_version"],
        "secrets": entries,
        "counts": counts,
        "blocking": counts["CRITICAL"] + counts["EXPIRED"] > 0,
    }


def render_report(report):
    """Render a concise Markdown report suitable for a GitHub step summary."""
    if not isinstance(report, dict) or report.get("schema_version") != "leanctx.secret-rotation-report/v1":
        raise GateError("invalid rotation report")
    entries = report.get("secrets")
    counts = report.get("counts")
    if not isinstance(entries, list) or not isinstance(counts, dict):
        raise GateError("invalid rotation report")
    lines = ["## Secret Rotation Status", "", "| Secret | Status | Age | Remaining |", "| --- | --- | ---: | ---: |"]
    for item in entries:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or item.get("status") not in ("OK", "WARNING", "CRITICAL", "EXPIRED"):
            raise GateError("invalid rotation report entry")
        age = str(item.get("age_days", "unknown"))
        remaining = str(item.get("days_remaining", "unknown"))
        lines.append(f"| {item['name']} | {item['status']} | {age} | {remaining} |")
    lines.extend(["", f"OK: {counts.get('OK', 0)}; WARNING: {counts.get('WARNING', 0)}; CRITICAL: {counts.get('CRITICAL', 0)}; EXPIRED: {counts.get('EXPIRED', 0)}"])
    return "\n".join(lines) + "\n"


def write_report(report, output):
    """Write canonical JSON to stdout or an explicitly selected output path."""
    encoded = canonical(report)
    if output is None:
        sys.stdout.buffer.write(encoded)
    else:
        output.write_bytes(encoded)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check GitHub Actions secret rotation deadlines.")
    subcommands = parser.add_subparsers(dest="action", required=True)
    check = subcommands.add_parser("check", help="query GitHub and emit a JSON rotation report")
    check.add_argument("--policy", type=Path, required=True)
    check.add_argument("--repo", required=True, help="GitHub repository as OWNER/REPOSITORY")
    check.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN"))
    check.add_argument("--output", type=Path)
    report = subcommands.add_parser("report", help="render a JSON rotation report as Markdown")
    report.add_argument("--policy", type=Path, required=True)
    report.add_argument("--input", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        policy = load_policy(args.policy)
        if args.action == "check":
            validate_scanner_sources(Path.cwd(), policy)
            result = build_report(policy, github_secrets(args.repo, args.github_token))
            write_report(result, args.output)
            return 1 if result["blocking"] else 0
        loaded = json.loads(args.input.read_bytes())
        print(render_report(loaded), end="")
        return 0
    except (GateError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"secret rotation check failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
