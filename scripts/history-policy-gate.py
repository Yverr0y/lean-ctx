#!/usr/bin/env python3
"""Bounded full-history audit and required baseline-delta policy gate.

Secret detection is two-stage:

1. ``secret_rule.pickaxe_regex`` is a POSIX ERE that git evaluates natively
   (``git log -S --pickaxe-regex`` for history, ``git grep -E`` for a tree).
   It only narrows candidates cheaply; it is deliberately a superset of the
   precise patterns on the line that carries the credential prefix, and it is
   interval-free: bounded repetitions such as ``{36}`` make git's POSIX
   matcher markedly slower over full history.
2. ``secret_rule.credential_patterns`` are Python regexes evaluated over the
   whole blob. They decide. Whole-blob matching lets a PEM block require key
   material on the lines after its BEGIN line (git's pickaxe is line-bound),
   and the ``password`` group of a database URL is checked against
   ``secret_rule.password_policy`` so placeholders and documented local
   development defaults are not reported as credentials.

Two further, narrow filters keep test fixtures out without path allowlists:

* ``synthetic_run_length``: a match containing an ascending run of that many
  consecutive digits or letters (``ABCDEFGH``, ``01234567``) is a hand-made
  fixture. A random credential contains such a run with negligible
  probability (about 3e-11 for a 36-character token and a run of 8).
* ``reviewed_blobs``: individually reviewed git blob IDs (for example a
  self-signed loopback TLS key read only by tests). The exemption is bound to
  the exact content; any edit produces a new blob and is scanned again.

A history candidate counts only when the precise match count of the path rises
in that commit (an introduction). Bare prefixes in detectors, tests and
warning docs never reach a finding. The current-tree scan applies the same
precise check at the tip, so an introduction the pickaxe cannot see (its
candidate count unchanged) is still caught there.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path


class GateError(RuntimeError):
    pass


FULL_AUDIT_SCANNER_VERSIONS = ["commit-path/v2", "diff-pickaxe/v3", "public-tree/v3"]
BASELINE_SCANNER_VERSIONS = FULL_AUDIT_SCANNER_VERSIONS
SECRET_RULE_KEYS = {
    "id",
    "rationale",
    "pickaxe_regex",
    "credential_patterns",
    "password_policy",
    "synthetic_run_length",
    "reviewed_blobs",
}
MIN_SYNTHETIC_RUN_LENGTH = 8
SEQUENCES = ("0123456789", "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
PASSWORD_POLICY_KEYS = {"min_length", "placeholder_prefixes", "placeholder_markers", "dev_default_passwords"}


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def git(root, timeout, *args, allowed=(0,)):
    try:
        result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise GateError(f"git command timed out: {args[0]}") from exc
    if result.returncode not in allowed:
        raise GateError(f"git command failed: {args[0]} ({result.returncode})")
    return result.stdout


def load_policy(path):
    policy = json.loads(path.read_bytes())
    expected = {
        "schema_version",
        "limits",
        "forbidden_paths",
        "secret_rule",
        "policy_source_path",
        "scanner_source_paths",
        "scanner_source_sha256",
        "baseline",
    }
    if not isinstance(policy, dict) or set(policy) != expected or policy["schema_version"] != "leanctx.history-policy/v1":
        raise GateError("invalid policy contract")
    limits = policy["limits"]
    required_keys = {"max_commits", "max_objects", "max_findings", "command_timeout_seconds"}
    optional_keys = {"full_audit_timeout_seconds"}
    if not required_keys <= set(limits) or not set(limits) <= required_keys | optional_keys or not all(isinstance(v, int) and v > 0 for v in limits.values()):
        raise GateError("invalid policy limits")
    baseline = policy["baseline"]
    if set(baseline) != {"commit", "report", "report_sha256"} or not re.fullmatch(r"[0-9a-f]{40}", baseline["commit"]) or not re.fullmatch(r"[0-9a-f]{64}", baseline["report_sha256"]):
        raise GateError("invalid baseline contract")
    source_paths = policy["scanner_source_paths"]
    sources = policy["scanner_source_sha256"]
    if (
        not isinstance(source_paths, list)
        or len(source_paths) != len(set(source_paths))
        or not isinstance(policy["policy_source_path"], str)
        or policy["policy_source_path"] not in source_paths
        or not isinstance(sources, dict)
        or not sources
        or not all(isinstance(path, str) and re.fullmatch(r"[0-9a-f]{64}", digest) for path, digest in sources.items())
        or set(source_paths) - {policy["policy_source_path"]} != set(sources)
    ):
        raise GateError("invalid scanner-source contract")
    validate_secret_rule(policy["secret_rule"])
    return policy


def string_list(value):
    return isinstance(value, list) and all(isinstance(item, str) and item for item in value)


def validate_secret_rule(rule):
    if not isinstance(rule, dict) or set(rule) != SECRET_RULE_KEYS:
        raise GateError("invalid secret-rule contract")
    if not all(isinstance(rule[key], str) and rule[key] for key in ("id", "rationale", "pickaxe_regex")):
        raise GateError("invalid secret-rule contract")
    patterns = rule["credential_patterns"]
    if (
        not isinstance(patterns, list)
        or not patterns
        or not all(isinstance(item, dict) and set(item) == {"id", "regex"} and all(isinstance(v, str) and v for v in item.values()) for item in patterns)
        or len({item["id"] for item in patterns}) != len(patterns)
    ):
        raise GateError("invalid credential-pattern contract")
    for item in patterns:
        try:
            compiled = re.compile(item["regex"])
        except re.error as exc:
            raise GateError(f"invalid credential pattern: {item['id']}") from exc
        if compiled.groupindex and set(compiled.groupindex) != {"password"}:
            raise GateError(f"credential pattern may only name a password group: {item['id']}")
    passwords = rule["password_policy"]
    if (
        not isinstance(passwords, dict)
        or set(passwords) != PASSWORD_POLICY_KEYS
        or not isinstance(passwords["min_length"], int)
        or passwords["min_length"] < 1
        or not all(string_list(passwords[key]) for key in PASSWORD_POLICY_KEYS - {"min_length"})
        or any(value != value.lower() for value in passwords["dev_default_passwords"])
    ):
        raise GateError("invalid password-policy contract")
    run = rule["synthetic_run_length"]
    if not isinstance(run, int) or isinstance(run, bool) or run < MIN_SYNTHETIC_RUN_LENGTH:
        raise GateError("invalid synthetic-run contract")
    reviewed = rule["reviewed_blobs"]
    if (
        not isinstance(reviewed, list)
        or not all(
            isinstance(item, dict)
            and set(item) == {"blob", "reason"}
            and isinstance(item["blob"], str)
            and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", item["blob"])
            and isinstance(item["reason"], str)
            and item["reason"].strip()
            for item in reviewed
        )
        or len({item["blob"] for item in reviewed}) != len(reviewed)
    ):
        raise GateError("invalid reviewed-blob contract")


def synthetic(value, run_length):
    """True when value holds an ascending run of run_length digits or letters."""
    return any(sequence[start : start + run_length] in value for sequence in SEQUENCES for start in range(len(sequence) - run_length + 1))


def placeholder_password(value, passwords):
    """True when a database-URL password is a placeholder or a documented dev default."""
    return (
        len(value) < passwords["min_length"]
        or value.startswith(tuple(passwords["placeholder_prefixes"]))
        or any(marker in value for marker in passwords["placeholder_markers"])
        or value.lower() in passwords["dev_default_passwords"]
    )


def credential_count(text, rule):
    """Count precise credential matches in text; the decision stage of SEC001."""
    count = 0
    for pattern in rule["credential_patterns"]:
        for match in re.finditer(pattern["regex"], text):
            password = match.groupdict().get("password")
            if password is not None and placeholder_password(password, rule["password_policy"]):
                continue
            if synthetic(match.group(0), rule["synthetic_run_length"]):
                continue
            count += 1
    return count


def policy_fingerprint(policy):
    baseline = policy["baseline"]
    material = {
        "schema_version": policy["schema_version"],
        "limits": policy["limits"],
        "forbidden_paths": policy["forbidden_paths"],
        "secret_rule": policy["secret_rule"],
        "policy_source_path": policy["policy_source_path"],
        "scanner_source_paths": policy["scanner_source_paths"],
        "scanner_source_sha256": policy["scanner_source_sha256"],
        "baseline": {"commit": baseline["commit"], "report": baseline["report"]},
    }
    return hashlib.sha256(canonical(material)).hexdigest()


def scanner_source(path, policy):
    return path in policy["scanner_source_paths"]


def repository_file(root, relative, label):
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


def validate_scanner_sources(root, policy):
    for path, expected in policy["scanner_source_sha256"].items():
        actual = hashlib.sha256(repository_file(root, path, "scanner source").read_bytes()).hexdigest()
        if actual != expected:
            raise GateError("scanner source digest mismatch")


def rule_for_path(path, policy):
    for rule in policy["forbidden_paths"]:
        prefix = rule["prefix"]
        if path == prefix.rstrip("/") or path.startswith(prefix):
            return rule["id"]
    return None


def finding(scanner, rule, path, object_ref):
    identity = hashlib.sha256("\0".join((scanner, rule, path, object_ref)).encode()).hexdigest()
    return {"id": identity, "scanner": scanner, "rule": rule, "path": path, "object": object_ref}


def bounded(findings, policy):
    unique = {(item["scanner"], item["rule"], item["path"], item["object"]): item for item in findings}
    values = sorted(unique.values(), key=lambda item: (item["scanner"], item["rule"], item["path"], item["object"]))
    if len(values) > policy["limits"]["max_findings"]:
        raise GateError("finding bound exceeded; evidence would be truncated")
    return values


def validate_baseline(root, policy):
    timeout = policy["limits"]["command_timeout_seconds"]
    baseline = policy["baseline"]
    validate_scanner_sources(root, policy)
    report_path = repository_file(root, baseline["report"], "baseline report")
    raw = report_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != baseline["report_sha256"]:
        raise GateError("baseline report digest mismatch")
    report = json.loads(raw)
    if raw != canonical(report) or report.get("schema_version") != "leanctx.full-history-evidence/v1" or report.get("audited_commit") != baseline["commit"]:
        raise GateError("baseline report is non-canonical or bound to another commit")
    if report.get("policy_sha256") != policy_fingerprint(policy):
        raise GateError("baseline report policy fingerprint mismatch")
    if report.get("scanner_versions") != BASELINE_SCANNER_VERSIONS:
        raise GateError("baseline report scanner-version mismatch")
    counts = report.get("counts")
    current_ids = report.get("current_tree_finding_ids")
    if (
        not isinstance(counts, dict)
        or set(counts) != {"commits", "objects", "findings"}
        or not all(isinstance(value, int) and value >= 0 for value in counts.values())
        or not isinstance(current_ids, list)
        or len(current_ids) != len(set(current_ids))
        or not all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in current_ids)
        or not re.fullmatch(r"[0-9a-f]{64}", report.get("finding_set_sha256", ""))
        or report.get("audit_status") != "rotation-and-rewrite-decision-pending"
    ):
        raise GateError("invalid baseline evidence contract")
    git(root, timeout, "cat-file", "-e", baseline["commit"] + "^{commit}")
    return report


def current_tree_scan(root, policy, ref="HEAD"):
    timeout = policy["limits"]["command_timeout_seconds"]
    findings = []
    paths = [value.decode(errors="surrogateescape") for value in git(root, timeout, "ls-tree", "-r", "--name-only", "-z", ref).split(b"\0") if value]
    for path in paths:
        if rule := rule_for_path(path, policy):
            object_ref = git(root, timeout, "rev-parse", f"{ref}:{path}").decode().strip()
            findings.append(finding("current-path", rule, path, object_ref))
    matches = git(root, timeout, "grep", "-I", "-l", "-E", policy["secret_rule"]["pickaxe_regex"], ref, allowed=(0, 1)).decode(errors="surrogateescape").splitlines()
    for value in matches:
        path = value.removeprefix(ref + ":")
        if scanner_source(path, policy) or not secret_match_count(root, timeout, ref, path, policy["secret_rule"]):
            continue
        object_ref = git(root, timeout, "rev-parse", f"{ref}:{path}").decode().strip()
        findings.append(finding("current-secret", policy["secret_rule"]["id"], path, object_ref))
    return findings


def secret_match_count(root, timeout, ref, path, rule):
    """Count precise credential matches for path at ref. Missing path or ref, or a reviewed blob → 0."""
    blob_id = git(root, timeout, "rev-parse", "--verify", "--quiet", f"{ref}:{path}", allowed=(0, 1, 128)).decode().strip()
    if not blob_id or blob_id in {item["blob"] for item in rule["reviewed_blobs"]}:
        return 0
    blob = git(root, timeout, "cat-file", "blob", blob_id, allowed=(0, 128))  # 128: a gitlink, not a blob
    return credential_count(blob.decode(errors="surrogateescape"), rule)


def secret_introduced(root, timeout, commit, path, rule):
    """Pickaxe -S fires on introduce AND remove; only a rising precise count is an introduction."""
    before = secret_match_count(root, timeout, f"{commit}^", path, rule)
    return secret_match_count(root, timeout, commit, path, rule) > before


def merge_base(root, timeout, left, right):
    return git(root, timeout, "merge-base", left, right, allowed=(0, 1)).decode().strip()


def pr_base_ref(root, timeout):
    base_ref = os.environ.get("GITHUB_BASE_REF", "").strip()
    if not base_ref or not re.fullmatch(r"[A-Za-z0-9._/-]+", base_ref):
        return ""
    for ref in (f"origin/{base_ref}", f"upstream/{base_ref}"):
        if git(root, timeout, "rev-parse", "--verify", "--quiet", ref + "^{commit}", allowed=(0, 1)).strip():
            return ref
    return ""


def delta_base(root, policy):
    timeout = policy["limits"]["command_timeout_seconds"]
    base = policy["baseline"]["commit"]
    if ref := pr_base_ref(root, timeout):
        if value := merge_base(root, timeout, ref, "HEAD"):
            return value
    if value := merge_base(root, timeout, base, "HEAD"):
        return value
    return base


def delta_scan(root, policy, base):
    timeout = policy["limits"]["command_timeout_seconds"]
    findings = []
    paths = git(root, timeout, "diff", "--name-only", "--no-renames", base + "..HEAD").decode(errors="surrogateescape").splitlines()
    for path in paths:
        if rule := rule_for_path(path, policy):
            findings.append(finding("delta-path", rule, path, base + "..HEAD"))
    regex = policy["secret_rule"]["pickaxe_regex"]
    stream = git(
        root,
        timeout,
        "log",
        "--format=%x1e%H",
        "--name-only",
        "--no-renames",
        "--pickaxe-regex",
        "-S",
        regex,
        base + "..HEAD",
    ).decode(errors="surrogateescape")
    for record in stream.split("\x1e"):
        lines_rec = [line for line in record.splitlines() if line]
        if not lines_rec:
            continue
        commit = lines_rec[0]
        for path in sorted(set(lines_rec[1:])):
            if scanner_source(path, policy) or not secret_introduced(root, timeout, commit, path, policy["secret_rule"]):
                continue
            findings.append(finding("delta-secret", policy["secret_rule"]["id"], path, commit))
    return findings


def gate(root, policy):
    baseline = validate_baseline(root, policy)
    inherited = set(baseline.get("current_tree_finding_ids", []))
    base = policy["baseline"]["commit"]
    comparison_base = delta_base(root, policy)
    # Content edits change blob hashes and therefore finding IDs. Treat the same
    # (scanner, rule, path) already present at the audited baseline as inherited
    # so docs/code churn on known findings does not fail the delta gate.
    inherited_keys = {
        (item["scanner"], item["rule"], item["path"])
        for item in current_tree_scan(root, policy, ref=base)
    }
    if comparison_base != base:
        inherited_keys.update(
            (item["scanner"], item["rule"], item["path"])
            for item in current_tree_scan(root, policy, ref=comparison_base)
        )

    def is_new_current(item):
        if item["id"] in inherited:
            return False
        if (item["scanner"], item["rule"], item["path"]) in inherited_keys:
            return False
        return True

    current = [item for item in current_tree_scan(root, policy) if is_new_current(item)]
    findings = bounded(current + delta_scan(root, policy, comparison_base), policy)
    return {
        "schema_version": "leanctx.history-delta-evidence/v1",
        "baseline_commit": policy["baseline"]["commit"],
        "baseline_report_sha256": policy["baseline"]["report_sha256"],
        "inherited_history_findings": baseline["counts"]["findings"],
        "inherited_current_tree_findings": len(inherited),
        "findings": findings,
    }


def full_audit(root, policy):
    timeout = policy["limits"].get("full_audit_timeout_seconds", policy["limits"]["command_timeout_seconds"] * 5)
    commits = git(root, timeout, "rev-list", "--all").decode().splitlines()
    objects = git(root, timeout, "rev-list", "--objects", "--all").splitlines()
    if not commits or len(commits) > policy["limits"]["max_commits"] or len(objects) > policy["limits"]["max_objects"]:
        raise GateError("full-history bounds exceeded")
    findings = []
    pathspecs = [rule["prefix"] for rule in policy["forbidden_paths"]]
    path_log = git(root, timeout, "log", "--all", "--format=%x1e%H", "--name-only", "--no-renames", "--", *pathspecs).decode(errors="surrogateescape")
    for record in path_log.split("\x1e"):
        lines = [line for line in record.splitlines() if line]
        if lines:
            for path in sorted(set(lines[1:])):
                if rule := rule_for_path(path, policy):
                    findings.append(finding("full-path", rule, path, lines[0]))
    secret_log = git(root, timeout, "log", "--all", "--root", "--format=%x1e%H", "--name-only", "--no-renames", "--pickaxe-regex", "-S", policy["secret_rule"]["pickaxe_regex"]).decode(errors="surrogateescape")
    for record in secret_log.split("\x1e"):
        lines = [line for line in record.splitlines() if line]
        if lines:
            for path in sorted(set(lines[1:])):
                if not scanner_source(path, policy) and secret_introduced(root, timeout, lines[0], path, policy["secret_rule"]):
                    findings.append(finding("full-secret", policy["secret_rule"]["id"], path, lines[0]))
    findings = bounded(findings, policy)
    current_ids = sorted(item["id"] for item in current_tree_scan(root, policy))
    return {
        "schema_version": "leanctx.full-history-evidence/v1",
        "audited_commit": git(root, timeout, "rev-parse", "HEAD").decode().strip(),
        "policy_sha256": policy_fingerprint(policy),
        "scanner_versions": FULL_AUDIT_SCANNER_VERSIONS,
        "counts": {"commits": len(commits), "objects": len(objects), "findings": len(findings)},
        "findings": findings,
        "current_tree_finding_ids": current_ids,
        "finding_set_sha256": hashlib.sha256(canonical(findings)).hexdigest(),
        "audit_status": "rotation-and-rewrite-decision-pending",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("full-audit", "gate"))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        policy = load_policy(args.policy)
        report = full_audit(args.root.resolve(), policy) if args.command == "full-audit" else gate(args.root.resolve(), policy)
        args.output.write_bytes(canonical(report))
    except (GateError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"history policy gate failed: {exc}", file=sys.stderr)
        return 2
    print(f"history policy {args.command}: {len(report['findings'])} new findings")
    return 1 if args.command == "gate" and report["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
