# Full-history baseline review

## Scanner-source re-attestation for the v4 merge

The v4 merge changes pinned scanner sources, so the attestation moves with it
(same chain as 7bf1ac8595). The audited history does not change.

- Audited commit, findings, counts and current-tree IDs are unchanged
  (`bff280bfc8eba6959854fafcbf104b5745d794c3`).
- `rust/src/proxy/anthropic.rs` changes digest (merged v4 and #1912 edits).
- Four v4 detector sources join the pinned scanner sources, mirroring the
  existing `anthropic.rs` + `anthropic_tests.rs` pair: they hold credential
  prefixes as rejection rules or synthetic rejection fixtures, never live
  credentials. Pinning makes every later edit to them a deliberate
  re-attestation.
  - `rust/crates/lean-ctx-protocol/src/credential_redaction.rs`
  - `rust/crates/lean-ctx-protocol/src/context_checkpoint.rs`
  - `rust/crates/lean-ctx-protocol/src/context_checkpoint/tests_core.rs`
  - `rust/src/core/execution_ledger/host/checkpoint_transfer/content.rs`
- Policy fingerprint `ed08cf77` → `b5057df6`; report digest `5e78496c` →
  `e4853cbb`. The gate reports 0 new findings on the merged tree.
- Forbidden paths, the secret rule and the limits are unchanged. No path
  exemption is added. The regeneration reproduces unchanged `main`
  byte-identically before it is applied.

## Baseline audit

- Audit target: `bff280bfc8eba6959854fafcbf104b5745d794c3`
- Audit source: clean post-rewrite clone, all public branches and tags
- Scanner contract: `commit-path/v2`, `diff-pickaxe/v2`, `public-tree/v2`
- Coverage: 16,291 commits, 99,593 objects, 558 metadata-only findings
- Current tree: 11 accepted finding IDs

The previous 473 findings remain present with identical IDs. The 85 additional
object-specific IDs introduce zero new `(scanner, rule, path)` combinations.
They therefore represent already-audited path classes across later or rewritten
objects, not a newly accepted finding class.

No rule, forbidden-path entry, source-binding requirement, or allowlist was
weakened. The pending audit status remains intentional because remediation of
other historical classes is outside this baseline rotation.

## Precise SEC001 rule and baseline rotation (2026-10-17)

The SEC001 rule matched bare prefixes (`ghp_`, `AKIA`, `sk_live_`,
`PRIVATE KEY-----`) and any database URL with a password field. Every
current-tree hit on the private integration tree (40, plus 53 history
introductions) was a secret *detector*, a test fake, a warning in
documentation, a `${VAR}` or `{placeholder}` password, a local development
default or a self-signed loopback test key. The noise hid real signals.

- **Two stages.** The git pickaxe uses an interval-free POSIX ERE that only
  narrows candidates (intervals such as `{36}` made `git log -S` exceed the
  per-command timeout on the larger private tree). A precise Python check over
  the blob decides: GitHub tokens with their full length, fine-grained
  `github_pat_`, AWS key IDs (`…EXAMPLE` documentation keys excluded), Stripe
  live keys, PEM blocks only with base64 key material, and database URLs only
  with a literal password of at least eight characters that is neither a
  placeholder nor a documented development default.
- **Two narrow filters.** A match containing an ascending run of eight
  characters (`ABCDEFGH`, `01234567`) is a hand-made fixture; one reviewed
  self-signed loopback TLS test key is exempt by Git blob ID only, so any change
  to its content is scanned again.
- **History** reports an introduction only when the precise match count of a
  blob rises in a commit.
- **Limits.** `command_timeout_seconds` is raised from 120 to 300 s: the
  candidate pickaxe over the private tree took 81 s, too close to the old limit
  for slower runners.

### Baseline audit

- Audit target: `b37ee3be11f2525cd785348d3e43ccdbb590fe94`
- Audit source: fresh clone of the public repository with `main`,
  `cla-signatures` and all tags — the ref set of the 16,291-commit audit above
  (recomputed: `main` up to `bff280` plus `cla-signatures` plus its tags gives
  exactly 16,291). Open pull-request branches are not part of the baseline.
- Scanner contract: `commit-path/v2`, `diff-pickaxe/v3`, `public-tree/v3`
- Coverage: 17,061 commits, 109,865 objects, 369 findings — 368 path findings
  (IP001–IP006) and one SEC001 finding (`server.md` in commit `13e3e76353`,
  reachable from an archive tag). The SEC001 finding is a credential; its
  rotation is tracked privately.
- Current tree: 0 accepted finding IDs (previously 11, all removed by the
  precise rule).
- Runtime: full audit 533 s (limit 1,800 s).
- The evidence that shipped with the 3.11.0 export named 8,818 commits, which
  matches no public ref set; it most likely came from the private integration
  tree. This rotation replaces it with an audit of the public refs.

Verified against the private integration tree: of the 93 findings the previous
rule reported there, none remains.
