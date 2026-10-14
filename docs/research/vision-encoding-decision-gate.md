# Vision Encoding Decision Gate

Issue #703 is a research gate, not a product default. The proxy now measures the
candidate share after request rewriting and before forwarding upstream.

`proxy-introspect.json` reports these process-lifetime cumulative fields:

- `total_input_tokens`
- `total_system_prompt_tokens`
- `total_bulk_candidate_tokens`
- `bulk_candidate_share_basis_points`
- `vision_encoding_decision_gate_met`
- `measurement_scope` (`process_lifetime`)
- `measurement_started_at_epoch_seconds`
- `measurement_elapsed_seconds`

Bulk candidates are the residual system slab, assistant history, and tool results.
The gate becomes true at 20% (2,000 basis points). A true gate only authorizes the
next experiment; it does not establish quality, profitability, model support, or
permission to enable image encoding.

The measurement is explicitly post-funnel because introspection analyzes the
prepared request body after compression. It is process-lifetime aggregate
telemetry and retains no prompt content.

The measurement window starts with the first observed request. Its elapsed time
uses a monotonic clock and resets when the proxy process restarts. Empty windows
have no start or elapsed value. Older snapshots without these fields do not prove
the duration of the sample; the snapshot's `ts` is the save time, not its start.

## Current local observation

Before the cumulative denominator was added, the latest real request contained
41,591 estimated input tokens and 39,808 bulk-candidate tokens (95.7%). Its system
slab alone was 9,067 tokens (21.8%). A single request is not a decision-quality
sample, so no renderer or default change follows from it.

Collect at least one normal usage day after installing this instrumentation
(`measurement_elapsed_seconds` at least 86,400), then
use the cumulative basis-point field for the issue's go/no-go decision. Any later
prototype remains default-off, model-allowlisted, byte-deterministic, and must keep
exact identifiers in text.
