use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

const BOUNCE_WINDOW: u64 = 5;
const BOUNCE_RATE_THRESHOLD: f64 = 0.30;
/// Seq-tick window during which a full read is treated as *edit-forced* rather
/// than a compression bounce. Must match the window `should_force_full` uses to
/// escalate post-edit reads to `full`, so the read we forced is never blamed on
/// the compression arm (GL #622).
const EDIT_FORCE_WINDOW: u64 = 10;
/// Outer-map retention: a path whose newest activity is older than this many seq ticks
/// can no longer satisfy BOUNCE_WINDOW (5) or the edit-force window (10), so it is inert
/// and safe to evict. Kept well above both windows to never change detection outcomes.
const TRACKED_PATH_TTL_SEQ: u64 = 64;

#[derive(Debug, Clone)]
struct ReadEvent {
    _mode: String,
    tokens_sent: usize,
    _original_tokens: usize,
    seq: u64,
    was_compressed: bool,
    /// Scope and task the read ran under; a bounce is that task's signal.
    origin: Option<crate::core::context_store::task_signals::Origin>,
}

#[derive(Debug, Default)]
struct BounceStats {
    total_reads: u64,
    bounces: u64,
    wasted_tokens: usize,
}

/// A detected compressed→full re-read that is not yet booked as a bounce.
///
/// Reading a file compressed for orientation, then in full, then editing it is
/// the normal edit flow (map to orient, full to edit), not a compression
/// failure. A bounce therefore stays provisional for `EDIT_FORCE_WINDOW` seq
/// ticks: an edit of the path inside that window cancels it, otherwise it is
/// committed (ledger entry, path memory, quality signal, scent).
#[derive(Debug, Clone)]
struct PendingBounce {
    path: String,
    /// Seq tick of the full read that triggered the detection.
    seq: u64,
    wasted: usize,
    origin: Option<crate::core::context_store::task_signals::Origin>,
    /// Wall-clock detection time, compared against host edits other
    /// processes report through the edit beacon.
    detected_unix_ms: u64,
}

#[derive(Debug, Default)]
pub struct BounceTracker {
    recent_reads: HashMap<String, Vec<ReadEvent>>,
    per_extension: HashMap<String, BounceStats>,
    recently_edited: HashMap<String, u64>,
    pending: Vec<PendingBounce>,
    seq_counter: u64,
    total_bounces: u64,
    total_wasted_tokens: usize,
    /// When true (only for the process-global tracker), detected bounces are appended to
    /// the persistent savings ledger so a fresh `gain` process sees historical bounce.
    /// Local trackers in unit tests leave this `false` to avoid touching the real ledger.
    persist: bool,
}

/// Upper bound on provisional bounces kept in memory; the oldest is committed
/// early when a burst exceeds it, so the queue can never grow without limit.
const MAX_PENDING_BOUNCES: usize = 256;

fn is_compressed_mode(mode: &str) -> bool {
    !matches!(mode, "full" | "diff")
}

fn extension_of(path: &str) -> String {
    path.rsplit('.')
        .next()
        .map(|e| format!(".{}", e.to_ascii_lowercase()))
        .unwrap_or_default()
}

impl BounceTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn next_seq(&mut self) -> u64 {
        self.seq_counter += 1;
        self.commit_due();
        self.seq_counter
    }

    pub fn set_seq(&mut self, seq: u64) {
        self.seq_counter = seq;
        self.commit_due();
    }

    pub fn record_read(
        &mut self,
        path: &str,
        mode: &str,
        tokens_sent: usize,
        original_tokens: usize,
    ) {
        let norm = crate::core::pathutil::normalize_tool_path(path);
        self.commit_due();
        let seq = self.seq_counter;
        let compressed = is_compressed_mode(mode);

        if !compressed {
            self.detect_bounce(&norm, seq);
        }
        if self.persist {
            // Keep the long-term majority rule honest: clean reads dilute
            // historical bounces (#496).
            crate::core::path_mode_memory::record_read_if_tracked(&norm);
        }

        let current = if self.persist {
            crate::core::context_store::task_signals::current_origin()
        } else {
            None
        };
        if let Some(current) = &current {
            // Bounces are seen only by the process that served the read: a
            // task served by several processes is not fully observed.
            crate::core::context_store::task_signals::observe(current);
        }
        let origin = current.filter(|_| compressed);
        let events = self.recent_reads.entry(norm).or_default();
        events.push(ReadEvent {
            _mode: mode.to_string(),
            tokens_sent,
            _original_tokens: original_tokens,
            seq,
            was_compressed: compressed,
            origin,
        });

        if events.len() > 10 {
            events.drain(..events.len() - 10);
        }

        let ext = extension_of(path);
        if !ext.is_empty() {
            let stats = self.per_extension.entry(ext).or_default();
            stats.total_reads += 1;
        }

        self.prune_stale_paths();
    }

    fn detect_bounce(&mut self, norm_path: &str, full_seq: u64) {
        // A full re-read the system itself forced after an edit is not a
        // compression failure (GL #622): `should_force_full` returns `full` for
        // EDIT_FORCE_WINDOW ticks post-edit, so the agent had no choice. Counting
        // it as a bounce would penalize the compression arm for the edit and
        // inflate the per-extension bounce rate until `should_force_full` pins the
        // whole extension to `full` — a self-reinforcing loss of compression.
        if let Some(&edit_seq) = self.recently_edited.get(norm_path)
            && full_seq.saturating_sub(edit_seq) <= EDIT_FORCE_WINDOW
        {
            return;
        }

        let Some(events) = self.recent_reads.get(norm_path) else {
            return;
        };

        if let Some(ev) = events.iter().next_back()
            && ev.was_compressed
            && full_seq.saturating_sub(ev.seq) <= BOUNCE_WINDOW
        {
            // Provisional until EDIT_FORCE_WINDOW passes without an edit of
            // this path (see `PendingBounce`).
            let pending = PendingBounce {
                path: norm_path.to_string(),
                seq: full_seq,
                wasted: ev.tokens_sent,
                origin: ev.origin.clone(),
                detected_unix_ms: now_unix_ms(),
            };
            self.pending.push(pending);
            if self.pending.len() > MAX_PENDING_BOUNCES {
                let oldest = self.pending.remove(0);
                self.commit(oldest);
            }
        }
    }

    /// Commit every provisional bounce whose edit window has passed. Called
    /// whenever the seq clock moves or a read/edit is recorded.
    fn commit_due(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let now = self.seq_counter;
        let (due, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending)
            .into_iter()
            .partition(|p| now.saturating_sub(p.seq) > EDIT_FORCE_WINDOW);
        self.pending = keep;
        for pending in due {
            self.commit(pending);
        }
    }

    /// Commit every provisional bounce now, regardless of its window. Used at
    /// process shutdown so a bounce detected shortly before exit is not lost.
    pub fn flush_pending(&mut self) {
        for pending in std::mem::take(&mut self.pending) {
            self.commit(pending);
        }
    }

    /// Provisional bounces still waiting for their edit window to pass.
    pub fn pending_bounces(&self) -> usize {
        self.pending.len()
    }

    /// Book one bounce: counters, per-extension stats and, for the
    /// process-global tracker, the ledger entry, path memory, quality signal
    /// and scent. A host edit another process reported for the path after the
    /// detection (edit beacon) cancels it instead.
    fn commit(&mut self, pending: PendingBounce) {
        if self.persist && host_edited_since(&pending.path, pending.detected_unix_ms) {
            return;
        }
        let PendingBounce {
            path: norm_path,
            wasted,
            origin,
            ..
        } = pending;
        self.total_bounces += 1;
        self.total_wasted_tokens += wasted;

        let ext = extension_of(&norm_path);
        if !ext.is_empty() {
            let stats = self.per_extension.entry(ext).or_default();
            stats.bounces += 1;
            stats.wasted_tokens += wasted;
        }

        if self.persist {
            crate::core::anti_interrupt::spawn_bounce_waste(wasted as u64);
            if let Some(origin) = origin {
                // Off this tracker's lock: recording waits on a file lock.
                std::thread::spawn(move || {
                    crate::core::context_store::task_signals::record(
                        &origin,
                        crate::core::context_store::task_signals::Signal::Bounce,
                    );
                });
            }
            crate::core::savings_ledger::record_bounce_event(wasted);
            // Long-term per-path memory (#496): remember which exact
            // files keep bouncing so auto-mode learns across restarts.
            crate::core::path_mode_memory::record_bounce(&norm_path);
            // Quality signal (#538): bounces push the learned entropy
            // threshold down for this extension (compress less) and
            // penalize the bandit arm that produced the read (#593).
            crate::core::adaptive_thresholds::record_quality_signal(
                &norm_path,
                crate::core::threshold_learning::QualitySignal::Bounce,
            );
            // Stigmergy (#540): a bounce marks this path as Stuck so
            // other agents see friction here. Background: lock may block.
            std::thread::spawn(move || {
                crate::core::scent_field::deposit(
                    crate::core::scent_field::scent_agent_id(),
                    crate::core::scent_field::ScentKind::Stuck,
                    &norm_path,
                    0.5,
                );
            });
        }
    }

    pub fn record_shell_file_access(&mut self, path: &str) {
        let norm = crate::core::pathutil::normalize_tool_path(path);
        self.commit_due();
        let seq = self.seq_counter;
        self.detect_bounce(&norm, seq);
    }

    /// Records an explicit archive/context expansion as a quality bounce.
    ///
    /// Unlike a full file re-read, `ctx_expand` may address a content handle
    /// rather than a path, so it cannot always be inferred by `detect_bounce`.
    /// Benchmark replay uses this method to keep the quality proxy on the same
    /// tracker as ordinary compressed-then-full bounces.
    pub fn record_expansion(&mut self, source: Option<&str>, wasted_tokens: usize) {
        self.total_bounces = self.total_bounces.saturating_add(1);
        self.total_wasted_tokens = self.total_wasted_tokens.saturating_add(wasted_tokens);

        if let Some(path) = source {
            let ext = extension_of(path);
            if !ext.is_empty() {
                let stats = self.per_extension.entry(ext).or_default();
                stats.bounces = stats.bounces.saturating_add(1);
                stats.wasted_tokens = stats.wasted_tokens.saturating_add(wasted_tokens);
            }
        }
    }

    /// The newest read of `path` this process still remembers: whether it
    /// was compressed and the scope and task it ran under, so a later event
    /// is charged to the read that caused it. `None`: no read is known here
    /// (another process, or before a restart).
    pub(crate) fn last_read(
        &self,
        path: &str,
    ) -> Option<(
        bool,
        Option<crate::core::context_store::task_signals::Origin>,
    )> {
        let norm = crate::core::pathutil::normalize_tool_path(path);
        let event = self.recent_reads.get(&norm)?.last()?;
        Some((event.was_compressed, event.origin.clone()))
    }

    /// An edit of `path`. Besides exempting the full re-reads it forces, it
    /// cancels any provisional bounce of the path still inside its edit
    /// window: the compressed→full re-read was the read-before-edit, not a
    /// compression failure.
    pub fn record_edit(&mut self, path: &str) {
        let norm = crate::core::pathutil::normalize_tool_path(path);
        self.commit_due();
        self.pending.retain(|p| p.path != norm);
        self.recently_edited.insert(norm, self.seq_counter);
        self.prune_stale_paths();
    }

    /// Evict outer-map entries whose newest seq is older than the detection windows —
    /// they can no longer affect bounce detection or `should_force_full`. Bounds the
    /// `recent_reads` / `recently_edited` maps on a long-lived process.
    fn prune_stale_paths(&mut self) {
        let seq = self.seq_counter;
        self.recent_reads.retain(|_, events| {
            events
                .last()
                .is_some_and(|e| seq.saturating_sub(e.seq) <= TRACKED_PATH_TTL_SEQ)
        });
        self.recently_edited
            .retain(|_, &mut edit_seq| seq.saturating_sub(edit_seq) <= TRACKED_PATH_TTL_SEQ);
    }

    pub fn should_force_full(&self, path: &str) -> bool {
        let norm = crate::core::pathutil::normalize_tool_path(path);

        if let Some(&edit_seq) = self.recently_edited.get(&norm)
            && self.seq_counter.saturating_sub(edit_seq) <= EDIT_FORCE_WINDOW
        {
            return true;
        }

        let ext = extension_of(path);
        if !ext.is_empty()
            && let Some(stats) = self.per_extension.get(&ext)
            && stats.total_reads >= 3
        {
            let rate = stats.bounces as f64 / stats.total_reads as f64;
            if rate >= BOUNCE_RATE_THRESHOLD {
                return true;
            }
        }

        false
    }

    pub fn bounce_rate_for_extension(&self, path: &str) -> Option<f64> {
        let ext = extension_of(path);
        self.per_extension.get(&ext).and_then(|s| {
            if s.total_reads >= 3 {
                Some(s.bounces as f64 / s.total_reads as f64)
            } else {
                None
            }
        })
    }

    pub fn total_bounces(&self) -> u64 {
        self.total_bounces
    }

    pub fn total_wasted_tokens(&self) -> usize {
        self.total_wasted_tokens
    }

    pub fn adjusted_savings(&self, raw_savings: usize) -> isize {
        raw_savings as isize - self.total_wasted_tokens as isize
    }

    pub fn per_extension_json(&self) -> Vec<serde_json::Value> {
        let mut exts: Vec<_> = self
            .per_extension
            .iter()
            .filter(|(_, s)| s.total_reads > 0)
            .collect();
        exts.sort_by_key(|a| std::cmp::Reverse(a.1.bounces));
        exts.iter()
            .take(10)
            .map(|(ext, stats)| {
                let rate = if stats.total_reads > 0 {
                    stats.bounces as f64 / stats.total_reads as f64
                } else {
                    0.0
                };
                serde_json::json!({
                    "ext": ext,
                    "reads": stats.total_reads,
                    "bounces": stats.bounces,
                    "wasted_tokens": stats.wasted_tokens,
                    "rate": (rate * 1000.0).round() / 1000.0,
                })
            })
            .collect()
    }

    pub fn format_summary(&self) -> String {
        if self.total_bounces == 0 {
            return "Bounces: 0".to_string();
        }
        let mut lines = vec![format!(
            "Bounces: {} ({} wasted tokens)",
            self.total_bounces, self.total_wasted_tokens
        )];
        let mut exts: Vec<_> = self
            .per_extension
            .iter()
            .filter(|(_, s)| s.bounces > 0)
            .collect();
        exts.sort_by_key(|a| std::cmp::Reverse(a.1.bounces));
        for (ext, stats) in exts.iter().take(5) {
            let rate = if stats.total_reads > 0 {
                stats.bounces as f64 / stats.total_reads as f64 * 100.0
            } else {
                0.0
            };
            lines.push(format!(
                "  {ext}: {}/{} reads bounced ({rate:.0}%), {} tok wasted",
                stats.bounces, stats.total_reads, stats.wasted_tokens,
            ));
        }
        lines.join("\n")
    }
}

static GLOBAL_TRACKER: OnceLock<Mutex<BounceTracker>> = OnceLock::new();

pub fn global() -> &'static Mutex<BounceTracker> {
    GLOBAL_TRACKER.get_or_init(|| {
        // Seed from the persistent ledger so every process (including a fresh `gain`)
        // accounts for historical bounce, then mark this tracker as the persisting one.
        let summary = crate::core::savings_ledger::summary();
        let mut bt = BounceTracker::new();
        bt.total_wasted_tokens = summary.bounce_tokens as usize;
        bt.total_bounces = summary.bounce_events as u64;
        bt.persist = true;
        Mutex::new(bt)
    })
}

/// Process shutdown: commit the global tracker's provisional bounces. A no-op
/// when this process never created the tracker (no read was served).
pub(crate) fn flush_pending() {
    if let Some(tracker) = GLOBAL_TRACKER.get()
        && let Ok(mut bt) = tracker.lock()
    {
        bt.flush_pending();
    }
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

// ── Edit beacon ─────────────────────────────────────────────────────────────
//
// Native host edits (Claude Code `Edit`/`Write`, Cursor `StrReplace`, …) are
// observed by short-lived hook processes, not by the MCP server that holds the
// in-memory tracker. They append `<unix_ms>\t<normalized path>` to a small
// append-only file; a provisional bounce consults it once, at commit time, and
// is cancelled when its path was edited after the detection. Lines are written
// with one `O_APPEND` write each, so concurrent hook processes do not
// interleave; the file rotates to `.1` above `EDIT_BEACON_MAX_BYTES`, and the
// reader scans both generations.

const EDIT_BEACON_FILE: &str = "edit_beacon.log";
const EDIT_BEACON_MAX_BYTES: u64 = 128 * 1024;

fn edit_beacon_path() -> Option<std::path::PathBuf> {
    crate::core::data_dir::lean_ctx_data_dir()
        .ok()
        .map(|dir| dir.join(EDIT_BEACON_FILE))
}

fn rotated_beacon_path(path: &std::path::Path) -> std::path::PathBuf {
    path.with_extension("log.1")
}

/// Hook processes: report a native host edit of `path` (best-effort).
pub(crate) fn note_host_edit(path: &str) {
    let Some(beacon) = edit_beacon_path() else {
        return;
    };
    append_edit_beacon(&beacon, path, now_unix_ms());
}

fn append_edit_beacon(beacon: &std::path::Path, path: &str, unix_ms: u64) {
    use std::io::Write;
    let norm = crate::core::pathutil::normalize_tool_path(path);
    if norm.is_empty() || norm.contains('\n') {
        return;
    }
    if std::fs::metadata(beacon).is_ok_and(|m| m.len() > EDIT_BEACON_MAX_BYTES) {
        let _ = std::fs::rename(beacon, rotated_beacon_path(beacon));
    }
    if let Some(parent) = beacon.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(beacon)
    {
        let _ = file.write_all(format!("{unix_ms}\t{norm}\n").as_bytes());
    }
}

fn host_edited_since(norm_path: &str, since_unix_ms: u64) -> bool {
    edit_beacon_path().is_some_and(|beacon| beacon_has_edit(&beacon, norm_path, since_unix_ms))
}

fn beacon_has_edit(beacon: &std::path::Path, norm_path: &str, since_unix_ms: u64) -> bool {
    use std::io::Read;
    [rotated_beacon_path(beacon), beacon.to_path_buf()]
        .iter()
        .any(|file| {
            let Ok(handle) = std::fs::File::open(file) else {
                return false;
            };
            let mut raw = String::new();
            // Bounded: rotation keeps each generation near EDIT_BEACON_MAX_BYTES.
            if handle
                .take(EDIT_BEACON_MAX_BYTES * 2)
                .read_to_string(&mut raw)
                .is_err()
            {
                return false;
            }
            raw.lines().any(|line| {
                line.split_once('\t').is_some_and(|(ts, path)| {
                    path == norm_path && ts.parse::<u64>().is_ok_and(|ts| ts >= since_unix_ms)
                })
            })
        })
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn no_bounce_when_first_read_is_full() {
        let mut bt = BounceTracker::new();
        bt.seq_counter = 1;
        bt.record_read("src/main.rs", "full", 500, 500);
        assert_eq!(bt.total_bounces(), 0);
        assert_eq!(bt.total_wasted_tokens(), 0);
    }

    #[test]
    fn bounce_detected_on_compressed_then_full() {
        let mut bt = BounceTracker::new();
        bt.seq_counter = 1;
        bt.record_read("src/main.rs", "map", 50, 500);
        bt.seq_counter = 2;
        bt.record_read("src/main.rs", "full", 500, 500);
        assert_eq!(
            bt.pending_bounces(),
            1,
            "provisional until the edit window passes"
        );
        bt.flush_pending();
        assert_eq!(bt.total_bounces(), 1);
        assert_eq!(bt.total_wasted_tokens(), 50);
    }

    #[test]
    fn no_bounce_outside_window() {
        let mut bt = BounceTracker::new();
        bt.seq_counter = 1;
        bt.record_read("src/main.rs", "map", 50, 500);
        bt.seq_counter = 10;
        bt.record_read("src/main.rs", "full", 500, 500);
        assert_eq!(bt.total_bounces(), 0);
    }

    #[test]
    fn shell_access_triggers_bounce() {
        let mut bt = BounceTracker::new();
        bt.seq_counter = 1;
        bt.record_read("config.yml", "signatures", 30, 400);
        bt.seq_counter = 3;
        bt.record_shell_file_access("config.yml");
        bt.flush_pending();
        assert_eq!(bt.total_bounces(), 1);
        assert_eq!(bt.total_wasted_tokens(), 30);
    }

    #[test]
    fn explicit_expansion_tracks_quality_and_waste() {
        let mut bt = BounceTracker::new();
        bt.record_expansion(Some("src/main.rs"), 125);
        assert_eq!(bt.total_bounces(), 1);
        assert_eq!(bt.total_wasted_tokens(), 125);
    }

    #[test]
    fn edit_forced_full_read_is_not_a_bounce() {
        // GL #622: a compressed overview read, then an edit, then the `full`
        // re-read that `should_force_full` mandates must NOT register as a bounce
        // — the edit forced it, the compression did not fail.
        let mut bt = BounceTracker::new();
        bt.seq_counter = 1;
        bt.record_read("src/lib.rs", "map", 40, 500);
        bt.seq_counter = 2;
        bt.record_edit("src/lib.rs");
        bt.seq_counter = 4;
        bt.record_read("src/lib.rs", "full", 500, 500);
        assert_eq!(
            bt.total_bounces(),
            0,
            "edit-forced full read must not count as a compression bounce"
        );
    }

    #[test]
    fn full_read_without_edit_still_bounces() {
        // The guard is scoped to edit-forced reads only: an unprompted full
        // re-read after a compressed read is still a real bounce.
        let mut bt = BounceTracker::new();
        bt.seq_counter = 1;
        bt.record_read("src/lib.rs", "map", 40, 500);
        bt.seq_counter = 3;
        bt.record_read("src/lib.rs", "full", 500, 500);
        bt.flush_pending();
        assert_eq!(bt.total_bounces(), 1);
    }

    #[test]
    fn should_force_full_after_edit() {
        let mut bt = BounceTracker::new();
        bt.seq_counter = 5;
        bt.record_edit("src/lib.rs");
        bt.seq_counter = 8;
        assert!(bt.should_force_full("src/lib.rs"));
        bt.seq_counter = 20;
        assert!(!bt.should_force_full("src/lib.rs"));
    }

    #[test]
    fn should_force_full_by_extension_bounce_rate() {
        let mut bt = BounceTracker::new();
        for i in 1..=6 {
            bt.seq_counter = i * 2 - 1;
            bt.record_read(&format!("f{i}.yml"), "map", 30, 400);
            bt.seq_counter = i * 2;
            bt.record_read(&format!("f{i}.yml"), "full", 400, 400);
        }
        bt.flush_pending();
        assert!(bt.should_force_full("new.yml"));
    }

    #[test]
    fn adjusted_savings_subtracts_waste() {
        let mut bt = BounceTracker::new();
        bt.seq_counter = 1;
        bt.record_read("a.rs", "map", 50, 500);
        bt.seq_counter = 2;
        bt.record_read("a.rs", "full", 500, 500);
        bt.flush_pending();
        assert_eq!(bt.adjusted_savings(1000), 950);
    }

    #[test]
    fn bounce_rate_for_extension_below_minimum() {
        let bt = BounceTracker::new();
        assert!(bt.bounce_rate_for_extension("test.rs").is_none());
    }

    #[test]
    fn format_summary_empty() {
        let bt = BounceTracker::new();
        assert_eq!(bt.format_summary(), "Bounces: 0");
    }

    #[test]
    fn map_full_edit_is_not_a_bounce() {
        // Read-before-edit: orient compressed, read full, edit. The full read
        // was the edit's preparation, not a compression failure.
        let mut bt = BounceTracker::new();
        bt.next_seq();
        bt.record_read("src/edit_me.rs", "map", 40, 500);
        bt.next_seq();
        bt.record_read("src/edit_me.rs", "full", 500, 500);
        assert_eq!(bt.pending_bounces(), 1);
        for _ in 0..3 {
            bt.next_seq();
        }
        bt.record_edit("src/edit_me.rs");
        assert_eq!(
            bt.pending_bounces(),
            0,
            "the edit cancels the provisional bounce"
        );
        for _ in 0..(EDIT_FORCE_WINDOW + 5) {
            bt.next_seq();
        }
        bt.flush_pending();
        assert_eq!(bt.total_bounces(), 0);
        assert_eq!(bt.total_wasted_tokens(), 0);
    }

    #[test]
    fn map_full_without_edit_commits_when_window_passes() {
        let mut bt = BounceTracker::new();
        bt.next_seq();
        bt.record_read("src/only_read.rs", "map", 40, 500);
        bt.next_seq();
        bt.record_read("src/only_read.rs", "full", 500, 500);
        for _ in 0..EDIT_FORCE_WINDOW {
            bt.next_seq();
        }
        assert_eq!(bt.total_bounces(), 0, "still inside the edit window");
        bt.next_seq();
        assert_eq!(bt.pending_bounces(), 0);
        assert_eq!(bt.total_bounces(), 1, "committed once the window passed");
        assert_eq!(bt.total_wasted_tokens(), 40);
        // An edit after the window no longer changes the booked bounce.
        bt.record_edit("src/only_read.rs");
        assert_eq!(bt.total_bounces(), 1);
    }

    #[test]
    fn edit_of_another_path_keeps_the_bounce() {
        let mut bt = BounceTracker::new();
        bt.next_seq();
        bt.record_read("src/a.rs", "map", 40, 500);
        bt.next_seq();
        bt.record_read("src/a.rs", "full", 500, 500);
        bt.record_edit("src/b.rs");
        bt.flush_pending();
        assert_eq!(bt.total_bounces(), 1);
    }

    #[test]
    fn flush_pending_commits_at_shutdown() {
        let mut bt = BounceTracker::new();
        bt.next_seq();
        bt.record_read("src/late.rs", "signatures", 25, 300);
        bt.next_seq();
        bt.record_read("src/late.rs", "full", 300, 300);
        assert_eq!(bt.total_bounces(), 0);
        bt.flush_pending();
        assert_eq!(bt.pending_bounces(), 0);
        assert_eq!(bt.total_bounces(), 1);
        assert_eq!(bt.total_wasted_tokens(), 25);
    }

    #[test]
    fn pending_queue_is_bounded() {
        let mut bt = BounceTracker::new();
        for i in 0..(MAX_PENDING_BOUNCES + 4) {
            let path = format!("src/burst{i}.rs");
            bt.record_read(&path, "map", 10, 100);
            bt.record_read(&path, "full", 100, 100);
        }
        assert_eq!(bt.pending_bounces(), MAX_PENDING_BOUNCES);
        assert_eq!(bt.total_bounces(), 4, "overflow commits the oldest early");
    }

    #[test]
    fn edit_beacon_reports_host_edits_after_detection() {
        let dir = tempfile::tempdir().unwrap();
        let beacon = dir.path().join(EDIT_BEACON_FILE);
        let file = dir.path().join("edited.rs");
        std::fs::write(&file, "fn main() {}\n").unwrap();
        let path = file.to_string_lossy().to_string();
        let norm = crate::core::pathutil::normalize_tool_path(&path);

        assert!(!beacon_has_edit(&beacon, &norm, 0), "no beacon yet");
        append_edit_beacon(&beacon, &path, 2_000);
        assert!(
            beacon_has_edit(&beacon, &norm, 1_500),
            "edit after detection"
        );
        assert!(
            !beacon_has_edit(&beacon, &norm, 2_500),
            "edit before detection"
        );
        assert!(!beacon_has_edit(&beacon, "/other/path.rs", 0));
    }

    #[test]
    fn edit_beacon_rotation_keeps_the_previous_generation_readable() {
        let dir = tempfile::tempdir().unwrap();
        let beacon = dir.path().join(EDIT_BEACON_FILE);
        append_edit_beacon(&beacon, "/rotated/first.rs", 10);
        let filler = "x".repeat(usize::try_from(EDIT_BEACON_MAX_BYTES).unwrap() + 1);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&beacon)
            .and_then(|mut f| std::io::Write::write_all(&mut f, filler.as_bytes()))
            .unwrap();
        append_edit_beacon(&beacon, "/rotated/second.rs", 20);
        assert!(rotated_beacon_path(&beacon).exists());
        assert!(beacon_has_edit(&beacon, "/rotated/first.rs", 0));
        assert!(beacon_has_edit(&beacon, "/rotated/second.rs", 0));
    }
}
