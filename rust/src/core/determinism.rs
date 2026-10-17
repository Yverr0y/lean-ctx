//! Byte-stable replay and versioned provider prompt-cache evidence (#1194).
//! Economics use the four-class [`ModelPricing`] rate table.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::bounce_tracker::BounceTracker;
use super::gain::model_pricing::ModelPricing;

pub const DEFAULT_CACHE_HIT_RATE_THRESHOLD: f64 = 0.80;
pub const MIN_CACHE_HIT_SAMPLES: u64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheHeaderObservation {
    pub hit: bool,
    pub cache_read_tokens: u64,
}

impl CacheHeaderObservation {
    /// Parses the cache evidence exposed by Anthropic and HTTP cache gateways.
    /// A positive token count is authoritative if headers disagree.
    pub fn from_header_values(
        x_cache: Option<&str>,
        anthropic_read_tokens: Option<&str>,
    ) -> Option<Self> {
        let token_signal = anthropic_read_tokens.and_then(|raw| raw.trim().parse::<u64>().ok());
        let x_cache_signal = x_cache.and_then(parse_x_cache);
        if token_signal.is_none() && x_cache_signal.is_none() {
            return None;
        }
        let cache_read_tokens = token_signal.unwrap_or(0);
        Some(Self {
            hit: cache_read_tokens > 0 || x_cache_signal.unwrap_or(false),
            cache_read_tokens,
        })
    }
}

fn parse_x_cache(raw: &str) -> Option<bool> {
    let normalized = raw.to_ascii_lowercase();
    if normalized
        .split([',', ' '])
        .any(|part| part.contains("hit"))
    {
        Some(true)
    } else if normalized
        .split([',', ' '])
        .any(|part| part.contains("miss"))
    {
        Some(false)
    } else {
        None
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheCounters {
    pub requests: u64,
    pub hits: u64,
    pub misses: u64,
    pub cache_read_tokens: u64,
}

impl CacheCounters {
    pub fn hit_rate(&self) -> Option<f64> {
        let classified = self.hits.saturating_add(self.misses);
        (classified > 0).then(|| self.hits as f64 / classified as f64)
    }

    fn record(&mut self, observation: CacheHeaderObservation) {
        self.requests = self.requests.saturating_add(1);
        if observation.hit {
            self.hits = self.hits.saturating_add(1);
        } else {
            self.misses = self.misses.saturating_add(1);
        }
        self.cache_read_tokens = self
            .cache_read_tokens
            .saturating_add(observation.cache_read_tokens);
    }

    fn add_delta(&mut self, current: &Self, baseline: &Self) {
        self.requests = self
            .requests
            .saturating_add(current.requests.saturating_sub(baseline.requests));
        self.hits = self
            .hits
            .saturating_add(current.hits.saturating_sub(baseline.hits));
        self.misses = self
            .misses
            .saturating_add(current.misses.saturating_sub(baseline.misses));
        self.cache_read_tokens = self.cache_read_tokens.saturating_add(
            current
                .cache_read_tokens
                .saturating_sub(baseline.cache_read_tokens),
        );
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderCacheStats {
    pub total: CacheCounters,
    pub by_version: BTreeMap<String, CacheCounters>,
    pub by_model: BTreeMap<String, CacheCounters>,
}

impl ProviderCacheStats {
    pub fn record(
        &mut self,
        version: &str,
        model: Option<&str>,
        observation: CacheHeaderObservation,
    ) {
        self.total.record(observation);
        self.by_version
            .entry(version.to_string())
            .or_default()
            .record(observation);
        self.by_model
            .entry(normalize_model(model))
            .or_default()
            .record(observation);
    }

    pub fn regression_after_update(
        &self,
        previous_version: &str,
        current_version: &str,
        threshold: f64,
    ) -> Option<CacheRegressionAlert> {
        let previous = self.by_version.get(previous_version)?;
        let current = self.by_version.get(current_version)?;
        if previous.requests < MIN_CACHE_HIT_SAMPLES || current.requests < MIN_CACHE_HIT_SAMPLES {
            return None;
        }
        let previous_rate = previous.hit_rate()?;
        let current_rate = current.hit_rate()?;
        (current_rate < threshold && current_rate < previous_rate).then_some(CacheRegressionAlert {
            previous_version: previous_version.to_string(),
            current_version: current_version.to_string(),
            previous_rate,
            current_rate,
            threshold,
        })
    }

    pub fn economics(
        &self,
        pricing: &ModelPricing,
        model: Option<&str>,
        bounce_tracker: &BounceTracker,
    ) -> CacheEconomics {
        let counters = model
            .and_then(|name| self.by_model.get(&normalize_model(Some(name))))
            .unwrap_or(&self.total);
        let cost = pricing.quote(model).cost;
        let tokens = counters.cache_read_tokens;
        let bounce_tokens = u64::try_from(bounce_tracker.total_wasted_tokens()).unwrap_or(u64::MAX);
        CacheEconomics {
            actual_cache_read_usd: cost.estimate_usd(0, 0, 0, tokens),
            uncached_input_usd: cost.estimate_usd(tokens, 0, 0, 0),
            cold_cache_write_usd: cost.estimate_usd(0, 0, tokens, 0),
            bounce_input_usd: cost.estimate_usd(bounce_tokens, 0, 0, 0),
        }
    }

    pub fn merge_delta(&mut self, current: &Self, baseline: &Self) {
        self.total.add_delta(&current.total, &baseline.total);
        merge_counter_maps(
            &mut self.by_version,
            &current.by_version,
            &baseline.by_version,
        );
        merge_counter_maps(&mut self.by_model, &current.by_model, &baseline.by_model);
    }
}

fn normalize_model(model: Option<&str>) -> String {
    model
        .map(str::trim)
        .filter(|model| !model.is_empty())
        .unwrap_or("unknown")
        .to_ascii_lowercase()
}

fn merge_counter_maps(
    merged: &mut BTreeMap<String, CacheCounters>,
    current: &BTreeMap<String, CacheCounters>,
    baseline: &BTreeMap<String, CacheCounters>,
) {
    for (key, value) in current {
        let base = baseline.get(key).cloned().unwrap_or_default();
        merged
            .entry(key.clone())
            .or_default()
            .add_delta(value, &base);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CacheRegressionAlert {
    pub previous_version: String,
    pub current_version: String,
    pub previous_rate: f64,
    pub current_rate: f64,
    pub threshold: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CacheEconomics {
    pub actual_cache_read_usd: f64,
    pub uncached_input_usd: f64,
    pub cold_cache_write_usd: f64,
    pub bounce_input_usd: f64,
}

impl CacheEconomics {
    pub fn lost_input_discount_usd(self) -> f64 {
        self.uncached_input_usd - self.actual_cache_read_usd
    }

    pub fn cold_write_penalty_usd(self) -> f64 {
        self.cold_cache_write_usd - self.actual_cache_read_usd
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayReport {
    pub sessions: usize,
    pub matching_sessions: usize,
    pub first_mismatch: Option<usize>,
    pub output_digest: String,
}

impl ReplayReport {
    pub fn byte_stable(&self) -> bool {
        self.sessions > 0 && self.matching_sessions == self.sessions
    }
}

/// Replays identical input `sessions` times and compares every output with the
/// committed expected bytes. The digest is content-only and version-independent.
pub fn replay_sessions<I, F>(
    input: &I,
    expected: &[u8],
    sessions: usize,
    mut render: F,
) -> ReplayReport
where
    F: FnMut(&I) -> Vec<u8>,
{
    let mut matching_sessions = 0;
    let mut first_mismatch = None;
    for session in 0..sessions {
        if render(input) == expected {
            matching_sessions += 1;
        } else if first_mismatch.is_none() {
            first_mismatch = Some(session);
        }
    }
    ReplayReport {
        sessions,
        matching_sessions,
        first_mismatch,
        output_digest: blake3::hash(expected).to_hex().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_close(actual: f64, expected: f64) {
        assert!((actual - expected).abs() < 1e-12, "{actual} != {expected}");
    }

    #[test]
    fn determinism_replays_identical_input_byte_for_byte() {
        let report = replay_sessions(&"alpha", b"ALPHA", 32, |input| {
            input.to_ascii_uppercase().into_bytes()
        });
        assert!(report.byte_stable());
        assert_eq!(report.matching_sessions, 32);
        assert_eq!(report.first_mismatch, None);
    }

    #[test]
    fn determinism_committed_baseline_detects_version_regression() {
        let report = replay_sessions(&"same-input", b"v1:same-input", 5, |input| {
            format!("v2:{input}").into_bytes()
        });
        assert!(!report.byte_stable());
        assert_eq!(report.first_mismatch, Some(0));
    }

    #[test]
    fn determinism_x_cache_and_anthropic_headers_are_classified() {
        let hit =
            CacheHeaderObservation::from_header_values(Some("Hit from cloudfront"), Some("200000"))
                .unwrap();
        let miss = CacheHeaderObservation::from_header_values(Some("MISS"), Some("0")).unwrap();
        assert_eq!(
            hit,
            CacheHeaderObservation {
                hit: true,
                cache_read_tokens: 200_000
            }
        );
        assert!(!miss.hit);
        assert!(CacheHeaderObservation::from_header_values(Some("unknown"), None).is_none());
    }

    #[test]
    fn determinism_token_evidence_wins_over_conflicting_x_cache() {
        let observation =
            CacheHeaderObservation::from_header_values(Some("MISS"), Some("1000")).unwrap();
        assert!(observation.hit);
        assert_eq!(observation.cache_read_tokens, 1_000);
    }

    #[test]
    fn determinism_alerts_when_update_drops_below_threshold() {
        let mut stats = ProviderCacheStats::default();
        for _ in 0..9 {
            stats.record(
                "1.0.0",
                None,
                CacheHeaderObservation {
                    hit: true,
                    cache_read_tokens: 1_000,
                },
            );
        }
        stats.record(
            "1.0.0",
            None,
            CacheHeaderObservation {
                hit: false,
                cache_read_tokens: 0,
            },
        );
        for _ in 0..7 {
            stats.record(
                "1.1.0",
                None,
                CacheHeaderObservation {
                    hit: true,
                    cache_read_tokens: 1_000,
                },
            );
        }
        for _ in 0..3 {
            stats.record(
                "1.1.0",
                None,
                CacheHeaderObservation {
                    hit: false,
                    cache_read_tokens: 0,
                },
            );
        }
        let alert = stats
            .regression_after_update("1.0.0", "1.1.0", DEFAULT_CACHE_HIT_RATE_THRESHOLD)
            .unwrap();
        assert_close(alert.previous_rate, 0.9);
        assert_close(alert.current_rate, 0.7);
    }

    #[test]
    fn determinism_no_alert_when_rate_stays_above_threshold() {
        let mut stats = ProviderCacheStats::default();
        for version in ["1.0.0", "1.1.0"] {
            for _ in 0..9 {
                stats.record(
                    version,
                    None,
                    CacheHeaderObservation {
                        hit: true,
                        cache_read_tokens: 1_000,
                    },
                );
            }
            stats.record(
                version,
                None,
                CacheHeaderObservation {
                    hit: false,
                    cache_read_tokens: 0,
                },
            );
        }
        assert!(
            stats
                .regression_after_update("1.0.0", "1.1.0", DEFAULT_CACHE_HIT_RATE_THRESHOLD)
                .is_none()
        );
    }

    #[test]
    fn determinism_alert_waits_for_real_sample_size() {
        let mut stats = ProviderCacheStats::default();
        for _ in 0..MIN_CACHE_HIT_SAMPLES {
            stats.record(
                "1.0.0",
                None,
                CacheHeaderObservation {
                    hit: true,
                    cache_read_tokens: 1_000,
                },
            );
        }
        stats.record(
            "1.1.0",
            None,
            CacheHeaderObservation {
                hit: false,
                cache_read_tokens: 0,
            },
        );
        assert!(
            stats
                .regression_after_update("1.0.0", "1.1.0", DEFAULT_CACHE_HIT_RATE_THRESHOLD)
                .is_none()
        );
    }

    #[test]
    fn determinism_economics_prices_all_cache_classes_in_usd() {
        let mut stats = ProviderCacheStats::default();
        stats.record(
            "1.0.0",
            Some("claude-opus-4.5"),
            CacheHeaderObservation {
                hit: true,
                cache_read_tokens: 1_000_000,
            },
        );
        let economics = stats.economics(
            &ModelPricing::embedded(),
            Some("claude-opus-4.5"),
            &BounceTracker::new(),
        );
        assert_close(economics.actual_cache_read_usd, 0.50);
        assert_close(economics.uncached_input_usd, 5.00);
        assert_close(economics.cold_cache_write_usd, 6.25);
        assert_close(economics.lost_input_discount_usd(), 4.50);
        assert_close(economics.cold_write_penalty_usd(), 5.75);
    }

    #[test]
    fn determinism_economics_charges_bounce_tokens_as_new_input() {
        let mut bounce = BounceTracker::new();
        bounce.next_seq();
        bounce.record_read("src/lib.rs", "map", 100_000, 1_000_000);
        bounce.next_seq();
        bounce.record_read("src/lib.rs", "full", 1_000_000, 1_000_000);
        bounce.flush_pending();
        let economics = ProviderCacheStats::default().economics(
            &ModelPricing::embedded(),
            Some("claude-opus-4.5"),
            &bounce,
        );
        assert_close(economics.bounce_input_usd, 0.50);
    }

    #[test]
    fn determinism_delta_merge_does_not_double_count_persisted_headers() {
        let hit = CacheHeaderObservation {
            hit: true,
            cache_read_tokens: 2_000,
        };
        let mut disk = ProviderCacheStats::default();
        disk.record("1.0.0", Some("claude-opus-4.5"), hit);
        let baseline = disk.clone();
        let mut current = baseline.clone();
        current.record("1.0.0", Some("claude-opus-4.5"), hit);
        disk.merge_delta(&current, &baseline);
        assert_eq!(disk.total.requests, 2);
        assert_eq!(disk.total.cache_read_tokens, 4_000);
    }

    #[test]
    fn determinism_savings_footer_is_stable_for_identical_inputs() {
        let _lock = crate::core::data_dir::test_env_lock();
        crate::test_env::set_var("LEAN_CTX_COMPRESSION_ANNOTATION", "quantized");
        crate::test_env::set_var("LEAN_CTX_SAVINGS_FOOTER", "always");
        crate::test_env::set_var("LEAN_CTX_SHOW_SAVINGS", "1");
        crate::test_env::remove_var("LEAN_CTX_QUIET");
        crate::core::protocol::set_mcp_context(false);

        let input = (1000usize, 400usize);
        let expected = crate::core::protocol::format_savings(input.0, input.1);

        let report = replay_sessions(&input, expected.as_bytes(), 10, |&(orig, comp)| {
            crate::core::protocol::format_savings(orig, comp).into_bytes()
        });
        assert!(
            report.byte_stable(),
            "savings footer must be byte-identical across sessions (mismatch at {:?})",
            report.first_mismatch
        );

        crate::test_env::remove_var("LEAN_CTX_COMPRESSION_ANNOTATION");
        crate::test_env::remove_var("LEAN_CTX_SAVINGS_FOOTER");
        crate::test_env::remove_var("LEAN_CTX_SHOW_SAVINGS");
    }

    #[test]
    fn determinism_quantized_footer_reduces_unique_variants() {
        let _lock = crate::core::data_dir::test_env_lock();
        crate::test_env::set_var("LEAN_CTX_SAVINGS_FOOTER", "always");
        crate::test_env::set_var("LEAN_CTX_SHOW_SAVINGS", "1");
        crate::test_env::remove_var("LEAN_CTX_QUIET");
        crate::core::protocol::set_mcp_context(false);

        crate::test_env::set_var("LEAN_CTX_COMPRESSION_ANNOTATION", "full");
        let full_variants: std::collections::HashSet<String> = (10..=90)
            .map(|pct| {
                let comp = 100 - pct;
                crate::core::protocol::format_savings(100, comp)
            })
            .collect();

        crate::test_env::set_var("LEAN_CTX_COMPRESSION_ANNOTATION", "quantized");
        let quantized_variants: std::collections::HashSet<String> = (10..=90)
            .map(|pct| {
                let comp = 100 - pct;
                crate::core::protocol::format_savings(100, comp)
            })
            .collect();

        assert!(
            quantized_variants.len() < full_variants.len(),
            "quantized ({}) must produce fewer unique variants than full ({})",
            quantized_variants.len(),
            full_variants.len()
        );

        crate::test_env::remove_var("LEAN_CTX_COMPRESSION_ANNOTATION");
        crate::test_env::remove_var("LEAN_CTX_SAVINGS_FOOTER");
        crate::test_env::remove_var("LEAN_CTX_SHOW_SAVINGS");
    }

    #[test]
    fn determinism_auto_mode_resolver_is_pure_for_identical_inputs() {
        let _lock = crate::core::data_dir::test_env_lock();
        let dir = std::env::temp_dir().join(format!("lctx-det-amr-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        crate::test_env::set_var("LEAN_CTX_DATA_DIR", dir.to_str().unwrap());
        crate::test_env::remove_var("LEAN_CTX_AUTO_MODE_LEARNING");

        let ctx = crate::core::auto_mode_resolver::AutoModeContext {
            path: "src/widget.rs",
            token_count: 3000,
            line_count: Some(750),
            task: None,
            cache: None,
        };
        let first = crate::core::auto_mode_resolver::resolve(&ctx);
        let second = crate::core::auto_mode_resolver::resolve(&ctx);
        assert_eq!(
            (first.mode.as_str(), first.source),
            (second.mode.as_str(), second.source),
            "auto-mode must be deterministic for identical inputs"
        );

        crate::test_env::remove_var("LEAN_CTX_DATA_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn determinism_serialization_is_stable_across_insertion_order() {
        let hit = CacheHeaderObservation {
            hit: true,
            cache_read_tokens: 100,
        };
        let mut left = ProviderCacheStats::default();
        left.record("2.0.0", Some("b"), hit);
        left.record("1.0.0", Some("a"), hit);
        let mut right = ProviderCacheStats::default();
        right.record("1.0.0", Some("a"), hit);
        right.record("2.0.0", Some("b"), hit);
        assert_eq!(
            serde_json::to_vec(&left).unwrap(),
            serde_json::to_vec(&right).unwrap()
        );
    }
}
