//! LLM reverse proxy — the core of the **Gateway pillar**.
//!
//! Intercepts Anthropic, OpenAI, Gemini and ChatGPT traffic, compresses
//! prompts, meters usage, and optionally translates request shapes.
//!
//! # TLS Requirements
//!
//! The proxy does NOT terminate TLS. For production/multi-tenant deployments,
//! place behind a TLS-terminating reverse proxy (nginx, caddy, traefik).
//! For mTLS, configure the reverse proxy with client certificates.
//! See: <https://github.com/yvgude/lean-ctx/issues/1371>
//!
//! # Org gateway coupling (ADR-023)
//!
//! The self-hosted org gateway (lean-ctx-enterprise) extends this proxy with
//! admin/usage-store routes. In the OSS build the proxy runs standalone.

pub mod adaptive_policy;
pub(crate) mod agent_compact;
#[cfg(feature = "http-server")]
pub mod anthropic;
#[cfg(all(test, feature = "http-server"))]
mod auth_tests;
pub mod auto_routing;
#[cfg(feature = "http-server")]
pub mod bedrock;
pub mod break_even;
pub mod cache_aligner;
pub mod cache_attribution;
pub mod cache_breakpoint;
pub mod cache_policy;
pub mod cache_safety;
pub mod ccr;
#[cfg(all(test, feature = "http-server"))]
mod ccr_robustness_tests;
#[cfg(feature = "http-server")]
pub mod chatgpt;
pub mod chatgpt_cookies;
#[cfg(feature = "http-server")]
pub mod chatgpt_ws;
pub mod circuit_breaker;
#[cfg(feature = "http-server")]
mod codec;
pub mod cold_prefix;
pub mod compress;
pub mod compress_api;
pub mod compress_shared;
pub mod compression_savings;
#[cfg(feature = "http-server")]
mod connector;
pub(crate) mod conversation;
pub mod cost;
pub mod counterfactual;
#[allow(dead_code)]
pub mod dedup;
#[allow(warnings)]
pub mod determinism_guard;
pub mod effort;
pub mod effort_routing;
pub mod eligibility;
#[cfg(feature = "http-server")]
pub mod forward;
#[cfg(feature = "enterprise")]
pub mod gateway_identity;
#[cfg(feature = "http-server")]
pub mod google;
pub mod history_prune;
pub mod holdout;
#[cfg(all(test, feature = "http-server"))]
mod host_journey_tests;
pub mod image_compression;
pub mod inference_manifest_operator;
#[cfg(all(test, feature = "http-server"))]
mod integration_tests;
#[cfg(feature = "http-server")]
mod intent;
pub mod introspect;
pub mod latency_guard;
pub mod leaderboard;
#[cfg(feature = "http-server")]
mod lineage;
pub mod metrics;
#[cfg(feature = "http-server")]
pub mod models_api;
#[cfg(feature = "http-server")]
pub mod ocla_cache_bridge;
#[cfg(feature = "http-server")]
pub mod openai;
#[cfg(feature = "http-server")]
pub mod openai_responses;
#[cfg(feature = "http-server")]
pub mod openai_responses_ws;
pub mod outbound_model_policy;
pub mod output_savings;
pub mod pii;
pub mod pipeline_bench;
#[cfg(feature = "enterprise")]
pub mod policy_gate;
pub mod pre_optimize;
pub mod prefix_cache_stats;
pub mod prefix_replay;
pub mod prose;
#[allow(warnings)]
pub mod prose_compress;
pub mod prose_patterns;
pub mod prose_ranker;
pub(crate) mod provider_headers;
#[cfg(feature = "http-server")]
pub mod providers;
#[cfg(feature = "http-server")]
pub mod quality_lab_api;
pub mod reasoning_budget;
#[cfg(all(test, feature = "http-server"))]
mod reference_tests;
pub mod response_optimizer;
#[allow(dead_code)]
pub(crate) mod response_shaper;
pub mod rollout;
pub mod routing;
#[doc(hidden)]
#[cfg(feature = "http-server")]
pub mod sensitive_transport;
#[cfg(feature = "shape-xlat")]
pub mod shape_xlat;
#[allow(dead_code)]
pub(crate) mod shaping_hook;
#[cfg(feature = "http-server")]
pub mod sse_keepalive;
#[cfg(all(test, feature = "http-server"))]
mod stats_tests;
pub mod sticky_tools;
pub mod tool_kind;
#[allow(dead_code)]
pub mod tool_output;
#[cfg(all(test, feature = "http-server"))]
mod upstream_tests;
pub mod usage;
#[cfg(feature = "http-server")]
pub mod usage_accounting;
#[cfg(feature = "http-server")]
pub mod usage_azure;
pub mod usage_meter;
pub mod usage_parity;
pub mod usage_sink;
pub mod value_gate_proxy;
pub mod verbosity;
#[cfg(all(test, feature = "http-server"))]
mod via_p0_characterization_tests;
#[cfg(feature = "http-server")]
pub mod web_app;
#[allow(dead_code)]
#[cfg(feature = "http-server")]
pub(crate) mod web_app_middleware;

pub mod connector_schedule;
#[allow(warnings)]
pub mod live_zone;

// The HTTP proxy server: state, router, middleware and handlers. Everything
// above builds without `http-server` (#586); this half needs axum.
#[cfg(feature = "http-server")]
mod server;
#[cfg(feature = "http-server")]
pub use server::*;
