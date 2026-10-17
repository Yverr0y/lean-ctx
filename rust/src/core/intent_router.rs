use serde::Serialize;

use crate::core::context_ledger::PressureAction;
use crate::core::intent_engine::{IntentDimension, ModelTier, TaskType, classify, route_intent};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct IntentRouteV1 {
    pub schema_version: u32,
    pub created_at: String,
    pub inputs: IntentRouteInputsV1,
    pub decision: IntentRouteDecisionV1,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct IntentRouteInputsV1 {
    pub query_md5: String,
    pub query_redacted: String,
    pub role: String,
    pub profile: String,
    pub task_type: TaskType,
    pub confidence: f64,
    pub dimension: IntentDimension,
    pub pressure: PressureSummaryV1,
    pub policy_md5: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct PressureSummaryV1 {
    pub utilization_pct: u8,
    pub remaining_tokens: usize,
    pub action: PressureActionV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PressureActionV1 {
    NoAction,
    SuggestCompression,
    ForceCompression,
    EvictLeastRelevant,
}

impl PressureActionV1 {
    fn from_action(a: PressureAction) -> Self {
        match a {
            PressureAction::NoAction => Self::NoAction,
            PressureAction::SuggestCompression => Self::SuggestCompression,
            PressureAction::ForceCompression => Self::ForceCompression,
            PressureAction::EvictLeastRelevant => Self::EvictLeastRelevant,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct IntentRouteDecisionV1 {
    pub recommended_model_tier: ModelTier,
    pub effective_model_tier: ModelTier,
    pub recommended_read_mode: String,
    pub effective_read_mode: String,
    pub degraded_by_tier_cap: bool,
    pub degraded_by_pressure: bool,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub(crate) struct RouteInputs {
    pub pressure_action: PressureAction,
    pub pressure_utilization: f64,
    pub pressure_remaining_tokens: usize,
}

pub(crate) fn route_v1(query: &str) -> IntentRouteV1 {
    let ledger = crate::core::context_ledger::ContextLedger::load();
    let pressure = ledger.pressure();
    let profile_name = crate::core::profiles::active_profile_name();
    let profile = crate::core::profiles::active_profile();
    let role_name = crate::core::roles::active_role_name();

    let inputs = RouteInputs {
        pressure_action: pressure.recommendation,
        pressure_utilization: pressure.utilization,
        pressure_remaining_tokens: pressure.remaining_tokens,
    };

    route_v1_with(
        query,
        &role_name,
        &profile_name,
        &profile.routing,
        &inputs,
        None,
    )
}

pub(crate) fn route_v1_with(
    query: &str,
    role_name: &str,
    profile_name: &str,
    routing: &crate::core::profiles::RoutingConfig,
    inputs: &RouteInputs,
    created_at_override: Option<&str>,
) -> IntentRouteV1 {
    let created_at = created_at_override.map_or_else(
        || chrono::Utc::now().to_rfc3339(),
        std::string::ToString::to_string,
    );

    let classification = classify(query);
    let base = route_intent(query, &classification);

    let query_redacted = truncate(&crate::core::redaction::redact_text(query), 180);
    let query_md5 = crate::core::hasher::hash_str(query);

    let policy_md5 = crate::core::hasher::hash_str(&format!(
        "max_model_tier={};degrade_under_pressure={}",
        routing.max_model_tier_effective(),
        routing.degrade_under_pressure_effective()
    ));

    let recommended_model_tier = base.model_tier;
    let effective_model_tier = cap_to(
        recommended_model_tier,
        parse_tier_cap(routing.max_model_tier_effective()),
    );
    let degraded_by_tier_cap = effective_model_tier != recommended_model_tier;

    let recommended_read_mode =
        read_mode_for_tier(recommended_model_tier, classification.task_type);
    let (effective_read_mode, degraded_by_pressure) = if routing.degrade_under_pressure_effective()
    {
        apply_pressure_degrade(&recommended_read_mode, inputs.pressure_action)
    } else {
        (recommended_read_mode.clone(), false)
    };

    let reason = build_reason(&ReasonInputs {
        task_type: classification.task_type,
        dimension: base.dimension,
        recommended_tier: recommended_model_tier,
        effective_tier: effective_model_tier,
        read_mode: effective_read_mode.clone(),
        degraded_by_tier_cap,
        degraded_by_pressure,
        pressure: inputs.pressure_action,
    });

    IntentRouteV1 {
        schema_version: crate::core::contracts::INTENT_ROUTE_V1_SCHEMA_VERSION,
        created_at,
        inputs: IntentRouteInputsV1 {
            query_md5,
            query_redacted,
            role: role_name.to_string(),
            profile: profile_name.to_string(),
            task_type: classification.task_type,
            confidence: classification.confidence,
            dimension: base.dimension,
            pressure: PressureSummaryV1 {
                utilization_pct: (inputs.pressure_utilization * 100.0).min(254.0) as u8,
                remaining_tokens: inputs.pressure_remaining_tokens,
                action: PressureActionV1::from_action(inputs.pressure_action),
            },
            policy_md5,
        },
        decision: IntentRouteDecisionV1 {
            recommended_model_tier,
            effective_model_tier,
            recommended_read_mode,
            effective_read_mode,
            degraded_by_tier_cap,
            degraded_by_pressure,
            reason,
        },
    }
}

fn parse_tier_cap(s: &str) -> ModelTier {
    match s.trim().to_lowercase().as_str() {
        "fast" => ModelTier::Fast,
        "standard" => ModelTier::Standard,
        _ => ModelTier::Premium,
    }
}

fn cap_to(tier: ModelTier, cap: ModelTier) -> ModelTier {
    match cap {
        ModelTier::Fast => ModelTier::Fast,
        ModelTier::Standard => match tier {
            ModelTier::Premium => ModelTier::Standard,
            _ => tier,
        },
        ModelTier::Premium => tier,
    }
}

pub(crate) fn read_mode_for_tier(tier: ModelTier, task_type: TaskType) -> String {
    // Editing tasks need the real, complete file — never an abbreviated,
    // signature-only, or identifier-obfuscated view — otherwise the agent is
    // forced into follow-up re-reads mid-edit. This holds across every tier
    // (a Fast-tier bugfix still has to see the code it changes).
    if matches!(
        task_type,
        TaskType::Refactor | TaskType::FixBug | TaskType::Generate
    ) {
        return "full".to_string();
    }
    // Science-driven: use cognitive mode for exploration/review tasks when
    // semantic chunking is available — returns code bodies, not just signatures.
    let science = crate::core::cognitive_gate::basic_science_enabled();
    match (tier, task_type) {
        (ModelTier::Fast, _) => "signatures".to_string(),
        (ModelTier::Standard, TaskType::Explore | TaskType::Review) if science => {
            "cognitive".to_string()
        }
        (ModelTier::Standard, TaskType::Explore | TaskType::Review) => "map".to_string(),
        (ModelTier::Standard, _) => "full".to_string(),
        (ModelTier::Premium, _) => "auto".to_string(),
    }
}

fn apply_pressure_degrade(mode: &str, pressure: PressureAction) -> (String, bool) {
    if let Some(downgraded) = crate::core::auto_mode_resolver::pressure_downgrade(mode, &pressure) {
        (downgraded, true)
    } else {
        (mode.to_string(), false)
    }
}

struct ReasonInputs {
    task_type: TaskType,
    dimension: IntentDimension,
    recommended_tier: ModelTier,
    effective_tier: ModelTier,
    read_mode: String,
    degraded_by_tier_cap: bool,
    degraded_by_pressure: bool,
    pressure: PressureAction,
}

fn build_reason(i: &ReasonInputs) -> String {
    format!(
        "task={} dim={} tier={}→{} read={} pressure={:?} degrade(tier_cap={},pressure={})",
        i.task_type.as_str(),
        i.dimension.as_str(),
        i.recommended_tier.as_str(),
        i.effective_tier.as_str(),
        i.read_mode,
        i.pressure,
        i.degraded_by_tier_cap,
        i.degraded_by_pressure
    )
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    s.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_is_deterministic_for_same_inputs() {
        let r = crate::core::profiles::RoutingConfig::default();
        let inputs = RouteInputs {
            pressure_action: PressureAction::NoAction,
            pressure_utilization: 0.1,
            pressure_remaining_tokens: 1000,
        };
        let a = route_v1_with(
            "fix bug in src/lib.rs",
            "coder",
            "bugfix",
            &r,
            &inputs,
            Some("2026-01-01T00:00:00Z"),
        );
        let b2 = route_v1_with(
            "fix bug in src/lib.rs",
            "coder",
            "bugfix",
            &r,
            &inputs,
            Some("2026-01-01T00:00:00Z"),
        );
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b2).unwrap()
        );
    }

    #[test]
    fn profile_tier_cap_limits_model_tier() {
        let routing = crate::core::profiles::RoutingConfig {
            max_model_tier: Some("fast".to_string()),
            ..Default::default()
        };
        let inputs = RouteInputs {
            pressure_action: PressureAction::NoAction,
            pressure_utilization: 0.1,
            pressure_remaining_tokens: 1000,
        };
        let r = route_v1_with(
            "implement feature x",
            "coder",
            "exploration",
            &routing,
            &inputs,
            Some("2026-01-01T00:00:00Z"),
        );
        assert_eq!(r.decision.effective_model_tier, ModelTier::Fast);
        assert!(r.decision.degraded_by_tier_cap);
    }

    #[test]
    fn pressure_forces_degraded_mode() {
        let routing = crate::core::profiles::RoutingConfig::default();
        let inputs = RouteInputs {
            pressure_action: PressureAction::EvictLeastRelevant,
            pressure_utilization: 0.95,
            pressure_remaining_tokens: 100,
        };
        let r = route_v1_with(
            "review the auth module",
            "coder",
            "review",
            &routing,
            &inputs,
            Some("2026-01-01T00:00:00Z"),
        );
        assert!(
            r.decision.effective_read_mode == "signatures"
                || r.decision.effective_read_mode == "cognitive"
                || r.decision.effective_read_mode == "reference",
            "expected degraded mode, got: {}",
            r.decision.effective_read_mode
        );
        assert!(r.decision.degraded_by_pressure);
    }
}
