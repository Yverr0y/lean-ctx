// SPDX-License-Identifier: Apache-2.0
//! Connector scheduling through the provider registry — the OCLA scheduler's
//! half of the universal provider framework. Kept apart from the HTTP routes in
//! `providers` so builds without `http-server` schedule connectors too (#586).

use crate::core::ocla::types::{ConnectorJob, OclaResult, ScheduledJob};

/// Select and schedule a connector through the real provider pipeline.
///
/// Explicitly requested, available providers win. Otherwise Active Inference
/// ranks available providers using the persisted provider-bandit model. The
/// requested connector remains a safe deferred fallback when providers have
/// not been initialized or authenticated yet.
pub fn schedule_connector(job: &ConnectorJob, sequence: u64) -> OclaResult<ScheduledJob> {
    job.context.validate()?;
    if job.connector_id.trim().is_empty() {
        return Err(crate::core::ocla::types::OclaError::InvalidRequest(
            "connector_id is required".into(),
        ));
    }

    let project_root = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    crate::core::providers::init::init_with_project_root(Some(&project_root));
    let available = crate::core::providers::global_registry().available_provider_ids();
    let task = format!("{} {}", job.connector_id, job.payload_ref);
    let mut bandit =
        crate::core::provider_bandit::ProviderBandit::load(project_root.to_str().unwrap_or("."));
    let (provider_id, action) = select_provider(&job.connector_id, &task, &available, &mut bandit);

    Ok(ScheduledJob {
        job_ref: format!("job:{}:{sequence}", job.connector_id),
        queue_ref: format!("provider:{provider_id}:{action}"),
    })
}

fn select_provider(
    requested: &str,
    task: &str,
    available: &[String],
    bandit: &mut crate::core::provider_bandit::ProviderBandit,
) -> (String, String) {
    if available.iter().any(|id| id == requested) {
        return (requested.to_string(), "dispatch".into());
    }

    if let Some(prediction) =
        crate::core::active_inference::predict_preloads(task, available, bandit, 1)
            .into_iter()
            .next()
    {
        return (prediction.provider_id, prediction.action);
    }

    (requested.to_string(), "dispatch".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_provider_honors_available_explicit_connector() {
        let available = vec!["github".to_string(), "jira".to_string()];
        let mut bandit = crate::core::provider_bandit::ProviderBandit::new();
        assert_eq!(
            select_provider("jira", "bug investigation", &available, &mut bandit),
            ("jira".to_string(), "dispatch".to_string())
        );
    }

    #[test]
    fn select_provider_uses_active_inference_priority() {
        let available = vec!["github".to_string(), "jira".to_string()];
        let mut bandit = crate::core::provider_bandit::ProviderBandit::new();
        assert_eq!(
            select_provider("automatic", "investigate a bug", &available, &mut bandit),
            ("github".to_string(), "issues".to_string())
        );
    }
}
