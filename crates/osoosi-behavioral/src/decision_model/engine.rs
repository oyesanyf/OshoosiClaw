use super::cloudflare_client::CloudflareClient;
use super::local_engine::LocalDecisionEngine;
use super::models::{
    build_security_incident_request, parse_security_incident_response, DecisionRequest,
    DecisionResponse, SecurityIncidentDecision,
};
use anyhow::Result;
use osoosi_types::config::DecisionModelConfig;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Thread-safe counters for runtime supervisor telemetry.
#[derive(Debug, Default)]
pub struct DecisionMetrics {
    pub total_evaluations: AtomicU64,
    pub local_evaluations: AtomicU64,
    pub cloudflare_evaluations: AtomicU64,
    pub fallback_evaluations: AtomicU64,
    pub error_count: AtomicU64,
    pub total_latency_micros: AtomicU64,
}

/// Snapshot summary of decision engine metrics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DecisionMetricsSummary {
    pub enabled: bool,
    pub provider: String,
    pub model: String,
    pub total_evaluations: u64,
    pub local_evaluations: u64,
    pub cloudflare_evaluations: u64,
    pub fallback_evaluations: u64,
    pub error_count: u64,
    pub avg_latency_ms: f64,
    pub timeout_ms: u64,
    pub fallback_to_local: bool,
    pub rl_feedback_count: u64,
    pub cumulative_rl_reward: f64,
}

/// The unified Clef Decision Engine uniting Cloudflare Workers AI and Local Brier Evaluators.
pub struct ClefDecisionEngine {
    config: DecisionModelConfig,
    cf_client: Option<CloudflareClient>,
    local_engine: LocalDecisionEngine,
    metrics: Arc<DecisionMetrics>,
}

impl ClefDecisionEngine {
    pub fn new(config: DecisionModelConfig) -> Self {
        let local_engine = LocalDecisionEngine::new(&config.model_dir);

        let cf_client = if config.provider.to_lowercase() == "local" {
            // Strictly self-hosted, skip remote client initialization
            None
        } else {
            match (&config.cloudflare_account_id, &config.cloudflare_api_token) {
                (Some(acc), Some(token)) if !acc.trim().is_empty() && !token.trim().is_empty() => {
                    match CloudflareClient::new(
                        acc.clone(),
                        token.clone(),
                        config.model.clone(),
                        config.timeout_ms,
                    ) {
                        Ok(client) => Some(client),
                        Err(e) => {
                            tracing::warn!(
                                "[DECISION] Cloudflare client initialization failed: {}. Fallback to local active.",
                                e
                            );
                            None
                        }
                    }
                }
                _ => None,
            }
        };

        Self {
            config,
            cf_client,
            local_engine,
            metrics: Arc::new(DecisionMetrics::default()),
        }
    }

    pub fn config(&self) -> &DecisionModelConfig {
        &self.config
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn provider(&self) -> &str {
        &self.config.provider
    }

    pub fn auto_escalate(&self) -> bool {
        self.config.auto_escalate_to_cortex
    }

    pub fn min_action_confidence(&self) -> f64 {
        self.config.min_action_confidence
    }

    pub fn local_engine(&self) -> &LocalDecisionEngine {
        &self.local_engine
    }

    /// Evaluates a raw DecisionRequest across configured or fallback providers.
    pub async fn evaluate_request(&self, request: &DecisionRequest) -> Result<DecisionResponse> {
        let start = Instant::now();
        self.metrics.total_evaluations.fetch_add(1, Ordering::Relaxed);

        let prov = self.config.provider.to_lowercase();
        let use_cloudflare = (prov == "cloudflare" || prov == "auto") && self.cf_client.is_some();

        if use_cloudflare {
            let client = self.cf_client.as_ref().unwrap();
            match client.run_decision(request).await {
                Ok(resp) => {
                    self.metrics.cloudflare_evaluations.fetch_add(1, Ordering::Relaxed);
                    let elapsed_micros = start.elapsed().as_micros() as u64;
                    self.metrics.total_latency_micros.fetch_add(elapsed_micros, Ordering::Relaxed);
                    return Ok(resp);
                }
                Err(err) => {
                    if self.config.fallback_to_local {
                        tracing::warn!(
                            "[DECISION] Cloudflare Workers AI call failed ({}); falling back to local engine.",
                            err
                        );
                        self.metrics.fallback_evaluations.fetch_add(1, Ordering::Relaxed);
                        match self.local_engine.evaluate(request) {
                            Ok(mut local_resp) => {
                                self.metrics.local_evaluations.fetch_add(1, Ordering::Relaxed);
                                let elapsed_micros = start.elapsed().as_micros() as u64;
                                self.metrics.total_latency_micros.fetch_add(elapsed_micros, Ordering::Relaxed);
                                local_resp.latency_ms = start.elapsed().as_secs_f64() * 1000.0;
                                return Ok(local_resp);
                            }
                            Err(e2) => {
                                self.metrics.error_count.fetch_add(1, Ordering::Relaxed);
                                return Err(e2);
                            }
                        }
                    } else {
                        self.metrics.error_count.fetch_add(1, Ordering::Relaxed);
                        return Err(err);
                    }
                }
            }
        }

        // Default or explicit local execution
        match self.local_engine.evaluate(request) {
            Ok(mut local_resp) => {
                self.metrics.local_evaluations.fetch_add(1, Ordering::Relaxed);
                let elapsed_micros = start.elapsed().as_micros() as u64;
                self.metrics.total_latency_micros.fetch_add(elapsed_micros, Ordering::Relaxed);
                local_resp.latency_ms = start.elapsed().as_secs_f64() * 1000.0;
                Ok(local_resp)
            }
            Err(e) => {
                self.metrics.error_count.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    /// Evaluates a security incident state string on the hot path in sub-5ms.
    pub async fn evaluate_security_incident(&self, state_text: &str) -> Result<SecurityIncidentDecision> {
        let req = build_security_incident_request(&self.config.model, state_text);
        let resp = self.evaluate_request(&req).await?;
        Ok(parse_security_incident_response(&resp))
    }

    /// Record Reinforcement Learning for Calibrated Decisions (RLCD) feedback.
    pub fn record_rl_feedback(&self, decision_id: &str, reward: f64, actual_outcome: &str) {
        self.local_engine.record_rl_feedback(decision_id, reward, actual_outcome);
    }

    /// Returns a point-in-time metrics summary for supervisor telemetry.
    pub fn metrics(&self) -> DecisionMetricsSummary {
        let total = self.metrics.total_evaluations.load(Ordering::Relaxed);
        let total_micros = self.metrics.total_latency_micros.load(Ordering::Relaxed);
        let avg_latency_ms = if total > 0 {
            (total_micros as f64 / total as f64) / 1000.0
        } else {
            0.0
        };

        DecisionMetricsSummary {
            enabled: self.config.enabled,
            provider: self.config.provider.clone(),
            model: self.config.model.clone(),
            total_evaluations: total,
            local_evaluations: self.metrics.local_evaluations.load(Ordering::Relaxed),
            cloudflare_evaluations: self.metrics.cloudflare_evaluations.load(Ordering::Relaxed),
            fallback_evaluations: self.metrics.fallback_evaluations.load(Ordering::Relaxed),
            error_count: self.metrics.error_count.load(Ordering::Relaxed),
            avg_latency_ms,
            timeout_ms: self.config.timeout_ms,
            fallback_to_local: self.config.fallback_to_local,
            rl_feedback_count: self.local_engine.rl_feedback_count(),
            cumulative_rl_reward: self.local_engine.cumulative_rl_reward(),
        }
    }
}
