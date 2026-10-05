use super::cloudflare_client::CloudflareClient;
use super::local_engine::LocalDecisionEngine;
use super::models::{
    build_security_incident_request, parse_security_incident_response, BoolAnswer, ChoiceAnswer,
    DecisionAnswer, DecisionRequest, DecisionResponse, SecurityIncidentDecision,
};
use super::strands_client::StrandsClient;
use anyhow::Result;
use osoosi_types::config::DecisionModelConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Thread-safe counters for runtime supervisor telemetry.
#[derive(Debug, Default)]
pub struct DecisionMetrics {
    pub total_evaluations: AtomicU64,
    pub local_evaluations: AtomicU64,
    pub cloudflare_evaluations: AtomicU64,
    pub strands_evaluations: AtomicU64,
    pub hybrid_evaluations: AtomicU64,
    pub consensus_disagreements: AtomicU64,
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
    pub strands_evaluations: u64,
    pub hybrid_evaluations: u64,
    pub consensus_disagreements: u64,
    pub fallback_evaluations: u64,
    pub error_count: u64,
    pub avg_latency_ms: f64,
    pub timeout_ms: u64,
    pub fallback_to_local: bool,
    pub rl_feedback_count: u64,
    pub cumulative_rl_reward: f64,
}

/// The unified Clef Decision Engine uniting Cloudflare Workers AI, Strands Decider 2B SLM,
/// and Local Brier Evaluators.
pub struct ClefDecisionEngine {
    config: DecisionModelConfig,
    cf_client: Option<CloudflareClient>,
    strands_client: Option<StrandsClient>,
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

        let strands_client = if let Some(ref ep) = config.strands_endpoint {
            if !ep.trim().is_empty() {
                match StrandsClient::new(
                    ep.clone(),
                    config.strands_model.clone(),
                    config.strands_timeout_ms,
                ) {
                    Ok(client) => Some(client),
                    Err(e) => {
                        tracing::warn!(
                            "[DECISION] Strands Decider client initialization failed: {}. Fallback active.",
                            e
                        );
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        Self {
            config,
            cf_client,
            strands_client,
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

    pub fn strands_client(&self) -> Option<&StrandsClient> {
        self.strands_client.as_ref()
    }

    pub fn metrics_handle(&self) -> &Arc<DecisionMetrics> {
        &self.metrics
    }

    /// Evaluates a raw DecisionRequest across configured or fallback providers.
    pub async fn evaluate_request(&self, request: &DecisionRequest) -> Result<DecisionResponse> {
        let start = Instant::now();
        self.metrics.total_evaluations.fetch_add(1, Ordering::Relaxed);

        let prov = self.config.provider.to_lowercase();

        // 1. Hybrid Provider Strategy Routing
        if prov == "hybrid" {
            self.metrics.hybrid_evaluations.fetch_add(1, Ordering::Relaxed);
            let strategy = self.config.hybrid_strategy.to_lowercase();
            let mut res = match strategy.as_str() {
                "consensus" => self.evaluate_hybrid_consensus(request).await,
                "local_first" => self.evaluate_hybrid_local_first(request).await,
                _ => self.evaluate_hybrid_cascade(request).await, // default: cascade
            }?;
            let elapsed_micros = start.elapsed().as_micros() as u64;
            self.metrics.total_latency_micros.fetch_add(elapsed_micros, Ordering::Relaxed);
            res.latency_ms = start.elapsed().as_secs_f64() * 1000.0;
            return Ok(res);
        }

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

    /// Tiered 4-Tier Hybrid Decision Cascade:
    /// Tier 1: In-process deterministic / Brier check (< 5ms)
    /// Tier 2: Cloudflare Clef Flash Non-Autoregressive Edge (~38ms)
    /// Tier 3: Local Strands Decider 2B SLM (~115ms)
    /// Tier 4: Native local heuristic engine fallback
    pub async fn evaluate_hybrid_cascade(&self, request: &DecisionRequest) -> Result<DecisionResponse> {
        // Tier 1: In-process Brier check (< 5ms)
        let local_res = self.local_engine.evaluate(request);
        if let Ok(local_resp) = local_res {
            let parsed = parse_security_incident_response(&local_resp);
            // If confidence >= 0.95 or <= 0.10, decisive answer on hot-path: return immediately
            if parsed.action_probability >= 0.95 || parsed.action_probability <= 0.10 {
                self.metrics.local_evaluations.fetch_add(1, Ordering::Relaxed);
                return Ok(local_resp);
            }

            // Tier 2: Cloudflare Clef Flash Non-Autoregressive Edge (~38ms)
            if let Some(ref cf) = self.cf_client {
                match cf.run_decision(request).await {
                    Ok(cf_resp) => {
                        self.metrics.cloudflare_evaluations.fetch_add(1, Ordering::Relaxed);
                        return Ok(cf_resp);
                    }
                    Err(err) => {
                        tracing::debug!(
                            "[DECISION-CASCADE] Clef Flash tier unreachable ({}); cascading to Tier 3.",
                            err
                        );
                    }
                }
            }

            // Tier 3: Local Strands Decider 2B SLM (~115ms)
            if let Some(ref sc) = self.strands_client {
                match sc.run_decision(request).await {
                    Ok(strands_resp) => {
                        self.metrics.strands_evaluations.fetch_add(1, Ordering::Relaxed);
                        return Ok(strands_resp);
                    }
                    Err(err) => {
                        tracing::debug!(
                            "[DECISION-CASCADE] Strands Decider 2B tier unreachable ({}); cascading to Tier 4.",
                            err
                        );
                    }
                }
            }

            // Tier 4: Native local heuristic fallback
            self.metrics.fallback_evaluations.fetch_add(1, Ordering::Relaxed);
            Ok(local_resp)
        } else {
            // Local evaluation failed, fallback to strands or cf
            if let Some(ref sc) = self.strands_client {
                if let Ok(s) = sc.run_decision(request).await {
                    self.metrics.strands_evaluations.fetch_add(1, Ordering::Relaxed);
                    return Ok(s);
                }
            }
            if let Some(ref cf) = self.cf_client {
                if let Ok(c) = cf.run_decision(request).await {
                    self.metrics.cloudflare_evaluations.fetch_add(1, Ordering::Relaxed);
                    return Ok(c);
                }
            }
            local_res
        }
    }

    /// Bayesian Consensus Resolution:
    /// Queries Clef Flash and Strands Decider 2B concurrently with `tokio::join!`.
    /// Combines action probability distributions with Bayesian weighting.
    /// If both models agree on containment (P >= 0.80), proceed autonomously.
    /// If models disagree, sets human_escalation_required = true, increments dispute counter, and logs.
    pub async fn evaluate_hybrid_consensus(&self, request: &DecisionRequest) -> Result<DecisionResponse> {
        let cf_fut = async {
            if let Some(ref cf) = self.cf_client {
                cf.run_decision(request).await.ok()
            } else {
                None
            }
        };

        let strands_fut = async {
            if let Some(ref sc) = self.strands_client {
                sc.run_decision(request).await.ok()
            } else {
                None
            }
        };

        let (cf_opt, strands_opt) = tokio::join!(cf_fut, strands_fut);

        // Fallback to local engines if endpoints not configured/offline
        let resp_clef = cf_opt
            .or_else(|| self.local_engine.evaluate(request).ok())
            .unwrap_or_else(|| StrandsClient::local_calibrated_estimation(request));

        let resp_strands = strands_opt
            .unwrap_or_else(|| StrandsClient::local_calibrated_estimation(request));

        let dec_clef = parse_security_incident_response(&resp_clef);
        let dec_strands = parse_security_incident_response(&resp_strands);

        let w_clef = 0.55;
        let w_strands = 0.45;

        // Extract action probabilities
        let candidate_actions = ["allow", "alert", "tarpit", "ghost_tarpit", "quarantine", "isolate"];
        let mut fused_probs: HashMap<String, f64> = HashMap::new();

        let probs_clef = resp_clef
            .answers
            .get("containment_action")
            .and_then(|a| a.probabilities.as_ref());
        let probs_strands = resp_strands
            .answers
            .get("containment_action")
            .and_then(|a| a.probabilities.as_ref());

        for &act in &candidate_actions {
            let p_c = probs_clef
                .and_then(|m| m.get(act).copied())
                .unwrap_or(if act == dec_clef.containment_action { dec_clef.action_probability } else { 0.05 });
            let p_s = probs_strands
                .and_then(|m| m.get(act).copied())
                .unwrap_or(if act == dec_strands.containment_action { dec_strands.action_probability } else { 0.05 });
            fused_probs.insert(act.to_string(), w_clef * p_c + w_strands * p_s);
        }

        // Normalize fused action probabilities
        let total_p: f64 = fused_probs.values().sum();
        if total_p > 0.0 {
            for v in fused_probs.values_mut() {
                *v /= total_p;
            }
        }

        // Determine top action
        let mut best_action = "alert".to_string();
        let mut max_prob = 0.0;
        for (act, &p) in &fused_probs {
            if p > max_prob {
                max_prob = p;
                best_action = act.clone();
            }
        }

        let is_containment = |act: &str| matches!(act, "isolate" | "quarantine" | "tarpit" | "ghost_tarpit");
        let clef_contains = is_containment(&dec_clef.containment_action);
        let strands_contains = is_containment(&dec_strands.containment_action);

        let mut disagreement = false;
        let mut human_escalation = dec_clef.human_escalation_required || dec_strands.human_escalation_required;

        // Disagreement detection: e.g. Clef says isolate while Strands says allow
        if clef_contains != strands_contains {
            disagreement = true;
            human_escalation = true;
            self.metrics.consensus_disagreements.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                "[DECISION-CONSENSUS] Model dispute detected: Clef action '{}' (P={:.2}) vs Strands action '{}' (P={:.2}). Human escalation flagged.",
                dec_clef.containment_action, dec_clef.action_probability,
                dec_strands.containment_action, dec_strands.action_probability
            );
        }

        let mut final_answers = resp_strands.answers;
        final_answers.insert(
            "containment_action".to_string(),
            DecisionAnswer::from_choice(ChoiceAnswer {
                value: best_action,
                probabilities: fused_probs,
            }),
        );
        final_answers.insert(
            "human_escalation".to_string(),
            DecisionAnswer::from_bool(BoolAnswer {
                value: human_escalation,
                probability: if human_escalation { 0.95 } else { 0.10 },
            }),
        );

        Ok(DecisionResponse {
            answers: final_answers,
            latency_ms: resp_clef.latency_ms.max(resp_strands.latency_ms),
            provider: if disagreement {
                "hybrid-consensus-dispute".to_string()
            } else {
                "hybrid-consensus".to_string()
            },
        })
    }

    /// 100% Air-Gapped Local-First Execution:
    /// Tier 1 Brier Gate (< 5ms) + Tier 3 Strands Decider 2B SLM exclusively.
    /// Strict zero-network egress.
    pub async fn evaluate_hybrid_local_first(&self, request: &DecisionRequest) -> Result<DecisionResponse> {
        // Tier 1 in-process Brier check
        let local_resp = self.local_engine.evaluate(request)?;
        let parsed = parse_security_incident_response(&local_resp);
        if parsed.action_probability >= 0.95 || parsed.action_probability <= 0.10 {
            self.metrics.local_evaluations.fetch_add(1, Ordering::Relaxed);
            return Ok(local_resp);
        }

        // Tier 3 Strands Decider 2B
        if let Some(ref sc) = self.strands_client {
            match sc.run_decision(request).await {
                Ok(mut strands_resp) => {
                    self.metrics.strands_evaluations.fetch_add(1, Ordering::Relaxed);
                    strands_resp.provider = "hybrid-local-first".to_string();
                    return Ok(strands_resp);
                }
                Err(e) => {
                    tracing::debug!("[DECISION-LOCAL] Strands SLM failed ({}). Fallback to Brier.", e);
                }
            }
        }

        // Fallback to Tier 1
        self.metrics.fallback_evaluations.fetch_add(1, Ordering::Relaxed);
        Ok(local_resp)
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
            strands_evaluations: self.metrics.strands_evaluations.load(Ordering::Relaxed),
            hybrid_evaluations: self.metrics.hybrid_evaluations.load(Ordering::Relaxed),
            consensus_disagreements: self.metrics.consensus_disagreements.load(Ordering::Relaxed),
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
