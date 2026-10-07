use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, error, warn};

use crate::reasoner::SemanticReasoningEngine;
use crate::screener::StatisticalScreener;
use crate::types::{
    AgentSessionSummary, AlertSeverity, AnomalyFinding, EnforceDecision, OwaspAgenticRisk,
    ToolCallTelemetry,
};

#[derive(Debug, Clone)]
struct SessionMeta {
    session_id: String,
    agent_id: String,
    total_calls: u64,
    flagged_anomalies: usize,
    last_active: DateTime<Utc>,
    highest_severity: AlertSeverity,
}

/// Core Agent Anomaly Detection (AAD) engine coordinating Layer 1 Fast Screener
/// and Layer 2 Semantic Reasoner.
#[derive(Clone)]
pub struct AgentAnomalyDetector {
    screener: Arc<StatisticalScreener>,
    reasoner: Arc<SemanticReasoningEngine>,
    telemetry_tx: mpsc::Sender<ToolCallTelemetry>,
    findings_tx: broadcast::Sender<AnomalyFinding>,
    recent_findings: Arc<RwLock<VecDeque<AnomalyFinding>>>,
    session_meta: Arc<DashMap<String, SessionMeta>>,
}

impl AgentAnomalyDetector {
    /// Creates a new `AgentAnomalyDetector` and launches background out-of-band workers.
    pub fn new(rate_limit: usize, batch_threshold: u64, upstream_url: Option<String>) -> Self {
        let screener = Arc::new(StatisticalScreener::new(
            rate_limit,
            batch_threshold,
            50_000,
            5,
        ));
        let reasoner = Arc::new(SemanticReasoningEngine::new(upstream_url));
        let (telemetry_tx, mut telemetry_rx) = mpsc::channel::<ToolCallTelemetry>(10_000);
        let (findings_tx, _) = broadcast::channel::<AnomalyFinding>(1_000);
        let recent_findings = Arc::new(RwLock::new(VecDeque::with_capacity(1_000)));
        let session_meta = Arc::new(DashMap::new());

        // Launch cleaner for dormant sessions (prune every 60s, TTL 300s)
        screener.clone().start_cleaner(Duration::from_secs(60), 300);

        let detector_self = Self {
            screener: screener.clone(),
            reasoner: reasoner.clone(),
            telemetry_tx,
            findings_tx,
            recent_findings: recent_findings.clone(),
            session_meta: session_meta.clone(),
        };

        // Out-of-band asynchronous processing worker
        let worker_detector = detector_self.clone();
        tokio::spawn(async move {
            debug!("AAD background out-of-band processor started.");
            while let Some(telemetry) = telemetry_rx.recv().await {
                // Out-of-band evaluation
                let _ = worker_detector.process_internal(&telemetry).await;
            }
        });

        detector_self
    }

    /// Subscribes to the broadcast stream of detected anomalies.
    pub fn subscribe_findings(&self) -> broadcast::Receiver<AnomalyFinding> {
        self.findings_tx.subscribe()
    }

    /// Submits tool telemetry asynchronously without blocking agent execution.
    pub async fn submit_telemetry(&self, telemetry: ToolCallTelemetry) {
        if let Err(e) = self.telemetry_tx.try_send(telemetry.clone()) {
            match e {
                mpsc::error::TrySendError::Full(_) => {
                    warn!("AAD telemetry queue full, awaiting buffer space...");
                    let _ = self.telemetry_tx.send(telemetry).await;
                }
                mpsc::error::TrySendError::Closed(_) => {
                    error!("AAD telemetry receiver channel closed!");
                }
            }
        }
    }

    /// Internal evaluation shared between immediate evaluation and background worker.
    async fn process_internal(&self, telemetry: &ToolCallTelemetry) -> Option<AnomalyFinding> {
        // Update session metadata
        {
            let mut meta = self
                .session_meta
                .entry(telemetry.session_id.clone())
                .or_insert_with(|| SessionMeta {
                    session_id: telemetry.session_id.clone(),
                    agent_id: telemetry.agent_id.clone(),
                    total_calls: 0,
                    flagged_anomalies: 0,
                    last_active: telemetry.timestamp,
                    highest_severity: AlertSeverity::Low,
                });
            meta.total_calls = meta.total_calls.saturating_add(1);
            meta.last_active = telemetry.timestamp;
        }

        // Layer 1: Fast-path Screener (<5µs)
        let screener_res = self.screener.inspect(telemetry);

        // Layer 2: Deep Semantic Reasoner
        let maybe_finding = self
            .reasoner
            .evaluate(telemetry, Some(&screener_res))
            .await;

        if let Some(finding) = &maybe_finding {
            // Update session metadata with anomaly
            if let Some(mut meta) = self.session_meta.get_mut(&telemetry.session_id) {
                meta.flagged_anomalies = meta.flagged_anomalies.saturating_add(1);
                if finding.severity > meta.highest_severity {
                    meta.highest_severity = finding.severity;
                }
            }

            // Append to in-memory ring buffer (capped at 1,000)
            {
                let mut q = self.recent_findings.write().await;
                if q.len() >= 1_000 {
                    q.pop_back();
                }
                q.push_front(finding.clone());
            }

            // Broadcast anomaly finding
            let _ = self.findings_tx.send(finding.clone());
        }

        maybe_finding
    }

    /// Evaluates telemetry synchronously and immediately returns any detected anomaly finding.
    pub async fn evaluate_immediate(&self, telemetry: &ToolCallTelemetry) -> Option<AnomalyFinding> {
        self.process_internal(telemetry).await
    }

    /// Programmatic interceptor callback for policy enforcement.
    ///
    /// Evaluates telemetry and returns an `EnforceDecision` based on the specified mode
    /// (`"enforce"`, `"block"`, or `"audit"`).
    pub async fn enforce_policy(&self, telemetry: &ToolCallTelemetry, mode: &str) -> EnforceDecision {
        let finding = self.evaluate_immediate(telemetry).await;

        match finding {
            Some(f) => {
                let is_enforcing = mode.eq_ignore_ascii_case("enforce")
                    || mode.eq_ignore_ascii_case("block");

                if is_enforcing {
                    match f.severity {
                        AlertSeverity::Critical => EnforceDecision {
                            allowed: false,
                            action: "isolate".to_string(),
                            reason: Some(format!(
                                "[CRITICAL] {}: {}",
                                f.risk_category.as_code(),
                                f.rationale
                            )),
                            finding: Some(f),
                        },
                        AlertSeverity::High => EnforceDecision {
                            allowed: false,
                            action: "block".to_string(),
                            reason: Some(format!(
                                "[HIGH] {}: {}",
                                f.risk_category.as_code(),
                                f.rationale
                            )),
                            finding: Some(f),
                        },
                        AlertSeverity::Medium => EnforceDecision {
                            allowed: false,
                            action: "require_approval".to_string(),
                            reason: Some(format!(
                                "[MEDIUM] {}: Approval required before tool invocation.",
                                f.risk_category.as_code()
                            )),
                            finding: Some(f),
                        },
                        AlertSeverity::Low => EnforceDecision {
                            allowed: true,
                            action: "allow".to_string(),
                            reason: Some(format!(
                                "[LOW] {}: Monitored tool call permitted.",
                                f.risk_category.as_code()
                            )),
                            finding: Some(f),
                        },
                    }
                } else {
                    // Audit mode: always allow, but attach finding for logging and telemetry
                    EnforceDecision {
                        allowed: true,
                        action: "allow".to_string(),
                        reason: Some(format!(
                            "[AUDIT] Flagged {} ({}): {}",
                            f.risk_category.as_code(),
                            f.severity.as_str(),
                            f.rationale
                        )),
                        finding: Some(f),
                    }
                }
            }
            None => EnforceDecision {
                allowed: true,
                action: "allow".to_string(),
                finding: None,
                reason: None,
            },
        }
    }

    /// Returns recent anomaly findings up to the specified limit.
    pub async fn get_recent_findings(&self, limit: usize) -> Vec<AnomalyFinding> {
        let q = self.recent_findings.read().await;
        q.iter().take(limit).cloned().collect()
    }

    /// Returns session tracking summaries for all active agent sessions.
    pub fn get_session_summaries(&self) -> Vec<AgentSessionSummary> {
        self.session_meta
            .iter()
            .map(|entry| {
                let m = entry.value();
                AgentSessionSummary {
                    session_id: m.session_id.clone(),
                    agent_id: m.agent_id.clone(),
                    total_calls: m.total_calls,
                    flagged_anomalies: m.flagged_anomalies,
                    last_active: m.last_active,
                    highest_severity: m.highest_severity,
                }
            })
            .collect()
    }

    /// Aggregates risk posture summary including OWASP Top 10 breakdown.
    pub async fn get_risk_summary(&self) -> serde_json::Value {
        let q = self.recent_findings.read().await;

        let mut owasp_counts = std::collections::HashMap::new();
        for risk in OwaspAgenticRisk::all() {
            owasp_counts.insert(risk.as_code(), 0usize);
        }

        let mut severity_counts = std::collections::HashMap::new();
        severity_counts.insert("Critical", 0usize);
        severity_counts.insert("High", 0usize);
        severity_counts.insert("Medium", 0usize);
        severity_counts.insert("Low", 0usize);

        let mut critical_threats = 0usize;

        for finding in q.iter() {
            *owasp_counts.entry(finding.risk_category.as_code()).or_default() += 1;
            *severity_counts.entry(finding.severity.as_str()).or_default() += 1;
            if finding.severity == AlertSeverity::Critical {
                critical_threats += 1;
            }
        }

        let total_sessions = self.session_meta.len();
        let total_calls: u64 = self
            .session_meta
            .iter()
            .map(|entry| entry.value().total_calls)
            .sum();

        serde_json::json!({
            "monitored_sessions": total_sessions,
            "total_calls": total_calls,
            "total_anomalies": q.len(),
            "critical_threats": critical_threats,
            "owasp_distribution": owasp_counts,
            "severity_distribution": severity_counts,
            "timestamp": Utc::now(),
        })
    }
}
