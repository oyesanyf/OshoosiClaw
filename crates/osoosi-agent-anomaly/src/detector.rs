use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::collections::VecDeque;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
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
    pub classifier: Arc<crate::classifier::DynamicAgentClassifier>,
    pub agentjacking_guard: Arc<crate::agentjacking_guard::AgentjackingGuard>,
    pub breakout_coordinator: Arc<crate::breakout_defense::BreakoutDefenseCoordinator>,
    pub containment_ring: Arc<crate::containment_ring::AgentContainmentRing>,
    pub atlas_matrix: Arc<crate::atlas_arm::MitreAtlasMatrix>,
    pub rasp_engine: Arc<crate::rasp::AgentRaspEngine>,
    pub mercury_engine: Arc<crate::mercury_guard::MercuryContainmentEngine>,
    pub spider_web_engine: Arc<crate::spider_physics::OrbWebContainmentEngine>,
    pub alignment_scanner: Arc<crate::alignment_scanner::RuntimeAlignmentScanner>,
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
        let classifier = Arc::new(crate::classifier::DynamicAgentClassifier::new());
        let agentjacking_guard = Arc::new(crate::agentjacking_guard::AgentjackingGuard::new());
        let breakout_coordinator =
            Arc::new(crate::breakout_defense::BreakoutDefenseCoordinator::new());
        let containment_ring = Arc::new(crate::containment_ring::AgentContainmentRing::new());
        let atlas_matrix = Arc::new(crate::atlas_arm::MitreAtlasMatrix::new());
        let rasp_engine = Arc::new(crate::rasp::AgentRaspEngine::default());
        let mercury_engine = Arc::new(crate::mercury_guard::MercuryContainmentEngine::new());
        let spider_web_engine = crate::spider_physics::global_spider_web_engine();
        let alignment_scanner = crate::alignment_scanner::global_alignment_scanner();

        // Launch cleaner for dormant sessions (prune every 60s, TTL 300s)
        screener.clone().start_cleaner(Duration::from_secs(60), 300);

        let detector_self = Self {
            screener: screener.clone(),
            reasoner: reasoner.clone(),
            telemetry_tx,
            findings_tx,
            recent_findings: recent_findings.clone(),
            session_meta: session_meta.clone(),
            classifier,
            agentjacking_guard,
            breakout_coordinator,
            containment_ring,
            atlas_matrix,
            rasp_engine,
            mercury_engine,
            spider_web_engine,
            alignment_scanner,
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

    /// Convenient bootstrap method returning the detector and a broadcast receiver for anomaly findings.
    pub fn bootstrap(
        _buffer_size: usize,
        rate_limit: usize,
        batch_threshold: u64,
        reasoning_url: String,
    ) -> (Self, broadcast::Receiver<AnomalyFinding>) {
        let detector = Self::new(rate_limit, batch_threshold, Some(reasoning_url));
        let rx = detector.subscribe_findings();
        (detector, rx)
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

        // 1. Classify subject via dynamic Bayesian inference
        let classification = self.classifier.classify_telemetry(telemetry);

        // 2. Breakout Defense Coordinator check (SSRF, Path Traversal, Sensitive OS stores, ADS)
        let param_str = telemetry.call_parameters.to_string();
        let target_resource = telemetry
            .call_parameters
            .get("path")
            .or_else(|| telemetry.call_parameters.get("file"))
            .or_else(|| telemetry.call_parameters.get("url"))
            .or_else(|| telemetry.call_parameters.get("target"))
            .and_then(|v| v.as_str())
            .unwrap_or(&telemetry.tool_name);

        let breakout_eval = self.breakout_coordinator.evaluate_action(
            &telemetry.agent_id,
            &telemetry.tool_name,
            target_resource,
            &param_str,
            classification.inferred_workspace_root.as_deref(),
        );

        let mut breakout_finding = None;
        if !breakout_eval.is_clean {
            if breakout_eval.ssrf_violation.is_some() {
                self.containment_ring
                    .ssrf_blocked
                    .fetch_add(1, Ordering::Relaxed);
            }
            if breakout_eval.path_violation.is_some() {
                self.containment_ring
                    .path_traversal_blocked
                    .fetch_add(1, Ordering::Relaxed);
            }

            // Broadcast P2P Mesh Watch-Out
            self.containment_ring
                .record_mesh_watchout(
                    &telemetry.agent_id,
                    &telemetry.session_id,
                    "ASI10",
                    &breakout_eval.composite_verdict,
                )
                .await;

            breakout_finding = Some(AnomalyFinding {
                id: format!(
                    "aad-breakout-{}",
                    uuid::Uuid::new_v4()
                        .to_string()
                        .chars()
                        .take(8)
                        .collect::<String>()
                ),
                session_id: telemetry.session_id.clone(),
                agent_id: telemetry.agent_id.clone(),
                risk_category: OwaspAgenticRisk::RogueAgentASI10,
                severity: AlertSeverity::Critical,
                confidence_score: 0.99,
                rationale: format!(
                    "Autonomous agent breakout intercepted: {}.",
                    breakout_eval.composite_verdict
                ),
                recommended_mitigation:
                    "Sever rogue agent branch, invalidate generation epoch, and isolate session"
                        .to_string(),
                flagged_at: Utc::now(),
                evidence: serde_json::to_value(&breakout_eval).unwrap_or_default(),
            });
        }

        // 3. Agentjacking Guard (Phase 3 Chained Tool Abuse)
        let aj_verdict = self.agentjacking_guard.evaluate_chained_tool_call(
            &telemetry.session_id,
            &telemetry.tool_name,
            &telemetry.call_parameters,
            None,
        );

        let mut aj_finding = None;
        if !aj_verdict.is_allowed {
            self.containment_ring
                .record_mesh_watchout(
                    &telemetry.agent_id,
                    &telemetry.session_id,
                    "ASI02",
                    &aj_verdict.reason,
                )
                .await;

            aj_finding = Some(AnomalyFinding {
                id: format!(
                    "aad-aj-{}",
                    uuid::Uuid::new_v4()
                        .to_string()
                        .chars()
                        .take(8)
                        .collect::<String>()
                ),
                session_id: telemetry.session_id.clone(),
                agent_id: telemetry.agent_id.clone(),
                risk_category: OwaspAgenticRisk::ToolMisuseASI02,
                severity: AlertSeverity::Critical,
                confidence_score: 0.95,
                rationale: aj_verdict.reason.clone(),
                recommended_mitigation: "Sever capability epoch and require supervisor consensus"
                    .to_string(),
                flagged_at: Utc::now(),
                evidence: serde_json::json!({
                    "violation_code": aj_verdict.violation_code,
                    "taint_state": format!("{:?}", aj_verdict.taint_state),
                }),
            });
        }

        // 4. Spider-Web Continuum Mechanics & Exposure-Bounded Containment Engine
        let param_str = serde_json::to_string(&telemetry.call_parameters).unwrap_or_default();
        let requested_bytes = param_str.len() as f64;
        let spider_verdict = self.spider_web_engine.evaluate_tool_activity(
            &telemetry.session_id,
            &telemetry.agent_id,
            &telemetry.tool_name,
            &param_str,
            requested_bytes,
        );

        let mut spider_finding = None;
        if !spider_verdict.allowed || spider_verdict.session_terminated {
            self.containment_ring
                .record_mesh_watchout(
                    &telemetry.agent_id,
                    &telemetry.session_id,
                    "ASI02",
                    &spider_verdict.rationale,
                )
                .await;

            spider_finding = Some(AnomalyFinding {
                id: format!("aad-spider-{}", uuid::Uuid::new_v4().to_string().chars().take(8).collect::<String>()),
                session_id: telemetry.session_id.clone(),
                agent_id: telemetry.agent_id.clone(),
                risk_category: OwaspAgenticRisk::ToolMisuseASI02,
                severity: AlertSeverity::Critical,
                confidence_score: 0.99,
                rationale: format!(
                    "Spider-Web Sacrificial Fracture ({}): {}.",
                    spider_verdict.regime.label(),
                    spider_verdict.rationale
                ),
                recommended_mitigation: "Sever compromised session, revoke ephemeral credentials, and initiate EDR host sweep".to_string(),
                flagged_at: Utc::now(),
                evidence: serde_json::to_value(&spider_verdict).unwrap_or_default(),
            });
        }

        // 5. Runtime Trace-Alignment Scanner (AlignmentCheck Pattern: Tier-1 Rust + Tier-2 Local Ollama)
        let mut alignment_finding = None;
        let has_pinned_intent = self
            .alignment_scanner
            .pinned_sessions
            .contains_key(&telemetry.session_id);
        let explicit_user_intent = telemetry
            .call_parameters
            .get("user_intent")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let explicit_untrusted_input = telemetry
            .call_parameters
            .get("untrusted_input")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        if has_pinned_intent
            || explicit_user_intent.is_some()
            || explicit_untrusted_input.is_some()
            || aj_verdict.taint_state.force_canary_cage()
        {
            let align_req = crate::alignment_scanner::AlignmentCheckRequest {
                session_id: Some(telemetry.session_id.clone()),
                agent_id: Some(telemetry.agent_id.clone()),
                arm_id: Some(telemetry.agent_id.clone()),
                model_name: None,
                user_intent: explicit_user_intent,
                untrusted_input: explicit_untrusted_input,
                untrusted_source: None,
                proposed_tool: Some(telemetry.tool_name.clone()),
                proposed_action: None,
                proposed_parameters: Some(telemetry.call_parameters.clone()),
                is_simulation: Some(false),
                scenario: None,
            };
            let align_verdict = self
                .alignment_scanner
                .evaluate_alignment_check(&align_req)
                .await;
            if !align_verdict.allowed {
                self.containment_ring
                    .record_mesh_watchout(
                        &telemetry.agent_id,
                        &telemetry.session_id,
                        "ASI01",
                        &align_verdict.rationale,
                    )
                    .await;
                let conf = (1.0_f64 - align_verdict.intent_alignment_score).clamp(0.85, 0.99);
                alignment_finding = Some(AnomalyFinding {
                    id: format!(
                        "aad-align-{}",
                        uuid::Uuid::new_v4()
                            .to_string()
                            .chars()
                            .take(8)
                            .collect::<String>()
                    ),
                    session_id: telemetry.session_id.clone(),
                    agent_id: telemetry.agent_id.clone(),
                    risk_category: OwaspAgenticRisk::PromptInjectionASI01,
                    severity: AlertSeverity::Critical,
                    confidence_score: conf as f32,
                    rationale: align_verdict.rationale.clone(),
                    recommended_mitigation:
                        "Quarantine hijacked agent session, block unaligned tool invocation, and rotate capability epoch"
                            .to_string(),
                    flagged_at: Utc::now(),
                    evidence: serde_json::to_value(&align_verdict).unwrap_or_default(),
                });
            }
        }

        // Layer 1: Fast-path Screener (<5µs)
        let screener_res = self.screener.inspect(telemetry);

        // Layer 2: Deep Semantic Reasoner
        let maybe_finding = self.reasoner.evaluate(telemetry, Some(&screener_res)).await;

        if let Some(ref finding) = maybe_finding {
            if finding.severity >= AlertSeverity::High {
                self.containment_ring
                    .record_mesh_watchout(
                        &telemetry.agent_id,
                        &telemetry.session_id,
                        finding.risk_category.as_code(),
                        &finding.rationale,
                    )
                    .await;
            }
        }

        // Prioritize critical breakout or spider-web fracture or trace-alignment hijack or chained abuse finding, otherwise reasoner finding
        let active_finding = breakout_finding
            .or(spider_finding)
            .or(alignment_finding)
            .or(aj_finding)
            .or(maybe_finding);

        if let Some(finding) = &active_finding {
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

        active_finding
    }

    /// Evaluates telemetry synchronously and immediately returns any detected anomaly finding.
    pub async fn evaluate_immediate(
        &self,
        telemetry: &ToolCallTelemetry,
    ) -> Option<AnomalyFinding> {
        self.process_internal(telemetry).await
    }

    /// Programmatic interceptor callback for policy enforcement.
    ///
    /// Evaluates telemetry and returns an `EnforceDecision` based on the specified mode
    /// (`"enforce"`, `"block"`, or `"audit"`).
    pub async fn enforce_policy(
        &self,
        telemetry: &ToolCallTelemetry,
        mode: &str,
    ) -> EnforceDecision {
        let finding = self.evaluate_immediate(telemetry).await;

        // Zero Disruption to Normal Operations:
        // Human interactive processes (P(IsAiAgent) < 0.75) receive 100% PassThrough unless Critical breakout detected
        let record = self
            .classifier
            .get_record(&telemetry.session_id)
            .unwrap_or_else(|| self.classifier.classify_telemetry(telemetry));

        if !record.is_verified_agent && record.posterior_probability < 0.75 {
            let is_critical = finding
                .as_ref()
                .map(|f| f.severity == AlertSeverity::Critical)
                .unwrap_or(false);
            if !is_critical {
                return EnforceDecision {
                    allowed: true,
                    action: "allow".to_string(),
                    finding: None,
                    reason: Some(
                        "Human interactive process verified - zero disruption pass-through"
                            .to_string(),
                    ),
                };
            }
        }

        match finding {
            Some(f) => {
                let is_enforcing =
                    mode.eq_ignore_ascii_case("enforce") || mode.eq_ignore_ascii_case("block");

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

    /// Dynamically scans host processes, sockets, and agent trees using native in-process `siquery`
    /// and populates active session metadata with verified agent processes.
    pub fn sync_siquery_host_agents(&self) -> Vec<crate::classifier::AgentClassificationRecord> {
        let discovered = self.classifier.run_siquery_host_scan();
        for rec in &discovered {
            if rec.is_verified_agent {
                let session_id = format!("agent_pid_{}", rec.subject_id);
                let agent_id = rec
                    .inferred_workspace_root
                    .clone()
                    .unwrap_or_else(|| format!("agent_pid_{}", rec.subject_id));

                self.session_meta
                    .entry(session_id.clone())
                    .or_insert_with(|| SessionMeta {
                        session_id,
                        agent_id,
                        total_calls: 1,
                        flagged_anomalies: 0,
                        last_active: rec.last_updated,
                        highest_severity: AlertSeverity::Low,
                    });
            }
        }
        discovered
    }

    /// Returns session tracking summaries for all active agent sessions.
    pub fn get_session_summaries(&self) -> Vec<AgentSessionSummary> {
        self.sync_siquery_host_agents();
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
            *owasp_counts
                .entry(finding.risk_category.as_code())
                .or_default() += 1;
            *severity_counts
                .entry(finding.severity.as_str())
                .or_default() += 1;
            if finding.severity == AlertSeverity::Critical {
                critical_threats += 1;
            }
        }

        let alignment_status = self.alignment_scanner.get_status_summary();
        let drift_traces = self.alignment_scanner.get_drift_traces(200);
        let pinned_sessions = self.alignment_scanner.get_pinned_sessions();

        let mut drift_anomalies = 0usize;
        let mut drift_critical = 0usize;
        for t in &drift_traces {
            if t.verdict == "HIJACK_BLOCKED_QUARANTINE" {
                drift_anomalies += 1;
                drift_critical += 1;
                *owasp_counts.entry("ASI01").or_default() += 1;
                *severity_counts.entry("Critical").or_default() += 1;
            } else if t.verdict == "DRIFT_WARNING_STEP_UP" {
                drift_anomalies += 1;
                *owasp_counts.entry("ASI06").or_default() += 1;
                *severity_counts.entry("High").or_default() += 1;
            }
        }

        let mut distinct_session_ids: std::collections::HashSet<String> =
            self.session_meta.iter().map(|e| e.key().clone()).collect();
        for ps in &pinned_sessions {
            distinct_session_ids.insert(ps.session_id.clone());
        }

        let total_sessions = distinct_session_ids.len().max(self.session_meta.len());
        let meta_calls: u64 = self
            .session_meta
            .iter()
            .map(|entry| entry.value().total_calls)
            .sum();
        let total_calls = meta_calls.max(drift_traces.len() as u64);
        let total_anomalies = q.len() + drift_anomalies;
        let total_critical = critical_threats + drift_critical;

        let containment = self.get_containment_status().await;

        serde_json::json!({
            "monitored_sessions": total_sessions,
            "total_calls": total_calls,
            "total_anomalies": total_anomalies,
            "critical_threats": total_critical,
            "quarantined_sessions": drift_critical,
            "drift_warnings": drift_anomalies.saturating_sub(drift_critical),
            "owasp_distribution": owasp_counts,
            "severity_distribution": severity_counts,
            "containment_ring": containment,
            "alignment_scanner": alignment_status,
            "timestamp": Utc::now(),
        })
    }

    /// Returns containment status metrics, discovered agents, and recent mesh watchouts.
    pub async fn get_containment_status(&self) -> serde_json::Value {
        self.sync_siquery_host_agents();
        let mut status = self.containment_ring.get_status_summary().await;
        let mut discovered_agents: Vec<crate::classifier::AgentClassificationRecord> = self
            .classifier
            .records
            .iter()
            .map(|r| r.value().clone())
            .filter(|r| {
                r.pid > 0
                    && !r.process_name.is_empty()
                    && r.process_name != "unknown"
                    && !r.process_name.eq_ignore_ascii_case("Program")
                    && (r.is_verified_agent
                        || r.posterior_probability >= 0.45
                        || !r.observed_signals.is_empty())
            })
            .collect();

        // If any records had pid > 0 but unknown process_name, try resolving via sysinfo
        if discovered_agents
            .iter()
            .any(|r| r.process_name.is_empty() || r.process_name == "unknown")
        {
            let mut sys = sysinfo::System::new();
            sys.refresh_processes();
            for ag in &mut discovered_agents {
                if ag.process_name.is_empty() || ag.process_name == "unknown" {
                    let pid = sysinfo::Pid::from(ag.pid as usize);
                    if let Some(p) = sys.process(pid) {
                        ag.process_name = p.name().to_string();
                    }
                }
            }
        }

        discovered_agents.retain(|r| {
            !r.process_name.is_empty()
                && r.process_name != "unknown"
                && !r.process_name.eq_ignore_ascii_case("Program")
        });

        // Sort descending by posterior_probability
        discovered_agents.sort_by(|a, b| {
            b.posterior_probability
                .partial_cmp(&a.posterior_probability)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        if let Some(obj) = status.as_object_mut() {
            obj.insert(
                "discovered_agents".to_string(),
                serde_json::to_value(&discovered_agents).unwrap_or_default(),
            );
            obj.insert(
                "discovered_agent_count".to_string(),
                serde_json::json!(discovered_agents.len()),
            );
            obj.insert(
                "alignment_scanner".to_string(),
                self.alignment_scanner.get_status_summary(),
            );
            obj.insert(
                "breakout_prevention".to_string(),
                crate::breakout_prevention::get_breakout_prevention_summary(),
            );
        }
        status
    }
}
