use std::sync::Arc;
use chrono::Utc;
use regex::Regex;
use tracing::debug;
use uuid::Uuid;
use osoosi_behavioral::{EmbeddingGemma2Engine, MatryoshkaDim};

use crate::screener::ScreenerResult;
use crate::types::{AlertSeverity, AnomalyFinding, OwaspAgenticRisk, ToolCallTelemetry};

/// Layer 2 Semantic Reasoning Engine evaluating deep contextual payloads and OWASP risks.
pub struct SemanticReasoningEngine {
    upstream_url: Option<String>,
    http_client: reqwest::Client,
    aws_key_re: Regex,
    jwt_re: Regex,
    credit_card_re: Regex,
    private_key_re: Regex,
    pub embedding_engine: Arc<EmbeddingGemma2Engine>,
}

impl Default for SemanticReasoningEngine {
    fn default() -> Self {
        Self::new(None)
    }
}

impl SemanticReasoningEngine {
    pub fn new(upstream_url: Option<String>) -> Self {
        Self {
            upstream_url,
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_millis(1500))
                .build()
                .unwrap_or_default(),
            aws_key_re: Regex::new(r"\bAKIA[0-9A-Z]{16}\b").expect("Valid AWS regex"),
            jwt_re: Regex::new(r"\beyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]+\b")
                .expect("Valid JWT regex"),
            credit_card_re: Regex::new(r"\b(?:\d{4}[ -]?){3}\d{4}\b").expect("Valid CC regex"),
            private_key_re: Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
                .expect("Valid private key regex"),
            embedding_engine: Arc::new(EmbeddingGemma2Engine::new(MatryoshkaDim::Dim128)),
        }
    }

    pub fn with_embedding_engine(mut self, engine: Arc<EmbeddingGemma2Engine>) -> Self {
        self.embedding_engine = engine;
        self
    }

    /// Evaluates telemetry and returns an `AnomalyFinding` if an OWASP risk pattern is confirmed.
    pub async fn evaluate(
        &self,
        telemetry: &ToolCallTelemetry,
        screener_flag: Option<&ScreenerResult>,
    ) -> Option<AnomalyFinding> {
        // Collect string values from call parameters for lexical/semantic scanning
        let mut strings = Vec::new();
        Self::collect_strings(&telemetry.call_parameters, &mut strings);

        // Compute EmbeddingGemma 2 128-dim vector embedding and threat cluster similarity
        let threat_similarity = self
            .embedding_engine
            .evaluate_similarity_against_threats(&telemetry.tool_name, &telemetry.call_parameters);

        let mut candidate_finding: Option<AnomalyFinding> = None;

        // Pattern 1: Prompt Injection & Jailbreak in Parameters (ASI01)
        if let Some(finding) = self.detect_prompt_injection(telemetry, &strings) {
            candidate_finding = Some(finding);
        } else if let Some(finding) = self.detect_rogue_agent_shell_destruction(telemetry, &strings) {
            // Pattern 2: Rogue Agent Shell Destruction (ASI10)
            candidate_finding = Some(finding);
        } else if let Some(finding) = self.detect_data_exfiltration(telemetry, &strings) {
            // Pattern 3: Secondary Channel Data Exfiltration (ASI07)
            candidate_finding = Some(finding);
        } else if let Some(finding) = self.detect_scraping_exfiltration(telemetry) {
            // Pattern 4: Scraping & Exfiltration (Google Inventory Agent pattern - ASI09/ASI02)
            candidate_finding = Some(finding);
        } else if let Some(finding) = self.detect_privilege_abuse(telemetry, &strings) {
            // Pattern 5: Confused Deputy & Privilege Abuse (ASI03)
            candidate_finding = Some(finding);
        } else if let Some(flag) = screener_flag {
            // Pattern 6: If Layer 1 screener flagged an anomaly (e.g. rate limit, cascading failure)
            if flag.is_anomalous {
                candidate_finding = Some(AnomalyFinding {
                    id: format!("AF-{}", Uuid::new_v4().simple()),
                    session_id: telemetry.session_id.clone(),
                    agent_id: telemetry.agent_id.clone(),
                    risk_category: flag.risk_category.unwrap_or(OwaspAgenticRisk::ResourceExhaustionASI09),
                    severity: flag.severity.unwrap_or(AlertSeverity::High),
                    confidence_score: 0.90,
                    rationale: flag.reason.clone().unwrap_or_else(|| "Fast Screener threshold exceeded.".to_string()),
                    recommended_mitigation: "Throttle agent invocation rate, apply concurrency limits, or investigate multi-agent loops.".to_string(),
                    flagged_at: Utc::now(),
                    evidence: serde_json::json!({
                        "screener_result": flag,
                        "tool_name": telemetry.tool_name,
                        "call_parameters": telemetry.call_parameters,
                    }),
                });
            }
        } else if let Some((threat_cluster, sim_score, tag)) = threat_similarity.as_ref() {
            // Pattern 7: EmbeddingGemma 2 semantic threat match (>= 0.85)
            if *sim_score >= 0.85 {
                let (risk_category, rationale, mitigation) = match threat_cluster.as_str() {
                    "Scraping" => (
                        OwaspAgenticRisk::ResourceExhaustionASI09,
                        format!(
                            "Bulk data harvesting detected matching Google Inventory Agent pattern: '{}' (EmbeddingGemma 2 cosine similarity {:.2})",
                            telemetry.tool_name, sim_score
                        ),
                        "Cap query pagination to 25 items max, enforce rate limiting, and require human-in-the-loop signoff for bulk exports.".to_string(),
                    ),
                    "Prompt Injection" => (
                        OwaspAgenticRisk::PromptInjectionASI01,
                        format!(
                            "Prompt injection semantic vector detected in '{}' (EmbeddingGemma 2 cosine similarity {:.2})",
                            telemetry.tool_name, sim_score
                        ),
                        "Quarantine prompt origin, sanitize retrieved RAG chunks, and reset agent context window.".to_string(),
                    ),
                    "Privilege Escalation" => (
                        OwaspAgenticRisk::PrivilegeAbuseASI03,
                        format!(
                            "Privilege escalation semantic pattern detected in '{}' (EmbeddingGemma 2 cosine similarity {:.2})",
                            telemetry.tool_name, sim_score
                        ),
                        "Enforce strict least-privilege RBAC boundaries; reject cross-tenant and unauthenticated impersonation queries.".to_string(),
                    ),
                    "Exfiltration" => (
                        OwaspAgenticRisk::DataExfiltrationASI07,
                        format!(
                            "Data exfiltration semantic pattern detected in '{}' (EmbeddingGemma 2 cosine similarity {:.2})",
                            telemetry.tool_name, sim_score
                        ),
                        "Halt transmission, rotate leaked credentials immediately, and quarantine origin session.".to_string(),
                    ),
                    "Shell Destruction" => (
                        OwaspAgenticRisk::RogueAgentASI10,
                        format!(
                            "Destructive shell command semantic pattern detected in '{}' (EmbeddingGemma 2 cosine similarity {:.2})",
                            telemetry.tool_name, sim_score
                        ),
                        "Immediately terminate agent process, revoke execution token, and snapshot environment state.".to_string(),
                    ),
                    _ => (
                        OwaspAgenticRisk::UnexpectedExecutionASI05,
                        format!(
                            "Anomalous tool execution vector in '{}' (EmbeddingGemma 2 cosine similarity {:.2})",
                            telemetry.tool_name, sim_score
                        ),
                        "Enforce strict agent authorization policy.".to_string(),
                    ),
                };

                candidate_finding = Some(AnomalyFinding {
                    id: format!("AF-{}", Uuid::new_v4().simple()),
                    session_id: telemetry.session_id.clone(),
                    agent_id: telemetry.agent_id.clone(),
                    risk_category,
                    severity: AlertSeverity::Critical,
                    confidence_score: *sim_score,
                    rationale,
                    recommended_mitigation: mitigation,
                    flagged_at: Utc::now(),
                    evidence: serde_json::json!({
                        "embedding_gemma2_cosine_score": sim_score,
                        "threat_cluster": threat_cluster,
                        "threat_tag": tag,
                        "mrl_dimension": 128,
                        "tool_name": telemetry.tool_name,
                        "call_parameters": telemetry.call_parameters,
                    }),
                });
            }
        }

        if let Some(mut found) = candidate_finding {
            if let Some((threat_cluster, sim_score, tag)) = threat_similarity {
                if let Some(obj) = found.evidence.as_object_mut() {
                    obj.insert("embedding_gemma2_cosine_score".to_string(), serde_json::json!(sim_score));
                    obj.insert("embedding_gemma2_threat_cluster".to_string(), serde_json::json!(threat_cluster));
                    obj.insert("embedding_gemma2_threat_tag".to_string(), serde_json::json!(tag));
                    obj.insert("embedding_gemma2_dimension".to_string(), serde_json::json!(128));
                }
                if sim_score >= 0.85 {
                    found.confidence_score = ((found.confidence_score + sim_score) / 2.0).clamp(0.0, 0.99);
                }
            }
            return Some(found);
        }

        // Optional: Upstream LLM / External evaluator hook
        if self.upstream_url.is_some() {
            if let Some(remote_finding) = self.evaluate_upstream(telemetry).await {
                return Some(remote_finding);
            }
        }

        None
    }

    /// Recursively flattens all string values in a JSON structure.
    fn collect_strings(val: &serde_json::Value, out: &mut Vec<String>) {
        match val {
            serde_json::Value::String(s) => out.push(s.clone()),
            serde_json::Value::Array(arr) => {
                for item in arr {
                    Self::collect_strings(item, out);
                }
            }
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    out.push(k.clone());
                    Self::collect_strings(v, out);
                }
            }
            _ => {}
        }
    }

    /// Detects prompt injections, jailbreaks, and instructions overwriting behavior inside tool parameters.
    fn detect_prompt_injection(
        &self,
        telemetry: &ToolCallTelemetry,
        strings: &[String],
    ) -> Option<AnomalyFinding> {
        let jailbreak_signatures = [
            "ignore previous instructions",
            "ignore all previous",
            "disregard previous instructions",
            "system prompt",
            "<|im_start|>",
            "<|im_end|>",
            "[inst]",
            "disregard safety",
            "jailbreak",
            "developer mode",
            "unrestricted mode",
            "bypass guardrails",
            "you are no longer an ai",
        ];

        for text in strings {
            let lower = text.to_lowercase();
            for sig in &jailbreak_signatures {
                if lower.contains(sig) {
                    return Some(AnomalyFinding {
                        id: format!("AF-{}", Uuid::new_v4().simple()),
                        session_id: telemetry.session_id.clone(),
                        agent_id: telemetry.agent_id.clone(),
                        risk_category: OwaspAgenticRisk::PromptInjectionASI01,
                        severity: AlertSeverity::Critical,
                        confidence_score: 0.98,
                        rationale: format!(
                            "Prompt injection/jailbreak signature detected in tool argument: '{}'",
                            sig
                        ),
                        recommended_mitigation: "Quarantine prompt origin, sanitize retrieved RAG chunks, and reset agent context window.".to_string(),
                        flagged_at: Utc::now(),
                        evidence: serde_json::json!({
                            "detected_signature": sig,
                            "matching_argument": text,
                            "tool_name": telemetry.tool_name,
                        }),
                    });
                }
            }
        }
        None
    }

    /// Detects rogue destructive commands executed through tools.
    fn detect_rogue_agent_shell_destruction(
        &self,
        telemetry: &ToolCallTelemetry,
        strings: &[String],
    ) -> Option<AnomalyFinding> {
        let destructive_patterns = [
            "rm -rf",
            "rmdir /s /q",
            "del /f /s /q",
            "del /s /q",
            "drop table",
            "drop database",
            "format c:",
            "mkfs.",
            "dd if=/dev/zero",
            ":(){ :|:& };:",
            "chmod -r 777 /",
        ];

        for text in strings {
            let lower = text.to_lowercase();
            for pattern in &destructive_patterns {
                if lower.contains(pattern) {
                    return Some(AnomalyFinding {
                        id: format!("AF-{}", Uuid::new_v4().simple()),
                        session_id: telemetry.session_id.clone(),
                        agent_id: telemetry.agent_id.clone(),
                        risk_category: OwaspAgenticRisk::RogueAgentASI10,
                        severity: AlertSeverity::Critical,
                        confidence_score: 0.99,
                        rationale: format!(
                            "Destructive OS command or irreversible database operation detected in payload: '{}'",
                            pattern
                        ),
                        recommended_mitigation: "Immediately terminate agent process, revoke execution token, and snapshot environment state.".to_string(),
                        flagged_at: Utc::now(),
                        evidence: serde_json::json!({
                            "destructive_pattern": pattern,
                            "payload_snippet": text,
                            "tool_name": telemetry.tool_name,
                        }),
                    });
                }
            }
        }
        None
    }

    /// Detects secondary channel data exfiltration: credit cards, AWS keys, JWTs, private keys.
    fn detect_data_exfiltration(
        &self,
        telemetry: &ToolCallTelemetry,
        strings: &[String],
    ) -> Option<AnomalyFinding> {
        for text in strings {
            if let Some(m) = self.aws_key_re.find(text) {
                return Some(AnomalyFinding {
                    id: format!("AF-{}", Uuid::new_v4().simple()),
                    session_id: telemetry.session_id.clone(),
                    agent_id: telemetry.agent_id.clone(),
                    risk_category: OwaspAgenticRisk::DataExfiltrationASI07,
                    severity: AlertSeverity::Critical,
                    confidence_score: 0.96,
                    rationale: "Live AWS Access Key detected in tool arguments (covert exfiltration or credential leak).".to_string(),
                    recommended_mitigation: "Halt transmission, rotate leaked AWS credentials immediately, and quarantine origin session.".to_string(),
                    flagged_at: Utc::now(),
                    evidence: serde_json::json!({
                        "secret_type": "AWS_ACCESS_KEY",
                        "matched_prefix": &m.as_str()[..8],
                        "tool_name": telemetry.tool_name,
                    }),
                });
            }

            if let Some(_m) = self.jwt_re.find(text) {
                return Some(AnomalyFinding {
                    id: format!("AF-{}", Uuid::new_v4().simple()),
                    session_id: telemetry.session_id.clone(),
                    agent_id: telemetry.agent_id.clone(),
                    risk_category: OwaspAgenticRisk::DataExfiltrationASI07,
                    severity: AlertSeverity::High,
                    confidence_score: 0.92,
                    rationale: "Bearer/JWT authentication token detected embedded in tool call parameters.".to_string(),
                    recommended_mitigation: "Enforce secret masking on agent tool inputs and revoke compromised tokens.".to_string(),
                    flagged_at: Utc::now(),
                    evidence: serde_json::json!({
                        "secret_type": "JWT_TOKEN",
                        "tool_name": telemetry.tool_name,
                    }),
                });
            }

            if let Some(_m) = self.credit_card_re.find(text) {
                return Some(AnomalyFinding {
                    id: format!("AF-{}", Uuid::new_v4().simple()),
                    session_id: telemetry.session_id.clone(),
                    agent_id: telemetry.agent_id.clone(),
                    risk_category: OwaspAgenticRisk::DataExfiltrationASI07,
                    severity: AlertSeverity::Critical,
                    confidence_score: 0.95,
                    rationale: "Credit card number pattern detected in outgoing tool call parameters.".to_string(),
                    recommended_mitigation: "Block outbound payload, trigger PCI-DSS compliance alert, and isolate session.".to_string(),
                    flagged_at: Utc::now(),
                    evidence: serde_json::json!({
                        "secret_type": "CREDIT_CARD",
                        "tool_name": telemetry.tool_name,
                    }),
                });
            }

            if self.private_key_re.is_match(text) {
                return Some(AnomalyFinding {
                    id: format!("AF-{}", Uuid::new_v4().simple()),
                    session_id: telemetry.session_id.clone(),
                    agent_id: telemetry.agent_id.clone(),
                    risk_category: OwaspAgenticRisk::DataExfiltrationASI07,
                    severity: AlertSeverity::Critical,
                    confidence_score: 0.99,
                    rationale: "Cryptographic private key header detected in tool arguments.".to_string(),
                    recommended_mitigation: "Revoke and rotate private key immediately; audit agent data source.".to_string(),
                    flagged_at: Utc::now(),
                    evidence: serde_json::json!({
                        "secret_type": "PRIVATE_KEY",
                        "tool_name": telemetry.tool_name,
                    }),
                });
            }
        }
        None
    }

    /// Detects Google Inventory Agent bulk data scraping and exfiltration pattern (ASI09 / ASI02).
    fn detect_scraping_exfiltration(
        &self,
        telemetry: &ToolCallTelemetry,
    ) -> Option<AnomalyFinding> {
        let tool_lower = telemetry.tool_name.to_lowercase();
        let is_data_tool = tool_lower.contains("inventory")
            || tool_lower.contains("customer")
            || tool_lower.contains("record")
            || tool_lower.contains("catalog")
            || tool_lower.contains("fetch_rows")
            || tool_lower.contains("export");

        if !is_data_tool {
            return None;
        }

        let mut limit = 0u64;
        let mut offset = 0u64;

        if let serde_json::Value::Object(map) = &telemetry.call_parameters {
            for (k, v) in map {
                let kl = k.to_lowercase();
                if kl == "limit" || kl == "count" || kl == "page_size" || kl == "pagesize" || kl == "batch_size" {
                    if let Some(n) = v.as_u64() {
                        limit = n;
                    } else if let Some(s) = v.as_str() {
                        limit = s.parse::<u64>().unwrap_or(0);
                    }
                }
                if kl == "offset" || kl == "skip" || kl == "start" {
                    if let Some(n) = v.as_u64() {
                        offset = n;
                    } else if let Some(s) = v.as_str() {
                        offset = s.parse::<u64>().unwrap_or(0);
                    }
                }
            }
        }

        // Google Inventory Agent pattern: large limits, large offsets, or combination
        if limit >= 100 || offset >= 100 || (limit >= 50 && offset > 0) {
            return Some(AnomalyFinding {
                id: format!("AF-{}", Uuid::new_v4().simple()),
                session_id: telemetry.session_id.clone(),
                agent_id: telemetry.agent_id.clone(),
                risk_category: OwaspAgenticRisk::ResourceExhaustionASI09,
                severity: AlertSeverity::Critical,
                confidence_score: 0.95,
                rationale: format!(
                    "Bulk data harvesting detected matching Google Inventory Agent pattern: '{}' called with limit={} and offset={}",
                    telemetry.tool_name, limit, offset
                ),
                recommended_mitigation: "Cap query pagination to 25 items max, enforce rate limiting, and require human-in-the-loop signoff for bulk exports.".to_string(),
                flagged_at: Utc::now(),
                evidence: serde_json::json!({
                    "tool_name": telemetry.tool_name,
                    "limit": limit,
                    "offset": offset,
                    "parameters": telemetry.call_parameters,
                }),
            });
        }

        None
    }

    /// Detects confused deputy and privilege abuse (ASI03).
    fn detect_privilege_abuse(
        &self,
        telemetry: &ToolCallTelemetry,
        strings: &[String],
    ) -> Option<AnomalyFinding> {
        let tool_lower = telemetry.tool_name.to_lowercase();
        let is_priv_tool = tool_lower.contains("impersonate")
            || tool_lower.contains("assume_role")
            || tool_lower.contains("elevate")
            || tool_lower.contains("sudo")
            || tool_lower.contains("grant_role");

        let mut role_escalation = false;
        let mut impersonation_attempt = false;
        let mut tenant_override = false;

        if let serde_json::Value::Object(map) = &telemetry.call_parameters {
            for (k, v) in map {
                let kl = k.to_lowercase();
                if kl == "role" {
                    if let Some(r) = v.as_str() {
                        let rl = r.to_lowercase();
                        if rl == "admin" || rl == "root" || rl == "superuser" || rl == "system" {
                            role_escalation = true;
                        }
                    }
                }
                if kl == "impersonate_user" || kl == "target_user" || kl == "run_as" {
                    impersonation_attempt = true;
                }
                if kl == "tenant_id" || kl == "tenant" {
                    if let Some(t) = v.as_str() {
                        if t == "*" || t == "all" || t.to_lowercase().contains("admin") {
                            tenant_override = true;
                        }
                    }
                }
            }
        }

        for text in strings {
            let lower = text.to_lowercase();
            if lower.contains("bypass_auth") || lower.contains("elevate_privileges") {
                role_escalation = true;
            }
        }

        if is_priv_tool || role_escalation || impersonation_attempt || tenant_override {
            return Some(AnomalyFinding {
                id: format!("AF-{}", Uuid::new_v4().simple()),
                session_id: telemetry.session_id.clone(),
                agent_id: telemetry.agent_id.clone(),
                risk_category: OwaspAgenticRisk::PrivilegeAbuseASI03,
                severity: AlertSeverity::Critical,
                confidence_score: 0.92,
                rationale: format!(
                    "Unauthorized identity or privilege escalation detected in tool call '{}' (role_escalation={}, impersonation={}, tenant_override={})",
                    telemetry.tool_name, role_escalation, impersonation_attempt, tenant_override
                ),
                recommended_mitigation: "Enforce strict least-privilege RBAC boundaries; reject cross-tenant and unauthenticated impersonation queries.".to_string(),
                flagged_at: Utc::now(),
                evidence: serde_json::json!({
                    "tool_name": telemetry.tool_name,
                    "parameters": telemetry.call_parameters,
                    "role_escalation": role_escalation,
                    "impersonation_attempt": impersonation_attempt,
                    "tenant_override": tenant_override,
                }),
            });
        }

        None
    }

    /// Evaluates telemetry against an optional upstream LLM/reasoner server.
    async fn evaluate_upstream(&self, telemetry: &ToolCallTelemetry) -> Option<AnomalyFinding> {
        let url = self.upstream_url.as_ref()?;
        match self.http_client.post(url).json(telemetry).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    resp.json::<AnomalyFinding>().await.ok()
                } else {
                    None
                }
            }
            Err(e) => {
                debug!("Upstream AAD evaluator unreachable: {}", e);
                None
            }
        }
    }
}
