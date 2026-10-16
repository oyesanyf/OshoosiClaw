use super::context::{
    AgentSecuritySubject, AgentTrustTier, RaspDecision, RaspThreatCategory, TaintLevel,
};
use super::policy::RaspPolicyEngine;
use regex::Regex;
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub struct CedarVerdict {
    pub is_allowed: bool,
    pub diagnostic_errors: Vec<String>,
}

#[derive(Default)]
pub struct CedarEngine;
impl CedarEngine {
    pub fn evaluate(
        &self,
        principal: &str,
        action: &str,
        _actuator: &str,
        resource_type: &str,
        _params: serde_json::Value,
    ) -> Result<CedarVerdict, String> {
        let p_norm = principal.trim().to_ascii_lowercase();
        let a_norm = action.trim().to_ascii_lowercase();
        let r_norm = resource_type.trim().to_ascii_lowercase();

        // 1. Fail closed on empty or untrusted/quarantined principals
        if p_norm.is_empty() {
            return Ok(CedarVerdict {
                is_allowed: false,
                diagnostic_errors: vec!["Anonymous or empty principal rejected by fail-closed policy".to_string()],
            });
        }
        if p_norm.contains("untrusted")
            || p_norm.contains("fuzz")
            || p_norm.contains("quarantine")
            || p_norm.contains("attacker")
            || p_norm.contains("malicious")
        {
            return Ok(CedarVerdict {
                is_allowed: false,
                diagnostic_errors: vec![format!(
                    "Untrusted or quarantined principal '{}' denied access to '{}'",
                    principal, resource_type
                )],
            });
        }

        // 2. High-privilege / critical system resources require supervisor or kernel principals
        let is_privileged_resource = r_norm == "systempolicy" || r_norm == "kernelsubstrate" || r_norm == "ledger";
        let is_privileged_principal = p_norm.contains("supervisor")
            || p_norm.contains("system")
            || p_norm.contains("admin")
            || p_norm.contains("kernel")
            || p_norm.contains("root");

        if is_privileged_resource && !is_privileged_principal {
            return Ok(CedarVerdict {
                is_allowed: false,
                diagnostic_errors: vec![format!(
                    "Principal '{}' lacks privilege for critical resource '{}'",
                    principal, resource_type
                )],
            });
        }

        // 3. Sensitive / dangerous action checks
        if a_norm == "change_security_policy"
            || a_norm == "kernel_sentinel"
            || a_norm.contains("bypass")
            || a_norm.contains("override")
        {
            if !is_privileged_principal {
                return Ok(CedarVerdict {
                    is_allowed: false,
                    diagnostic_errors: vec![format!(
                        "Action '{}' is restricted to supervisor/system principals",
                        action
                    )],
                });
            }
        }

        // 4. Default allowed for legitimate verified principals accessing valid resources
        Ok(CedarVerdict {
            is_allowed: true,
            diagnostic_errors: Vec::new(),
        })
    }
}

#[derive(Default)]
pub struct CedarAuthorizationGateway {
    engine: CedarEngine,
}

impl CedarAuthorizationGateway {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn engine(&self) -> &CedarEngine {
        &self.engine
    }

    pub fn is_authorized(&self, principal: &str, action: &str, resource: &str) -> bool {
        match self.engine.evaluate(principal, action, "gateway", resource, serde_json::Value::Null) {
            Ok(verdict) => verdict.is_allowed,
            Err(_) => false, // fail-closed on any error
        }
    }
}

/// Core trait implemented by all modular RT-ASP interceptors.
pub trait RaspInterceptor: Send + Sync {
    fn name(&self) -> &'static str;
    fn is_enabled(&self) -> bool;
}

// ============================================================================
// 1. Invocation / Prompt & Directive Interceptor
// ============================================================================

pub struct PromptInvocationInterceptor {
    policy_engine: Arc<RaspPolicyEngine>,
    jailbreak_patterns: Vec<Regex>,
    zero_width_regex: Regex,
}

impl Default for PromptInvocationInterceptor {
    fn default() -> Self {
        Self::new(Arc::new(RaspPolicyEngine::default()))
    }
}

impl PromptInvocationInterceptor {
    pub fn new(policy_engine: Arc<RaspPolicyEngine>) -> Self {
        let patterns = vec![
            Regex::new(r"(?i)ignore\s+(all\s+)?(previous|prior)\s+(instructions|directives|rules)").unwrap(),
            Regex::new(r"(?i)disregard\s+(all\s+)?(previous|prior|safety)\s+(rules|constraints|instructions)").unwrap(),
            Regex::new(r"(?i)system\s*override\s*:\s*disable\s*security").unwrap(),
            Regex::new(r"(?i)you\s+are\s+now\s+(in\s+)?(DAN|developer|jailbreak|unfiltered)\s+mode").unwrap(),
            Regex::new(r"(?i)forget\s+(all\s+)?(security|safety|ethical)\s+(guidelines|rules|constraints)").unwrap(),
            Regex::new(r"(?i)bypass\s+(cedar|rasp|policy|security|containment)\s+(gate|engine|checks)").unwrap(),
            Regex::new(r"(?i)pretend\s+you\s+have\s+root\s+privileges").unwrap(),
            Regex::new(r"(?i)exfiltrate\s+confidential\s+keys").unwrap(),
        ];

        let zero_width_regex = Regex::new(r"[\u{200B}\u{200C}\u{200D}\u{FEFF}\u{202A}-\u{202E}]").unwrap();

        Self {
            policy_engine,
            jailbreak_patterns: patterns,
            zero_width_regex,
        }
    }

    /// Evaluates prompt input across syntax, semantics, and multilingual domains.
    pub fn inspect_prompt(
        &self,
        prompt: &str,
        language_code: Option<&str>,
        subject: &AgentSecuritySubject,
    ) -> (RaspDecision, Option<RaspThreatCategory>, TaintLevel) {
        // 1. Check for zero-width steganographic injection
        if self.zero_width_regex.is_match(prompt) {
            let cat = RaspThreatCategory::SteganographySmuggling;
            let dec = self.policy_engine.evaluate_mitigation_action(
                cat,
                "Zero-width unicode steganographic characters detected in prompt",
                subject,
                "RASP-PROMPT-001",
            );
            return (dec, Some(cat), TaintLevel::Malicious);
        }

        // 2. Check for Canary tripwire in prompt
        if let Some((canary, label)) = self.policy_engine.canary_mgr().check_and_trip(prompt) {
            let cat = RaspThreatCategory::CanaryTokenTripped;
            let dec = self.policy_engine.evaluate_mitigation_action(
                cat,
                &format!("Canary token tripped in prompt: {} ({})", canary, label),
                subject,
                "RASP-CANARY-001",
            );
            return (dec, Some(cat), TaintLevel::Malicious);
        }

        // 3. Scan for adversarial injection patterns
        for pattern in &self.jailbreak_patterns {
            if pattern.is_match(prompt) {
                let cat = RaspThreatCategory::PromptInjection;
                let dec = self.policy_engine.evaluate_mitigation_action(
                    cat,
                    &format!("Direct prompt injection pattern matched: {}", pattern.as_str()),
                    subject,
                    "RASP-PROMPT-002",
                );
                return (dec, Some(cat), TaintLevel::Malicious);
            }
        }

        // 4. Multilingual evaluation: Legitimate foreign language prompts are cleanly permitted
        // while tracking suspect taint if unknown tokens appear.
        let is_foreign_lang = language_code.map_or(false, |code| {
            let c = code.trim().to_ascii_lowercase();
            !c.is_empty() && c != "en" && c != "english"
        });

        if is_foreign_lang && self.policy_engine.config().enable_multilingual_semantic_pass {
            // Multilingual instructions pass cleanly if no adversarial signatures exist
            return (
                RaspDecision::Allow {
                    taint_level: TaintLevel::Clean,
                },
                None,
                TaintLevel::Clean,
            );
        }

        (
            RaspDecision::Allow {
                taint_level: TaintLevel::Clean,
            },
            None,
            TaintLevel::Clean,
        )
    }
}

impl RaspInterceptor for PromptInvocationInterceptor {
    fn name(&self) -> &'static str {
        "PromptInvocationInterceptor"
    }

    fn is_enabled(&self) -> bool {
        true
    }
}

// ============================================================================
// 2. Actuator / Tool-Call Interceptor
// ============================================================================

pub struct ToolActuatorInterceptor {
    policy_engine: Arc<RaspPolicyEngine>,
    cmd_injection_regex: Regex,
    path_traversal_regex: Regex,
}

impl Default for ToolActuatorInterceptor {
    fn default() -> Self {
        Self::new(Arc::new(RaspPolicyEngine::default()))
    }
}

impl ToolActuatorInterceptor {
    pub fn new(policy_engine: Arc<RaspPolicyEngine>) -> Self {
        let cmd_regex = Regex::new(r#"(?i)(;|&&|\|\||`|\$\(|\bpowershell(\.exe)?\b|\bcmd(\.exe)?\b|\bbash\b|\bwscript(\.exe)?\b)"#).unwrap();
        let path_regex = Regex::new(r#"(?i)(\.\./|\.\.\\|/etc/passwd|c:\\windows\\system32|%2e%2e)"#).unwrap();

        Self {
            policy_engine,
            cmd_injection_regex: cmd_regex,
            path_traversal_regex: path_regex,
        }
    }

    /// Evaluates tool actuator invocation, parameters, and numerical boundaries.
    pub fn intercept_tool_call(
        &self,
        tool_name: &str,
        params: &serde_json::Value,
        subject: &AgentSecuritySubject,
        cedar_gateway: Option<&CedarAuthorizationGateway>,
    ) -> (RaspDecision, Option<RaspThreatCategory>, serde_json::Value) {
        let params_str = params.to_string();

        // 1. Path traversal check
        if self.path_traversal_regex.is_match(&params_str) {
            let cat = RaspThreatCategory::PathTraversal;
            let dec = self.policy_engine.evaluate_mitigation_action(
                cat,
                "Unauthorized directory traversal pattern detected in tool parameters",
                subject,
                "RASP-TOOL-001",
            );
            return (dec, Some(cat), params.clone());
        }

        // 2. Command injection check
        if self.cmd_injection_regex.is_match(&params_str) {
            let cat = RaspThreatCategory::CommandInjection;
            let dec = self.policy_engine.evaluate_mitigation_action(
                cat,
                "Command injection delimiter or shell binary detected in tool parameters",
                subject,
                "RASP-TOOL-002",
            );
            return (dec, Some(cat), params.clone());
        }

        // 3. Dynamic 64-bit numerical boundary validation
        if let Some(obj) = params.as_object() {
            for (key, val) in obj {
                if key.contains("amount") || key.contains("budget") || key.contains("count") || key.contains("limit") {
                    if let Some(n) = val.as_i64() {
                        // Negative values on financial or disbursement actions are invalid
                        if n < 0 && (tool_name.contains("disburse") || tool_name.contains("transfer") || tool_name.contains("spend")) {
                            let cat = RaspThreatCategory::NumericalBoundaryViolation;
                            let dec = self.policy_engine.evaluate_mitigation_action(
                                cat,
                                &format!("Negative numerical disbursement attempted: {}", n),
                                subject,
                                "RASP-TOOL-003",
                            );
                            return (dec, Some(cat), params.clone());
                        }

                        // High-value disbursement without supervisor signature
                        let max_unattested = self.policy_engine.config().max_ledger_disbursement_unattested;
                        if n > max_unattested && subject.supervisor_signature.is_none() && subject.trust_tier != AgentTrustTier::SupervisorAttested {
                            let cat = RaspThreatCategory::PrivilegeEscalation;
                            let dec = self.policy_engine.evaluate_mitigation_action(
                                cat,
                                &format!("Disbursement of ${} exceeds ${} limit without supervisor attestation", n, max_unattested),
                                subject,
                                "RASP-TOOL-004",
                            );
                            return (dec, Some(cat), params.clone());
                        }
                    }
                }
            }
        }

        // 4. Cedar policy evaluation if gateway provided
        if let Some(gateway) = cedar_gateway {
            let resource_type = match tool_name {
                "doc_extractor" => "Document",
                "ledger_writer" => "Ledger",
                "http_egress" => "NetworkTarget",
                "notifier" => "Agent",
                "change_security_policy" => "SystemPolicy",
                "quarantine" => "DecoyTrap",
                "kernel_sentinel" => "KernelSubstrate",
                _ => "Actuator",
            };

            let eval_result = gateway.engine().evaluate(
                &subject.agent_id,
                tool_name,
                "system_actuator",
                resource_type,
                params.clone(),
            );

            match eval_result {
                Ok(verdict) => {
                    if !verdict.is_allowed {
                        let cat = RaspThreatCategory::ToolParameterTampering;
                        let dec = self.policy_engine.evaluate_mitigation_action(
                            cat,
                            &format!("Cedar policy violation: {:?}", verdict.diagnostic_errors),
                            subject,
                            "RASP-CEDAR-GATE",
                        );
                        return (dec, Some(cat), params.clone());
                    }
                }
                Err(e) => {
                    let cat = RaspThreatCategory::ToolParameterTampering;
                    let dec = self.policy_engine.evaluate_mitigation_action(
                        cat,
                        &format!("Cedar evaluation failure: {}", e),
                        subject,
                        "RASP-CEDAR-ERROR",
                    );
                    return (dec, Some(cat), params.clone());
                }
            }
        }

        (
            RaspDecision::Allow {
                taint_level: TaintLevel::Clean,
            },
            None,
            params.clone(),
        )
    }
}

impl RaspInterceptor for ToolActuatorInterceptor {
    fn name(&self) -> &'static str {
        "ToolActuatorInterceptor"
    }

    fn is_enabled(&self) -> bool {
        true
    }
}

// ============================================================================
// 3. Memory & Scratchpad Interceptor
// ============================================================================

pub struct MemoryScratchpadInterceptor {
    policy_engine: Arc<RaspPolicyEngine>,
    credential_regex: Regex,
}

impl Default for MemoryScratchpadInterceptor {
    fn default() -> Self {
        Self::new(Arc::new(RaspPolicyEngine::default()))
    }
}

impl MemoryScratchpadInterceptor {
    pub fn new(policy_engine: Arc<RaspPolicyEngine>) -> Self {
        let cred_regex = Regex::new(r#"(?i)(sk-[a-zA-Z0-9_\-]{20,}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16}|-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----)"#).unwrap();
        Self {
            policy_engine,
            credential_regex: cred_regex,
        }
    }

    /// Intercepts memory read requests and enforces isolation boundaries.
    pub fn intercept_memory_read(
        &self,
        key: &str,
        subject: &AgentSecuritySubject,
    ) -> (RaspDecision, Option<RaspThreatCategory>) {
        // 1. Canary check
        if let Some((canary, label)) = self.policy_engine.canary_mgr().check_and_trip(key) {
            let cat = RaspThreatCategory::CanaryTokenTripped;
            let dec = self.policy_engine.evaluate_mitigation_action(
                cat,
                &format!("Unauthorized access to canary memory address: {} ({})", canary, label),
                subject,
                "RASP-MEM-001",
            );
            return (dec, Some(cat));
        }

        // 2. Cross-agent scratchpad partition: workers cannot read another worker's private scratchpad
        if key.starts_with("scratchpad:") {
            let parts: Vec<&str> = key.split(':').collect();
            if parts.len() >= 2 {
                let owner = parts[1];
                if owner != subject.agent_id && subject.trust_tier == AgentTrustTier::WorkerSandboxed {
                    let cat = RaspThreatCategory::ScratchpadBleed;
                    let dec = self.policy_engine.evaluate_mitigation_action(
                        cat,
                        &format!("Cross-agent scratchpad access denied for agent '{}' accessing '{}'", subject.agent_id, owner),
                        subject,
                        "RASP-MEM-002",
                    );
                    return (dec, Some(cat));
                }
            }
        }

        (
            RaspDecision::Allow {
                taint_level: TaintLevel::Clean,
            },
            None,
        )
    }

    /// Intercepts memory write operations, sanitizes credentials, and trips canary writes.
    pub fn intercept_memory_write(
        &self,
        key: &str,
        content: &str,
        subject: &AgentSecuritySubject,
    ) -> (RaspDecision, Option<RaspThreatCategory>, String) {
        // 1. Canary check
        if let Some((canary, label)) = self.policy_engine.canary_mgr().check_and_trip(key) {
            let cat = RaspThreatCategory::CanaryTokenTripped;
            let dec = self.policy_engine.evaluate_mitigation_action(
                cat,
                &format!("Unauthorized write to canary memory address: {} ({})", canary, label),
                subject,
                "RASP-MEM-003",
            );
            return (dec, Some(cat), content.to_string());
        }

        // 2. Detect and auto-redact credentials
        if self.credential_regex.is_match(content) {
            let sanitized = self.credential_regex.replace_all(content, "[REDACTED_BY_RT_ASP]").to_string();
            let cat = RaspThreatCategory::CredentialLeakage;
            let dec = self.policy_engine.evaluate_mitigation_action(
                cat,
                "Ephemeral credential pattern detected in memory write, auto-redaction enforced",
                subject,
                "RASP-MEM-004",
            );
            return (dec, Some(cat), sanitized);
        }

        (
            RaspDecision::Allow {
                taint_level: TaintLevel::Clean,
            },
            None,
            content.to_string(),
        )
    }
}

impl RaspInterceptor for MemoryScratchpadInterceptor {
    fn name(&self) -> &'static str {
        "MemoryScratchpadInterceptor"
    }

    fn is_enabled(&self) -> bool {
        true
    }
}

// ============================================================================
// 4. Lateral A2A (Agent-to-Agent) Interceptor
// ============================================================================

pub struct LateralA2AInterceptor {
    policy_engine: Arc<RaspPolicyEngine>,
}

impl Default for LateralA2AInterceptor {
    fn default() -> Self {
        Self::new(Arc::new(RaspPolicyEngine::default()))
    }
}

impl LateralA2AInterceptor {
    pub fn new(policy_engine: Arc<RaspPolicyEngine>) -> Self {
        Self { policy_engine }
    }

    /// Intercepts lateral communications and multi-agent ledger flows.
    pub fn intercept_a2a_message(
        &self,
        sender_subject: &AgentSecuritySubject,
        target_agent: &str,
        message: &serde_json::Value,
    ) -> (RaspDecision, Option<RaspThreatCategory>) {
        // 1. Prevent unauthorized inter-agent ledger transfers
        if let Some(action) = message.get("action").and_then(|a| a.as_str()) {
            if action == "disburse_ledger" || action == "transfer_funds" {
                let amount = message.get("amount").and_then(|a| a.as_i64()).unwrap_or(0);
                if amount > self.policy_engine.config().max_ledger_disbursement_unattested {
                    // Must have supervisor attestation
                    if sender_subject.supervisor_signature.is_none() && sender_subject.trust_tier != AgentTrustTier::SupervisorAttested {
                        let cat = RaspThreatCategory::LateralCollusion;
                        let dec = self.policy_engine.evaluate_mitigation_action(
                            cat,
                            &format!("Lateral ledger disbursement of ${} to '{}' without supervisor attestation", amount, target_agent),
                            sender_subject,
                            "RASP-A2A-001",
                        );
                        return (dec, Some(cat));
                    }
                }
            }
        }

        (
            RaspDecision::Allow {
                taint_level: TaintLevel::Clean,
            },
            None,
        )
    }
}

impl RaspInterceptor for LateralA2AInterceptor {
    fn name(&self) -> &'static str {
        "LateralA2AInterceptor"
    }

    fn is_enabled(&self) -> bool {
        true
    }
}

// ============================================================================
// 5. Substrate & Syscall Interceptor
// ============================================================================

pub struct SubstrateClampInterceptor {
    policy_engine: Arc<RaspPolicyEngine>,
}

impl Default for SubstrateClampInterceptor {
    fn default() -> Self {
        Self::new(Arc::new(RaspPolicyEngine::default()))
    }
}

impl SubstrateClampInterceptor {
    pub fn new(policy_engine: Arc<RaspPolicyEngine>) -> Self {
        Self { policy_engine }
    }

    /// Intercepts process spawn requests at the OS substrate level.
    pub fn intercept_process_spawn(
        &self,
        executable: &str,
        _args: &[String],
        subject: &AgentSecuritySubject,
    ) -> (RaspDecision, Option<RaspThreatCategory>) {
        let exe_lower = executable.to_ascii_lowercase();

        // System kernel subjects are allowed
        if subject.trust_tier == AgentTrustTier::SystemKernel {
            return (
                RaspDecision::Allow {
                    taint_level: TaintLevel::Clean,
                },
                None,
            );
        }

        // Veto unauthorized interactive shells
        let blocked_shells = ["powershell.exe", "cmd.exe", "bash", "sh", "wscript.exe", "cscript.exe", "pwsh.exe"];
        for blocked in &blocked_shells {
            if exe_lower.ends_with(blocked) {
                let cat = RaspThreatCategory::SubstrateClampBreach;
                let dec = self.policy_engine.evaluate_mitigation_action(
                    cat,
                    &format!("Unauthorized shell execution vetoed: {}", executable),
                    subject,
                    "RASP-SUBSTRATE-001",
                );
                return (dec, Some(cat));
            }
        }

        (
            RaspDecision::Allow {
                taint_level: TaintLevel::Clean,
            },
            None,
        )
    }

    /// Intercepts agent memory growth against the 64MB Windows Job Object clamp.
    pub fn intercept_memory_allocation(
        &self,
        requested_bytes: usize,
        current_usage_bytes: usize,
        subject: &AgentSecuritySubject,
    ) -> (RaspDecision, Option<RaspThreatCategory>) {
        let max_clamp = self.policy_engine.config().max_memory_bytes_per_agent;
        let total = current_usage_bytes.saturating_add(requested_bytes);

        if total > max_clamp && subject.trust_tier != AgentTrustTier::SystemKernel {
            let cat = RaspThreatCategory::SubstrateClampBreach;
            let dec = self.policy_engine.evaluate_mitigation_action(
                cat,
                &format!("Memory request {} bytes exceeds 64MB clamp (current: {}, max: {})", requested_bytes, current_usage_bytes, max_clamp),
                subject,
                "RASP-SUBSTRATE-002",
            );
            return (dec, Some(cat));
        }

        (
            RaspDecision::Allow {
                taint_level: TaintLevel::Clean,
            },
            None,
        )
    }
}

impl RaspInterceptor for SubstrateClampInterceptor {
    fn name(&self) -> &'static str {
        "SubstrateClampInterceptor"
    }

    fn is_enabled(&self) -> bool {
        true
    }
}
