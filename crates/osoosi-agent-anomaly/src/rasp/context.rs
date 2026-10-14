use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Trust tier classification of the agent subject requesting execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RaspAgentTrustTier {
    SystemKernel,
    SupervisorAttested,
    WorkerSandboxed,
    UntrustedExternal,
}

pub type AgentTrustTier = RaspAgentTrustTier;

impl Default for RaspAgentTrustTier {
    fn default() -> Self {
        RaspAgentTrustTier::WorkerSandboxed
    }
}

/// Subject identity and security attributes of an agent requesting execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSecuritySubject {
    pub agent_id: String,
    pub role: String,
    pub trust_tier: AgentTrustTier,
    pub session_id: String,
    pub tenant_id: Option<String>,
    pub supervisor_signature: Option<String>,
    pub step_count: usize,
    pub memory_usage_bytes: usize,
}

impl Default for AgentSecuritySubject {
    fn default() -> Self {
        Self {
            agent_id: "agent_worker_default".to_string(),
            role: "worker".to_string(),
            trust_tier: AgentTrustTier::WorkerSandboxed,
            session_id: "sess_default".to_string(),
            tenant_id: None,
            supervisor_signature: None,
            step_count: 0,
            memory_usage_bytes: 1024 * 1024, // 1MB nominal
        }
    }
}

impl AgentSecuritySubject {
    pub fn new(agent_id: &str, role: &str, trust_tier: AgentTrustTier) -> Self {
        Self {
            agent_id: agent_id.to_string(),
            role: role.to_string(),
            trust_tier,
            session_id: format!("sess_{}", rand::random::<u32>()),
            tenant_id: None,
            supervisor_signature: None,
            step_count: 0,
            memory_usage_bytes: 1024 * 1024,
        }
    }

    pub fn with_supervisor_attestation(mut self, sig: &str) -> Self {
        self.supervisor_signature = Some(sig.to_string());
        if self.trust_tier == AgentTrustTier::WorkerSandboxed {
            self.trust_tier = AgentTrustTier::SupervisorAttested;
        }
        self
    }
}

/// Dynamic semantic taint level tracking for inputs and context memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TaintLevel {
    Clean = 0,
    Suspect = 1,
    Tainted = 2,
    Malicious = 3,
}

/// Taxonomy of agentic threat categories intercepted by RT-ASP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RaspThreatCategory {
    PromptInjection,
    SemanticJailbreak,
    ToolParameterTampering,
    NumericalBoundaryViolation,
    PathTraversal,
    CommandInjection,
    ScratchpadBleed,
    CredentialLeakage,
    CanaryTokenTripped,
    LateralCollusion,
    PrivilegeEscalation,
    SubstrateClampBreach,
    SteganographySmuggling,
    MultilingualSmuggling,
}

impl std::fmt::Display for RaspThreatCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Security decision rendered by an RT-ASP interceptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RaspDecision {
    Allow {
        taint_level: TaintLevel,
    },
    Deny {
        reason: String,
        policy_id: String,
        threat_category: RaspThreatCategory,
    },
    Tarpit {
        delay_ms: u64,
        decoy_payload: serde_json::Value,
        reason: String,
        threat_category: RaspThreatCategory,
    },
    Sanitize {
        modified_payload: serde_json::Value,
        redaction_count: usize,
        warnings: Vec<String>,
        threat_category: RaspThreatCategory,
    },
    Quarantine {
        agent_id: String,
        reason: String,
        threat_category: RaspThreatCategory,
    },
}

impl RaspDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, RaspDecision::Allow { .. } | RaspDecision::Sanitize { .. })
    }

    pub fn is_blocked(&self) -> bool {
        matches!(
            self,
            RaspDecision::Deny { .. } | RaspDecision::Quarantine { .. } | RaspDecision::Tarpit { .. }
        )
    }

    pub fn verdict_str(&self) -> &'static str {
        match self {
            RaspDecision::Allow { .. } => "ALLOW",
            RaspDecision::Deny { .. } => "DENY",
            RaspDecision::Tarpit { .. } => "TARPIT",
            RaspDecision::Sanitize { .. } => "SANITIZE",
            RaspDecision::Quarantine { .. } => "QUARANTINE",
        }
    }
}

/// Detailed telemetry event recorded upon interceptor invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaspInterceptionEvent {
    pub event_id: String,
    pub timestamp_secs: u64,
    pub interceptor_name: String,
    pub subject: AgentSecuritySubject,
    pub threat_category: Option<RaspThreatCategory>,
    pub decision: RaspDecision,
    pub raw_input_summary: String,
    pub sanitized_output_summary: Option<String>,
    pub latency_micros: u64,
    pub trace_id: String,
    pub remediated_by_rl: bool,
    pub attributes: HashMap<String, String>,
}
