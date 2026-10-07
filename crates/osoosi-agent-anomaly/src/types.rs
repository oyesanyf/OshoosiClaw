use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Tool call telemetry emitted by autonomous agents or intercepted by the EDR gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallTelemetry {
    pub session_id: String,
    pub agent_id: String,
    pub trace_id: Option<String>,
    pub tool_name: String,
    pub call_parameters: serde_json::Value,
    pub execution_duration_ms: u64,
    pub timestamp: DateTime<Utc>,
    pub tokens_used: Option<u32>,
    pub is_error: bool,
    pub error_message: Option<String>,
}

/// OWASP Top 10 for Agentic Applications (2026 Edition) risk taxonomy mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OwaspAgenticRisk {
    PromptInjectionASI01,
    ToolMisuseASI02,
    PrivilegeAbuseASI03,
    SupplyChainPoisoningASI04,
    UnexpectedExecutionASI05,
    ContextPoisoningASI06,
    DataExfiltrationASI07,
    CascadingFailuresASI08,
    ResourceExhaustionASI09,
    RogueAgentASI10,
}

impl OwaspAgenticRisk {
    /// Returns the standard OWASP Agentic code (e.g. "ASI01").
    pub fn as_code(&self) -> &'static str {
        match self {
            Self::PromptInjectionASI01 => "ASI01",
            Self::ToolMisuseASI02 => "ASI02",
            Self::PrivilegeAbuseASI03 => "ASI03",
            Self::SupplyChainPoisoningASI04 => "ASI04",
            Self::UnexpectedExecutionASI05 => "ASI05",
            Self::ContextPoisoningASI06 => "ASI06",
            Self::DataExfiltrationASI07 => "ASI07",
            Self::CascadingFailuresASI08 => "ASI08",
            Self::ResourceExhaustionASI09 => "ASI09",
            Self::RogueAgentASI10 => "ASI10",
        }
    }

    /// Returns the descriptive OWASP Agentic title.
    pub fn as_name(&self) -> &'static str {
        match self {
            Self::PromptInjectionASI01 => "Prompt Injection & Jailbreak",
            Self::ToolMisuseASI02 => "Tool Misuse & Excessive Agency",
            Self::PrivilegeAbuseASI03 => "Identity & Privilege Abuse",
            Self::SupplyChainPoisoningASI04 => "Untrusted Tool & Supply Chain Poisoning",
            Self::UnexpectedExecutionASI05 => "Unexpected Execution Path",
            Self::ContextPoisoningASI06 => "Context & RAG Poisoning",
            Self::DataExfiltrationASI07 => "Secondary Channel Data Exfiltration",
            Self::CascadingFailuresASI08 => "Cascading Failures & Multi-Agent Loops",
            Self::ResourceExhaustionASI09 => "Resource Exhaustion & Denial of Wallet",
            Self::RogueAgentASI10 => "Rogue Agent & Mission Drift",
        }
    }

    /// All OWASP Agentic risk variants.
    pub fn all() -> &'static [OwaspAgenticRisk] {
        &[
            Self::PromptInjectionASI01,
            Self::ToolMisuseASI02,
            Self::PrivilegeAbuseASI03,
            Self::SupplyChainPoisoningASI04,
            Self::UnexpectedExecutionASI05,
            Self::ContextPoisoningASI06,
            Self::DataExfiltrationASI07,
            Self::CascadingFailuresASI08,
            Self::ResourceExhaustionASI09,
            Self::RogueAgentASI10,
        ]
    }
}

/// Alert severity classifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl AlertSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
}

/// An identified anomaly with evidence, confidence, and tactical remediation advice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyFinding {
    pub id: String,
    pub session_id: String,
    pub agent_id: String,
    pub risk_category: OwaspAgenticRisk,
    pub severity: AlertSeverity,
    pub confidence_score: f32,
    pub rationale: String,
    pub recommended_mitigation: String,
    pub flagged_at: DateTime<Utc>,
    pub evidence: serde_json::Value,
}

/// Aggregated per-session tracking summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSessionSummary {
    pub session_id: String,
    pub agent_id: String,
    pub total_calls: u64,
    pub flagged_anomalies: usize,
    pub last_active: DateTime<Utc>,
    pub highest_severity: AlertSeverity,
}

/// Response returned to an interceptor callback or policy enforcement point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforceDecision {
    pub allowed: bool,
    pub action: String, // "allow", "block", "isolate", "require_approval"
    pub finding: Option<AnomalyFinding>,
    pub reason: Option<String>,
}
