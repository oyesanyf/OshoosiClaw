use super::*;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use osoosi_behavioral::{EmbeddingGemma2Engine, MatryoshkaDim};
use osoosi_types::{ArmRole, HostSecurityEvent, OctopusSecurityError};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

// ============================================================================
// 2. Canonical Cedar Entities, Actions, & Enforcement Stages
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CedarAction {
    ChildProcessExec,
    SensitiveFileAccess,
    ExternalNetworkConnect,
    ExternalWrite,
    PrivilegedLocalControl,
    DynamicCodeExec,
    CrossSessionTransfer,
}

impl CedarAction {
    pub fn cedar_id(self) -> &'static str {
        match self {
            Self::ChildProcessExec => "Action::\"ChildProcessExec\"",
            Self::SensitiveFileAccess => "Action::\"SensitiveFileAccess\"",
            Self::ExternalNetworkConnect => "Action::\"ExternalNetworkConnect\"",
            Self::ExternalWrite => "Action::\"ExternalWrite\"",
            Self::PrivilegedLocalControl => "Action::\"PrivilegedLocalControl\"",
            Self::DynamicCodeExec => "Action::\"DynamicCodeExec\"",
            Self::CrossSessionTransfer => "Action::\"CrossSessionTransfer\"",
        }
    }

    pub fn matrix_operation_class(self) -> &'static str {
        match self {
            Self::ChildProcessExec => "Child process execution",
            Self::SensitiveFileAccess => "Sensitive file access",
            Self::ExternalNetworkConnect => "External network connection",
            Self::ExternalWrite => "External SaaS mutation",
            Self::PrivilegedLocalControl => "Privileged IPC operation",
            Self::DynamicCodeExec => "Dynamic code execution",
            Self::CrossSessionTransfer => "Cross-session data transfer",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum DataClassification {
    Public = 0,
    InternalWorkspace = 1,
    Confidential = 2,
    CrownJewelSecret = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EnforcementStage {
    PreExecutionPrevented,
    PostNotificationContained,
    PostExecutionDetected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CedarPrincipal {
    pub principal_id: String,
    pub session_id: String,
    pub process_instance_key: String,
    pub authority_level: AuthorityLevel,
    pub approved_capabilities: Vec<String>,
    #[serde(default)]
    pub authenticated_role: Option<ArmRole>,
}

impl CedarPrincipal {
    pub fn new(
        principal_id: impl Into<String>,
        session_id: impl Into<String>,
        process_instance_key: impl Into<String>,
        authority_level: AuthorityLevel,
        approved_capabilities: Vec<String>,
    ) -> Self {
        Self {
            principal_id: principal_id.into(),
            session_id: session_id.into(),
            process_instance_key: process_instance_key.into(),
            authority_level,
            approved_capabilities,
            authenticated_role: None,
        }
    }

    pub fn with_role(mut self, role: ArmRole) -> Self {
        self.authenticated_role = Some(role);
        self
    }
}

/// Maps an authenticated ArmRole to its canonical reserved Cedar principal name.
pub fn canonical_reserved_principal_for_role(role: &ArmRole) -> &'static str {
    match role {
        ArmRole::UntrustedDocIngest => "document_arm",
        ArmRole::AccountingLedgerWrite => "ledger_arm",
        ArmRole::NetworkEgress => "network_arm",
        ArmRole::TarpitDecoyDefense => "tarpit_arm",
        ArmRole::KernelLevelSentinel => "kernel_sentinel_arm",
        ArmRole::OutboundNotification => "notifier_arm",
        ArmRole::CedarPolicyEvaluation => "cedar_arm",
        ArmRole::AtlasThreatIntelligence => "atlas_arm",
        ArmRole::AnomalyDetection => "anomaly_arm",
        ArmRole::VulnerabilityResearch => "vulnerability_arm",
        ArmRole::ContinuousOssFuzz => "oss_fuzz_arm",
        ArmRole::ContinuousOsvScanner => "osv_scanner_arm",
        ArmRole::DifferentialProtocolAnalyzer => "protocol_analyzer_arm",
        ArmRole::AutonomousProtocolResearch => "protocol_research_arm",
        ArmRole::PostQuantumAttestation => "pqc_arm",
        ArmRole::EvolutionaryOptimizer => "evolution_arm",
        ArmRole::DreamRsiOptimizer => "dream_rsi_arm",
        ArmRole::RecursiveHarnessOptimizer => "harness2_arm",
    }
}

/// Checks if an identifier matches one of the reserved Cedar principal identities.
pub fn is_reserved_principal(agent_id: &str) -> bool {
    matches!(
        agent_id,
        "document_arm"
            | "ledger_arm"
            | "network_arm"
            | "tarpit_arm"
            | "kernel_sentinel_arm"
            | "notifier_arm"
            | "cedar_arm"
            | "atlas_arm"
            | "anomaly_arm"
            | "vulnerability_arm"
            | "oss_fuzz_arm"
            | "osv_scanner_arm"
            | "protocol_analyzer_arm"
            | "protocol_research_arm"
            | "pqc_arm"
            | "evolution_arm"
            | "dream_rsi_arm"
            | "harness2_arm"
    )
}

/// Validates that an agent claiming a reserved Cedar principal identity has an authenticated role matching that principal.
/// Rejects unauthorized or mismatched principal claims with `CEDAR_PRINCIPAL_SPOOF_BLOCKED`.
pub fn validate_cedar_principal_role(
    agent_id: &str,
    role: &ArmRole,
) -> Result<&'static str, OctopusSecurityError> {
    let role_principal = canonical_reserved_principal_for_role(role);
    if is_reserved_principal(agent_id) && agent_id != role_principal {
        return Err(OctopusSecurityError::CapabilityDenied(format!(
            "CEDAR_PRINCIPAL_SPOOF_BLOCKED: agent_id '{}' conflicts with authenticated role {:?} (expected '{}')",
            agent_id, role, role_principal
        )));
    }
    Ok(role_principal)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CedarResource {
    pub resource_id: String,
    pub resource_type: String,
    pub classification: DataClassification,
    pub is_signed_and_allowlisted: bool,
    pub is_approved_child_binary: bool,
    pub is_task_scoped_destination: bool,
    pub is_declassified_approved_sink: bool,
    pub service_identity: Option<String>,
    pub service_operation: Option<String>,
}
