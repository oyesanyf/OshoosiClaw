//! CAGE Governance Types
//!
//! Shared types for Google Cybernetic Agent Governance Engine (CAGE) integration.
//! These types define governance verdicts, cryptographic routing seals, multi-format
//! policy identifiers, STPA Unsafe Control Actions (UCAs), evaluation stage outcomes,
//! and Control Barrier Function (CBF) parameters.

use serde::{Deserialize, Serialize};

/// Canonical 5-element governance verdict lattice issued by the CAGE evaluation pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceVerdict {
    /// Action cleared all governance tiers without restriction.
    /// A single-use 30-second TTL cryptographic routing seal is issued.
    Allow,

    /// Hard constraints passed, but parameters exceeded soft policy boundaries.
    /// Execution is permitted only under the provided clamped parameters.
    Narrow { clamped_params: serde_json::Value },

    /// Action requires human-in-the-loop (HITL) approval or escalation.
    /// No routing seal is issued; request is parked with an approval token.
    RequireApproval {
        reason: String,
        approval_token: String,
    },

    /// Action is temporarily deferred (e.g. awaiting telemetry or confidence refresh).
    /// Client should retry after the specified backoff period.
    Defer { backoff_ms: u64 },

    /// Hard policy violation or Control Barrier Function (CBF) boundary breach.
    /// Action is blocked immediately; any reserved fiscal resources are rolled back.
    Deny { reason: String, proof_hash: String },
}

impl GovernanceVerdict {
    /// Returns true if the verdict allows execution (either directly or via narrowed parameters).
    #[inline]
    pub fn is_allowed_or_narrowed(&self) -> bool {
        matches!(self, Self::Allow | Self::Narrow { .. })
    }

    /// Returns true if the action is unconditionally denied.
    #[inline]
    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    /// Returns the canonical uppercase string representation of the verdict.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Narrow { .. } => "NARROW",
            Self::RequireApproval { .. } => "REQUIRE_APPROVAL",
            Self::Defer { .. } => "DEFER",
            Self::Deny { .. } => "DENY",
        }
    }
}

/// A cryptographically signed capability token binding an approved action to its execution payload.
///
/// Enforces the `NoDirectBind` invariant: downstream actuators (such as the host capability gate)
/// must validate and atomically consume this seal before executing state-mutating actuations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingSeal {
    /// Unique identifier (UUIDv4 or hex nonce) for this seal instance.
    pub seal_id: String,

    /// Deterministic 16-character hex SHA-256 identifier of the active policy version.
    pub policy_version_id: String,

    /// 64-character lowercase hex SHA-256 digest of the bound action and canonical parameters.
    pub action_digest: String,

    /// Issuance timestamp in Unix epoch seconds.
    pub issued_at: u64,

    /// Expiration timestamp in Unix epoch seconds (`issued_at + 30s`).
    pub expires_at: u64,

    /// HMAC-SHA256 signature authenticating the seal fields against the substrate secret key.
    pub signature: String,
}

impl RoutingSeal {
    /// Default TTL for CAGE routing seals (strictly 30 seconds).
    pub const DEFAULT_TTL_SECS: u64 = 30;

    /// Checks whether the routing seal has expired relative to the given Unix epoch timestamp.
    #[inline]
    pub fn is_expired(&self, current_time_secs: u64) -> bool {
        current_time_secs > self.expires_at
    }

    /// Computes the configured TTL duration in seconds.
    #[inline]
    pub fn ttl_seconds(&self) -> u64 {
        self.expires_at.saturating_sub(self.issued_at)
    }

    /// Validates the format of the seal identifiers (16-hex policy version and 64-hex action digest).
    pub fn validate_format(&self) -> bool {
        self.policy_version_id.len() == 16
            && self
                .policy_version_id
                .chars()
                .all(|c| c.is_ascii_hexdigit())
            && self.action_digest.len() == 64
            && self.action_digest.chars().all(|c| c.is_ascii_hexdigit())
            && !self.seal_id.is_empty()
            && !self.signature.is_empty()
    }
}

/// Supported external and native governance policy formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicyFormat {
    /// Microsoft Agent Control Specification (`behaviorDeclarations`)
    MicrosoftAcs,

    /// Linux Foundation Autonomous Agent Interoperability Framework (`governedRunLoop`)
    LinuxFoundationAaif,

    /// NIST Open Security Controls Assessment Language 1.1.x (`oscal-version`)
    NistOscal,

    /// Lula Validation Manifest (`kind: LulaValidation` or embedded Rego)
    LulaValidation,

    /// Native CAGE STPA control structure YAML/JSON (`stpa_control_structure`)
    CageStpa,
}

impl PolicyFormat {
    /// Canonical short identifier for the policy format.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MicrosoftAcs => "acs",
            Self::LinuxFoundationAaif => "aaif",
            Self::NistOscal => "oscal",
            Self::LulaValidation => "lula",
            Self::CageStpa => "cage_yaml",
        }
    }

    /// Resolves a short string identifier into a `PolicyFormat`.
    pub fn from_identifier(id: &str) -> Option<Self> {
        match id.to_ascii_lowercase().as_str() {
            "acs" | "microsoft_acs" | "microsoftacs" => Some(Self::MicrosoftAcs),
            "aaif" | "linux_foundation_aaif" | "linuxfoundationaaif" => {
                Some(Self::LinuxFoundationAaif)
            }
            "oscal" | "nist_oscal" | "nistoscal" => Some(Self::NistOscal),
            "lula" | "lula_validation" | "lulavalidation" => Some(Self::LulaValidation),
            "cage_yaml" | "stpa" | "cage_stpa" | "cagestpa" => Some(Self::CageStpa),
            _ => None,
        }
    }
}

impl std::fmt::Display for PolicyFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// STPA (Systems-Theoretic Process Analysis) Unsafe Control Action (UCA) definition.
///
/// Identifies hazardous control actions in specific operating contexts and maps them
/// to concrete mitigation constraints and Cedar rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsafeControlAction {
    /// Unique identifier for the UCA (e.g. "UCA-1", "ACS-TRADE-001").
    pub uca_id: String,

    /// Reference to the associated hazard identifier (e.g. "H-1", "H-FIN-01").
    pub hazard_ref: String,

    /// Name of the control action that may be issued unsafely.
    pub control_action: String,

    /// Contextual predicate or condition under which the action is considered unsafe.
    pub context_condition: String,

    /// Plaintext or rule-based safety constraint enforcing mitigation.
    pub mitigation: String,
}

/// Individual outcome recorded by a tier in the multi-tier governance pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageOutcome {
    /// Identifier of the evaluation stage (e.g. "ftra", "stpa", "cedar", "confidence", "consensus", "cbf", "fiscal").
    pub stage_name: String,

    /// Whether this specific tier passed.
    pub passed: bool,

    /// Diagnostic details or failure justification if applicable.
    pub details: Option<String>,
}

/// Parameters configuring the discrete-time exponential Control Barrier Function (CBF).
///
/// Constrains resource/safety depletion according to:
/// `h_{t+1} = (B_t - c) - B_min >= (1 - gamma) * h_t >= 0`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CbfParameters {
    /// Maximum fractional safety margin decay rate per step (`gamma \in (0, 1]`). Default: 0.1.
    pub gamma: f64,

    /// Invariant safety floor below which resources must never drop. Default: 10.0.
    pub b_min: f64,
}

impl Default for CbfParameters {
    fn default() -> Self {
        Self {
            gamma: 0.1,
            b_min: 10.0,
        }
    }
}
