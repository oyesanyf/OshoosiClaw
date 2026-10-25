//! Strongly Typed Arm Roles and Trust Tiers for Multi-Ring Containment (Finding 2).
//!
//! Provides exhaustive, compile-time classification of agent roles into mathematical trust tiers
//! (`Untrusted = 10`, `Worker = 50`, `PrivilegedSink = 100`) preventing confused-deputy authority
//! laundering across lateral inter-agent relays.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Trust tier of an authenticated arm role (discrete privilege potential $\phi \in \mathbb{Z}$).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TrustTier {
    /// Arms that ingest attacker-controlled input (documents, fuzz corpora, raw wire traffic, decoys).
    Untrusted = 10,
    /// Standard worker / analysis arms.
    Worker = 50,
    /// High-privilege sinks (ledger writes, kernel sentinel, policy authority, signing keys).
    PrivilegedSink = 100,
}

impl TrustTier {
    /// Discrete privilege potential 0-cochain value.
    pub fn potential(self) -> i64 {
        self as i64
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Untrusted => "Untrusted",
            Self::Worker => "Worker",
            Self::PrivilegedSink => "PrivilegedSink",
        }
    }
}

impl fmt::Display for TrustTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Exhaustive catalog of all 18 swarm agent arm roles in the hybrid containment architecture.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArmRole {
    UntrustedDocIngest,
    AccountingLedgerWrite,
    OutboundNotification,
    NetworkEgress,
    TarpitDecoyDefense,
    KernelLevelSentinel,
    CedarPolicyEvaluation,
    AtlasThreatIntelligence,
    AnomalyDetection,
    VulnerabilityResearch,
    ContinuousOssFuzz,
    ContinuousOsvScanner,
    DifferentialProtocolAnalyzer,
    AutonomousProtocolResearch,
    PostQuantumAttestation,
    EvolutionaryOptimizer,
    DreamRsiOptimizer,
    RecursiveHarnessOptimizer,
}

impl ArmRole {
    /// Maps this role to its compile-time immutable trust tier.
    pub fn trust_tier(&self) -> TrustTier {
        role_trust_tier(self)
    }

    /// Discrete privilege potential $\phi(v)$.
    pub fn potential(&self) -> i64 {
        self.trust_tier().potential()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UntrustedDocIngest => "UntrustedDocIngest",
            Self::AccountingLedgerWrite => "AccountingLedgerWrite",
            Self::OutboundNotification => "OutboundNotification",
            Self::NetworkEgress => "NetworkEgress",
            Self::TarpitDecoyDefense => "TarpitDecoyDefense",
            Self::KernelLevelSentinel => "KernelLevelSentinel",
            Self::CedarPolicyEvaluation => "CedarPolicyEvaluation",
            Self::AtlasThreatIntelligence => "AtlasThreatIntelligence",
            Self::AnomalyDetection => "AnomalyDetection",
            Self::VulnerabilityResearch => "VulnerabilityResearch",
            Self::ContinuousOssFuzz => "ContinuousOssFuzz",
            Self::ContinuousOsvScanner => "ContinuousOsvScanner",
            Self::DifferentialProtocolAnalyzer => "DifferentialProtocolAnalyzer",
            Self::AutonomousProtocolResearch => "AutonomousProtocolResearch",
            Self::PostQuantumAttestation => "PostQuantumAttestation",
            Self::EvolutionaryOptimizer => "EvolutionaryOptimizer",
            Self::DreamRsiOptimizer => "DreamRsiOptimizer",
            Self::RecursiveHarnessOptimizer => "RecursiveHarnessOptimizer",
        }
    }
}

impl fmt::Display for ArmRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for ArmRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let clean = s.trim();
        match clean {
            "UntrustedDocIngest" => Ok(Self::UntrustedDocIngest),
            "AccountingLedgerWrite" => Ok(Self::AccountingLedgerWrite),
            "OutboundNotification" => Ok(Self::OutboundNotification),
            "NetworkEgress" => Ok(Self::NetworkEgress),
            "TarpitDecoyDefense" => Ok(Self::TarpitDecoyDefense),
            "KernelLevelSentinel" => Ok(Self::KernelLevelSentinel),
            "CedarPolicyEvaluation" => Ok(Self::CedarPolicyEvaluation),
            "AtlasThreatIntelligence" => Ok(Self::AtlasThreatIntelligence),
            "AnomalyDetection" => Ok(Self::AnomalyDetection),
            "VulnerabilityResearch" => Ok(Self::VulnerabilityResearch),
            "ContinuousOssFuzz" => Ok(Self::ContinuousOssFuzz),
            "ContinuousOsvScanner" => Ok(Self::ContinuousOsvScanner),
            "DifferentialProtocolAnalyzer" => Ok(Self::DifferentialProtocolAnalyzer),
            "AutonomousProtocolResearch" => Ok(Self::AutonomousProtocolResearch),
            "PostQuantumAttestation" => Ok(Self::PostQuantumAttestation),
            "EvolutionaryOptimizer" => Ok(Self::EvolutionaryOptimizer),
            "DreamRsiOptimizer" => Ok(Self::DreamRsiOptimizer),
            "RecursiveHarnessOptimizer" => Ok(Self::RecursiveHarnessOptimizer),
            other => Err(format!("Unknown ArmRole: '{}'", other)),
        }
    }
}

/// Exhaustive role -> trust tier mapping.
///
/// INVARIANT: There is deliberately NO wildcard arm match.
/// Adding a new [`ArmRole`] variant is a compile error until it is explicitly classified (fail-closed).
pub fn role_trust_tier(role: &ArmRole) -> TrustTier {
    match role {
        ArmRole::UntrustedDocIngest
        | ArmRole::DifferentialProtocolAnalyzer
        | ArmRole::AutonomousProtocolResearch
        | ArmRole::ContinuousOssFuzz
        | ArmRole::TarpitDecoyDefense => TrustTier::Untrusted,

        ArmRole::AccountingLedgerWrite
        | ArmRole::KernelLevelSentinel
        | ArmRole::CedarPolicyEvaluation
        | ArmRole::PostQuantumAttestation => TrustTier::PrivilegedSink,

        ArmRole::OutboundNotification
        | ArmRole::NetworkEgress
        | ArmRole::AtlasThreatIntelligence
        | ArmRole::AnomalyDetection
        | ArmRole::VulnerabilityResearch
        | ArmRole::ContinuousOsvScanner
        | ArmRole::EvolutionaryOptimizer
        | ArmRole::DreamRsiOptimizer
        | ArmRole::RecursiveHarnessOptimizer => TrustTier::Worker,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arm_role_trust_tier_mapping() {
        assert_eq!(role_trust_tier(&ArmRole::UntrustedDocIngest), TrustTier::Untrusted);
        assert_eq!(role_trust_tier(&ArmRole::AnomalyDetection), TrustTier::Worker);
        assert_eq!(role_trust_tier(&ArmRole::AccountingLedgerWrite), TrustTier::PrivilegedSink);
        assert_eq!(ArmRole::CedarPolicyEvaluation.trust_tier(), TrustTier::PrivilegedSink);
        assert_eq!(ArmRole::DifferentialProtocolAnalyzer.trust_tier(), TrustTier::Untrusted);
    }

    #[test]
    fn test_arm_role_roundtrip() {
        for role in [
            ArmRole::UntrustedDocIngest,
            ArmRole::AccountingLedgerWrite,
            ArmRole::OutboundNotification,
            ArmRole::NetworkEgress,
            ArmRole::TarpitDecoyDefense,
            ArmRole::KernelLevelSentinel,
            ArmRole::CedarPolicyEvaluation,
            ArmRole::AtlasThreatIntelligence,
            ArmRole::AnomalyDetection,
            ArmRole::VulnerabilityResearch,
            ArmRole::ContinuousOssFuzz,
            ArmRole::ContinuousOsvScanner,
            ArmRole::DifferentialProtocolAnalyzer,
            ArmRole::AutonomousProtocolResearch,
            ArmRole::PostQuantumAttestation,
            ArmRole::EvolutionaryOptimizer,
            ArmRole::DreamRsiOptimizer,
            ArmRole::RecursiveHarnessOptimizer,
        ] {
            let s = role.to_string();
            let parsed: ArmRole = s.parse().unwrap();
            assert_eq!(role, parsed);
        }
    }
}
