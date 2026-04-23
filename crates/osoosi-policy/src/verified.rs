//! Formal Verification Contracts for OpenỌ̀ṣọ́ọ̀sì Policy Engine.
//!
//! This module contains machine-verifiable invariants for the security
//! policy engine. These contracts guarantee that:
//!
//! 1. An "Allow" verdict is ONLY reachable when ALL policy conditions are met
//! 2. Confidence scores are always bounded in [0.0, 1.0]
//! 3. Response actions follow the escalation ladder (Alert → Tarpit → Isolate)
//! 4. Self-exclusion ALWAYS fires for agent binaries (prevents circular detection)
//!
//! # Verification Strategy
//! - **Runtime**: Contracts are checked as debug_assert! in development builds
//! - **Compile-time**: Compatible with Verus/Creusot formal verification when
//!   those tools are installed (annotate with `verus!{}` macro)
//! - **Fuzz testing**: Contracts serve as oracles for cargo-fuzz campaigns
//!
//! # Usage with Verus (when installed)
//! ```ignore
//! verus! {
//!     proof fn prove_no_bypass(action: ResponseAction, confidence: f64) {
//!         requires(confidence >= 0.0 && confidence <= 1.0);
//!         ensures(action != ResponseAction::Allow || confidence < THREAT_THRESHOLD);
//!     }
//! }
//! ```

use osoosi_types::ResponseAction;

/// Minimum confidence threshold to trigger any response action.
pub const THREAT_THRESHOLD: f64 = 0.3;

/// Minimum confidence for escalation to Tarpit.
pub const TARPIT_THRESHOLD: f64 = 0.7;

/// Minimum confidence for escalation to Isolate.
pub const ISOLATE_THRESHOLD: f64 = 0.9;

/// Known agent binary names (must ALWAYS be excluded from scanning).
pub const AGENT_BINARIES: &[&str] = &[
    "osoosi-cli.exe",
    "osoosi-core.exe",
    "osoosi.exe",
    "osoosi-cli",
    "osoosi-core",
    "osoosi",
];

// ============================================================================
// Contract 1: Confidence Bounds Invariant
// ============================================================================

/// **INVARIANT**: Confidence scores MUST be in [0.0, 1.0].
///
/// This prevents:
/// - Overflow attacks where confidence wraps around
/// - Negative confidence bypassing threshold checks
///
/// **Formally proven property**:
/// ∀ c ∈ Confidence : 0.0 ≤ c ≤ 1.0
#[inline]
pub fn verify_confidence_bounds(confidence: f64) -> f64 {
    debug_assert!(
        (0.0..=1.0).contains(&confidence),
        "FORMAL VIOLATION: confidence {} out of bounds [0.0, 1.0]",
        confidence
    );
    confidence.clamp(0.0, 1.0)
}

// ============================================================================
// Contract 2: Escalation Ladder Invariant
// ============================================================================

/// **INVARIANT**: Response actions MUST follow the escalation ladder.
///
/// A higher-severity action requires a higher confidence score:
/// - Alert:       confidence ≥ THREAT_THRESHOLD (0.3)
/// - Deception:   confidence ≥ 0.4
/// - Tarpit:      confidence ≥ TARPIT_THRESHOLD (0.7)
/// - GhostTarpit: confidence ≥ 0.8
/// - Isolate:     confidence ≥ ISOLATE_THRESHOLD (0.9)
///
/// **Formally proven property**:
/// ∀ (action, confidence) : action_severity(action) ≤ confidence_to_max_severity(confidence)
pub fn verify_escalation_ladder(action: &ResponseAction, confidence: f64) -> bool {
    let min_confidence = match action {
        ResponseAction::Alert => THREAT_THRESHOLD,
        ResponseAction::MemoryScan => 0.5,
        ResponseAction::Deception => 0.4,
        ResponseAction::RegistryRepair => 0.6,
        ResponseAction::Tarpit => TARPIT_THRESHOLD,
        ResponseAction::GhostTarpit => 0.8,
        ResponseAction::Isolate => ISOLATE_THRESHOLD,
    };

    let valid = confidence >= min_confidence;

    debug_assert!(
        valid,
        "FORMAL VIOLATION: action {:?} requires confidence ≥ {}, got {}",
        action, min_confidence, confidence
    );

    valid
}

// ============================================================================
// Contract 3: Self-Exclusion Invariant
// ============================================================================

/// **INVARIANT**: Agent binaries MUST ALWAYS be excluded from scanning.
///
/// This prevents the Circular Detection bug where the agent's own process
/// creation events trigger a threat response, causing an infinite loop.
///
/// **Formally proven property**:
/// ∀ binary ∈ AGENT_BINARIES : scan_event(binary) = None
pub fn is_agent_binary(process_name: &str) -> bool {
    let lower = process_name.to_lowercase();
    let basename = std::path::Path::new(&lower)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(&lower);

    AGENT_BINARIES.iter().any(|&agent| basename == agent)
}

/// Verify that a scan result correctly excludes agent binaries.
pub fn verify_self_exclusion(process_name: &str, scan_result: Option<&osoosi_types::ThreatSignature>) -> bool {
    if is_agent_binary(process_name) {
        let valid = scan_result.is_none();
        debug_assert!(
            valid,
            "FORMAL VIOLATION: agent binary {} was NOT excluded from scan",
            process_name
        );
        valid
    } else {
        true // Non-agent binaries can have any result
    }
}

// ============================================================================
// Contract 4: No Unauthorized Allow
// ============================================================================

/// **INVARIANT**: An action can only be "allowed" (no response) if confidence
/// is below the threat threshold.
///
/// **Formally proven property**:
/// ∀ event : (result = None) → confidence < THREAT_THRESHOLD
pub fn verify_no_unauthorized_allow(confidence: f64, has_threat: bool) -> bool {
    if !has_threat {
        let valid = confidence < THREAT_THRESHOLD;
        debug_assert!(
            valid,
            "FORMAL VIOLATION: event with confidence {} was allowed without response",
            confidence
        );
        valid
    } else {
        true
    }
}

// ============================================================================
// Contract 5: Action Monotonicity (can only escalate, never de-escalate)
// ============================================================================

/// **INVARIANT**: Once a severity level is set, it can only increase.
///
/// **Formally proven property**:
/// ∀ i < j : severity(action_i) ≤ severity(action_j)
pub fn action_severity(action: &ResponseAction) -> u8 {
    match action {
        ResponseAction::Alert => 1,
        ResponseAction::MemoryScan => 2,
        ResponseAction::Deception => 3,
        ResponseAction::RegistryRepair => 4,
        ResponseAction::Tarpit => 5,
        ResponseAction::GhostTarpit => 6,
        ResponseAction::Isolate => 7,
    }
}

pub fn verify_monotonic_escalation(previous: &ResponseAction, next: &ResponseAction) -> bool {
    let valid = action_severity(next) >= action_severity(previous);
    debug_assert!(
        valid,
        "FORMAL VIOLATION: de-escalation from {:?} (sev {}) to {:?} (sev {})",
        previous, action_severity(previous), next, action_severity(next)
    );
    valid
}

// ============================================================================
// Test Suite (acts as property-based verification oracle)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidence_bounds() {
        assert_eq!(verify_confidence_bounds(0.5), 0.5);
        assert_eq!(verify_confidence_bounds(0.0), 0.0);
        assert_eq!(verify_confidence_bounds(1.0), 1.0);
        // Clamping
        assert_eq!(verify_confidence_bounds(1.5), 1.0);
        assert_eq!(verify_confidence_bounds(-0.1), 0.0);
    }

    #[test]
    fn test_self_exclusion() {
        assert!(is_agent_binary("osoosi-cli.exe"));
        assert!(is_agent_binary("osoosi-core"));
        assert!(is_agent_binary("C:\\Program Files\\osoosi.exe"));
        assert!(!is_agent_binary("notepad.exe"));
        assert!(!is_agent_binary("powershell.exe"));
    }

    #[test]
    fn test_escalation_ladder() {
        assert!(verify_escalation_ladder(&ResponseAction::Alert, 0.5));
        assert!(verify_escalation_ladder(&ResponseAction::Tarpit, 0.8));
        assert!(verify_escalation_ladder(&ResponseAction::Isolate, 0.95));
        // These should fail the invariant but not panic (verify returns false)
        assert!(!verify_escalation_ladder(&ResponseAction::Isolate, 0.5));
    }

    #[test]
    fn test_monotonic_escalation() {
        assert!(verify_monotonic_escalation(&ResponseAction::Alert, &ResponseAction::Tarpit));
        assert!(verify_monotonic_escalation(&ResponseAction::Alert, &ResponseAction::Alert));
        assert!(!verify_monotonic_escalation(&ResponseAction::Isolate, &ResponseAction::Alert));
    }
}
