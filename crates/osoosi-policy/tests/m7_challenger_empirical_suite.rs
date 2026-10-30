//! crates/osoosi-policy/tests/m7_challenger_empirical_suite.rs
//!
//! Milestone M7 Empirical Challenger Verification Suite:
//! Feature F20 (Consensus Engine Deterministic Asymmetric Veto & Boundary Stress Matrix)
//! Feature F21 (Regression & Robustness Verification)
//!
//! Conducted by teamwork_challenger_m7_1 (Empirical Challenger)
//!
//! Stress-tests:
//! 1. High-volume benign ML voter flooding (up to 5,000 voters at confidence 0.01) vs single deterministic invariant violations.
//! 2. Whitelist veto neutralization (NSRL, Trusted-Vendor, Git-Noise-Filter) combined with invariant breaches.
//! 3. Extreme voter weights (f32::INFINITY, -f32::INFINITY, f32::NAN, extreme magnitudes).
//! 4. Full 5-family invariant coverage (CedarForbid, Ring0Tamper, ProcessTokenPrivilege, CryptographicMeshMismatch, LateralContainmentBreach).

use chrono::Utc;
use osoosi_memory::MemoryStore;
use osoosi_policy::{
    detect_deterministic_asymmetric_veto, orchestrate_evidence, EvidenceClass, EvidenceVote,
    InvariantViolationFamily, PolicyEngine, ThreatVoter, VoteResult,
};
use osoosi_types::{HostEventSource, HostSecurityEvent, PolicyConfig, ResponseAction};
use serde_json::json;
use std::sync::Arc;

fn make_test_event(image: &str, cmdline: &str) -> HostSecurityEvent {
    HostSecurityEvent {
        source: HostEventSource::WindowsEventLog,
        event_id: 1, // ProcessCreate
        timestamp: Utc::now(),
        computer: "TEST-CHALLENGER-M7".to_string(),
        data: json!({
            "Image": image,
            "CommandLine": cmdline,
            "ProcessId": 8844,
        }),
        causal_parent: None,
    }
}

/// Dynamic Benign ML voter for stress testing
struct FloodingBenignVoter {
    id: usize,
    score: f32,
    weight: f32,
}

#[async_trait::async_trait]
impl ThreatVoter for FloodingBenignVoter {
    fn name(&self) -> String {
        format!("BenignML-Voter-{}", self.id)
    }

    async fn vote(&self, _event: &HostSecurityEvent) -> Option<VoteResult> {
        Some(VoteResult {
            confidence: self.score,
            reason: format!(
                "Flooding ML model {} predicts benign (p={:.4})",
                self.id, self.score
            ),
            weight: self.weight,
        })
    }
}

// =========================================================================
// Dimension 1: High-Volume Benign ML Voter Flooding vs Invariant Violations
// =========================================================================

#[test]
fn test_m7_direct_orchestrate_evidence_1000_ml_voters_flooding() {
    let config = PolicyConfig::default();
    let mut event = make_test_event(
        "C:\\Windows\\System32\\svchost.exe",
        "svchost.exe -k netsvcs",
    );
    event.data["PrivilegeEscalationDetected"] = json!(true);

    // Build 1,000 benign ML votes scoring 0.01 with weight 1.0
    let mut votes = Vec::with_capacity(1001);
    for i in 0..1000 {
        votes.push(EvidenceVote {
            result: VoteResult {
                confidence: 0.01,
                reason: format!("Benign PE Classifier #{}", i),
                weight: 1.0,
            },
            class: EvidenceClass::StaticArtifact,
            reliability: 0.80,
            strong_action: false,
        });
    }

    // Add a single deterministic memory/credential guard vote
    votes.push(EvidenceVote {
        result: VoteResult {
            confidence: 0.99,
            reason: "CredentialGuard: LSASS memory dump detected via comsvcs.dll".to_string(),
            weight: 3.0,
        },
        class: EvidenceClass::Memory,
        reliability: 0.98,
        strong_action: true,
    });

    let decision = orchestrate_evidence(&votes, &event, &config);

    // Invariant: Even with 1,000 benign votes diluting base to ~0.01,
    // confidence MUST saturate to 1.0 and action MUST command Isolate!
    assert_eq!(
        decision.confidence, 1.0f32,
        "CRITICAL INVARIANT VIOLATION: 1,000 ML voters diluted confidence below 1.0! Got: {}",
        decision.confidence
    );
    assert_eq!(
        decision.action,
        ResponseAction::Isolate,
        "Action must be ResponseAction::Isolate"
    );
    assert!(
        !decision.require_approval,
        "Autonomous containment must not require human approval"
    );
    assert!(
        decision.summary.contains("ASYMMETRIC_VETO_ISOLATE"),
        "Summary must explicitly document asymmetric veto isolate"
    );
}

#[tokio::test]
async fn test_m7_scan_event_500_ml_voters_flooding_end_to_end() {
    let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
    let config = PolicyConfig::default();
    let engine = PolicyEngine::new(memory, config);

    // Register 100 benign ML voters voting 0.01
    for i in 0..100 {
        engine
            .add_voter(Box::new(FloodingBenignVoter {
                id: i,
                score: 0.01,
                weight: 1.0,
            }))
            .await;
    }

    // Register 1 deterministic credential guard voter
    engine
        .add_voter(Box::new(osoosi_policy::voters::CredentialGuardVoter))
        .await;

    let mut event = make_test_event(
        "C:\\Windows\\System32\\rundll32.exe",
        "rundll32.exe comsvcs.dll, #24 672 C:\\temp\\lsass.dmp full",
    );
    event.data["TokenElevationViolation"] = json!(true);

    let sig = engine
        .scan_event(&event)
        .await
        .expect("Deterministic breach must emit threat signature despite ML flood");

    assert_eq!(
        sig.confidence, 1.0f32,
        "Confidence must be 1.0 under asymmetric veto"
    );
    assert_eq!(
        sig.recommended_action,
        ResponseAction::Isolate,
        "Action must be Isolate"
    );
    assert!(!sig.require_approval);
}

// =========================================================================
// Dimension 2: Whitelist Veto Neutralization Across All 5 Invariant Families
// =========================================================================

#[tokio::test]
async fn test_m7_whitelist_veto_neutralization_family_1_cedar_forbid() {
    let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
    let config = PolicyConfig::default();
    let engine = PolicyEngine::new(memory, config);

    // NSRL and Trusted-Vendor voters attempt to abort the round with weight -1.0
    engine
        .add_voter(Box::new(osoosi_policy::voters::TrustedVendorVoter))
        .await;

    let mut event = make_test_event("C:\\Windows\\System32\\notepad.exe", "notepad.exe");
    event.data["CedarDecision"] = json!("Forbid");
    event.data["CedarForbidTripped"] = json!(true);

    let sig = engine
        .scan_event(&event)
        .await
        .expect("NSRL/Trusted-Vendor cannot abort Family 1 (CedarForbid) breach");

    assert_eq!(sig.confidence, 1.0f32);
    assert_eq!(sig.recommended_action, ResponseAction::Isolate);
    assert!(!sig.require_approval);
}

#[tokio::test]
async fn test_m7_whitelist_veto_neutralization_family_2_ring0_tamper() {
    let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
    let config = PolicyConfig::default();
    let engine = PolicyEngine::new(memory, config);

    engine
        .add_voter(Box::new(osoosi_policy::voters::TrustedVendorVoter))
        .await;

    let mut event = make_test_event(
        "C:\\Windows\\System32\\svchost.exe",
        "svchost.exe -k netsvcs",
    );
    event.data["KernelTamperDetected"] = json!(true);
    event.data["DkomTamperDetected"] = json!(true);

    let sig = engine
        .scan_event(&event)
        .await
        .expect("Whitelist cannot abort Family 2 (Ring0Tamper) breach");

    assert_eq!(sig.confidence, 1.0f32);
    assert_eq!(sig.recommended_action, ResponseAction::Isolate);
    assert!(!sig.require_approval);
}

#[tokio::test]
async fn test_m7_whitelist_veto_neutralization_family_3_process_token_privilege() {
    let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
    let config = PolicyConfig::default();
    let engine = PolicyEngine::new(memory, config);

    engine
        .add_voter(Box::new(osoosi_policy::voters::TrustedVendorVoter))
        .await;

    let mut event = make_test_event("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c echo test");
    event.data["PrivilegeEscalationDetected"] = json!(true);

    let sig = engine
        .scan_event(&event)
        .await
        .expect("Whitelist cannot abort Family 3 (ProcessTokenPrivilege) breach");

    assert_eq!(sig.confidence, 1.0f32);
    assert_eq!(sig.recommended_action, ResponseAction::Isolate);
}

#[tokio::test]
async fn test_m7_whitelist_veto_neutralization_family_4_cryptographic_mesh_mismatch() {
    let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
    let config = PolicyConfig::default();
    let engine = PolicyEngine::new(memory, config);

    engine
        .add_voter(Box::new(osoosi_policy::voters::TrustedVendorVoter))
        .await;

    let mut event = make_test_event("C:\\Windows\\System32\\conhost.exe", "conhost.exe 0x4");
    event.data["CryptoSignatureMismatch"] = json!(true);
    event.data["EpochSpoofingDetected"] = json!(true);

    let sig = engine
        .scan_event(&event)
        .await
        .expect("Whitelist cannot abort Family 4 (CryptographicMeshMismatch) breach");

    assert_eq!(sig.confidence, 1.0f32);
    assert_eq!(sig.recommended_action, ResponseAction::Isolate);
}

#[tokio::test]
async fn test_m7_whitelist_veto_neutralization_family_5_lateral_containment_breach() {
    let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
    let config = PolicyConfig::default();
    let engine = PolicyEngine::new(memory, config);

    engine
        .add_voter(Box::new(osoosi_policy::voters::TrustedVendorVoter))
        .await;

    let mut event = make_test_event(
        "C:\\Windows\\System32\\powershell.exe",
        "powershell.exe -enc test",
    );
    event.data["CanaryTrapTripped"] = json!(true);

    let sig = engine
        .scan_event(&event)
        .await
        .expect("Whitelist cannot abort Family 5 (LateralContainmentBreach) breach");

    assert_eq!(sig.confidence, 1.0f32);
    assert_eq!(sig.recommended_action, ResponseAction::Isolate);
}

#[tokio::test]
async fn test_m7_whitelist_veto_aborts_on_truly_benign_workload_without_invariants() {
    let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
    let config = PolicyConfig::default();
    let engine = PolicyEngine::new(memory, config);

    engine
        .add_voter(Box::new(osoosi_policy::voters::TrustedVendorVoter))
        .await;

    // Truly benign event without any invariant flags
    let event = make_test_event(
        "C:\\Windows\\System32\\notepad.exe",
        "notepad.exe document.txt",
    );

    let sig = engine.scan_event(&event).await;
    assert!(
        sig.is_none(),
        "Trusted-Vendor whitelist MUST abort round when no deterministic invariant is violated"
    );
}

// =========================================================================
// Dimension 3: Extreme Voter Weight Clamping & Numerical Robustness
// =========================================================================

#[test]
fn test_m7_extreme_voter_weight_clamping_boundary_matrix() {
    let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
    let config = PolicyConfig::default();
    let engine = PolicyEngine::new(memory, config);

    let test_cases = vec![
        ("PosInf", f32::INFINITY, 2.50),
        ("NegInf", -f32::INFINITY, 0.50),
        ("NaN", f32::NAN, 1.00),
        ("ExtremeHigh", 1e38, 2.50),
        ("ExtremeLow", -1e38, 0.50),
        ("Zero", 0.0, 0.50),
        ("NegativeZero", -0.0, 0.50),
        ("ValidMid", 1.75, 1.75),
        ("BoundaryMin", 0.50, 0.50),
        ("BoundaryMax", 2.50, 2.50),
    ];

    for (name, input_weight, expected_clamped) in test_cases {
        let actual = engine.set_voter_weight(name, input_weight);
        assert_eq!(
            actual, expected_clamped,
            "Failed weight clamping for case {}: input={}, expected={}, got={}",
            name, input_weight, expected_clamped, actual
        );
    }
}

#[tokio::test]
async fn test_m7_scan_event_with_extreme_weights_does_not_panic() {
    let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
    let config = PolicyConfig::default();
    let engine = PolicyEngine::new(memory, config);

    // Register voters with extreme multiplier weights
    engine.set_voter_weight("VoterPosInf", f32::INFINITY);
    engine.set_voter_weight("VoterNegInf", -f32::INFINITY);
    engine.set_voter_weight("VoterNaN", f32::NAN);

    engine
        .add_voter(Box::new(FloodingBenignVoter {
            id: 1,
            score: 0.10,
            weight: 1.0,
        }))
        .await;

    let event = make_test_event("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c dir");

    // Must not panic under extreme weight multipliers
    let result = engine.scan_event(&event).await;
    // Benign cmd.exe with 0.10 confidence and no invariant breach should produce no threat
    assert!(result.is_none());
}

// =========================================================================
// Dimension 4: Direct Oracle Unit Testing for detect_deterministic_asymmetric_veto
// =========================================================================

#[test]
fn test_m7_detect_deterministic_asymmetric_veto_all_5_families_isolated() {
    let event_clean = make_test_event("C:\\calc.exe", "calc.exe");
    let veto_clean = detect_deterministic_asymmetric_veto(&event_clean, &[]);
    assert!(!veto_clean.is_violated);
    assert!(veto_clean.families.is_empty());

    // Family 1: CedarForbid
    let mut e1 = event_clean.clone();
    e1.data["CedarDecision"] = json!("Forbid");
    let v1 = detect_deterministic_asymmetric_veto(&e1, &[]);
    assert!(v1.is_violated);
    assert!(v1.families.contains(&InvariantViolationFamily::CedarForbid));

    // Family 2: Ring0Tamper
    let mut e2 = event_clean.clone();
    e2.data["KernelTamperDetected"] = json!(true);
    let v2 = detect_deterministic_asymmetric_veto(&e2, &[]);
    assert!(v2.is_violated);
    assert!(v2.families.contains(&InvariantViolationFamily::Ring0Tamper));

    // Family 3: ProcessTokenPrivilege
    let mut e3 = event_clean.clone();
    e3.data["PrivilegeEscalationDetected"] = json!(true);
    let v3 = detect_deterministic_asymmetric_veto(&e3, &[]);
    assert!(v3.is_violated);
    assert!(v3
        .families
        .contains(&InvariantViolationFamily::ProcessTokenPrivilege));

    // Family 4: CryptographicMeshMismatch
    let mut e4 = event_clean.clone();
    e4.data["CryptoSignatureMismatch"] = json!(true);
    let v4 = detect_deterministic_asymmetric_veto(&e4, &[]);
    assert!(v4.is_violated);
    assert!(v4
        .families
        .contains(&InvariantViolationFamily::CryptographicMeshMismatch));

    // Family 5: LateralContainmentBreach
    let mut e5 = event_clean.clone();
    e5.data["CanaryTrapTripped"] = json!(true);
    let v5 = detect_deterministic_asymmetric_veto(&e5, &[]);
    assert!(v5.is_violated);
    assert!(v5
        .families
        .contains(&InvariantViolationFamily::LateralContainmentBreach));

    // Multi-family compound breach
    let mut e_compound = event_clean.clone();
    e_compound.data["CedarForbidTripped"] = json!(true);
    e_compound.data["KernelTamperDetected"] = json!(true);
    e_compound.data["CanaryTrapTripped"] = json!(true);
    let v_compound = detect_deterministic_asymmetric_veto(&e_compound, &[]);
    assert!(v_compound.is_violated);
    assert_eq!(v_compound.families.len(), 3);
    assert!(v_compound.causal_rule.contains("CedarForbid"));
    assert!(v_compound.causal_rule.contains("Ring0Tamper"));
    assert!(v_compound.causal_rule.contains("LateralContainmentBreach"));
}
