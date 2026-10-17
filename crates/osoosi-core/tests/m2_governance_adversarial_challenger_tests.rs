// Empirical Adversarial Challenger Test Suite
// Milestone M2 Iteration 2: Human Escalation Hard Gate & Corroboration Stress Harness

use osoosi_core::EdrOrchestrator;
use osoosi_types::trust::MerkleProof;
use osoosi_types::{ActionState, ResponseAction, ThreatSignature};

#[test]
fn test_adversarial_human_escalation_hard_gate_stress() {
    // Stress-test human escalation hard gate against all potential overrides:
    // 100% confidence, maximum severity, MITRE catalog attacks, destructive mutations,
    // active lockdown mode parameters, and diverse initial action proposals.

    let test_actions = [
        ResponseAction::Isolate,
        ResponseAction::Tarpit,
        ResponseAction::GhostTarpit,
        ResponseAction::Deception,
        ResponseAction::MemoryScan,
        ResponseAction::RegistryRepair,
        ResponseAction::Alert,
    ];

    let mitre_attacks = [
        ("T1059.001", "PowerShell Execution"),
        ("T1055", "Process Injection"),
        ("T1003.001", "LSASS Memory Dump"),
        ("T1490", "Inhibit System Recovery / VSS Admin"),
        ("T1006", "Direct Volume Access"),
        ("T1136", "Create Account"),
        ("T1543.003", "Windows Service Persistence"),
    ];

    for initial_action in &test_actions {
        for (tech_id, tech_name) in &mitre_attacks {
            let mut sig = ThreatSignature::new("did:osoosi:adversarial_node".to_string());
            sig.confidence = 1.0; // Maximum 100% confidence
            sig.detector_count = 10; // High multi-detector corroboration
            sig.mitre_technique = Some(tech_id.to_string());
            sig.mitre_technique_name = Some(tech_name.to_string());
            sig.recommended_action = *initial_action;
            sig.action_state = ActionState::Executed; // Try forcing Executed beforehand
            sig.require_approval = false;
            sig.signature = Some("cryptographic_ed25519_detached_signature".to_string());
            sig.merkle_proof = Some(MerkleProof {
                leaf_hash: "00000000000000000000000000000000".to_string(),
                root_hash: "ffffffffffffffffffffffffffffffff".to_string(),
                siblings: vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()],
                index: 42,
            });

            let mut effective_action = *initial_action;

            // Apply the production human escalation gate with human_escalation_required = true
            EdrOrchestrator::apply_human_escalation_gate(
                &mut sig,
                &mut effective_action,
                true,
            );

            // Invariant assertions: ALL overrides must fail.
            assert_eq!(
                effective_action,
                ResponseAction::Alert,
                "Failed for initial {:?}, tech {}: effective_action must be Alert",
                initial_action, tech_id
            );
            assert_eq!(
                sig.recommended_action,
                ResponseAction::Alert,
                "Failed for initial {:?}, tech {}: recommended_action must be Alert",
                initial_action, tech_id
            );
            assert_eq!(
                sig.action_state,
                ActionState::Pending,
                "Failed for initial {:?}, tech {}: action_state must be Pending",
                initial_action, tech_id
            );
            assert!(
                sig.require_approval,
                "Failed for initial {:?}, tech {}: require_approval must be true",
                initial_action, tech_id
            );
        }
    }
}

#[test]
fn test_adversarial_human_escalation_negative_control() {
    // When human escalation is NOT required (false), the gate MUST be a no-op
    // and preserve the caller's action, state, and approval status.
    let mut sig = ThreatSignature::new("did:osoosi:nominal_node".to_string());
    sig.confidence = 0.95;
    sig.detector_count = 3;
    sig.recommended_action = ResponseAction::Isolate;
    sig.action_state = ActionState::Executed;
    sig.require_approval = false;

    let mut effective_action = ResponseAction::Isolate;

    EdrOrchestrator::apply_human_escalation_gate(
        &mut sig,
        &mut effective_action,
        false,
    );

    assert_eq!(effective_action, ResponseAction::Isolate);
    assert_eq!(sig.recommended_action, ResponseAction::Isolate);
    assert_eq!(sig.action_state, ActionState::Executed);
    assert!(!sig.require_approval);
}

#[test]
fn test_adversarial_corroboration_gate_single_detector_capped() {
    // Test that uncorroborated single-detector destructive actions (Isolate, Tarpit, GhostTarpit)
    // are strictly capped to require administrator approval.
    let destructive_actions = [
        ResponseAction::Isolate,
        ResponseAction::Tarpit,
        ResponseAction::GhostTarpit,
    ];

    let confidences = [0.10, 0.45, 0.70, 0.85, 0.89];

    for act in &destructive_actions {
        for conf in &confidences {
            let mut sig = ThreatSignature::new("did:osoosi:uncorroborated_node".to_string());
            sig.confidence = *conf;
            sig.detector_count = 1; // Lone detector!
            sig.cve_id = None;
            sig.signature = None;
            sig.merkle_proof = None;
            sig.require_approval = false;
            sig.recommended_action = *act;

            let is_destructive = false;
            let action_confidence_threshold = 0.60;

            EdrOrchestrator::apply_corroboration_gate(
                &mut sig,
                *act,
                is_destructive,
                action_confidence_threshold,
            );

            assert!(
                sig.require_approval,
                "Single-detector {:?} at confidence {:.2} must require administrator approval",
                act, conf
            );
        }
    }
}

#[test]
fn test_adversarial_corroboration_gate_zero_detector_boundary() {
    // Boundary condition: detector_count = 0 (anomaly or unclassified event)
    let mut sig = ThreatSignature::new("did:osoosi:zero_detector".to_string());
    sig.confidence = 0.75;
    sig.detector_count = 0;
    sig.cve_id = None;
    sig.signature = None;
    sig.merkle_proof = None;
    sig.require_approval = false;

    EdrOrchestrator::apply_corroboration_gate(
        &mut sig,
        ResponseAction::Isolate,
        false,
        0.50,
    );

    assert!(
        sig.require_approval,
        "detector_count=0 must be capped to require approval"
    );
}

#[test]
fn test_adversarial_corroboration_gate_multi_signal_bypasses() {
    // Test all valid corroboration bypass paths:
    // 1. Multi-detector (count >= 2)
    // 2. Merkle proof
    // 3. Cryptographic signature
    // 4. CVE ID

    // Path 1: Multi-detector count >= 2
    for count in 2..=8 {
        let mut sig = ThreatSignature::new("did:osoosi:corroborated_multi".to_string());
        sig.confidence = 0.85;
        sig.detector_count = count;
        sig.cve_id = None;
        sig.signature = None;
        sig.merkle_proof = None;
        sig.require_approval = false;

        EdrOrchestrator::apply_corroboration_gate(
            &mut sig,
            ResponseAction::Isolate,
            false,
            0.50,
        );

        assert!(
            !sig.require_approval,
            "Multi-detector (count={}) must bypass corroboration approval gate",
            count
        );
    }

    // Path 2: Merkle proof
    let mut sig_merkle = ThreatSignature::new("did:osoosi:merkle_proof_node".to_string());
    sig_merkle.confidence = 0.85;
    sig_merkle.detector_count = 1; // Single detector
    sig_merkle.merkle_proof = Some(MerkleProof {
        leaf_hash: "leaf_1234".to_string(),
        root_hash: "root_5678".to_string(),
        siblings: vec!["sib_90ab".to_string()],
        index: 1,
    });
    sig_merkle.require_approval = false;

    EdrOrchestrator::apply_corroboration_gate(
        &mut sig_merkle,
        ResponseAction::Isolate,
        false,
        0.50,
    );

    assert!(
        !sig_merkle.require_approval,
        "Valid Merkle proof must bypass corroboration approval gate"
    );

    // Path 3: Cryptographic signature
    let mut sig_signed = ThreatSignature::new("did:osoosi:signed_node".to_string());
    sig_signed.confidence = 0.85;
    sig_signed.detector_count = 1;
    sig_signed.signature = Some("valid_ed25519_signature".to_string());
    sig_signed.require_approval = false;

    EdrOrchestrator::apply_corroboration_gate(
        &mut sig_signed,
        ResponseAction::Isolate,
        false,
        0.50,
    );

    assert!(
        !sig_signed.require_approval,
        "Valid cryptographic signature must bypass corroboration approval gate"
    );

    // Path 4: CVE ID
    let mut sig_cve = ThreatSignature::new("did:osoosi:cve_node".to_string());
    sig_cve.confidence = 0.85;
    sig_cve.detector_count = 1;
    sig_cve.cve_id = Some("CVE-2024-38077".to_string());
    sig_cve.require_approval = false;

    EdrOrchestrator::apply_corroboration_gate(
        &mut sig_cve,
        ResponseAction::Isolate,
        false,
        0.50,
    );

    assert!(
        !sig_cve.require_approval,
        "Known CVE identifier must bypass corroboration approval gate"
    );
}

#[test]
fn test_adversarial_corroboration_gate_alert_action_untouched() {
    // If effective action is Alert, the corroboration gate should never force require_approval = true,
    // because alerts are non-destructive and do not interrupt operations.
    let mut sig = ThreatSignature::new("did:osoosi:alert_node".to_string());
    sig.confidence = 0.50;
    sig.detector_count = 1;
    sig.require_approval = false;

    EdrOrchestrator::apply_corroboration_gate(
        &mut sig,
        ResponseAction::Alert,
        false,
        0.50,
    );

    assert!(
        !sig.require_approval,
        "Non-destructive Alert action must not have require_approval flipped to true"
    );
}

#[test]
fn test_administrative_shield_exhaustive_matrix() {
    use osoosi_core::remediation::is_administrative_or_ssh_session;

    let admin_cases = [
        ("sshd", vec!["/usr/sbin/sshd", "-D"]),
        ("sshd", vec!["sshd: user@pts/1"]),
        ("sshd", vec!["sshd: user@notty [priv]"]),
        ("ansible-playbook", vec!["/usr/bin/ansible-playbook", "site.yml"]),
        ("python3", vec!["/usr/bin/python3", "/tmp/ansible_module.py"]),
        ("bash", vec!["bash", "-l", "pts/0"]),
        ("zsh", vec!["zsh", "-i", "pts/3"]),
        ("sshd: user", vec!["/usr/lib/openssh/sftp-server"]),
    ];

    for (proc_name, cmd_args) in &admin_cases {
        let args: Vec<String> = cmd_args.iter().map(|s| s.to_string()).collect();
        assert!(
            is_administrative_or_ssh_session(proc_name, &args),
            "Expected administrative session for {} with args {:?}",
            proc_name,
            args
        );
    }

    let non_admin_cases = [
        ("malware.exe", vec!["C:\\temp\\malware.exe", "--inject"]),
        ("nc", vec!["nc", "-lvnp", "4444"]),
        ("crypto_miner", vec!["./xmrig", "-o", "pool.minexmr.com"]),
        ("python", vec!["python", "evil_script.py"]),
    ];

    for (proc_name, cmd_args) in &non_admin_cases {
        let args: Vec<String> = cmd_args.iter().map(|s| s.to_string()).collect();
        assert!(
            !is_administrative_or_ssh_session(proc_name, &args),
            "Expected NON-administrative session for {} with args {:?}",
            proc_name,
            args
        );
    }
}
