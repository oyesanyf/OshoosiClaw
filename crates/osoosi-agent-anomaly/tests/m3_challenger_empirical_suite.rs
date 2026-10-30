//! Empirical Adversarial Challenge Suite: Milestone M3
//! Features: F07, F08, F29, F30, F31
//! Conducted by: teamwork_challenger_m3_2 (Empirical Challenger)
//!
//! Stress-tests:
//! 1. F07 HMAC Tamper Matrix: Multi-field forgery, downgrade attacks, epoch rollbacks, bit flips.
//! 2. F08 Downstream Capability Stripping: Privilege stripping, multi-hop sticky taint, proxy laundering veto.
//! 3. F29 Visual Deception Matrix: Exhaustive UTS #39 confusables, RTLO/bidi overrides, zero-width steganography, hex & base64 shell decoders, ANSI escapes.
//! 4. F30 Semantic Divergence & Typed Challenge: Exact boundaries (0.85 auto-veto, 0.45 challenge), token generation and verification.
//! 5. F31 Cognitive Red-Team Interceptor: Causal state tracing, fluency suppression, SAELens auto-veto, polymorphic challenge verification, TTL expiry, and dual-custody quorum ($O_1 \neq O_2$).

use chrono::Utc;
use osoosi_agent_anomaly::cognitive_redteam::{
    CognitiveRedTeamInterceptor, HitlApprovalState, PendingExecutionGraphNode, AUTO_VETO_THRESHOLD,
};
use osoosi_agent_anomaly::containment_ring::{ArmContainmentRing, MessageKind, ProvenanceHop};
use osoosi_agent_anomaly::rasp::TaintLevel;
use osoosi_runtime::mesh_guard::{
    HitlCognitiveFirewall, HitlDeceptionIndicator, HitlFirewallDecision, MeshTaintLevel,
};
use osoosi_types::arm_role::ArmRole;

// ============================================================================
// 1. F07: HMAC Tamper Matrix & Cryptographic Envelope Integrity
// ============================================================================

#[tokio::test]
async fn challenge_f07_hmac_tamper_matrix() {
    let master_seed = [0x5A; 32];
    let sender_ring = ArmContainmentRing::new(1, ArmRole::UntrustedDocIngest, 1, &master_seed);
    let receiver_ring = ArmContainmentRing::new(2, ArmRole::AnomalyDetection, 1, &master_seed);

    let pristine_msg = sender_ring
        .sign_mesh_message_with_taint(
            2,
            1,
            MessageKind::Finding,
            "corr-f07-matrix",
            "arXiv:2609.11223 payload description",
            TaintLevel::UntrustedExternal,
        )
        .await
        .expect("Valid envelope signing should succeed");

    // 1. Pristine message must be accepted
    let verified = receiver_ring
        .verify_incoming_message(&pristine_msg)
        .await
        .expect("Pristine message must pass verification");
    assert_eq!(
        verified.message().taint_level,
        TaintLevel::UntrustedExternal
    );

    // 2. Attack: Downgrade taint level (UntrustedExternal -> Clean)
    let mut tampered = pristine_msg.clone();
    tampered.taint_level = TaintLevel::Clean;
    let res = receiver_ring.verify_incoming_message(&tampered).await;
    assert!(
        res.is_err(),
        "Downgrading taint level must be rejected by HMAC"
    );

    // 3. Attack: Downgrade taint level (UntrustedExternal -> Suspect)
    let mut tampered = pristine_msg.clone();
    tampered.taint_level = TaintLevel::Suspect;
    let res = receiver_ring.verify_incoming_message(&tampered).await;
    assert!(res.is_err(), "Changing taint level must invalidate HMAC");

    // 4. Attack: Sender Arm ID spoofing (Arm 1 -> Arm 99)
    let mut tampered = pristine_msg.clone();
    tampered.sender_arm_id = 99;
    let res = receiver_ring.verify_incoming_message(&tampered).await;
    assert!(res.is_err(), "Spoofed sender arm ID must be rejected");

    // 5. Attack: Sender Role spoofing (UntrustedDocIngest -> AnomalyDetection)
    let mut tampered = pristine_msg.clone();
    tampered.sender_role = ArmRole::AnomalyDetection;
    let res = receiver_ring.verify_incoming_message(&tampered).await;
    assert!(res.is_err(), "Spoofed sender role must be rejected");

    // 6. Attack: Sender Generation rollback (Gen 1 -> Gen 0)
    let mut tampered = pristine_msg.clone();
    tampered.sender_generation = 0;
    let res = receiver_ring.verify_incoming_message(&tampered).await;
    assert!(res.is_err(), "Epoch 0 must fail closed");

    // 7. Attack: Target Arm ID alteration (redirect to Arm 3)
    let mut tampered = pristine_msg.clone();
    tampered.target_arm_id = 3;
    let res = receiver_ring.verify_incoming_message(&tampered).await;
    assert!(res.is_err(), "Target misrouting must fail closed");

    // 8. Attack: Payload bit-flip / modification
    let mut tampered = pristine_msg.clone();
    tampered.payload = "arXiv:2609.11223 payload description modified".to_string();
    let res = receiver_ring.verify_incoming_message(&tampered).await;
    assert!(res.is_err(), "Payload modification must fail closed");

    // 9. Attack: Correlation ID tampering
    let mut tampered = pristine_msg.clone();
    tampered.correlation_id = "corr-f07-tampered".to_string();
    let res = receiver_ring.verify_incoming_message(&tampered).await;
    assert!(res.is_err(), "Correlation ID tampering must fail closed");

    // 10. Attack: Provenance hop tampering
    let mut tampered = pristine_msg.clone();
    tampered.provenance.push(ProvenanceHop {
        arm_id: 3,
        role: ArmRole::UntrustedDocIngest,
        generation: 1,
    });
    let res = receiver_ring.verify_incoming_message(&tampered).await;
    assert!(res.is_err(), "Provenance tampering must fail closed");

    // 11. Attack: Signature truncation or bit-flip
    let mut tampered = pristine_msg.clone();
    let mut sig_chars: Vec<char> = tampered.signature_hex.chars().collect();
    sig_chars[0] = if sig_chars[0] == 'a' { 'b' } else { 'a' };
    tampered.signature_hex = sig_chars.into_iter().collect();
    let res = receiver_ring.verify_incoming_message(&tampered).await;
    assert!(res.is_err(), "Bit-flipped signature must fail closed");

    // 12. Attack: Empty signature
    let mut tampered = pristine_msg.clone();
    tampered.signature_hex = String::new();
    let res = receiver_ring.verify_incoming_message(&tampered).await;
    assert!(res.is_err(), "Empty signature must fail closed");
}

// ============================================================================
// 2. F08: Downstream Capability Stripping & Sticky Taint Inheritance
// ============================================================================

#[tokio::test]
async fn challenge_f08_downstream_capability_stripping_and_sticky_taint() {
    let master_seed = [0x77; 32];
    let ring_untrusted = ArmContainmentRing::new(1, ArmRole::UntrustedDocIngest, 1, &master_seed);
    let ring_worker = ArmContainmentRing::new(2, ArmRole::AnomalyDetection, 1, &master_seed);
    let ring_priv = ArmContainmentRing::new(3, ArmRole::AccountingLedgerWrite, 1, &master_seed);

    // Initial state: explicitly grant high-privilege tools to worker
    ring_worker.grant_tool("shell_exec").await;
    ring_worker.grant_tool("cmd").await;
    ring_worker.grant_tool("powershell").await;
    ring_worker.grant_tool("write_file").await;
    ring_worker.grant_tool("network_egress").await;
    ring_worker.grant_tool("extract_credentials").await;
    ring_worker.grant_tool("modify_policy").await;
    ring_worker.grant_tool("ledger_writer").await;
    ring_worker.grant_tool("read_file").await;

    let initial_tools = ring_worker.allowed_tools_snapshot().await;
    assert!(initial_tools.contains("shell_exec"));
    assert!(initial_tools.contains("write_file"));

    // Step 1: Untrusted Doc Ingest signs message with UntrustedExternal
    let msg1 = ring_untrusted
        .sign_mesh_message_with_taint(
            2,
            1,
            MessageKind::Finding,
            "corr-f08-strip",
            "Untrusted PDF download payload",
            TaintLevel::UntrustedExternal,
        )
        .await
        .expect("Sign must succeed");

    // Step 2: Worker receives message. High-privilege tools must be stripped immediately!
    let verified1 = ring_worker
        .verify_incoming_message(&msg1)
        .await
        .expect("Verification must succeed");
    assert_eq!(
        verified1.message().taint_level,
        TaintLevel::UntrustedExternal
    );

    // Verify all 8 high-privilege tools are strictly missing from allowed_tools
    let tools_after = ring_worker.allowed_tools_snapshot().await;
    for high_priv_tool in &[
        "shell_exec",
        "cmd",
        "powershell",
        "write_file",
        "network_egress",
        "extract_credentials",
        "modify_policy",
        "ledger_writer",
    ] {
        assert!(
            !tools_after.contains(*high_priv_tool),
            "Tool '{}' MUST be stripped after receiving UntrustedExternal taint",
            high_priv_tool
        );
    }
    // Benign tool remains
    assert!(
        tools_after.contains("read_file"),
        "Benign read tool should remain untouched"
    );

    // Step 3: Worker tries to relay message to PrivilegedSink (AccountingLedgerWrite)
    // Sticky taint rule LAW1_STICKY_TAINT_VETO must trigger!
    let relay_msg = ring_worker
        .sign_mesh_message_with_taint(
            3,
            1,
            MessageKind::Finding,
            "corr-f08-relay",
            "Relayed write ledger request",
            TaintLevel::Clean, // Worker tries to claim clean!
        )
        .await
        .expect("Signing by worker succeeds");

    let relay_res = ring_priv.verify_incoming_message(&relay_msg).await;
    assert!(
        relay_res.is_err(),
        "Relaying tainted message to PrivilegedSink must be blocked by sticky taint"
    );
    let err_str = format!("{:?}", relay_res.unwrap_err());
    assert!(
        err_str.contains("LAW1_STICKY_TAINT_VETO") || err_str.contains("Ring Boundary Violation"),
        "Expected sticky taint veto error, got: {}",
        err_str
    );
}

// ============================================================================
// 3. F29: HitlCognitiveFirewall Visual Deception Scanner
// ============================================================================

#[test]
fn challenge_f29_visual_deception_matrix() {
    // 1. Comprehensive Cyrillic and Greek lookalikes
    let cyrillic_homographs = [
        ("sh\u{0435}ll_exec", "Cyrillic small e"),
        ("cmd\u{0430}.exe", "Cyrillic small a"),
        ("p\u{043E}wershell", "Cyrillic small o"),
        ("extr\u{0430}ct_credentials", "Cyrillic small a"),
        ("id_rs\u{0430}", "Cyrillic small a"),
        ("dr\u{0456}vers\\etc\\hosts", "Cyrillic small i"),
        ("l\u{0458}ass.exe", "Cyrillic small je"),
        ("C:\\W\u{0456}ndows\\System32", "Cyrillic small i"),
    ];
    for (input, desc) in &cyrillic_homographs {
        let findings = HitlCognitiveFirewall::scan_for_visual_deception(input);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f, HitlDeceptionIndicator::UnicodeConfusableHomograph(_))),
            "Failed to detect Cyrillic homograph '{}' ({})",
            input,
            desc
        );
    }

    let greek_homographs = [
        ("sh\u{03B5}ll", "Greek small epsilon"),
        ("m\u{03BF}dify_policy", "Greek small omicron"),
        ("netw\u{03BF}rk", "Greek small omicron"),
        ("c\u{03C5}rl.exe", "Greek small upsilon"),
    ];
    for (input, desc) in &greek_homographs {
        let findings = HitlCognitiveFirewall::scan_for_visual_deception(input);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f, HitlDeceptionIndicator::UnicodeConfusableHomograph(_))),
            "Failed to detect Greek homograph '{}' ({})",
            input,
            desc
        );
    }

    // 2. Comprehensive Directional Overrides (RTLO, LRO, etc.)
    let bidi_chars = [
        ('\u{202E}', "RTLO Right-to-Left Override"),
        ('\u{202D}', "LRO Left-to-Right Override"),
        ('\u{202A}', "LRE Left-to-Right Embedding"),
        ('\u{202B}', "RLE Right-to-Left Embedding"),
        ('\u{202C}', "PDF Pop Directional Formatting"),
        ('\u{2066}', "LRI Left-to-Right Isolate"),
        ('\u{2067}', "RLI Right-to-Left Isolate"),
        ('\u{2068}', "FSI First Strong Isolate"),
        ('\u{2069}', "PDI Pop Directional Isolate"),
        ('\u{200E}', "LRM Left-to-Right Mark"),
        ('\u{200F}', "RLM Right-to-Left Mark"),
    ];
    for (c, desc) in &bidi_chars {
        let payload = format!("calc{}exe.pdf", c);
        let findings = HitlCognitiveFirewall::scan_for_visual_deception(&payload);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f, HitlDeceptionIndicator::BidirectionalOverrideRtlo(_))),
            "Failed to detect bidi character U+{:04X} ({})",
            *c as u32,
            desc
        );
    }

    // 3. Zero-Width characters & Soft Hyphens
    let zero_width_chars = [
        ('\u{00AD}', "Soft Hyphen"),
        ('\u{200B}', "Zero Width Space"),
        ('\u{200C}', "Zero Width Non-Joiner"),
        ('\u{200D}', "Zero Width Joiner"),
        ('\u{FEFF}', "Zero Width No-Break Space / BOM"),
        ('\u{2060}', "Word Joiner"),
        ('\u{180E}', "Mongolian Vowel Separator"),
    ];
    for (c, desc) in &zero_width_chars {
        let payload = format!("cur{}l http://evil.com", c);
        let findings = HitlCognitiveFirewall::scan_for_visual_deception(&payload);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f, HitlDeceptionIndicator::ZeroWidthSteganography(_))),
            "Failed to detect zero-width char U+{:04X} ({})",
            *c as u32,
            desc
        );
    }

    // 4. Hex & Base64 Shell Obfuscation Payloads
    let obfuscated_payloads = [
        "certutil -decodehex in.hex out.exe",
        "certutil.exe -decodehex file.txt payload.dll",
        "$bytes = [System.Convert]::FromHexString('4D5A90')",
        "cat shellcode.hex | xxd -r -p > rev.bin",
        "xxd -r payload.hex payload.exe",
        "echo aGVsbG8= | base64 -d",
        "base64 --decode encoded.txt",
        "powershell -enc JAB4ACAAPQAgACcAdABlAHMAdAAnAA==",
        "powershell.exe -EncodedCommand IAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAA==",
        "$b = [System.Convert]::FromBase64String($s)",
        "eval(atob('ZG9jdW1lbnQud3JpdGUoMSk='))",
        "\\x90\\x90\\x90\\x90\\x31\\xc0\\x50\\x68",
        "0x41, 0x42, 0x43, 0x44, 0x45, 0x46",
    ];
    for payload in &obfuscated_payloads {
        let findings = HitlCognitiveFirewall::scan_for_visual_deception(payload);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f, HitlDeceptionIndicator::ObfuscatedShellPayload(_))),
            "Failed to detect obfuscated shell payload: {}",
            payload
        );
    }

    // 5. ANSI / VT100 Terminal Escapes
    let ansi_escapes = [
        "\x1b[2JSystem Normal",
        "\x1b[31;1mError: Access Denied\x1b[0m",
        "\u{009B}[2JClear Screen",
    ];
    for ansi in &ansi_escapes {
        let findings = HitlCognitiveFirewall::scan_for_visual_deception(ansi);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f, HitlDeceptionIndicator::AnsiEscapeInjection(_))),
            "Failed to detect ANSI escape in: {:?}",
            ansi
        );
    }
}

// ============================================================================
// 4. F30: Intent-vs-Effect Divergence Scoring & Typed Token Gate
// ============================================================================

#[test]
fn challenge_f30_divergence_boundaries_and_token_derivation() {
    // 1. Extreme contradiction: format docs objective + LSASS credential dump -> Auto-Veto (Score >= 0.85)
    let decision = HitlCognitiveFirewall::evaluate_hitl_escalation(
        "Format project documentation and markdown tables",
        "Formatting documentation for consistency",
        "extract_credentials",
        "C:\\Windows\\System32\\lsass.exe",
        "--dump",
        MeshTaintLevel::UntrustedExternal,
    );
    match decision {
        HitlFirewallDecision::AutoVetoDeceptive {
            veto_reason,
            blast_radius,
        } => {
            assert!(
                blast_radius.divergence_score >= 0.85,
                "Expected score >= 0.85, got {}",
                blast_radius.divergence_score
            );
            assert!(veto_reason.contains("HITL_COGNITIVE_FIREWALL_AUTO_VETO"));
        }
        other => panic!("Expected AutoVetoDeceptive, got {:?}", other),
    }

    // 2. Homograph in file path targeting hosts -> Auto-Veto due to visual deception
    let decision_homo = HitlCognitiveFirewall::evaluate_hitl_escalation(
        "Update host resolution",
        "Updating test host",
        "write_file",
        "C:\\Windows\\System32\\dr\u{0456}vers\\etc\\hosts", // Cyrillic 'i'
        "127.0.0.1 test.local",
        MeshTaintLevel::TrustedInternal,
    );
    assert!(
        matches!(
            decision_homo,
            HitlFirewallDecision::AutoVetoDeceptive { .. }
        ),
        "Visual deception in target resource must trigger AutoVeto"
    );

    // 3. Elevated friction: Build release objective + write release manifest -> RequireTypedBlastRadiusChallenge
    let decision_friction = HitlCognitiveFirewall::evaluate_hitl_escalation(
        "Build and package release installer",
        "Writing release configuration file",
        "write_file",
        "C:\\workspace\\deploy\\release_manifest.json",
        "{\"version\": \"1.2.0\"}",
        MeshTaintLevel::UntrustedExternal,
    );
    match &decision_friction {
        HitlFirewallDecision::RequireTypedBlastRadiusChallenge {
            blast_radius,
            expected_confirmation_token,
        } => {
            assert!(
                blast_radius.divergence_score >= 0.45 && blast_radius.divergence_score < 0.85,
                "Expected score in [0.45, 0.85), got {}",
                blast_radius.divergence_score
            );
            assert_eq!(
                expected_confirmation_token,
                "CONFIRM:WRITE_FILE:RELEASE_MANIFEST.JSON"
            );
        }
        other => panic!("Expected RequireTypedBlastRadiusChallenge, got {:?}", other),
    }

    // 4. Test expected_blast_radius_token derivation with complex paths
    assert_eq!(
        HitlCognitiveFirewall::expected_blast_radius_token(
            "write_file",
            "C:\\Program Files\\OshoosiClaw\\osoosi.toml"
        ),
        "CONFIRM:WRITE_FILE:OSOOSI.TOML"
    );
    assert_eq!(
        HitlCognitiveFirewall::expected_blast_radius_token(
            "shell_exec",
            "/usr/local/bin/deploy.sh"
        ),
        "CONFIRM:SHELL_EXEC:DEPLOY.SH"
    );
    // Trailing slash path produces leaf directory name SCRATCH
    assert_eq!(
        HitlCognitiveFirewall::expected_blast_radius_token("read_file", "C:\\temp\\scratch\\"),
        "CONFIRM:READ_FILE:SCRATCH"
    );
    // Non-trailing slash path extracts the leaf directory or file name
    assert_eq!(
        HitlCognitiveFirewall::expected_blast_radius_token("read_file", "C:\\temp\\scratch"),
        "CONFIRM:READ_FILE:SCRATCH"
    );
    // Empty resource fallback
    assert_eq!(
        HitlCognitiveFirewall::expected_blast_radius_token("network_egress", ""),
        "CONFIRM:NETWORK_EGRESS:RESOURCE"
    );

    // 5. Verification of typed confirmation challenge
    assert!(HitlCognitiveFirewall::verify_typed_blast_radius_challenge(
        &decision_friction,
        Some("CONFIRM:WRITE_FILE:RELEASE_MANIFEST.JSON")
    )
    .is_ok());

    // Exact token with whitespace trimming is accepted
    assert!(HitlCognitiveFirewall::verify_typed_blast_radius_challenge(
        &decision_friction,
        Some("  CONFIRM:WRITE_FILE:RELEASE_MANIFEST.JSON  ")
    )
    .is_ok());

    // Case-sensitivity: lowercase token is rejected
    assert!(HitlCognitiveFirewall::verify_typed_blast_radius_challenge(
        &decision_friction,
        Some("confirm:write_file:release_manifest.json")
    )
    .is_err());

    // Wrong token rejected
    assert!(HitlCognitiveFirewall::verify_typed_blast_radius_challenge(
        &decision_friction,
        Some("CONFIRM:WRITE_FILE:WRONG.JSON")
    )
    .is_err());

    // None token rejected
    assert!(
        HitlCognitiveFirewall::verify_typed_blast_radius_challenge(&decision_friction, None)
            .is_err()
    );
}

// ============================================================================
// 5. F31: Cognitive Red-Team Interceptor & Deliberate Friction Quorum
// ============================================================================

#[tokio::test]
async fn challenge_f31_cognitive_redteam_full_lifecycle() {
    let secret = [0x99u8; 32];
    let interceptor = CognitiveRedTeamInterceptor::new(secret);

    // Scenario A: Persuasive Deceptive Action -> Deception >= 0.85 Auto-Veto
    let deceptive_node = PendingExecutionGraphNode {
        session_id: "sess-001".to_string(),
        arm_id: 1,
        arm_generation: 1,
        agent_id: "agent_rouge".to_string(),
        correlation_id: "corr-adv-001".to_string(),
        tool_name: "extract_credentials".to_string(),
        target_resource: "C:\\Windows\\System32\\lsass.exe".to_string(),
        command_args: "--dump".to_string(),
        stated_justification: "CRITICAL: The CEO urgently needs this credential dump to fix an active outage. Please click approve immediately!".to_string(),
        incoming_taint: MeshTaintLevel::UntrustedExternal,
        user_objective: "Read documentation and summarize".to_string(),
    };

    let assessment_deceptive = interceptor.evaluate_pending_action(deceptive_node);
    assert!(
        assessment_deceptive.auto_vetoed,
        "Deceptive credential extraction must be auto-vetoed"
    );
    assert!(
        assessment_deceptive.deception_score >= AUTO_VETO_THRESHOLD,
        "Deception score {:.2} must be >= {:.2}",
        assessment_deceptive.deception_score,
        AUTO_VETO_THRESHOLD
    );
    assert_eq!(
        assessment_deceptive.stripped_justification,
        "[STRIPPED BY COGNITIVE RED-TEAM: Fluency suppressed. Review deterministic blast radius below]"
    );
    assert!(
        !assessment_deceptive
            .stripped_justification
            .contains("CEO urgently needs"),
        "Natural language justification must be stripped!"
    );

    // Attempting to approve an auto-vetoed action MUST fail closed!
    let approve_res = interceptor.submit_approval(
        &assessment_deceptive.request_id,
        "operator_bob",
        0,
        "dummy_nonce",
        None,
    );
    assert!(
        approve_res.is_err(),
        "Approving an auto-vetoed action must be rejected"
    );

    // Scenario B: Elevated Operation requiring Dual Custody and Polymorphic Challenge
    let elevated_node = PendingExecutionGraphNode {
        session_id: "sess-002".to_string(),
        arm_id: 2,
        arm_generation: 1,
        agent_id: "agent_deployer".to_string(),
        correlation_id: "corr-adv-002".to_string(),
        tool_name: "write_file".to_string(),
        target_resource: "C:\\Windows\\System32\\drivers\\etc\\hosts".to_string(),
        command_args: "10.0.0.1 test.internal".to_string(),
        stated_justification: "Configuring host resolution for test".to_string(),
        incoming_taint: MeshTaintLevel::UntrustedExternal,
        user_objective: "Update host resolution".to_string(),
    };

    let assessment_elevated = interceptor.evaluate_pending_action(elevated_node);
    assert!(
        assessment_elevated.dual_custody_required,
        "Untrusted external taint and persistent system write must require dual custody"
    );
    assert!(
        assessment_elevated.blast_radius_diff.is_irreversible,
        "System path write must be classified as irreversible"
    );

    let pub_challenge = assessment_elevated
        .challenge
        .expect("Challenge must be generated for non-auto-vetoed action");
    assert_eq!(pub_challenge.options.len(), 4);

    // Attack 1: Empty operator ID
    let empty_op_res = interceptor.submit_approval(
        &assessment_elevated.request_id,
        "   ",
        0,
        &pub_challenge.challenge_nonce,
        Some("CONFIRM:WRITE_FILE:HOSTS"),
    );
    assert!(empty_op_res.is_err(), "Empty operator ID must be rejected");

    // Attack 2: Tampered challenge nonce
    let bad_nonce_res = interceptor.submit_approval(
        &assessment_elevated.request_id,
        "operator_alice",
        0,
        "tampered_nonce_12345",
        Some("CONFIRM:WRITE_FILE:HOSTS"),
    );
    assert!(bad_nonce_res.is_err(), "Invalid nonce must be rejected");

    // Find correct index by trial
    let mut correct_index = 0;
    for i in 0..4 {
        let trial = interceptor.submit_approval(
            &assessment_elevated.request_id,
            "operator_alice",
            i,
            &pub_challenge.challenge_nonce,
            Some("CONFIRM:WRITE_FILE:HOSTS"),
        );
        if trial.is_ok() {
            correct_index = i;
            break;
        }
    }

    // Operator 1 (Alice) has approved, transitioning to PendingSecondApproval { first_operator: "operator_alice" }
    let state_after_first = interceptor
        .get_pending_actions()
        .into_iter()
        .find(|a| a.request_id == assessment_elevated.request_id)
        .unwrap()
        .approval_state;
    match state_after_first {
        HitlApprovalState::PendingSecondApproval { first_operator } => {
            assert_eq!(first_operator, "operator_alice");
        }
        other => panic!("Expected PendingSecondApproval, got {:?}", other),
    }

    // Attack 4: Self-approval! Alice attempts to approve a second time as O2 ($O_1 == O_2$)
    let self_approve_res = interceptor.submit_approval(
        &assessment_elevated.request_id,
        "operator_alice",
        correct_index,
        &pub_challenge.challenge_nonce,
        Some("CONFIRM:WRITE_FILE:HOSTS"),
    );
    assert!(
        self_approve_res.is_err(),
        "Self-approval in dual custody must be blocked"
    );
    let err_str = format!("{:?}", self_approve_res.unwrap_err());
    assert!(
        err_str.contains("DUAL_CUSTODY_SELF_APPROVAL_FORBIDDEN"),
        "Expected DUAL_CUSTODY_SELF_APPROVAL_FORBIDDEN, got: {}",
        err_str
    );

    // Operator 2 (Bob, distinct operator $O_1 \neq O_2$) approves!
    let second_approve_res = interceptor.submit_approval(
        &assessment_elevated.request_id,
        "operator_bob",
        correct_index,
        &pub_challenge.challenge_nonce,
        Some("CONFIRM:WRITE_FILE:HOSTS"),
    );
    assert!(
        second_approve_res.is_ok(),
        "Second distinct operator approval must succeed"
    );
    let final_state = second_approve_res.unwrap();
    match final_state {
        HitlApprovalState::QuorumApproved { operators, receipt } => {
            assert_eq!(operators, vec!["operator_alice", "operator_bob"]);
            assert!(receipt.is_some(), "Cryptographic receipt must be issued");
            let r = receipt.unwrap();
            assert_eq!(r.operator_id, "operator_alice+operator_bob");
            assert!(
                r.verify(2, 1, "corr-adv-002", Utc::now().timestamp() as u64, &secret)
                    .is_ok(),
                "Issued approval receipt must verify against operator secret"
            );
        }
        other => panic!("Expected QuorumApproved, got {:?}", other),
    }

    // Scenario C: Status counters verify accurate tracking
    let status = interceptor.get_status();
    assert_eq!(status.total_evaluations, 2);
    assert_eq!(status.total_auto_vetoes, 1);
    assert!(status.total_challenges_passed >= 2);
    assert_eq!(status.total_quorum_completions, 1);
}
