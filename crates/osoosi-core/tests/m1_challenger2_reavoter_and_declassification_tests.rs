//! Empirical Adversarial Challenge Test Suite — Milestone M1 (Challenger 2)
//!
//! Empirically challenges:
//! 1. `ReaVoter` dynamic image loading (Sysmon Event 7):
//!    - Developer binaries (`cargo.exe`, `python.exe`, `node.exe`, `rustc.exe`) dynamically loading
//!      unsigned DLLs (`evil.dll`) and native extensions (`payload.pyd`).
//!    - Verifies escalation with positive weight (`weight > 1.0`) and suppression of benign veto.
//! 2. `ReaVoter` tainted session veto suppression:
//!    - Tainted sessions (`untrusted_taint`, `taint_level > 0`, `has_crown_jewel_taint`, `tainted`)
//!      attempting to claim benign process vetoes via `BENIGN_PROCS`.
//!    - Verifies benign vetoes are strictly suppressed.
//! 3. Trusted ZK-PII Declassification (`CausalSecurityGraph::declassify_node`):
//!    - Tampered ML-DSA-65 post-quantum signatures, tampered Fiat-Shamir commitments,
//!      missing `<ZK_PII:...>` tags, non-zero leakage bits, and low sigma_z confidence.
//!    - Verifies fail-closed rejection and proves SQLite taint is NEVER cleared upon rejection.

use anyhow::Result;
use osoosi_core::causal_graph::{AuthorityLevel, CausalSecurityGraph, FileClassification};
use osoosi_core::rea::{is_rea_benign_system_or_dev_process, ReaVoter};
use osoosi_dp::PresidioGlinerPiiZeroGuard;
use osoosi_policy::engine::ThreatVoter;
use osoosi_types::{HostEventSource, HostSecurityEvent};
use serde_json::json;

// -----------------------------------------------------------------------------
// 1. ReaVoter Sysmon Event 7 Dynamic Image Loading Empirical Challenges
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_adversarial_reavoter_sysmon_event_7_unsigned_dll_and_pyd_injection() {
    let rea_voter = ReaVoter::new();

    // Challenge 1a: Developer binary `cargo.exe` dynamically loads unsigned `evil.dll`
    // Sysmon Event 7 with Signed="false" and SignatureStatus="Unavailable"
    let event_cargo_unsigned_dll = HostSecurityEvent {
        source: HostEventSource::WindowsEventLog,
        event_id: 7,
        timestamp: chrono::Utc::now(),
        computer: "DEV-STATION-01".to_string(),
        data: json!({
            "Image": r"C:\Users\developer\.cargo\bin\cargo.exe",
            "ImageLoaded": r"C:\project\target\debug\deps\evil.dll",
            "Signed": "false",
            "SignatureStatus": "Unavailable"
        }),
        causal_parent: None,
    };

    let vote = rea_voter
        .vote(&event_cargo_unsigned_dll)
        .await
        .expect("ReaVoter must vote on unsigned DLL load in cargo.exe");

    assert!(
        vote.weight > 1.0,
        "Unsigned DLL load in cargo.exe must receive malicious escalation weight (> 1.0), got {}",
        vote.weight
    );
    assert_eq!(
        vote.weight, 1.85,
        "Weight must match escalation tier (1.85)"
    );
    assert!(
        vote.reason
            .contains("Untrusted or unsigned dynamic module load"),
        "Reason must state untrusted/unsigned dynamic load: {}",
        vote.reason
    );
    assert!(
        vote.reason.contains("evil.dll"),
        "Reason must name the loaded module: {}",
        vote.reason
    );

    // Challenge 1b: Developer binary `python.exe` dynamically loads unsigned `payload.pyd`
    // Using boolean `Signed: false`
    let event_python_unsigned_pyd = HostSecurityEvent {
        source: HostEventSource::WindowsEventLog,
        event_id: 7,
        timestamp: chrono::Utc::now(),
        computer: "DEV-STATION-01".to_string(),
        data: json!({
            "Image": r"C:\Python312\python.exe",
            "ImageLoaded": r"C:\workspace\modules\payload.pyd",
            "Signed": false,
            "SignatureStatus": "Unknown"
        }),
        causal_parent: None,
    };

    let vote_pyd = rea_voter
        .vote(&event_python_unsigned_pyd)
        .await
        .expect("ReaVoter must vote on unsigned PYD load in python.exe");

    assert!(
        vote_pyd.weight > 1.0,
        "Unsigned PYD load in python.exe must receive positive escalation weight, got {}",
        vote_pyd.weight
    );
    assert!(
        vote_pyd.reason.contains("payload.pyd"),
        "Reason must name payload.pyd: {}",
        vote_pyd.reason
    );

    // Challenge 1c: Developer binary `node.exe` dynamically loads native addon from untrusted temp path
    // Path: AppData\Local\Temp\addon.node
    let event_node_temp_dll = HostSecurityEvent {
        source: HostEventSource::WindowsEventLog,
        event_id: 7,
        timestamp: chrono::Utc::now(),
        computer: "DEV-STATION-01".to_string(),
        data: json!({
            "Image": r"C:\Program Files\nodejs\node.exe",
            "ImageLoaded": r"C:\Users\developer\AppData\Local\Temp\addon.node",
            "Signed": "true",
            "SignatureStatus": "Valid"
        }),
        causal_parent: None,
    };

    let vote_temp = rea_voter
        .vote(&event_node_temp_dll)
        .await
        .expect("ReaVoter must vote on temp directory dynamic load in node.exe");

    assert!(
        vote_temp.weight > 1.0,
        "Dynamic load from untrusted Temp folder must receive positive escalation weight, got {}",
        vote_temp.weight
    );

    // Challenge 1d: Sysmon event with lowercase `image_loaded` field
    let event_lowercase_field = HostSecurityEvent {
        source: HostEventSource::WindowsEventLog,
        event_id: 7,
        timestamp: chrono::Utc::now(),
        computer: "DEV-STATION-01".to_string(),
        data: json!({
            "Image": r"C:\Users\developer\.cargo\bin\rustc.exe",
            "image_loaded": r"C:\Users\developer\AppData\Local\Temp\rust_inject.dll",
            "is_signed": false
        }),
        causal_parent: None,
    };

    let vote_lc = rea_voter
        .vote(&event_lowercase_field)
        .await
        .expect("ReaVoter must handle lowercase image_loaded field");

    assert!(
        vote_lc.weight > 1.0,
        "Lowercase image_loaded unsigned load must receive positive escalation weight, got {}",
        vote_lc.weight
    );

    // Challenge 1e: Developer binary `cargo.exe` dynamically loads signed, valid system DLL
    // Should NOT falsely escalate as untrusted dynamic load
    let event_clean_system_dll = HostSecurityEvent {
        source: HostEventSource::WindowsEventLog,
        event_id: 7,
        timestamp: chrono::Utc::now(),
        computer: "DEV-STATION-01".to_string(),
        data: json!({
            "Image": r"C:\Users\developer\.cargo\bin\cargo.exe",
            "ImageLoaded": r"C:\Windows\System32\kernel32.dll",
            "Signed": "true",
            "SignatureStatus": "Valid"
        }),
        causal_parent: None,
    };

    let vote_clean = rea_voter.vote(&event_clean_system_dll).await;
    if let Some(v) = vote_clean {
        assert!(
            !v.reason
                .contains("Untrusted or unsigned dynamic module load"),
            "Clean system DLL load in cargo.exe must NOT be flagged as untrusted load! Got: {}",
            v.reason
        );
    }
}

// -----------------------------------------------------------------------------
// 2. ReaVoter Tainted Session Benign Veto Suppression Challenges
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_adversarial_reavoter_tainted_session_veto_suppression() {
    let rea_voter = ReaVoter::new();

    // Challenge 2a: `cargo.exe` with untrusted_taint = true
    let event_tainted_cargo = HostSecurityEvent {
        source: HostEventSource::WindowsEventLog,
        event_id: 1,
        timestamp: chrono::Utc::now(),
        computer: "DEV-STATION-01".to_string(),
        data: json!({
            "Image": r"C:\Users\developer\.cargo\bin\cargo.exe",
            "CommandLine": "cargo build",
            "untrusted_taint": true
        }),
        causal_parent: None,
    };

    let vote_cargo = rea_voter.vote(&event_tainted_cargo).await;
    assert!(
        vote_cargo.is_none() || vote_cargo.as_ref().unwrap().weight > 0.0,
        "Tainted cargo.exe session must NEVER receive benign veto (weight < 0.0)! Got: {:?}",
        vote_cargo
    );

    // Challenge 2b: `python.exe` with taint_level > 0 (e.g. taint_level = 3)
    let event_tainted_python = HostSecurityEvent {
        source: HostEventSource::WindowsEventLog,
        event_id: 1,
        timestamp: chrono::Utc::now(),
        computer: "DEV-STATION-01".to_string(),
        data: json!({
            "Image": r"C:\Python312\python.exe",
            "CommandLine": "python app.py",
            "taint_level": 3
        }),
        causal_parent: None,
    };

    let vote_python = rea_voter.vote(&event_tainted_python).await;
    assert!(
        vote_python.is_none() || vote_python.as_ref().unwrap().weight > 0.0,
        "Session with taint_level > 0 must NEVER receive benign veto! Got: {:?}",
        vote_python
    );

    // Challenge 2c: `cl.exe` with has_crown_jewel_taint = true
    let event_tainted_cl = HostSecurityEvent {
        source: HostEventSource::WindowsEventLog,
        event_id: 1,
        timestamp: chrono::Utc::now(),
        computer: "DEV-STATION-01".to_string(),
        data: json!({
            "Image": r"C:\Program Files\Microsoft Visual Studio\VC\bin\cl.exe",
            "CommandLine": "cl.exe /c main.cpp",
            "has_crown_jewel_taint": true
        }),
        causal_parent: None,
    };

    let vote_cl = rea_voter.vote(&event_tainted_cl).await;
    assert!(
        vote_cl.is_none() || vote_cl.as_ref().unwrap().weight > 0.0,
        "Session with has_crown_jewel_taint must NEVER receive benign veto! Got: {:?}",
        vote_cl
    );

    // Challenge 2d: `git.exe` with tainted = true
    let event_tainted_git = HostSecurityEvent {
        source: HostEventSource::WindowsEventLog,
        event_id: 1,
        timestamp: chrono::Utc::now(),
        computer: "DEV-STATION-01".to_string(),
        data: json!({
            "Image": r"C:\Program Files\Git\cmd\git.exe",
            "CommandLine": "git push origin main",
            "tainted": true
        }),
        causal_parent: None,
    };

    let vote_git = rea_voter.vote(&event_tainted_git).await;
    assert!(
        vote_git.is_none() || vote_git.as_ref().unwrap().weight > 0.0,
        "Session with tainted=true must NEVER receive benign veto! Got: {:?}",
        vote_git
    );

    // Challenge 2e: Direct helper function `is_rea_benign_system_or_dev_process`
    // Must strictly return false when reason contains any taint or untrusted module indicator!
    assert!(
        !is_rea_benign_system_or_dev_process("cargo.exe", Some("untrusted_taint")),
        "is_rea_benign_system_or_dev_process must return false for untrusted_taint"
    );
    assert!(
        !is_rea_benign_system_or_dev_process("python.exe", Some("tainted")),
        "is_rea_benign_system_or_dev_process must return false for tainted"
    );
    assert!(
        !is_rea_benign_system_or_dev_process("git.exe", Some("unsigned_module")),
        "is_rea_benign_system_or_dev_process must return false for unsigned_module"
    );
    assert!(
        !is_rea_benign_system_or_dev_process("node.exe", Some("image_loaded_untrusted")),
        "is_rea_benign_system_or_dev_process must return false for image_loaded_untrusted"
    );
    assert!(
        !is_rea_benign_system_or_dev_process("rustc.exe", Some("dynamic_load_untrusted")),
        "is_rea_benign_system_or_dev_process must return false for dynamic_load_untrusted"
    );

    // Contrast: Clean untainted process without indicators returns true
    assert!(
        is_rea_benign_system_or_dev_process("cargo.exe", None),
        "Clean cargo.exe without taint or reason must return true"
    );
}

// -----------------------------------------------------------------------------
// 3. Trusted ZK-PII Declassification Empirical Adversarial Challenges
// -----------------------------------------------------------------------------

#[test]
fn test_adversarial_zk_pii_declassification_tampered_proofs_fail_closed() -> Result<()> {
    let graph = CausalSecurityGraph::in_memory()?;

    // Step 1: Register upstream sensitive Crown-Jewel source file
    let secret_file_id = graph.register_file(
        "C:\\vault\\secret_credentials.env",
        "C:\\vault\\secret_credentials.env",
        "hash_vault_secret_99812",
        FileClassification::CrownJewel,
        AuthorityLevel::SystemSecurityPolicy,
        4,    // taint level 4
        true, // has crown jewel taint
    )?;

    // Step 2: Register downstream derived destination file (initially inherits taint)
    let declass_file_id = graph.register_file(
        "C:\\output\\scrubbed_manifest.json",
        "C:\\output\\scrubbed_manifest.json",
        "hash_output_scrubbed_11204",
        FileClassification::Scratchpad,
        AuthorityLevel::WorkspaceConfiguration,
        4,    // initially tainted
        true, // initially tainted
    )?;

    // Verify initial taint state of destination file before declassification
    let initial_report = graph.get_transitive_taint_report(&declass_file_id)?;
    assert_eq!(initial_report.max_taint_level, 4);
    assert!(initial_report.has_crown_jewel_taint);

    // Step 3: Generate genuine baseline proof via PresidioGlinerPiiZeroGuard
    let raw_payload = "Target System API Key: sk-live-99887766554433221100aabbccddeeff";
    let genuine_proof = PresidioGlinerPiiZeroGuard::scrub_and_prove(raw_payload, 777, 6.2, 4);
    assert!(genuine_proof.scrubbed_payload.contains("<ZK_PII:"));
    assert_eq!(genuine_proof.pii_leakage_bits, 0);
    assert!(genuine_proof.is_valid_zero_knowledge_proof);

    // -------------------------------------------------------------------------
    // Attack 3a: Tampered ML-DSA-65 post-quantum signature
    // -------------------------------------------------------------------------
    let mut tampered_sig_proof = genuine_proof.clone();
    // Invert trailing bytes of the signature hex string
    let mut sig_chars: Vec<char> = tampered_sig_proof
        .pqc_mldsa65_signature_hex
        .chars()
        .collect();
    if let Some(last) = sig_chars.last_mut() {
        *last = if *last == '0' { 'f' } else { '0' };
    }
    tampered_sig_proof.pqc_mldsa65_signature_hex = sig_chars.into_iter().collect();

    let res_tampered_sig = graph.declassify_node(
        &secret_file_id,
        &declass_file_id,
        &tampered_sig_proof,
        "adversarial_session_1",
        Some("decision_atk_sig"),
    )?;

    assert!(
        !res_tampered_sig.success,
        "Declassification with tampered ML-DSA-65 signature MUST fail!"
    );
    assert!(
        !res_tampered_sig.pqc_signature_verified,
        "Signature verification must be false"
    );
    assert!(
        res_tampered_sig
            .reason
            .contains("proof verification failed"),
        "Reason must state proof verification failed: {}",
        res_tampered_sig.reason
    );

    // Assert taint was NOT cleared in SQLite!
    let report_after_sig_tamper = graph.get_transitive_taint_report(&declass_file_id)?;
    assert_eq!(
        report_after_sig_tamper.max_taint_level, 4,
        "Taint level must remain 4 after tampered signature attack!"
    );
    assert!(
        report_after_sig_tamper.has_crown_jewel_taint,
        "Crown-Jewel taint must remain true after tampered signature attack!"
    );

    // -------------------------------------------------------------------------
    // Attack 3b: Tampered Schnorr / Fiat-Shamir commitment hash
    // -------------------------------------------------------------------------
    let mut tampered_commit_proof = genuine_proof.clone();
    tampered_commit_proof.schnorr_fiat_shamir_commitment =
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string();

    let res_tampered_commit = graph.declassify_node(
        &secret_file_id,
        &declass_file_id,
        &tampered_commit_proof,
        "adversarial_session_2",
        Some("decision_atk_commit"),
    )?;

    assert!(
        !res_tampered_commit.success,
        "Declassification with tampered commitment hash MUST fail!"
    );

    // Assert taint was NOT cleared in SQLite!
    let report_after_commit_tamper = graph.get_transitive_taint_report(&declass_file_id)?;
    assert_eq!(
        report_after_commit_tamper.max_taint_level, 4,
        "Taint level must remain 4 after tampered commitment attack!"
    );
    assert!(
        report_after_commit_tamper.has_crown_jewel_taint,
        "Crown-Jewel taint must remain true after tampered commitment attack!"
    );

    // -------------------------------------------------------------------------
    // Attack 3c: Missing `<ZK_PII:...>` tags in scrubbed payload
    // -------------------------------------------------------------------------
    let mut missing_tags_proof = genuine_proof.clone();
    // Strip <ZK_PII:...> tags from payload while leaving redacted_entity_count > 0
    missing_tags_proof.scrubbed_payload = "Target System API Key: [REDACTED_API_KEY]".to_string();

    let res_missing_tags = graph.declassify_node(
        &secret_file_id,
        &declass_file_id,
        &missing_tags_proof,
        "adversarial_session_3",
        Some("decision_atk_tags"),
    )?;

    assert!(
        !res_missing_tags.success,
        "Declassification without mandatory <ZK_PII:...> tags MUST fail!"
    );
    assert!(
        res_missing_tags
            .reason
            .contains("missing mandatory <ZK_PII:...> commitments"),
        "Reason must explicitly identify missing <ZK_PII:...> commitments: {}",
        res_missing_tags.reason
    );

    // Assert taint was NOT cleared in SQLite!
    let report_after_missing_tags = graph.get_transitive_taint_report(&declass_file_id)?;
    assert_eq!(
        report_after_missing_tags.max_taint_level, 4,
        "Taint level must remain 4 after missing tags attack!"
    );
    assert!(
        report_after_missing_tags.has_crown_jewel_taint,
        "Crown-Jewel taint must remain true after missing tags attack!"
    );

    // -------------------------------------------------------------------------
    // Attack 3d: Non-zero leakage bits
    // -------------------------------------------------------------------------
    let mut leakage_proof = genuine_proof.clone();
    leakage_proof.pii_leakage_bits = 16;

    let res_leakage = graph.declassify_node(
        &secret_file_id,
        &declass_file_id,
        &leakage_proof,
        "adversarial_session_4",
        Some("decision_atk_leakage"),
    )?;

    assert!(
        !res_leakage.success,
        "Declassification with non-zero leakage bits MUST fail!"
    );
    assert!(
        res_leakage.reason.contains("non-zero leakage bits"),
        "Reason must state non-zero leakage bits: {}",
        res_leakage.reason
    );

    // Assert taint was NOT cleared in SQLite!
    let report_after_leakage = graph.get_transitive_taint_report(&declass_file_id)?;
    assert_eq!(report_after_leakage.max_taint_level, 4);
    assert!(report_after_leakage.has_crown_jewel_taint);

    // -------------------------------------------------------------------------
    // Attack 3e: Low sigma_z statistical confidence (< 5.0)
    // -------------------------------------------------------------------------
    let mut low_sigma_proof = genuine_proof.clone();
    low_sigma_proof.sigma_z = 3.5;
    low_sigma_proof.is_valid_zero_knowledge_proof = false;

    let res_low_sigma = graph.declassify_node(
        &secret_file_id,
        &declass_file_id,
        &low_sigma_proof,
        "adversarial_session_5",
        Some("decision_atk_sigma"),
    )?;

    assert!(
        !res_low_sigma.success,
        "Declassification with low sigma_z MUST fail!"
    );

    // Assert taint was NOT cleared in SQLite!
    let report_after_low_sigma = graph.get_transitive_taint_report(&declass_file_id)?;
    assert_eq!(report_after_low_sigma.max_taint_level, 4);
    assert!(report_after_low_sigma.has_crown_jewel_taint);

    // -------------------------------------------------------------------------
    // Genuine Baseline Verification: Legitimate proof clears taint
    // -------------------------------------------------------------------------
    let res_genuine = graph.declassify_node(
        &secret_file_id,
        &declass_file_id,
        &genuine_proof,
        "legitimate_session",
        Some("decision_legit_001"),
    )?;

    assert!(
        res_genuine.success,
        "Genuine verified proof MUST successfully declassify: {}",
        res_genuine.reason
    );
    assert_eq!(res_genuine.pii_leakage_bits, 0);
    assert!(res_genuine.pqc_signature_verified);

    // Assert taint IS NOW cleared in SQLite!
    let final_report = graph.get_transitive_taint_report(&declass_file_id)?;
    assert_eq!(
        final_report.max_taint_level, 0,
        "Taint level must be 0 after successful declassification!"
    );
    assert!(
        !final_report.has_crown_jewel_taint,
        "Crown-Jewel taint must be false after successful declassification!"
    );

    // Verify upstream secret file remains tainted (only the derived output was declassified)
    let secret_report = graph.get_transitive_taint_report(&secret_file_id)?;
    assert_eq!(
        secret_report.max_taint_level, 4,
        "Originating sensitive file must preserve its taint level 4!"
    );
    assert!(
        secret_report.has_crown_jewel_taint,
        "Originating sensitive file must preserve Crown-Jewel taint!"
    );

    Ok(())
}
