use chrono::Utc;
use osoosi_core::byzantine::{
    analyze_policy_consensus, mine_vote_work_nonce, vote_work_proof_valid, BftConsensusParams,
};
use osoosi_core::quarantine::quarantine_file;
use osoosi_core::win_trust::{is_trusted_signed_binary, is_trusted_vendor, verify_file_signature};
use osoosi_model::{ModelConfig, ThreatModel};
use osoosi_types::{
    FederatedModelDelta, PolicyConsensusMessage, PolicyHealthStatus, PolicyHealthVote,
};
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

// =========================================================================
// 1. AUTHENTICODE SIGNATURE TAMPERING & UNTRUSTED ROOT REJECTION
// =========================================================================

#[test]
fn test_attack_authenticode_nonexistent_binary_rejected() {
    let fake_path = Path::new(r"C:\Windows\System32\definitely_not_existing_payload_012345.exe");
    assert!(!is_trusted_signed_binary(fake_path));
    assert!(!verify_file_signature(fake_path.to_str().unwrap()));
}

#[test]
fn test_attack_authenticode_unsigned_temp_file_rejected() {
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join(format!("malware_sample_{}.exe", uuid::Uuid::new_v4()));
    let mut f = std::fs::File::create(&temp_file).unwrap();
    f.write_all(b"MZ\x90\x00\x03\x00\x00\x00FAKE_PE_HEADER_MALICIOUS_SHELLCODE").unwrap();
    drop(f);

    // Any unverified/unsigned PE binary in non-IDE directories must be rejected
    assert!(
        !is_trusted_signed_binary(&temp_file),
        "Unsigned binary in temp directory must not be trusted"
    );
    assert!(
        !verify_file_signature(temp_file.to_str().unwrap()),
        "WinVerifyTrust on unsigned binary must return false"
    );

    let _ = std::fs::remove_file(&temp_file);
}

#[test]
fn test_attack_authenticode_fake_vendor_names_rejected() {
    // Known adversarial or spoofed vendor strings
    let malicious_vendors = [
        "APT29 Cyber Group",
        "Lazarus Group LLC",
        "Insecure Hacker LLC",
        "Malware Author",
        "Cobalt Strike Operations",
        "DarkComet RAT Team",
        "Ransomware Syndicate Inc",
        "Cracked Software Org",
        "",
        " ",
    ];

    for vendor in malicious_vendors {
        assert!(
            !is_trusted_vendor(vendor),
            "Vendor '{}' must be rejected as untrusted",
            vendor
        );
    }

    // Legitimate vendor recognition
    let trusted_vendors = [
        "Microsoft Corporation",
        "Google LLC",
        "Mozilla Corporation",
        "The Khronos Group Inc.",
        "Khronos",
        "HugOS IDE",
        "Rust Language",
        "Node.js Foundation",
    ];

    for vendor in trusted_vendors {
        assert!(
            is_trusted_vendor(vendor),
            "Vendor '{}' should be recognized as trusted",
            vendor
        );
    }
}

// =========================================================================
// 2. HOST FILE QUARANTINE INTEGRITY & ATTACK MITIGATION
// =========================================================================

#[test]
fn test_attack_quarantine_malware_file_moves_and_isolates() {
    let temp_dir = std::env::temp_dir();
    let malware_path = temp_dir.join(format!("dropped_payload_{}.dll", uuid::Uuid::new_v4()));

    // Create a mock malicious dropped artifact
    let mut file = std::fs::File::create(&malware_path).unwrap();
    file.write_all(b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").unwrap();
    drop(file);

    assert!(malware_path.exists(), "Source mock payload must exist initially");

    // Perform quarantine
    let quarantine_result = quarantine_file(malware_path.to_str().unwrap());
    assert!(quarantine_result.is_ok(), "quarantine_file should succeed");

    let dest_path = quarantine_result.unwrap();
    assert!(dest_path.exists(), "Quarantined file must exist in quarantine dir");
    assert!(
        !malware_path.exists(),
        "Source file must no longer exist at original compromised location"
    );

    // Verify filename format contains timestamp and original name
    let filename = dest_path.file_name().unwrap().to_str().unwrap();
    assert!(filename.contains("dropped_payload_"));
    assert!(filename.ends_with(".dll"));

    // Cleanup quarantine artifact
    let _ = std::fs::remove_file(&dest_path);
}

#[test]
fn test_attack_quarantine_nonexistent_file_fails_safely() {
    let nonexistent = "/tmp/does_not_exist_at_all_payload_9999.exe";
    let res = quarantine_file(nonexistent);
    assert!(res.is_err(), "Quarantining nonexistent file must return Err");
}

// =========================================================================
// 3. BYZANTINE FAULT TOLERANCE & SYBIL VOTE POISONING
// =========================================================================

#[test]
fn test_attack_byzantine_sybil_proof_of_work_defense() {
    let policy_id = "pol_audit_hardening_v2";

    // Honest voter mines valid PoW (4 bits)
    let honest_voter = "node_honest_01";
    let valid_nonce = mine_vote_work_nonce(honest_voter, policy_id, 4).expect("Failed to mine PoW");
    assert!(vote_work_proof_valid(honest_voter, policy_id, Some(&valid_nonce), 4));

    // Sybil attacker creates votes without PoW or with invalid nonces
    let sybil_voter_1 = "node_sybil_attacker_01";
    let sybil_voter_2 = "node_sybil_attacker_02";

    let messages = vec![
        PolicyConsensusMessage::Vote(PolicyHealthVote {
            policy_id: policy_id.to_string(),
            voter_id: honest_voter.to_string(),
            status: PolicyHealthStatus::Optimal,
            uptime_seconds: 3600,
            timestamp: Utc::now(),
            work_nonce: Some(valid_nonce),
        }),
        // Sybil votes attempting to force Degraded/CriticalFailure without PoW
        PolicyConsensusMessage::Vote(PolicyHealthVote {
            policy_id: policy_id.to_string(),
            voter_id: sybil_voter_1.to_string(),
            status: PolicyHealthStatus::CriticalFailure,
            uptime_seconds: 10,
            timestamp: Utc::now(),
            work_nonce: None, // Missing PoW
        }),
        PolicyConsensusMessage::Vote(PolicyHealthVote {
            policy_id: policy_id.to_string(),
            voter_id: sybil_voter_2.to_string(),
            status: PolicyHealthStatus::Degraded,
            uptime_seconds: 10,
            timestamp: Utc::now(),
            work_nonce: Some("invalid_unmined_nonce_deadbeef".to_string()), // Invalid PoW
        }),
    ];

    let mut params = BftConsensusParams::default();
    params.pow_vote_leading_zero_bits = 4; // Require 4 bits of PoW

    let outcome = analyze_policy_consensus(
        &messages,
        |_id| 0.8, // all peers have 0.8 reputation
        &params,
    );

    // Both Sybil votes must be filtered out, leaving only the honest voter
    assert_eq!(outcome.participating_voters, 1, "Only voter with valid PoW should be counted");
    assert_eq!(outcome.optimal_count, 1);
    assert_eq!(outcome.degraded_count, 0);
    assert_eq!(outcome.critical_count, 0);
}

#[test]
fn test_attack_byzantine_voter_whitelist_blocks_unauthorized_peers() {
    let policy_id = "pol_kernel_tamper_defense";

    let authorized_voter = "node_authorized_master";
    let rogue_voter = "node_unauthorized_intruder";

    let messages = vec![
        PolicyConsensusMessage::Vote(PolicyHealthVote {
            policy_id: policy_id.to_string(),
            voter_id: authorized_voter.to_string(),
            status: PolicyHealthStatus::Optimal,
            uptime_seconds: 7200,
            timestamp: Utc::now(),
            work_nonce: None,
        }),
        PolicyConsensusMessage::Vote(PolicyHealthVote {
            policy_id: policy_id.to_string(),
            voter_id: rogue_voter.to_string(),
            status: PolicyHealthStatus::CriticalFailure,
            uptime_seconds: 100,
            timestamp: Utc::now(),
            work_nonce: None,
        }),
    ];

    let mut whitelist = HashSet::new();
    whitelist.insert(authorized_voter.to_string());

    let mut params = BftConsensusParams::default();
    params.pow_vote_leading_zero_bits = 0;
    params.voter_whitelist = Some(whitelist);

    let outcome = analyze_policy_consensus(
        &messages,
        |_id| 0.9,
        &params,
    );

    // Rogue voter must be excluded by whitelist filter
    assert_eq!(outcome.participating_voters, 1);
    assert_eq!(outcome.optimal_count, 1);
    assert_eq!(outcome.critical_count, 0);
}

#[test]
fn test_attack_byzantine_fault_tolerance_under_malicious_minority() {
    let policy_id = "pol_firewall_mesh_rules";

    // 2 honest nodes vote Optimal, 1 compromised node votes CriticalFailure (f = 1, n = 3)
    let messages = vec![
        PolicyConsensusMessage::Vote(PolicyHealthVote {
            policy_id: policy_id.to_string(),
            voter_id: "node_honest_1".to_string(),
            status: PolicyHealthStatus::Optimal,
            uptime_seconds: 5000,
            timestamp: Utc::now(),
            work_nonce: None,
        }),
        PolicyConsensusMessage::Vote(PolicyHealthVote {
            policy_id: policy_id.to_string(),
            voter_id: "node_honest_2".to_string(),
            status: PolicyHealthStatus::Optimal,
            uptime_seconds: 5000,
            timestamp: Utc::now(),
            work_nonce: None,
        }),
        PolicyConsensusMessage::Vote(PolicyHealthVote {
            policy_id: policy_id.to_string(),
            voter_id: "node_compromised_byzantine".to_string(),
            status: PolicyHealthStatus::CriticalFailure,
            uptime_seconds: 50,
            timestamp: Utc::now(),
            work_nonce: None,
        }),
    ];

    let mut params = BftConsensusParams::default();
    params.pow_vote_leading_zero_bits = 0;
    params.voter_whitelist = None;

    let outcome = analyze_policy_consensus(
        &messages,
        |_id| 0.85,
        &params,
    );

    // 2 out of 3 = 66.7% >= 2/3 BFT threshold
    assert_eq!(outcome.participating_voters, 3);
    assert_eq!(outcome.optimal_count, 2);
    assert_eq!(outcome.critical_count, 1);
    assert!(outcome.mesh_validated);
}

#[test]
fn test_attack_byzantine_replayed_stale_vote_cannot_overwrite_fresh_vote() {
    let policy_id = "pol_edr_agent_integrity";
    let voter = "node_validator_alpha";

    // 1. Fresh honest vote cast at T0: Optimal
    let fresh_vote = PolicyConsensusMessage::Vote(PolicyHealthVote {
        policy_id: policy_id.to_string(),
        voter_id: voter.to_string(),
        status: PolicyHealthStatus::Optimal,
        uptime_seconds: 3600,
        timestamp: Utc::now(),
        work_nonce: None,
    });

    // 2. Adversary replays an older vote from this node (1 hour stale): CriticalFailure
    let stale_replayed_vote = PolicyConsensusMessage::Vote(PolicyHealthVote {
        policy_id: policy_id.to_string(),
        voter_id: voter.to_string(),
        status: PolicyHealthStatus::CriticalFailure,
        uptime_seconds: 10,
        timestamp: Utc::now() - chrono::Duration::seconds(3600),
        work_nonce: None,
    });

    // Replayed stale vote appears later in message vector (e.g. over gossip)
    let messages = vec![fresh_vote, stale_replayed_vote];

    let mut params = BftConsensusParams::default();
    params.pow_vote_leading_zero_bits = 0;

    let outcome = analyze_policy_consensus(&messages, |_id| 0.9, &params);

    // The fresher Optimal vote MUST prevail over the stale replayed vote!
    assert_eq!(outcome.participating_voters, 1);
    assert_eq!(
        outcome.optimal_count, 1,
        "Stale replayed vote must not overwrite fresher vote"
    );
    assert_eq!(outcome.critical_count, 0);
    assert!(outcome.mesh_validated);
}

#[test]
fn test_attack_byzantine_future_dated_vote_mitigation() {
    let policy_id = "pol_audit_tamper";
    let rogue_voter = "node_time_warp_attacker";

    // Adversary submits a vote dated 1 hour into the future to permanently lock the vote
    let future_vote = PolicyConsensusMessage::Vote(PolicyHealthVote {
        policy_id: policy_id.to_string(),
        voter_id: rogue_voter.to_string(),
        status: PolicyHealthStatus::CriticalFailure,
        uptime_seconds: 9999,
        timestamp: Utc::now() + chrono::Duration::seconds(3600),
        work_nonce: None,
    });

    let messages = vec![future_vote];
    let mut params = BftConsensusParams::default();
    params.pow_vote_leading_zero_bits = 0;

    let outcome = analyze_policy_consensus(&messages, |_id| 0.9, &params);

    // Future-dated vote (> 120s) must be discarded by consensus filters
    assert_eq!(
        outcome.participating_voters, 0,
        "Future-dated vote must be dropped from consensus"
    );
    assert_eq!(outcome.critical_count, 0);
}

#[test]
fn test_attack_poisoned_model_delta_merge_defense() {
    let temp_dir = std::env::temp_dir().join(format!("test_model_{}", uuid::Uuid::new_v4()));
    let config = ModelConfig {
        models_dir: temp_dir.to_str().unwrap().to_string(),
        min_samples: 1,
        model_file: "model.json".to_string(),
        dp_config: None,
    };

    let mut model = ThreatModel::new(config);

    // Adversary crafts poisoned delta with NaN, +Inf, -Inf, and extreme weights
    let mut poisoned_features = std::collections::HashMap::new();
    poisoned_features.insert("cve:cve-2024-9999".to_string(), f32::NAN);
    poisoned_features.insert("cve:cve-2024-8888".to_string(), f32::INFINITY);
    poisoned_features.insert("cve:cve-2024-7777".to_string(), f32::NEG_INFINITY);
    poisoned_features.insert("cve:cve-2024-1234".to_string(), 1000.0); // Extreme weight

    let delta = FederatedModelDelta {
        source_node: "rogue_peer_poisoner".to_string(),
        features: poisoned_features,
        epsilon: 0.1,
        timestamp: Utc::now(),
    };

    // Merging must handle poisoning gracefully without panicking or creating NaNs
    model.merge_delta(&delta);

    let weights = model.weights();
    assert!(
        !weights.features.contains_key("cve:cve-2024-9999"),
        "NaN weight must be rejected"
    );
    assert!(
        !weights.features.contains_key("cve:cve-2024-8888"),
        "Infinity weight must be rejected"
    );
    assert!(
        !weights.features.contains_key("cve:cve-2024-7777"),
        "Negative infinity weight must be rejected"
    );

    // Extreme weight should be clamped to max bound (5.0 / 2.0 = 2.5)
    let clamped_entry = weights.features.get("cve:cve-2024-1234").copied().unwrap_or(0.0);
    assert!(
        clamped_entry.is_finite() && clamped_entry <= 5.0,
        "Extreme weight must be clamped and finite, got: {}",
        clamped_entry
    );

    // Threat inference must remain valid and finite
    let score = model.infer(None, Some("cve-2024-1234"), None, vec![]);
    assert!(
        score.is_finite() && score >= 0.0 && score <= 1.0,
        "Inference score must remain finite and bounded [0.0, 1.0], got: {}",
        score
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_attack_byzantine_stalemate_conflict_detection() {
    let policy_id = "pol_stalemate_eval";

    // 3 nodes vote Optimal, 3 nodes vote Critical (equal reputation 0.8)
    let messages = vec![
        PolicyConsensusMessage::Vote(PolicyHealthVote {
            policy_id: policy_id.to_string(),
            voter_id: "voter_opt_1".to_string(),
            status: PolicyHealthStatus::Optimal,
            uptime_seconds: 1000,
            timestamp: Utc::now(),
            work_nonce: None,
        }),
        PolicyConsensusMessage::Vote(PolicyHealthVote {
            policy_id: policy_id.to_string(),
            voter_id: "voter_opt_2".to_string(),
            status: PolicyHealthStatus::Optimal,
            uptime_seconds: 1000,
            timestamp: Utc::now(),
            work_nonce: None,
        }),
        PolicyConsensusMessage::Vote(PolicyHealthVote {
            policy_id: policy_id.to_string(),
            voter_id: "voter_opt_3".to_string(),
            status: PolicyHealthStatus::Optimal,
            uptime_seconds: 1000,
            timestamp: Utc::now(),
            work_nonce: None,
        }),
        PolicyConsensusMessage::Vote(PolicyHealthVote {
            policy_id: policy_id.to_string(),
            voter_id: "voter_crit_1".to_string(),
            status: PolicyHealthStatus::CriticalFailure,
            uptime_seconds: 1000,
            timestamp: Utc::now(),
            work_nonce: None,
        }),
        PolicyConsensusMessage::Vote(PolicyHealthVote {
            policy_id: policy_id.to_string(),
            voter_id: "voter_crit_2".to_string(),
            status: PolicyHealthStatus::CriticalFailure,
            uptime_seconds: 1000,
            timestamp: Utc::now(),
            work_nonce: None,
        }),
        PolicyConsensusMessage::Vote(PolicyHealthVote {
            policy_id: policy_id.to_string(),
            voter_id: "voter_crit_3".to_string(),
            status: PolicyHealthStatus::CriticalFailure,
            uptime_seconds: 1000,
            timestamp: Utc::now(),
            work_nonce: None,
        }),
    ];

    let mut params = BftConsensusParams::default();
    params.pow_vote_leading_zero_bits = 0;

    let outcome = analyze_policy_consensus(&messages, |_id| 0.8, &params);
    assert_eq!(outcome.participating_voters, 6);
    assert!(!outcome.mesh_validated, "Stalemate must NOT validate mesh policy");
    assert!(outcome.stalemate_conflict, "50/50 conflict should be detected as stalemate");
}

#[test]
fn test_attack_quarantine_concurrent_file_isolation() {
    let temp_dir = std::env::temp_dir().join(format!("quarantine_race_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    // Create 4 distinct mock malware samples with identical basenames in different subdirectories
    let mut files = Vec::new();
    for i in 0..4 {
        let sub = temp_dir.join(format!("dir_{}", i));
        std::fs::create_dir_all(&sub).unwrap();
        let file_path = sub.join("payload.exe");
        let mut f = std::fs::File::create(&file_path).unwrap();
        write!(f, "malicious payload content {}", i).unwrap();
        files.push(file_path);
    }

    // Concurrently quarantine all 4 samples
    let handles: Vec<_> = files
        .into_iter()
        .map(|path| {
            std::thread::spawn(move || {
                quarantine_file(path.to_str().unwrap())
            })
        })
        .collect();

    let mut quarantined_paths = Vec::new();
    for h in handles {
        let res = h.join().unwrap();
        assert!(res.is_ok(), "Concurrent quarantine should succeed");
        let dest = res.unwrap();
        assert!(dest.exists(), "Quarantined destination must exist");
        quarantined_paths.push(dest);
    }

    // Verify all 4 quarantined files have distinct paths (no collisions)
    let unique_paths: HashSet<_> = quarantined_paths.iter().collect();
    assert_eq!(
        unique_paths.len(),
        4,
        "Concurrent quarantine of identical filenames must produce unique destination paths"
    );

    // Cleanup
    for p in quarantined_paths {
        let _ = std::fs::remove_file(p);
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

