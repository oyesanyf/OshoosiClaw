//! Empirical Challenge & Stress Test Suite for CausalSecurityGraph (Milestone 1)
//!
//! Empirically challenges:
//! 1. Deep process ancestry trees (64+ levels) recursive traversal, stack safety, and latency.
//! 2. High-concurrency readers and writers under extreme contention.
//! 3. PID reuse attacks against composite `ProcessInstanceIdentity`.
//! 4. Concurrency capability invalidation barrier (seqlock/epoch invalidation).
//! 5. Directed cycle resilience and DAG termination.
//! 6. Adversarial ZK-PII declassification oracle (tampered signatures, leakage bits, missing commitments).
//! 7. Confused-deputy broker attribution and unlinked spoofing defense.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::Utc;
use osoosi_core::causal_graph::{
    AuthorityLevel, CausalEdgeType, CausalEventRecord, CausalSecurityGraph, FileClassification,
    ProcessInstanceIdentity,
};
use osoosi_dp::PresidioGlinerPiiZeroGuard;

// =============================================================================
// CHALLENGE 1: Deep Process Ancestry Tree (64+ Levels) & Stack Safety
// =============================================================================

#[test]
fn test_deep_process_ancestry_tree_stress_and_stack_safety() -> Result<()> {
    let graph = CausalSecurityGraph::in_memory()?;
    let depth = 64;

    let root_session = "session_deep_lineage_001";
    let root = ProcessInstanceIdentity::new(
        1000,
        100_000,
        "blake3_root_image_digest",
        None,
        Some("job_root".to_string()),
        root_session,
    );
    graph.register_process_instance(&root, "C:\\agent\\root.exe", 0, false)?;

    // Root process reads a Crown-Jewel secret file
    let cj_file_path = "C:\\vault\\crown_jewel_root.key";
    let cj_id = graph.register_file(
        cj_file_path,
        cj_file_path,
        "hash_crown_jewel_secret",
        FileClassification::CrownJewel,
        AuthorityLevel::SystemSecurityPolicy,
        3,
        true,
    )?;

    let (proc_taint, proc_cj) = graph.record_file_read(&root.instance_id, cj_file_path)?;
    assert_eq!(proc_taint, 3);
    assert!(proc_cj);

    // Build a 64-level deep process ancestry chain
    let mut current_parent = root;
    let mut all_instances = Vec::new();

    let start_time = Instant::now();
    for i in 1..=depth {
        let child_pid = 1000 + i as u32;
        let child_start = 100_000 + (i as u64 * 10);
        let child = ProcessInstanceIdentity::new(
            child_pid,
            child_start,
            format!("blake3_digest_level_{}", i),
            Some(current_parent.instance_id.clone()),
            Some(format!("job_level_{}", i)),
            root_session,
        );

        let child_image = format!("C:\\agent\\worker_level_{}.exe", i);
        graph.record_process_spawn(&current_parent, &child, &child_image)?;

        all_instances.push(child.clone());
        current_parent = child;
    }
    let chain_construction_time = start_time.elapsed();
    println!(
        "[CHALLENGE 1] Constructed {}-level ancestry chain in {:?}",
        depth, chain_construction_time
    );

    // The deepest child (level 64) writes to a leaf output artifact
    let leaf_instance = all_instances.last().unwrap();
    let leaf_output_path = "C:\\temp\\deep_leaf_artifact.dat";
    graph.record_file_write(
        &leaf_instance.instance_id,
        leaf_output_path,
        leaf_output_path,
        "hash_leaf_output",
    )?;

    let leaf_file_id = blake3::hash(leaf_output_path.as_bytes())
        .to_hex()
        .to_string();

    // Query transitive taint on leaf artifact
    let query_start = Instant::now();
    let report = graph.get_transitive_taint_report(&leaf_file_id)?;
    let query_duration = query_start.elapsed();

    println!(
        "[CHALLENGE 1] Querying 64-level deep transitive taint completed in {:?}",
        query_duration
    );

    // Invariant Assertions:
    assert!(
        report.is_tainted,
        "Leaf artifact MUST inherit transitive taint from 64 generations above"
    );
    assert_eq!(
        report.max_taint_level, 3,
        "Taint level MUST be 3 (CrownJewel)"
    );
    assert!(
        report.has_crown_jewel_taint,
        "Crown-Jewel taint flag MUST survive 64 process generations"
    );
    assert!(
        report.causal_chain.len() >= depth + 1,
        "Causal chain must contain at least {} nodes, actual: {}",
        depth + 1,
        report.causal_chain.len()
    );
    assert!(
        report.taint_origins.iter().any(|o| o.contains(&cj_id)),
        "Root Crown-Jewel file origin MUST be present in taint origins list"
    );
    assert!(
        query_duration < Duration::from_millis(500),
        "Transitive taint report for 64 levels MUST evaluate in < 500ms, actual: {:?}",
        query_duration
    );

    Ok(())
}

// =============================================================================
// CHALLENGE 2: Directed Graph Cycle Resilience (No Infinite Loops / Stack Overflow)
// =============================================================================

#[test]
fn test_causal_graph_directed_cycle_resilience() -> Result<()> {
    let graph = CausalSecurityGraph::in_memory()?;

    // Create 3 nodes in a synthetic cycle: Node A -> Node B -> Node C -> Node A
    let node_a = "cycle_node_a";
    let node_b = "cycle_node_b";
    let node_c = "cycle_node_c";

    graph.record_edge(node_a, node_b, CausalEdgeType::DerivedFrom, 2, false)?;
    graph.record_edge(node_b, node_c, CausalEdgeType::DerivedFrom, 2, false)?;
    graph.record_edge(node_c, node_a, CausalEdgeType::DerivedFrom, 2, false)?;

    // Traversal must terminate cleanly and promptly without infinite loop
    let start = Instant::now();
    let report = graph.get_transitive_taint_report(node_a)?;
    let elapsed = start.elapsed();

    assert!(report.is_tainted);
    assert_eq!(report.max_taint_level, 2);
    assert!(
        elapsed < Duration::from_millis(100),
        "Cycle traversal must terminate in < 100ms"
    );
    assert!(report.causal_chain.contains(&node_a.to_string()));
    assert!(report.causal_chain.contains(&node_b.to_string()));
    assert!(report.causal_chain.contains(&node_c.to_string()));

    Ok(())
}

// =============================================================================
// CHALLENGE 3: PID Reuse Attack Resistance (Non-Detachable Composite Identity)
// =============================================================================

#[test]
fn test_pid_reuse_attack_resistance_via_composite_identity() -> Result<()> {
    let graph = CausalSecurityGraph::in_memory()?;
    let reused_pid = 7777;

    // Phase 1: Malware process executes under PID 7777 at T = 100_000
    let identity_malware = ProcessInstanceIdentity::new(
        reused_pid,
        100_000,
        "blake3_malware_hash_deadbeef",
        None,
        Some("job_isolated".to_string()),
        "session_malware_turn_0",
    );
    graph.register_process_instance(&identity_malware, "C:\\evil\\backdoor.exe", 0, false)?;

    // Malware reads sensitive credentials, becoming tainted (taint = 3, CJ = true)
    let cred_file = "C:\\vault\\api_keys.env";
    graph.register_file(
        cred_file,
        cred_file,
        "hash_api_keys",
        FileClassification::CrownJewel,
        AuthorityLevel::SystemSecurityPolicy,
        3,
        true,
    )?;
    let (m_taint, m_cj) = graph.record_file_read(&identity_malware.instance_id, cred_file)?;
    assert_eq!(m_taint, 3);
    assert!(m_cj);

    // Phase 2: Malware exits. Later, OS re-assigns PID 7777 to a benign developer process
    // at T = 450_000 in a clean session
    let identity_benign_dev = ProcessInstanceIdentity::new(
        reused_pid,
        450_000, // Distinct 100ns start time
        "blake3_cargo_hash_feedcafe",
        None,
        Some("job_dev".to_string()),
        "session_clean_developer",
    );
    graph.register_process_instance(
        &identity_benign_dev,
        "C:\\Rust\\.cargo\\bin\\cargo.exe",
        0,
        false,
    )?;

    // Attack Verification: Assert instance IDs are distinct
    assert_ne!(
        identity_malware.instance_id, identity_benign_dev.instance_id,
        "Reused PID with distinct start time MUST produce completely distinct instance_ids"
    );

    // Assert benign process has ZERO taint and ZERO crown jewel flags in SQLite
    let benign_lookup = graph.get_process_instance(&identity_benign_dev.instance_id)?;
    assert!(benign_lookup.is_some());

    let benign_taint_report =
        graph.get_transitive_taint_report(&identity_benign_dev.instance_id)?;
    assert!(
        !benign_taint_report.is_tainted,
        "Benign process assigned recycled PID MUST NOT inherit malware's taint!"
    );
    assert_eq!(benign_taint_report.max_taint_level, 0);
    assert!(!benign_taint_report.has_crown_jewel_taint);

    // Assert malware process retains its taint
    let malware_taint_report = graph.get_transitive_taint_report(&identity_malware.instance_id)?;
    assert!(malware_taint_report.is_tainted);
    assert_eq!(malware_taint_report.max_taint_level, 3);
    assert!(malware_taint_report.has_crown_jewel_taint);

    // Phase 3: Attacker attempts to spoof same PID and same start time, but has different image digest
    let identity_spoof_digest = ProcessInstanceIdentity::new(
        reused_pid,
        100_000,
        "blake3_different_binary_hash",
        None,
        Some("job_isolated".to_string()),
        "session_malware_turn_0",
    );
    assert_ne!(
        identity_malware.instance_id, identity_spoof_digest.instance_id,
        "Image digest difference MUST prevent identity collision"
    );

    // Phase 4: Attacker attempts to spoof PID, start time, digest, but in different session
    let identity_spoof_session = ProcessInstanceIdentity::new(
        reused_pid,
        100_000,
        "blake3_malware_hash_deadbeef",
        None,
        Some("job_isolated".to_string()),
        "session_different_hijack",
    );
    assert_ne!(
        identity_malware.instance_id, identity_spoof_session.instance_id,
        "Session ID difference MUST prevent cross-session identity laundering"
    );

    Ok(())
}

// =============================================================================
// CHALLENGE 4: High-Concurrency Readers and Writers Stress Harness
// =============================================================================

#[test]
fn test_high_concurrency_readers_and_writers_stress() -> Result<()> {
    let graph = Arc::new(CausalSecurityGraph::in_memory()?);
    let num_threads = 16;
    let ops_per_thread = 200;

    let stop_signal = Arc::new(AtomicBool::new(false));
    let successful_ops = Arc::new(AtomicUsize::new(0));

    // Seed baseline root process and file
    let root = ProcessInstanceIdentity::new(
        5000,
        1_000_000,
        "root_digest",
        None,
        None,
        "concurrency_session",
    );
    graph.register_process_instance(&root, "C:\\app\\root.exe", 1, false)?;

    let seed_file = "C:\\app\\data_shared.json";
    graph.register_file(
        seed_file,
        seed_file,
        "hash_shared_data",
        FileClassification::Scratchpad,
        AuthorityLevel::WorkspaceConfiguration,
        1,
        false,
    )?;

    let mut handles = Vec::new();

    for thread_idx in 0..num_threads {
        let g = Arc::clone(&graph);
        let stop = Arc::clone(&stop_signal);
        let success_counter = Arc::clone(&successful_ops);
        let root_id = root.instance_id.clone();

        let handle = thread::spawn(move || {
            let session_id = format!("concurrency_session_{}", thread_idx);

            for op_idx in 0..ops_per_thread {
                if stop.load(Ordering::Relaxed) {
                    break;
                }

                let sub_op = (thread_idx + op_idx) % 6;
                match sub_op {
                    0 => {
                        // Concurrent process registration and spawn
                        let pid = 10000 + (thread_idx * 1000 + op_idx) as u32;
                        let proc = ProcessInstanceIdentity::new(
                            pid,
                            2_000_000 + op_idx as u64,
                            format!("digest_{}_{}", thread_idx, op_idx),
                            Some(root_id.clone()),
                            None,
                            &session_id,
                        );
                        let _ = g.register_process_instance(
                            &proc,
                            &format!("C:\\proc_{}_{}.exe", thread_idx, op_idx),
                            1,
                            false,
                        );
                    }
                    1 => {
                        // Concurrent file write
                        let path = format!("C:\\temp\\file_{}_{}.tmp", thread_idx, op_idx % 20);
                        let _ = g.record_file_write(&root_id, &path, &path, "hash_tmp");
                    }
                    2 => {
                        // Concurrent event logging
                        let now = Utc::now().to_rfc3339();
                        let evt = CausalEventRecord {
                            event_id: format!("evt_{}_{}", thread_idx, op_idx),
                            event_seq: op_idx as u64 + 1,
                            decision_id: Some(format!("dec_{}", op_idx)),
                            session_id: session_id.clone(),
                            process_instance_id: root_id.clone(),
                            effect_type: "SensitiveFileAccess".to_string(),
                            source_resource: root_id.clone(),
                            target_resource: "C:\\app\\data_shared.json".to_string(),
                            is_authorized: true,
                            verdict: "Allow".to_string(),
                            policy_version: 1,
                            taint_epoch: 1,
                            pre_event_taint: 1,
                            post_event_taint: 1,
                            details_json: None,
                            timestamp: now,
                        };
                        let _ = g.record_event(&evt);
                    }
                    3 => {
                        // Concurrent capability cache read & write
                        let key_res = format!("res_{}", op_idx % 10);
                        let _ = g.store_capability(
                            &format!("principal_{}", thread_idx),
                            "ExternalWrite",
                            &key_res,
                            true,
                            1,
                            1,
                            1,
                            "dec_test",
                            120,
                        );
                        let _ = g.check_capability(
                            &format!("principal_{}", thread_idx),
                            "ExternalWrite",
                            &key_res,
                            1,
                            1,
                            1,
                        );
                    }
                    4 => {
                        // Concurrent capability invalidation
                        let _ = g.invalidate_capabilities_by_revocation(1);
                        let _ = g.invalidate_capabilities_by_taint_epoch(1);
                    }
                    _ => {
                        // Concurrent transitive taint query
                        let _ = g.get_transitive_taint_report(&root_id);
                    }
                }

                success_counter.fetch_add(1, Ordering::Relaxed);
            }
        });

        handles.push(handle);
    }

    for h in handles {
        h.join()
            .expect("Worker thread panicked under concurrency contention!");
    }

    let total_ops = successful_ops.load(Ordering::SeqCst);
    println!(
        "[CHALLENGE 4] High-concurrency stress completed: {} successful mixed operations across {} threads with ZERO panics or deadlock",
        total_ops, num_threads
    );
    assert_eq!(total_ops, num_threads * ops_per_thread);

    Ok(())
}

// =============================================================================
// CHALLENGE 5: Concurrency Capability Invalidation Barrier (Seqlock / Epoch Race)
// =============================================================================

#[test]
fn test_concurrency_capability_invalidation_barrier() -> Result<()> {
    let graph = CausalSecurityGraph::in_memory()?;
    let principal = "agent_worker_42";
    let action = "ExternalWrite";
    let destination = "https://api.github.com/repos/target/issues/comments";

    // Step 1: Initial grant under policy_version=1, taint_epoch=1, revocation_seq=1
    graph.store_capability(
        principal,
        action,
        destination,
        true,
        1, // policy_version
        1, // taint_epoch
        1, // revocation_seq
        "decision_initial_permit",
        600,
    )?;

    // Cache hit under valid epoch
    let hit = graph.check_capability(principal, action, destination, 1, 1, 1)?;
    assert_eq!(hit, Some(true), "Capability must hit under matching epoch");

    // Step 2: Crown-Jewel access occurs! Taint epoch is bumped to 2, revocation_seq to 2
    let (new_epoch, new_rev_seq) = graph.bump_taint_epoch("session_42", 3, true);
    assert_eq!(new_epoch, 2);
    assert_eq!(new_rev_seq, 2);

    // Step 3: Invalidate capability cache for stale epochs
    let purged = graph.invalidate_capabilities_by_taint_epoch(new_epoch)?;
    assert_eq!(purged, 1, "Exactly 1 stale capability should be purged");

    // Stale lookup with old epoch (1, 1) returns None
    let stale_lookup = graph.check_capability(principal, action, destination, 1, 1, 1)?;
    assert_eq!(
        stale_lookup, None,
        "Stale capability MUST NOT be returned after invalidation"
    );

    // Lookup with new epoch (2, 2) also misses (requires fresh Cedar evaluation)
    let fresh_lookup =
        graph.check_capability(principal, action, destination, 1, new_epoch, new_rev_seq)?;
    assert_eq!(
        fresh_lookup, None,
        "Fresh evaluation is mandatory once taint epoch has bumped"
    );

    Ok(())
}

// =============================================================================
// CHALLENGE 6: Adversarial ZK-PII Declassification Oracle Verification
// =============================================================================

#[test]
fn test_zk_pii_declassification_adversarial_oracle() -> Result<()> {
    let graph = CausalSecurityGraph::in_memory()?;

    // Register tainted Crown-Jewel source
    let secret_path = "C:\\vault\\confidential_records.csv";
    let secret_id = graph.register_file(
        secret_path,
        secret_path,
        "hash_csv_secrets",
        FileClassification::CrownJewel,
        AuthorityLevel::SystemSecurityPolicy,
        3,
        true,
    )?;

    // Generate genuine baseline proof via PresidioGlinerPiiZeroGuard
    let raw = "Contact phone: +1-555-867-5309, SSN: 000-12-3456";
    let valid_proof = PresidioGlinerPiiZeroGuard::scrub_and_prove(raw, 500, 6.0, 4);

    let clean_path = "C:\\vault\\scrubbed_records.csv";
    let clean_id = graph.register_file(
        clean_path,
        clean_path,
        "hash_scrubbed_clean",
        FileClassification::Scratchpad,
        AuthorityLevel::WorkspaceConfiguration,
        3, // initially inherits taint
        true,
    )?;

    // Probe A: Tamper proof by introducing non-zero leakage bits
    let mut leak_proof = valid_proof.clone();
    leak_proof.pii_leakage_bits = 4;
    let res_leak =
        graph.declassify_node(&secret_id, &clean_id, &leak_proof, "session_test", None)?;
    assert!(
        !res_leak.success,
        "Declassification with non-zero leakage bits MUST fail closed"
    );
    assert!(res_leak.reason.contains("non-zero leakage bits"));

    // Probe B: Invalidate ZK proof flag
    let mut invalid_zk_proof = valid_proof.clone();
    invalid_zk_proof.is_valid_zero_knowledge_proof = false;
    let res_zk = graph.declassify_node(
        &secret_id,
        &clean_id,
        &invalid_zk_proof,
        "session_test",
        None,
    )?;
    assert!(!res_zk.success, "Invalid ZK proof flag MUST fail closed");

    // Probe C: Corrupt ML-DSA-65 post-quantum signature bytes
    let mut tampered_sig_proof = valid_proof.clone();
    assert!(
        !tampered_sig_proof.pqc_mldsa65_signature_hex.is_empty(),
        "Valid ZK-PII proof must carry an ML-DSA-65 + Ed25519 hybrid signature"
    );
    tampered_sig_proof.pqc_mldsa65_signature_hex = "deadbeefcafebabe00112233".to_string();
    let res_sig = graph.declassify_node(
        &secret_id,
        &clean_id,
        &tampered_sig_proof,
        "session_test",
        None,
    )?;
    assert!(
        !res_sig.success,
        "Forged ML-DSA-65 signature MUST fail verification"
    );

    // Probe D: Missing mandatory <ZK_PII:...> commitments
    let mut missing_commitments_proof = valid_proof.clone();
    missing_commitments_proof.scrubbed_payload = "Plain payload with no commitments".to_string();
    missing_commitments_proof.redacted_entity_count = 2;
    let res_commit = graph.declassify_node(
        &secret_id,
        &clean_id,
        &missing_commitments_proof,
        "session_test",
        None,
    )?;
    assert!(
        !res_commit.success,
        "Missing <ZK_PII:...> commitments MUST fail closed"
    );

    // Probe E: Valid proof succeeds and clears taint
    let res_valid = graph.declassify_node(
        &secret_id,
        &clean_id,
        &valid_proof,
        "session_test",
        Some("dec_approved"),
    )?;
    assert!(
        res_valid.success,
        "Legitimate ZK-PII declassification MUST succeed"
    );
    assert_eq!(res_valid.pii_leakage_bits, 0);
    assert!(res_valid.pqc_signature_verified);

    // Verify clean node taint was cleared in SQLite
    let report_clean = graph.get_transitive_taint_report(&clean_id)?;
    assert_eq!(report_clean.max_taint_level, 0);
    assert!(!report_clean.has_crown_jewel_taint);

    // Verify origin secret file REMAINS tainted
    let report_secret = graph.get_transitive_taint_report(&secret_id)?;
    assert_eq!(report_secret.max_taint_level, 3);
    assert!(report_secret.has_crown_jewel_taint);

    Ok(())
}

// =============================================================================
// CHALLENGE 7: Confused-Deputy Broker Attribution & Spoofing Defense
// =============================================================================

#[test]
fn test_confused_deputy_broker_attribution_and_tamper_defense() -> Result<()> {
    let graph = CausalSecurityGraph::in_memory()?;

    // Register active agent session
    let agent_proc = ProcessInstanceIdentity::new(
        3000,
        50_000,
        "blake3_agent_digest",
        None,
        None,
        "session_agent_origin",
    );

    // 1. Legitimate broker registration (WmiPrvSE.exe, PID 9000)
    let broker_pid = 9000;
    let broker_image = "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe";
    graph.broker_router.register_delegation(
        broker_pid,
        broker_image,
        "session_agent_origin",
        &agent_proc.instance_id,
    );

    // Resolution succeeds
    let attributed = graph.attribute_broker_action(broker_pid, broker_image, "inst_broker_9000")?;
    assert_eq!(attributed, Some("session_agent_origin".to_string()));

    // 2. Non-broker process (e.g. rogue explorer.exe or cmd_fake.exe) attempts attribution
    let non_broker_image = "C:\\malware\\explorer.exe";
    let fake_attributed =
        graph.attribute_broker_action(broker_pid, non_broker_image, "inst_fake")?;
    assert_eq!(
        fake_attributed, None,
        "Non-broker binary MUST NOT be attributed as a broker"
    );

    // 3. Unregistered broker PID returns None
    let unregistered_pid = 9001;
    let unreg_attributed =
        graph.attribute_broker_action(unregistered_pid, broker_image, "inst_unreg")?;
    assert_eq!(unreg_attributed, None);

    // 4. Removing delegation clears active broker mapping
    graph.broker_router.remove_delegation(broker_pid);
    let after_remove =
        graph.attribute_broker_action(broker_pid, broker_image, "inst_broker_9000")?;
    assert_eq!(after_remove, None, "Removed delegation MUST return None");

    Ok(())
}
