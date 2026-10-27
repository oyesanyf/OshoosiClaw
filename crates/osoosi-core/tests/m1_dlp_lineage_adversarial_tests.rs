//! Adversarial Empirical Challenge Suite for Milestone 1:
//! Synthetic OpenTelemetry Producer & Lock-Free DashMap Taint State Machine.
//!
//! Tests:
//! 1. Multi-file merge with 5+ source files (parent SpanContext, SpanLinks count, strictest-wins Baggage).
//! 2. Complete lattice dominance edge-case matrix (meet-semilattice algebraic laws, cross-lattice orthogonality).
//! 3. PID reuse temporal collision immunity under rapid OS churn.
//! 4. Multi-threaded concurrency stress & DashMap lock hygiene.
//! 5. Pure-Rust ssdeep fuzzy hashing edge cases & boundary mitigations.

use std::sync::Arc;
use std::thread;

use chrono::Utc;
use osoosi_core::dlp_lineage::{
    compare_ssdeep, compute_ssdeep, ArtifactKey, ClassificationLattice, DlpBaggage,
    DlpLineageTracker, EgressDecision, FileWriteTaintDecision, PolicyLattice, ProcessInstanceKey,
};

// ============================================================================
// 1. Multi-File Merge with 5+ Source Files Adversarial Challenge
// ============================================================================

#[test]
fn test_adversarial_multi_file_merge_5_plus_sources_and_links() {
    let tracker = DlpLineageTracker::new(30);

    // --- Scenario A: 5 Tainted Sources ---
    // Create 5 tainted files with different classifications and policies.
    // Order:
    // File 1: Confidential, Block
    // File 2: Internal (explicitly sensitive/tainted via Confidential registration), Monitor
    // File 3: CrownJewel, Quarantine
    // File 4: Confidential, Quarantine
    // File 5: Confidential, Block
    let k1 = ArtifactKey::new(100, 1);
    let k2 = ArtifactKey::new(100, 2);
    let k3 = ArtifactKey::new(100, 3);
    let k4 = ArtifactKey::new(100, 4);
    let k5 = ArtifactKey::new(100, 5);

    let rec1 = tracker.register_crown_jewel_artifact(
        k1,
        "src_1_conf.docx",
        b"Confidential Project Plan Alpha",
        ClassificationLattice::Confidential,
        PolicyLattice::Block,
    );
    let rec2 = tracker.register_crown_jewel_artifact(
        k2,
        "src_2_conf.docx",
        b"Confidential Financial Memo Beta",
        ClassificationLattice::Confidential,
        PolicyLattice::Monitor,
    );
    let rec3 = tracker.register_crown_jewel_artifact(
        k3,
        "src_3_crown.pem",
        b"Crown Jewel Root Key Gamma",
        ClassificationLattice::CrownJewel,
        PolicyLattice::Quarantine,
    );
    let rec4 = tracker.register_crown_jewel_artifact(
        k4,
        "src_4_conf.csv",
        b"Confidential User Accounts Delta",
        ClassificationLattice::Confidential,
        PolicyLattice::Quarantine,
    );
    let rec5 = tracker.register_crown_jewel_artifact(
        k5,
        "src_5_conf.json",
        b"Confidential API Keys Epsilon",
        ClassificationLattice::Confidential,
        PolicyLattice::Block,
    );

    let proc_key_a = ProcessInstanceKey::new(9100, 500_000_000);
    let out_key_a = ArtifactKey::new(100, 99);
    let zip_content_a = b"PK\x03\x04MOCK_ZIP_ARCHIVE_5_FILES";

    let merged_a = tracker.record_process_transform(
        proc_key_a,
        "7z.exe",
        "C:\\Tools\\7z.exe",
        &[k1, k2, k3, k4, k5],
        out_key_a,
        "C:\\staging\\archive_5.7z",
        zip_content_a,
        false,
    );

    // 1. Verify Strictest-Wins Lattice Dominance
    assert_eq!(
        merged_a.classification,
        ClassificationLattice::CrownJewel,
        "Strictest classification must be CrownJewel"
    );
    assert_eq!(
        merged_a.policy,
        PolicyLattice::Quarantine,
        "Strictest policy must be Quarantine"
    );
    assert!(merged_a.tainted, "Output must be marked tainted");

    // 2. Verify SpanLinks count: for 5 tainted inputs, exactly 4 secondary files linked
    assert_eq!(
        merged_a.linked_span_contexts.len(),
        4,
        "5 tainted files must produce exactly 4 SpanLinks"
    );

    // Verify secondary linked span contexts correspond to files 2..5
    let linked_span_ids: Vec<_> = merged_a
        .linked_span_contexts
        .iter()
        .map(|sc| sc.span_id())
        .collect();
    assert!(linked_span_ids.contains(&rec2.origin_span_context.span_id()));
    assert!(linked_span_ids.contains(&rec3.origin_span_context.span_id()));
    assert!(linked_span_ids.contains(&rec4.origin_span_context.span_id()));
    assert!(linked_span_ids.contains(&rec5.origin_span_context.span_id()));
    // File 1 is parent, NOT in secondary links
    assert!(!linked_span_ids.contains(&rec1.origin_span_context.span_id()));

    // 3. Verify Baggage propagation
    assert_eq!(
        merged_a.baggage.classification,
        ClassificationLattice::CrownJewel
    );
    assert_eq!(merged_a.baggage.policy, PolicyLattice::Quarantine);
    assert!(merged_a.baggage.tainted);
    assert_eq!(
        merged_a.baggage.source_sha256, rec3.sha256,
        "Dominant source SHA-256 must be from CrownJewel input (rec3)"
    );

    let header_a = merged_a.baggage.to_w3c_header();
    assert!(header_a.contains("dlp.classification=CROWN_JEWEL"));
    assert!(header_a.contains("dlp.policy=QUARANTINE"));
    assert!(header_a.contains("dlp.tainted=true"));

    // --- Scenario B: 7 Sources (6 Tainted, 1 Untainted) ---
    // Test that untainted files do not corrupt the link count or dominance.
    let k6 = ArtifactKey::new(100, 6);
    let k7 = ArtifactKey::new(100, 7);
    let rec6 = tracker.register_crown_jewel_artifact(
        k6,
        "src_6_crown2.pem",
        b"Crown Jewel Secondary Root Key Zeta",
        ClassificationLattice::CrownJewel,
        PolicyLattice::Quarantine,
    );
    // k7 is Public (untainted)
    let _rec7 = tracker.register_crown_jewel_artifact(
        k7,
        "src_7_public.txt",
        b"Public release notes Eta",
        ClassificationLattice::Public,
        PolicyLattice::Monitor,
    );

    let proc_key_b = ProcessInstanceKey::new(9200, 600_000_000);
    let out_key_b = ArtifactKey::new(100, 199);
    let tar_content_b = b"USTAR_ARCHIVE_7_FILES";

    let merged_b = tracker.record_process_transform(
        proc_key_b,
        "tar.exe",
        "C:\\Windows\\System32\\tar.exe",
        &[k1, k2, k3, k4, k5, k6, k7],
        out_key_b,
        "C:\\staging\\archive_7.tar",
        tar_content_b,
        false,
    );

    // 6 tainted files total -> 1 parent (k1) + 5 secondary links
    assert_eq!(
        merged_b.linked_span_contexts.len(),
        5,
        "6 tainted files must produce exactly 5 SpanLinks"
    );
    assert_eq!(merged_b.classification, ClassificationLattice::CrownJewel);
    assert_eq!(merged_b.policy, PolicyLattice::Quarantine);

    // --- Scenario C: Permutation Invariance (Order Reversal) ---
    // If we pass files in reverse order [k6, k5, k4, k3, k2, k1]:
    // First tainted file is k6 (CrownJewel).
    // Dominance must still yield CrownJewel + Quarantine.
    let proc_key_c = ProcessInstanceKey::new(9300, 700_000_000);
    let out_key_c = ArtifactKey::new(100, 299);
    let merged_c = tracker.record_process_transform(
        proc_key_c,
        "7z.exe",
        "C:\\Tools\\7z.exe",
        &[k6, k5, k4, k3, k2, k1],
        out_key_c,
        "C:\\staging\\archive_rev.7z",
        b"PK_REVERSED_ORDER",
        false,
    );

    assert_eq!(merged_c.classification, ClassificationLattice::CrownJewel);
    assert_eq!(merged_c.policy, PolicyLattice::Quarantine);
    assert_eq!(merged_c.linked_span_contexts.len(), 5);
    // In reversed order, k6 is parent, so k6 must NOT be in secondary links
    let rev_linked_ids: Vec<_> = merged_c
        .linked_span_contexts
        .iter()
        .map(|sc| sc.span_id())
        .collect();
    assert!(!rev_linked_ids.contains(&rec6.origin_span_context.span_id()));
    assert!(rev_linked_ids.contains(&rec1.origin_span_context.span_id()));
}

// ============================================================================
// 2. Complete Lattice Dominance Edge-Case Matrix
// ============================================================================

#[test]
fn test_adversarial_lattice_dominance_edge_case_matrix() {
    let all_classifications = [
        ClassificationLattice::Public,
        ClassificationLattice::Internal,
        ClassificationLattice::Confidential,
        ClassificationLattice::CrownJewel,
    ];

    let all_policies = [
        PolicyLattice::Monitor,
        PolicyLattice::Block,
        PolicyLattice::Quarantine,
    ];

    // 1. Algebraic Laws: ClassificationLattice Meet-Semilattice
    for &a in &all_classifications {
        // Idempotence: a.join(a) == a
        assert_eq!(a.join(a), a, "Classification join must be idempotent");

        // Identity with bottom element (Public)
        assert_eq!(
            a.join(ClassificationLattice::Public),
            a,
            "Public must be the identity for join"
        );

        // Dominance by top element (CrownJewel)
        assert_eq!(
            a.join(ClassificationLattice::CrownJewel),
            ClassificationLattice::CrownJewel,
            "CrownJewel must dominate any classification"
        );

        for &b in &all_classifications {
            // Commutativity: a.join(b) == b.join(a)
            assert_eq!(
                a.join(b),
                b.join(a),
                "Classification join must be commutative"
            );

            // Consistency with order
            if a <= b {
                assert_eq!(a.join(b), b, "If a <= b, join(a, b) must equal b");
            } else {
                assert_eq!(a.join(b), a, "If a > b, join(a, b) must equal a");
            }

            for &c in &all_classifications {
                // Associativity: (a.join(b)).join(c) == a.join(b.join(c))
                assert_eq!(
                    (a.join(b)).join(c),
                    a.join(b.join(c)),
                    "Classification join must be associative"
                );

                // Monotonicity: if a <= b, then a.join(c) <= b.join(c)
                if a <= b {
                    assert!(
                        a.join(c) <= b.join(c),
                        "Classification join must be monotonic"
                    );
                }
            }
        }
    }

    // 2. Algebraic Laws: PolicyLattice Meet-Semilattice
    for &p in &all_policies {
        // Idempotence
        assert_eq!(p.join(p), p, "Policy join must be idempotent");

        // Identity with bottom (Monitor)
        assert_eq!(
            p.join(PolicyLattice::Monitor),
            p,
            "Monitor must be identity for policy join"
        );

        // Dominance by top (Quarantine)
        assert_eq!(
            p.join(PolicyLattice::Quarantine),
            PolicyLattice::Quarantine,
            "Quarantine must dominate any policy"
        );

        for &q in &all_policies {
            // Commutativity
            assert_eq!(p.join(q), q.join(p), "Policy join must be commutative");

            if p <= q {
                assert_eq!(p.join(q), q);
            } else {
                assert_eq!(p.join(q), p);
            }

            for &r in &all_policies {
                // Associativity
                assert_eq!((p.join(q)).join(r), p.join(q.join(r)));

                // Monotonicity
                if p <= q {
                    assert!(p.join(r) <= q.join(r));
                }
            }
        }
    }

    // 3. Cross-Lattice Orthogonality in DlpBaggage
    // Case: Low classification + High policy joined with High classification + Low policy
    let bag_a = DlpBaggage::new(
        ClassificationLattice::Public,
        PolicyLattice::Quarantine,
        true,
        "sha_low_class_high_pol",
    );
    let bag_b = DlpBaggage::new(
        ClassificationLattice::CrownJewel,
        PolicyLattice::Monitor,
        true,
        "sha_high_class_low_pol",
    );

    let joined_ab = bag_a.join(&bag_b);
    assert_eq!(
        joined_ab.classification,
        ClassificationLattice::CrownJewel,
        "Joined baggage must elevate to highest classification (CrownJewel)"
    );
    assert_eq!(
        joined_ab.policy,
        PolicyLattice::Quarantine,
        "Joined baggage must elevate to strictest policy (Quarantine)"
    );
    assert!(joined_ab.tainted);
    assert_eq!(
        joined_ab.source_sha256, "sha_high_class_low_pol",
        "Higher classification source SHA must win"
    );

    // 4. Boundary String Parsing Resilience (No Panics)
    assert_eq!(
        ClassificationLattice::from_str_relaxed(""),
        ClassificationLattice::Public
    );
    assert_eq!(
        ClassificationLattice::from_str_relaxed("   "),
        ClassificationLattice::Public
    );
    assert_eq!(
        ClassificationLattice::from_str_relaxed("SECRET"),
        ClassificationLattice::CrownJewel
    );
    assert_eq!(
        ClassificationLattice::from_str_relaxed("RESTRICTED"),
        ClassificationLattice::Confidential
    );
    assert_eq!(
        ClassificationLattice::from_str_relaxed("WORKSPACE_CONFIG"),
        ClassificationLattice::Internal
    );
    assert_eq!(
        ClassificationLattice::from_str_relaxed("UNKNOWN_INJECTION_PAYLOAD'; DROP TABLE;--"),
        ClassificationLattice::Public
    );

    assert_eq!(PolicyLattice::from_str_relaxed(""), PolicyLattice::Monitor);
    assert_eq!(
        PolicyLattice::from_str_relaxed("QUARANTINE_ON_CROWN_JEWEL"),
        PolicyLattice::Quarantine
    );
    assert_eq!(
        PolicyLattice::from_str_relaxed("ENFORCE_BLOCK_AND_SCRUB"),
        PolicyLattice::Block
    );
    assert_eq!(
        PolicyLattice::from_str_relaxed("MALFORMED_POLICY"),
        PolicyLattice::Monitor
    );

    // 5. Corrupted W3C Header Parsing
    let corrupted_header = ",,,dlp.classification=CONFIDENTIAL,,dlp.policy=BLOCK,dlp.tainted=TRUE,unknown.key=val=extra,,,";
    let parsed_bag = DlpBaggage::from_w3c_header(corrupted_header);
    assert_eq!(
        parsed_bag.classification,
        ClassificationLattice::Confidential
    );
    assert_eq!(parsed_bag.policy, PolicyLattice::Block);
    assert!(parsed_bag.tainted);
}

// ============================================================================
// 3. PID Reuse Temporal Collision Immunity Adversarial Stress Test
// ============================================================================

#[test]
fn test_adversarial_pid_reuse_temporal_collision_immunity() {
    let tracker = DlpLineageTracker::new(10); // 10s TTL

    let secret_key = ArtifactKey::new(50, 1001);
    tracker.register_crown_jewel_artifact(
        secret_key,
        "crown_secret.key",
        b"CROWN_SECRET_KEY_MATERIAL",
        ClassificationLattice::CrownJewel,
        PolicyLattice::Quarantine,
    );

    let conf_key = ArtifactKey::new(50, 2002);
    tracker.register_crown_jewel_artifact(
        conf_key,
        "confidential_doc.pdf",
        b"CONFIDENTIAL_PDF_DOC",
        ClassificationLattice::Confidential,
        PolicyLattice::Block,
    );

    let recycled_pid = 7890u32;

    // Simulate 6 sequential generations of the SAME recycled PID:
    // Gen 0: start_time = 100_000. Clean process. Never touches sensitive files.
    let g0_key = ProcessInstanceKey::new(recycled_pid, 100_000);
    assert_eq!(
        tracker.check_process_egress_blocking(&g0_key),
        EgressDecision::Allowed,
        "Gen 0 must be allowed"
    );

    // Gen 1: start_time = 200_000. Reads Crown Jewel. Must be quarantined.
    let g1_key = ProcessInstanceKey::new(recycled_pid, 200_000);
    tracker.on_file_read(g1_key, "cmd.exe", "C:\\Windows\\cmd.exe", secret_key);
    assert!(matches!(
        tracker.check_process_egress_blocking(&g1_key),
        EgressDecision::Blocked {
            policy: PolicyLattice::Quarantine,
            classification: ClassificationLattice::CrownJewel,
            ..
        }
    ));

    // Gen 2: start_time = 300_000. New process instance with same PID.
    // Must NOT inherit Gen 1's taint!
    let g2_key = ProcessInstanceKey::new(recycled_pid, 300_000);
    assert_eq!(
        tracker.check_process_egress_blocking(&g2_key),
        EgressDecision::Allowed,
        "Gen 2 must NOT inherit taint from Gen 1 with identical PID"
    );

    // Gen 2 writes a file -> must be excluded (untainted proc)
    let g2_out = ArtifactKey::new(50, 3003);
    let decision_g2 = tracker.on_file_write(
        &g2_key,
        &g2_out,
        "C:\\temp\\gen2.log",
        Some(b"Gen 2 benign log entry"),
        Utc::now(),
    );
    assert!(matches!(
        decision_g2,
        FileWriteTaintDecision::BenignExcluded { .. }
    ));
    assert_eq!(
        tracker.check_egress_blocking(&g2_out),
        EgressDecision::Allowed
    );

    // Gen 3: start_time = 400_000. Reads Confidential file. Must be blocked (not quarantined).
    let g3_key = ProcessInstanceKey::new(recycled_pid, 400_000);
    tracker.on_file_read(g3_key, "python.exe", "C:\\Python\\python.exe", conf_key);
    assert!(matches!(
        tracker.check_process_egress_blocking(&g3_key),
        EgressDecision::Blocked {
            policy: PolicyLattice::Block,
            classification: ClassificationLattice::Confidential,
            ..
        }
    ));

    // Gen 4: start_time = 500_000. Clean process. Must be allowed.
    let g4_key = ProcessInstanceKey::new(recycled_pid, 500_000);
    assert_eq!(
        tracker.check_process_egress_blocking(&g4_key),
        EgressDecision::Allowed,
        "Gen 4 must be completely untainted"
    );

    // Verify Gen 1 is STILL quarantined, Gen 3 is STILL blocked, Gen 0/2/4 are STILL allowed!
    assert!(matches!(
        tracker.check_process_egress_blocking(&g1_key),
        EgressDecision::Blocked {
            policy: PolicyLattice::Quarantine,
            ..
        }
    ));
    assert!(matches!(
        tracker.check_process_egress_blocking(&g3_key),
        EgressDecision::Blocked {
            policy: PolicyLattice::Block,
            ..
        }
    ));
    assert_eq!(
        tracker.check_process_egress_blocking(&g0_key),
        EgressDecision::Allowed
    );
    assert_eq!(
        tracker.check_process_egress_blocking(&g2_key),
        EgressDecision::Allowed
    );
    assert_eq!(
        tracker.check_process_egress_blocking(&g4_key),
        EgressDecision::Allowed
    );

    // --- High-Churn Stress Test: 500 Recycled PIDs ---
    let churn_pid = 4444u32;
    for epoch in 1..=500 {
        let churn_key = ProcessInstanceKey::new(churn_pid, epoch * 1_000);
        if epoch % 50 == 0 {
            // Every 50th epoch touches Crown Jewel
            tracker.on_file_read(churn_key, "worker.exe", "C:\\worker.exe", secret_key);
            assert!(matches!(
                tracker.check_process_egress_blocking(&churn_key),
                EgressDecision::Blocked {
                    policy: PolicyLattice::Quarantine,
                    ..
                }
            ));
        } else {
            // All other epochs are clean
            assert_eq!(
                tracker.check_process_egress_blocking(&churn_key),
                EgressDecision::Allowed,
                "Epoch {} must be untainted",
                epoch
            );
        }
    }
}

// ============================================================================
// 4. Multi-Threaded Concurrency Stress & DashMap Lock Hygiene
// ============================================================================

#[test]
fn test_adversarial_concurrency_and_dashmap_lock_hygiene() {
    let tracker = Arc::new(DlpLineageTracker::new(20));

    // Seed initial Crown Jewel
    let root_secret = ArtifactKey::new(1, 9999);
    tracker.register_crown_jewel_artifact(
        root_secret,
        "root_vault.pem",
        b"ROOT_VAULT_CERT_SECRET",
        ClassificationLattice::CrownJewel,
        PolicyLattice::Quarantine,
    );

    let num_threads = 12;
    let iterations_per_thread = 50;
    let mut handles = Vec::with_capacity(num_threads);

    for t_idx in 0..num_threads {
        let t_tracker = Arc::clone(&tracker);
        let handle = thread::spawn(move || {
            for iter in 0..iterations_per_thread {
                let pid = (t_idx * 1000 + iter) as u32;
                let start_time = (iter * 1_000_000 + 1) as u64;
                let proc_key = ProcessInstanceKey::new(pid, start_time);

                // Register thread-local artifact
                let art_key = ArtifactKey::new((t_idx + 10) as u64, (iter + 1) as u64);
                let content = format!("THREAD_{}_ITER_{}_DATA", t_idx, iter).into_bytes();

                t_tracker.register_crown_jewel_artifact(
                    art_key,
                    &format!("t_{}_file_{}.dat", t_idx, iter),
                    &content,
                    ClassificationLattice::Confidential,
                    PolicyLattice::Block,
                );

                // Read artifact
                t_tracker.on_file_read(proc_key, "worker.exe", "C:\\worker.exe", art_key);

                // Verify egress blocked
                let egress = t_tracker.check_process_egress_blocking(&proc_key);
                assert!(matches!(egress, EgressDecision::Blocked { .. }));

                // Multi-file transform
                let out_key = ArtifactKey::new((t_idx + 10) as u64, (iter + 5000) as u64);
                let out_rec = t_tracker.record_process_transform(
                    proc_key,
                    "worker.exe",
                    "C:\\worker.exe",
                    &[art_key, root_secret],
                    out_key,
                    &format!("out_{}_{}.zip", t_idx, iter),
                    &content,
                    false,
                );

                assert_eq!(out_rec.classification, ClassificationLattice::CrownJewel);
                assert_eq!(out_rec.policy, PolicyLattice::Quarantine);

                // Inode rehydration probe
                let new_inode_key = ArtifactKey::new(999, (t_idx * 10000 + iter) as u64);
                let rehydrated = t_tracker.rehydrate_artifact_if_unknown(
                    &new_inode_key,
                    "E:\\recovered.dat",
                    &content,
                );
                assert!(rehydrated.is_some());
            }
        });
        handles.push(handle);
    }

    // Wait for all threads to finish without deadlock
    for h in handles {
        h.join()
            .expect("Thread panicked during concurrency stress test");
    }

    assert!(tracker.active_artifacts.len() > 100);
    assert!(tracker.active_processes.len() > 100);
}

// ============================================================================
// 5. ssdeep Fuzzy Hashing & Zero-Similarity Edge Cases
// ============================================================================

#[test]
fn test_adversarial_ssdeep_edge_cases() {
    // 1. Empty data
    let empty_ssdeep = compute_ssdeep(b"");
    assert_eq!(empty_ssdeep, "3::");
    assert_eq!(compare_ssdeep(&empty_ssdeep, &empty_ssdeep), 0);

    // 2. Identical long inputs
    let text_a =
        b"The quick brown fox jumps over the lazy dog repeatedly to generate block boundaries";
    let h_a = compute_ssdeep(text_a);
    assert_eq!(compare_ssdeep(&h_a, &h_a), 100);

    // 3. Minor modification (high similarity)
    let mut text_b = text_a.to_vec();
    text_b.extend_from_slice(b" with slight appendix appended");
    let h_b = compute_ssdeep(&text_b);
    let sim_ab = compare_ssdeep(&h_a, &h_b);
    assert!(
        sim_ab >= 30,
        "Minor change should yield high similarity, got {}",
        sim_ab
    );

    // 4. Completely unrelated inputs
    let text_c = b"\x00\xff\xfe\xfd\xfc\xfb\xfa\x01\x02\x03\x04\x05\x06\x07";
    let h_c = compute_ssdeep(text_c);
    let sim_ac = compare_ssdeep(&h_a, &h_c);
    assert_eq!(sim_ac, 0, "Unrelated input must have 0% similarity");

    // 5. Corrupted ssdeep strings
    assert_eq!(compare_ssdeep("invalid", "3:a:b"), 0);
    assert_eq!(compare_ssdeep("not_a_number:a:b", "3:a:b"), 0);
    assert_eq!(compare_ssdeep("0:a:b", "3:a:b"), 0);
    assert_eq!(compare_ssdeep(":::", ":::"), 0);
}
