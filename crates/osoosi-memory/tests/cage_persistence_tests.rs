//! Integration tests for CAGE Governance persistence in MemoryStore (Milestone M5).

use osoosi_audit::MerkleAuditTree;
use osoosi_memory::MemoryStore;
use osoosi_types::cage::RoutingSeal;
use serde_json::json;

#[test]
fn test_cage_policy_storage_and_retrieval() {
    let mem = MemoryStore::new(":memory:").expect("Create in-memory SQLite store");

    let version_id = "abcd1234ef567890";
    let format = "MicrosoftAcs";
    let raw = r#"{"behaviorDeclarations":[{"id":"ACS-1","action":"RunTool"}]}"#;
    let cedar = r#"["permit (principal, action == Action::\"RunTool\", resource);"]"#;
    let ucas = r#"[{"id":"UCA-1","action":"RunTool"}]"#;
    let gamma = 0.5;
    let b_min = 10.0;

    // Store policy
    mem.store_cage_policy(version_id, format, raw, cedar, ucas, gamma, b_min)
        .expect("Store policy must succeed");

    // Retrieve by version ID
    let retrieved = mem
        .get_cage_policy(version_id)
        .expect("Query policy must succeed")
        .expect("Policy must be present");

    assert_eq!(retrieved["policy_version_id"], version_id);
    assert_eq!(retrieved["format"], format);
    assert_eq!(retrieved["raw_content"], raw);
    assert_eq!(retrieved["cbf_gamma"], gamma);
    assert_eq!(retrieved["cbf_b_min"], b_min);

    // Retrieve latest
    let latest = mem
        .get_latest_cage_policy()
        .expect("Query latest policy must succeed")
        .expect("Latest policy must be present");
    assert_eq!(latest["policy_version_id"], version_id);

    // Query non-existent policy
    let missing = mem
        .get_cage_policy("nonexistent12345")
        .expect("Query missing must not fail");
    assert!(missing.is_none());
}

#[test]
fn test_cage_routing_seal_lifecycle_and_single_use() {
    let mem = MemoryStore::new(":memory:").expect("Create in-memory SQLite store");

    let seal = RoutingSeal {
        seal_id: "seal-uuid-1234-5678".to_string(),
        policy_version_id: "1234567890abcdef".to_string(),
        action_digest: "a".repeat(64),
        issued_at: 1700000000,
        expires_at: 1700000030,
        signature: "sig-hmac-sha256-hex".to_string(),
    };

    // 1. Record seal as ACTIVE
    mem.record_cage_routing_seal(&seal, "ACTIVE")
        .expect("Record seal must succeed");

    // 2. Retrieve seal and verify fields
    let retrieved = mem
        .get_cage_routing_seal(&seal.seal_id)
        .expect("Query seal must succeed")
        .expect("Seal must exist");
    assert_eq!(retrieved.seal_id, seal.seal_id);
    assert_eq!(retrieved.policy_version_id, seal.policy_version_id);
    assert_eq!(retrieved.action_digest, seal.action_digest);
    assert_eq!(retrieved.issued_at, seal.issued_at);
    assert_eq!(retrieved.expires_at, seal.expires_at);
    assert_eq!(retrieved.signature, seal.signature);

    // 3. First consumption must succeed (return true)
    let consumed_at = 1700000010;
    let ok = mem
        .mark_cage_routing_seal_consumed(&seal.seal_id, consumed_at)
        .expect("Consume seal must succeed");
    assert!(ok, "First consumption of active seal must return true");

    // 4. Second consumption must be rejected (return false)
    let replay = mem
        .mark_cage_routing_seal_consumed(&seal.seal_id, consumed_at + 1)
        .expect("Replay query must succeed");
    assert!(
        !replay,
        "Second consumption of seal must return false (replay blocked)"
    );

    // 5. Non-existent seal consumption returns false
    let fake_consumed = mem
        .mark_cage_routing_seal_consumed("non-existent-seal-id", consumed_at)
        .expect("Query non-existent must succeed");
    assert!(!fake_consumed);
}

#[test]
fn test_cage_governance_traces_persistence_and_chain_verification() {
    let mem = MemoryStore::new(":memory:").expect("Create in-memory SQLite store");
    let tree = MerkleAuditTree::new();

    let genesis_prev = "0".repeat(64);

    // Trace 0 (Genesis)
    let p0 = json!({"event": "INIT", "user": "alice"});
    let (leaf0, root0) = tree.log_cage_governance_trace(&p0);
    mem.append_cage_governance_trace(
        "trace-0",
        0,
        &genesis_prev,
        "SystemInit",
        "ALLOW",
        Some(100.0),
        Some(0.0),
        "pol-v1",
        &leaf0,
        &root0,
        &p0.to_string(),
    )
    .expect("Append trace 0 must succeed");

    // Trace 1
    let p1 = json!({"event": "ACTION", "tool": "QueryData", "fuel": 2.5});
    let (leaf1, root1) = tree.log_cage_governance_trace(&p1);
    mem.append_cage_governance_trace(
        "trace-1",
        1,
        &leaf0,
        "QueryData",
        "ALLOW",
        Some(97.5),
        Some(2.5),
        "pol-v1",
        &leaf1,
        &root1,
        &p1.to_string(),
    )
    .expect("Append trace 1 must succeed");

    // Trace 2
    let p2 = json!({"event": "REFUSAL", "reason": "CBF boundary violation"});
    let (leaf2, root2) = tree.log_cage_governance_trace(&p2);
    mem.append_cage_governance_trace(
        "trace-2",
        2,
        &leaf1,
        "DeleteAll",
        "DENY",
        Some(0.0),
        Some(0.0),
        "pol-v1",
        &leaf2,
        &root2,
        &p2.to_string(),
    )
    .expect("Append trace 2 must succeed");

    // Retrieve traces
    let traces = mem
        .get_cage_governance_traces(10)
        .expect("Query traces must succeed");
    assert_eq!(traces.len(), 3);
    assert_eq!(traces[0]["trace_id"], "trace-0");
    assert_eq!(traces[1]["trace_id"], "trace-1");
    assert_eq!(traces[2]["trace_id"], "trace-2");

    // Verify cryptographic chain
    let is_valid = mem
        .verify_cage_trace_chain()
        .expect("Chain verification must succeed");
    assert!(is_valid, "Untampered chain must verify successfully");

    // Tamper test: append trace with broken prev_hash
    let bad_prev = "f".repeat(64);
    let p3 = json!({"event": "TAMPERED"});
    let (leaf3, root3) = tree.log_cage_governance_trace(&p3);
    mem.append_cage_governance_trace(
        "trace-3",
        3,
        &bad_prev,
        "TamperedAction",
        "DENY",
        None,
        None,
        "pol-v1",
        &leaf3,
        &root3,
        &p3.to_string(),
    )
    .expect("Append trace 3 must succeed");

    let is_tampered_valid = mem
        .verify_cage_trace_chain()
        .expect("Chain verification query must succeed");
    assert!(
        !is_tampered_valid,
        "Tampered chain must fail cryptographic verification"
    );
}
