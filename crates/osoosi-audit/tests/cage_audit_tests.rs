//! Unit and Integration Tests for RFC 8785 JCS, CAGE Audit Records, and Merkle Anchoring

use osoosi_audit::{
    canonicalize_jcs, compute_canonical_hash, verify_trace_chain, CageTraceRecord, MerkleAuditTree,
    AUDIT_SCHEMA_VERSION, EVENT_ACTUATION_RECEIPT, EVENT_CBF_COMMIT, EVENT_CBF_ROLLBACK,
    EVENT_GOVERNANCE_DECISION, EVENT_GOVERNANCE_REFUSAL, EVENT_GOVERNANCE_SEAL_CONSUMED,
    GENESIS_PREV_HASH,
};
use serde_json::json;

// =============================================================================
// 1. RFC 8785 JSON Canonicalization Scheme (JCS) Tests
// =============================================================================

#[test]
fn test_jcs_utf16_key_sorting() {
    // RFC 8785 §3.2.3: Keys sorted lexicographically by UTF-16 code units.
    // 'B' (0x42) < 'a' (0x61) < 'm' (0x6D) < 'z' (0x7A)
    let val = json!({
        "z": 1,
        "a": 2,
        "m": 3,
        "B": 4
    });
    let canonical = canonicalize_jcs(&val).expect("Canonicalization must succeed");
    assert_eq!(canonical, r#"{"B":4,"a":2,"m":3,"z":1}"#);

    // Multibyte and unicode keys
    let unicode_val = json!({
        "\u{00E9}": "e-acute",
        "e": "latin-e",
        "\u{0100}": "A-macron",
        "\u{FF41}": "fullwidth-a"
    });
    let c_unicode = canonicalize_jcs(&unicode_val).expect("Unicode key sorting");
    // 'e' (0x0065) < '\u00e9' (0x00E9) < '\u0100' (0x0100) < '\uff41' (0xFF41)
    assert_eq!(
        c_unicode,
        r#"{"e":"latin-e","\u00e9":"e-acute","\u0100":"A-macron","\uff41":"fullwidth-a"}"#
            .replace("\\u00e9", "\u{00E9}")
            .replace("\\u0100", "\u{0100}")
            .replace("\\uff41", "\u{FF41}")
    );
}

#[test]
fn test_jcs_number_formatting() {
    // Integers vs floats with integer values
    let val_int = json!({"val": 42});
    let val_float = json!({"val": 42.0});
    assert_eq!(canonicalize_jcs(&val_int).unwrap(), r#"{"val":42}"#);
    assert_eq!(canonicalize_jcs(&val_float).unwrap(), r#"{"val":42}"#);

    // Negative numbers
    let neg_int = json!({"val": -100});
    let neg_float = json!({"val": -100.0});
    assert_eq!(canonicalize_jcs(&neg_int).unwrap(), r#"{"val":-100}"#);
    assert_eq!(canonicalize_jcs(&neg_float).unwrap(), r#"{"val":-100}"#);

    // Zero and negative zero
    let zeros = json!({"zero": 0.0, "neg_zero": -0.0});
    assert_eq!(
        canonicalize_jcs(&zeros).unwrap(),
        r#"{"neg_zero":0,"zero":0}"#
    );

    // Safe integer boundaries (2^53 - 1)
    let safe_limits = json!({
        "max": 9007199254740991.0,
        "min": -9007199254740991.0
    });
    assert_eq!(
        canonicalize_jcs(&safe_limits).unwrap(),
        r#"{"max":9007199254740991,"min":-9007199254740991}"#
    );

    // Floats with decimals
    let dec_val = json!({"val": 123.456});
    assert_eq!(canonicalize_jcs(&dec_val).unwrap(), r#"{"val":123.456}"#);

    // Exponential notation without '+'
    let exp_val = json!({"large": 1e20});
    let c_exp = canonicalize_jcs(&exp_val).unwrap();
    assert!(!c_exp.contains("e+"));
}

#[test]
fn test_jcs_string_escaping() {
    // Minimal escaping: quotes, backslashes, control characters < 0x20
    let str_val = json!({
        "msg": "Hello\nWorld\t\"Quotes\"\\Backslash\rReturn\u{0008}Backspace\u{000c}Formfeed"
    });
    let expected = r#"{"msg":"Hello\nWorld\t\"Quotes\"\\Backslash\rReturn\bBackspace\fFormfeed"}"#;
    assert_eq!(canonicalize_jcs(&str_val).unwrap(), expected);

    // Slash '/' MUST NOT be escaped
    let slash_val = json!({"url": "https://example.com/api/v1/resource"});
    assert_eq!(
        canonicalize_jcs(&slash_val).unwrap(),
        r#"{"url":"https://example.com/api/v1/resource"}"#
    );

    // Control characters < 0x20 without special shorthands (e.g. U+0000, U+001F)
    let ctrl_val = json!({"null_byte": "\u{0000}", "unit_sep": "\u{001f}"});
    assert_eq!(
        canonicalize_jcs(&ctrl_val).unwrap(),
        r#"{"null_byte":"\u0000","unit_sep":"\u001f"}"#
    );

    // UTF-8 characters and emojis are NOT escaped
    let emoji_val = json!({"symbol": "🛡️", "greek": "αβγ"});
    let c_emoji = canonicalize_jcs(&emoji_val).unwrap();
    assert_eq!(c_emoji, r#"{"greek":"αβγ","symbol":"🛡️"}"#);
}

#[test]
fn test_jcs_whitespace_elimination() {
    let complex_val = json!({
        "nested": {
            "arr": [1, 2, {"inner": true}, null],
            "flag": false
        }
    });
    assert_eq!(
        canonicalize_jcs(&complex_val).unwrap(),
        r#"{"nested":{"arr":[1,2,{"inner":true},null],"flag":false}}"#
    );
}

// =============================================================================
// 2. Canonical Digest Determinism Tests
// =============================================================================

#[test]
fn test_canonical_hash_determinism_under_key_permutation() {
    let obj_a = json!({
        "alpha": 1,
        "beta": [2, 3],
        "gamma": {"delta": "test"}
    });
    let obj_b = json!({
        "gamma": {"delta": "test"},
        "alpha": 1,
        "beta": [2, 3]
    });

    let hash_a = compute_canonical_hash(&obj_a);
    let hash_b = compute_canonical_hash(&obj_b);

    assert_eq!(hash_a, hash_b);
    assert_eq!(hash_a.len(), 64);
    assert!(hash_a
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
}

#[test]
fn test_canonical_hash_divergence_on_semantic_difference() {
    let obj_1 = json!({"action": "execute_tool", "fuel": 10.0});
    let obj_2 = json!({"action": "execute_tool", "fuel": 10.1});

    let h1 = compute_canonical_hash(&obj_1);
    let h2 = compute_canonical_hash(&obj_2);

    assert_ne!(h1, h2);
}

// =============================================================================
// 3. Merkle Audit Tree Tests
// =============================================================================

#[test]
fn test_merkle_audit_tree_empty_and_single_leaf() {
    let empty_root = MerkleAuditTree::compute_root(&[]);
    assert_eq!(empty_root, "0".repeat(64));

    let leaf = compute_canonical_hash(&json!({"event": "INIT"}));
    let single_root = MerkleAuditTree::compute_root(std::slice::from_ref(&leaf));
    assert_eq!(single_root, leaf);
}

#[test]
fn test_merkle_audit_tree_log_cage_governance_trace() {
    let tree = MerkleAuditTree::new();
    let trace1 = json!({
        "action_name": "ReadSecret",
        "verdict": "ALLOW",
        "cbf_h_value": 45.0,
        "fuel_consumed": 2.5
    });

    let (leaf1, root1) = tree.log_cage_governance_trace(&trace1);
    assert_eq!(leaf1, compute_canonical_hash(&trace1));
    assert_eq!(root1, leaf1); // For single leaf, root equals leaf

    let trace2 = json!({
        "action_name": "WriteFile",
        "verdict": "DENY",
        "cbf_h_value": 0.0,
        "fuel_consumed": 0.0
    });

    let (leaf2, root2) = tree.log_cage_governance_trace(&trace2);
    assert_eq!(leaf2, compute_canonical_hash(&trace2));
    assert_ne!(root2, root1);
    assert_eq!(root2.len(), 64);
}

// =============================================================================
// 4. CAGE Audit Hash Chaining and Tamper Detection
// =============================================================================

#[test]
fn test_cage_trace_record_hash_chaining() {
    let tree = MerkleAuditTree::new();

    // Genesis record (sequence 0)
    let payload0 = json!({"init": true, "actor": "system"});
    let mut rec0 = CageTraceRecord::new(
        "trace-0",
        0,
        GENESIS_PREV_HASH,
        "InitializeSystem",
        "ALLOW",
        Some(100.0),
        Some(0.0),
        "pol-v1-abcdef01",
        "",
        "",
        payload0.clone(),
        "2026-11-02T00:00:00Z",
    );
    let leaf0 = rec0.compute_canonical_leaf_hash();
    let (_, root0) = tree.log_cage_governance_trace(&payload0);
    rec0.merkle_leaf_hash = leaf0.clone();
    rec0.merkle_root = root0;

    // Second record (sequence 1) binding to rec0's leaf hash
    let payload1 = json!({"tool": "ReadConfig", "cost": 1.0});
    let mut rec1 = CageTraceRecord::new(
        "trace-1",
        1,
        &leaf0,
        "ReadConfig",
        "ALLOW",
        Some(99.0),
        Some(1.0),
        "pol-v1-abcdef01",
        "",
        "",
        payload1.clone(),
        "2026-11-02T00:00:05Z",
    );
    let leaf1 = rec1.compute_canonical_leaf_hash();
    let (_, root1) = tree.log_cage_governance_trace(&payload1);
    rec1.merkle_leaf_hash = leaf1.clone();
    rec1.merkle_root = root1;

    // Third record (sequence 2) binding to rec1's leaf hash
    let payload2 = json!({"tool": "ModifyPolicy", "cost": 0.0});
    let mut rec2 = CageTraceRecord::new(
        "trace-2",
        2,
        &leaf1,
        "ModifyPolicy",
        "DENY",
        Some(99.0),
        Some(0.0),
        "pol-v1-abcdef01",
        "",
        "",
        payload2.clone(),
        "2026-11-02T00:00:10Z",
    );
    let leaf2 = rec2.compute_canonical_leaf_hash();
    let (_, root2) = tree.log_cage_governance_trace(&payload2);
    rec2.merkle_leaf_hash = leaf2;
    rec2.merkle_root = root2;

    let chain = vec![rec0.clone(), rec1.clone(), rec2.clone()];
    assert!(verify_trace_chain(&chain).is_ok());

    // Tamper Test 1: Modifying payload in rec1 breaks leaf hash
    let mut tampered_rec1 = rec1.clone();
    tampered_rec1.payload = json!({"tool": "ReadConfig", "cost": 999.0});
    let tampered_chain1 = vec![rec0.clone(), tampered_rec1, rec2.clone()];
    let res1 = verify_trace_chain(&tampered_chain1);
    assert!(res1.is_err());
    assert!(res1.unwrap_err().contains("Tampered leaf hash"));

    // Tamper Test 2: Breaking the prev_hash link
    let mut tampered_rec2 = rec2.clone();
    tampered_rec2.prev_hash = "f".repeat(64);
    tampered_rec2.merkle_leaf_hash = tampered_rec2.compute_canonical_leaf_hash();
    let tampered_chain2 = vec![rec0.clone(), rec1.clone(), tampered_rec2];
    let res2 = verify_trace_chain(&tampered_chain2);
    assert!(res2.is_err());
    assert!(res2.unwrap_err().contains("Chain break"));

    // Tamper Test 3: Sequence discontinuity
    let mut skipped_seq_rec2 = rec2.clone();
    skipped_seq_rec2.sequence_number = 3;
    let tampered_chain3 = vec![rec0, rec1, skipped_seq_rec2];
    let res3 = verify_trace_chain(&tampered_chain3);
    assert!(res3.is_err());
    assert!(res3.unwrap_err().contains("Sequence discontinuity"));
}

#[test]
fn test_cage_audit_constants_and_schema_version() {
    assert_eq!(AUDIT_SCHEMA_VERSION, "cage-audit/3.0");
    assert_eq!(GENESIS_PREV_HASH.len(), 64);
    assert_eq!(EVENT_GOVERNANCE_DECISION, "GOVERNANCE_DECISION");
    assert_eq!(EVENT_GOVERNANCE_SEAL_CONSUMED, "GOVERNANCE_SEAL_CONSUMED");
    assert_eq!(EVENT_CBF_COMMIT, "CBF_COMMIT");
    assert_eq!(EVENT_CBF_ROLLBACK, "CBF_ROLLBACK");
    assert_eq!(EVENT_GOVERNANCE_REFUSAL, "GOVERNANCE_REFUSAL");
    assert_eq!(EVENT_ACTUATION_RECEIPT, "ACTUATION_RECEIPT");
}
