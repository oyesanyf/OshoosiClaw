//! Empirical Adversarial Security & Boundary Enforcement Test Suite for HostCapabilityGate
//!
//! Adversarially challenges:
//! 1. Subsecond and boundary TTL expiration testing:
//!    - Exact boundary t = issued_at + 30s
//!    - Expired at t = issued_at + 31s
//!    - Subsecond elapsed t = issued_at + 30.001s (discrete second ceiling / fractional)
//!    - Real-time wallclock subsecond sleep expiration
//!    - Distant future t = issued_at + 1000s
//!    - Negative / inverted TTL timestamps (issued_at > expires_at)
//! 2. Action digest tampering & canonicalization attacks:
//!    - 1-byte payload tampering across types (number, string, bool, array, extra/missing keys)
//!    - Action name mutations (case, whitespace, null bytes, homoglyphs)
//!    - Canonical JCS key reordering on deeply nested structures
//!    - Unicode accents, emojis, CJK, and RFC 8785 control character escaping
//!    - Array element order preservation (permutations must alter digest)
//! 3. Cryptographic signature forgery attacks:
//!    - 1-byte bit flips across multiple byte positions in HMAC signature
//!    - Signature truncation (32 chars, 63 chars, 1 char) and extension (65 chars, 128 chars)
//!    - Cross-seal, cross-action, cross-policy, and cross-timestamp signature reuse
//!    - Unconfigured rogue key signatures against default and custom gates
//! 4. Unsealed actuation and bypass attempts:
//!    - dispatch_request_with_seal with None seal (NoDirectBind violation)
//!    - dispatch_request_with_seal with empty seal_id, tampered params, expired seal, forged signature
//!    - Immediate fail-closed without network dispatch
//!    - Replay detection on already-consumed seal
//!    - Unconsumed invariance on failed verification
//!    - 50-thread concurrent race condition (strictly 1 winner, 49 rejected)

use osoosi_sandbox::host_capability_gate::{
    canonicalize_jcs, compute_action_digest, sign_routing_seal, GateError, HostCapabilityGate,
    DEFAULT_CAGE_SUBSTRATE_SECRET,
};
use osoosi_types::cage::RoutingSeal;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Helper to construct a signed routing seal.
fn create_test_seal(
    secret: &[u8],
    seal_id: &str,
    action_name: &str,
    params: &serde_json::Value,
    policy_version_id: &str,
    issued_at: u64,
    ttl_seconds: u64,
) -> RoutingSeal {
    let action_digest = compute_action_digest(action_name, params);
    let signature = sign_routing_seal(
        secret,
        seal_id,
        &action_digest,
        policy_version_id,
        issued_at,
    );
    RoutingSeal {
        seal_id: seal_id.to_string(),
        policy_version_id: policy_version_id.to_string(),
        action_digest,
        issued_at,
        expires_at: issued_at + ttl_seconds,
        signature,
    }
}

// ============================================================================
// CATEGORY 1: Subsecond and Boundary TTL Expiration Testing
// ============================================================================

#[test]
fn test_ttl_boundary_exact_30s_consumed_with_zero_ttl_remaining() {
    let gate = HostCapabilityGate::default();
    let params = json!({"command": "list_files", "path": "/var/log"});
    let issued_at = 1_700_000_000;
    let seal = create_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_boundary_exact_30s",
        "ListFiles",
        &params,
        "1122334455667788",
        issued_at,
        30,
    );

    // Exact boundary: t = issued_at + 30s. now == expires_at.
    // Invariant: now > expires_at is FALSE, so seal is valid.
    let receipt = gate
        .validate_and_consume_seal(&seal, "ListFiles", &params, Some(issued_at + 30))
        .expect("Seal at exact 30s boundary must be valid and consumed");

    assert_eq!(receipt.status, "CONSUMED");
    assert_eq!(receipt.seal_id, "seal_boundary_exact_30s");
    assert_eq!(receipt.consumed_at_utc, issued_at + 30);
    assert_eq!(
        receipt.ttl_remaining_seconds, 0,
        "Remaining TTL at exact boundary must be 0"
    );
    assert!(gate.is_seal_consumed("seal_boundary_exact_30s"));
}

#[test]
fn test_ttl_boundary_plus_31s_rejected_as_expired() {
    let gate = HostCapabilityGate::default();
    let params = json!({"command": "delete_entry", "id": 99});
    let issued_at = 1_700_000_000;
    let seal = create_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_boundary_31s_expired",
        "DeleteEntry",
        &params,
        "aabbccddeeff0011",
        issued_at,
        30,
    );

    // t = issued_at + 31s (strictly past 30s TTL window)
    let outcome =
        gate.validate_and_consume_seal(&seal, "DeleteEntry", &params, Some(issued_at + 31));

    match outcome {
        Err(GateError::SealRejection(msg)) => {
            assert!(
                msg.contains("expired"),
                "Error message must specify expiration, got: {}",
                msg
            );
            assert!(msg.contains("1700000031"));
            assert!(msg.contains("1700000030"));
        }
        other => panic!(
            "Expected GateError::SealRejection for 31s expiration, got: {:?}",
            other
        ),
    }

    // Expired seal must NOT be marked consumed
    assert!(!gate.is_seal_consumed("seal_boundary_31s_expired"));
    assert_eq!(gate.consumed_seals_count(), 0);
}

#[test]
fn test_ttl_subsecond_30_001s_discrete_ceiling_and_fractional_expiration() {
    let gate = HostCapabilityGate::default();
    let params = json!({"target": "worker_pool"});
    let issued_at = 1_700_000_000;
    let seal = create_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_subsecond_30_001",
        "ScalePool",
        &params,
        "deadbeef12345678",
        issued_at,
        30,
    );

    // Elapsed wall-clock time: 30.001s.
    // In discrete seconds, any time past 30.000s rounds up to the next second boundary (ceil: 31s).
    let elapsed_float: f64 = 30.001;
    let ceiling_second = (issued_at as f64 + elapsed_float).ceil() as u64; // 1_700_000_031
    assert_eq!(ceiling_second, issued_at + 31);

    let ceiling_res =
        gate.validate_and_consume_seal(&seal, "ScalePool", &params, Some(ceiling_second));
    assert!(
        matches!(ceiling_res, Err(GateError::SealRejection(ref msg)) if msg.contains("expired")),
        "Ceiling evaluation of 30.001s elapsed must reject as expired"
    );

    // Boundary at t = 29s (1 second before expiration) must succeed
    let receipt_29 = gate
        .validate_and_consume_seal(&seal, "ScalePool", &params, Some(issued_at + 29))
        .expect("t = 29s must be valid");
    assert_eq!(receipt_29.ttl_remaining_seconds, 1);
}

#[tokio::test]
async fn test_ttl_subsecond_realtime_wallclock_sleep_expiration() {
    let gate = HostCapabilityGate::default();
    let params = json!({"op": "sync_clock"});
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Create a seal with a 1-second TTL starting at current second
    let seal = create_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_wallclock_subsecond_sleep",
        "SyncClock",
        &params,
        "cafebabedeadbeef",
        now,
        1,
    );

    // Sleep until the wall clock strictly advances past seal.expires_at (now + 1)
    while SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        <= seal.expires_at
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Validate using system clock (current_time_utc = None)
    let res = gate.validate_and_consume_seal(&seal, "SyncClock", &params, None);

    match res {
        Err(GateError::SealRejection(msg)) => {
            assert!(
                msg.contains("expired"),
                "Wall clock sleep must cause expiration rejection, got: {}",
                msg
            );
        }
        other => panic!(
            "Expected GateError::SealRejection after wall-clock sleep, got: {:?}",
            other
        ),
    }

    assert!(!gate.is_seal_consumed("seal_wallclock_subsecond_sleep"));
}

#[test]
fn test_ttl_distant_future_1000s_rejected() {
    let gate = HostCapabilityGate::default();
    let params = json!({"action": "deploy"});
    let issued_at = 1_600_000_000;
    let seal = create_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_distant_future_1000s",
        "Deploy",
        &params,
        "8877665544332211",
        issued_at,
        30,
    );

    // t = issued_at + 1000s
    let outcome = gate.validate_and_consume_seal(&seal, "Deploy", &params, Some(issued_at + 1000));
    assert!(
        matches!(outcome, Err(GateError::SealRejection(ref msg)) if msg.contains("expired")),
        "Distant future invocation (1000s) must be rejected"
    );
    assert!(!gate.is_seal_consumed("seal_distant_future_1000s"));
}

#[test]
fn test_ttl_inverted_timestamps_rejected_immediately() {
    let gate = HostCapabilityGate::default();
    let params = json!({"mode": "raw"});
    let issued_at = 1_700_000_050;

    // Inverted: expires_at is 1_700_000_000 (before issued_at)
    let mut seal = create_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_inverted_ttl",
        "RawMode",
        &params,
        "1234123412341234",
        issued_at,
        0,
    );
    seal.expires_at = 1_700_000_000; // Force expires_at < issued_at

    // Re-sign to make HMAC valid
    seal.signature = sign_routing_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        &seal.seal_id,
        &seal.action_digest,
        &seal.policy_version_id,
        seal.issued_at,
    );

    // Calling at issued_at (1_700_000_050 > 1_700_000_000)
    let outcome = gate.validate_and_consume_seal(&seal, "RawMode", &params, Some(issued_at));
    assert!(
        matches!(outcome, Err(GateError::SealRejection(ref msg)) if msg.contains("expired")),
        "Inverted timestamp must be rejected as expired"
    );
}

// ============================================================================
// CATEGORY 2: Action Digest Tampering & Canonicalization Attacks
// ============================================================================

#[test]
fn test_action_digest_1byte_payload_tampering_across_types() {
    let gate = HostCapabilityGate::default();
    let base_params = json!({
        "amount": 100,
        "recipient": "alice",
        "verified": true,
        "tags": ["prod", "finance"],
        "metadata": {"priority": 1}
    });

    let seal = create_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_digest_tamper_suite",
        "TransferAsset",
        &base_params,
        "c0ffee00c0ffee00",
        1_700_000_000,
        30,
    );

    // Attack 1: Mutate 1 numeric digit (100 -> 101)
    let tampered_num = json!({
        "amount": 101,
        "recipient": "alice",
        "verified": true,
        "tags": ["prod", "finance"],
        "metadata": {"priority": 1}
    });
    let res1 =
        gate.validate_and_consume_seal(&seal, "TransferAsset", &tampered_num, Some(1_700_000_005));
    assert!(
        matches!(res1, Err(GateError::SealRejection(ref msg)) if msg.contains("Action digest mismatch"))
    );

    // Attack 2: Mutate 1 character in string ("alice" -> "bob")
    let tampered_str = json!({
        "amount": 100,
        "recipient": "bob",
        "verified": true,
        "tags": ["prod", "finance"],
        "metadata": {"priority": 1}
    });
    let res2 =
        gate.validate_and_consume_seal(&seal, "TransferAsset", &tampered_str, Some(1_700_000_005));
    assert!(
        matches!(res2, Err(GateError::SealRejection(ref msg)) if msg.contains("Action digest mismatch"))
    );

    // Attack 3: Mutate boolean (true -> false)
    let tampered_bool = json!({
        "amount": 100,
        "recipient": "alice",
        "verified": false,
        "tags": ["prod", "finance"],
        "metadata": {"priority": 1}
    });
    let res3 =
        gate.validate_and_consume_seal(&seal, "TransferAsset", &tampered_bool, Some(1_700_000_005));
    assert!(
        matches!(res3, Err(GateError::SealRejection(ref msg)) if msg.contains("Action digest mismatch"))
    );

    // Attack 4: Mutate 1 array element ("prod" -> "dev")
    let tampered_arr = json!({
        "amount": 100,
        "recipient": "alice",
        "verified": true,
        "tags": ["dev", "finance"],
        "metadata": {"priority": 1}
    });
    let res4 =
        gate.validate_and_consume_seal(&seal, "TransferAsset", &tampered_arr, Some(1_700_000_005));
    assert!(
        matches!(res4, Err(GateError::SealRejection(ref msg)) if msg.contains("Action digest mismatch"))
    );

    // Attack 5: Inject unexpected extra key
    let tampered_extra = json!({
        "amount": 100,
        "recipient": "alice",
        "verified": true,
        "tags": ["prod", "finance"],
        "metadata": {"priority": 1},
        "admin_override": true
    });
    let res5 = gate.validate_and_consume_seal(
        &seal,
        "TransferAsset",
        &tampered_extra,
        Some(1_700_000_005),
    );
    assert!(
        matches!(res5, Err(GateError::SealRejection(ref msg)) if msg.contains("Action digest mismatch"))
    );

    // Attack 6: Omit an existing key
    let tampered_missing = json!({
        "amount": 100,
        "recipient": "alice",
        "tags": ["prod", "finance"],
        "metadata": {"priority": 1}
    });
    let res6 = gate.validate_and_consume_seal(
        &seal,
        "TransferAsset",
        &tampered_missing,
        Some(1_700_000_005),
    );
    assert!(
        matches!(res6, Err(GateError::SealRejection(ref msg)) if msg.contains("Action digest mismatch"))
    );

    // Attack 7: Type confusion (number 100 -> string "100")
    let tampered_type = json!({
        "amount": "100",
        "recipient": "alice",
        "verified": true,
        "tags": ["prod", "finance"],
        "metadata": {"priority": 1}
    });
    let res7 =
        gate.validate_and_consume_seal(&seal, "TransferAsset", &tampered_type, Some(1_700_000_005));
    assert!(
        matches!(res7, Err(GateError::SealRejection(ref msg)) if msg.contains("Action digest mismatch"))
    );

    // Assert the seal was never marked consumed after all 7 failed tamper attempts
    assert!(!gate.is_seal_consumed("seal_digest_tamper_suite"));
    assert_eq!(gate.consumed_seals_count(), 0);
}

#[test]
fn test_action_name_mutations_and_homoglyphs() {
    let gate = HostCapabilityGate::default();
    let params = json!({"flag": true});
    let seal = create_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_action_name_mutations",
        "AuthorizePayment",
        &params,
        "fedcba9876543210",
        1_700_000_000,
        30,
    );

    let mutated_action_names = [
        "authorizepayment",    // lowercase
        "AUTHORIZEPAYMENT",    // uppercase
        " AuthorizePayment",   // leading space
        "AuthorizePayment ",   // trailing space
        "AuthorizePayment\0",  // null byte injection
        "AuthorizePayment\n",  // newline injection
        "AuthorizePayment_v2", // suffix mutation
        "AuthorizePayments",   // plural typo
        "AutһorizePayment",    // Cyrillic small letter shha 'һ' homoglyph
    ];

    for mutant in &mutated_action_names {
        let res = gate.validate_and_consume_seal(&seal, mutant, &params, Some(1_700_000_005));
        match res {
            Err(GateError::SealRejection(ref msg)) => {
                assert!(
                    msg.contains("Action digest mismatch"),
                    "Mutated action name '{}' must fail with digest mismatch, got: {}",
                    mutant,
                    msg
                );
            }
            other => panic!(
                "Expected GateError::SealRejection for mutant '{}', got: {:?}",
                mutant, other
            ),
        }
    }

    assert!(!gate.is_seal_consumed("seal_action_name_mutations"));
}

#[test]
fn test_canonical_jcs_deeply_nested_key_reordering() {
    // Generate complex deeply nested objects with permuted key orders
    let order_a = json!({
        "database": {
            "retries": 3,
            "host": "postgres.internal",
            "credentials": {
                "user": "app_user",
                "pool_size": 10,
                "auth_type": "scram-sha-256"
            }
        },
        "cluster": "us-west-2",
        "active": true,
        "accounts": [
            {"id": "acc_001", "balance": 500, "status": "active"},
            {"balance": 1200, "status": "pending", "id": "acc_002"}
        ]
    });

    let order_b = json!({
        "active": true,
        "cluster": "us-west-2",
        "accounts": [
            {"status": "active", "id": "acc_001", "balance": 500},
            {"id": "acc_002", "balance": 1200, "status": "pending"}
        ],
        "database": {
            "credentials": {
                "auth_type": "scram-sha-256",
                "pool_size": 10,
                "user": "app_user"
            },
            "host": "postgres.internal",
            "retries": 3
        }
    });

    let jcs_a = canonicalize_jcs(&order_a).expect("Order A canonicalization must succeed");
    let jcs_b = canonicalize_jcs(&order_b).expect("Order B canonicalization must succeed");
    assert_eq!(
        jcs_a, jcs_b,
        "JCS canonicalization must be identical across key reorderings"
    );

    let digest_a = compute_action_digest("ComplexAction", &order_a);
    let digest_b = compute_action_digest("ComplexAction", &order_b);
    assert_eq!(
        digest_a, digest_b,
        "Action digest must be identical across key reorderings"
    );

    // Verify seal issued under order_a validates and is consumed when presented with order_b
    let gate = HostCapabilityGate::default();
    let seal = create_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_jcs_reordering",
        "ComplexAction",
        &order_a,
        "1234432112344321",
        1_700_000_000,
        30,
    );

    let receipt = gate
        .validate_and_consume_seal(&seal, "ComplexAction", &order_b, Some(1_700_000_010))
        .expect("Seal issued with key order A must validate with key order B");
    assert_eq!(receipt.status, "CONSUMED");
    assert!(gate.is_seal_consumed("seal_jcs_reordering"));
}

#[test]
fn test_canonical_jcs_unicode_accents_emojis_cjk_control_chars() {
    let unicode_params = json!({
        "accents": "café naïve résumé façade",
        "emojis": "🦀 🛡️ 🚀 🔐 ✨",
        "cjk": "网络安全 セキュリティ 사이버보안",
        "escapes": "line1\nline2\ttabbed\r\ncarriage\\backslash\"quote\"",
        "url_slash": "https://api.github.com/repos/org/project",
        "special_control": "\u{0000}\u{001f}\u{0008}\u{000c}"
    });

    let jcs = canonicalize_jcs(&unicode_params).expect("Unicode JCS canonicalization must succeed");

    // RFC 8785 invariant: '/' MUST NOT be escaped
    assert!(
        jcs.contains("https://api.github.com/repos/org/project"),
        "JCS must not escape forward slashes, got: {}",
        jcs
    );
    assert!(
        !jcs.contains("https:\\/\\/"),
        "JCS must not produce escaped forward slashes"
    );

    // RFC 8785 invariant: control characters <= 0x1F escaped as \u00xx
    assert!(jcs.contains("\\u0000"));
    assert!(jcs.contains("\\u001f"));
    assert!(jcs.contains("\\b"));
    assert!(jcs.contains("\\f"));

    // Verify digest determinism
    let digest1 = compute_action_digest("UnicodeAction", &unicode_params);
    let digest2 = compute_action_digest("UnicodeAction", &unicode_params);
    assert_eq!(digest1, digest2);
    assert_eq!(digest1.len(), 64);

    // Verify seal validation with unicode params
    let gate = HostCapabilityGate::default();
    let seal = create_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_unicode_validation",
        "UnicodeAction",
        &unicode_params,
        "ffff0000ffff0000",
        1_700_000_000,
        30,
    );

    let receipt = gate
        .validate_and_consume_seal(&seal, "UnicodeAction", &unicode_params, Some(1_700_000_005))
        .expect("Unicode seal must validate cleanly");
    assert_eq!(receipt.status, "CONSUMED");
}

#[test]
fn test_canonical_jcs_array_order_is_preserved_permutations_alter_digest() {
    // Unlike object keys, array order is significant in JSON and JCS
    let params_arr1 = json!({"items": ["alpha", "beta", "gamma"]});
    let params_arr2 = json!({"items": ["beta", "alpha", "gamma"]});

    let digest1 = compute_action_digest("ArrayAction", &params_arr1);
    let digest2 = compute_action_digest("ArrayAction", &params_arr2);

    assert_ne!(
        digest1, digest2,
        "Array element reordering MUST produce different action digests"
    );

    let gate = HostCapabilityGate::default();
    let seal = create_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_array_order",
        "ArrayAction",
        &params_arr1,
        "0011223344556677",
        1_700_000_000,
        30,
    );

    // Presenting permuted array must fail
    let res =
        gate.validate_and_consume_seal(&seal, "ArrayAction", &params_arr2, Some(1_700_000_005));
    assert!(
        matches!(res, Err(GateError::SealRejection(ref msg)) if msg.contains("Action digest mismatch"))
    );
    assert!(!gate.is_seal_consumed("seal_array_order"));
}

// ============================================================================
// CATEGORY 3: Cryptographic Signature Forgery Attacks
// ============================================================================

#[test]
fn test_signature_forgery_1byte_bit_flips_across_multiple_positions() {
    let gate = HostCapabilityGate::default();
    let params = json!({"vault": "secrets_primary"});
    let base_seal = create_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_sig_bit_flips",
        "UnlockVault",
        &params,
        "9988776655443322",
        1_700_000_000,
        30,
    );

    let original_sig = base_seal.signature.clone();
    assert_eq!(original_sig.len(), 64);

    // Test bit flips / character substitutions at 8 different positions
    let test_indices = [0, 7, 15, 23, 31, 40, 52, 63];
    for &idx in &test_indices {
        let mut forged_seal = base_seal.clone();
        let mut chars: Vec<char> = original_sig.chars().collect();
        // Flip the character: if '0', replace with '1'; otherwise replace with '0'
        chars[idx] = if chars[idx] == '0' { '1' } else { '0' };
        forged_seal.signature = chars.into_iter().collect();

        let outcome = gate.validate_and_consume_seal(
            &forged_seal,
            "UnlockVault",
            &params,
            Some(1_700_000_005),
        );

        match outcome {
            Err(GateError::SealRejection(ref msg)) => {
                assert!(
                    msg.contains("Cryptographic HMAC signature invalid"),
                    "Bit flip at index {} must reject HMAC signature, got: {}",
                    idx,
                    msg
                );
            }
            other => panic!(
                "Expected GateError::SealRejection for bit flip at index {}, got: {:?}",
                idx, other
            ),
        }
    }

    assert!(!gate.is_seal_consumed("seal_sig_bit_flips"));
}

#[test]
fn test_signature_truncation_and_extension_attacks() {
    let gate = HostCapabilityGate::default();
    let params = json!({"action": "flush_cache"});
    let base_seal = create_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_sig_truncation",
        "FlushCache",
        &params,
        "1234567812345678",
        1_700_000_000,
        30,
    );

    let truncated_or_extended_sigs = [
        ("truncated_32_chars", base_seal.signature[..32].to_string()),
        ("truncated_63_chars", base_seal.signature[..63].to_string()),
        ("truncated_1_char", base_seal.signature[..1].to_string()),
        ("empty_sig", "".to_string()),
        ("extended_65_chars", format!("{}0", base_seal.signature)),
        (
            "extended_128_chars",
            format!("{}{}", base_seal.signature, base_seal.signature),
        ),
    ];

    for (label, forged_sig) in truncated_or_extended_sigs {
        let mut seal = base_seal.clone();
        seal.signature = forged_sig;

        let res = gate.validate_and_consume_seal(&seal, "FlushCache", &params, Some(1_700_000_005));
        assert!(
            matches!(res, Err(GateError::SealRejection(ref msg)) if msg.contains("Cryptographic HMAC signature invalid")),
            "Signature variant '{}' must fail with HMAC signature invalid",
            label
        );
    }

    assert!(!gate.is_seal_consumed("seal_sig_truncation"));
}

#[test]
fn test_cross_seal_and_cross_context_signature_reuse() {
    let gate = HostCapabilityGate::default();
    let params_a = json!({"resource": "ledger_read"});
    let params_b = json!({"resource": "ledger_write", "amount": 1_000_000});

    let seal_a = create_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_legit_read",
        "ReadLedger",
        &params_a,
        "1111222233334444",
        1_700_000_000,
        30,
    );

    // Reuse Attack 1: Attempt to copy Seal A's signature into Seal B (different seal_id and different action)
    let mut seal_b = create_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_stolen_write",
        "WriteLedger",
        &params_b,
        "1111222233334444",
        1_700_000_000,
        30,
    );
    seal_b.signature = seal_a.signature.clone();

    let res1 =
        gate.validate_and_consume_seal(&seal_b, "WriteLedger", &params_b, Some(1_700_000_005));
    assert!(
        matches!(res1, Err(GateError::SealRejection(ref msg)) if msg.contains("Cryptographic HMAC signature invalid"))
    );

    // Reuse Attack 2: Seal ID spoofing (keep Seal A's ID and signature, but switch action to WriteLedger)
    let res2 =
        gate.validate_and_consume_seal(&seal_a, "WriteLedger", &params_b, Some(1_700_000_005));
    assert!(
        matches!(res2, Err(GateError::SealRejection(ref msg)) if msg.contains("Action digest mismatch"))
    );

    // Reuse Attack 3: Cross-policy version spoofing (same seal_id, same action, but altered policy_version_id)
    let mut seal_cross_policy = seal_a.clone();
    seal_cross_policy.policy_version_id = "9999888877776666".to_string();
    let res3 = gate.validate_and_consume_seal(
        &seal_cross_policy,
        "ReadLedger",
        &params_a,
        Some(1_700_000_005),
    );
    assert!(
        matches!(res3, Err(GateError::SealRejection(ref msg)) if msg.contains("Cryptographic HMAC signature invalid"))
    );

    // Reuse Attack 4: Cross-timestamp spoofing (same seal_id, same action, but altered issued_at)
    let mut seal_cross_time = seal_a.clone();
    seal_cross_time.issued_at = 1_700_000_010;
    let res4 = gate.validate_and_consume_seal(
        &seal_cross_time,
        "ReadLedger",
        &params_a,
        Some(1_700_000_015),
    );
    assert!(
        matches!(res4, Err(GateError::SealRejection(ref msg)) if msg.contains("Cryptographic HMAC signature invalid"))
    );

    assert_eq!(gate.consumed_seals_count(), 0);
}

#[test]
fn test_rogue_substrate_key_forgery_fails_closed() {
    let rogue_key = b"rogue_attacker_fabricated_master_secret_key!";
    let params = json!({"grant": "superadmin"});
    let rogue_seal = create_test_seal(
        rogue_key,
        "seal_rogue_key_forged",
        "ElevatePrivileges",
        &params,
        "aaaabbbbccccdddd",
        1_700_000_000,
        30,
    );

    // Gate 1: Default substrate secret
    let default_gate = HostCapabilityGate::default();
    let res1 = default_gate.validate_and_consume_seal(
        &rogue_seal,
        "ElevatePrivileges",
        &params,
        Some(1_700_000_005),
    );
    assert!(
        matches!(res1, Err(GateError::SealRejection(ref msg)) if msg.contains("Cryptographic HMAC signature invalid"))
    );

    // Gate 2: Custom enterprise secret
    let custom_gate = HostCapabilityGate::default()
        .with_substrate_secret(b"enterprise_production_vault_secret_9999");
    let res2 = custom_gate.validate_and_consume_seal(
        &rogue_seal,
        "ElevatePrivileges",
        &params,
        Some(1_700_000_005),
    );
    assert!(
        matches!(res2, Err(GateError::SealRejection(ref msg)) if msg.contains("Cryptographic HMAC signature invalid"))
    );

    assert_eq!(default_gate.consumed_seals_count(), 0);
    assert_eq!(custom_gate.consumed_seals_count(), 0);
}

// ============================================================================
// CATEGORY 4: Unsealed Actuation and Bypass Attempts
// ============================================================================

#[tokio::test]
async fn test_unsealed_actuation_with_none_seal_fails_closed_immediately() {
    let gate = HostCapabilityGate::default();
    let params = json!({"query": "unauthorized_fetch"});

    // Calling dispatch_request_with_seal with seal = None
    // Invariant: Fails closed with GateError::SealRequired BEFORE any network interaction
    let res = gate
        .dispatch_request_with_seal(
            "GET",
            "https://export.arxiv.org/api/query?search_query=all:unauthorized",
            &[],
            None,
            None,
            "FetchArxiv",
            &params,
        )
        .await;

    match res {
        Err(GateError::SealRequired(err_msg)) => {
            assert!(
                err_msg.contains("NoDirectBind violation: unsealed execution rejected"),
                "Must enforce NoDirectBind violation, got: {}",
                err_msg
            );
        }
        other => panic!(
            "Expected GateError::SealRequired for None seal, got: {:?}",
            other
        ),
    }

    assert_eq!(gate.consumed_seals_count(), 0);
}

#[tokio::test]
async fn test_unsealed_actuation_with_empty_or_tampered_seal_fails_closed() {
    let gate = HostCapabilityGate::default();
    let legit_params = json!({"metric": "cpu"});
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut seal = create_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_dispatch_tamper",
        "GetMetric",
        &legit_params,
        "1234567890abcdef",
        now,
        30,
    );

    // Case 1: Empty seal_id
    seal.seal_id = "".to_string();
    let res1 = gate
        .dispatch_request_with_seal(
            "GET",
            "https://export.arxiv.org/status",
            &[],
            None,
            Some(&seal),
            "GetMetric",
            &legit_params,
        )
        .await;
    assert!(
        matches!(res1, Err(GateError::SealRejection(ref msg)) if msg.contains("Missing seal_id"))
    );

    // Restore seal_id
    seal.seal_id = "seal_dispatch_tamper".to_string();

    // Case 2: Tampered expected action name
    let res2 = gate
        .dispatch_request_with_seal(
            "GET",
            "https://export.arxiv.org/status",
            &[],
            None,
            Some(&seal),
            "SneakyBypassAction",
            &legit_params,
        )
        .await;
    assert!(
        matches!(res2, Err(GateError::SealRejection(ref msg)) if msg.contains("Action digest mismatch"))
    );

    // Case 3: Forged signature
    seal.signature = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
    let res3 = gate
        .dispatch_request_with_seal(
            "GET",
            "https://export.arxiv.org/status",
            &[],
            None,
            Some(&seal),
            "GetMetric",
            &legit_params,
        )
        .await;
    assert!(
        matches!(res3, Err(GateError::SealRejection(ref msg)) if msg.contains("Cryptographic HMAC signature invalid"))
    );

    // Case 4: Expired seal
    let mut expired_seal = seal.clone();
    expired_seal.issued_at = now - 60;
    expired_seal.expires_at = now - 30;
    expired_seal.signature = sign_routing_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        &expired_seal.seal_id,
        &expired_seal.action_digest,
        &expired_seal.policy_version_id,
        expired_seal.issued_at,
    );
    let res4 = gate
        .dispatch_request_with_seal(
            "GET",
            "https://export.arxiv.org/status",
            &[],
            None,
            Some(&expired_seal),
            "GetMetric",
            &legit_params,
        )
        .await;
    assert!(matches!(res4, Err(GateError::SealRejection(ref msg)) if msg.contains("expired")));

    assert_eq!(gate.consumed_seals_count(), 0);
}

#[tokio::test]
async fn test_dispatch_request_with_seal_rejects_already_consumed_seal_before_network() {
    let gate = HostCapabilityGate::default();
    let params = json!({"id": 42});
    let seal = create_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_consumed_before_dispatch",
        "InspectItem",
        &params,
        "aabbccddeeff1122",
        1_700_000_000,
        30,
    );

    // First: consume the seal directly via validate_and_consume_seal
    let first_res =
        gate.validate_and_consume_seal(&seal, "InspectItem", &params, Some(1_700_000_005));
    assert!(first_res.is_ok());
    assert!(gate.is_seal_consumed("seal_consumed_before_dispatch"));

    // Second: Attempt dispatch_request_with_seal with the same seal
    // Invariant: Must fail closed with replay detection BEFORE making any network call (even if URL is invalid)
    let second_res = gate
        .dispatch_request_with_seal(
            "GET",
            "https://invalid.unwhitelisted.domain.example.com",
            &[],
            None,
            Some(&seal),
            "InspectItem",
            &params,
        )
        .await;

    match second_res {
        Err(GateError::SealRejection(ref msg)) => {
            assert!(
                msg.contains("Replay detected"),
                "Must reject replay before network check, got: {}",
                msg
            );
        }
        other => panic!("Expected GateError::SealRejection replay, got: {:?}", other),
    }

    assert_eq!(gate.consumed_seals_count(), 1);
}

#[test]
fn test_unconsumed_invariance_on_failed_verifications() {
    let gate = HostCapabilityGate::default();
    let params = json!({"state": "init"});

    // Construct 3 invalid seals:
    // 1. Invalid signature
    let mut bad_sig = create_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_fail_sig",
        "InitState",
        &params,
        "1234123412341234",
        1_700_000_000,
        30,
    );
    bad_sig.signature =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();

    // 2. Expired seal
    let expired_seal = create_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_fail_expired",
        "InitState",
        &params,
        "1234123412341234",
        1_700_000_000,
        30,
    );

    // 3. Action mismatch seal
    let mismatch_seal = create_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_fail_mismatch",
        "WrongAction",
        &params,
        "1234123412341234",
        1_700_000_000,
        30,
    );

    assert!(gate
        .validate_and_consume_seal(&bad_sig, "InitState", &params, Some(1_700_000_005))
        .is_err());
    assert!(gate
        .validate_and_consume_seal(&expired_seal, "InitState", &params, Some(1_700_000_050))
        .is_err());
    assert!(gate
        .validate_and_consume_seal(&mismatch_seal, "InitState", &params, Some(1_700_000_005))
        .is_err());

    // Invariant: None of the failed seals are recorded as consumed
    assert!(!gate.is_seal_consumed("seal_fail_sig"));
    assert!(!gate.is_seal_consumed("seal_fail_expired"));
    assert!(!gate.is_seal_consumed("seal_fail_mismatch"));
    assert_eq!(gate.consumed_seals_count(), 0);
}

#[test]
fn test_concurrent_multi_thread_seal_consumption_race_50_threads() {
    const NUM_THREADS: usize = 50;
    let gate = Arc::new(HostCapabilityGate::default());
    let params = json!({"action": "fund_transfer", "amount": 500_000});

    let seal = Arc::new(create_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_high_concurrency_race_50",
        "FundTransfer",
        &params,
        "aabbccddeeff0011",
        1_700_000_000,
        30,
    ));

    let barrier = Arc::new(Barrier::new(NUM_THREADS));
    let win_count = Arc::new(AtomicUsize::new(0));
    let replay_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(NUM_THREADS);
    for _ in 0..NUM_THREADS {
        let gate_clone = Arc::clone(&gate);
        let seal_clone = Arc::clone(&seal);
        let barrier_clone = Arc::clone(&barrier);
        let params_clone = params.clone();
        let win_clone = Arc::clone(&win_count);
        let replay_clone = Arc::clone(&replay_count);

        handles.push(thread::spawn(move || {
            // Synchronize all 50 threads to fire simultaneously
            barrier_clone.wait();

            let res = gate_clone.validate_and_consume_seal(
                &seal_clone,
                "FundTransfer",
                &params_clone,
                Some(1_700_000_005),
            );

            match res {
                Ok(_) => {
                    win_clone.fetch_add(1, Ordering::SeqCst);
                }
                Err(GateError::SealRejection(ref msg)) if msg.contains("Replay detected") => {
                    replay_clone.fetch_add(1, Ordering::SeqCst);
                }
                Err(e) => {
                    panic!("Unexpected error in concurrency test: {:?}", e);
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("All 50 worker threads must join cleanly");
    }

    // Invariant: Exactly 1 winner, strictly 49 replays detected
    assert_eq!(
        win_count.load(Ordering::SeqCst),
        1,
        "Strictly 1 thread must win seal consumption"
    );
    assert_eq!(
        replay_count.load(Ordering::SeqCst),
        NUM_THREADS - 1,
        "Strictly 49 threads must be rejected with replay detection"
    );
    assert!(gate.is_seal_consumed("seal_high_concurrency_race_50"));
    assert_eq!(gate.consumed_seals_count(), 1);
}
