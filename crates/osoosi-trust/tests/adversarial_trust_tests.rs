use osoosi_trust::TrustManager;
use osoosi_types::{
    AttestationChallenge, AttestationError, GoldenBaseline, SecuredExecutor,
};
use std::sync::Arc;

struct DummyExecutor;

#[async_trait::async_trait]
impl SecuredExecutor for DummyExecutor {
    async fn execute(&self, _cmd: std::process::Command) -> anyhow::Result<std::process::Output> {
        Ok(std::process::Output {
            status: std::process::ExitStatus::default(),
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    }

    async fn download(&self, _url: &str, _dest: &std::path::Path, _resume: bool) -> anyhow::Result<()> {
        Ok(())
    }
}

fn create_test_managers() -> (TrustManager, TrustManager) {
    let challenger = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
    let responder = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
    (challenger, responder)
}

// =========================================================================
// 1. REPLAY ATTACK PATTERNS
// =========================================================================

#[test]
fn test_attack_replay_stale_attestation_response() {
    let (challenger, responder) = create_test_managers();

    // Challenger creates Challenge A and Challenge B
    let challenge_a = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    let challenge_b = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    assert_ne!(challenge_a.nonce, challenge_b.nonce);

    // Responder legitimately responds to Challenge A
    let response_a = responder.respond_to_attestation(challenge_a.clone()).unwrap();

    // Attacker replays response A against Challenge B
    let result = challenger.verify_attestation_with_policy(&challenge_b, &response_a, None);
    assert_eq!(
        result,
        Err(AttestationError::NonceReplayDetected),
        "Replaying an attestation response against a fresh challenge must trigger NonceReplayDetected"
    );
}

#[test]
fn test_attack_replay_tampered_nonce_in_response() {
    let (challenger, responder) = create_test_managers();
    let challenge = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    let mut response = responder.respond_to_attestation(challenge.clone()).unwrap();

    // Attacker alters a single bit in the response's challenge nonce
    response.challenge_nonce[15] ^= 0x01;

    let result = challenger.verify_attestation_with_policy(&challenge, &response, None);
    assert_eq!(
        result,
        Err(AttestationError::NonceReplayDetected),
        "Mismatched challenge nonce must immediately fail with NonceReplayDetected"
    );
}

#[test]
fn test_attack_replay_expired_challenge_ttl() {
    let (challenger, responder) = create_test_managers();
    let mut challenge = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);

    // Set challenge timestamp 400 seconds into the past (exceeding default 300s TTL)
    challenge.timestamp = chrono::Utc::now() - chrono::Duration::seconds(400);

    let response = responder.respond_to_attestation(challenge.clone()).unwrap();

    // Policy with standard 300s TTL
    let policy = GoldenBaseline::new().with_max_nonce_age(300);
    let result = challenger.verify_attestation_with_policy(&challenge, &response, Some(&policy));
    assert_eq!(
        result,
        Err(AttestationError::NonceReplayDetected),
        "Attestation against an expired challenge timestamp must fail with NonceReplayDetected"
    );
}

#[test]
fn test_attack_replay_future_timestamp_challenge() {
    let (challenger, responder) = create_test_managers();
    let mut challenge = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);

    // Set challenge timestamp in the future (age < 0)
    challenge.timestamp = chrono::Utc::now() + chrono::Duration::seconds(120);

    let response = responder.respond_to_attestation(challenge.clone()).unwrap();

    let policy = GoldenBaseline::new().with_max_nonce_age(300);
    let result = challenger.verify_attestation_with_policy(&challenge, &response, Some(&policy));
    assert_eq!(
        result,
        Err(AttestationError::NonceReplayDetected),
        "Attestation challenge with future timestamp must fail with NonceReplayDetected"
    );
}

// =========================================================================
// 2. FORGERY AND TAMPERING PATTERNS: TPM 2.0 PCR QUOTES
// =========================================================================

#[test]
fn test_attack_tampered_pcr_quote_composite_digest() {
    let (challenger, responder) = create_test_managers();
    let challenge = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    let mut response = responder.respond_to_attestation(challenge.clone()).unwrap();

    // Attacker modifies the quote's composite pcr_digest string
    if let Some(ref mut quote) = response.tpm_quote {
        quote.pcr_digest = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string();
    }

    let result = challenger.verify_attestation_with_policy(&challenge, &response, None);
    match result {
        Err(AttestationError::QuoteDigestMismatch { .. }) => (),
        other => panic!("Expected QuoteDigestMismatch for tampered pcr_digest, got: {:?}", other),
    }
}

#[test]
fn test_attack_tampered_pcr_quote_quoted_digest() {
    let (challenger, responder) = create_test_managers();
    let challenge = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    let mut response = responder.respond_to_attestation(challenge.clone()).unwrap();

    // Attacker modifies quoted_digest (binding challenge nonce and PCRs)
    if let Some(ref mut quote) = response.tpm_quote {
        quote.quoted_digest = "baadf00dbaadf00dbaadf00dbaadf00dbaadf00dbaadf00dbaadf00dbaadf00d".to_string();
    }

    let result = challenger.verify_attestation_with_policy(&challenge, &response, None);
    match result {
        Err(AttestationError::QuoteDigestMismatch { .. }) => (),
        other => panic!("Expected QuoteDigestMismatch for forged quoted_digest, got: {:?}", other),
    }
}

#[test]
fn test_attack_tampered_pcr_0_firmware_register() {
    let (challenger, responder) = create_test_managers();
    let challenge = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    let mut response = responder.respond_to_attestation(challenge.clone()).unwrap();

    // Attacker modifies PCR 0 (Firmware / BIOS integrity)
    response.pcr_values.insert(
        0,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
    );

    let result = challenger.verify_attestation_with_policy(&challenge, &response, None);
    match result {
        Err(AttestationError::QuoteDigestMismatch { .. }) => (),
        other => panic!("Expected QuoteDigestMismatch for tampered PCR 0, got: {:?}", other),
    }
}

#[test]
fn test_attack_tampered_pcr_7_secure_boot_register() {
    let (challenger, responder) = create_test_managers();
    let challenge = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    let mut response = responder.respond_to_attestation(challenge.clone()).unwrap();

    // Attacker modifies PCR 7 (Secure Boot state)
    response.pcr_values.insert(
        7,
        "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
    );

    let result = challenger.verify_attestation_with_policy(&challenge, &response, None);
    match result {
        Err(AttestationError::QuoteDigestMismatch { .. }) => (),
        other => panic!("Expected QuoteDigestMismatch for tampered PCR 7, got: {:?}", other),
    }
}

#[test]
fn test_attack_quote_missing_one_of_requested_pcr_indices() {
    let (challenger, responder) = create_test_managers();
    let challenge = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    let mut response = responder.respond_to_attestation(challenge.clone()).unwrap();

    // Attacker removes PCR 16 from quote.pcr_indices
    if let Some(ref mut quote) = response.tpm_quote {
        quote.pcr_indices.retain(|&idx| idx != 16);
    }

    let result = challenger.verify_attestation_with_policy(&challenge, &response, None);
    assert_eq!(
        result,
        Err(AttestationError::MissingPcr(16)),
        "TPM quote missing requested PCR index must be rejected with MissingPcr"
    );
}

#[test]
fn test_attack_stripped_tpm_quote_when_pcrs_requested() {
    let (challenger, responder) = create_test_managers();
    let challenge = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    let mut response = responder.respond_to_attestation(challenge.clone()).unwrap();

    // Attacker completely removes TPM quote from response
    response.tpm_quote = None;

    let result = challenger.verify_attestation_with_policy(&challenge, &response, None);
    match result {
        Err(AttestationError::MissingPcr(_)) => (),
        other => panic!("Expected MissingPcr error when quote is stripped, got: {:?}", other),
    }
}

// =========================================================================
// 3. FORGERY AND TAMPERING: DIGITAL SIGNATURES & IDENTITY
// =========================================================================

#[test]
fn test_attack_forged_signature_tampered_bytes() {
    let (challenger, responder) = create_test_managers();
    let challenge = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    let mut response = responder.respond_to_attestation(challenge.clone()).unwrap();

    // Flip byte in signature hex
    let mut sig_bytes = hex::decode(&response.signature).unwrap();
    sig_bytes[10] ^= 0x42;
    response.signature = hex::encode(sig_bytes);

    let result = challenger.verify_attestation_with_policy(&challenge, &response, None);
    assert_eq!(
        result,
        Err(AttestationError::InvalidSignature),
        "Corrupted signature bytes must fail verification with InvalidSignature"
    );
}

#[test]
fn test_attack_forged_signature_signed_by_different_attacker_key() {
    let (challenger, responder) = create_test_managers();
    let challenge = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    let mut response = responder.respond_to_attestation(challenge.clone()).unwrap();

    // Rogue attacker node generates a different key and signs the attestation digest
    let attacker_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();

    // Attacker signs using their own key but keeps victim's responder_did
    let forged_response = attacker_tm.respond_to_attestation(challenge.clone()).unwrap();
    response.signature = forged_response.signature;

    let result = challenger.verify_attestation_with_policy(&challenge, &response, None);
    assert_eq!(
        result,
        Err(AttestationError::InvalidSignature),
        "Signature from different key than responder_did must fail with InvalidSignature"
    );
}

#[test]
fn test_attack_spoofed_did_identity_mismatch() {
    let (challenger, responder) = create_test_managers();
    let challenge = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    let mut response = responder.respond_to_attestation(challenge.clone()).unwrap();

    // Attacker attempts to spoof a different node's 64-hex DID ID while keeping their own public key
    response.responder_did.id = "did:osoosi:0000000000000000000000000000000000000000000000000000000000000000".to_string();

    let result = challenger.verify_attestation_with_policy(&challenge, &response, None);
    match result {
        Err(AttestationError::InvalidPublicKey(msg)) => {
            assert!(msg.contains("DID identifier does not match public key"));
        }
        other => panic!("Expected InvalidPublicKey for spoofed DID ID, got: {:?}", other),
    }
}

#[test]
fn test_attack_spoofed_did_malformed_hex_public_key() {
    let (challenger, responder) = create_test_managers();
    let challenge = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    let mut response = responder.respond_to_attestation(challenge.clone()).unwrap();

    // Attacker injects non-hex characters in public_key
    response.responder_did.public_key = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ".to_string();
    response.responder_did.id = format!("did:osoosi:{}", response.responder_did.public_key);

    let result = challenger.verify_attestation_with_policy(&challenge, &response, None);
    match result {
        Err(AttestationError::InvalidPublicKey(_)) => (),
        other => panic!("Expected InvalidPublicKey for malformed hex, got: {:?}", other),
    }
}

#[test]
fn test_attack_spoofed_did_truncated_public_key() {
    let (challenger, responder) = create_test_managers();
    let challenge = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    let mut response = responder.respond_to_attestation(challenge.clone()).unwrap();

    // Truncate public key to 16 bytes (32 hex chars) instead of 32 bytes (64 hex chars)
    response.responder_did.public_key = "0123456789abcdef0123456789abcdef".to_string();

    let result = challenger.verify_attestation_with_policy(&challenge, &response, None);
    match result {
        Err(AttestationError::InvalidPublicKey(msg)) => {
            assert!(msg.contains("32 bytes"));
        }
        other => panic!("Expected InvalidPublicKey for truncated key, got: {:?}", other),
    }
}

// =========================================================================
// 4. MISMATCHED GOLDEN BASELINE ATTACKS
// =========================================================================

#[test]
fn test_attack_golden_baseline_tampered_binary_hash() {
    let (challenger, mut responder) = create_test_managers();
    let golden_bin = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string();
    let rogue_bin = "f9e8d7c6b5a4f9e8d7c6b5a4f9e8d7c6b5a4f9e8d7c6b5a4f9e8d7c6b5a4f9e8".to_string();

    responder.set_local_binary_hash(rogue_bin.clone());
    let challenge = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    let response = responder.respond_to_attestation(challenge.clone()).unwrap();

    let baseline = GoldenBaseline::new().allow_binary_hash(&golden_bin);
    let result = challenger.verify_attestation_with_policy(&challenge, &response, Some(&baseline));
    assert_eq!(
        result,
        Err(AttestationError::BinaryHashMismatch { actual: rogue_bin }),
        "Rogue binary hash must be rejected with BinaryHashMismatch"
    );
}

#[test]
fn test_attack_golden_baseline_tampered_config_hash() {
    let (challenger, mut responder) = create_test_managers();
    let golden_cfg = "1111111111111111111111111111111111111111111111111111111111111111".to_string();
    let rogue_cfg = "9999999999999999999999999999999999999999999999999999999999999999".to_string();

    responder.set_local_config_hash(rogue_cfg.clone());
    let challenge = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    let response = responder.respond_to_attestation(challenge.clone()).unwrap();

    let baseline = GoldenBaseline::new().allow_config_hash(&golden_cfg);
    let result = challenger.verify_attestation_with_policy(&challenge, &response, Some(&baseline));
    assert_eq!(
        result,
        Err(AttestationError::ConfigHashMismatch { actual: rogue_cfg }),
        "Rogue config hash must be rejected with ConfigHashMismatch"
    );
}

#[test]
fn test_attack_golden_baseline_tampered_pcr_0_and_pcr_7() {
    let (challenger, responder) = create_test_managers();
    let challenge = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    let response = responder.respond_to_attestation(challenge.clone()).unwrap();

    // Baseline strictly requires known PCR values that don't match the responder's
    let baseline = GoldenBaseline::new()
        .allow_pcr(0, "expected_oem_uefi_firmware_measurement")
        .allow_pcr(7, "expected_microsoft_uefi_ca_secure_boot");

    let result = challenger.verify_attestation_with_policy(&challenge, &response, Some(&baseline));
    match result {
        Err(AttestationError::PcrMismatch { pcr_index, .. }) => {
            assert!(pcr_index == 0 || pcr_index == 7);
        }
        other => panic!("Expected PcrMismatch, got: {:?}", other),
    }
}

#[test]
fn test_attack_golden_baseline_hardware_tpm_enforcement() {
    let (challenger, responder) = create_test_managers();
    let challenge = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    let response = responder.respond_to_attestation(challenge.clone()).unwrap();

    // Policy strictly mandates hardware TPM
    let baseline = GoldenBaseline::new().require_hardware(true);
    let result = challenger.verify_attestation_with_policy(&challenge, &response, Some(&baseline));
    assert_eq!(
        result,
        Err(AttestationError::HardwareTpmRequired),
        "Software simulated TPM must be rejected when GoldenBaseline enforces hardware TPM"
    );
}

#[test]
fn test_attack_golden_baseline_comprehensive_enforcement_success() {
    let (challenger, mut responder) = create_test_managers();
    let known_bin = "approved_edr_core_v1_0_binary_hash_sha256_mock_0000000000000000".to_string();
    let known_cfg = "approved_mesh_listen_zone_config_hash_sha256_000000000000000000".to_string();

    responder.set_local_binary_hash(known_bin.clone());
    responder.set_local_config_hash(known_cfg.clone());

    let challenge = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    let response = responder.respond_to_attestation(challenge.clone()).unwrap();

    let pcr0 = response.pcr_values.get(&0).cloned().unwrap();
    let pcr7 = response.pcr_values.get(&7).cloned().unwrap();
    let pcr16 = response.pcr_values.get(&16).cloned().unwrap();

    let baseline = GoldenBaseline::new()
        .allow_binary_hash(&known_bin)
        .allow_config_hash(&known_cfg)
        .allow_pcr(0, pcr0)
        .allow_pcr(7, pcr7)
        .allow_pcr(16, pcr16)
        .require_hardware(false)
        .with_max_nonce_age(300);

    let result = challenger.verify_attestation_with_policy(&challenge, &response, Some(&baseline));
    assert!(result.is_ok(), "Attestation must pass when all golden baseline requirements are satisfied: {:?}", result);
}

#[test]
fn test_attack_challenge_with_null_zero_nonce() {
    let (challenger, responder) = create_test_managers();
    let mut challenge = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    challenge.nonce = [0u8; 32]; // Null/all-zero nonce

    let response = responder.respond_to_attestation(challenge.clone()).unwrap();
    assert_eq!(response.challenge_nonce, [0u8; 32]);

    let result = challenger.verify_attestation_with_policy(&challenge, &response, None);
    assert!(result.is_ok(), "Null nonce attestation should verify correctly without panics");
}

#[test]
fn test_attack_golden_baseline_strict_whitelist_rejects_unlisted_binary() {
    let (challenger, responder) = create_test_managers();
    let challenge = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    let response = responder.respond_to_attestation(challenge.clone()).unwrap();

    // Baseline with non-matching binary whitelist enforces default-deny against unlisted binaries
    let baseline = GoldenBaseline::new().allow_binary_hash("0000000000000000000000000000000000000000000000000000000000000000");
    let result = challenger.verify_attestation_with_policy(&challenge, &response, Some(&baseline));
    match result {
        Err(AttestationError::BinaryHashMismatch { .. }) => (),
        other => panic!("Expected BinaryHashMismatch when whitelist does not match responder hash, got: {:?}", other),
    }
}

#[test]
fn test_attack_golden_baseline_multi_binary_whitelist_matching_and_rejection() {
    let (challenger, mut responder) = create_test_managers();
    let allowed_bin_1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
    let allowed_bin_2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
    let rogue_bin = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string();

    let baseline = GoldenBaseline::new()
        .allow_binary_hash(&allowed_bin_1)
        .allow_binary_hash(&allowed_bin_2);

    // 1. Responder with allowed_bin_2 should pass binary check
    responder.set_local_binary_hash(allowed_bin_2.clone());
    let challenge = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    let response = responder.respond_to_attestation(challenge.clone()).unwrap();
    let result = challenger.verify_attestation_with_policy(&challenge, &response, Some(&baseline));
    assert!(result.is_ok(), "Matching second binary hash in whitelist must pass: {:?}", result);

    // 2. Responder with rogue binary should fail
    responder.set_local_binary_hash(rogue_bin.clone());
    let challenge2 = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    let response2 = responder.respond_to_attestation(challenge2.clone()).unwrap();
    let result2 = challenger.verify_attestation_with_policy(&challenge2, &response2, Some(&baseline));
    assert_eq!(result2, Err(AttestationError::BinaryHashMismatch { actual: rogue_bin }));
}

#[test]
fn test_attack_attestation_mismatched_challenger_did_handling() {
    let (challenger, responder) = create_test_managers();
    let third_party_challenger = TrustManager::new(Arc::new(DummyExecutor)).unwrap();

    // Challenge issued by third party
    let challenge_foreign = AttestationChallenge::new(third_party_challenger.did().clone(), vec![0, 7, 16]);
    let response = responder.respond_to_attestation(challenge_foreign.clone()).unwrap();

    // Local challenger tries to verify against its own challenge
    let challenge_local = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    let result = challenger.verify_attestation_with_policy(&challenge_local, &response, None);
    assert_eq!(
        result,
        Err(AttestationError::NonceReplayDetected),
        "Response to different challenger's challenge must fail verification"
    );
}

#[test]
fn test_attack_clock_skew_boundary_295s_accept_305s_reject() {
    let (challenger, responder) = create_test_managers();

    // 1. 295s age: within 300s TTL -> PASS
    let mut challenge_valid = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    challenge_valid.timestamp = chrono::Utc::now() - chrono::Duration::seconds(295);
    let resp_valid = responder.respond_to_attestation(challenge_valid.clone()).unwrap();
    let baseline = GoldenBaseline::new().with_max_nonce_age(300);
    let res1 = challenger.verify_attestation_with_policy(&challenge_valid, &resp_valid, Some(&baseline));
    assert!(res1.is_ok(), "Attestation at 295s (< 300s TTL) must succeed: {:?}", res1);

    // 2. 305s age: past 300s TTL -> REJECT
    let mut challenge_expired = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    challenge_expired.timestamp = chrono::Utc::now() - chrono::Duration::seconds(305);
    let resp_expired = responder.respond_to_attestation(challenge_expired.clone()).unwrap();
    let res2 = challenger.verify_attestation_with_policy(&challenge_expired, &resp_expired, Some(&baseline));
    assert_eq!(
        res2,
        Err(AttestationError::NonceReplayDetected),
        "Attestation at 305s (> 300s TTL) must fail with NonceReplayDetected"
    );
}

#[test]
fn test_attack_golden_baseline_missing_pcr_in_response() {
    let (challenger, responder) = create_test_managers();
    let challenge = AttestationChallenge::new(challenger.did().clone(), vec![0, 7, 16]);
    let mut response = responder.respond_to_attestation(challenge.clone()).unwrap();

    // Attacker removes PCR 16 from response values
    response.pcr_values.remove(&16);

    let baseline = GoldenBaseline::new()
        .allow_pcr(0, "mock")
        .allow_pcr(7, "mock")
        .allow_pcr(16, "mock");

    let result = challenger.verify_attestation_with_policy(&challenge, &response, Some(&baseline));
    match result {
        Err(AttestationError::MissingPcr(idx)) => assert_eq!(idx, 16),
        other => panic!("Expected MissingPcr(16), got: {:?}", other),
    }
}

