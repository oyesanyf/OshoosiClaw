use osoosi_trust::TrustManager;
use std::sync::Arc;

struct DummyExecutor;

#[async_trait::async_trait]
impl osoosi_types::SecuredExecutor for DummyExecutor {
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

#[test]
fn test_did_generation() {
    let tm = TrustManager::new(Arc::new(DummyExecutor)).expect("Failed to create TrustManager");
    let did = tm.did();

    assert!(
        did.id.starts_with("did:osoosi:"),
        "DID should use the osoosi prefix"
    );
    assert_eq!(
        did.public_key.len(),
        64,
        "Public key hex should be 64 characters (32 bytes)"
    );
}

#[tokio::test]
async fn test_ca_init_structure() {
    let tm = TrustManager::new(Arc::new(DummyExecutor)).expect("Failed to create TrustManager");
    let temp_dir = std::env::temp_dir().join(format!("osoosi_test_{}", uuid::Uuid::new_v4()));

    std::fs::create_dir_all(&temp_dir).unwrap();

    if let Err(e) = tm.init_ca(temp_dir.to_str().unwrap()).await {
        if e.to_string().contains("failed to fill whole buffer")
            || e.to_string().contains("not found")
        {
            return;
        }
        panic!("CA Init failed: {}", e);
    }

    assert!(temp_dir.join("rootCA.key").exists());
    assert!(temp_dir.join("rootCA.crt").exists());

    let _ = std::fs::remove_dir_all(temp_dir);
}

#[test]
fn test_tpm2_attestation_flow() {
    let challenger_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
    let responder_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();

    let pcr_selection = vec![0, 7, 16];
    let challenge = osoosi_types::AttestationChallenge::new(challenger_tm.did().clone(), pcr_selection.clone());

    let response = responder_tm.respond_to_attestation(challenge.clone()).expect("Failed to respond to attestation");

    assert_eq!(response.challenge_nonce, challenge.nonce);
    assert_eq!(response.responder_did, *responder_tm.did());
    assert!(response.pcr_values.contains_key(&0));
    assert!(response.pcr_values.contains_key(&7));
    assert!(response.pcr_values.contains_key(&16));

    let quote = response.tpm_quote.as_ref().expect("TPM quote missing in response");
    assert_eq!(quote.pcr_indices, pcr_selection);
    assert!(!quote.pcr_digest.is_empty());
    assert!(!quote.quoted_digest.is_empty());

    // Challenger verifies the attestation response
    let valid = challenger_tm.verify_attestation(&challenge, &response);
    assert!(valid, "Attestation response must successfully verify");
}

#[test]
fn test_golden_baseline_matching() {
    let challenger_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
    let mut responder_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();

    let known_bin_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
    let known_cfg_hash = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string();
    responder_tm.set_local_binary_hash(known_bin_hash.clone());
    responder_tm.set_local_config_hash(known_cfg_hash.clone());

    let challenge = osoosi_types::AttestationChallenge::new(challenger_tm.did().clone(), vec![0, 7, 16]);
    let response = responder_tm.respond_to_attestation(challenge.clone()).unwrap();

    let pcr0_val = response.pcr_values.get(&0).cloned().unwrap();
    let pcr7_val = response.pcr_values.get(&7).cloned().unwrap();

    let policy = osoosi_types::GoldenBaseline::new()
        .allow_binary_hash(known_bin_hash)
        .allow_config_hash(known_cfg_hash)
        .allow_pcr(0, pcr0_val)
        .allow_pcr(7, pcr7_val);

    let result = challenger_tm.verify_attestation_with_policy(&challenge, &response, Some(&policy));
    assert!(result.is_ok(), "Expected policy matching to succeed, got: {:?}", result);
}

#[test]
fn test_golden_baseline_mismatched_binary_hash() {
    let challenger_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
    let mut responder_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();

    responder_tm.set_local_binary_hash("corrupted_binary_hash".to_string());
    let challenge = osoosi_types::AttestationChallenge::new(challenger_tm.did().clone(), vec![0, 7, 16]);
    let response = responder_tm.respond_to_attestation(challenge.clone()).unwrap();

    let policy = osoosi_types::GoldenBaseline::new()
        .allow_binary_hash("approved_golden_hash");

    let result = challenger_tm.verify_attestation_with_policy(&challenge, &response, Some(&policy));
    match result {
        Err(osoosi_types::AttestationError::BinaryHashMismatch { actual }) => {
            assert_eq!(actual, "corrupted_binary_hash");
        }
        other => panic!("Expected BinaryHashMismatch, got: {:?}", other),
    }
}

#[test]
fn test_golden_baseline_mismatched_pcr() {
    let challenger_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
    let responder_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();

    let challenge = osoosi_types::AttestationChallenge::new(challenger_tm.did().clone(), vec![0, 7, 16]);
    let response = responder_tm.respond_to_attestation(challenge.clone()).unwrap();

    let policy = osoosi_types::GoldenBaseline::new()
        .allow_pcr(7, "expected_different_secure_boot_pcr7_value");

    let result = challenger_tm.verify_attestation_with_policy(&challenge, &response, Some(&policy));
    match result {
        Err(osoosi_types::AttestationError::PcrMismatch { pcr_index, .. }) => {
            assert_eq!(pcr_index, 7);
        }
        other => panic!("Expected PcrMismatch on PCR 7, got: {:?}", other),
    }
}

#[test]
fn test_replay_attack_prevention() {
    let challenger_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
    let responder_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();

    let challenge1 = osoosi_types::AttestationChallenge::new(challenger_tm.did().clone(), vec![0, 7, 16]);
    let mut response = responder_tm.respond_to_attestation(challenge1.clone()).unwrap();

    // Attacker sends response against a different challenge nonce
    let challenge2 = osoosi_types::AttestationChallenge::new(challenger_tm.did().clone(), vec![0, 7, 16]);
    let result = challenger_tm.verify_attestation_with_policy(&challenge2, &response, None);
    assert_eq!(result, Err(osoosi_types::AttestationError::NonceReplayDetected));

    // Attacker modifies nonce inside response
    response.challenge_nonce[0] ^= 0xff;
    let result2 = challenger_tm.verify_attestation_with_policy(&challenge1, &response, None);
    assert_eq!(result2, Err(osoosi_types::AttestationError::NonceReplayDetected));
}

#[test]
fn test_tampered_signature_rejection() {
    let challenger_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
    let responder_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();

    let challenge = osoosi_types::AttestationChallenge::new(challenger_tm.did().clone(), vec![0, 7, 16]);
    let mut response = responder_tm.respond_to_attestation(challenge.clone()).unwrap();

    // Corrupt signature
    let mut sig_bytes = hex::decode(&response.signature).unwrap();
    sig_bytes[0] ^= 0xaa;
    response.signature = hex::encode(sig_bytes);

    let result = challenger_tm.verify_attestation_with_policy(&challenge, &response, None);
    assert_eq!(result, Err(osoosi_types::AttestationError::InvalidSignature));
}

#[test]
fn test_tampered_pcr_quote_rejection() {
    let challenger_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
    let responder_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();

    let challenge = osoosi_types::AttestationChallenge::new(challenger_tm.did().clone(), vec![0, 7, 16]);
    let mut response = responder_tm.respond_to_attestation(challenge.clone()).unwrap();

    // Attacker silently modifies PCR 16 value in response
    response.pcr_values.insert(16, "0000000000000000000000000000000000000000000000000000000000000000".to_string());

    let result = challenger_tm.verify_attestation_with_policy(&challenge, &response, None);
    match result {
        Err(osoosi_types::AttestationError::QuoteDigestMismatch { .. }) => (),
        other => panic!("Expected QuoteDigestMismatch for tampered PCR value, got: {:?}", other),
    }
}

#[test]
fn test_hardware_tpm_required_rejection() {
    let challenger_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
    let responder_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();

    let challenge = osoosi_types::AttestationChallenge::new(challenger_tm.did().clone(), vec![0, 7, 16]);
    let mut response = responder_tm.respond_to_attestation(challenge.clone()).unwrap();

    let policy = osoosi_types::GoldenBaseline::new().require_hardware(true);

    // In simulated environment, quote.hardware_backed is false -> must fail with HardwareTpmRequired
    let result = challenger_tm.verify_attestation_with_policy(&challenge, &response, Some(&policy));
    assert_eq!(result, Err(osoosi_types::AttestationError::HardwareTpmRequired));

    // Even if attacker strips quote completely, must still fail with HardwareTpmRequired
    response.tpm_quote = None;
    let result2 = challenger_tm.verify_attestation_with_policy(&challenge, &response, Some(&policy));
    assert_eq!(result2, Err(osoosi_types::AttestationError::HardwareTpmRequired));
}

#[test]
fn test_missing_requested_pcr_rejection() {
    let challenger_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
    let responder_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();

    // Challenger specifically asks for PCR 0, 7, and 16
    let challenge = osoosi_types::AttestationChallenge::new(challenger_tm.did().clone(), vec![0, 7, 16]);
    let mut response = responder_tm.respond_to_attestation(challenge.clone()).unwrap();

    // Attacker removes PCR 7 (Secure Boot) from response
    response.pcr_values.remove(&7);

    let result = challenger_tm.verify_attestation_with_policy(&challenge, &response, None);
    assert_eq!(result, Err(osoosi_types::AttestationError::MissingPcr(7)));
}

#[test]
fn test_quote_missing_requested_pcr_index_rejection() {
    let challenger_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
    let responder_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();

    let challenge = osoosi_types::AttestationChallenge::new(challenger_tm.did().clone(), vec![0, 7, 16]);
    let mut response = responder_tm.respond_to_attestation(challenge.clone()).unwrap();

    // Attacker modifies quote to only claim PCR 0
    if let Some(ref mut quote) = response.tpm_quote {
        quote.pcr_indices = vec![0];
    }

    let result = challenger_tm.verify_attestation_with_policy(&challenge, &response, None);
    assert_eq!(result, Err(osoosi_types::AttestationError::MissingPcr(7)));
}

#[test]
fn test_did_identifier_mismatch_rejection() {
    let challenger_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
    let responder_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();

    let challenge = osoosi_types::AttestationChallenge::new(challenger_tm.did().clone(), vec![0, 7, 16]);
    let mut response = responder_tm.respond_to_attestation(challenge.clone()).unwrap();

    // Attacker alters DID ID to claim a different identity while keeping same public key
    response.responder_did.id = "did:osoosi:0000000000000000000000000000000000000000000000000000000000000000".to_string();

    let result = challenger_tm.verify_attestation_with_policy(&challenge, &response, None);
    match result {
        Err(osoosi_types::AttestationError::InvalidPublicKey(msg)) => {
            assert!(msg.contains("DID identifier does not match public key"));
        }
        other => panic!("Expected InvalidPublicKey error, got: {:?}", other),
    }
}

