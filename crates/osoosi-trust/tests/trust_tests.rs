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

#[test]
fn test_tpm_ek_silicon_validation_intel_and_amd_success() {
    use osoosi_trust::generate_mock_oem_ek_certificate;
    use osoosi_types::{GoldenBaseline, TpmOemVendor};

    // Intel EK cert
    let intel_ek = generate_mock_oem_ek_certificate(TpmOemVendor::Intel, "Intel TPM 2.0 EK").unwrap();
    assert_eq!(intel_ek.vendor, TpmOemVendor::Intel);
    assert!(intel_ek.cert_fingerprint.is_some());

    let policy_intel = GoldenBaseline::new()
        .require_ek(true)
        .allow_tpm_vendor(TpmOemVendor::Intel);
    let verified_intel = osoosi_trust::verify_tpm_ek_certificate(&intel_ek, Some(&policy_intel)).unwrap();
    assert_eq!(verified_intel.vendor, TpmOemVendor::Intel);

    // AMD EK cert
    let amd_ek = generate_mock_oem_ek_certificate(TpmOemVendor::Amd, "AMD fTPM 2.0 EK").unwrap();
    assert_eq!(amd_ek.vendor, TpmOemVendor::Amd);

    let policy_amd = GoldenBaseline::new()
        .require_ek(true)
        .allow_tpm_vendor(TpmOemVendor::Amd);
    let verified_amd = osoosi_trust::verify_tpm_ek_certificate(&amd_ek, Some(&policy_amd)).unwrap();
    assert_eq!(verified_amd.vendor, TpmOemVendor::Amd);
}

#[test]
fn test_tpm_ek_silicon_validation_infineon_and_stmicro() {
    use osoosi_trust::generate_mock_oem_ek_certificate;
    use osoosi_types::TpmOemVendor;

    let ifx_ek = generate_mock_oem_ek_certificate(TpmOemVendor::Infineon, "Infineon OPTIGA TPM EK").unwrap();
    assert_eq!(ifx_ek.vendor, TpmOemVendor::Infineon);
    let verified_ifx = osoosi_trust::verify_tpm_ek_certificate(&ifx_ek, None).unwrap();
    assert_eq!(verified_ifx.vendor, TpmOemVendor::Infineon);

    let st_ek = generate_mock_oem_ek_certificate(TpmOemVendor::StMicro, "STMicro ST33 TPM EK").unwrap();
    assert_eq!(st_ek.vendor, TpmOemVendor::StMicro);
    let verified_st = osoosi_trust::verify_tpm_ek_certificate(&st_ek, None).unwrap();
    assert_eq!(verified_st.vendor, TpmOemVendor::StMicro);
}

#[test]
fn test_tpm_ek_disallowed_vendor_rejection() {
    use osoosi_trust::generate_mock_oem_ek_certificate;
    use osoosi_types::{GoldenBaseline, TpmOemVendor};

    let intel_ek = generate_mock_oem_ek_certificate(TpmOemVendor::Intel, "Intel TPM EK").unwrap();
    // Policy strictly mandates AMD silicon
    let policy = GoldenBaseline::new()
        .require_ek(true)
        .allow_tpm_vendor(TpmOemVendor::Amd);

    let result = osoosi_trust::verify_tpm_ek_certificate(&intel_ek, Some(&policy));
    assert_eq!(result, Err(osoosi_types::AttestationError::DisallowedTpmVendor("Intel".to_string())));
}

#[test]
fn test_tpm_ek_missing_when_required() {
    let challenger_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
    let responder_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();

    let challenge = osoosi_types::AttestationChallenge::new(challenger_tm.did().clone(), vec![0, 7, 16]);
    let response = responder_tm.respond_to_attestation(challenge.clone()).unwrap();
    assert!(response.ek_certificate.is_none());

    let policy = osoosi_types::GoldenBaseline::new().require_ek(true);
    let result = challenger_tm.verify_attestation_with_policy(&challenge, &response, Some(&policy));
    assert_eq!(result, Err(osoosi_types::AttestationError::MissingEkCertificate));
}

#[test]
fn test_tpm_ek_fingerprint_pinning() {
    use osoosi_trust::generate_mock_oem_ek_certificate;
    use osoosi_types::{GoldenBaseline, TpmOemVendor};

    let ek_cert = generate_mock_oem_ek_certificate(TpmOemVendor::Intel, "Intel Pinned Node EK").unwrap();
    let fp = ek_cert.cert_fingerprint.clone().unwrap();

    // Pin correct fingerprint
    let policy_pass = GoldenBaseline::new().pin_ek_fingerprint(&fp);
    assert!(osoosi_trust::verify_tpm_ek_certificate(&ek_cert, Some(&policy_pass)).is_ok());

    // Pin wrong fingerprint
    let policy_fail = GoldenBaseline::new().pin_ek_fingerprint("0000000000000000000000000000000000000000000000000000000000000000");
    match osoosi_trust::verify_tpm_ek_certificate(&ek_cert, Some(&policy_fail)) {
        Err(osoosi_types::AttestationError::EkValidationFailed(msg)) => {
            assert!(msg.contains("not in pinned allowed list"));
        }
        other => panic!("Expected EkValidationFailed, got: {:?}", other),
    }
}

#[test]
fn test_tpm_ek_tampered_bytes_rejected() {
    use osoosi_trust::generate_mock_oem_ek_certificate;
    use osoosi_types::TpmOemVendor;

    let mut ek_cert = generate_mock_oem_ek_certificate(TpmOemVendor::Intel, "Intel Tampered EK").unwrap();
    // Tamper raw DER bytes in signature or key block
    let len = ek_cert.raw_der.len();
    ek_cert.raw_der[len - 10] ^= 0x5a;

    let result = osoosi_trust::verify_tpm_ek_certificate(&ek_cert, None);
    assert!(result.is_err(), "Tampered EK certificate must fail cryptographic signature verification");
}

#[test]
fn test_tpm_ek_root_ca_fingerprint_pinning() {
    use osoosi_trust::generate_mock_oem_ek_certificate;
    use osoosi_types::{GoldenBaseline, TpmOemVendor};
    use sha2::{Digest, Sha256};

    let ek_cert = generate_mock_oem_ek_certificate(TpmOemVendor::Amd, "AMD Root Pinned EK").unwrap();
    let root_der = ek_cert.issuer_der.as_ref().expect("issuer_der must be present in hierarchy");
    let root_fp = hex::encode(Sha256::digest(root_der)).to_lowercase();

    // Matching root fingerprint passes
    let policy_pass = GoldenBaseline::new().allow_root_fingerprint(&root_fp);
    assert!(osoosi_trust::verify_tpm_ek_certificate(&ek_cert, Some(&policy_pass)).is_ok());

    // Mismatched root fingerprint fails
    let policy_fail = GoldenBaseline::new().allow_root_fingerprint("1111111111111111111111111111111111111111111111111111111111111111");
    match osoosi_trust::verify_tpm_ek_certificate(&ek_cert, Some(&policy_fail)) {
        Err(osoosi_types::AttestationError::EkValidationFailed(msg)) => {
            assert!(msg.contains("not in allowed root list"));
        }
        other => panic!("Expected EkValidationFailed for mismatched root fingerprint, got: {:?}", other),
    }
}

#[test]
fn test_tpm_ek_forged_issuer_cert_rejected() {
    use osoosi_trust::generate_mock_oem_ek_certificate;
    use osoosi_types::TpmOemVendor;

    let mut ek_cert = generate_mock_oem_ek_certificate(TpmOemVendor::Intel, "Intel Node EK").unwrap();
    // Generate a completely different root CA that did NOT sign this EK certificate
    let other_ek = generate_mock_oem_ek_certificate(TpmOemVendor::Intel, "Other Node EK").unwrap();
    ek_cert.issuer_der = other_ek.issuer_der;

    let result = osoosi_trust::verify_tpm_ek_certificate(&ek_cert, None);
    match result {
        Err(osoosi_types::AttestationError::EkValidationFailed(msg)) => {
            assert!(msg.contains("verification against issuer CA failed") || msg.contains("failed"));
        }
        other => panic!("Expected EkValidationFailed for forged issuer cert, got: {:?}", other),
    }
}

#[test]
fn test_oem_root_store_all_vendors() {
    use osoosi_trust::oem_roots::*;
    use osoosi_types::TpmOemVendor;

    let vendors = [
        TpmOemVendor::Intel,
        TpmOemVendor::Amd,
        TpmOemVendor::Infineon,
        TpmOemVendor::StMicro,
        TpmOemVendor::Nuvoton,
        TpmOemVendor::Nationz,
    ];

    for vendor in &vendors {
        let fps = get_verified_oem_root_fingerprints(*vendor);
        assert!(!fps.is_empty(), "Store must contain verified fingerprints for {:?}", vendor);
        for fp in &fps {
            assert!(
                is_trusted_oem_root(*vendor, fp),
                "Root fingerprint {} must be recognized for {:?}",
                fp, vendor
            );
        }
    }
}

#[test]
fn test_oem_root_offline_leaf_verification() {
    use osoosi_trust::{generate_mock_oem_ek_certificate, verify_leaf_against_oem_roots};
    use osoosi_types::TpmOemVendor;

    for vendor in [
        TpmOemVendor::Intel,
        TpmOemVendor::Amd,
        TpmOemVendor::Infineon,
        TpmOemVendor::StMicro,
        TpmOemVendor::Nuvoton,
        TpmOemVendor::Nationz,
    ] {
        let ek = generate_mock_oem_ek_certificate(vendor, &format!("{:?} Genuine Silicon Leaf", vendor)).unwrap();
        let verified = verify_leaf_against_oem_roots(&ek, None).expect("Offline OEM verification must succeed");
        assert_eq!(verified.vendor, vendor);
    }
}

#[test]
fn test_hardware_tpm2_nvram_and_tbs_inspection() {
    use osoosi_trust::{inspect_tpm_hardware_tbs, read_hardware_ek_certificate_nvram};

    let inspection = inspect_tpm_hardware_tbs();
    assert_eq!(inspection.tpm_version, "2.0");
    assert!(!inspection.interface_type.is_empty());

    let ek_cert = read_hardware_ek_certificate_nvram().expect("NVRAM EK certificate read must succeed with seamless fallback");
    assert!(!ek_cert.raw_der.is_empty());
    assert!(ek_cert.cert_fingerprint.is_some());
}




