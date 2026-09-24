//! Decentralized Trust and Certificate Management.
//!
//! Manages identity (DID), Merkle Proofs, and S2S Certificates.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use osoosi_types::{
    AttestationChallenge, AttestationError, AttestationResponse, GoldenBaseline, NodeDID, TpmQuote,
};
pub use osoosi_types::{
    verify_tpm_ek_certificate, TpmEkCertificate, TpmOemVendor, VerifiedEkIdentity,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use tracing::info;

pub struct TrustManager {
    signing_key: SigningKey,
    did: NodeDID,
    golden_baseline: Option<GoldenBaseline>,
    local_binary_hash: Option<String>,
    local_config_hash: Option<String>,
    local_ek_certificate: Option<TpmEkCertificate>,
    _executor: std::sync::Arc<dyn osoosi_types::SecuredExecutor>,
}

/// Compute canonical digest signed during attestation: Sha256(nonce || binary_hash || config_hash || pcr_digest).
pub fn compute_attestation_digest(
    nonce: &[u8; 32],
    binary_hash: &str,
    config_hash: &str,
    pcr_digest: Option<&str>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(nonce);
    hasher.update(binary_hash.as_bytes());
    hasher.update(config_hash.as_bytes());
    if let Some(pd) = pcr_digest {
        hasher.update(pd.as_bytes());
    }
    hasher.finalize().into()
}

/// Compute SHA256 of the running executable binary, with deterministic fallback.
pub fn compute_local_binary_hash() -> String {
    if let Ok(exe_path) = std::env::current_exe() {
        if let Ok(bytes) = fs::read(&exe_path) {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            return hex::encode(hasher.finalize());
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(b"OSOOSI_LOCAL_BINARY_BASELINE");
    hex::encode(hasher.finalize())
}

/// Compute SHA256 of current mesh configuration.
pub fn compute_local_config_hash() -> String {
    let mesh_config = osoosi_types::load_mesh_listen_config();
    let mut hasher = Sha256::new();
    hasher.update(mesh_config.zone.as_bytes());
    for addr in &mesh_config.listen_addrs {
        hasher.update(addr.as_bytes());
    }
    hex::encode(hasher.finalize())
}

impl TrustManager {
    pub fn new(
        executor: std::sync::Arc<dyn osoosi_types::SecuredExecutor>,
    ) -> anyhow::Result<Self> {
        // In a real app, load this from secure storage/TPM
        let mut csprng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut csprng);
        let public_key = signing_key.verifying_key();

        let did = NodeDID {
            id: format!("did:osoosi:{}", hex::encode(public_key.to_bytes())),
            public_key: hex::encode(public_key.to_bytes()),
        };

        Ok(Self {
            signing_key,
            did,
            golden_baseline: None,
            local_binary_hash: None,
            local_config_hash: None,
            local_ek_certificate: None,
            _executor: executor,
        })
    }

    pub fn with_golden_baseline(mut self, baseline: GoldenBaseline) -> Self {
        self.golden_baseline = Some(baseline);
        self
    }

    pub fn set_golden_baseline(&mut self, baseline: GoldenBaseline) {
        self.golden_baseline = Some(baseline);
    }

    pub fn golden_baseline(&self) -> Option<&GoldenBaseline> {
        self.golden_baseline.as_ref()
    }

    pub fn with_ek_certificate(mut self, ek: TpmEkCertificate) -> Self {
        self.local_ek_certificate = Some(ek);
        self
    }

    pub fn set_ek_certificate(&mut self, ek: TpmEkCertificate) {
        self.local_ek_certificate = Some(ek);
    }

    pub fn ek_certificate(&self) -> Option<&TpmEkCertificate> {
        self.local_ek_certificate.as_ref()
    }

    pub fn set_local_binary_hash(&mut self, hash: String) {
        self.local_binary_hash = Some(hash);
    }

    pub fn set_local_config_hash(&mut self, hash: String) {
        self.local_config_hash = Some(hash);
    }

    /// Generate a Master Node membership proof (signature) for a peer ID.
    pub fn generate_membership_proof(&self, peer_id: &str) -> String {
        let signature = self.signing_key.sign(peer_id.as_bytes());
        hex::encode(signature.to_bytes())
    }

    pub fn did(&self) -> &NodeDID {
        &self.did
    }

    /// Set up a local Certificate Authority (CA) using rcgen (pure Rust).
    pub async fn init_ca(&self, path: &str) -> anyhow::Result<()> {
        use rcgen::{CertificateParams, KeyPair, DistinguishedName, IsCa};

        let path = Path::new(path);
        if !path.exists() {
            fs::create_dir_all(path)?;
        }

        info!("Initializing Osoosi Root CA (pure Rust)...");

        // 1. Generate Root Key and Params
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CountryName, "US");
        params.distinguished_name.push(rcgen::DnType::StateOrProvinceName, "Cyber");
        params.distinguished_name.push(rcgen::DnType::LocalityName, "Decentralized");
        params.distinguished_name.push(rcgen::DnType::OrganizationName, "Osoosi");
        params.distinguished_name.push(rcgen::DnType::OrganizationalUnitName, "Security");
        params.distinguished_name.push(rcgen::DnType::CommonName, "OsoosiRootCA");
        
        let key_pair = KeyPair::generate()?;
        fs::write(path.join("rootCA.key"), key_pair.serialize_pem())?;

        // 2. Generate Root Certificate
        let cert = params.self_signed(&key_pair)?;
        fs::write(path.join("rootCA.crt"), cert.pem())?;

        Ok(())
    }

    /// Issue a Service-to-Service (S2S) Certificate for a peer using rcgen.
    pub async fn issue_certificate(
        &self,
        ca_path: &str,
        peer_did: &str,
        output_path: &str,
    ) -> anyhow::Result<()> {
        use rcgen::{CertificateParams, KeyPair, DistinguishedName, IsCa};

        let ca_path = Path::new(ca_path);
        let out_path = Path::new(output_path);
        if !out_path.exists() {
            fs::create_dir_all(out_path)?;
        }

        info!("Issuing S2S Certificate for node (pure Rust): {}", peer_did);

        // 1. Load CA
        let ca_cert_pem = fs::read_to_string(ca_path.join("rootCA.crt"))?;
        let ca_key_pem = fs::read_to_string(ca_path.join("rootCA.key"))?;
        
        let ca_key_pair = KeyPair::from_pem(&ca_key_pem)?;
        let ca_cert = CertificateParams::from_ca_cert_pem(&ca_cert_pem)?.self_signed(&ca_key_pair)?;

        // 2. Generate Peer Key
        let peer_key_pair = KeyPair::generate()?;
        fs::write(out_path.join("peer.key"), peer_key_pair.serialize_pem())?;

        // 3. Generate Peer Certificate Params
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CountryName, "US");
        params.distinguished_name.push(rcgen::DnType::StateOrProvinceName, "Cyber");
        params.distinguished_name.push(rcgen::DnType::LocalityName, "Node");
        params.distinguished_name.push(rcgen::DnType::OrganizationName, "Osoosi");
        params.distinguished_name.push(rcgen::DnType::CommonName, peer_did);
        params.is_ca = IsCa::NoCa;

        // 4. Sign with CA
        let cert = params.signed_by(&peer_key_pair, &ca_cert, &ca_key_pair)?;

        fs::write(out_path.join("peer.crt"), cert.pem())?;

        Ok(())
    }

    /// Process a challenge for Mutual Attestation with TPM 2.0 PCR quote generation.
    pub fn respond_to_attestation(
        &self,
        challenge: AttestationChallenge,
    ) -> anyhow::Result<AttestationResponse> {
        let binary_hash = self
            .local_binary_hash
            .clone()
            .unwrap_or_else(compute_local_binary_hash);
        let config_hash = self
            .local_config_hash
            .clone()
            .unwrap_or_else(compute_local_config_hash);

        let pcr_selection = if challenge.pcr_selection.is_empty() {
            vec![0, 7, 16]
        } else {
            challenge.pcr_selection.clone()
        };

        // Query PCRs from TPM facility / clean fallback
        let mut pcr_values = std::collections::BTreeMap::new();
        let mut all_hardware = true;
        for &idx in &pcr_selection {
            let (val, hw) = osoosi_audit::tpm::get_pcr_value(idx);
            if !hw {
                all_hardware = false;
            }
            pcr_values.insert(idx, val);
        }

        // Composite PCR digest: Sha256(sum_i (idx_i || PCR_i))
        let pcr_digest = osoosi_audit::tpm::compute_pcr_composite_digest(&pcr_values);

        // Quoted digest binding challenge nonce and composite PCR digest
        let mut quote_hasher = Sha256::new();
        quote_hasher.update(&challenge.nonce);
        quote_hasher.update(pcr_digest.as_bytes());
        let quoted_digest = hex::encode(quote_hasher.finalize());

        let tpm_quote = TpmQuote {
            pcr_digest: pcr_digest.clone(),
            pcr_indices: pcr_selection,
            quoted_digest,
            hardware_backed: all_hardware,
            raw_quote: None,
        };

        // Sign digest of (nonce + binary_hash + config_hash + pcr_digest)
        let msg = compute_attestation_digest(
            &challenge.nonce,
            &binary_hash,
            &config_hash,
            Some(&pcr_digest),
        );
        let signature = self.signing_key.sign(&msg);

        // Extend audit records for attestation results to TPM PCR 16
        let audit_hash = hex::encode(Sha256::digest(
            format!("{}:{}", hex::encode(challenge.nonce), pcr_digest).as_bytes(),
        ));
        osoosi_audit::tpm::extend_audit_to_tpm("attestation_response", &audit_hash);

        Ok(AttestationResponse {
            challenge_nonce: challenge.nonce,
            binary_hash,
            config_hash,
            responder_did: self.did.clone(),
            signature: hex::encode(signature.to_bytes()),
            pcr_values,
            tpm_quote: Some(tpm_quote),
            ek_certificate: self.local_ek_certificate.clone(),
        })
    }

    /// Verify an attestation response against a challenge and optional Golden Baseline policy.
    pub fn verify_attestation_with_policy(
        &self,
        challenge: &AttestationChallenge,
        response: &AttestationResponse,
        policy: Option<&GoldenBaseline>,
    ) -> Result<(), AttestationError> {
        let policy = policy.or(self.golden_baseline.as_ref());
        verify_attestation_with_policy(challenge, response, policy)
    }

    /// Verify a peer's attestation response (boolean outcome).
    pub fn verify_attestation(
        &self,
        challenge: &AttestationChallenge,
        response: &AttestationResponse,
    ) -> bool {
        self.verify_attestation_with_policy(challenge, response, None).is_ok()
    }
}

/// Standalone attestation verification with optional Golden Baseline policy evaluation.
/// Validates nonces, signature math, TPM quotes, requested PCR registers, and policy constraints,
/// recording immutable audit events directly to TPM PCR 16.
pub fn verify_attestation_with_policy(
    challenge: &AttestationChallenge,
    response: &AttestationResponse,
    policy: Option<&GoldenBaseline>,
) -> Result<(), AttestationError> {
    // 1. Replay attack defense: verify challenge nonce matches
    if response.challenge_nonce != challenge.nonce {
        let _ = osoosi_audit::tpm::extend_audit_to_tpm(
            "attestation_failed",
            &hex::encode(Sha256::digest(b"nonce_mismatch")),
        );
        return Err(AttestationError::NonceReplayDetected);
    }

    // Verify challenge timestamp age (default 300s TTL if policy unspecified)
    let max_nonce_age = policy.map(|p| p.max_nonce_age_secs).unwrap_or(300);
    if max_nonce_age > 0 {
        let age = (chrono::Utc::now() - challenge.timestamp).num_seconds();
        if age < 0 || age > max_nonce_age as i64 {
            let _ = osoosi_audit::tpm::extend_audit_to_tpm(
                "attestation_failed",
                &hex::encode(Sha256::digest(b"challenge_expired")),
            );
            return Err(AttestationError::NonceReplayDetected);
        }
    }

    // 2. Parse and validate responder DID public key
    let pk_bytes = hex::decode(&response.responder_did.public_key)
        .map_err(|e| AttestationError::InvalidPublicKey(e.to_string()))?;
    if pk_bytes.len() != 32 {
        return Err(AttestationError::InvalidPublicKey(
            "Public key must be 32 bytes".to_string(),
        ));
    }
    let verifying_key = VerifyingKey::try_from(pk_bytes.as_slice())
        .map_err(|e| AttestationError::InvalidPublicKey(e.to_string()))?;

    if let Some(did_pub) = response.responder_did.id.strip_prefix("did:osoosi:") {
        if did_pub.len() == 64 && did_pub != response.responder_did.public_key {
            return Err(AttestationError::InvalidPublicKey(
                "DID identifier does not match public key in DID".to_string(),
            ));
        }
    }

    // 3. Hardware TPM enforcement (from policy)
    if let Some(pol) = policy {
        if pol.require_hardware_tpm {
            match &response.tpm_quote {
                Some(quote) if quote.hardware_backed => {}
                _ => {
                    let _ = osoosi_audit::tpm::extend_audit_to_tpm(
                        "attestation_failed",
                        &hex::encode(Sha256::digest(b"hardware_tpm_required")),
                    );
                    return Err(AttestationError::HardwareTpmRequired);
                }
            }
        }
    }

    // 3b. TPM Endorsement Key (EK) and Silicon Chain Validation
    if let Some(ref ek_cert) = response.ek_certificate {
        let verified_ek = verify_tpm_ek_certificate(ek_cert, policy)?;
        let data_hash = hex::encode(Sha256::digest(
            format!("ek_verified:{}:{}", verified_ek.vendor, verified_ek.cert_fingerprint).as_bytes(),
        ));
        let _ = osoosi_audit::tpm::extend_audit_to_tpm("ek_chain_verified", &data_hash);
    } else if let Some(pol) = policy {
        if pol.require_tpm_ek_validation {
            let _ = osoosi_audit::tpm::extend_audit_to_tpm(
                "attestation_failed",
                &hex::encode(Sha256::digest(b"missing_ek_certificate")),
            );
            return Err(AttestationError::MissingEkCertificate);
        }
    }

    // 4. Verify all requested PCRs in challenge.pcr_selection are provided
    for &pcr_idx in &challenge.pcr_selection {
        if !response.pcr_values.contains_key(&pcr_idx) {
            let _ = osoosi_audit::tpm::extend_audit_to_tpm(
                "attestation_failed",
                &hex::encode(Sha256::digest(format!("missing_pcr_{}", pcr_idx).as_bytes())),
            );
            return Err(AttestationError::MissingPcr(pcr_idx));
        }
    }
    if !challenge.pcr_selection.is_empty() && response.tpm_quote.is_none() {
        let _ = osoosi_audit::tpm::extend_audit_to_tpm(
            "attestation_failed",
            &hex::encode(Sha256::digest(b"missing_tpm_quote_for_pcrs")),
        );
        return Err(AttestationError::MissingPcr(challenge.pcr_selection[0]));
    }

    // 5. Verify TPM Quote integrity if quote is present
    let pcr_digest_opt = if let Some(ref quote) = response.tpm_quote {
        // Verify quote contains all requested PCR indices
        for &pcr_idx in &challenge.pcr_selection {
            if !quote.pcr_indices.contains(&pcr_idx) {
                let _ = osoosi_audit::tpm::extend_audit_to_tpm(
                    "attestation_failed",
                    &hex::encode(Sha256::digest(format!("quote_missing_pcr_{}", pcr_idx).as_bytes())),
                );
                return Err(AttestationError::MissingPcr(pcr_idx));
            }
        }

        // Recompute composite PCR digest
        let recomputed_pcr_digest =
            osoosi_audit::tpm::compute_pcr_composite_digest(&response.pcr_values);
        if recomputed_pcr_digest != quote.pcr_digest {
            let _ = osoosi_audit::tpm::extend_audit_to_tpm(
                "attestation_failed",
                &hex::encode(Sha256::digest(b"pcr_digest_mismatch")),
            );
            return Err(AttestationError::QuoteDigestMismatch {
                expected: quote.pcr_digest.clone(),
                actual: recomputed_pcr_digest,
            });
        }

        // Verify quoted digest: Sha256(challenge_nonce || pcr_digest)
        let mut quote_hasher = Sha256::new();
        quote_hasher.update(&challenge.nonce);
        quote_hasher.update(quote.pcr_digest.as_bytes());
        let expected_quoted_digest = hex::encode(quote_hasher.finalize());
        if expected_quoted_digest != quote.quoted_digest {
            let _ = osoosi_audit::tpm::extend_audit_to_tpm(
                "attestation_failed",
                &hex::encode(Sha256::digest(b"quoted_digest_mismatch")),
            );
            return Err(AttestationError::QuoteDigestMismatch {
                expected: expected_quoted_digest,
                actual: quote.quoted_digest.clone(),
            });
        }

        Some(quote.pcr_digest.as_str())
    } else {
        None
    };

    // 6. Verify Ed25519 signature
    let msg = compute_attestation_digest(
        &challenge.nonce,
        &response.binary_hash,
        &response.config_hash,
        pcr_digest_opt,
    );

    let sig_bytes = hex::decode(&response.signature)
        .map_err(|_| AttestationError::InvalidSignature)?;
    let signature = Signature::try_from(sig_bytes.as_slice())
        .map_err(|_| AttestationError::InvalidSignature)?;

    if verifying_key.verify(&msg, &signature).is_err() {
        let _ = osoosi_audit::tpm::extend_audit_to_tpm(
            "attestation_failed",
            &hex::encode(Sha256::digest(b"invalid_signature")),
        );
        return Err(AttestationError::InvalidSignature);
    }

    // 7. Golden Baseline policy validation
    if let Some(pol) = policy {
        if !pol.allowed_binary_hashes.is_empty()
            && !pol.allowed_binary_hashes.contains(&response.binary_hash)
        {
            let _ = osoosi_audit::tpm::extend_audit_to_tpm(
                "attestation_failed",
                &hex::encode(Sha256::digest(response.binary_hash.as_bytes())),
            );
            return Err(AttestationError::BinaryHashMismatch {
                actual: response.binary_hash.clone(),
            });
        }

        if !pol.allowed_config_hashes.is_empty()
            && !pol.allowed_config_hashes.contains(&response.config_hash)
        {
            let _ = osoosi_audit::tpm::extend_audit_to_tpm(
                "attestation_failed",
                &hex::encode(Sha256::digest(response.config_hash.as_bytes())),
            );
            return Err(AttestationError::ConfigHashMismatch {
                actual: response.config_hash.clone(),
            });
        }

        for (pcr_idx, expected_vals) in &pol.expected_pcrs {
            if let Some(actual_val) = response.pcr_values.get(pcr_idx) {
                if !expected_vals.is_empty() && !expected_vals.contains(actual_val) {
                    let _ = osoosi_audit::tpm::extend_audit_to_tpm(
                        "attestation_failed",
                        &hex::encode(Sha256::digest(
                            format!("pcr_{}:{}", pcr_idx, actual_val).as_bytes(),
                        )),
                    );
                    return Err(AttestationError::PcrMismatch {
                        pcr_index: *pcr_idx,
                        actual: actual_val.clone(),
                    });
                }
            } else if !expected_vals.is_empty() {
                let _ = osoosi_audit::tpm::extend_audit_to_tpm(
                    "attestation_failed",
                    &hex::encode(Sha256::digest(format!("missing_pcr_{}", pcr_idx).as_bytes())),
                );
                return Err(AttestationError::MissingPcr(*pcr_idx));
            }
        }
    }

    // Extend audit records for attestation results to TPM PCR 16
    let data_hash = hex::encode(Sha256::digest(
        format!(
            "{}:{}",
            response.responder_did.id,
            hex::encode(challenge.nonce)
        )
        .as_bytes(),
    ));
    osoosi_audit::tpm::extend_audit_to_tpm("attestation_verified", &data_hash);

    Ok(())
}

/// Generate a mock hardware OEM Endorsement Key (EK) certificate for tests and silicon anchoring validation.
pub fn generate_mock_oem_ek_certificate(
    vendor: TpmOemVendor,
    common_name: &str,
) -> anyhow::Result<TpmEkCertificate> {
    use rcgen::{CertificateParams, DistinguishedName, KeyPair};

    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    let org = match vendor {
        TpmOemVendor::Intel => "Intel Corporation",
        TpmOemVendor::Amd => "Advanced Micro Devices",
        TpmOemVendor::Infineon => "Infineon Technologies AG",
        TpmOemVendor::StMicro => "STMicroelectronics",
        TpmOemVendor::Nuvoton => "Nuvoton Technology",
        TpmOemVendor::Microchip => "Microchip Technology Inc.",
        TpmOemVendor::Unknown => "Unknown Hardware OEM",
    };
    params.distinguished_name.push(rcgen::DnType::OrganizationName, org);
    params.distinguished_name.push(rcgen::DnType::CommonName, common_name);

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    let raw_der = cert.der().to_vec();

    TpmEkCertificate::from_der(raw_der).map_err(|e| anyhow::anyhow!("{}", e))
}
