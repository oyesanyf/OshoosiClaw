//! Decentralized Trust Model for Odídẹrẹ́.
//!
//! Includes Decentralized Identifiers (DID), Proof of Execution (PoE),
//! and Mutual Attestation structures.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A Decentralized Identifier (DID) representing an Odídẹrẹ́ node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeDID {
    pub id: String,         // e.g., "did:osoosi:12D3KooWN6LE..."
    pub public_key: String, // Hex-encoded Ed25519 public key
}

impl std::fmt::Display for NodeDID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)
    }
}

/// A "Proof of Execution" verifying that a piece of data is part of a node's Merkle Audit Trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_hash: String,
    pub root_hash: String,
    pub siblings: Vec<String>,
    pub index: usize,
}

/// A Trust Certificate issued after a successful Mutual Attestation (challenge-response protocol).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustCertificate {
    pub issuer_did: NodeDID,
    pub subject_did: NodeDID,
    pub binary_hash: String, // Hash of the WASM/Runtime binary verified during attestation
    pub memory_config_hash: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub signature: String,
}

pub fn default_pcr_selection() -> Vec<u32> {
    vec![0, 7, 16]
}

/// A Challenge-Response packet for binary integrity checks and TPM 2.0 attestation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationChallenge {
    pub nonce: [u8; 32],
    pub challenger_did: NodeDID,
    pub timestamp: DateTime<Utc>,
    #[serde(default = "default_pcr_selection")]
    pub pcr_selection: Vec<u32>,
}

impl AttestationChallenge {
    pub fn new(challenger_did: NodeDID, pcr_selection: Vec<u32>) -> Self {
        use rand::RngCore;
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        Self {
            nonce,
            challenger_did,
            timestamp: Utc::now(),
            pcr_selection: if pcr_selection.is_empty() {
                default_pcr_selection()
            } else {
                pcr_selection
            },
        }
    }
}

/// Hardware OEM vendor identifying the physical TPM silicon manufacturer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TpmOemVendor {
    Intel,
    Amd,
    Infineon,
    StMicro,
    Nuvoton,
    Microchip,
    Unknown,
}

impl std::fmt::Display for TpmOemVendor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Intel => write!(f, "Intel"),
            Self::Amd => write!(f, "AMD"),
            Self::Infineon => write!(f, "Infineon"),
            Self::StMicro => write!(f, "STMicroelectronics"),
            Self::Nuvoton => write!(f, "Nuvoton"),
            Self::Microchip => write!(f, "Microchip"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// TPM Endorsement Key (EK) Certificate proving physical hardware silicon provenance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TpmEkCertificate {
    /// Raw DER-encoded X.509 certificate provisioned by the TPM manufacturer
    pub raw_der: Vec<u8>,
    /// Optional DER-encoded issuing CA or OEM Root CA certificate in the silicon chain
    #[serde(default)]
    pub issuer_der: Option<Vec<u8>>,
    /// Hardware OEM vendor (e.g. Intel, AMD, Infineon, STMicro)
    pub vendor: TpmOemVendor,
    /// Subject Common Name or Serial Number from the EK certificate
    #[serde(default)]
    pub subject: Option<String>,
    /// Issuer Common Name or Organization from the EK certificate
    #[serde(default)]
    pub issuer: Option<String>,
    /// SHA-256 fingerprint (lowercase hex) of the raw DER certificate
    #[serde(default)]
    pub cert_fingerprint: Option<String>,
    /// Public key bytes (hex) extracted from the EK certificate
    #[serde(default)]
    pub public_key_hex: Option<String>,
}

impl TpmEkCertificate {
    /// Parse and construct a TpmEkCertificate from raw DER bytes with OEM vendor detection.
    pub fn from_der(raw_der: Vec<u8>) -> Result<Self, String> {
        use sha2::{Digest, Sha256};
        use x509_parser::prelude::*;

        let (_, cert) = X509Certificate::from_der(&raw_der)
            .map_err(|e| format!("Failed to parse X.509 DER EK certificate: {}", e))?;

        let subject = cert.subject().to_string();
        let issuer = cert.issuer().to_string();
        let cert_fingerprint = hex::encode(Sha256::digest(&raw_der)).to_lowercase();
        let public_key_hex = hex::encode(cert.public_key().raw);

        // Detect vendor from Issuer or Subject
        let issuer_lc = issuer.to_lowercase();
        let subject_lc = subject.to_lowercase();
        let vendor = if issuer_lc.contains("intel") || subject_lc.contains("intel") {
            TpmOemVendor::Intel
        } else if issuer_lc.contains("amd") || subject_lc.contains("amd") {
            TpmOemVendor::Amd
        } else if issuer_lc.contains("infineon") || issuer_lc.contains("optiga") || subject_lc.contains("infineon") {
            TpmOemVendor::Infineon
        } else if issuer_lc.contains("stmicro") || issuer_lc.contains("stm32") || subject_lc.contains("stmicro") {
            TpmOemVendor::StMicro
        } else if issuer_lc.contains("nuvoton") || subject_lc.contains("nuvoton") {
            TpmOemVendor::Nuvoton
        } else if issuer_lc.contains("microchip") || issuer_lc.contains("atmel") || subject_lc.contains("microchip") {
            TpmOemVendor::Microchip
        } else {
            TpmOemVendor::Unknown
        };

        Ok(Self {
            raw_der,
            issuer_der: None,
            vendor,
            subject: Some(subject),
            issuer: Some(issuer),
            cert_fingerprint: Some(cert_fingerprint),
            public_key_hex: Some(public_key_hex),
        })
    }
}

/// Hardware or software-anchored TPM 2.0 quote structure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TpmQuote {
    /// Composite digest of all selected PCRs: Sha256(PCR_i || PCR_j || ...)
    pub pcr_digest: String,
    /// Selected PCR indices in this quote
    pub pcr_indices: Vec<u32>,
    /// Quoted digest: Sha256(challenge_nonce || pcr_digest)
    pub quoted_digest: String,
    /// Whether this quote was generated by physical hardware TPM (true) or clean fallback (false)
    pub hardware_backed: bool,
    /// Raw TPM quote bytes if available from TBS / tpm2-tools
    #[serde(default)]
    pub raw_quote: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationResponse {
    pub challenge_nonce: [u8; 32],
    pub binary_hash: String,
    pub config_hash: String,
    pub responder_did: NodeDID,
    pub signature: String, // Signature of (nonce + binary_hash + config_hash + pcr_digest)
    #[serde(default)]
    pub pcr_values: std::collections::BTreeMap<u32, String>,
    #[serde(default)]
    pub tpm_quote: Option<TpmQuote>,
    /// Optional TPM Endorsement Key (EK) certificate proving physical silicon identity.
    #[serde(default)]
    pub ek_certificate: Option<TpmEkCertificate>,
}

/// Golden Baseline policy for attestation verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GoldenBaseline {
    /// Acceptable SHA256 hashes of the executable binary (PCR 0 or binary hash).
    #[serde(default)]
    pub allowed_binary_hashes: Vec<String>,
    /// Acceptable SHA256 hashes of the system/mesh config.
    #[serde(default)]
    pub allowed_config_hashes: Vec<String>,
    /// Acceptable PCR values by PCR index (e.g. PCR 0, PCR 7, PCR 16).
    #[serde(default)]
    pub expected_pcrs: std::collections::BTreeMap<u32, Vec<String>>,
    /// Whether attestation must strictly be hardware-backed (reject software fallback).
    #[serde(default)]
    pub require_hardware_tpm: bool,
    /// Maximum allowed age for challenge nonce in seconds (to prevent replay attacks).
    #[serde(default = "default_max_nonce_age_secs")]
    pub max_nonce_age_secs: u64,
    /// Whether attestation must strictly validate TPM Endorsement Key (EK) silicon provenance.
    #[serde(default)]
    pub require_tpm_ek_validation: bool,
    /// Permitted hardware TPM silicon vendors (empty = allow any recognized OEM vendor).
    #[serde(default)]
    pub allowed_tpm_vendors: Vec<TpmOemVendor>,
    /// Pinned TPM EK certificate SHA-256 fingerprints (empty = allow any verified OEM root).
    #[serde(default)]
    pub pinned_ek_fingerprints: Vec<String>,
    /// Pinned OEM Root CA certificate SHA-256 fingerprints (empty = allow any recognized OEM root).
    #[serde(default)]
    pub allowed_tpm_root_fingerprints: Vec<String>,
}

fn default_max_nonce_age_secs() -> u64 {
    300
}

impl Default for GoldenBaseline {
    fn default() -> Self {
        Self {
            allowed_binary_hashes: Vec::new(),
            allowed_config_hashes: Vec::new(),
            expected_pcrs: std::collections::BTreeMap::new(),
            require_hardware_tpm: false,
            max_nonce_age_secs: default_max_nonce_age_secs(),
            require_tpm_ek_validation: false,
            allowed_tpm_vendors: Vec::new(),
            pinned_ek_fingerprints: Vec::new(),
            allowed_tpm_root_fingerprints: Vec::new(),
        }
    }
}

impl GoldenBaseline {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow_binary_hash(mut self, hash: impl Into<String>) -> Self {
        self.allowed_binary_hashes.push(hash.into());
        self
    }

    pub fn allow_config_hash(mut self, hash: impl Into<String>) -> Self {
        self.allowed_config_hashes.push(hash.into());
        self
    }

    pub fn allow_pcr(mut self, pcr: u32, hash: impl Into<String>) -> Self {
        self.expected_pcrs.entry(pcr).or_default().push(hash.into());
        self
    }

    pub fn require_hardware(mut self, require: bool) -> Self {
        self.require_hardware_tpm = require;
        self
    }

    pub fn with_max_nonce_age(mut self, secs: u64) -> Self {
        self.max_nonce_age_secs = secs;
        self
    }

    pub fn require_ek(mut self, require: bool) -> Self {
        self.require_tpm_ek_validation = require;
        self
    }

    pub fn allow_tpm_vendor(mut self, vendor: TpmOemVendor) -> Self {
        self.allowed_tpm_vendors.push(vendor);
        self
    }

    pub fn pin_ek_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.pinned_ek_fingerprints.push(fingerprint.into().to_lowercase());
        self
    }

    pub fn allow_root_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.allowed_tpm_root_fingerprints.push(fingerprint.into().to_lowercase());
        self
    }
}

/// Errors occurring during mutual attestation and Golden Baseline verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, thiserror::Error)]
pub enum AttestationError {
    #[error("Invalid cryptographic signature")]
    InvalidSignature,
    #[error("Replay attack detected: nonce mismatch or expired challenge")]
    NonceReplayDetected,
    #[error("Corrupted binary hash: actual {actual} not in golden baseline")]
    BinaryHashMismatch { actual: String },
    #[error("Corrupted config hash: actual {actual} not in golden baseline")]
    ConfigHashMismatch { actual: String },
    #[error("PCR {pcr_index} mismatch: actual {actual} does not match golden baseline")]
    PcrMismatch { pcr_index: u32, actual: String },
    #[error("Missing requested PCR {0} in response")]
    MissingPcr(u32),
    #[error("Hardware-backed TPM quote required but software fallback received")]
    HardwareTpmRequired,
    #[error("TPM quote digest verification failed: expected {expected}, actual {actual}")]
    QuoteDigestMismatch { expected: String, actual: String },
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("TPM Endorsement Key (EK) validation failed: {0}")]
    EkValidationFailed(String),
    #[error("TPM OEM vendor {0} not permitted by golden baseline")]
    DisallowedTpmVendor(String),
    #[error("TPM EK certificate required by golden baseline but not provided")]
    MissingEkCertificate,
}

/// Verified hardware TPM identity after successful silicon provenance validation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedEkIdentity {
    pub vendor: TpmOemVendor,
    pub subject: String,
    pub issuer: String,
    pub cert_fingerprint: String,
    pub public_key_hex: String,
}

/// Validate a TPM Endorsement Key (EK) certificate against physical silicon OEM roots
/// (e.g. Intel, AMD, Infineon, STMicroelectronics, Nuvoton, Microchip) and policy constraints.
pub fn verify_tpm_ek_certificate(
    ek_cert: &TpmEkCertificate,
    policy: Option<&GoldenBaseline>,
) -> Result<VerifiedEkIdentity, AttestationError> {
    use sha2::{Digest, Sha256};
    use x509_parser::prelude::*;

    // 1. Parse raw X.509 DER certificate
    let (_, cert) = X509Certificate::from_der(&ek_cert.raw_der)
        .map_err(|e| AttestationError::EkValidationFailed(format!("Invalid X.509 certificate: {}", e)))?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let calculated_fingerprint = hex::encode(Sha256::digest(&ek_cert.raw_der)).to_lowercase();
    let public_key_hex = hex::encode(cert.public_key().raw);

    // 2. Cryptographic signature and silicon root verification
    if let Some(ref issuer_bytes) = ek_cert.issuer_der {
        let (_, issuer_cert) = X509Certificate::from_der(issuer_bytes)
            .map_err(|e| AttestationError::EkValidationFailed(format!("Invalid issuing CA certificate: {}", e)))?;
        cert.verify_signature(Some(&issuer_cert.public_key()))
            .map_err(|e| AttestationError::EkValidationFailed(format!("EK signature verification against issuer CA failed: {}", e)))?;
        if issuer_cert.subject() == issuer_cert.issuer() {
            issuer_cert.verify_signature(Some(&issuer_cert.public_key()))
                .map_err(|e| AttestationError::EkValidationFailed(format!("OEM Root CA self-signature verification failed: {}", e)))?;
        }
    } else if cert.subject() == cert.issuer() {
        // Self-signed certificate (e.g. standalone test or single-tier mock)
        cert.verify_signature(Some(&cert.public_key()))
            .map_err(|e| AttestationError::EkValidationFailed(format!("Self-signed EK certificate signature verification failed: {}", e)))?;
    }

    // 3. Detect and verify OEM Root CA authenticity
    let issuer_lc = issuer.to_lowercase();
    let subject_lc = subject.to_lowercase();

    let recognized_vendor = if issuer_lc.contains("intel") || subject_lc.contains("intel") {
        TpmOemVendor::Intel
    } else if issuer_lc.contains("amd") || subject_lc.contains("amd") {
        TpmOemVendor::Amd
    } else if issuer_lc.contains("infineon") || issuer_lc.contains("optiga") || subject_lc.contains("infineon") {
        TpmOemVendor::Infineon
    } else if issuer_lc.contains("stmicro") || issuer_lc.contains("stm32") || subject_lc.contains("stmicro") {
        TpmOemVendor::StMicro
    } else if issuer_lc.contains("nuvoton") || subject_lc.contains("nuvoton") {
        TpmOemVendor::Nuvoton
    } else if issuer_lc.contains("microchip") || issuer_lc.contains("atmel") || subject_lc.contains("microchip") {
        TpmOemVendor::Microchip
    } else {
        TpmOemVendor::Unknown
    };

    // Reject unknown vendor unless explicitly pinned by fingerprint
    let is_pinned = policy.map(|p| {
        p.pinned_ek_fingerprints.iter().any(|f| f.to_lowercase() == calculated_fingerprint)
    }).unwrap_or(false);

    if recognized_vendor == TpmOemVendor::Unknown && !is_pinned {
        return Err(AttestationError::EkValidationFailed(
            format!("Unrecognized TPM silicon manufacturer: issuer '{}', subject '{}'", issuer, subject)
        ));
    }

    let effective_vendor = if recognized_vendor != TpmOemVendor::Unknown {
        recognized_vendor
    } else {
        ek_cert.vendor
    };

    // 4. Golden Baseline policy enforcement
    if let Some(pol) = policy {
        // Enforce allowed vendors if restricted
        if !pol.allowed_tpm_vendors.is_empty() && !pol.allowed_tpm_vendors.contains(&effective_vendor) {
            return Err(AttestationError::DisallowedTpmVendor(effective_vendor.to_string()));
        }

        // Enforce pinned leaf fingerprints if restricted
        if !pol.pinned_ek_fingerprints.is_empty()
            && !pol.pinned_ek_fingerprints.iter().any(|f| f.to_lowercase() == calculated_fingerprint)
        {
            return Err(AttestationError::EkValidationFailed(
                format!("EK certificate fingerprint {} is not in pinned allowed list", calculated_fingerprint)
            ));
        }

        // Enforce pinned OEM Root CA fingerprints if configured
        if !pol.allowed_tpm_root_fingerprints.is_empty() {
            let root_fp = if let Some(ref ib) = ek_cert.issuer_der {
                hex::encode(Sha256::digest(ib)).to_lowercase()
            } else {
                calculated_fingerprint.clone()
            };
            if !pol.allowed_tpm_root_fingerprints.iter().any(|f| f.to_lowercase() == root_fp) {
                return Err(AttestationError::EkValidationFailed(
                    format!("OEM Root CA fingerprint {} is not in allowed root list", root_fp)
                ));
            }
        }
    }

    Ok(VerifiedEkIdentity {
        vendor: effective_vendor,
        subject,
        issuer,
        cert_fingerprint: calculated_fingerprint,
        public_key_hex,
    })
}

/// Dynamic Reputation Score for EigenTrust-lite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationScore {
    pub node_id: String,
    pub score: f32, // 0.0 to 1.0 (1.0 = absolute trust)
    pub alerts_verified: u64,
    pub false_positives: u64,
    pub last_updated: DateTime<Utc>,
}

/// A peer requesting to join the mesh, awaiting user approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingJoinRequest {
    pub peer_id: String,
    pub multiaddr: Option<String>,
    pub reputation_score: f32,
    pub alerts_verified: u64,
    pub false_positives: u64,
    pub discovered_at: DateTime<Utc>,
}

/// A peer that has been quarantined from the mesh due to suspicious behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantinedPeer {
    pub peer_id: String,
    pub reason: String,
    pub reputation_score: f32,
    pub quarantined_at: DateTime<Utc>,
    pub released_at: Option<DateTime<Utc>>,
    pub active: bool,
}
