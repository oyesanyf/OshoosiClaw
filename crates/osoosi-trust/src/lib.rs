//! Decentralized Trust and Certificate Management.
//!
//! Manages identity (DID), Merkle Proofs, and S2S Certificates.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use osoosi_types::{AttestationChallenge, AttestationResponse, NodeDID};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use tracing::info;

pub struct TrustManager {
    signing_key: SigningKey,
    did: NodeDID,
    _executor: std::sync::Arc<dyn osoosi_types::SecuredExecutor>,
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
            _executor: executor,
        })
    }

    /// Generate a Master Node membership proof (signature) for a peer ID.
    pub fn generate_membership_proof(&self, peer_id: &str) -> String {
        let signature = self.signing_key.sign(peer_id.as_bytes());
        hex::encode(signature.to_bytes())
    }

    pub fn did(&self) -> &NodeDID {
        &self.did
    }

    /// Set up a local Certificate Authority (CA) using OpenSSL library.
    pub async fn init_ca(&self, path: &str) -> anyhow::Result<()> {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509NameBuilder, X509};

        let path = Path::new(path);
        if !path.exists() {
            fs::create_dir_all(path)?;
        }

        info!("Initializing Osoosi Root CA (library-based)...");

        // 1. Generate Root Key
        let rsa = Rsa::generate(4096)?;
        let priv_key = PKey::from_rsa(rsa)?;
        fs::write(path.join("rootCA.key"), priv_key.private_key_to_pem_pkcs8()?)?;

        // 2. Generate Root Certificate
        let mut x509_name = X509NameBuilder::new()?;
        x509_name.append_entry_by_text("C", "US")?;
        x509_name.append_entry_by_text("ST", "Cyber")?;
        x509_name.append_entry_by_text("L", "Decentralized")?;
        x509_name.append_entry_by_text("O", "Osoosi")?;
        x509_name.append_entry_by_text("OU", "Security")?;
        x509_name.append_entry_by_text("CN", "OsoosiRootCA")?;
        let x509_name = x509_name.build();

        let mut cert_builder = X509::builder()?;
        cert_builder.set_version(2)?;
        let serial_number = openssl::bn::BigNum::from_u32(1)?.to_asn1_integer()?;
        cert_builder.set_serial_number(&serial_number)?;
        cert_builder.set_subject_name(&x509_name)?;
        cert_builder.set_issuer_name(&x509_name)?;
        cert_builder.set_pubkey(&priv_key)?;

        let not_before = Asn1Time::days_from_now(0)?;
        cert_builder.set_not_before(&not_before)?;
        let not_after = Asn1Time::days_from_now(3650)?;
        cert_builder.set_not_after(&not_after)?;

        cert_builder.sign(&priv_key, MessageDigest::sha256())?;
        let cert = cert_builder.build();

        fs::write(path.join("rootCA.crt"), cert.to_pem()?)?;

        Ok(())
    }

    /// Issue a Service-to-Service (S2S) Certificate for a peer.
    pub async fn issue_certificate(
        &self,
        ca_path: &str,
        peer_did: &str,
        output_path: &str,
    ) -> anyhow::Result<()> {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509NameBuilder, X509Req, X509};

        let ca_path = Path::new(ca_path);
        let out_path = Path::new(output_path);
        if !out_path.exists() {
            fs::create_dir_all(out_path)?;
        }

        info!("Issuing S2S Certificate for node (library-based): {}", peer_did);

        // 1. Load CA
        let ca_cert_pem = fs::read(ca_path.join("rootCA.crt"))?;
        let ca_cert = X509::from_pem(&ca_cert_pem)?;
        let ca_key_pem = fs::read(ca_path.join("rootCA.key"))?;
        let ca_key = PKey::private_key_from_pem(&ca_key_pem)?;

        // 2. Generate Peer Key
        let rsa = Rsa::generate(2048)?;
        let peer_key = PKey::from_rsa(rsa)?;
        fs::write(out_path.join("peer.key"), peer_key.private_key_to_pem_pkcs8()?)?;

        // 3. Generate CSR
        let mut x509_name = X509NameBuilder::new()?;
        x509_name.append_entry_by_text("C", "US")?;
        x509_name.append_entry_by_text("ST", "Cyber")?;
        x509_name.append_entry_by_text("L", "Node")?;
        x509_name.append_entry_by_text("O", "Osoosi")?;
        x509_name.append_entry_by_text("CN", peer_did)?;
        let x509_name = x509_name.build();

        let mut req_builder = X509Req::builder()?;
        req_builder.set_subject_name(&x509_name)?;
        req_builder.set_pubkey(&peer_key)?;
        req_builder.sign(&peer_key, MessageDigest::sha256())?;
        let req = req_builder.build();

        // 4. Sign with CA
        let mut cert_builder = X509::builder()?;
        cert_builder.set_version(2)?;
        let serial_number = openssl::bn::BigNum::from_u32(2)?.to_asn1_integer()?; // Simplified serial
        cert_builder.set_serial_number(&serial_number)?;
        cert_builder.set_subject_name(req.subject_name())?;
        cert_builder.set_issuer_name(ca_cert.subject_name())?;
        cert_builder.set_pubkey(&peer_key)?;

        let not_before = Asn1Time::days_from_now(0)?;
        cert_builder.set_not_before(&not_before)?;
        let not_after = Asn1Time::days_from_now(365)?;
        cert_builder.set_not_after(&not_after)?;

        cert_builder.sign(&ca_key, MessageDigest::sha256())?;
        let cert = cert_builder.build();

        fs::write(out_path.join("peer.crt"), cert.to_pem()?)?;

        Ok(())
    }

    /// Process a challenge for Mutual Attestation.
    pub fn respond_to_attestation(
        &self,
        challenge: AttestationChallenge,
    ) -> anyhow::Result<AttestationResponse> {
        // In a real system, we'd hash the actual binary file
        let binary_hash = "f1e2d3c4b5a6...".to_string(); // Placeholder
        let config_hash = "c0d3...".to_string();

        let mut hasher = Sha256::new();
        hasher.update(challenge.nonce);
        hasher.update(binary_hash.as_bytes());
        hasher.update(config_hash.as_bytes());
        let msg = hasher.finalize();

        let signature = self.signing_key.sign(&msg);

        Ok(AttestationResponse {
            challenge_nonce: challenge.nonce,
            binary_hash,
            config_hash,
            responder_did: self.did.clone(),
            signature: hex::encode(signature.to_bytes()),
        })
    }

    /// Verify a peer's attestation response.
    pub fn verify_attestation(
        &self,
        challenge: &AttestationChallenge,
        response: &AttestationResponse,
    ) -> bool {
        let pk_bytes = match hex::decode(&response.responder_did.public_key) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let verifying_key = match VerifyingKey::try_from(pk_bytes.as_slice()) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let mut hasher = Sha256::new();
        hasher.update(challenge.nonce);
        hasher.update(response.binary_hash.as_bytes());
        hasher.update(response.config_hash.as_bytes());
        let msg = hasher.finalize();

        let sig_bytes = match hex::decode(&response.signature) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let signature = match Signature::try_from(sig_bytes.as_slice()) {
            Ok(s) => s,
            Err(_) => return false,
        };

        verifying_key.verify(&msg, &signature).is_ok()
    }
}
