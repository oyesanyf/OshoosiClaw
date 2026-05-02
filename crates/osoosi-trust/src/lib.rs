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
