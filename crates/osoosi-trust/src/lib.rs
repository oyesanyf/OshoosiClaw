//! Decentralized Trust and Certificate Management.
//!
//! Manages identity (DID), Merkle Proofs, and S2S Certificates.

use std::process::Command;
use std::path::Path;
use osoosi_types::{NodeDID, AttestationChallenge, AttestationResponse};
use ed25519_dalek::{SigningKey, Signer, VerifyingKey, Verifier, Signature};
use sha2::{Sha256, Digest};
use tracing::info;
use std::fs;

pub struct TrustManager {
    signing_key: SigningKey,
    did: NodeDID,
}

impl TrustManager {
    pub fn new() -> anyhow::Result<Self> {
        // In a real app, load this from secure storage/TPM
        let mut csprng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut csprng);
        let public_key = signing_key.verifying_key();
        
        let did = NodeDID {
            id: format!("did:osoosi:{}", hex::encode(public_key.to_bytes())),
            public_key: hex::encode(public_key.to_bytes()),
        };

        Ok(Self { signing_key, did })
    }

    /// Generate a Master Node membership proof (signature) for a peer ID.
    pub fn generate_membership_proof(&self, peer_id: &str) -> String {
        let signature = self.signing_key.sign(peer_id.as_bytes());
        hex::encode(signature.to_bytes())
    }

    pub fn did(&self) -> &NodeDID {
        &self.did
    }

    /// Set up a local Certificate Authority (CA) using OpenSSL.
    pub fn init_ca(&self, path: &str) -> anyhow::Result<()> {
        let path = Path::new(path);
        if !path.exists() {
            fs::create_dir_all(path)?;
        }

        info!("Initializing Osoosi Root CA...");

        // 1. Generate Root Key
        let output = Command::new("openssl")
            .args([
                "genrsa", "-out", 
                path.join("rootCA.key").to_str().unwrap(), 
                "4096"
            ])
            .output()?;
        if !output.status.success() {
            return Err(anyhow::anyhow!("OpenSSL failed to generate CA key: {}", String::from_utf8_lossy(&output.stderr)));
        }

        // 2. Generate Root Certificate
        let output = Command::new("openssl")
            .args([
                "req", "-x509", "-new", "-nodes", 
                "-key", path.join("rootCA.key").to_str().unwrap(),
                "-sha256", "-days", "3650", 
                "-out", path.join("rootCA.crt").to_str().unwrap(),
                "-subj", "/C=US/ST=Cyber/L=Decentralized/O=Osoosi/OU=Security/CN=OsoosiRootCA"
            ])
            .output()?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("OpenSSL failed to generate CA cert: {}", String::from_utf8_lossy(&output.stderr)));
        }

        Ok(())
    }

    /// Issue a Service-to-Service (S2S) Certificate for a peer.
    pub fn issue_certificate(&self, ca_path: &str, peer_did: &str, output_path: &str) -> anyhow::Result<()> {
        let ca_path = Path::new(ca_path);
        let out_path = Path::new(output_path);
        if !out_path.exists() {
            fs::create_dir_all(out_path)?;
        }

        info!("Issuing S2S Certificate for node: {}", peer_did);

        // 1. Generate Peer Key
        Command::new("openssl")
            .args(["genrsa", "-out", out_path.join("peer.key").to_str().unwrap(), "2048"])
            .output()?;

        // 2. Generate CSR (include DID in Common Name)
        let subj = format!("/C=US/ST=Cyber/L=Node/O=Osoosi/CN={}", peer_did);
        Command::new("openssl")
            .args([
                "req", "-new", 
                "-key", out_path.join("peer.key").to_str().unwrap(),
                "-out", out_path.join("peer.csr").to_str().unwrap(),
                "-subj", &subj
            ])
            .output()?;

        // 3. Sign with CA
        let output = Command::new("openssl")
            .args([
                "x509", "-req", 
                "-in", out_path.join("peer.csr").to_str().unwrap(),
                "-CA", ca_path.join("rootCA.crt").to_str().unwrap(),
                "-CAkey", ca_path.join("rootCA.key").to_str().unwrap(),
                "-CAcreateserial", 
                "-out", out_path.join("peer.crt").to_str().unwrap(),
                "-days", "365", "-sha256"
            ])
            .output()?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("OpenSSL failed to sign peer cert: {}", String::from_utf8_lossy(&output.stderr)));
        }

        Ok(())
    }

    /// Process a challenge for Mutual Attestation.
    pub fn respond_to_attestation(&self, challenge: AttestationChallenge) -> anyhow::Result<AttestationResponse> {
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
    pub fn verify_attestation(&self, challenge: &AttestationChallenge, response: &AttestationResponse) -> bool {
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
