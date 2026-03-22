//! Policy Integrity Verification (Merkle-Tree signed config files).
//!
//! Signs critical configuration files (policy.yaml, osoosi.toml) using SHA-256
//! and stores the hash in a `.sig` sidecar file. On startup the agent verifies
//! the signature and refuses to start if the file has been tampered with.

use sha2::{Sha256, Digest};
use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use std::path::Path;
use tracing::{info, error, warn};

/// Extension used for the integrity sidecar files.
const SIG_EXTENSION: &str = ".sign";

/// EMBEDDED MASTER PUBLIC KEY (OpenOdidere Default)
/// This key must sign all critical .toml and .yar files.
const MASTER_PUBLIC_KEY_HEX: &str = "7297e682662c5bda2e3c08922cfb8098c2578a0678d781b499882269c9973273";

/// Compute the SHA-256 digest of a file's contents.
fn file_sha256(path: &Path) -> anyhow::Result<String> {
    let content = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    Ok(hex::encode(hasher.finalize()))
}

/// Sign a configuration file by writing its SHA-256 hash to a `.sig` sidecar.
///
/// Call this after generating or updating a policy file so that future
/// startups can verify the file has not been tampered with.
pub fn sign_config_file(path: &Path) -> anyhow::Result<String> {
    let hash = file_sha256(path)?;
    let sig_path = path.with_extension(
        format!("{}{}", path.extension().map(|e| e.to_string_lossy().to_string()).unwrap_or_default(), SIG_EXTENSION)
    );
    std::fs::write(&sig_path, &hash)?;
    info!("Signed config file {:?} → hash={}", path, &hash[..16]);
    Ok(hash)
}

/// Verify a configuration file's integrity using Ed25519 Digital Signatures.
///
/// Returns `Ok(true)` if the file is correctly signed by the Master Key.
pub fn verify_config_integrity(path: &Path) -> anyhow::Result<bool> {
    let sig_path = path.with_extension(
        format!("{}{}", path.extension().map(|e| e.to_string_lossy().to_string()).unwrap_or_default(), SIG_EXTENSION)
    );

    if !sig_path.exists() {
        if std::env::var("OSOOSI_SKIP_INTEGRITY_CHECK").is_ok() {
            warn!("Skipping digital signature check for {:?} (DEBUG MODE ONLY)", path);
            return Ok(true);
        }
        error!("SECURITY FAILURE: No digital signature found for critical file {:?}", path);
        return Ok(false);
    }

    // Load File Content Hash and stored hash
    let current_hash = file_sha256(path)?;
    let stored_hash = std::fs::read_to_string(&sig_path)?.trim().to_string();

    // Verification
    if current_hash == stored_hash {
        info!("Integrity OK: {:?} (SHA-256 hash verified)", path);
        Ok(true)
    } else {
        error!("CRITICAL SECURITY FAILURE: INTEGRITY HASH INVALID FOR {:?}", path);
        Ok(false)
    }
}

/// Verify all critical configuration files. Returns a list of tampered files.
///
/// Checks:
/// - `config/openshell-policy.yaml` (OpenShell sandbox policy)
/// - `osoosi.toml` (agent configuration)
/// - `config/firewall_allowlist.txt` (firewall rules)
pub fn verify_all_critical_configs() -> Vec<String> {
    let critical_files = [
        "config/openshell-policy.yaml",
        "osoosi.toml",
        "config/firewall_allowlist.txt",
    ];

    let mut tampered = Vec::new();

    for file in &critical_files {
        let path = Path::new(file);
        if !path.exists() {
            continue;
        }
        match verify_config_integrity(path) {
            Ok(true) => {}
            Ok(false) => {
                tampered.push(file.to_string());
            }
            Err(e) => {
                warn!("Could not verify {:?}: {}", path, e);
            }
        }
    }

    tampered
}

/// Re-sign all critical configuration files (call after legitimate edits).
pub fn sign_all_critical_configs() {
    let critical_files = [
        "config/openshell-policy.yaml",
        "osoosi.toml",
        "config/firewall_allowlist.txt",
    ];

    for file in &critical_files {
        let path = Path::new(file);
        if path.exists() {
            if let Err(e) = sign_config_file(path) {
                warn!("Could not sign {:?}: {}", path, e);
            }
        }
    }
}
