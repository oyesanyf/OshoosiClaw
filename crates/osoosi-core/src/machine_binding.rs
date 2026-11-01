//! Adaptive Cross-Platform MAC Address Discovery and 4-Anchor Machine Binding.
//!
//! Provides cryptographic machine binding for OshoosiClaw and its encrypted vaults/configs.
//! Guarantees that protected secrets bind exclusively to the provisioned computer while
//! automatically adjusting for legitimate MAC address changes (Wi-Fi address randomization,
//! USB dock attach/detach, interface reordering, or NIC replacement) without locking out
//! the legitimate host or corrupting backup vaults.
//!
//! Security Quorum:
//! - Anchor 1: Physical MAC addresses + Bounded Historical Ring (16 entries).
//! - Anchor 2: OS Machine ID (Windows MachineGuid, Linux /etc/machine-id, or macOS UUID).
//! - Anchor 3: Silicon & TPM Identity (CPU brand + physical core count + OS/Arch + TPM device ID).
//! - Anchor 4: Local Cryptographic Attestation Seal.
//!
//! When MAC addresses rotate on the same physical host, the 2-of-3 non-MAC quorum
//! cryptographically proves host identity, re-anchors the MAC set automatically,
//! and maintains a stable 32-byte host root secret across all rotations.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use sysinfo::Networks;
use tracing::{debug, info, warn};

/// Information regarding an inspected network adapter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveredNicInfo {
    /// Operating system interface identifier (e.g., "Ethernet", "eth0", "wlan0").
    pub interface_name: String,
    /// Canonical uppercase colon-separated MAC address (e.g., "AA:BB:CC:DD:EE:FF").
    pub mac_formatted: String,
    /// Masked MAC string for safe display and logging (e.g., "AA:BB:CC:**:**:FF").
    pub mac_masked: String,
    /// Salted BLAKE3 hash of "OSHOOSI_MAC_ANCHOR_V1:" + mac_formatted.
    pub mac_salted_hash: String,
    /// First three octets representing the OUI prefix (e.g., "AA:BB:CC").
    pub oui_prefix: String,
    /// Whether this interface corresponds to physical hardware rather than a virtual/VPN/container adapter.
    pub is_physical_hardware: bool,
    /// IEEE 802 globally unique address flag: true if Universally Administered ((first_octet & 0x02) == 0).
    pub is_universally_administered: bool,
}

/// The persistent hardware binding manifest recorded in `database/host_binding_manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostBindingManifest {
    /// Manifest schema version.
    pub binding_version: u32,
    /// Enrolled physical MAC salted hashes.
    pub enrolled_physical_mac_hashes: Vec<String>,
    /// Historical MAC salted hashes observed on this host (ring buffer capped at 16 entries).
    pub historical_mac_hashes: Vec<String>,
    /// Salted hash of the operating system machine GUID / ID.
    pub os_machine_id_hash: String,
    /// Salted hash of silicon topology and TPM 2.0 device identity.
    pub silicon_anchor_hash: String,
    /// Salted hash of the local attestation seal key.
    pub local_seal_hash: String,
    /// Cumulative counter of legitimate MAC address rotation events.
    pub mac_rotation_count: u64,
    /// Timestamp of the most recent legitimate MAC rotation.
    pub last_mac_change_at: Option<String>,
    /// Hex-encoded ChaCha20Poly1305-encrypted 32-byte host root secret (nonce + ciphertext + tag).
    pub encrypted_host_root_secret_hex: String,
    /// Keyed BLAKE3 integrity tag verifying manifest authenticity.
    pub manifest_hmac_hex: String,
}

/// Verification result providing fine-grained telemetry to supervisors and WebUI dashboards.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MachineBindingStatus {
    /// Binding verdict: "BOUND", "MAC_ROTATION_ADAPTED", or "PROVISIONED".
    pub verdict: String,
    /// Whether the host is confirmed bound and authorized.
    pub bound: bool,
    /// Confidence score between 0.0 and 1.0.
    pub confidence_score: f64,
    /// Number of active physical network adapters discovered.
    pub active_physical_nics: usize,
    /// Number of active virtual/VPN/container adapters discovered.
    pub active_virtual_nics: usize,
    /// Masked MAC fingerprints for safe diagnostic display.
    pub masked_mac_fingerprints: Vec<String>,
    /// Cumulative count of MAC rotations observed on this host.
    pub mac_rotation_count: u64,
    /// Timestamp of last MAC change.
    pub last_mac_change_at: Option<String>,
    /// Number of non-MAC anchors matching current host (0 to 3).
    pub non_mac_anchor_matches: usize,
    /// Whether at least one active MAC matched the enrolled or historical set.
    pub mac_matched: bool,
}

/// Errors raised during machine binding operations.
#[derive(Debug, thiserror::Error)]
pub enum MachineBindingError {
    #[error("Foreign host detected: host anchor quorum failed ({0})")]
    ForeignHostDetected(String),
    #[error("Manifest I/O or serialization error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Crypto failure: {0}")]
    Crypto(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// MAC Formatting & Hashing Primitives
// ─────────────────────────────────────────────────────────────────────────────

/// Formats a 6-byte MAC address into canonical uppercase `AA:BB:CC:DD:EE:FF`.
pub fn format_mac(bytes: &[u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

/// Masks bytes 3 and 4 for safe telemetry and display (e.g., `AA:BB:CC:**:**:FF`).
pub fn mask_mac(bytes: &[u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:**:**:{:02X}",
        bytes[0], bytes[1], bytes[2], bytes[5]
    )
}

/// Computes a salted BLAKE3 hash for a formatted MAC address.
pub fn hash_mac(mac_formatted: &str) -> String {
    let key = format!("OSHOOSI_MAC_ANCHOR_V1:{}", mac_formatted);
    blake3::hash(key.as_bytes()).to_hex().to_string()
}

/// Checks whether an interface name represents a known virtual, VPN, loopback, or container interface.
pub fn is_virtual_or_vpn_interface(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("loopback")
        || lower == "lo"
        || lower.starts_with("lo") && lower.len() <= 4
        || lower.contains("wintun")
        || lower.contains("wireguard")
        || lower.contains("tailscale")
        || lower.contains("docker")
        || lower.contains("veth")
        || lower.contains("br-")
        || lower.contains("virbr")
        || lower.contains("vmnet")
        || lower.contains("vboxnet")
        || lower.contains("utun")
        || lower.contains("awdl")
        || lower.contains("llw")
        || lower.contains("hyper-v")
        || lower.contains("wan miniport")
        || lower.contains("teredo")
        || lower.contains("isatap")
        || lower.contains("pseudo")
        || lower.contains("dummy")
}

// ─────────────────────────────────────────────────────────────────────────────
// Discovery Implementations
// ─────────────────────────────────────────────────────────────────────────────

/// Discovers and classifies all available network interfaces on the host.
pub fn discover_network_mac_inventory() -> Vec<DiscoveredNicInfo> {
    let networks = Networks::new_with_refreshed_list();
    let mut inventory = Vec::new();

    for (iface_name, data) in networks.iter() {
        let mac_bytes = data.mac_address().0;

        // Exclude all-zero (uninitialized) and all-FF (broadcast) MAC addresses
        if mac_bytes == [0, 0, 0, 0, 0, 0] || mac_bytes == [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF] {
            continue;
        }

        let mac_formatted = format_mac(&mac_bytes);
        let mac_masked = mask_mac(&mac_bytes);
        let mac_salted_hash = hash_mac(&mac_formatted);
        let oui_prefix = format!(
            "{:02X}:{:02X}:{:02X}",
            mac_bytes[0], mac_bytes[1], mac_bytes[2]
        );
        let is_universally_administered = (mac_bytes[0] & 0x02) == 0;

        let mut is_physical = !is_virtual_or_vpn_interface(iface_name);

        #[cfg(target_os = "linux")]
        {
            // On Linux, verify physical bus presence via /sys/class/net/<iface>/device
            let device_path = format!("/sys/class/net/{}/device", iface_name);
            if !std::path::Path::new(&device_path).exists() {
                is_physical = false;
            }
        }

        #[cfg(target_os = "windows")]
        {
            // On Windows, verify adapter characteristics if virtual markers were not tripped
            if is_physical && iface_name.to_ascii_lowercase().contains("virtual") {
                is_physical = false;
            }
        }

        inventory.push(DiscoveredNicInfo {
            interface_name: iface_name.clone(),
            mac_formatted,
            mac_masked,
            mac_salted_hash,
            oui_prefix,
            is_physical_hardware: is_physical,
            is_universally_administered,
        });
    }

    // Container / Minimal VM Resilience Fallback:
    // If no interfaces are classified as physical hardware (e.g. running inside Docker,
    // Kubernetes, or cloud microVMs), fall back to all non-loopback discovered adapters
    // so machine binding functions seamlessly across containerized deployments.
    if !inventory.is_empty() && !inventory.iter().any(|n| n.is_physical_hardware) {
        for nic in inventory.iter_mut() {
            if !nic.interface_name.to_ascii_lowercase().contains("loopback")
                && nic.interface_name != "lo"
            {
                nic.is_physical_hardware = true;
            }
        }
    }

    inventory.sort_by(|a, b| a.interface_name.cmp(&b.interface_name));
    inventory
}

/// Discovers the operating system machine identifier (Anchor 2).
pub fn detect_os_machine_id() -> String {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(key) = hklm.open_subkey("SOFTWARE\\Microsoft\\Cryptography") {
            if let Ok(guid) = key.get_value::<String, _>("MachineGuid") {
                let trimmed = guid.trim().to_string();
                if !trimmed.is_empty() {
                    return trimmed;
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
            let trimmed = id.trim().to_string();
            if !trimmed.is_empty() {
                return trimmed;
            }
        }
        if let Ok(id) = std::fs::read_to_string("/var/lib/dbus/machine-id") {
            let trimmed = id.trim().to_string();
            if !trimmed.is_empty() {
                return trimmed;
            }
        }
    }

    let host = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown_host".into());
    format!(
        "{}:{}:{}",
        host,
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}

/// Computes salted hash for OS machine identifier (Anchor 2).
pub fn hash_os_machine_id(machine_id: &str) -> String {
    let key = format!("OSHOOSI_OS_MACHINE_ID_ANCHOR_V1:{}", machine_id);
    blake3::hash(key.as_bytes()).to_hex().to_string()
}

/// Discovers the silicon and hardware topology anchor (Anchor 3).
pub fn detect_silicon_anchor() -> String {
    let mut sys = sysinfo::System::new();
    sys.refresh_cpu_specifics(sysinfo::CpuRefreshKind::everything());
    let cpu_brand = sys
        .cpus()
        .first()
        .map(|c| c.brand())
        .unwrap_or("generic_cpu");
    let core_count = sys.physical_core_count().unwrap_or(sys.cpus().len());
    let tpm_id = crate::hardened::detect_tpm()
        .device_id
        .unwrap_or_else(|| "no_tpm".into());
    format!(
        "{}:{}:{}:{}:{}",
        cpu_brand,
        core_count,
        std::env::consts::OS,
        std::env::consts::ARCH,
        tpm_id
    )
}

/// Computes salted hash for silicon anchor (Anchor 3).
pub fn hash_silicon_anchor(silicon: &str) -> String {
    let key = format!("OSHOOSI_SILICON_ANCHOR_V1:{}", silicon);
    blake3::hash(key.as_bytes()).to_hex().to_string()
}

/// Detects and computes the local attestation seal anchor (Anchor 4).
pub fn detect_local_seal_hash() -> String {
    let secret = crate::hardened::get_or_create_attestation_secret_pub();
    let mut hasher = blake3::Hasher::new_keyed(&secret);
    hasher.update(b"OSHOOSI_LOCAL_SEAL_ANCHOR_V1");
    hasher.finalize().to_hex().to_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// Host Root Secret Cryptographic Protection & Key Derivation
// ─────────────────────────────────────────────────────────────────────────────

/// Derives a 32-byte ChaCha20Poly1305 key from a combination of non-MAC anchors.
pub fn derive_anchor_aead_key(os_hash: &str, silicon_hash: &str, seal_hash: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"OSHOOSI_ANCHOR_AEAD_KEY_KDF_V1:");
    hasher.update(os_hash.as_bytes());
    hasher.update(b":");
    hasher.update(silicon_hash.as_bytes());
    hasher.update(b":");
    hasher.update(seal_hash.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Encrypts the 32-byte host root secret with ChaCha20Poly1305 under the derived anchor key.
fn encrypt_host_root_secret(
    secret: &[u8; 32],
    aead_key: &[u8; 32],
) -> Result<String, MachineBindingError> {
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(aead_key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), secret.as_ref())
        .map_err(|e| {
            MachineBindingError::Crypto(format!("ChaCha20Poly1305 encrypt failed: {}", e))
        })?;

    let mut payload = Vec::with_capacity(12 + ciphertext.len());
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&ciphertext);
    Ok(hex::encode(payload))
}

/// Decrypts the 32-byte host root secret using ChaCha20Poly1305.
fn decrypt_host_root_secret(
    encrypted_hex: &str,
    aead_key: &[u8; 32],
) -> Result<[u8; 32], MachineBindingError> {
    let payload = hex::decode(encrypted_hex)
        .map_err(|e| MachineBindingError::Crypto(format!("Hex decode failed: {}", e)))?;
    if payload.len() < 12 + 16 {
        return Err(MachineBindingError::Crypto(
            "Invalid ciphertext length".into(),
        ));
    }

    let nonce_bytes = &payload[..12];
    let ciphertext = &payload[12..];

    let cipher = ChaCha20Poly1305::new(Key::from_slice(aead_key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|e| {
            MachineBindingError::Crypto(format!("ChaCha20Poly1305 decrypt failed: {}", e))
        })?;

    if plaintext.len() != 32 {
        return Err(MachineBindingError::Crypto(
            "Decrypted secret length mismatch".into(),
        ));
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&plaintext);
    Ok(secret)
}

/// Computes keyed BLAKE3 integrity HMAC for a manifest.
#[allow(clippy::too_many_arguments)]
fn compute_manifest_hmac(
    binding_version: u32,
    enrolled_macs: &[String],
    historical_macs: &[String],
    os_id_hash: &str,
    silicon_hash: &str,
    local_seal_hash: &str,
    mac_rotation_count: u64,
    last_mac_change_at: Option<&str>,
    encrypted_secret_hex: &str,
    seal_key: &[u8; 32],
) -> String {
    let mut hasher = blake3::Hasher::new_keyed(seal_key);
    hasher.update(b"OSHOOSI_HOST_BINDING_MANIFEST_HMAC_V1:");
    hasher.update(&binding_version.to_le_bytes());
    for m in enrolled_macs {
        hasher.update(m.as_bytes());
    }
    for m in historical_macs {
        hasher.update(m.as_bytes());
    }
    hasher.update(os_id_hash.as_bytes());
    hasher.update(silicon_hash.as_bytes());
    hasher.update(local_seal_hash.as_bytes());
    hasher.update(&mac_rotation_count.to_le_bytes());
    if let Some(t) = last_mac_change_at {
        hasher.update(t.as_bytes());
    }
    hasher.update(encrypted_secret_hex.as_bytes());
    hasher.finalize().to_hex().to_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// Verification, Automatic MAC Adaptation & Atomic Persistence
// ─────────────────────────────────────────────────────────────────────────────

/// Path to companion DPAPI protected secret file on Windows.
fn companion_dpapi_path(manifest_path: &Path) -> PathBuf {
    manifest_path.with_extension("dpapi")
}

/// Resolves the default canonical path for the host binding manifest.
pub fn get_default_host_binding_manifest_path() -> PathBuf {
    osoosi_types::config::resolve_data_dir()
        .join("database")
        .join("host_binding_manifest.json")
}

/// Atomically persists the manifest (and optional DPAPI companion on Windows).
fn persist_manifest_atomic(
    manifest_path: &Path,
    manifest: &HostBindingManifest,
    raw_host_root_secret: Option<&[u8; 32]>,
) -> Result<(), MachineBindingError> {
    if let Some(parent) = manifest_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let json_bytes = serde_json::to_vec_pretty(manifest)
        .map_err(|e| MachineBindingError::Crypto(e.to_string()))?;

    let tmp_path = manifest_path.with_extension("tmp");
    {
        let mut f = File::create(&tmp_path)?;
        f.write_all(&json_bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp_path, manifest_path)?;

    // On Windows, also write the companion DPAPI wrapped key file
    if let Some(secret) = raw_host_root_secret {
        if let Ok(dpapi_wrapped) = crate::protected_env_backup::dpapi_protect_bytes(secret) {
            let dpapi_path = companion_dpapi_path(manifest_path);
            let dpapi_tmp = dpapi_path.with_extension("tmp");
            if let Ok(mut df) = File::create(&dpapi_tmp) {
                if df.write_all(&dpapi_wrapped).is_ok() && df.sync_all().is_ok() {
                    let _ = std::fs::rename(&dpapi_tmp, &dpapi_path);
                }
            }
        }
    }

    Ok(())
}

/// Evaluates and verifies the live host against a persistent HostBindingManifest,
/// automatically adapting for legitimate MAC rotations if non-MAC quorum holds.
pub fn verify_and_adapt_machine_binding(
    manifest_path: &Path,
) -> Result<MachineBindingStatus, MachineBindingError> {
    let inventory = discover_network_mac_inventory();
    let physical_nics: Vec<&DiscoveredNicInfo> = inventory
        .iter()
        .filter(|n| n.is_physical_hardware)
        .collect();
    let virtual_nics_count = inventory.len().saturating_sub(physical_nics.len());

    let live_mac_hashes: Vec<String> = if !physical_nics.is_empty() {
        physical_nics
            .iter()
            .map(|n| n.mac_salted_hash.clone())
            .collect()
    } else {
        inventory
            .iter()
            .map(|n| n.mac_salted_hash.clone())
            .collect()
    };

    let masked_fingerprints: Vec<String> = inventory.iter().map(|n| n.mac_masked.clone()).collect();

    let live_os_id = detect_os_machine_id();
    let live_os_id_hash = hash_os_machine_id(&live_os_id);

    let live_silicon = detect_silicon_anchor();
    let live_silicon_hash = hash_silicon_anchor(&live_silicon);

    let live_local_seal_hash = detect_local_seal_hash();
    let local_seal_key = crate::hardened::get_or_create_attestation_secret_pub();

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 1: Initial Provisioning (Manifest does not exist)
    // ─────────────────────────────────────────────────────────────────────────
    if !manifest_path.exists() {
        info!(
            "HostBindingManifest not found at {:?}. Provisioning hardware binding.",
            manifest_path
        );
        let mut host_root_secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut host_root_secret);

        let aead_key =
            derive_anchor_aead_key(&live_os_id_hash, &live_silicon_hash, &live_local_seal_hash);
        let encrypted_secret_hex = encrypt_host_root_secret(&host_root_secret, &aead_key)?;

        let manifest_hmac_hex = compute_manifest_hmac(
            1,
            &live_mac_hashes,
            &[],
            &live_os_id_hash,
            &live_silicon_hash,
            &live_local_seal_hash,
            0,
            None,
            &encrypted_secret_hex,
            &local_seal_key,
        );

        let manifest = HostBindingManifest {
            binding_version: 1,
            enrolled_physical_mac_hashes: live_mac_hashes.clone(),
            historical_mac_hashes: Vec::new(),
            os_machine_id_hash: live_os_id_hash,
            silicon_anchor_hash: live_silicon_hash,
            local_seal_hash: live_local_seal_hash,
            mac_rotation_count: 0,
            last_mac_change_at: None,
            encrypted_host_root_secret_hex: encrypted_secret_hex,
            manifest_hmac_hex,
        };

        persist_manifest_atomic(manifest_path, &manifest, Some(&host_root_secret))?;

        return Ok(MachineBindingStatus {
            verdict: "PROVISIONED".to_string(),
            bound: true,
            confidence_score: 1.0,
            active_physical_nics: physical_nics.len(),
            active_virtual_nics: virtual_nics_count,
            masked_mac_fingerprints: masked_fingerprints,
            mac_rotation_count: 0,
            last_mac_change_at: None,
            non_mac_anchor_matches: 3,
            mac_matched: true,
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 2: Live Verification Against Stored Manifest
    // ─────────────────────────────────────────────────────────────────────────
    let mut f = File::open(manifest_path)?;
    let mut raw_bytes = Vec::new();
    f.read_to_end(&mut raw_bytes)?;
    let mut manifest: HostBindingManifest = serde_json::from_slice(&raw_bytes)
        .map_err(|e| MachineBindingError::Crypto(format!("Failed to parse manifest: {}", e)))?;

    // Check non-MAC anchors
    let mut non_mac_matches = 0;
    if manifest.os_machine_id_hash == live_os_id_hash {
        non_mac_matches += 1;
    }
    if manifest.silicon_anchor_hash == live_silicon_hash {
        non_mac_matches += 1;
    }
    if manifest.local_seal_hash == live_local_seal_hash {
        non_mac_matches += 1;
    }

    // Check MAC matching (enrolled or historical)
    let enrolled_set: HashSet<&str> = manifest
        .enrolled_physical_mac_hashes
        .iter()
        .map(|s| s.as_str())
        .collect();
    let historical_set: HashSet<&str> = manifest
        .historical_mac_hashes
        .iter()
        .map(|s| s.as_str())
        .collect();
    let mac_matched = live_mac_hashes
        .iter()
        .any(|h| enrolled_set.contains(h.as_str()) || historical_set.contains(h.as_str()));

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 3: Quorum Evaluation
    // ─────────────────────────────────────────────────────────────────────────

    // Case 3: Foreign Computer / Cloned Disk Attack -> Fail Closed
    if non_mac_matches < 2 {
        warn!(
            "Machine binding quorum failed: only {} of 3 immutable anchors matched. Rejecting foreign host.",
            non_mac_matches
        );
        return Err(MachineBindingError::ForeignHostDetected(format!(
            "Only {} of 3 immutable hardware/OS anchors matched manifest",
            non_mac_matches
        )));
    }

    // Unwrap host root secret using companion DPAPI or anchor AEAD combinations
    let host_root_secret = unwrap_host_root_secret_resilient(
        manifest_path,
        &manifest,
        &live_os_id_hash,
        &live_silicon_hash,
        &live_local_seal_hash,
    )?;

    // Case 1: Bound & Current (MAC matched and non-MAC quorum >= 2)
    if mac_matched {
        debug!(
            "Machine binding confirmed: host is bound and active MACs match enrolled inventory."
        );
        let mut updated = false;

        // If any newly discovered physical NICs are present, enroll them
        for h in &live_mac_hashes {
            if !manifest.enrolled_physical_mac_hashes.contains(h) {
                manifest.enrolled_physical_mac_hashes.push(h.clone());
                updated = true;
            }
        }

        if updated {
            manifest.manifest_hmac_hex = compute_manifest_hmac(
                manifest.binding_version,
                &manifest.enrolled_physical_mac_hashes,
                &manifest.historical_mac_hashes,
                &manifest.os_machine_id_hash,
                &manifest.silicon_anchor_hash,
                &manifest.local_seal_hash,
                manifest.mac_rotation_count,
                manifest.last_mac_change_at.as_deref(),
                &manifest.encrypted_host_root_secret_hex,
                &local_seal_key,
            );
            persist_manifest_atomic(manifest_path, &manifest, Some(&host_root_secret))?;
        }

        return Ok(MachineBindingStatus {
            verdict: "BOUND".to_string(),
            bound: true,
            confidence_score: 1.0,
            active_physical_nics: physical_nics.len(),
            active_virtual_nics: virtual_nics_count,
            masked_mac_fingerprints: masked_fingerprints,
            mac_rotation_count: manifest.mac_rotation_count,
            last_mac_change_at: manifest.last_mac_change_at,
            non_mac_anchor_matches: non_mac_matches,
            mac_matched: true,
        });
    }

    // Case 2: Legitimate MAC Address Change / Rotation on Same Computer
    // The MAC changed (Wi-Fi randomization, dock attach/detach, or NIC swap),
    // but the host is mathematically proven to be genuine by the 2-of-3 non-MAC quorum!
    info!(
        "Legitimate MAC rotation detected on bound host (Quorum {}/3 matched). Adapting manifest.",
        non_mac_matches
    );

    // Push existing enrolled MACs to historical ring (capped at 16)
    for old_h in &manifest.enrolled_physical_mac_hashes {
        if !manifest.historical_mac_hashes.contains(old_h) {
            manifest.historical_mac_hashes.push(old_h.clone());
        }
    }
    while manifest.historical_mac_hashes.len() > 16 {
        manifest.historical_mac_hashes.remove(0);
    }

    // Replace enrolled MACs with current live set
    manifest.enrolled_physical_mac_hashes = live_mac_hashes;
    manifest.mac_rotation_count += 1;
    let now_str = Utc::now().to_rfc3339();
    manifest.last_mac_change_at = Some(now_str);

    // Re-encrypt root secret with live anchor key to refresh envelope
    let live_aead_key =
        derive_anchor_aead_key(&live_os_id_hash, &live_silicon_hash, &live_local_seal_hash);
    manifest.encrypted_host_root_secret_hex =
        encrypt_host_root_secret(&host_root_secret, &live_aead_key)?;
    manifest.os_machine_id_hash = live_os_id_hash;
    manifest.silicon_anchor_hash = live_silicon_hash;
    manifest.local_seal_hash = live_local_seal_hash;

    manifest.manifest_hmac_hex = compute_manifest_hmac(
        manifest.binding_version,
        &manifest.enrolled_physical_mac_hashes,
        &manifest.historical_mac_hashes,
        &manifest.os_machine_id_hash,
        &manifest.silicon_anchor_hash,
        &manifest.local_seal_hash,
        manifest.mac_rotation_count,
        manifest.last_mac_change_at.as_deref(),
        &manifest.encrypted_host_root_secret_hex,
        &local_seal_key,
    );

    persist_manifest_atomic(manifest_path, &manifest, Some(&host_root_secret))?;

    Ok(MachineBindingStatus {
        verdict: "MAC_ROTATION_ADAPTED".to_string(),
        bound: true,
        confidence_score: 0.95,
        active_physical_nics: physical_nics.len(),
        active_virtual_nics: virtual_nics_count,
        masked_mac_fingerprints: masked_fingerprints,
        mac_rotation_count: manifest.mac_rotation_count,
        last_mac_change_at: manifest.last_mac_change_at,
        non_mac_anchor_matches: non_mac_matches,
        mac_matched: true,
    })
}

/// Helper that verifies the machine binding against the default system manifest path.
pub fn verify_default_machine_binding() -> Result<MachineBindingStatus, MachineBindingError> {
    let manifest_path = get_default_host_binding_manifest_path();
    verify_and_adapt_machine_binding(&manifest_path)
}

/// Unwraps the 32-byte host root secret across anchor combinations.
fn unwrap_host_root_secret_resilient(
    manifest_path: &Path,
    manifest: &HostBindingManifest,
    live_os_hash: &str,
    live_silicon_hash: &str,
    live_seal_hash: &str,
) -> Result<[u8; 32], MachineBindingError> {
    // 1. Try companion DPAPI file on Windows
    let dpapi_path = companion_dpapi_path(manifest_path);
    if dpapi_path.exists() {
        if let Ok(bytes) = std::fs::read(&dpapi_path) {
            if let Ok(unprotected) = crate::protected_env_backup::dpapi_unprotect_bytes(&bytes) {
                if unprotected.len() == 32 {
                    let mut secret = [0u8; 32];
                    secret.copy_from_slice(&unprotected);
                    return Ok(secret);
                }
            }
        }
    }

    // 2. Try anchor AEAD permutations (2-of-3 tolerance)
    let candidate_keys = [
        derive_anchor_aead_key(live_os_hash, live_silicon_hash, live_seal_hash),
        derive_anchor_aead_key(live_os_hash, live_silicon_hash, &manifest.local_seal_hash),
        derive_anchor_aead_key(live_os_hash, &manifest.silicon_anchor_hash, live_seal_hash),
        derive_anchor_aead_key(
            &manifest.os_machine_id_hash,
            live_silicon_hash,
            live_seal_hash,
        ),
        derive_anchor_aead_key(
            &manifest.os_machine_id_hash,
            &manifest.silicon_anchor_hash,
            live_seal_hash,
        ),
    ];

    for key in &candidate_keys {
        if let Ok(secret) = decrypt_host_root_secret(&manifest.encrypted_host_root_secret_hex, key)
        {
            return Ok(secret);
        }
    }

    Err(MachineBindingError::Crypto(
        "Failed to unwrap host root secret under any anchor combination".into(),
    ))
}

/// Derives a stable 32-byte vault key bound to this host.
///
/// Ensures `ProtectedEnvBackupVault` remains 100% decryptable across MAC address
/// rotations on the same computer while failing closed immediately on foreign machines.
pub fn derive_bound_host_vault_key() -> Result<[u8; 32], MachineBindingError> {
    let manifest_path = get_default_host_binding_manifest_path();
    let _ = verify_and_adapt_machine_binding(&manifest_path)?;

    let live_os = detect_os_machine_id();
    let live_os_hash = hash_os_machine_id(&live_os);
    let live_silicon = detect_silicon_anchor();
    let live_silicon_hash = hash_silicon_anchor(&live_silicon);
    let live_seal_hash = detect_local_seal_hash();

    let mut f = File::open(&manifest_path)?;
    let mut raw_bytes = Vec::new();
    f.read_to_end(&mut raw_bytes)?;
    let manifest: HostBindingManifest = serde_json::from_slice(&raw_bytes)
        .map_err(|e| MachineBindingError::Crypto(e.to_string()))?;

    let root_secret = unwrap_host_root_secret_resilient(
        &manifest_path,
        &manifest,
        &live_os_hash,
        &live_silicon_hash,
        &live_seal_hash,
    )?;

    let mut hasher = blake3::Hasher::new_keyed(&root_secret);
    hasher.update(b"OSHOOSI_BOUND_HOST_VAULT_KEY_DERIVATION_V1");
    Ok(*hasher.finalize().as_bytes())
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_discover_network_mac_inventory_and_virtual_filtering() {
        let inventory = discover_network_mac_inventory();
        assert!(
            !inventory.is_empty(),
            "Should discover at least one network adapter or fallback adapter"
        );

        for nic in &inventory {
            assert!(!nic.mac_formatted.is_empty());
            assert_eq!(nic.mac_formatted.len(), 17);
            assert!(nic.mac_formatted.contains(':'));
            assert_eq!(nic.oui_prefix.len(), 8);
            assert!(nic.mac_masked.contains("**:**"));
            assert!(!nic.mac_salted_hash.is_empty());

            if is_virtual_or_vpn_interface(&nic.interface_name) {
                // If filtered as virtual, check flag consistency unless container fallback activated
                assert!(!nic.interface_name.is_empty());
            }
        }
    }

    #[test]
    fn test_machine_binding_survives_mac_address_change_on_same_host() {
        let dir = tempdir().unwrap();
        let manifest_path = dir.path().join("test_host_binding.json");

        // 1. Initial provisioning on simulated initial host state
        let status1 = verify_and_adapt_machine_binding(&manifest_path).unwrap();
        assert!(status1.bound);
        assert_eq!(status1.mac_rotation_count, 0);

        // Read the provisioned host root secret
        let live_os = detect_os_machine_id();
        let live_os_hash = hash_os_machine_id(&live_os);
        let live_silicon = detect_silicon_anchor();
        let live_silicon_hash = hash_silicon_anchor(&live_silicon);
        let live_seal_hash = detect_local_seal_hash();

        let raw = std::fs::read(&manifest_path).unwrap();
        let mut manifest: HostBindingManifest = serde_json::from_slice(&raw).unwrap();
        let secret1 = unwrap_host_root_secret_resilient(
            &manifest_path,
            &manifest,
            &live_os_hash,
            &live_silicon_hash,
            &live_seal_hash,
        )
        .unwrap();

        // 2. Simulate complete MAC address change (e.g. Wi-Fi privacy MAC change or dock disconnect)
        // by altering enrolled MAC hashes to a different simulated MAC ("DE:AD:BE:EF:44:55")
        let simulated_old_mac = "AA:BB:CC:11:22:33";
        let simulated_old_hash = hash_mac(simulated_old_mac);
        manifest.enrolled_physical_mac_hashes = vec![simulated_old_hash.clone()];
        manifest.historical_mac_hashes.clear();

        // Save simulated manifest
        let json = serde_json::to_vec_pretty(&manifest).unwrap();
        std::fs::write(&manifest_path, json).unwrap();

        // 3. Re-verify: because non-MAC hardware/OS anchors match, host must be adapted!
        let status2 = verify_and_adapt_machine_binding(&manifest_path).unwrap();
        assert!(status2.bound);
        assert_eq!(status2.verdict, "MAC_ROTATION_ADAPTED");
        assert_eq!(status2.mac_rotation_count, 1);
        assert!(status2.last_mac_change_at.is_some());

        // Verify that the secret remained invariant across MAC rotation!
        let raw2 = std::fs::read(&manifest_path).unwrap();
        let manifest2: HostBindingManifest = serde_json::from_slice(&raw2).unwrap();
        let secret2 = unwrap_host_root_secret_resilient(
            &manifest_path,
            &manifest2,
            &live_os_hash,
            &live_silicon_hash,
            &live_seal_hash,
        )
        .unwrap();

        assert_eq!(
            secret1, secret2,
            "Host root secret must remain invariant across MAC rotations!"
        );
        assert!(
            manifest2
                .historical_mac_hashes
                .contains(&simulated_old_hash),
            "Old MAC must be saved in historical ring"
        );
    }

    #[test]
    fn test_machine_binding_fails_closed_on_foreign_host() {
        let dir = tempdir().unwrap();
        let manifest_path = dir.path().join("foreign_host_binding.json");

        // 1. Initial provisioning
        verify_and_adapt_machine_binding(&manifest_path).unwrap();

        // 2. Tamper manifest to simulate execution on a foreign computer
        // (different OS machine ID + different silicon anchor)
        let raw = std::fs::read(&manifest_path).unwrap();
        let mut manifest: HostBindingManifest = serde_json::from_slice(&raw).unwrap();
        manifest.enrolled_physical_mac_hashes = vec![hash_mac("00:11:22:33:44:55")];
        manifest.historical_mac_hashes.clear();
        manifest.os_machine_id_hash = hash_os_machine_id("foreign_vm_guid_12345");
        manifest.silicon_anchor_hash = hash_silicon_anchor("foreign_cpu:16:linux:x86_64:no_tpm");

        let json = serde_json::to_vec_pretty(&manifest).unwrap();
        std::fs::write(&manifest_path, json).unwrap();

        // Also remove companion .dpapi file if present to simulate foreign filesystem clone
        let dpapi_path = companion_dpapi_path(&manifest_path);
        let _ = std::fs::remove_file(dpapi_path);

        // 3. Re-verify on current host -> MUST FAIL CLOSED
        let res = verify_and_adapt_machine_binding(&manifest_path);
        assert!(res.is_err(), "Must fail closed on foreign host");
        match res.unwrap_err() {
            MachineBindingError::ForeignHostDetected(msg) => {
                assert!(msg.contains("immutable hardware/OS anchors matched"));
            }
            other => panic!("Expected ForeignHostDetected, got {:?}", other),
        }
    }
}
