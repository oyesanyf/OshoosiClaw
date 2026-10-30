//! crates/osoosi-core/src/threshold_secret.rs
//!
//! Shamir's t-of-n Secret Sharing over GF(2^8) & Cryptographic Micro-Perimeters at Rest
//! (Features F33 & F28, Residual Threat Boundary 2, arXiv:2609.00406 & arXiv:2609.20909).
//!
//! Provides:
//! 1. Constant-time Russian Peasant polynomial multiplication (`gf256_mul`) modulo P(X) = 0x11B.
//! 2. Constant-time Fermat multiplicative inversion (`gf256_inv`, a^254 = a^-1).
//! 3. `ShamirThresholdScheme::split_secret` & `reconstruct_secret` with Lagrange interpolation at x=0.
//! 4. `MicroPerimeterCrypto::encrypt_envelope` & `decrypt_envelope` (OSHOOSI_CRYPT_V1) with AEAD and anti-transposition.
//! 5. `VolatilePeerShareRegistry` holding Shares 2..n in volatile RAM with automatic zeroization on drop.
//! 6. Audit-First monotonic epoch and Merkle state-root anti-rollback verification.

use dashmap::DashMap;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const MICRO_PERIMETER_MAGIC: &[u8; 16] = b"OSHOOSI_CRYPT_V1\0";
pub const GF256_POLY: u16 = 0x11B; // X^8 + X^4 + X^3 + X + 1 (Rijndael irreducible polynomial)

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ThresholdSecretError {
    #[error("Invalid threshold configuration: t={threshold} must satisfy 2 <= t <= n={total_shares} <= 255")]
    InvalidThreshold { threshold: u8, total_shares: u8 },

    #[error("Insufficient shares for quorum: provided {actual}, required threshold {required}")]
    InsufficientShares { actual: usize, required: u8 },

    #[error("Duplicate share coordinate x={index} detected in quorum")]
    DuplicateShareIndex { index: u8 },

    #[error("Invalid coordinate: x=0 is reserved for secret evaluation")]
    ZeroCoordinateNotAllowed,

    #[error("Inconsistent share length: expected {expected} bytes, got {actual}")]
    InconsistentShareLength { expected: usize, actual: usize },

    #[error("Fingerprint mismatch across shares: candidate shares belong to different secrets")]
    FingerprintMismatch,

    #[error("Field inversion by zero encountered in GF(2^8)")]
    DivisionByZero,

    #[error("Micro-perimeter AEAD decryption failed: {0}")]
    AeadAuthenticationFailed(String),

    #[error("Hardware TPM 2.0 unseal failed or PCR policy violated: {0}")]
    TpmPolicyViolation(String),

    #[error("P2P mesh peer rejected quorum attestation: {0}")]
    PeerQuorumRejected(String),

    #[error("Audit-First state rollback detected: on-disk epoch {on_disk} < hardware/mesh epoch {anchor}")]
    StateRollbackDetected { on_disk: u64, anchor: u64 },

    #[error("Audit-First state fork detected at epoch {epoch}: Merkle root mismatch between disk and hardware anchor")]
    StateForkDetected { epoch: u64 },
}

/// A single Shamir key share holding evaluated bytes at coordinate `index`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyShare {
    /// Non-zero coordinate x_i in GF(2^8) (1 <= index <= 255)
    pub index: u8,
    /// Evaluated polynomial bytes y_{k,i} (32 bytes for 256-bit master AEAD key)
    pub data: Vec<u8>,
    /// Threshold t required for reconstruction
    pub threshold: u8,
    /// Total shares n generated
    pub total_shares: u8,
    /// Truncated 16-byte BLAKE3 fingerprint of the original master secret
    pub key_fingerprint: [u8; 16],
}

impl Drop for KeyShare {
    fn drop(&mut self) {
        silicon_shield::SiliconIntegrityGuard::constant_time_scrub(&mut self.data);
    }
}

/// Constant-time Russian Peasant polynomial multiplication in GF(2^8) modulo 0x11B.
/// Runs in exactly 8 branchless iterations, eliminating timing and cache side-channels.
#[inline]
pub fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        p ^= a * (b & 1);
        let hi = (a >> 7) & 1;
        a <<= 1;
        a ^= hi * 0x1B; // 0x11B mod 256 = 0x1B
        b >>= 1;
    }
    p
}

/// Constant-time multiplicative inverse in GF(2^8) via Fermat's Little Theorem (a^-1 = a^254).
/// Returns Error on a=0 since zero has no multiplicative inverse in any field.
#[inline]
pub fn gf256_inv(a: u8) -> Result<u8, ThresholdSecretError> {
    if a == 0 {
        return Err(ThresholdSecretError::DivisionByZero);
    }
    // Exponentiation by squaring to compute a^254 (254 = 11111110_2)
    let a2 = gf256_mul(a, a); // a^2
    let a3 = gf256_mul(a2, a); // a^3
    let a6 = gf256_mul(a3, a3); // a^6
    let a7 = gf256_mul(a6, a); // a^7
    let a14 = gf256_mul(a7, a7); // a^14
    let a15 = gf256_mul(a14, a); // a^15
    let a30 = gf256_mul(a15, a15); // a^30
    let a31 = gf256_mul(a30, a); // a^31
    let a62 = gf256_mul(a31, a31); // a^62
    let a63 = gf256_mul(a62, a); // a^63
    let a126 = gf256_mul(a63, a63); // a^126
    let a127 = gf256_mul(a126, a); // a^127
    let a254 = gf256_mul(a127, a127); // a^254
    Ok(a254)
}

/// Shamir's (t, n) Secret Sharing scheme over Galois Field GF(2^8).
pub struct ShamirThresholdScheme;

impl ShamirThresholdScheme {
    /// Computes the 16-byte BLAKE3 key fingerprint for share validation.
    pub fn compute_fingerprint(secret: &[u8; 32]) -> [u8; 16] {
        let digest = blake3::hash(secret);
        let mut fp = [0u8; 16];
        fp.copy_from_slice(&digest.as_bytes()[0..16]);
        fp
    }

    /// Splits a 32-byte secret key into n shares with threshold t over GF(2^8).
    /// For each byte index k in 0..32, samples t-1 independent random coefficients
    /// from OsRng, forming polynomial f_k(x) with f_k(0) = secret[k].
    pub fn split_secret(
        secret: &[u8; 32],
        threshold: u8,
        total_shares: u8,
    ) -> Result<Vec<KeyShare>, ThresholdSecretError> {
        if threshold < 2 || total_shares < threshold {
            return Err(ThresholdSecretError::InvalidThreshold {
                threshold,
                total_shares,
            });
        }

        let key_fingerprint = Self::compute_fingerprint(secret);
        let mut shares_data: Vec<Vec<u8>> = (0..total_shares)
            .map(|_| Vec::with_capacity(secret.len()))
            .collect();

        let mut rng = rand::rngs::OsRng;

        // Sample t-1 random coefficients per secret byte
        for &secret_byte in secret.iter() {
            let mut coeffs = vec![secret_byte];
            for _ in 1..threshold {
                let mut rand_byte = [0u8; 1];
                rng.fill_bytes(&mut rand_byte);
                coeffs.push(rand_byte[0]);
            }

            // Evaluate polynomial at x in 1..=total_shares
            for (share_idx, share_buf) in shares_data.iter_mut().enumerate() {
                let x = (share_idx + 1) as u8;
                let mut val = 0u8;
                let mut x_pow = 1u8;
                for &coeff in &coeffs {
                    val ^= gf256_mul(coeff, x_pow);
                    x_pow = gf256_mul(x_pow, x);
                }
                share_buf.push(val);
            }

            // Wipe temporary random coefficients from stack
            silicon_shield::SiliconIntegrityGuard::constant_time_scrub(&mut coeffs);
        }

        let key_shares = shares_data
            .into_iter()
            .enumerate()
            .map(|(idx, data)| KeyShare {
                index: (idx + 1) as u8,
                data,
                threshold,
                total_shares,
                key_fingerprint,
            })
            .collect();

        Ok(key_shares)
    }

    /// Reconstructs the 32-byte secret key from any t distinct shares using Lagrange interpolation at x=0.
    pub fn reconstruct_secret(
        shares: &[KeyShare],
        threshold: u8,
    ) -> Result<[u8; 32], ThresholdSecretError> {
        if shares.len() < threshold as usize {
            return Err(ThresholdSecretError::InsufficientShares {
                actual: shares.len(),
                required: threshold,
            });
        }

        let quorum = &shares[0..threshold as usize];

        // 1. Verify coordinate validity and check for duplicates
        let mut seen_indices = [false; 256];
        for share in quorum {
            if share.index == 0 {
                return Err(ThresholdSecretError::ZeroCoordinateNotAllowed);
            }
            if seen_indices[share.index as usize] {
                return Err(ThresholdSecretError::DuplicateShareIndex { index: share.index });
            }
            seen_indices[share.index as usize] = true;
            if share.data.len() != 32 {
                return Err(ThresholdSecretError::InconsistentShareLength {
                    expected: 32,
                    actual: share.data.len(),
                });
            }
        }

        // 2. Verify fingerprint consistency across quorum
        let expected_fp = quorum[0].key_fingerprint;
        for share in quorum.iter().skip(1) {
            if share.key_fingerprint != expected_fp {
                return Err(ThresholdSecretError::FingerprintMismatch);
            }
        }

        // 3. Compute Lagrange basis weights at x = 0: L_j(0) = Prod_{m != j} (x_m / (x_j ^ x_m))
        let xs: Vec<u8> = quorum.iter().map(|s| s.index).collect();
        let mut lagrange_weights = Vec::with_capacity(threshold as usize);

        for j in 0..threshold as usize {
            let mut num = 1u8;
            let mut den = 1u8;
            for m in 0..threshold as usize {
                if m == j {
                    continue;
                }
                num = gf256_mul(num, xs[m]);
                den = gf256_mul(den, xs[j] ^ xs[m]);
            }
            let weight = gf256_mul(num, gf256_inv(den)?);
            lagrange_weights.push(weight);
        }

        // 4. Interpolate each byte: s_k = XOR_{j=0}^{t-1} (y_{k,j} * L_j(0))
        let mut secret = [0u8; 32];
        for k in 0..32 {
            let mut s = 0u8;
            for j in 0..threshold as usize {
                s ^= gf256_mul(quorum[j].data[k], lagrange_weights[j]);
            }
            secret[k] = s;
        }

        // 5. Verify reconstructed secret against fingerprint
        let actual_fp = Self::compute_fingerprint(&secret);
        if actual_fp != expected_fp {
            silicon_shield::SiliconIntegrityGuard::constant_time_scrub(&mut secret);
            return Err(ThresholdSecretError::FingerprintMismatch);
        }

        Ok(secret)
    }
}

/// Metadata bound cryptographically to each micro-perimeter ciphertext envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MicroPerimeterAssociatedData {
    pub target_path: String,
    pub host_did: String,
    pub commit_epoch: u64,
}

/// Application-Layer Authenticated Encryption for Micro-Perimeters at Rest (`OSHOOSI_CRYPT_V1`).
pub struct MicroPerimeterCrypto;

impl MicroPerimeterCrypto {
    /// Encrypts sensitive configuration or database bytes at rest.
    ///
    /// Envelope format:
    /// `[16B Magic: OSHOOSI_CRYPT_V1\0] [16B Salt] [12B Nonce] [8B Epoch BE] [4B AD Len BE] [AD JSON] [Ciphertext] [32B HMAC-SHA256 Tag]`
    pub fn encrypt_envelope(
        plaintext: &[u8],
        master_key: &[u8; 32],
        target_path: &str,
        host_did: &str,
        commit_epoch: u64,
    ) -> Result<Vec<u8>, ThresholdSecretError> {
        let mut rng = rand::rngs::OsRng;
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce);

        let ad = MicroPerimeterAssociatedData {
            target_path: target_path.to_string(),
            host_did: host_did.to_string(),
            commit_epoch,
        };
        let ad_json = serde_json::to_vec(&ad).map_err(|e| {
            ThresholdSecretError::AeadAuthenticationFailed(format!(
                "AD serialization failed: {}",
                e
            ))
        })?;

        // Derive subkeys via SHA-256 HKDF-style domain separation:
        // K_enc = SHA256(master_key || salt || b"|ENC")
        // K_mac = SHA256(master_key || salt || b"|MAC")
        let mut hasher_enc = Sha256::new();
        hasher_enc.update(master_key);
        hasher_enc.update(salt);
        hasher_enc.update(b"|MICRO_PERIMETER_ENC_V1");
        let k_enc = hasher_enc.finalize();

        let mut hasher_mac = Sha256::new();
        hasher_mac.update(master_key);
        hasher_mac.update(salt);
        hasher_mac.update(b"|MICRO_PERIMETER_MAC_V1");
        let k_mac = hasher_mac.finalize();

        // Encrypt plaintext with SHA-256 counter mode keystream
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut counter: u32 = 0;
        let mut offset = 0;
        while offset < plaintext.len() {
            let mut block_hasher = Sha256::new();
            block_hasher.update(&k_enc);
            block_hasher.update(nonce);
            block_hasher.update(&counter.to_be_bytes());
            let keystream_block = block_hasher.finalize();

            let take = (plaintext.len() - offset).min(32);
            for i in 0..take {
                ciphertext.push(plaintext[offset + i] ^ keystream_block[i]);
            }
            offset += take;
            counter = counter.wrapping_add(1);
        }

        // Header layout:
        // [16B Magic] [16B Salt] [12B Nonce] [8B Epoch] [4B AD Len] [AD JSON]
        let mut envelope =
            Vec::with_capacity(16 + 16 + 12 + 8 + 4 + ad_json.len() + ciphertext.len() + 32);
        envelope.extend_from_slice(MICRO_PERIMETER_MAGIC);
        envelope.extend_from_slice(&salt);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&commit_epoch.to_be_bytes());
        envelope.extend_from_slice(&(ad_json.len() as u32).to_be_bytes());
        envelope.extend_from_slice(&ad_json);
        envelope.extend_from_slice(&ciphertext);

        // Compute HMAC-SHA256 authentication tag over all preceding envelope bytes
        let mut mac = HmacSha256::new_from_slice(&k_mac).map_err(|e| {
            ThresholdSecretError::AeadAuthenticationFailed(format!("HMAC init failed: {}", e))
        })?;
        mac.update(&envelope);
        let auth_tag = mac.finalize().into_bytes();
        envelope.extend_from_slice(&auth_tag);

        Ok(envelope)
    }

    /// Decrypts and authenticates micro-perimeter envelope bytes at rest.
    /// Returns the decrypted plaintext and the authenticated commit epoch.
    pub fn decrypt_envelope(
        envelope: &[u8],
        master_key: &[u8; 32],
        expected_target_path: &str,
        expected_host_did: &str,
    ) -> Result<(Vec<u8>, u64), ThresholdSecretError> {
        let min_len = 16 + 16 + 12 + 8 + 4 + 32;
        if envelope.len() < min_len || &envelope[0..16] != MICRO_PERIMETER_MAGIC {
            return Err(ThresholdSecretError::AeadAuthenticationFailed(
                "Invalid micro-perimeter container magic".into(),
            ));
        }

        let salt = &envelope[16..32];
        let nonce = &envelope[32..44];
        let epoch = u64::from_be_bytes(envelope[44..52].try_into().map_err(|_| {
            ThresholdSecretError::AeadAuthenticationFailed("Malformed epoch".into())
        })?);
        let ad_len = u32::from_be_bytes(envelope[52..56].try_into().map_err(|_| {
            ThresholdSecretError::AeadAuthenticationFailed("Malformed AD length".into())
        })?) as usize;

        let total_header_len = 56 + ad_len;
        if envelope.len() < total_header_len + 32 {
            return Err(ThresholdSecretError::AeadAuthenticationFailed(
                "Micro-perimeter envelope truncated".into(),
            ));
        }

        let ad_bytes = &envelope[56..total_header_len];
        let ad: MicroPerimeterAssociatedData = serde_json::from_slice(ad_bytes).map_err(|e| {
            ThresholdSecretError::AeadAuthenticationFailed(format!("AD parsing failed: {}", e))
        })?;

        // Anti-transposition check: assert canonical path and DID match
        if ad.target_path != expected_target_path || ad.host_did != expected_host_did {
            return Err(ThresholdSecretError::AeadAuthenticationFailed(format!(
                "Anti-transposition violation: expected ({}, {}), got ({}, {})",
                expected_target_path, expected_host_did, ad.target_path, ad.host_did
            )));
        }

        let tag_start = envelope.len() - 32;
        let authenticated_data = &envelope[0..tag_start];
        let auth_tag = &envelope[tag_start..];
        let ciphertext = &envelope[total_header_len..tag_start];

        // Derive subkeys
        let mut hasher_enc = Sha256::new();
        hasher_enc.update(master_key);
        hasher_enc.update(salt);
        hasher_enc.update(b"|MICRO_PERIMETER_ENC_V1");
        let k_enc = hasher_enc.finalize();

        let mut hasher_mac = Sha256::new();
        hasher_mac.update(master_key);
        hasher_mac.update(salt);
        hasher_mac.update(b"|MICRO_PERIMETER_MAC_V1");
        let k_mac = hasher_mac.finalize();

        // Verify HMAC-SHA256 in constant time
        let mut mac = HmacSha256::new_from_slice(&k_mac).map_err(|e| {
            ThresholdSecretError::AeadAuthenticationFailed(format!("HMAC init failed: {}", e))
        })?;
        mac.update(authenticated_data);
        let expected_tag = mac.finalize().into_bytes();

        if auth_tag.ct_eq(&expected_tag).unwrap_u8() != 1 {
            return Err(ThresholdSecretError::AeadAuthenticationFailed(
                "HMAC authentication tag mismatch (tampering detected)".into(),
            ));
        }

        // Decrypt ciphertext
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut counter: u32 = 0;
        let mut offset = 0;
        while offset < ciphertext.len() {
            let mut block_hasher = Sha256::new();
            block_hasher.update(&k_enc);
            block_hasher.update(nonce);
            block_hasher.update(&counter.to_be_bytes());
            let keystream_block = block_hasher.finalize();

            let take = (ciphertext.len() - offset).min(32);
            for i in 0..take {
                plaintext.push(ciphertext[offset + i] ^ keystream_block[i]);
            }
            offset += take;
            counter = counter.wrapping_add(1);
        }

        Ok((plaintext, epoch))
    }
}

/// Remote peer share entry held strictly in volatile RAM.
#[derive(Debug, Clone)]
pub struct VolatilePeerShareEntry {
    pub share: KeyShare,
    pub node_did: String,
    pub expected_pcr0_hex: String,
    pub expected_pcr7_hex: String,
    pub latest_epoch: u64,
}

/// Registry holding Shares 2..n in volatile RAM across trusted P2P mesh peers.
pub struct VolatilePeerShareRegistry {
    entries: DashMap<String, VolatilePeerShareEntry>,
}

impl Default for VolatilePeerShareRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl VolatilePeerShareRegistry {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    /// Stores a remote peer's share strictly in volatile RAM.
    pub fn store_share(&self, node_did: &str, entry: VolatilePeerShareEntry) {
        self.entries.insert(node_did.to_string(), entry);
    }

    /// Evaluates peer attestation and releases held share if PCRs match,
    /// node is not quarantined, and epoch satisfies monotonic anti-rollback.
    pub fn evaluate_and_release_share(
        &self,
        node_did: &str,
        presented_pcr0_hex: &str,
        presented_pcr7_hex: &str,
        presented_epoch: u64,
        is_quarantined: bool,
    ) -> Result<KeyShare, ThresholdSecretError> {
        let entry = self.entries.get(node_did).ok_or_else(|| {
            ThresholdSecretError::PeerQuorumRejected(
                "Node DID not enrolled in peer share registry".into(),
            )
        })?;

        if is_quarantined {
            return Err(ThresholdSecretError::PeerQuorumRejected(
                "Node is currently in quarantine".into(),
            ));
        }

        // F28 Anti-Rollback Gate: node cannot present an older epoch than recorded anchor
        if presented_epoch < entry.latest_epoch {
            return Err(ThresholdSecretError::StateRollbackDetected {
                on_disk: presented_epoch,
                anchor: entry.latest_epoch,
            });
        }

        // PCR verification
        if !entry
            .expected_pcr0_hex
            .eq_ignore_ascii_case(presented_pcr0_hex)
            || !entry
                .expected_pcr7_hex
                .eq_ignore_ascii_case(presented_pcr7_hex)
        {
            return Err(ThresholdSecretError::TpmPolicyViolation(
                "PCR measurements mismatch peer baseline".into(),
            ));
        }

        Ok(entry.share.clone())
    }

    /// Purges and zeroizes all held volatile peer shares on daemon shutdown.
    pub fn purge_all_volatile_memory(&self) {
        self.entries.clear();
    }
}

/// Verifies monotonic epoch and Merkle state root anti-rollback consistency (`arXiv:2609.00406`).
pub fn verify_anti_rollback_epoch(
    on_disk_epoch: u64,
    hardware_anchor_epoch: u64,
    on_disk_root: &str,
    hardware_root: &str,
) -> Result<(), ThresholdSecretError> {
    if on_disk_epoch < hardware_anchor_epoch {
        return Err(ThresholdSecretError::StateRollbackDetected {
            on_disk: on_disk_epoch,
            anchor: hardware_anchor_epoch,
        });
    }
    if on_disk_epoch == hardware_anchor_epoch
        && on_disk_root
            .as_bytes()
            .ct_eq(hardware_root.as_bytes())
            .unwrap_u8()
            != 1
    {
        return Err(ThresholdSecretError::StateForkDetected {
            epoch: on_disk_epoch,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf256_multiplication_and_inversion_all_elements() {
        // Test that a * a^-1 == 1 for all 255 non-zero elements
        for a in 1..=255u8 {
            let inv = gf256_inv(a).expect("Inversion must succeed for non-zero element");
            let prod = gf256_mul(a, inv);
            assert_eq!(prod, 1, "Failed for element 0x{:02x}: inv=0x{:02x}", a, inv);
        }
        assert_eq!(gf256_inv(0), Err(ThresholdSecretError::DivisionByZero));
    }

    #[test]
    fn test_shamir_2_of_3_reconstructs_from_any_quorum() {
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);

        let shares =
            ShamirThresholdScheme::split_secret(&secret, 2, 3).expect("Split 2-of-3 must succeed");
        assert_eq!(shares.len(), 3);

        // Quorum {0, 1} (Shares 1 and 2)
        let r12 =
            ShamirThresholdScheme::reconstruct_secret(&[shares[0].clone(), shares[1].clone()], 2)
                .expect("Reconstruction from {1, 2} must succeed");
        assert_eq!(r12, secret);

        // Quorum {0, 2} (Shares 1 and 3)
        let r13 =
            ShamirThresholdScheme::reconstruct_secret(&[shares[0].clone(), shares[2].clone()], 2)
                .expect("Reconstruction from {1, 3} must succeed");
        assert_eq!(r13, secret);

        // Quorum {1, 2} (Shares 2 and 3)
        let r23 =
            ShamirThresholdScheme::reconstruct_secret(&[shares[1].clone(), shares[2].clone()], 2)
                .expect("Reconstruction from {2, 3} must succeed");
        assert_eq!(r23, secret);
    }

    #[test]
    fn test_shamir_3_of_5_reconstructs_from_any_quorum() {
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);

        let shares =
            ShamirThresholdScheme::split_secret(&secret, 3, 5).expect("Split 3-of-5 must succeed");
        assert_eq!(shares.len(), 5);

        // Quorum of 3 shares: {0, 2, 4}
        let r = ShamirThresholdScheme::reconstruct_secret(
            &[shares[0].clone(), shares[2].clone(), shares[4].clone()],
            3,
        )
        .expect("Reconstruction from {1, 3, 5} must succeed");
        assert_eq!(r, secret);
    }

    #[test]
    fn test_single_share_fails_reconstruction() {
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);

        let shares = ShamirThresholdScheme::split_secret(&secret, 2, 3).unwrap();
        let res = ShamirThresholdScheme::reconstruct_secret(&[shares[0].clone()], 2);
        assert_eq!(
            res,
            Err(ThresholdSecretError::InsufficientShares {
                actual: 1,
                required: 2
            })
        );
    }

    #[test]
    fn test_duplicate_and_zero_coordinates_rejected() {
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);

        let shares = ShamirThresholdScheme::split_secret(&secret, 2, 3).unwrap();

        // Duplicate coordinates: [share[0], share[0]]
        let dup_res =
            ShamirThresholdScheme::reconstruct_secret(&[shares[0].clone(), shares[0].clone()], 2);
        assert_eq!(
            dup_res,
            Err(ThresholdSecretError::DuplicateShareIndex {
                index: shares[0].index
            })
        );

        // Zero coordinate
        let mut zero_share = shares[0].clone();
        zero_share.index = 0;
        let zero_res =
            ShamirThresholdScheme::reconstruct_secret(&[zero_share, shares[1].clone()], 2);
        assert_eq!(
            zero_res,
            Err(ThresholdSecretError::ZeroCoordinateNotAllowed)
        );
    }

    #[test]
    fn test_micro_perimeter_encrypt_decrypt_roundtrip() {
        let master_key = [0x55u8; 32];
        let plaintext = b"sqlite_database_and_config_sensitive_payload_bytes_at_rest";
        let target_path = "database/osoosi.db";
        let host_did = "did:oshoosi:node_alpha_01";
        let commit_epoch = 42;

        let envelope = MicroPerimeterCrypto::encrypt_envelope(
            plaintext,
            &master_key,
            target_path,
            host_did,
            commit_epoch,
        )
        .expect("Encryption must succeed");

        let (decrypted, epoch) =
            MicroPerimeterCrypto::decrypt_envelope(&envelope, &master_key, target_path, host_did)
                .expect("Decryption must succeed");

        assert_eq!(decrypted, plaintext);
        assert_eq!(epoch, commit_epoch);
    }

    #[test]
    fn test_micro_perimeter_transposition_rejected() {
        let master_key = [0x55u8; 32];
        let plaintext = b"sqlite_database_and_config_sensitive_payload_bytes_at_rest";
        let target_path = "database/osoosi.db";
        let host_did = "did:oshoosi:node_alpha_01";
        let commit_epoch = 42;

        let envelope = MicroPerimeterCrypto::encrypt_envelope(
            plaintext,
            &master_key,
            target_path,
            host_did,
            commit_epoch,
        )
        .unwrap();

        // Attacker attempts transposition attack (moving database to config path)
        let res =
            MicroPerimeterCrypto::decrypt_envelope(&envelope, &master_key, "osoosi.toml", host_did);
        assert!(res.is_err(), "Transposition must be rejected");
    }

    #[test]
    fn test_volatile_peer_share_registry_and_quarantine() {
        let registry = VolatilePeerShareRegistry::new();
        let share = KeyShare {
            index: 2,
            data: vec![0x42; 32],
            threshold: 2,
            total_shares: 3,
            key_fingerprint: [0x11; 16],
        };
        let entry = VolatilePeerShareEntry {
            share: share.clone(),
            node_did: "did:oshoosi:node_beta".to_string(),
            expected_pcr0_hex: "0123456789abcdef".to_string(),
            expected_pcr7_hex: "fedcba9876543210".to_string(),
            latest_epoch: 10,
        };
        registry.store_share("did:oshoosi:node_beta", entry);

        // Quarantined node rejected
        let q_err = registry.evaluate_and_release_share(
            "did:oshoosi:node_beta",
            "0123456789abcdef",
            "fedcba9876543210",
            10,
            true, // quarantined
        );
        assert!(q_err.is_err());

        // Rollback epoch rejected
        let rb_err = registry.evaluate_and_release_share(
            "did:oshoosi:node_beta",
            "0123456789abcdef",
            "fedcba9876543210",
            9, // presented epoch 9 < recorded 10
            false,
        );
        assert_eq!(
            rb_err,
            Err(ThresholdSecretError::StateRollbackDetected {
                on_disk: 9,
                anchor: 10
            })
        );

        // Genuine release
        let released = registry
            .evaluate_and_release_share(
                "did:oshoosi:node_beta",
                "0123456789abcdef",
                "fedcba9876543210",
                10,
                false,
            )
            .expect("Valid attestation must release share");
        assert_eq!(released.data, share.data);
    }

    #[test]
    fn test_audit_first_anti_rollback_detection() {
        assert!(verify_anti_rollback_epoch(5, 5, "root_a", "root_a").is_ok());
        assert!(verify_anti_rollback_epoch(6, 5, "root_b", "root_a").is_ok());

        // Stale snapshot restored
        let rb = verify_anti_rollback_epoch(4, 5, "root_old", "root_new");
        assert_eq!(
            rb,
            Err(ThresholdSecretError::StateRollbackDetected {
                on_disk: 4,
                anchor: 5
            })
        );

        // Fork detected
        let fork = verify_anti_rollback_epoch(5, 5, "root_fork", "root_expected");
        assert_eq!(
            fork,
            Err(ThresholdSecretError::StateForkDetected { epoch: 5 })
        );
    }
}
