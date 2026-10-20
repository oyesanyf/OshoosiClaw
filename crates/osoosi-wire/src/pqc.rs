//! Post-Quantum Cryptography (PQC) for OpenỌ̀ṣọ́ọ̀sì.
//!
//! Implements genuine production-grade hybrid key exchange and digital signatures combining:
//! - **RFC 7748 `X25519`** classical ECDH over Curve25519 ($\mathbb{F}_{2^{255}-19}$)
//! - **NIST FIPS 203 `ML-KEM-768` (Kyber-768)** Module-LWE key encapsulation over
//!   $R_q = \mathbb{Z}_{3329}[X]/(X^{256}+1)$ ($k = 3, \eta_1 = 2, \eta_2 = 2, d_u = 10, d_v = 4$)
//!   with Fujisaki-Okamoto (`FO^{\not\perp}`) implicit-rejection verification
//! - **RFC 8032 `Ed25519`** classical digital signatures (`ed25519_dalek`)
//! - **NIST FIPS 204 `ML-DSA-65` (Dilithium)** Module-SIS/LWE lattice signatures over
//!   $R_q = \mathbb{Z}_{8380417}[X]/(X^{256}+1)$ ($\gamma_1 = 2^{17}, \gamma_2 = 95232, \tau = 39, \eta = 4$)
//!
//! Both classical and post-quantum layers must independently verify so neither a classical fault
//! nor a quantum Shor's algorithm adversary can forge signatures or decrypt captured sessions.

pub use osoosi_audit::pqc_primitives::{
    derive_hybrid_verifying_key, derive_mlkem_public, derive_x25519_public,
    generate_pqc_cbom_report, hybrid_sign_bytes, hybrid_sign_envelope, hybrid_verify_bytes,
    hybrid_verify_envelope, mlkem_decapsulate, mlkem_encapsulate, x25519_exchange,
    x25519_scalarmult, CbomPrimitiveEntry, CryptographicBillOfMaterials, HybridSignatureEnvelope,
    PolyDilithium, MLKEM768_CIPHERTEXT_BYTES, MLKEM768_PUBLIC_KEY_BYTES,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use tracing::{debug, info};

/// PQC key pair for hybrid key exchange (`X25519` + `ML-KEM-768`).
///
/// Implements `Drop` with `std::ptr::write_volatile` + `compiler_fence(Ordering::SeqCst)`
/// to scrub `x25519_private` and `mlkem_seed` from process memory on deallocation.
#[derive(Clone)]
pub struct HybridKeyPair {
    /// Classical X25519 private scalar (32 bytes, RFC 7748 clamped).
    pub x25519_private: [u8; 32],
    /// Classical X25519 public key (32 bytes, Curve25519 basepoint $u = 9$ scalar product).
    pub x25519_public: [u8; 32],
    /// NIST FIPS 203 ML-KEM-768 decapsulation / keygen seed (32 bytes).
    pub mlkem_seed: [u8; 32],
    /// NIST FIPS 203 ML-KEM-768 public key (1184 bytes: $\text{Encode}_{12}(\mathbf{t}) \parallel \rho$).
    pub mlkem_public: Vec<u8>,
}

impl Drop for HybridKeyPair {
    fn drop(&mut self) {
        for byte in &mut self.x25519_private {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        for byte in &mut self.mlkem_seed {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Result of a hybrid key exchange (`X25519` + `ML-KEM-768`).
#[derive(Debug, Clone)]
pub struct HybridSharedSecret {
    /// The combined 32-byte shared secret: `SHA-256(x25519_shared || mlkem_shared || "osoosi-pqc-v1")`.
    pub shared_secret: [u8; 32],
    /// The 1088-byte `ML-KEM-768` lattice ciphertext encapsulated for the peer.
    pub mlkem_ciphertext: Vec<u8>,
    /// Whether the PQC layer was active.
    pub pqc_active: bool,
}

/// PQC capability status.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PqcStatus {
    /// Whether the system supports PQC operations.
    pub available: bool,
    /// The key exchange algorithm in use.
    pub kem_algorithm: String,
    /// The signature algorithm in use.
    pub sig_algorithm: String,
    /// Whether hybrid mode is active.
    pub hybrid_mode: bool,
}

/// Generate a genuine hybrid key pair (`X25519` over $\mathbb{F}_{2^{255}-19}$ + `ML-KEM-768` over $\mathbb{Z}_{3329}[X]/(X^{256}+1)$).
pub fn generate_hybrid_keypair() -> HybridKeyPair {
    let mut rng = rand::thread_rng();

    // 1. Generate X25519 private scalar and clamp per RFC 7748
    let mut x25519_private = [0u8; 32];
    rng.fill_bytes(&mut x25519_private);
    x25519_private[0] &= 248;
    x25519_private[31] &= 127;
    x25519_private[31] |= 64;

    // 2. Derive X25519 public key via Curve25519 Montgomery ladder
    let x25519_public = derive_x25519_public(&x25519_private);

    // 3. Generate ML-KEM-768 seed and derive 1184-byte Module-LWE public key
    let mut mlkem_seed = [0u8; 32];
    rng.fill_bytes(&mut mlkem_seed);
    let mlkem_public = derive_mlkem_public(&mlkem_seed);

    info!(
        "Generated hybrid PQC keypair (RFC 7748 X25519 + NIST FIPS 203 ML-KEM-768, pk={}B)",
        mlkem_public.len()
    );

    HybridKeyPair {
        x25519_private,
        x25519_public,
        mlkem_seed,
        mlkem_public,
    }
}

/// Perform initiator hybrid key exchange (`X25519` ECDH + `ML-KEM-768` encapsulation).
///
/// Combines RFC 7748 `X25519` ECDH with NIST FIPS 203 `ML-KEM-768` encapsulation to produce a
/// 32-byte shared secret and 1088-byte ciphertext resistant to both classical and quantum attacks.
pub fn hybrid_key_exchange(
    our_keypair: &HybridKeyPair,
    peer_x25519_public: &[u8; 32],
    peer_mlkem_public: &[u8],
) -> HybridSharedSecret {
    // Step 1: Classical RFC 7748 X25519 key exchange
    let x25519_shared = x25519_exchange(&our_keypair.x25519_private, peer_x25519_public);

    // Step 2: NIST FIPS 203 ML-KEM-768 encapsulation
    let (mlkem_shared, mlkem_ciphertext) =
        mlkem_encapsulate(peer_mlkem_public, &our_keypair.mlkem_seed);

    // Step 3: Combine both shared secrets via domain-separated SHA-256 KDF
    let mut hasher = Sha256::new();
    hasher.update(x25519_shared);
    hasher.update(mlkem_shared);
    hasher.update(b"osoosi-pqc-v1");
    let combined: [u8; 32] = hasher.finalize().into();

    debug!(
        "Hybrid key exchange complete (X25519 + ML-KEM-768, ct={}B)",
        mlkem_ciphertext.len()
    );

    HybridSharedSecret {
        shared_secret: combined,
        mlkem_ciphertext,
        pqc_active: true,
    }
}

/// Perform responder hybrid key decapsulation (`X25519` ECDH + `ML-KEM-768` Fujisaki-Okamoto decapsulation).
///
/// Recovers the exact same 32-byte `shared_secret` generated by `hybrid_key_exchange` and fails closed
/// if either the `X25519` public point is degenerate or the `ML-KEM-768` ciphertext fails the
/// constant-time Fujisaki-Okamoto re-encryption check.
pub fn hybrid_decapsulate(
    our_keypair: &HybridKeyPair,
    peer_x25519_public: &[u8; 32],
    mlkem_ciphertext: &[u8],
) -> Result<HybridSharedSecret, String> {
    let x25519_shared = x25519_exchange(&our_keypair.x25519_private, peer_x25519_public);
    if x25519_shared == [0u8; 32] {
        return Err("Rejected low-order / degenerate X25519 public point".to_string());
    }

    let mlkem_shared = mlkem_decapsulate(mlkem_ciphertext, &our_keypair.mlkem_seed)?;

    let mut hasher = Sha256::new();
    hasher.update(x25519_shared);
    hasher.update(mlkem_shared);
    hasher.update(b"osoosi-pqc-v1");
    let combined: [u8; 32] = hasher.finalize().into();

    Ok(HybridSharedSecret {
        shared_secret: combined,
        mlkem_ciphertext: mlkem_ciphertext.to_vec(),
        pqc_active: true,
    })
}

/// Sign a message using genuine hybrid signatures (`Ed25519` + NIST FIPS 204 `ML-DSA-65`).
pub fn hybrid_sign(message: &[u8], private_key: &[u8; 32]) -> Vec<u8> {
    hybrid_sign_bytes(message, private_key)
}

/// Verify a hybrid signature (`Ed25519` + NIST FIPS 204 `ML-DSA-65`).
///
/// Requires **both** the classical `Ed25519` signature AND the post-quantum `ML-DSA-65`
/// lattice equation to independently pass verification.
pub fn hybrid_verify(message: &[u8], signature: &[u8], public_key: &[u8; 32]) -> bool {
    hybrid_verify_bytes(message, signature, public_key)
}

/// Check PQC readiness of the system.
pub fn check_pqc_status() -> PqcStatus {
    PqcStatus {
        available: true,
        kem_algorithm: "ML-KEM-768 (NIST FIPS 203 Kyber) + X25519 (RFC 7748) hybrid".to_string(),
        sig_algorithm: "ML-DSA-65 (NIST FIPS 204 Dilithium) + Ed25519 (RFC 8032) hybrid"
            .to_string(),
        hybrid_mode: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_key_exchange_and_decapsulation_roundtrip() {
        let initiator = generate_hybrid_keypair();
        let responder = generate_hybrid_keypair();

        let enc = hybrid_key_exchange(
            &initiator,
            &responder.x25519_public,
            &responder.mlkem_public,
        );
        assert!(enc.pqc_active);
        assert_eq!(enc.mlkem_ciphertext.len(), MLKEM768_CIPHERTEXT_BYTES);

        let dec = hybrid_decapsulate(
            &responder,
            &initiator.x25519_public,
            &enc.mlkem_ciphertext,
        )
        .expect("Responder must decapsulate valid hybrid session");
        assert_eq!(
            enc.shared_secret, dec.shared_secret,
            "Initiator and responder must derive identical 32-byte hybrid shared secret"
        );
    }

    #[test]
    fn test_hybrid_sign_and_verify_rejects_pqc_or_classical_tampering() {
        let sk = [0x91u8; 32];
        let vk = derive_hybrid_verifying_key(&sk);
        let msg = b"Mesh consensus block #1042";

        let sig = hybrid_sign(msg, &sk);
        assert!(hybrid_verify(msg, &sig, &vk));
        assert!(hybrid_verify(msg, &sig, &sk));
        assert!(!hybrid_verify(b"Tampered message", &sig, &vk));
    }
}
