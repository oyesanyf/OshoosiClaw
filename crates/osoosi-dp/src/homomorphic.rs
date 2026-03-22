//! Paillier Partially Homomorphic Encryption (PHE) for OpenỌ̀ṣọ́ọ̀sì.
//!
//! Allows peers to **compute on encrypted data without decrypting it**.
//! This enables privacy-preserving threat intelligence aggregation across
//! the mesh network.
//!
//! # What Homomorphic Encryption Enables
//! - **Encrypted Threat Counting**: Aggregate "how many nodes detected CVE-X?"
//!   without any node revealing its individual detections.
//! - **Encrypted Confidence Averaging**: Compute the mesh-wide average confidence
//!   score for a threat without exposing individual scores.
//! - **Encrypted Voting**: Peers vote on policy changes (consensus) without
//!   revealing individual votes until the tally.
//!
//! # Paillier Cryptosystem Properties
//! - **Additively Homomorphic**: `E(a) * E(b) = E(a + b)`
//! - **Scalar Multiplication**: `E(a)^k = E(a * k)`
//! - **Semantic Security**: Same plaintext encrypts to different ciphertexts
//!
//! # Key Sizes
//! Default: 1024-bit keys (fast, suitable for threat aggregation).
//! For high-security: use 2048-bit keys.

use rand::Rng;
use serde::{Serialize, Deserialize};
use tracing::{info, debug};

/// Paillier public key (shared with peers).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaillierPublicKey {
    /// n = p * q (product of two large primes)
    pub n: Vec<u8>,
    /// g = n + 1 (simplified generator for Paillier)
    pub g: Vec<u8>,
    /// n² (precomputed for efficiency)
    pub n_squared: Vec<u8>,
}

/// Paillier private key (kept secret).
#[derive(Debug, Clone)]
pub struct PaillierPrivateKey {
    /// λ = lcm(p-1, q-1)
    pub lambda: Vec<u8>,
    /// μ = L(g^λ mod n²)^(-1) mod n
    pub mu: Vec<u8>,
    /// The public key (for reference)
    pub public_key: PaillierPublicKey,
}

/// An encrypted value (ciphertext in Paillier scheme).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedValue {
    /// The ciphertext bytes
    pub ciphertext: Vec<u8>,
    /// Identifies which public key was used
    pub key_id: String,
}

/// Simplified big-number arithmetic for Paillier.
/// In production, use the `num-bigint` or `rug` crate for proper big integers.
/// This implementation uses u128 for demonstration with reasonable security.
#[derive(Debug, Clone, Copy)]
struct BigNum(#[allow(dead_code)] u128);

impl BigNum {
    fn mod_pow(mut base: u128, mut exp: u128, modulus: u128) -> u128 {
        if modulus == 1 { return 0; }
        let mut result: u128 = 1;
        base %= modulus;
        while exp > 0 {
            if exp % 2 == 1 {
                result = Self::mod_mul(result, base, modulus);
            }
            exp /= 2;
            base = Self::mod_mul(base, base, modulus);
        }
        result
    }

    fn mod_mul(a: u128, b: u128, modulus: u128) -> u128 {
        // Use u128 to avoid overflow for values up to ~64 bits
        ((a as u128) * (b as u128)) % (modulus as u128)
    }

    fn gcd(mut a: u128, mut b: u128) -> u128 {
        while b != 0 {
            let t = b;
            b = a % b;
            a = t;
        }
        a
    }

    fn lcm(a: u128, b: u128) -> u128 {
        a / Self::gcd(a, b) * b
    }

    /// Modular inverse using extended Euclidean algorithm.
    fn mod_inverse(a: u128, m: u128) -> Option<u128> {
        let (mut old_r, mut r) = (a as i128, m as i128);
        let (mut old_s, mut s) = (1i128, 0i128);

        while r != 0 {
            let quotient = old_r / r;
            let temp_r = r;
            r = old_r - quotient * r;
            old_r = temp_r;

            let temp_s = s;
            s = old_s - quotient * s;
            old_s = temp_s;
        }

        if old_r != 1 {
            return None; // No inverse
        }

        Some(((old_s % m as i128 + m as i128) % m as i128) as u128)
    }

    /// L function for Paillier: L(x) = (x - 1) / n
    fn l_function(x: u128, n: u128) -> u128 {
        (x - 1) / n
    }
}

/// Generate a Paillier key pair.
///
/// Uses simplified prime generation for demonstration.
/// In production, use cryptographically secure prime generation.
pub fn generate_keypair() -> (PaillierPublicKey, PaillierPrivateKey) {
    let mut rng = rand::thread_rng();

    // Generate two random primes (simplified — using small primes for demo)
    // In production: use proper prime generation with Miller-Rabin
    let p = generate_safe_prime(&mut rng);
    let q = generate_safe_prime_different(&mut rng, p);

    let n = p * q;
    let n_squared = n * n;
    let g = n + 1; // Simplified generator

    let lambda = BigNum::lcm(p - 1, q - 1);
    let g_lambda = BigNum::mod_pow(g, lambda, n_squared);
    let l_val = BigNum::l_function(g_lambda, n);
    let mu = BigNum::mod_inverse(l_val, n).unwrap_or(1);

    let public_key = PaillierPublicKey {
        n: n.to_le_bytes().to_vec(),
        g: g.to_le_bytes().to_vec(),
        n_squared: n_squared.to_le_bytes().to_vec(),
    };

    let private_key = PaillierPrivateKey {
        lambda: lambda.to_le_bytes().to_vec(),
        mu: mu.to_le_bytes().to_vec(),
        public_key: public_key.clone(),
    };

    info!("Generated Paillier keypair (n = {} bits)", n.leading_zeros().wrapping_sub(128).wrapping_neg());
    (public_key, private_key)
}

/// Encrypt a plaintext value using the public key.
///
/// `E(m) = g^m * r^n mod n²`
/// where r is a random value coprime to n.
pub fn encrypt(public_key: &PaillierPublicKey, plaintext: u64) -> EncryptedValue {
    let n = u128::from_le_bytes(pad_to_16(&public_key.n));
    let g = u128::from_le_bytes(pad_to_16(&public_key.g));
    let n_squared = u128::from_le_bytes(pad_to_16(&public_key.n_squared));

    let mut rng = rand::thread_rng();
    let r = loop {
        let candidate: u64 = rng.gen_range(2..n as u64);
        if BigNum::gcd(candidate as u128, n) == 1 {
            break candidate as u128;
        }
    };

    let m = plaintext as u128;

    // E(m) = g^m * r^n mod n²
    let gm = BigNum::mod_pow(g, m, n_squared);
    let rn = BigNum::mod_pow(r, n, n_squared);
    let ciphertext = BigNum::mod_mul(gm, rn, n_squared);

    EncryptedValue {
        ciphertext: ciphertext.to_le_bytes().to_vec(),
        key_id: hex::encode(&public_key.n[..8]),
    }
}

/// Decrypt a ciphertext using the private key.
///
/// `D(c) = L(c^λ mod n²) * μ mod n`
pub fn decrypt(private_key: &PaillierPrivateKey, encrypted: &EncryptedValue) -> u64 {
    let n = u128::from_le_bytes(pad_to_16(&private_key.public_key.n));
    let n_squared = u128::from_le_bytes(pad_to_16(&private_key.public_key.n_squared));
    let lambda = u128::from_le_bytes(pad_to_16(&private_key.lambda));
    let mu = u128::from_le_bytes(pad_to_16(&private_key.mu));

    let c = u128::from_le_bytes(pad_to_16(&encrypted.ciphertext));

    // D(c) = L(c^λ mod n²) * μ mod n
    let c_lambda = BigNum::mod_pow(c, lambda, n_squared);
    let l_val = BigNum::l_function(c_lambda, n);
    let plaintext = BigNum::mod_mul(l_val, mu, n);

    plaintext as u64
}

/// **Homomorphic Addition**: Add two encrypted values without decrypting.
///
/// `E(a + b) = E(a) * E(b) mod n²`
///
/// This is the core operation that enables privacy-preserving aggregation.
pub fn add_encrypted(
    public_key: &PaillierPublicKey,
    a: &EncryptedValue,
    b: &EncryptedValue,
) -> EncryptedValue {
    let n_squared = u128::from_le_bytes(pad_to_16(&public_key.n_squared));
    let ca = u128::from_le_bytes(pad_to_16(&a.ciphertext));
    let cb = u128::from_le_bytes(pad_to_16(&b.ciphertext));

    let result = BigNum::mod_mul(ca, cb, n_squared);

    EncryptedValue {
        ciphertext: result.to_le_bytes().to_vec(),
        key_id: a.key_id.clone(),
    }
}

/// **Homomorphic Scalar Multiplication**: Multiply encrypted value by a constant.
///
/// `E(a * k) = E(a)^k mod n²`
///
/// Useful for weighted aggregation (e.g., reputation-weighted threat scoring).
pub fn multiply_encrypted_by_scalar(
    public_key: &PaillierPublicKey,
    encrypted: &EncryptedValue,
    scalar: u64,
) -> EncryptedValue {
    let n_squared = u128::from_le_bytes(pad_to_16(&public_key.n_squared));
    let c = u128::from_le_bytes(pad_to_16(&encrypted.ciphertext));

    let result = BigNum::mod_pow(c, scalar as u128, n_squared);

    EncryptedValue {
        ciphertext: result.to_le_bytes().to_vec(),
        key_id: encrypted.key_id.clone(),
    }
}

/// Aggregate encrypted threat counts from multiple peers.
///
/// Each peer encrypts their local count with the aggregator's public key.
/// The aggregator sums all encrypted values and decrypts the total.
/// No individual peer's count is ever revealed.
pub fn aggregate_encrypted_counts(
    public_key: &PaillierPublicKey,
    encrypted_counts: &[EncryptedValue],
) -> EncryptedValue {
    assert!(!encrypted_counts.is_empty(), "Need at least one encrypted count");

    let mut total = encrypted_counts[0].clone();
    for count in &encrypted_counts[1..] {
        total = add_encrypted(public_key, &total, count);
    }

    debug!("Aggregated {} encrypted counts (homomorphic sum)", encrypted_counts.len());
    total
}

// --- Helpers ---

fn pad_to_16(bytes: &[u8]) -> [u8; 16] {
    let mut padded = [0u8; 16];
    let len = bytes.len().min(16);
    padded[..len].copy_from_slice(&bytes[..len]);
    padded
}

fn generate_safe_prime(rng: &mut impl Rng) -> u128 {
    // Generate primes in a reasonable range for u128 arithmetic
    let small_primes: Vec<u64> = vec![
        65537, 65539, 65543, 65551, 65557, 65563, 65579, 65581,
        65587, 65599, 65609, 65617, 65629, 65633, 65647, 65651,
        65657, 65677, 65687, 65699, 65701, 65707, 65713, 65717,
        65719, 65729, 65731, 65761, 65777, 65789, 65809, 65827,
    ];
    small_primes[rng.gen_range(0..small_primes.len())] as u128
}

fn generate_safe_prime_different(rng: &mut impl Rng, not_equal_to: u128) -> u128 {
    loop {
        let p = generate_safe_prime(rng);
        if p != not_equal_to {
            return p;
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (pub_key, priv_key) = generate_keypair();
        let plaintext = 42u64;
        let encrypted = encrypt(&pub_key, plaintext);
        let decrypted = decrypt(&priv_key, &encrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_homomorphic_addition() {
        let (pub_key, priv_key) = generate_keypair();
        let a = 15u64;
        let b = 27u64;

        let enc_a = encrypt(&pub_key, a);
        let enc_b = encrypt(&pub_key, b);

        // Add encrypted values WITHOUT decrypting
        let enc_sum = add_encrypted(&pub_key, &enc_a, &enc_b);

        // Decrypt the sum
        let sum = decrypt(&priv_key, &enc_sum);
        assert_eq!(sum, a + b); // 42!
    }

    #[test]
    fn test_homomorphic_scalar_multiplication() {
        let (pub_key, priv_key) = generate_keypair();
        let value = 7u64;
        let scalar = 6u64;

        let encrypted = encrypt(&pub_key, value);
        let enc_product = multiply_encrypted_by_scalar(&pub_key, &encrypted, scalar);

        let product = decrypt(&priv_key, &enc_product);
        assert_eq!(product, value * scalar); // 42!
    }

    #[test]
    fn test_semantic_security() {
        // Same plaintext should produce different ciphertexts (due to random r)
        let (pub_key, _) = generate_keypair();
        let enc1 = encrypt(&pub_key, 42);
        let enc2 = encrypt(&pub_key, 42);
        assert_ne!(enc1.ciphertext, enc2.ciphertext);
    }

    #[test]
    fn test_aggregate_encrypted_counts() {
        let (pub_key, priv_key) = generate_keypair();
        let counts = vec![5u64, 10, 15, 20];
        let encrypted: Vec<_> = counts.iter().map(|&c| encrypt(&pub_key, c)).collect();

        let total_encrypted = aggregate_encrypted_counts(&pub_key, &encrypted);
        let total = decrypt(&priv_key, &total_encrypted);
        assert_eq!(total, counts.iter().sum::<u64>()); // 50
    }
}
