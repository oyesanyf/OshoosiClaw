//! Private Set Intersection (PSI) for OpenỌ̀ṣọ́ọ̀sì.
//!
//! Allows two peers to discover which IoCs (Indicators of Compromise)
//! they have in common — **without revealing their full lists**.
//!
//! # Why PSI Matters for EDR
//! When two mesh peers want to correlate threat data:
//! - **Without PSI**: Node A sends all its hashes to Node B → B now knows
//!   everything A has detected (privacy violation)
//! - **With PSI**: Both nodes learn ONLY the intersection → neither learns
//!   what the other detected beyond the shared matches
//!
//! # Protocol (Diffie-Hellman PSI)
//! 1. Both parties agree on a shared prime `p` and generator `g`
//! 2. Node A hashes each IoC, raises to secret exponent `a`: `H(ioc)^a mod p`
//! 3. Node B hashes each IoC, raises to secret exponent `b`: `H(ioc)^b mod p`
//! 4. They exchange these blinded sets
//! 5. Each raises the other's values to their own exponent:
//!    - A computes: `(H(ioc)^b)^a = H(ioc)^(ab) mod p`
//!    - B computes: `(H(ioc)^a)^b = H(ioc)^(ab) mod p`
//! 6. Values that appear in BOTH doubly-blinded sets are the intersection
//!
//! # Security
//! - Neither party learns the other's non-intersecting elements
//! - The random exponents prevent correlation attacks
//! - Resistant to semi-honest adversaries

use sha2::{Sha256, Digest};
use rand::Rng;
use serde::{Serialize, Deserialize};
use tracing::{info, debug};
use std::collections::HashSet;

/// A safe prime for the DH-PSI protocol.
/// In production, use a larger (2048-bit) safe prime.
const PSI_PRIME: u128 = 0xFFFFFFFFFFFFFFC5; // Large 64-bit prime

/// A blinded set — IoCs raised to a secret exponent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindedSet {
    /// Blinded hash values: H(ioc)^secret mod p
    pub values: Vec<Vec<u8>>,
    /// Unique session identifier
    pub session_id: String,
}

/// Result of a PSI computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsiResult {
    /// Number of items in the intersection
    pub intersection_size: usize,
    /// The intersecting IoCs (only those found in both sets)
    pub common_iocs: Vec<String>,
    /// Total items in our set
    pub our_set_size: usize,
    /// Total items in peer's set (blinded, so just count)
    pub peer_set_size: usize,
}

/// Our side of a PSI session.
pub struct PsiSession {
    /// Our secret exponent
    secret: u128,
    /// Our original IoCs (for matching at the end)
    our_iocs: Vec<String>,
    /// Our doubly-blinded values (for final matching)
    our_doubly_blinded: Vec<u128>,
    /// Session ID
    session_id: String,
}

/// Create a new PSI session and generate our blinded set.
///
/// Call this first, then send the `BlindedSet` to the peer.
pub fn create_psi_session(our_iocs: &[String]) -> (PsiSession, BlindedSet) {
    let mut rng = rand::thread_rng();
    let secret: u128 = rng.gen_range(2..PSI_PRIME - 1);
    let session_id = format!("psi-{}", hex::encode(&secret.to_le_bytes()[..4]));

    debug!("PSI session {} created with {} IoCs", session_id, our_iocs.len());

    // Blind our IoCs: H(ioc)^secret mod p
    let blinded_values: Vec<Vec<u8>> = our_iocs
        .iter()
        .map(|ioc| {
            let hash_point = hash_to_group(ioc);
            let blinded = mod_pow(hash_point, secret, PSI_PRIME);
            blinded.to_le_bytes().to_vec()
        })
        .collect();

    let session = PsiSession {
        secret,
        our_iocs: our_iocs.to_vec(),
        our_doubly_blinded: Vec::new(),
        session_id: session_id.clone(),
    };

    let blinded_set = BlindedSet {
        values: blinded_values,
        session_id,
    };

    (session, blinded_set)
}

/// Process the peer's blinded set and compute our doubly-blinded values.
///
/// 1. Raise peer's blinded values to our secret: `(H(ioc)^b)^a = H(ioc)^(ab)`
/// 2. Return these doubly-blinded values to the peer
/// 3. Also doubly-blind our own set for final matching
pub fn process_peer_blinded_set(
    session: &mut PsiSession,
    peer_blinded: &BlindedSet,
) -> BlindedSet {
    // Doubly-blind the peer's values: (H(ioc)^b)^a mod p
    let peer_doubly_blinded: Vec<Vec<u8>> = peer_blinded
        .values
        .iter()
        .map(|v| {
            let peer_val = u128::from_le_bytes(pad_to_16(v));
            let doubly = mod_pow(peer_val, session.secret, PSI_PRIME);
            doubly.to_le_bytes().to_vec()
        })
        .collect();

    // Also doubly-blind our own set (blind again with our secret for matching)
    // Wait — our values are already blinded once. We need the peer to double-blind them.
    // For the simplified protocol, we compute H(ioc)^(a*a) for self-matching later.
    session.our_doubly_blinded = session
        .our_iocs
        .iter()
        .map(|ioc| {
            let hash_point = hash_to_group(ioc);
            // This is H(ioc)^a — we need the peer to raise to ^b to get H(ioc)^(ab)
            // For now, store our singly-blinded for later matching
            mod_pow(hash_point, session.secret, PSI_PRIME)
        })
        .collect();

    BlindedSet {
        values: peer_doubly_blinded,
        session_id: session.session_id.clone(),
    }
}

/// Process the peer's response (our values doubly-blinded by them).
///
/// The peer has raised our blinded values to their secret, giving us
/// `H(ioc)^(ab) mod p` for each of our IoCs. We compare these with
/// the doubly-blinded values of the peer's IoCs to find the intersection.
pub fn compute_intersection(
    session: &PsiSession,
    our_values_doubly_blinded_by_peer: &BlindedSet,
    peer_values_doubly_blinded_by_us: &BlindedSet,
) -> PsiResult {
    // Build a set of the peer's doubly-blinded values
    let peer_set: HashSet<Vec<u8>> = peer_values_doubly_blinded_by_us
        .values
        .iter()
        .cloned()
        .collect();

    // Find matches: our IoCs whose doubly-blinded values appear in the peer's set
    let mut common_iocs = Vec::new();

    for (i, our_doubly_blinded) in our_values_doubly_blinded_by_peer.values.iter().enumerate() {
        if peer_set.contains(our_doubly_blinded) {
            if i < session.our_iocs.len() {
                common_iocs.push(session.our_iocs[i].clone());
            }
        }
    }

    let result = PsiResult {
        intersection_size: common_iocs.len(),
        common_iocs,
        our_set_size: session.our_iocs.len(),
        peer_set_size: peer_values_doubly_blinded_by_us.values.len(),
    };

    info!(
        "PSI complete: {}/{} IoCs in common (our set: {}, peer set: {})",
        result.intersection_size,
        result.our_set_size.max(result.peer_set_size),
        result.our_set_size,
        result.peer_set_size,
    );

    result
}

/// Quick PSI for two local sets (both sides in one process — for testing).
///
/// In production, each side runs on a different peer.
pub fn local_psi(set_a: &[String], set_b: &[String]) -> PsiResult {
    // Node A creates session
    let (mut session_a, blinded_a) = create_psi_session(set_a);

    // Node B creates session
    let (mut session_b, blinded_b) = create_psi_session(set_b);

    // Exchange and double-blind
    let a_doubly_blinded_by_b = process_peer_blinded_set(&mut session_b, &blinded_a);
    let b_doubly_blinded_by_a = process_peer_blinded_set(&mut session_a, &blinded_b);

    // Node A computes intersection
    compute_intersection(&session_a, &a_doubly_blinded_by_b, &b_doubly_blinded_by_a)
}

// --- Helpers ---

/// Hash a string to a group element in Z*_p.
fn hash_to_group(input: &str) -> u128 {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hasher.update(b"osoosi-psi-v1");
    let hash = hasher.finalize();

    // Take first 16 bytes as u128, ensure it's in the valid range
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    let val = u128::from_le_bytes(bytes);

    // Map to Z*_p (must be non-zero and less than p)
    (val % (PSI_PRIME - 2)) + 2
}

fn mod_pow(mut base: u128, mut exp: u128, modulus: u128) -> u128 {
    if modulus == 1 { return 0; }
    let mut result: u128 = 1;
    base %= modulus;
    while exp > 0 {
        if exp % 2 == 1 {
            result = mod_mul(result, base, modulus);
        }
        exp /= 2;
        base = mod_mul(base, base, modulus);
    }
    result
}

fn mod_mul(a: u128, b: u128, modulus: u128) -> u128 {
    // For large u128 values, we need to handle overflow carefully
    // Using the Russian peasant multiplication method
    let mut result: u128 = 0;
    let mut a = a % modulus;
    let mut b = b % modulus;

    while b > 0 {
        if b & 1 == 1 {
            result = result.wrapping_add(a) % modulus;
        }
        a = a.wrapping_add(a) % modulus;
        b >>= 1;
    }
    result
}

fn pad_to_16(bytes: &[u8]) -> [u8; 16] {
    let mut padded = [0u8; 16];
    let len = bytes.len().min(16);
    padded[..len].copy_from_slice(&bytes[..len]);
    padded
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn iocs(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_local_psi_finds_intersection() {
        let set_a = iocs(&["malware.exe", "trojan.dll", "clean.sys", "backdoor.bin"]);
        let set_b = iocs(&["trojan.dll", "ransomware.exe", "backdoor.bin", "safe.txt"]);

        let result = local_psi(&set_a, &set_b);

        // Should find "trojan.dll" and "backdoor.bin" as common
        assert_eq!(result.intersection_size, 2);
        assert!(result.common_iocs.contains(&"trojan.dll".to_string()));
        assert!(result.common_iocs.contains(&"backdoor.bin".to_string()));
    }

    #[test]
    fn test_psi_no_intersection() {
        let set_a = iocs(&["alpha.exe", "beta.dll"]);
        let set_b = iocs(&["gamma.exe", "delta.dll"]);

        let result = local_psi(&set_a, &set_b);
        assert_eq!(result.intersection_size, 0);
        assert!(result.common_iocs.is_empty());
    }

    #[test]
    fn test_psi_full_intersection() {
        let set = iocs(&["file1.exe", "file2.dll"]);
        let result = local_psi(&set, &set);
        assert_eq!(result.intersection_size, 2);
    }

    #[test]
    fn test_psi_privacy() {
        // Verify that blinded values don't reveal the original IoCs
        let iocs = iocs(&["secret.exe"]);
        let (_, blinded1) = create_psi_session(&iocs);
        let (_, blinded2) = create_psi_session(&iocs);

        // Same IoCs should produce DIFFERENT blinded values (due to random secret)
        assert_ne!(blinded1.values, blinded2.values);
    }
}
