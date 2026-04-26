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

/// A Challenge-Response packet for binary integrity checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationChallenge {
    pub nonce: [u8; 32],
    pub challenger_did: NodeDID,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResponse {
    pub challenge_nonce: [u8; 32],
    pub binary_hash: String,
    pub config_hash: String,
    pub responder_did: NodeDID,
    pub signature: String, // Signature of (nonce + binary_hash + config_hash)
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
