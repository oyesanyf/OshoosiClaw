//! Cryptographic Routing Seals & Single-Use Consumption Verifier
//!
//! Enforces the foundational CAGE `NoDirectBind` invariant:
//!
//! $$\text{NoDirectBind} \equiv (\text{phase} = \texttt{EXECUTED}) \implies (\text{resolvedAllow} = \texttt{TRUE} \land \text{seal\_present} = \texttt{TRUE})$$
//!
//! Routing seals are issued exclusively upon unanimous governance clearance ([`GovernanceVerdict::Allow`]
//! or [`GovernanceVerdict::Narrow`]). Each seal cryptographically binds an approved action to its
//! execution parameters via an HMAC-SHA256 signature, enforces a strict 30-second TTL
//! (`expires_at = issued_at + 30`), and requires atomic single-use consumption by downstream
//! host capability gates to prevent execution replays.

use dashmap::DashSet;
use hmac::{Hmac, Mac};
use osoosi_types::cage::RoutingSeal;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Strict 30-second TTL duration for all CAGE routing seals.
pub const ROUTING_SEAL_TTL_SECS: u64 = 30;

/// Rejection reasons returned when a routing seal fails validation or consumption.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum SealRejection {
    #[error("Routing seal signature is invalid or tampered")]
    InvalidSignature,

    #[error("Routing seal has expired: current_time={current_time} > expires_at={expires_at} (TTL exceeded)")]
    Expired { current_time: u64, expires_at: u64 },

    #[error("Routing seal issued in future or severe clock drift: current_time={current_time} < issued_at={issued_at}")]
    FutureTimestamp { current_time: u64, issued_at: u64 },

    #[error("Routing seal already consumed (single-use replay detected): {0}")]
    AlreadyConsumed(String),

    #[error("Policy version mismatch: expected active version '{expected}', seal specifies '{actual}'")]
    PolicyVersionMismatch { expected: String, actual: String },

    #[error("Action digest mismatch: expected '{expected}', seal contains '{actual}'")]
    ActionDigestMismatch { expected: String, actual: String },

    #[error("Malformed routing seal: {0}")]
    MalformedSeal(String),
}

/// Computes the 64-character lowercase hex SHA-256 action digest over an action and its canonical JSON parameters.
pub fn compute_action_digest(action_name: &str, params: &serde_json::Value) -> String {
    let canonical_params = crate::cage::policy_ingest::canonicalize_jcs(params)
        .unwrap_or_else(|_| params.to_string());
    let mut hasher = Sha256::new();
    hasher.update(action_name.as_bytes());
    hasher.update(b":");
    hasher.update(canonical_params.as_bytes());
    hex::encode(hasher.finalize())
}

/// Signer and verifier for cryptographic 30-second TTL single-use routing seals.
pub struct RoutingSealSigner {
    secret_key: Vec<u8>,
    policy_version_id: RwLock<String>,
    consumed_seals: Arc<DashSet<String>>,
}

impl RoutingSealSigner {
    /// Creates a new seal signer with the specified HMAC secret key and active policy version ID.
    pub fn new(secret_key: &[u8], policy_version_id: &str) -> Self {
        Self {
            secret_key: secret_key.to_vec(),
            policy_version_id: RwLock::new(policy_version_id.to_string()),
            consumed_seals: Arc::new(DashSet::new()),
        }
    }

    /// Returns the currently active policy version ID.
    pub fn active_policy_version(&self) -> String {
        self.policy_version_id.read().clone()
    }

    /// Updates the active policy version ID.
    pub fn set_policy_version(&self, new_version: &str) {
        let mut w = self.policy_version_id.write();
        *w = new_version.to_string();
    }

    /// Computes the HMAC-SHA256 signature over the canonical seal payload:
    ///
    /// `seal_id|action_digest|policy_version_id|issued_at`
    pub fn compute_signature(
        secret_key: &[u8],
        seal_id: &str,
        action_digest: &str,
        policy_version_id: &str,
        issued_at: u64,
    ) -> String {
        let payload = format!("{}|{}|{}|{}", seal_id, action_digest, policy_version_id, issued_at);
        let mut mac = HmacSha256::new_from_slice(secret_key)
            .expect("HMAC initialization must succeed with any key length");
        mac.update(payload.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Issues a new cryptographic routing seal for an approved action digest.
    ///
    /// Configures strict 30-second TTL: `expires_at = issued_at + 30`.
    pub fn issue_seal(&self, action_digest: &str, now: u64) -> RoutingSeal {
        let seal_id = format!("seal_{}", uuid::Uuid::new_v4().simple());
        let version_id = self.active_policy_version();
        let expires_at = now + ROUTING_SEAL_TTL_SECS;

        let signature = Self::compute_signature(
            &self.secret_key,
            &seal_id,
            action_digest,
            &version_id,
            now,
        );

        RoutingSeal {
            seal_id,
            policy_version_id: version_id,
            action_digest: action_digest.to_string(),
            issued_at: now,
            expires_at,
            signature,
        }
    }

    /// Issues a seal using the system clock timestamp.
    pub fn issue_seal_now(&self, action_digest: &str) -> RoutingSeal {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.issue_seal(action_digest, now)
    }

    /// Verifies the HMAC-SHA256 signature of a routing seal in constant time.
    pub fn verify_signature(&self, seal: &RoutingSeal) -> bool {
        let expected_sig = Self::compute_signature(
            &self.secret_key,
            &seal.seal_id,
            &seal.action_digest,
            &seal.policy_version_id,
            seal.issued_at,
        );

        if seal.signature.len() != expected_sig.len() {
            return false;
        }

        seal.signature.as_bytes().ct_eq(expected_sig.as_bytes()).into()
    }

    /// Validates seal format, policy version, action digest, TTL window, and HMAC signature.
    pub fn validate_seal_properties(
        &self,
        seal: &RoutingSeal,
        expected_action_digest: &str,
        current_time: u64,
    ) -> Result<(), SealRejection> {
        // 1. Format validation
        if !seal.validate_format() {
            return Err(SealRejection::MalformedSeal(
                "Seal fields do not meet hex or length requirements".to_string(),
            ));
        }

        // 2. Policy version check
        let active_ver = self.active_policy_version();
        if seal.policy_version_id != active_ver {
            return Err(SealRejection::PolicyVersionMismatch {
                expected: active_ver,
                actual: seal.policy_version_id.clone(),
            });
        }

        // 3. Action digest binding
        if seal.action_digest != expected_action_digest {
            return Err(SealRejection::ActionDigestMismatch {
                expected: expected_action_digest.to_string(),
                actual: seal.action_digest.clone(),
            });
        }

        // 4. Future timestamp / clock drift check (allow up to 5s clock skew)
        if seal.issued_at > current_time + 5 {
            return Err(SealRejection::FutureTimestamp {
                current_time,
                issued_at: seal.issued_at,
            });
        }

        // 5. Expiration / TTL check
        if seal.is_expired(current_time) {
            return Err(SealRejection::Expired {
                current_time,
                expires_at: seal.expires_at,
            });
        }

        // 6. Cryptographic signature check
        if !self.verify_signature(seal) {
            return Err(SealRejection::InvalidSignature);
        }

        Ok(())
    }

    /// Atomically validates the seal and consumes it in the thread-safe nonce set.
    ///
    /// If already consumed or invalid, execution fails closed with [`SealRejection`].
    pub fn validate_and_consume(
        &self,
        seal: &RoutingSeal,
        expected_action_digest: &str,
        current_time: u64,
    ) -> Result<(), SealRejection> {
        self.validate_seal_properties(seal, expected_action_digest, current_time)?;

        // Atomic single-use consumption
        if !self.consumed_seals.insert(seal.seal_id.clone()) {
            return Err(SealRejection::AlreadyConsumed(seal.seal_id.clone()));
        }

        Ok(())
    }

    /// Atomically consumes a seal using current system timestamp.
    pub fn validate_and_consume_now(
        &self,
        seal: &RoutingSeal,
        expected_action_digest: &str,
    ) -> Result<(), SealRejection> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.validate_and_consume(seal, expected_action_digest, now)
    }

    /// Checks if a specific seal ID has already been consumed.
    pub fn is_seal_consumed(&self, seal_id: &str) -> bool {
        self.consumed_seals.contains(seal_id)
    }

    /// Returns the total count of consumed seals.
    pub fn consumed_count(&self) -> usize {
        self.consumed_seals.len()
    }
}
