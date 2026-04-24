//! Threat intelligence types: CVE (NVD) and KEV (CISA).
//!
//! Used for active threat detection and automated patching/tarpitting.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Recommended autonomous response action.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Default)]
pub enum ResponseAction {
    /// Log and alert only
    #[default]
    Alert,
    /// Materialize fake data (Honey-traps)
    Deception,
    /// Throttle CPU/Memory access
    Tarpit,
    /// Both deception and throttling
    GhostTarpit,
    /// Kill process and network
    Isolate,
    /// Deep memory scan (Windows only)
    MemoryScan,
    /// Rollback registry persistence
    RegistryRepair,
}

/// State of an autonomous action (Human-in-the-loop).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ActionState {
    #[default]
    Pending,
    Approved,
    Rejected,
    Executed,
    Failed,
}

impl std::str::FromStr for ResponseAction {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "alert" => Ok(ResponseAction::Alert),
            "deception" | "ghost" => Ok(ResponseAction::Deception),
            "tarpit" => Ok(ResponseAction::Tarpit),
            "ghosttarpit" | "ghost_tarpit" => Ok(ResponseAction::GhostTarpit),
            "isolate" | "kill" => Ok(ResponseAction::Isolate),
            _ => Err(()),
        }
    }
}

/// CVE (Common Vulnerabilities and Exposures) from NVD.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cve {
    pub cve_id: String,
    pub description: String,
    pub cvssv3_score: Option<f32>,
    pub published_date: DateTime<Utc>,
}

/// CISA KEV (Known Exploited Vulnerabilities) entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Kev {
    pub cve_id: String,
    pub vendor_project: String,
    pub product: String,
    pub vulnerability_name: String,
    pub date_added: DateTime<Utc>,
    pub required_action: String,
    pub due_date: DateTime<Utc>,
    pub known_exploited: bool,
}

/// NIST NSRL (National Software Reference Library) record.
/// Used for 'Known Good' file identification (allowlisting).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NsrlRecord {
    pub sha1: String,
    pub md5: Option<String>,
    pub sha256: Option<String>,
    pub file_name: String,
    pub file_size: u64,
    pub product_code: Option<String>,
    pub os_code: Option<String>,
}

/// Zero Day Defense: Autonomous response to trending deep-web vulnerabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroDayDefense {
    pub cve_id: String,
    pub title: String,
    pub description: String,
    pub severity: f32, // 0.0 - 1.0
    pub learned_rule: String, // YARA or Sigma rule content
    pub software_target: String, // e.g. "nginx", "openssl"
    pub date_learned: DateTime<Utc>,
}

/// Malware sample for distributed classifier training (EMBER-style).
/// Shared across mesh for continuous learning. Features can be EMBER (2351) or legacy (54).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareSample {
    /// Source host (peer_id or node identifier).
    pub source_node: String,
    /// File hash (SHA256 or Blake3) for deduplication.
    pub file_hash: String,
    /// Label: 0 = malware, 1 = legitimate.
    pub label: u8,
    /// Feature vector. EMBER v2: 2351 floats; legacy: 54 floats.
    pub features: Vec<f64>,
    /// Feature version: "ember_v2" | "legacy".
    #[serde(default = "default_feature_version")]
    pub feature_version: String,
    /// Timestamp when sample was created.
    pub timestamp: DateTime<Utc>,
}

fn default_feature_version() -> String {
    "legacy".to_string()
}

/// Global Intelligence broadcast for mesh-wide "Gossip Sleuthing".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalIntelligence {
    pub source_url: String,
    pub summary: String,
    pub defense: Option<ZeroDayDefense>,
    pub timestamp: DateTime<Utc>,
    pub source_node: String,
}

/// Federated Model Delta: Gossip-based shared feature weights (Privacy Preserving).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedModelDelta {
    pub source_node: String,
    pub features: std::collections::HashMap<String, f32>,
    pub epsilon: f32, // DP noise level used
    pub timestamp: DateTime<Utc>,
}

/// A "Threat Signature" for P2P gossip.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreatSignature {
    pub id: String,
    pub cve_id: Option<String>,
    pub hash_blake3: Option<String>,
    pub process_name: Option<String>,
    pub confidence: f32, // 0.0 - 1.0
    pub detector_count: u32,
    pub detected_at: DateTime<Utc>,
    pub source_node: String,
    pub signature: Option<String>,
    pub public_key: Option<String>,
    pub merkle_proof: Option<crate::trust::MerkleProof>,
    pub recommended_action: ResponseAction,
    /// Human-readable explanation of why this was flagged (explainable AI).
    #[serde(default)]
    pub reason: Option<String>,
    /// Predicted next attack step if not remediated (predictive remediation).
    #[serde(default)]
    pub predicted_next: Option<String>,
    /// Privacy budget (epsilon) spent on this signature (Differential Privacy).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epsilon: Option<f32>,
    /// Whether this action requires manual human approval before execution.
    #[serde(default)]
    pub require_approval: bool,
    /// Current state of the recommended action.
    #[serde(default)]
    pub action_state: ActionState,
}

impl ThreatSignature {
    pub fn new(source_node: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            cve_id: None,
            hash_blake3: None,
            process_name: None,
            confidence: 0.0,
            detector_count: 0,
            detected_at: Utc::now(),
            source_node,
            signature: None,
            public_key: None,
            merkle_proof: None,
            recommended_action: ResponseAction::Alert,
            reason: None,
            predicted_next: None,
            epsilon: None,
            require_approval: false,
            action_state: ActionState::Pending,
        }
    }

    /// Append a reason (explainable AI). Chains multiple reasons.
    pub fn add_reason(&mut self, r: impl AsRef<str>) {
        let r = r.as_ref().trim();
        if r.is_empty() {
            return;
        }
        self.reason = Some(match &self.reason {
            Some(existing) => format!("{}; {}", existing, r),
            None => r.to_string(),
        });
    }

    /// Set predicted next attack step.
    pub fn set_predicted_next(&mut self, next: impl Into<String>) {
        self.predicted_next = Some(next.into());
    }

    /// Sign the threat signature using a private key.
    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) -> anyhow::Result<()> {
        use ed25519_dalek::Signer;
        
        let data = self.to_signing_bytes()?;
        let signature = signing_key.sign(&data);
        
        self.signature = Some(hex::encode(signature.to_bytes()));
        self.public_key = Some(hex::encode(signing_key.verifying_key().to_bytes()));
        
        Ok(())
    }

    /// Verify the threat signature using its embedded public key and signature.
    pub fn verify(&self) -> bool {
        use ed25519_dalek::{VerifyingKey, Signature, Verifier};
        
        let (sig_hex, pk_hex) = match (&self.signature, &self.public_key) {
            (Some(s), Some(p)) => (s, p),
            _ => return false,
        };

        let sig_bytes = match hex::decode(sig_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let pk_bytes = match hex::decode(pk_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let signature: Signature = match Signature::try_from(sig_bytes.as_slice()) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let public_key: VerifyingKey = match VerifyingKey::try_from(pk_bytes.as_slice()) {
            Ok(p) => p,
            Err(_) => return false,
        };

        let data = match self.to_signing_bytes() {
            Ok(d) => d,
            Err(_) => return false,
        };

        public_key.verify(&data, &signature).is_ok()
    }

    fn to_signing_bytes(&self) -> anyhow::Result<Vec<u8>> {
        // Sign the core data except the signature itself
        let mut clone = self.clone();
        clone.signature = None;
        Ok(serde_json::to_vec(&clone)?)
    }
}

/// OTX (Open Threat Exchange) indicator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtxIndicator {
    pub indicator_type: String,
    pub value: String,
    pub source: String,
}
