use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchMetadata {
    pub cve_id: String,
    pub description: String,
    pub severity: PatchSeverity,
    pub component: String,
    pub version: String,
    #[serde(default)]
    pub download_url: Option<String>,
    /// Expected SHA256 of patch file for legitimacy verification. If set, apply is rejected when hash does not match.
    #[serde(default)]
    pub expected_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PatchSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PatchState {
    Discovery,
    Snapshotting,
    Applying,
    Verifying,
    Committed,
    RollingBack,
    Quarantined,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchTransaction {
    pub transaction_id: String,
    pub patch: PatchMetadata,
    pub state: PatchState,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub snapshot_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthMetric {
    pub component: String,
    pub score: f32, // 0.0 to 1.0
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealth {
    pub overall_score: f32,
    pub metrics: Vec<HealthMetric>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAnnouncement {
    pub policy_id: String,
    pub name: String,
    pub hash: String,
    pub component: String,
    pub version: String,
    pub announced_by: String, // node ID
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyHealthStatus {
    Optimal,
    Degraded,
    CriticalFailure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyHealthVote {
    pub policy_id: String,
    pub voter_id: String,
    pub status: PolicyHealthStatus,
    pub uptime_seconds: u64,
    pub timestamp: DateTime<Utc>,
    /// Optional proof-of-work (Sybil / cheap-VM resistance): hex string `nonce` such that
    /// SHA256(`voter_id`|`policy_id`|`nonce`) has at least `OSOOSI_POW_VOTE_BITS` leading zero bits (when that env > 0).
    #[serde(default)]
    pub work_nonce: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyConsensusMessage {
    Announcement(PolicyAnnouncement),
    Vote(PolicyHealthVote),
}

/// Peer status broadcast for mesh join rules. Peers publish this so others can enforce require_patched / require_supported_os.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAnnounce {
    pub source_node: String,
    /// No pending critical/high security patches.
    pub is_patched: bool,
    pub os_name: String,
    pub os_version: String,
    /// OS is within support lifecycle (not EOL).
    pub os_supported: bool,
    pub timestamp: DateTime<Utc>,
    /// Master Node signature of the source_node ID (hex). Required if Master Node security is enabled.
    #[serde(default)]
    pub membership_proof: Option<String>,
}

/// Stored peer status (from PeerAnnounce) for join rule enforcement.
#[derive(Debug, Clone)]
pub struct PeerStatus {
    pub peer_id: String,
    pub is_patched: bool,
    pub os_name: String,
    pub os_version: String,
    pub os_supported: bool,
    pub received_at: DateTime<Utc>,
}
