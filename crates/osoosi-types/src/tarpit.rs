use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TarpitArtifact {
    /// The adversary scanned memory and hit our fake executable header
    FakePeHeader { virtual_address: usize },
    /// The adversary attempted to scrape and use a fake credential
    PoisonedCredential { hash: String, token_type: String },
    /// The adversary touched a monitored PAGE_GUARD region
    GuardPageViolation { virtual_address: usize, access_type: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffendingProcess {
    pub pid: u32,
    pub name: String,
    pub executable_path: String,
    /// High-speed cryptographic hash of the malicious binary on disk
    pub blake3_hash: String, 
    /// The command line arguments used to launch the malware
    pub command_line: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshTripwireAlert {
    /// The libp2p PeerId of the node that caught the adversary
    pub source_node_id: String, 
    /// Unix timestamp of the exact millisecond the trap was sprung
    pub timestamp_utc: i64,
    /// What the adversary touched
    pub trigger: TarpitArtifact,
    /// Who the adversary is
    pub offender: OffendingProcess,
    
    // --- Cryptographic Verification ---
    
    /// Ed25519 signature of the serialized fields above to prove node identity
    pub cryptographic_signature: Vec<u8>, 
    /// (Optional) To tie this specific alert into your global consensus state
    pub merkle_proof: Option<Vec<u8>>, 
}
