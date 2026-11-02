use super::*;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use osoosi_behavioral::{EmbeddingGemma2Engine, MatryoshkaDim};
use osoosi_types::{ArmRole, HostSecurityEvent, OctopusSecurityError};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

// ============================================================================
// 5. Revocation-Bound Capability Delegation Cache & Concurrency Seqlock Barrier
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CapabilityCacheKey {
    pub principal_id: String,
    pub action: CedarAction,
    pub resource_id: String,
    pub policy_version: String,
    pub taint_epoch: u64,
    pub revocation_seq: u64,
    /// BLAKE3 fingerprint over every decision input read by `evaluate_cedar_request` (principal
    /// session/authority, resource attributes, request context, live causal-graph state, and workload
    /// degradation mode). A cached permit may only be replayed for a request whose complete decision
    /// inputs are identical; any context that could produce a forbid (egress budget exhaustion, taint,
    /// semantic similarity, missing capability, terminated session) yields a different key.
    pub decision_input_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardedEffectOutcome<T> {
    Committed {
        output: T,
        policy_decision_id: String,
        causal_event_id: String,
    },
    DeniedPreExecution {
        policy_decision_id: String,
        causal_event_id: String,
        reason: String,
    },
    DeniedByConcurrentRevocation {
        policy_decision_id: String,
        causal_event_id: String,
        decision_taint_epoch: u64,
        current_taint_epoch: u64,
        decision_revocation_seq: u64,
        current_revocation_seq: u64,
        reason: String,
    },
}

pub struct RevocationBoundCapabilityCache {
    pub(crate) entries: DashMap<CapabilityCacheKey, PolicyDecisionRecord>,
    pub(crate) taint_epoch: AtomicU64,
    pub(crate) revocation_seq: AtomicU64,
    pub(crate) in_flight_sensitive_reads: AtomicU64,
    pub(crate) taint_transition_barrier: RwLock<()>,
}

impl Default for RevocationBoundCapabilityCache {
    fn default() -> Self {
        Self::new()
    }
}

impl RevocationBoundCapabilityCache {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            taint_epoch: AtomicU64::new(1),
            revocation_seq: AtomicU64::new(1),
            in_flight_sensitive_reads: AtomicU64::new(0),
            taint_transition_barrier: RwLock::new(()),
        }
    }

    pub fn current_taint_epoch(&self) -> u64 {
        self.taint_epoch.load(Ordering::SeqCst)
    }

    pub fn current_revocation_seq(&self) -> u64 {
        self.revocation_seq.load(Ordering::SeqCst)
    }

    pub fn in_flight_sensitive_reads(&self) -> u64 {
        self.in_flight_sensitive_reads.load(Ordering::SeqCst)
    }

    pub fn advance_taint_and_revocation(&self) -> (u64, u64) {
        let new_taint = self.taint_epoch.fetch_add(1, Ordering::SeqCst) + 1;
        let new_rev = self.revocation_seq.fetch_add(1, Ordering::SeqCst) + 1;
        self.entries.clear();
        (new_taint, new_rev)
    }

    pub fn get_cached(&self, key: &CapabilityCacheKey) -> Option<PolicyDecisionRecord> {
        if key.taint_epoch != self.current_taint_epoch()
            || key.revocation_seq != self.current_revocation_seq()
            || self.in_flight_sensitive_reads() > 0
        {
            return None;
        }
        self.entries.get(key).map(|r| r.value().clone())
    }

    pub fn put_cached(&self, key: CapabilityCacheKey, decision: PolicyDecisionRecord) {
        if decision.allowed
            && key.taint_epoch == self.current_taint_epoch()
            && key.revocation_seq == self.current_revocation_seq()
            && self.in_flight_sensitive_reads() == 0
        {
            self.entries.insert(key, decision);
        }
    }
}

