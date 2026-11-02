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
// 3. Non-Forgeable Composite ProcessInstanceIdentity, Broker Attribution & CausalSecurityGraph
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessInstanceIdentity {
    pub pid: u32,
    pub start_time_100ns: u64,
    pub image_digest_blake3: String,
    pub parent_instance_key: Option<String>,
    pub job_object_id: Option<String>,
    pub origin_session_id: String,
}

impl ProcessInstanceIdentity {
    pub fn new(
        pid: u32,
        start_time_100ns: u64,
        image_digest_blake3: impl Into<String>,
        parent_instance_key: Option<String>,
        job_object_id: Option<String>,
        origin_session_id: impl Into<String>,
    ) -> Self {
        Self {
            pid,
            start_time_100ns,
            image_digest_blake3: image_digest_blake3.into(),
            parent_instance_key,
            job_object_id,
            origin_session_id: origin_session_id.into(),
        }
    }

    pub fn instance_key(&self) -> String {
        let dig_prefix = &self.image_digest_blake3[..self.image_digest_blake3.len().min(12)];
        format!(
            "proc:{}:{}:{}:{}",
            self.pid, self.start_time_100ns, dig_prefix, self.origin_session_id
        )
    }
}

/// Identifies system/developer broker processes (`P1.2` Confused-Deputy Broker Attribution)
/// that execute operations on behalf of an initiating agent process/session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BrokerAttributionRecord {
    pub broker_image: String,
    pub broker_pid: u32,
    pub requesting_client_pid: u32,
    pub requesting_instance_key: String,
    pub attributed_origin_session_id: String,
    pub inherited_crown_jewel_taint: bool,
    pub inherited_taint_level: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalNodeState {
    pub node_key: String,
    pub origin_session_id: String,
    pub process_identity: Option<ProcessInstanceIdentity>,
    pub authority_level: AuthorityLevel,
    pub taint_level: f64,
    pub has_crown_jewel_taint: bool,
    pub highest_classification: DataClassification,
    pub cumulative_turns: u32,
    pub ancestor_keys: Vec<String>,
    pub last_causal_event_id: String,
    pub capabilities_revoked: bool,
    pub declassified_receipts: Vec<String>,
    pub session_terminated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustedTransformationKind {
    BooleanPassFailSummary,
    AggregateMetricCount,
    ZkRedactedAuditSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeclassificationReceipt {
    pub receipt_id: String,
    pub session_id: String,
    pub source_node_key: String,
    pub sanitized_payload_blake3: String,
    pub supervisor_hmac_tag: String,
    pub issued_at: DateTime<Utc>,
}

pub struct CausalSecurityGraph {
    nodes: DashMap<String, CausalNodeState>,
    pub(crate) pid_to_latest_instance: DashMap<u32, String>,
    session_taint: DashMap<String, CausalNodeState>,
    declassification_receipts: DashMap<String, DeclassificationReceipt>,
    broker_attributions: DashMap<u32, BrokerAttributionRecord>,
    supervisor_key: [u8; 32],
    causal_seq: AtomicU64,
}

impl Default for CausalSecurityGraph {
    fn default() -> Self {
        Self::new(*DEFAULT_SUPERVISOR_DECLASSIFY_KEY)
    }
}

impl CausalSecurityGraph {
    pub fn new(supervisor_key: [u8; 32]) -> Self {
        Self {
            nodes: DashMap::new(),
            pid_to_latest_instance: DashMap::new(),
            session_taint: DashMap::new(),
            declassification_receipts: DashMap::new(),
            broker_attributions: DashMap::new(),
            supervisor_key,
            causal_seq: AtomicU64::new(1),
        }
    }

    fn next_causal_event_id(&self, prefix: &str, key: &str) -> String {
        let seq = self.causal_seq.fetch_add(1, Ordering::SeqCst);
        let digest = blake3::hash(format!("{}:{}:{}", prefix, key, seq).as_bytes());
        format!("cevt-{:06}-{}", seq, &digest.to_hex()[..12])
    }

    /// Returns true if an executable image is a system/developer broker (`WmiPrvSE.exe`, `svchost.exe`,
    /// `conhost.exe`, `git-remote-https.exe`, `ssh.exe`, `dllhost.exe`).
    pub fn is_broker_process_image(image: &str) -> bool {
        let lower = image.replace('\\', "/").to_ascii_lowercase();
        const BROKERS: &[&str] = &[
            "wmiprvse.exe",
            "svchost.exe",
            "conhost.exe",
            "git-remote-https",
            "git-remote-http",
            "ssh.exe",
            "/usr/bin/ssh",
            "dllhost.exe",
            "backgroundtaskhost.exe",
        ];
        BROKERS
            .iter()
            .any(|b| lower.ends_with(b) || lower.contains(b))
    }

    /// Attributes a broker process (`WmiPrvSE.exe`, `svchost.exe`, `conhost.exe`, `git-remote-https.exe`, `ssh.exe`)
    /// to the requesting client PID / agent session (`P1.2` Confused-Deputy Broker Attribution) so that a tainted
    /// agent cannot launder privileged or outbound actions through an OS/Git/SSH broker.
    pub fn attribute_broker_operation(
        &self,
        broker_pid: u32,
        broker_start_time_100ns: u64,
        broker_image: &str,
        requesting_client_pid: u32,
        fallback_session_id: &str,
    ) -> (CausalNodeState, BrokerAttributionRecord) {
        let client_instance_key = self
            .pid_to_latest_instance
            .get(&requesting_client_pid)
            .map(|r| r.value().clone());

        let client_state = self.resolve_state(
            client_instance_key.as_deref(),
            Some(requesting_client_pid),
            fallback_session_id,
        );

        let broker_identity = ProcessInstanceIdentity::new(
            broker_pid,
            broker_start_time_100ns,
            blake3::hash(format!("broker:{}:{}", broker_image, requesting_client_pid).as_bytes())
                .to_hex()
                .to_string(),
            Some(client_state.node_key.clone()),
            None,
            client_state.origin_session_id.clone(),
        );

        let broker_state =
            self.register_process_instance(broker_identity, client_state.authority_level);

        let record = BrokerAttributionRecord {
            broker_image: broker_image.to_string(),
            broker_pid,
            requesting_client_pid,
            requesting_instance_key: client_state.node_key,
            attributed_origin_session_id: broker_state.origin_session_id.clone(),
            inherited_crown_jewel_taint: broker_state.has_crown_jewel_taint,
            inherited_taint_level: broker_state.taint_level,
        };
        self.broker_attributions.insert(broker_pid, record.clone());
        (broker_state, record)
    }

    pub fn register_process_instance(
        &self,
        identity: ProcessInstanceIdentity,
        initial_authority: AuthorityLevel,
    ) -> CausalNodeState {
        let key = identity.instance_key();
        let mut taint_level = 0.0_f64;
        let mut has_crown_jewel_taint = false;
        let mut highest_classification = DataClassification::InternalWorkspace;
        let mut cumulative_turns = 1_u32;
        let mut ancestor_keys = Vec::new();
        let mut effective_authority = initial_authority;
        let mut capabilities_revoked = false;

        if let Some(ref parent_key) = identity.parent_instance_key {
            if let Some(parent_ref) = self.nodes.get(parent_key) {
                let p = parent_ref.value();
                taint_level = taint_level.max(p.taint_level);
                has_crown_jewel_taint |= p.has_crown_jewel_taint;
                highest_classification = highest_classification.max(p.highest_classification);
                cumulative_turns = p.cumulative_turns.saturating_add(1);
                ancestor_keys = p.ancestor_keys.clone();
                ancestor_keys.push(parent_key.clone());
                if effective_authority.rank() < p.authority_level.rank() {
                    effective_authority = p.authority_level;
                }
                capabilities_revoked |= p.capabilities_revoked;
            }
        }

        if let Some(sess_ref) = self.session_taint.get(&identity.origin_session_id) {
            let s = sess_ref.value();
            taint_level = taint_level.max(s.taint_level);
            has_crown_jewel_taint |= s.has_crown_jewel_taint;
            highest_classification = highest_classification.max(s.highest_classification);
            cumulative_turns = cumulative_turns.max(s.cumulative_turns);
            capabilities_revoked |= s.capabilities_revoked;
        }

        let causal_event_id = self.next_causal_event_id("proc-spawn", &key);
        let state = CausalNodeState {
            node_key: key.clone(),
            origin_session_id: identity.origin_session_id.clone(),
            process_identity: Some(identity.clone()),
            authority_level: effective_authority,
            taint_level,
            has_crown_jewel_taint,
            highest_classification,
            cumulative_turns,
            ancestor_keys,
            last_causal_event_id: causal_event_id,
            capabilities_revoked,
            declassified_receipts: Vec::new(),
            session_terminated: false,
        };

        self.nodes.insert(key.clone(), state.clone());
        self.pid_to_latest_instance.insert(identity.pid, key);
        self.sync_session_state(&state);
        state
    }

    /// Evicts deceased process instance mapping on Sysmon Event 5 (Process Termination)
    /// to prevent PID reuse / taint laundering.
    pub fn evict_process_termination(&self, pid: u32) {
        self.pid_to_latest_instance.remove(&pid);
        self.broker_attributions.remove(&pid);
    }

    fn sync_session_state(&self, node: &CausalNodeState) {
        let sess_id = node.origin_session_id.clone();
        let existing = self.session_taint.get(&sess_id).map(|r| r.value().clone());
        let updated = match existing {
            Some(mut cur) => {
                cur.taint_level = cur.taint_level.max(node.taint_level);
                cur.has_crown_jewel_taint |= node.has_crown_jewel_taint;
                cur.highest_classification =
                    cur.highest_classification.max(node.highest_classification);
                cur.cumulative_turns = cur.cumulative_turns.max(node.cumulative_turns);
                cur.last_causal_event_id = node.last_causal_event_id.clone();
                cur.capabilities_revoked |= node.capabilities_revoked;
                if node.authority_level.rank() > cur.authority_level.rank() {
                    cur.authority_level = node.authority_level;
                }
                cur
            }
            None => node.clone(),
        };
        self.session_taint.insert(sess_id, updated);
    }

    pub fn record_causal_step(
        &self,
        node_key: &str,
        session_id: &str,
        step_taint_delta: f64,
        classification_read: DataClassification,
        salami_increment: f64,
    ) -> CausalNodeState {
        let existing_node = self.nodes.get(node_key).map(|r| r.value().clone());
        let existing_sess = self
            .session_taint
            .get(session_id)
            .map(|r| r.value().clone());

        let base = existing_node.or(existing_sess).unwrap_or(CausalNodeState {
            node_key: node_key.to_string(),
            origin_session_id: session_id.to_string(),
            process_identity: None,
            authority_level: AuthorityLevel::L2AuthorizedUserObjective,
            taint_level: 0.0,
            has_crown_jewel_taint: false,
            highest_classification: DataClassification::Public,
            cumulative_turns: 0,
            ancestor_keys: Vec::new(),
            last_causal_event_id: String::new(),
            capabilities_revoked: false,
            declassified_receipts: Vec::new(),
            session_terminated: false,
        });

        let is_crown_jewel = classification_read == DataClassification::CrownJewelSecret;
        let next_taint = (base.taint_level.max(step_taint_delta) + salami_increment.max(0.0))
            .max(if is_crown_jewel { 0.95 } else { 0.0 })
            .min(1.0);
        let causal_event_id = self.next_causal_event_id("step", node_key);

        let updated = CausalNodeState {
            node_key: node_key.to_string(),
            origin_session_id: session_id.to_string(),
            process_identity: base.process_identity,
            authority_level: base.authority_level,
            taint_level: next_taint,
            has_crown_jewel_taint: base.has_crown_jewel_taint || is_crown_jewel,
            highest_classification: base.highest_classification.max(classification_read),
            cumulative_turns: base.cumulative_turns.saturating_add(1),
            ancestor_keys: base.ancestor_keys,
            last_causal_event_id: causal_event_id,
            capabilities_revoked: base.capabilities_revoked,
            declassified_receipts: base.declassified_receipts,
            session_terminated: base.session_terminated,
        };

        self.nodes.insert(node_key.to_string(), updated.clone());
        self.sync_session_state(&updated);
        updated
    }

    pub fn propagate_edge(
        &self,
        source_key: &str,
        target_key: &str,
        target_session_id: &str,
    ) -> CausalNodeState {
        let src = self
            .nodes
            .get(source_key)
            .map(|r| r.value().clone())
            .or_else(|| {
                self.session_taint
                    .get(source_key)
                    .map(|r| r.value().clone())
            });

        let dst = self
            .nodes
            .get(target_key)
            .map(|r| r.value().clone())
            .unwrap_or(CausalNodeState {
                node_key: target_key.to_string(),
                origin_session_id: target_session_id.to_string(),
                process_identity: None,
                authority_level: AuthorityLevel::L2AuthorizedUserObjective,
                taint_level: 0.0,
                has_crown_jewel_taint: false,
                highest_classification: DataClassification::Public,
                cumulative_turns: 0,
                ancestor_keys: Vec::new(),
                last_causal_event_id: String::new(),
                capabilities_revoked: false,
                declassified_receipts: Vec::new(),
                session_terminated: false,
            });

        let (
            taint_level,
            has_crown_jewel_taint,
            highest_classification,
            mut ancestors,
            turns,
            revoked,
        ) = if let Some(s) = src {
            let mut anc = dst.ancestor_keys.clone();
            for k in &s.ancestor_keys {
                if !anc.contains(k) {
                    anc.push(k.clone());
                }
            }
            if !anc.contains(&s.node_key) {
                anc.push(s.node_key.clone());
            }
            (
                dst.taint_level.max(s.taint_level),
                dst.has_crown_jewel_taint || s.has_crown_jewel_taint,
                dst.highest_classification.max(s.highest_classification),
                anc,
                dst.cumulative_turns
                    .max(s.cumulative_turns)
                    .saturating_add(1),
                dst.capabilities_revoked || s.capabilities_revoked,
            )
        } else {
            (
                dst.taint_level,
                dst.has_crown_jewel_taint,
                dst.highest_classification,
                dst.ancestor_keys,
                dst.cumulative_turns.saturating_add(1),
                dst.capabilities_revoked,
            )
        };

        let causal_event_id = self.next_causal_event_id("edge", target_key);
        let updated = CausalNodeState {
            node_key: target_key.to_string(),
            origin_session_id: target_session_id.to_string(),
            process_identity: dst.process_identity,
            authority_level: dst.authority_level,
            taint_level,
            has_crown_jewel_taint,
            highest_classification,
            cumulative_turns: turns,
            ancestor_keys: std::mem::take(&mut ancestors),
            last_causal_event_id: causal_event_id,
            capabilities_revoked: revoked,
            declassified_receipts: dst.declassified_receipts,
            session_terminated: dst.session_terminated,
        };

        self.nodes.insert(target_key.to_string(), updated.clone());
        self.sync_session_state(&updated);
        updated
    }

    pub fn revoke_node_capabilities(&self, node_key: &str, session_id: &str) {
        if let Some(mut node) = self.nodes.get_mut(node_key) {
            node.capabilities_revoked = true;
            node.taint_level = 1.0;
        }
        if let Some(mut sess) = self.session_taint.get_mut(session_id) {
            sess.capabilities_revoked = true;
            sess.taint_level = 1.0;
        }
    }

    pub fn issue_supervisor_declassification_receipt(
        &self,
        session_id: &str,
        source_node_key: &str,
        redacted_payload: &str,
    ) -> Result<DeclassificationReceipt, String> {
        if !redacted_payload.contains("<ZK_PII:")
            && !redacted_payload.contains("<ZK_CROWN_JEWEL_REDACTED:")
            && !redacted_payload.contains("<ZK_MI_REDACTED>")
        {
            return Err(
                "DECLASSIFICATION_REJECTED: Payload must be ZK-redacted (<ZK_PII:...> or <ZK_CROWN_JEWEL_REDACTED:...>)"
                    .to_string(),
            );
        }

        let payload_blake3 = blake3::hash(redacted_payload.as_bytes())
            .to_hex()
            .to_string();
        let msg = format!(
            "zk-declassify-v1|sess={}|node={}|hash={}",
            session_id, source_node_key, payload_blake3
        );
        let mut mac =
            HmacSha256::new_from_slice(&self.supervisor_key).expect("HMAC accepts 32-byte key");
        mac.update(msg.as_bytes());
        let tag_hex = hex::encode(mac.finalize().into_bytes());
        let receipt_id = format!("zkrec-{}", &payload_blake3[..16]);

        let receipt = DeclassificationReceipt {
            receipt_id: receipt_id.clone(),
            session_id: session_id.to_string(),
            source_node_key: source_node_key.to_string(),
            sanitized_payload_blake3: payload_blake3,
            supervisor_hmac_tag: tag_hex,
            issued_at: Utc::now(),
        };
        self.declassification_receipts
            .insert(receipt_id.clone(), receipt.clone());

        if let Some(mut node) = self.nodes.get_mut(source_node_key) {
            node.declassified_receipts.push(receipt_id.clone());
        }
        if let Some(mut sess) = self.session_taint.get_mut(session_id) {
            sess.declassified_receipts.push(receipt_id);
        }
        Ok(receipt)
    }

    pub fn verify_declassification_receipt(
        &self,
        receipt_id: &str,
        session_id: &str,
        redacted_payload: &str,
    ) -> bool {
        let Some(rec_ref) = self.declassification_receipts.get(receipt_id) else {
            return false;
        };
        let rec = rec_ref.value().clone();
        drop(rec_ref);

        if rec.session_id != session_id {
            return false;
        }
        let actual_hash = blake3::hash(redacted_payload.as_bytes())
            .to_hex()
            .to_string();
        if !bool::from(
            rec.sanitized_payload_blake3
                .as_bytes()
                .ct_eq(actual_hash.as_bytes()),
        ) {
            return false;
        }

        let msg = format!(
            "zk-declassify-v1|sess={}|node={}|hash={}",
            rec.session_id, rec.source_node_key, actual_hash
        );
        let mut mac =
            HmacSha256::new_from_slice(&self.supervisor_key).expect("HMAC accepts 32-byte key");
        mac.update(msg.as_bytes());
        let expected = mac.finalize().into_bytes();
        let Ok(provided) = hex::decode(&rec.supervisor_hmac_tag) else {
            return false;
        };
        provided.len() == 32 && bool::from(provided.as_slice().ct_eq(&expected))
    }

    pub fn apply_trusted_transformation(
        &self,
        session_id: &str,
        source_node_key: &str,
        derived_node_key: &str,
        kind: TrustedTransformationKind,
        transformed_value: &str,
    ) -> Result<CausalNodeState, String> {
        let valid_format = match kind {
            TrustedTransformationKind::BooleanPassFailSummary => {
                matches!(transformed_value.trim(), "PASS" | "FAIL" | "true" | "false")
            }
            TrustedTransformationKind::AggregateMetricCount => {
                transformed_value.trim().parse::<u64>().is_ok()
            }
            TrustedTransformationKind::ZkRedactedAuditSummary => {
                transformed_value.contains("<ZK_PII:")
                    || transformed_value.contains("<ZK_CROWN_JEWEL_REDACTED:")
            }
        };
        if !valid_format {
            return Err(format!(
                "TRUSTED_TRANSFORMATION_REJECTED: Value {:?} does not conform to {:?}",
                transformed_value, kind
            ));
        }

        let causal_event_id = self.next_causal_event_id("trusted-transform", derived_node_key);
        let derived = CausalNodeState {
            node_key: derived_node_key.to_string(),
            origin_session_id: session_id.to_string(),
            process_identity: None,
            authority_level: AuthorityLevel::L3TrustedApplicationInstruction,
            taint_level: 0.10,
            has_crown_jewel_taint: false,
            highest_classification: DataClassification::InternalWorkspace,
            cumulative_turns: 1,
            ancestor_keys: vec![source_node_key.to_string()],
            last_causal_event_id: causal_event_id,
            capabilities_revoked: false,
            declassified_receipts: Vec::new(),
            session_terminated: false,
        };
        self.nodes
            .insert(derived_node_key.to_string(), derived.clone());
        Ok(derived)
    }

    pub fn terminate_session(&self, session_id: &str) {
        if let Some(mut sess) = self.session_taint.get_mut(session_id) {
            sess.session_terminated = true;
            sess.capabilities_revoked = true;
        }
        let keys_to_terminate: Vec<String> = self
            .nodes
            .iter()
            .filter(|r| r.value().origin_session_id == session_id)
            .map(|r| r.key().clone())
            .collect();
        for k in keys_to_terminate {
            if let Some(mut node) = self.nodes.get_mut(&k) {
                node.session_terminated = true;
                node.capabilities_revoked = true;
            }
        }
    }

    pub fn resolve_state(
        &self,
        node_key: Option<&str>,
        pid: Option<u32>,
        session_id: &str,
    ) -> CausalNodeState {
        if let Some(k) = node_key {
            if let Some(n) = self.nodes.get(k) {
                let mut state = n.value().clone();
                if let Some(s) = self.session_taint.get(session_id) {
                    state.taint_level = state.taint_level.max(s.taint_level);
                    state.has_crown_jewel_taint |= s.has_crown_jewel_taint;
                    state.highest_classification =
                        state.highest_classification.max(s.highest_classification);
                    state.capabilities_revoked |= s.capabilities_revoked;
                    state.session_terminated |= s.session_terminated;
                }
                return state;
            }
        }
        if let Some(p) = pid {
            if let Some(inst_key) = self.pid_to_latest_instance.get(&p) {
                let k = inst_key.value().clone();
                drop(inst_key);
                if let Some(n) = self.nodes.get(&k) {
                    return n.value().clone();
                }
            }
        }
        if let Some(s) = self.session_taint.get(session_id) {
            return s.value().clone();
        }
        CausalNodeState {
            node_key: node_key.unwrap_or(session_id).to_string(),
            origin_session_id: session_id.to_string(),
            process_identity: None,
            authority_level: AuthorityLevel::L2AuthorizedUserObjective,
            taint_level: 0.0,
            has_crown_jewel_taint: false,
            highest_classification: DataClassification::InternalWorkspace,
            cumulative_turns: 0,
            ancestor_keys: Vec::new(),
            last_causal_event_id: self.next_causal_event_id("init", session_id),
            capabilities_revoked: false,
            declassified_receipts: Vec::new(),
            session_terminated: false,
        }
    }

    /// Exports a deterministic snapshot of all session taint nodes for `P2.2` trusted-state recovery.
    pub fn export_session_snapshot(&self) -> Vec<(String, CausalNodeState)> {
        let mut out: Vec<(String, CausalNodeState)> = self
            .session_taint
            .iter()
            .map(|r| (r.key().clone(), r.value().clone()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Restores session taint state from a verified snapshot (`P2.2` recovery).
    pub fn restore_session_snapshot(&self, snapshot: &[(String, CausalNodeState)]) {
        self.session_taint.clear();
        for (k, v) in snapshot {
            self.session_taint.insert(k.clone(), v.clone());
        }
    }
}
