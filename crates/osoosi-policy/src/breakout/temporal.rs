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
// 2.5. Dogwood MFOTL Past-Only Sliding-Window Temporal Policy Evaluator
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TemporalEventType {
    UntrustedWebInput,
    ScratchFileWrite,
    SubprocessEnvOrArg,
    SupervisorDeclassification,
}

pub type TemporalActionKind = TemporalEventType;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporalTraceAtom {
    pub timestamp_utc: i64,
    pub event_type: TemporalEventType,
    pub session_id: String,
    pub resource_path: Option<String>,
}

impl TemporalTraceAtom {
    pub fn new(
        timestamp_utc: i64,
        event_type: TemporalEventType,
        session_id: impl Into<String>,
        resource_path: Option<String>,
    ) -> Self {
        Self {
            timestamp_utc,
            event_type,
            session_id: session_id.into(),
            resource_path,
        }
    }
}

pub fn default_temporal_trace_window_seconds() -> u64 {
    7200
}

#[derive(Debug, Clone)]
pub struct DogwoodTemporalPolicyEvaluator {
    pub default_window_seconds: u64,
    trace_events: Arc<DashMap<String, Vec<TemporalTraceAtom>>>,
}

impl Default for DogwoodTemporalPolicyEvaluator {
    fn default() -> Self {
        Self::new(7200)
    }
}

impl DogwoodTemporalPolicyEvaluator {
    pub fn new(default_window_seconds: u64) -> Self {
        Self {
            default_window_seconds,
            trace_events: Arc::new(DashMap::new()),
        }
    }

    pub fn record_event(
        &self,
        session_id: &str,
        event_type: TemporalEventType,
        resource_path: Option<String>,
    ) {
        let now = Utc::now().timestamp();
        self.record_atom(TemporalTraceAtom {
            timestamp_utc: now,
            event_type,
            session_id: session_id.to_string(),
            resource_path,
        });
    }

    pub fn record_atom(&self, atom: TemporalTraceAtom) {
        let mut entry = self
            .trace_events
            .entry(atom.session_id.clone())
            .or_default();
        let cutoff = atom
            .timestamp_utc
            .saturating_sub(self.default_window_seconds as i64);
        entry.retain(|e| e.timestamp_utc >= cutoff);
        entry.push(atom);
    }

    pub fn record_declassification(&self, session_id: &str) {
        self.record_event(
            session_id,
            TemporalEventType::SupervisorDeclassification,
            None,
        );
    }

    pub fn clear_session(&self, session_id: &str) {
        self.trace_events.remove(session_id);
    }

    pub fn get_session_events(&self, session_id: &str) -> Vec<TemporalTraceAtom> {
        self.trace_events
            .get(session_id)
            .map(|e| e.value().clone())
            .unwrap_or_default()
    }

    /// Evaluates past-only sliding-window Dogwood MFOTL temporal formula:
    /// forbid when temporal {
    ///     formerly within W (Action::UntrustedWebInput)
    ///     && formerly within W (Action::ScratchFileWrite)
    ///     && Action::SubprocessEnvOrArg
    /// } unless temporal {
    ///     formerly within W (Action::SupervisorDeclassification)
    /// }
    pub fn evaluate_taint_flow(
        &self,
        session_id: &str,
        current_time_utc: i64,
        window_seconds: Option<u64>,
    ) -> (bool, Option<String>) {
        let win = window_seconds.unwrap_or(self.default_window_seconds) as i64;
        let Some(events) = self.trace_events.get(session_id) else {
            return (false, None);
        };

        let cutoff = current_time_utc.saturating_sub(win);
        let window_events: Vec<&TemporalTraceAtom> = events
            .iter()
            .filter(|e| e.timestamp_utc >= cutoff && e.timestamp_utc <= current_time_utc)
            .collect();

        // Check for latest supervisor declassification
        let last_declass_time = window_events
            .iter()
            .filter(|e| e.event_type == TemporalEventType::SupervisorDeclassification)
            .map(|e| e.timestamp_utc)
            .max();

        let mut has_web_input = false;
        let mut has_scratch_write = false;

        for e in window_events {
            if let Some(dec_time) = last_declass_time {
                if e.timestamp_utc <= dec_time {
                    continue;
                }
            }

            if e.event_type == TemporalEventType::UntrustedWebInput {
                has_web_input = true;
            } else if e.event_type == TemporalEventType::ScratchFileWrite && has_web_input {
                has_scratch_write = true;
            } else if e.event_type == TemporalEventType::SubprocessEnvOrArg
                && has_web_input
                && has_scratch_write
            {
                return (
                    true,
                    Some(
                        "CEDAR-FORBID-TEMPORAL-TAINT-FRAGMENTATION: CEDAR-FORBID-004D: Multi-turn payload fragmentation detected: untrusted web input flowed into scratch file and subsequently into subprocess execution within temporal window"
                            .to_string(),
                    ),
                );
            }
        }

        (false, None)
    }

    /// Evaluates if a proposed child process execution references or touches any scratch file
    /// written after untrusted web input was recorded within the sliding temporal window.
    pub fn evaluate_scratch_file_touch(
        &self,
        session_id: &str,
        command_line_or_resource: &str,
        current_time_utc: i64,
        window_seconds: Option<u64>,
    ) -> (bool, Option<String>) {
        let win = window_seconds.unwrap_or(self.default_window_seconds) as i64;
        let Some(events) = self.trace_events.get(session_id) else {
            return (false, None);
        };

        let cutoff = current_time_utc.saturating_sub(win);
        let window_events: Vec<&TemporalTraceAtom> = events
            .iter()
            .filter(|e| e.timestamp_utc >= cutoff && e.timestamp_utc <= current_time_utc)
            .collect();

        // Check for latest supervisor declassification
        let last_declass_time = window_events
            .iter()
            .filter(|e| e.event_type == TemporalEventType::SupervisorDeclassification)
            .map(|e| e.timestamp_utc)
            .max();

        let web_inputs: Vec<&TemporalTraceAtom> = window_events
            .iter()
            .filter(|e| e.event_type == TemporalEventType::UntrustedWebInput)
            .copied()
            .collect();

        let scratch_writes: Vec<&TemporalTraceAtom> = window_events
            .iter()
            .filter(|e| e.event_type == TemporalEventType::ScratchFileWrite)
            .copied()
            .collect();

        if web_inputs.is_empty() || scratch_writes.is_empty() {
            return (false, None);
        }

        let earliest_web_input = web_inputs
            .iter()
            .map(|e| e.timestamp_utc)
            .min()
            .unwrap_or(0);
        let writes_after_web: Vec<&TemporalTraceAtom> = scratch_writes
            .into_iter()
            .filter(|sw| sw.timestamp_utc >= earliest_web_input)
            .collect();

        if writes_after_web.is_empty() {
            return (false, None);
        }

        if let Some(dec_time) = last_declass_time {
            let latest_write = writes_after_web
                .iter()
                .map(|e| e.timestamp_utc)
                .max()
                .unwrap_or(0);
            if dec_time >= latest_write {
                return (false, None);
            }
        }

        let lower_cmd = command_line_or_resource.to_ascii_lowercase();
        for sw in &writes_after_web {
            if let Some(ref path) = sw.resource_path {
                let norm_path = path.replace('\\', "/").to_ascii_lowercase();
                let file_name = std::path::Path::new(path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(path)
                    .to_ascii_lowercase();
                if (!file_name.is_empty() && lower_cmd.contains(&file_name))
                    || lower_cmd.contains(&norm_path)
                    || lower_cmd.contains(&path.to_ascii_lowercase())
                {
                    return (
                        true,
                        Some(format!(
                            "CEDAR-FORBID-TEMPORAL-TAINT-FRAGMENTATION: CEDAR-FORBID-004D: Multi-turn payload fragmentation detected: untrusted web input flowed into scratch file '{}' and subsequently into subprocess execution within temporal window",
                            path
                        )),
                    );
                }
            } else {
                return (
                    true,
                    Some(
                        "CEDAR-FORBID-TEMPORAL-TAINT-FRAGMENTATION: CEDAR-FORBID-004D: Multi-turn payload fragmentation detected: untrusted web input flowed into scratch file and subsequently into subprocess execution within temporal window"
                            .to_string(),
                    ),
                );
            }
        }

        (false, None)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CedarContext {
    pub policy_version: String,
    pub causal_event_id: String,
    pub has_crown_jewel_taint: bool,
    pub highest_data_classification: DataClassification,
    pub taint_level: f64,
    pub cumulative_salami_turns: u32,
    pub has_approved_capability: bool,
    pub has_cryptographic_declassification: bool,
    pub upward_authority_promotion_attempted: bool,
    pub egress_budget_exceeded: bool,
    pub semantic_cosine_similarity: f64,
    pub covert_jitter_applied_ms: u64,
    pub taint_epoch: u64,
    pub revocation_seq: u64,
    #[serde(default)]
    pub has_untrusted_web_input: bool,
    #[serde(default)]
    pub has_scratch_file_write: bool,
    #[serde(default)]
    pub subprocess_env_or_arg_tainted: bool,
    #[serde(default = "default_temporal_trace_window_seconds")]
    pub temporal_trace_window_seconds: u64,
}

impl Default for CedarContext {
    fn default() -> Self {
        Self {
            policy_version: CEDAR_BREAKOUT_POLICY_VERSION.to_string(),
            causal_event_id: String::new(),
            has_crown_jewel_taint: false,
            highest_data_classification: DataClassification::Public,
            taint_level: 0.0,
            cumulative_salami_turns: 0,
            has_approved_capability: false,
            has_cryptographic_declassification: false,
            upward_authority_promotion_attempted: false,
            egress_budget_exceeded: false,
            semantic_cosine_similarity: 0.0,
            covert_jitter_applied_ms: 0,
            taint_epoch: 0,
            revocation_seq: 0,
            has_untrusted_web_input: false,
            has_scratch_file_write: false,
            subprocess_env_or_arg_tainted: false,
            temporal_trace_window_seconds: 7200,
        }
    }
}

impl CedarContext {
    pub fn new(policy_version: impl Into<String>, causal_event_id: impl Into<String>) -> Self {
        Self {
            policy_version: policy_version.into(),
            causal_event_id: causal_event_id.into(),
            ..Default::default()
        }
    }

    pub fn with_temporal_trace(
        mut self,
        has_untrusted_web_input: bool,
        has_scratch_file_write: bool,
        subprocess_env_or_arg_tainted: bool,
    ) -> Self {
        self.has_untrusted_web_input = has_untrusted_web_input;
        self.has_scratch_file_write = has_scratch_file_write;
        self.subprocess_env_or_arg_tainted = subprocess_env_or_arg_tainted;
        self
    }

    pub fn with_temporal_window(mut self, window_seconds: u64) -> Self {
        self.temporal_trace_window_seconds = window_seconds;
        self
    }

    pub fn with_declassification(mut self, declassified: bool) -> Self {
        self.has_cryptographic_declassification = declassified;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecisionRecord {
    pub allowed: bool,
    pub policy_decision_id: String,
    pub causal_event_id: String,
    pub policy_version: String,
    pub action: CedarAction,
    pub enforcement_stage: EnforcementStage,
    pub matched_forbid_policies: Vec<String>,
    pub matched_permit_policies: Vec<String>,
    pub reason: String,
    pub taint_epoch_at_decision: u64,
    pub revocation_seq_at_decision: u64,
    pub covert_jitter_ms: u64,
    pub evaluated_at: DateTime<Utc>,
}
