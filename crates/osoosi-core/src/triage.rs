//! LLM Triage: high-confidence threats queued for agent decision.
//! When OSOOSI_LLM_TRIAGE_ENABLED=1, threats with confidence >= 0.9 are added
//! to pending_triage. The agent can call triage_decide to override or confirm the action.

use dashmap::DashMap;
use osoosi_types::{ResponseAction, SysmonEvent, ThreatSignature};
use serde_json::Value;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub fn triage_enabled() -> bool {
    std::env::var("OSOOSI_LLM_TRIAGE_ENABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn triage_confidence_threshold() -> f32 {
    std::env::var("OSOOSI_LLM_TRIAGE_CONFIDENCE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.9)
}

#[derive(Clone)]
pub struct PendingTriageEntry {
    pub threat: ThreatSignature,
    pub event: Value,
    pub applied_action: ResponseAction,
    pub added_at: Instant,
}

pub type TriageStore = Arc<DashMap<String, PendingTriageEntry>>;

pub fn new_triage_store() -> TriageStore {
    Arc::new(DashMap::new())
}

pub fn add_pending(
    store: &TriageStore,
    threat_id: &str,
    threat: ThreatSignature,
    event: &SysmonEvent,
    applied_action: ResponseAction,
) {
    let event_val = serde_json::to_value(event).unwrap_or(Value::Null);
    store.insert(
        threat_id.to_string(),
        PendingTriageEntry {
            threat,
            event: event_val,
            applied_action,
            added_at: Instant::now(),
        },
    );
}

pub fn list_pending(store: &TriageStore, max_age_secs: u64) -> Vec<serde_json::Value> {
    let cutoff = Instant::now() - Duration::from_secs(max_age_secs);
    store
        .iter()
        .filter(|r| r.value().added_at > cutoff)
        .map(|r| {
            serde_json::json!({
                "threat_id": r.key(),
                "confidence": r.value().threat.confidence,
                "process_name": r.value().threat.process_name,
                "reason": r.value().threat.reason,
                "applied_action": format!("{:?}", r.value().applied_action),
            })
        })
        .collect()
}

pub fn remove_expired(store: &TriageStore, max_age_secs: u64) {
    let cutoff = Instant::now() - Duration::from_secs(max_age_secs);
    store.retain(|_, v| v.added_at > cutoff);
}
