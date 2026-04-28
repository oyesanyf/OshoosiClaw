use chrono::Utc;
use dashmap::DashMap;
use osoosi_types::{HostSecurityEvent, SysmonEvent};
use std::sync::Arc;
use tracing::warn;

/// Einsteinian \"Relativistic Guard\": Verifies the causality of event chains.
///
/// \"The only reason for time is so that everything doesn't happen at once.\"
/// In security, if things happen 'at once' (violating causality), it is a botnet/attack.
pub struct RelativisticGuard {
    /// Mapping of Process ID -> Last Event Hash (The causality chain).
    /// DashMap: lock-free concurrent access — no blocking on high-frequency event ingestion.
    event_cones: Arc<DashMap<String, String>>,
}

impl Default for RelativisticGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl RelativisticGuard {
    pub fn new() -> Self {
        Self {
            event_cones: Arc::new(DashMap::new()),
        }
    }

    /// Check for \"Causal Violations\" (Faster-than-Light attacks).
    /// Returns 0.0 if causality is preserved, higher scores for violations.
    pub fn verify_causality(&self, event: &HostSecurityEvent) -> f32 {
        let process_id = event
            .data
            .get("ProcessId")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // Calculate hash of current event
        let current_hash = blake3::hash(event.data.to_string().as_bytes()).to_string();

        if let Some(parent) = &event.causal_parent {
            if let Some(expected_parent) = self.event_cones.get(process_id) {
                if parent != expected_parent.value() {
                    warn!("Einstein Alert: CAUSAL DECOHERENCE for process {}. Expected parent {}, got {}.", 
                        process_id, expected_parent.value(), parent);
                    return 0.95; // High anomaly - event sequence has been tampered with or skipped.
                }
            }
        }

        // Update the cone for this world-line (lock-free insert)
        self.event_cones.insert(process_id.to_string(), current_hash);
        0.0
    }

    /// Measure the \"Dilation of Truth\":
    /// Comparing Proper Time (OS Uptime) with Coordinate Time (Mesh Timestamp).
    pub fn check_temporal_dilation(&self, event: &SysmonEvent) -> f32 {
        let event_time = event.timestamp;
        let system_now = Utc::now();

        let delta = system_now.signed_duration_since(event_time).num_seconds();

        // Relativistic Threshold: If an event 'arrives' before it was 'sent' (negative delta)
        // or if it's too far in the past while claiming to be 'live'.
        if delta < -5 {
            warn!(
                "Temporal Paradox: Event from {} arrived from the future (delta: {}s). Rejecting.",
                event.computer, delta
            );
            return 1.0;
        }

        if delta > 3600 {
            // 1 hour
            // \"Sleeper\" Relativity: Malware often waits hours.
            // We flag this as 'Low-Energy' state behavior.
            return 0.4;
        }

        0.0
    }
}
