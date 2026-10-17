use super::context::{RaspDecision, RaspInterceptionEvent, RaspThreatCategory};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::RwLock;

/// Aggregate telemetry metrics for the Real-Time Agentic Self-Protection engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaspTelemetryMetrics {
    pub total_inspections: usize,
    pub total_allowed: usize,
    pub total_denied: usize,
    pub total_tarpitted: usize,
    pub total_sanitized: usize,
    pub total_quarantined: usize,
    pub threat_distribution: HashMap<String, usize>,
    pub average_latency_micros: f64,
    pub operational_health_score: f64,
    pub recent_event_count: usize,
}

/// Thread-safe registry buffering RT-ASP events and tracking runtime metrics.
pub struct RaspTelemetryRegistry {
    max_history: usize,
    events: RwLock<VecDeque<RaspInterceptionEvent>>,
    total_inspections: AtomicUsize,
    total_allowed: AtomicUsize,
    total_denied: AtomicUsize,
    total_tarpitted: AtomicUsize,
    total_sanitized: AtomicUsize,
    total_quarantined: AtomicUsize,
    threat_counts: RwLock<HashMap<RaspThreatCategory, usize>>,
    total_latency_micros: AtomicUsize,
}

impl Default for RaspTelemetryRegistry {
    fn default() -> Self {
        Self::new(1000)
    }
}

impl RaspTelemetryRegistry {
    pub fn new(max_history: usize) -> Self {
        Self {
            max_history,
            events: RwLock::new(VecDeque::with_capacity(max_history)),
            total_inspections: AtomicUsize::new(0),
            total_allowed: AtomicUsize::new(0),
            total_denied: AtomicUsize::new(0),
            total_tarpitted: AtomicUsize::new(0),
            total_sanitized: AtomicUsize::new(0),
            total_quarantined: AtomicUsize::new(0),
            threat_counts: RwLock::new(HashMap::new()),
            total_latency_micros: AtomicUsize::new(0),
        }
    }

    /// Records an interceptor event into the telemetry registry.
    pub fn record_event(&self, event: RaspInterceptionEvent) {
        self.total_inspections.fetch_add(1, Ordering::Relaxed);
        self.total_latency_micros
            .fetch_add(event.latency_micros as usize, Ordering::Relaxed);

        match &event.decision {
            RaspDecision::Allow { .. } => {
                self.total_allowed.fetch_add(1, Ordering::Relaxed);
            }
            RaspDecision::Deny { .. } => {
                self.total_denied.fetch_add(1, Ordering::Relaxed);
            }
            RaspDecision::Tarpit { .. } => {
                self.total_tarpitted.fetch_add(1, Ordering::Relaxed);
            }
            RaspDecision::Sanitize { .. } => {
                self.total_sanitized.fetch_add(1, Ordering::Relaxed);
            }
            RaspDecision::Quarantine { .. } => {
                self.total_quarantined.fetch_add(1, Ordering::Relaxed);
            }
        }

        if let Some(cat) = event.threat_category {
            let mut counts = self
                .threat_counts
                .write()
                .unwrap_or_else(|e| e.into_inner());
            *counts.entry(cat).or_insert(0) += 1;
        }

        let mut events = self.events.write().unwrap_or_else(|e| e.into_inner());
        if events.len() >= self.max_history {
            events.pop_front();
        }
        events.push_back(event);
    }

    /// Retrieves the most recent N interception events.
    pub fn get_recent_events(&self, limit: usize) -> Vec<RaspInterceptionEvent> {
        let events = self.events.read().unwrap_or_else(|e| e.into_inner());
        events.iter().rev().take(limit).cloned().collect()
    }

    /// Computes aggregate telemetry metrics for dashboards and OTel exports.
    pub fn get_metrics(&self) -> RaspTelemetryMetrics {
        let inspections = self.total_inspections.load(Ordering::Relaxed);
        let allowed = self.total_allowed.load(Ordering::Relaxed);
        let denied = self.total_denied.load(Ordering::Relaxed);
        let tarpitted = self.total_tarpitted.load(Ordering::Relaxed);
        let sanitized = self.total_sanitized.load(Ordering::Relaxed);
        let quarantined = self.total_quarantined.load(Ordering::Relaxed);
        let total_micros = self.total_latency_micros.load(Ordering::Relaxed);

        let avg_latency = if inspections > 0 {
            total_micros as f64 / inspections as f64
        } else {
            0.0
        };

        // Health score: 100% minus penalty for uncontained breaches
        let health_score = if inspections > 0 {
            let blocked_ratio =
                (denied + tarpitted + sanitized + quarantined) as f64 / inspections as f64;
            (1.0 - (blocked_ratio * 0.1)).clamp(0.0, 1.0) * 100.0
        } else {
            100.0
        };

        let threat_counts = self.threat_counts.read().unwrap_or_else(|e| e.into_inner());
        let mut distribution = HashMap::new();
        for (k, v) in threat_counts.iter() {
            distribution.insert(k.to_string(), *v);
        }

        let recent_count = self.events.read().unwrap_or_else(|e| e.into_inner()).len();

        RaspTelemetryMetrics {
            total_inspections: inspections,
            total_allowed: allowed,
            total_denied: denied,
            total_tarpitted: tarpitted,
            total_sanitized: sanitized,
            total_quarantined: quarantined,
            threat_distribution: distribution,
            average_latency_micros: avg_latency,
            operational_health_score: health_score,
            recent_event_count: recent_count,
        }
    }
}
