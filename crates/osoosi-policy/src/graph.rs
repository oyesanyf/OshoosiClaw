//! Spatio-Temporal Graph Correlation (STGC).
//!
//! Tracks relationships between processes, files, and network activity over time.

use chrono::{DateTime, Utc};
use dashmap::DashMap;

#[derive(Debug, Clone)]
pub struct Relationship {
    pub source: String,
    pub target: String,
    pub interaction_type: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub frequency: u64,
}

pub struct GraphCorrelationEngine {
    /// Graph edges representing interactions
    edges: DashMap<String, Relationship>,
}

impl Default for GraphCorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl GraphCorrelationEngine {
    pub fn new() -> Self {
        Self {
            edges: DashMap::new(),
        }
    }

    /// Record an interaction (e.g., Process -> File).
    pub fn track(&self, source: &str, target: &str, itype: &str) {
        let key = format!("{}:{}:{}", source, itype, target);

        self.edges
            .entry(key.clone())
            .and_modify(|r| {
                r.last_seen = Utc::now();
                r.frequency += 1;
            })
            .or_insert(Relationship {
                source: source.to_string(),
                target: target.to_string(),
                interaction_type: itype.to_string(),
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                frequency: 1,
            });
    }

    /// Return all tracked relationships for attack graph construction.
    pub fn relationships(&self) -> Vec<Relationship> {
        self.edges.iter().map(|r| r.value().clone()).collect()
    }

    /// Identify anomalies in topological shifts (e.g. trusted process accessing sensitive file for the first time).
    pub fn score_anomaly(&self, source: &str, target: &str, itype: &str) -> f32 {
        let key = format!("{}:{}:{}", source, itype, target);

        if let Some(rel) = self.edges.get(&key) {
            // High frequency indicates established "normal" behavior
            if rel.frequency > 100 {
                return 0.01;
            }
            0.1
        } else {
            // First time seeing this interaction (Topological Shift)
            // If it's a sensitive target, score higher
            if target.to_lowercase().contains("lsass")
                || target.to_lowercase().contains("etc/shadow")
            {
                return 0.85;
            }
            0.3
        }
    }
}
