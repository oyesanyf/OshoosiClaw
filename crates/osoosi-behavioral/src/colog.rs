use crate::LogEvent;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// CoLog-style log template.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct LogTemplate {
    pub source: String,
    pub event_id: u32,
    pub pattern: String,
}

/// Tier 1: Sequence anomaly detector inspired by CoLog.
pub struct CoLogFilter {
    window_size: usize,
    history: VecDeque<LogTemplate>,
    // Simple frequency-based transition matrix (placeholder for a real RNN/BERT-lite)
    // In a real implementation, this would be a loaded model.
    anomaly_threshold: f32,
}

impl CoLogFilter {
    pub fn new(window_size: usize) -> Self {
        Self {
            window_size,
            history: VecDeque::with_capacity(window_size),
            anomaly_threshold: 0.8,
        }
    }

    /// Process a new event and return an anomaly score (0.0 to 1.0).
    pub fn process(&mut self, event: &LogEvent) -> f32 {
        let template = self.extract_template(event);

        let score = if self.history.len() < 5 {
            // Not enough history for sequence analysis
            0.0
        } else {
            self.calculate_sequence_anomaly(&template)
        };

        self.history.push_back(template);
        if self.history.len() > self.window_size {
            self.history.pop_front();
        }

        score
    }

    fn extract_template(&self, event: &LogEvent) -> LogTemplate {
        // Normalize the message/data into a template (ignoring PII like DIPs, Usernames)
        let pattern = event
            .data
            .get("Message")
            .and_then(|v| v.as_str())
            .map(|s| self.mask_pii(s))
            .unwrap_or_else(|| "empty_event".to_string());

        LogTemplate {
            source: event.source.clone(),
            event_id: event.event_id,
            pattern,
        }
    }

    fn mask_pii(&self, s: &str) -> String {
        // Very basic mask for demonstration; in prod use regex for IPs/Paths/Users
        s.chars()
            .map(|c| if c.is_numeric() { 'X' } else { c })
            .collect()
    }

    fn calculate_sequence_anomaly(&self, new_template: &LogTemplate) -> f32 {
        // Placeholder for sequence probability calculation.
        // For now, we use a simple heuristic: if this template is rarely seen
        // after the previous sequence, it's anomalous.
        // anomaly_threshold (default 0.8) defines the score above which we flag as anomalous.

        let last_n = self.history.iter().rev().take(5).collect::<Vec<_>>();
        let source_count = last_n
            .iter()
            .filter(|t| t.source == new_template.source)
            .count();

        if source_count > 4 {
            // Rapid repeat from same source - often suspicious (scanning/brute)
            self.anomaly_threshold - 0.05 // 0.75 when threshold is 0.8
        } else {
            0.1
        }
    }
}
