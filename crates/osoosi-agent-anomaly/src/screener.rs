use std::sync::Arc;
use std::time::Duration;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::types::{AlertSeverity, OwaspAgenticRisk, ToolCallTelemetry};

/// Records for a single tool call within the sliding window.
#[derive(Debug, Clone)]
struct CallRecord {
    timestamp: DateTime<Utc>,
    items: u64,
    tokens: u32,
}

/// Tracks sliding window state and velocity metrics for an active agent session.
#[derive(Debug, Clone)]
pub struct SessionWindow {
    pub call_timestamps: Vec<DateTime<Utc>>,
    pub cumulative_items_requested: u64,
    pub cumulative_tokens: u64,
    pub tool_sequence: Vec<String>,
    pub consecutive_errors: u32,
    pub last_seen: DateTime<Utc>,
    pub total_calls: u64,
    call_records: Vec<CallRecord>,
}

impl Default for SessionWindow {
    fn default() -> Self {
        Self {
            call_timestamps: Vec::new(),
            cumulative_items_requested: 0,
            cumulative_tokens: 0,
            tool_sequence: Vec::new(),
            consecutive_errors: 0,
            last_seen: Utc::now(),
            total_calls: 0,
            call_records: Vec::new(),
        }
    }
}

/// Evaluation result from Layer 1 Fast Screener.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenerResult {
    pub is_anomalous: bool,
    pub risk_category: Option<OwaspAgenticRisk>,
    pub severity: Option<AlertSeverity>,
    pub reason: Option<String>,
    pub calls_in_window: usize,
    pub cumulative_items: u64,
    pub cumulative_tokens: u64,
}

/// In-memory statistical screener for sub-millisecond anomaly detection.
pub struct StatisticalScreener {
    pub sessions: DashMap<String, SessionWindow>,
    pub rate_limit_per_minute: usize,
    pub batch_threshold: u64,
    pub token_burst_threshold: u64,
    pub max_consecutive_errors: u32,
}

impl Default for StatisticalScreener {
    fn default() -> Self {
        Self::new(20, 200, 50_000, 5)
    }
}

impl StatisticalScreener {
    /// Creates a new StatisticalScreener with calibrated thresholds.
    pub fn new(
        rate_limit_per_minute: usize,
        batch_threshold: u64,
        token_burst_threshold: u64,
        max_consecutive_errors: u32,
    ) -> Self {
        Self {
            sessions: DashMap::new(),
            rate_limit_per_minute,
            batch_threshold,
            token_burst_threshold,
            max_consecutive_errors,
        }
    }

    /// Evaluates tool telemetry against the sliding 60-second window.
    pub fn inspect(&self, event: &ToolCallTelemetry) -> ScreenerResult {
        let items_in_call = Self::extract_requested_items(&event.call_parameters);
        let tokens_in_call = event.tokens_used.unwrap_or(0);

        let mut window = self
            .sessions
            .entry(event.session_id.clone())
            .or_default();

        window.last_seen = event.timestamp;
        window.total_calls = window.total_calls.saturating_add(1);

        // Record call
        window.call_records.push(CallRecord {
            timestamp: event.timestamp,
            items: items_in_call,
            tokens: tokens_in_call,
        });

        // Sliding 60-second window decay
        let window_start = event.timestamp - chrono::Duration::seconds(60);
        window.call_records.retain(|r| r.timestamp >= window_start);

        window.call_timestamps = window.call_records.iter().map(|r| r.timestamp).collect();
        window.cumulative_items_requested = window
            .call_records
            .iter()
            .fold(0u64, |acc, r| acc.saturating_add(r.items));
        window.cumulative_tokens = window
            .call_records
            .iter()
            .fold(0u64, |acc, r| acc.saturating_add(r.tokens as u64));

        // Error tracking
        if event.is_error {
            window.consecutive_errors = window.consecutive_errors.saturating_add(1);
        } else {
            window.consecutive_errors = 0;
        }

        // Tool sequence tracking (keep last 50)
        window.tool_sequence.push(event.tool_name.clone());
        if window.tool_sequence.len() > 50 {
            window.tool_sequence.remove(0);
        }

        let calls_in_window = window.call_records.len();
        let cumulative_items = window.cumulative_items_requested;
        let cumulative_tokens = window.cumulative_tokens;
        let consecutive_errs = window.consecutive_errors;

        // 1. Check Rate / Velocity Anomaly
        if calls_in_window > self.rate_limit_per_minute {
            return ScreenerResult {
                is_anomalous: true,
                risk_category: Some(OwaspAgenticRisk::ResourceExhaustionASI09),
                severity: Some(AlertSeverity::High),
                reason: Some(format!(
                    "Tool call velocity exceeded: {} calls in 60s (threshold: {})",
                    calls_in_window, self.rate_limit_per_minute
                )),
                calls_in_window,
                cumulative_items,
                cumulative_tokens,
            };
        }

        // 2. Check Volume / Batch Scraping Anomaly
        if cumulative_items > self.batch_threshold {
            return ScreenerResult {
                is_anomalous: true,
                risk_category: Some(OwaspAgenticRisk::ResourceExhaustionASI09),
                severity: Some(AlertSeverity::High),
                reason: Some(format!(
                    "Cumulative batch items requested ({} in 60s) exceeded threshold ({})",
                    cumulative_items, self.batch_threshold
                )),
                calls_in_window,
                cumulative_items,
                cumulative_tokens,
            };
        }

        // 3. Check Token Burst Anomaly
        if cumulative_tokens > self.token_burst_threshold {
            return ScreenerResult {
                is_anomalous: true,
                risk_category: Some(OwaspAgenticRisk::ResourceExhaustionASI09),
                severity: Some(AlertSeverity::Medium),
                reason: Some(format!(
                    "Cumulative tokens consumed ({} in 60s) exceeded burst threshold ({})",
                    cumulative_tokens, self.token_burst_threshold
                )),
                calls_in_window,
                cumulative_items,
                cumulative_tokens,
            };
        }

        // 4. Check Cascading Errors
        if consecutive_errs >= self.max_consecutive_errors {
            return ScreenerResult {
                is_anomalous: true,
                risk_category: Some(OwaspAgenticRisk::CascadingFailuresASI08),
                severity: Some(AlertSeverity::High),
                reason: Some(format!(
                    "Cascading failure loop detected: {} consecutive tool execution errors",
                    consecutive_errs
                )),
                calls_in_window,
                cumulative_items,
                cumulative_tokens,
            };
        }

        // 5. Check Repetitive Tool Invocation Loop (6+ identical consecutive calls)
        if window.tool_sequence.len() >= 6 {
            let last_tool = &window.tool_sequence[window.tool_sequence.len() - 1];
            let all_same = window.tool_sequence[window.tool_sequence.len() - 6..]
                .iter()
                .all(|t| t == last_tool);
            if all_same {
                return ScreenerResult {
                    is_anomalous: true,
                    risk_category: Some(OwaspAgenticRisk::CascadingFailuresASI08),
                    severity: Some(AlertSeverity::Medium),
                    reason: Some(format!(
                        "Repetitive tool invocation loop detected for tool '{}'",
                        last_tool
                    )),
                    calls_in_window,
                    cumulative_items,
                    cumulative_tokens,
                };
            }
        }

        ScreenerResult {
            is_anomalous: false,
            risk_category: None,
            severity: None,
            reason: None,
            calls_in_window,
            cumulative_items,
            cumulative_tokens,
        }
    }

    /// Extracts item count, limit, or batch size from tool arguments.
    pub fn extract_requested_items(params: &serde_json::Value) -> u64 {
        match params {
            serde_json::Value::Object(map) => {
                for (key, val) in map {
                    let k_lower = key.to_ascii_lowercase();
                    if k_lower == "limit"
                        || k_lower == "count"
                        || k_lower == "batch_size"
                        || k_lower == "batchsize"
                        || k_lower == "top"
                        || k_lower == "pagesize"
                        || k_lower == "page_size"
                        || k_lower == "max_results"
                        || k_lower == "maxresults"
                        || k_lower == "records"
                    {
                        if let Some(n) = val.as_u64() {
                            return n;
                        } else if let Some(s) = val.as_str() {
                            if let Ok(n) = s.parse::<u64>() {
                                return n;
                            }
                        }
                    }
                }
                0
            }
            _ => 0,
        }
    }

    /// Spawns a background cleaner task to prune dormant sessions older than `ttl_seconds`.
    pub fn start_cleaner(self: Arc<Self>, interval: Duration, ttl_seconds: i64) {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                let now = Utc::now();
                self.sessions.retain(|_id, window| {
                    (now - window.last_seen).num_seconds() < ttl_seconds
                });
            }
        });
    }
}
