//! Multi-Protocol Rate-Limit & Truncated Exponential Backoff + Jitter Correlation Engine.
//!
//! Provides RETE Alpha-Beta pattern matching, RFC 6298 (TCP), RFC 9002 (QUIC),
//! Google API exponential backoff & jitter verification with 15% clock skew tolerance,
//! 3-Voter Ensemble consensus quorum, user UI override allowlisting, and native WFP containment.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, RwLock};
use tracing::info;

// ============================================================================
// 1. NetworkProtocol (11 Supported Transport & Application Protocols)
// ============================================================================

/// Protocol taxonomy spanning 11 common transport and application protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkProtocol {
    HttpHttps,
    Tcp,
    Udp,
    Quic,
    Dns,
    Grpc,
    WebSocket,
    Ssh,
    Smtp,
    SmbRdp,
    Icmp,
}

impl NetworkProtocol {
    /// Case-insensitively parses protocol string and infers protocol from destination port when ambiguous.
    pub fn from_str_or_port(proto: &str, dst_port: Option<u16>) -> Self {
        let p_lower = proto.trim().to_ascii_lowercase();
        match p_lower.as_str() {
            "http" | "https" | "http/https" | "http1" | "http2" | "h2" => Self::HttpHttps,
            "tcp" => match dst_port {
                Some(53) => Self::Dns,
                Some(22) => Self::Ssh,
                Some(25) | Some(465) | Some(587) => Self::Smtp,
                Some(445) | Some(3389) => Self::SmbRdp,
                Some(80) | Some(443) | Some(3030) | Some(8080) | Some(8443) => Self::HttpHttps,
                Some(50051) => Self::Grpc,
                _ => Self::Tcp,
            },
            "udp" => match dst_port {
                Some(53) => Self::Dns,
                Some(443) | Some(8443) => Self::Quic,
                _ => Self::Udp,
            },
            "quic" | "http3" | "h3" => Self::Quic,
            "dns" => Self::Dns,
            "grpc" => Self::Grpc,
            "ws" | "wss" | "websocket" => Self::WebSocket,
            "ssh" => Self::Ssh,
            "smtp" => Self::Smtp,
            "smb" | "rdp" | "smb/rdp" | "smbrdp" => Self::SmbRdp,
            "icmp" | "ping" => Self::Icmp,
            _ => {
                if let Some(port) = dst_port {
                    match port {
                        53 => Self::Dns,
                        22 => Self::Ssh,
                        25 | 465 | 587 => Self::Smtp,
                        445 | 3389 => Self::SmbRdp,
                        80 | 443 | 3030 | 8080 | 8443 => Self::HttpHttps,
                        50051 => Self::Grpc,
                        _ => Self::Tcp,
                    }
                } else {
                    Self::HttpHttps
                }
            }
        }
    }

    /// Base Retransmission Timeout (RTO) floor in milliseconds:
    /// - 200ms for transport layer (Tcp, Udp, Quic, Dns, Icmp)
    /// - 500ms for application layer (HttpHttps, Grpc, WebSocket, Ssh, Smtp, SmbRdp)
    pub const fn base_rto_floor_ms(&self) -> u64 {
        match self {
            Self::Tcp | Self::Udp | Self::Quic | Self::Dns | Self::Icmp => 200,
            Self::HttpHttps
            | Self::Grpc
            | Self::WebSocket
            | Self::Ssh
            | Self::Smtp
            | Self::SmbRdp => 500,
        }
    }

    /// Evaluates whether a numeric status or protocol error code signifies throttling/rate-limiting.
    pub fn is_throttle_status(&self, status: u32) -> bool {
        match self {
            Self::HttpHttps => status == 429 || status == 503,
            Self::Tcp => status == 104 || status == 111 || status == 0 || status == 504,
            Self::Udp => status == 1 || status == 11 || status == 503,
            Self::Quic => status == 0x02 || status == 0x0b || status == 429 || status == 503,
            Self::Dns => status == 2 || status == 5 || status == 429,
            Self::Grpc => status == 8 || status == 14,
            Self::WebSocket => status == 1013 || status == 1008 || status == 429,
            Self::Ssh => status == 1 || status == 429,
            Self::Smtp => status == 421 || status == 450 || status == 451 || status == 452,
            Self::SmbRdp => status == 0xC000005E || status == 429 || status == 503,
            Self::Icmp => status == 3 || status == 4,
        }
    }

    /// Returns human-readable string identifier for UI badges and logs.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::HttpHttps => "HTTP/HTTPS",
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Quic => "QUIC",
            Self::Dns => "DNS",
            Self::Grpc => "gRPC",
            Self::WebSocket => "WebSocket",
            Self::Ssh => "SSH",
            Self::Smtp => "SMTP",
            Self::SmbRdp => "SMB/RDP",
            Self::Icmp => "ICMP",
        }
    }
}

// ============================================================================
// 2. Multi-Source Fact & Telemetry Structures
// ============================================================================

/// Raw observation sample within a network traffic stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarEntrySample {
    pub timestamp_ms: u64,
    pub status: u32,
    pub retry_after_ms: Option<u64>,
    pub url: String,
    pub method: String,
    pub protocol: NetworkProtocol,
    pub duration_ms: u64,
}

/// L7/L4 Network flow fact extracted and evaluated over a time window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarFlowFact {
    pub flow_id: String,
    pub pid: u32,
    pub protocol: NetworkProtocol,
    pub dst_host: String,
    pub dst_port: u16,
    pub samples: Vec<HarEntrySample>,
    pub backoff_compliant: bool,
    pub observed_jitter_present: bool,
    pub honors_retry_after: bool,
    pub flood_detected: bool,
}

/// Host execution context fact queried from OS sensors / osquery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsqueryProcessFact {
    pub pid: u32,
    pub process_name: String,
    pub cmdline: String,
    pub is_interactive: bool,
    pub parent_pid: u32,
    pub username: String,
}

/// Reverse-engineering & binary forensics fact derived from REA engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReaBinaryFact {
    pub pid: u32,
    pub binary_path: String,
    pub is_packed: bool,
    pub direct_syscall_count: u32,
    pub obfuscation_entropy: f64,
    pub is_authenticode_signed: bool,
    pub yara_detections: Vec<String>,
}

/// Unified evidence bundle joined by PID across asynchronous Alpha memories.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedEvidenceBundle {
    pub pid: u32,
    pub flow: Option<HarFlowFact>,
    pub process: Option<OsqueryProcessFact>,
    pub binary: Option<ReaBinaryFact>,
    pub protocol: NetworkProtocol,
    pub dst_host: String,
}

// ============================================================================
// 3. Google API & RFC 6298 / RFC 9002 Exponential Backoff Analyzer
// ============================================================================

/// Comprehensive backoff evaluation report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackoffEvaluationReport {
    pub protocol: NetworkProtocol,
    pub total_samples: usize,
    pub throttle_count: usize,
    pub backoff_compliant: bool,
    pub observed_jitter_present: bool,
    pub honors_retry_after: bool,
    pub flood_detected: bool,
    pub calculated_rto_ms: u64,
    pub summary: String,
}

// ============================================================================
// 2.5. Mathematical Backoff & RFC 6298 / RFC 9002 Formulations
// ============================================================================

/// Truncated exponential backoff with stochastic jitter formula:
/// T_wait(attempt, T_base, T_max, jitter) = min(T_base * 2^attempt + jitter, T_max)
pub fn calculate_exponential_backoff_ms(
    attempt: u32,
    base_ms: u64,
    max_ms: u64,
    jitter_ms: u64,
) -> u64 {
    let factor = 1u64.checked_shl(attempt).unwrap_or(u64::MAX);
    let exp_val = base_ms.saturating_mul(factor);
    let with_jitter = exp_val.saturating_add(jitter_ms);
    with_jitter.min(max_ms)
}

/// RFC 6298 Section 5.5: TCP Retransmission Timeout doubling formula:
/// RTO_next(RTO, RTO_max) = min(2 * RTO, RTO_max)
pub fn rfc6298_next_rto_ms(current_rto_ms: u64, max_rto_ms: u64) -> u64 {
    current_rto_ms.saturating_mul(2).min(max_rto_ms)
}

/// RFC 6298 Cumulative TCP RTO after N consecutive timeout expirations:
/// RTO_n = min(RTO_base * 2^attempts, RTO_max)
pub fn rfc6298_rto_after_attempts_ms(base_rto_ms: u64, attempts: u32, max_rto_ms: u64) -> u64 {
    let factor = 1u64.checked_shl(attempts).unwrap_or(u64::MAX);
    base_rto_ms.saturating_mul(factor).min(max_rto_ms)
}

/// RFC 9002 Section 6.2.1: QUIC Probe Timeout (PTO) exponential backoff formula:
/// PTO_next(PTO, pto_count) = PTO * 2^pto_count
pub fn rfc9002_next_pto_ms(base_pto_ms: u64, pto_count: u32, max_pto_ms: u64) -> u64 {
    let factor = 1u64.checked_shl(pto_count).unwrap_or(u64::MAX);
    base_pto_ms.saturating_mul(factor).min(max_pto_ms)
}

/// Result of mathematical exponential curve fitting.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CurveFitResult {
    pub backoff_compliant: bool,
    pub observed_jitter_present: bool,
    pub fit_slope: f64,
    pub avg_growth_ratio: f64,
}

/// Exponential backoff and jitter analyzer adhering to RFC 6298, RFC 9002, and Google API guidelines.
pub struct GoogleApiBackoffAnalyzer;

impl GoogleApiBackoffAnalyzer {
    /// Evaluates an array of `HarEntrySample`s for truncated exponential backoff compliance,
    /// stochastic jitter presence, `Retry-After` header adherence (15% clock skew tolerance), and flooding.
    pub fn evaluate_har_stream(entries: &[HarEntrySample]) -> BackoffEvaluationReport {
        if entries.is_empty() {
            return BackoffEvaluationReport {
                protocol: NetworkProtocol::HttpHttps,
                total_samples: 0,
                throttle_count: 0,
                backoff_compliant: true,
                observed_jitter_present: false,
                honors_retry_after: true,
                flood_detected: false,
                calculated_rto_ms: 0,
                summary: "Empty traffic stream".to_string(),
            };
        }

        let proto = entries[0].protocol;
        Self::evaluate_protocol_stream(proto, entries)
    }

    /// Mathematically verifies that a sequence of retry intervals follows an exponential curve
    /// T_base * 2^k within allowable stochastic jitter and 15% clock skew tolerance.
    /// Strictly rejects flat (constant) intervals, linear progression, and collapsing intervals.
    pub fn verify_exponential_curve(
        intervals: &[u64],
        base_rto_ms: u64,
        max_backoff_ms: u64,
    ) -> CurveFitResult {
        if intervals.is_empty() {
            return CurveFitResult {
                backoff_compliant: true,
                observed_jitter_present: false,
                fit_slope: 0.0,
                avg_growth_ratio: 1.0,
            };
        }

        if intervals.len() == 1 {
            // A single retry interval must be at least 85% of base RTO floor (15% skew tolerance)
            let compliant = intervals[0] >= ((base_rto_ms as f64) * 0.85) as u64;
            return CurveFitResult {
                backoff_compliant: compliant,
                observed_jitter_present: false,
                fit_slope: std::f64::consts::LN_2,
                avg_growth_ratio: 2.0,
            };
        }

        // Observed jitter check: positive variance across intervals
        let first = intervals[0];
        let observed_jitter_present = intervals.iter().any(|&d| d != first);

        // Filter intervals before saturation ceiling (85% of max_backoff_ms)
        let saturation_threshold = ((max_backoff_ms as f64) * 0.85) as u64;
        let mut pre_saturation: Vec<u64> = intervals
            .iter()
            .copied()
            .take_while(|&d| d < saturation_threshold)
            .collect();

        if pre_saturation.is_empty() {
            pre_saturation.push(intervals[0]);
        } else if pre_saturation.len() < intervals.len() {
            pre_saturation.push(intervals[pre_saturation.len()]);
        }

        // --- Invariant 1: Reject Flat / Constant Intervals ---
        // If max - min is within 15% of min and not at saturation, it's flat polling, NOT backoff!
        let min_val = *intervals.iter().min().unwrap_or(&0);
        let max_val = *intervals.iter().max().unwrap_or(&0);
        if max_val < saturation_threshold {
            let spread = max_val.saturating_sub(min_val) as f64;
            let rel_spread = spread / (min_val.max(1) as f64);
            if rel_spread < 0.15 && !observed_jitter_present {
                return CurveFitResult {
                    backoff_compliant: false,
                    observed_jitter_present: false,
                    fit_slope: 0.0,
                    avg_growth_ratio: 1.0,
                };
            }
        }

        // --- Invariant 2: Reject Collapsing Intervals ---
        for w in pre_saturation.windows(2) {
            let prev = w[0] as f64;
            let next = w[1] as f64;
            if next < prev * 0.70 {
                return CurveFitResult {
                    backoff_compliant: false,
                    observed_jitter_present,
                    fit_slope: 0.0,
                    avg_growth_ratio: next / prev.max(1.0),
                };
            }
        }

        // --- Invariant 3: Growth Ratio & Arithmetic/Linear Progression Rejection ---
        let mut growth_ratios = Vec::new();
        for w in pre_saturation.windows(2) {
            let prev = w[0].max(1) as f64;
            let next = w[1] as f64;
            growth_ratios.push(next / prev);
        }

        let avg_growth_ratio: f64 = if !growth_ratios.is_empty() {
            growth_ratios.iter().sum::<f64>() / (growth_ratios.len() as f64)
        } else {
            1.0
        };

        // For exponential doubling (2^k), ideal ratio is 2.0.
        // With 15% clock skew and stochastic jitter, avg_growth_ratio must be at least 1.40.
        // Flat (ratio ~1.0) and linear intervals (ratio ~1.1-1.25) are strictly rejected!
        if avg_growth_ratio < 1.40 {
            return CurveFitResult {
                backoff_compliant: false,
                observed_jitter_present,
                fit_slope: 0.0,
                avg_growth_ratio,
            };
        }

        // --- Invariant 4: Log-Linear Regression Slope: ln(I_k) vs k ---
        // In exponential backoff: ln(I_k) = ln(T_0) + k * ln(2)
        // Expected slope: ln(2) = 0.69315
        let n = pre_saturation.len() as f64;
        let mut sum_k = 0.0;
        let mut sum_lnk = 0.0;
        let mut sum_k_sq = 0.0;
        let mut sum_k_lnk = 0.0;

        for (k_idx, &interval) in pre_saturation.iter().enumerate() {
            let k = k_idx as f64;
            let ln_val = (interval.max(1) as f64).ln();
            sum_k += k;
            sum_lnk += ln_val;
            sum_k_sq += k * k;
            sum_k_lnk += k * ln_val;
        }

        let denom = n * sum_k_sq - sum_k * sum_k;
        let fit_slope = if denom.abs() > 1e-9 {
            (n * sum_k_lnk - sum_k * sum_lnk) / denom
        } else {
            std::f64::consts::LN_2
        };

        // Allow slope between 0.38 and 1.35 (ln(2) = 0.693 is dead center).
        let backoff_compliant = (0.38..=1.35).contains(&fit_slope);

        CurveFitResult {
            backoff_compliant,
            observed_jitter_present,
            fit_slope,
            avg_growth_ratio,
        }
    }

    /// Evaluates a multi-protocol stream for a designated `NetworkProtocol`.
    pub fn evaluate_protocol_stream(
        proto: NetworkProtocol,
        samples: &[HarEntrySample],
    ) -> BackoffEvaluationReport {
        let total_samples = samples.len();
        let base_rto = proto.base_rto_floor_ms();

        if total_samples <= 1 {
            let throttled = samples.iter().any(|s| proto.is_throttle_status(s.status));
            return BackoffEvaluationReport {
                protocol: proto,
                total_samples,
                throttle_count: if throttled { 1 } else { 0 },
                backoff_compliant: true,
                observed_jitter_present: false,
                honors_retry_after: true,
                flood_detected: false,
                calculated_rto_ms: base_rto,
                summary: "Insufficient sample sequence to evaluate backoff delta".to_string(),
            };
        }

        let mut throttled_intervals: Vec<u64> = Vec::new();
        let mut retry_after_compliances: Vec<bool> = Vec::new();
        let mut throttle_count = 0;
        let mut consecutive_fast_retries = 0;
        let mut max_consecutive_fast_retries = 0;

        for i in 1..samples.len() {
            let prev = &samples[i - 1];
            let curr = &samples[i];

            if proto.is_throttle_status(prev.status) {
                throttle_count += 1;
                let delta = curr.timestamp_ms.saturating_sub(prev.timestamp_ms);
                throttled_intervals.push(delta);

                // Flood check: interval < 50ms on throttled retry
                if delta < 50 {
                    consecutive_fast_retries += 1;
                    if consecutive_fast_retries > max_consecutive_fast_retries {
                        max_consecutive_fast_retries = consecutive_fast_retries;
                    }
                } else {
                    consecutive_fast_retries = 0;
                }

                // Retry-After adherence with 15% clock skew tolerance
                if let Some(req_wait) = prev.retry_after_ms {
                    let min_skew_wait = ((req_wait as f64) * 0.85) as u64;
                    retry_after_compliances.push(delta >= min_skew_wait);
                }
            }
        }

        let flood_detected = max_consecutive_fast_retries >= 2
            || (throttled_intervals.len() >= 3
                && throttled_intervals.iter().all(|&d| d < base_rto / 2));

        // Exponential curve verification: mathematically fit exponential curve (T_base * 2^k)
        let curve_res = Self::verify_exponential_curve(&throttled_intervals, base_rto, 60_000);
        let mut backoff_compliant = !flood_detected && curve_res.backoff_compliant;

        let observed_jitter_present = curve_res.observed_jitter_present;

        let honors_retry_after = if retry_after_compliances.is_empty() {
            true
        } else {
            retry_after_compliances.iter().all(|&c| c)
        };

        if !honors_retry_after {
            backoff_compliant = false;
        }

        // Genuine RFC 6298 / RFC 9002 / Exponential formula calculation for calculated_rto_ms
        let calculated_rto_ms = match proto {
            NetworkProtocol::Tcp => {
                let last_interval = throttled_intervals.last().copied().unwrap_or(base_rto);
                rfc6298_next_rto_ms(last_interval.max(base_rto), 60_000)
            }
            NetworkProtocol::Quic => {
                let pto_count = throttle_count as u32;
                rfc9002_next_pto_ms(base_rto, pto_count, 60_000)
            }
            _ => {
                let attempt = throttle_count as u32;
                let base = if let Some(last_req_wait) =
                    samples.iter().rev().find_map(|s| s.retry_after_ms)
                {
                    last_req_wait
                } else {
                    throttled_intervals.first().copied().unwrap_or(base_rto)
                };
                calculate_exponential_backoff_ms(attempt, base, 60_000, 0)
            }
        };

        let summary = format!(
            "[{}] evaluated {} samples ({} throttled). Compliant: {}, Retry-After: {}, Jitter: {}, Flood: {}",
            proto.as_str(),
            total_samples,
            throttle_count,
            backoff_compliant,
            honors_retry_after,
            observed_jitter_present,
            flood_detected
        );

        BackoffEvaluationReport {
            protocol: proto,
            total_samples,
            throttle_count,
            backoff_compliant,
            observed_jitter_present,
            honors_retry_after,
            flood_detected,
            calculated_rto_ms,
            summary,
        }
    }
}

// ============================================================================
// 4. RETE Pattern-Matching Engine (Bounded 1024 Memories & Beta Join)
// ============================================================================

const MAX_ALPHA_ENTRIES: usize = 1024;

/// Bounded Alpha-Beta RETE Pattern Matching Engine.
pub struct ReteEngine {
    har_alpha: RwLock<HashMap<u32, (u64, HarFlowFact)>>,
    osquery_alpha: RwLock<HashMap<u32, (u64, OsqueryProcessFact)>>,
    rea_alpha: RwLock<HashMap<u32, (u64, ReaBinaryFact)>>,
    eviction_queue_har: RwLock<VecDeque<u32>>,
    eviction_queue_osquery: RwLock<VecDeque<u32>>,
    eviction_queue_rea: RwLock<VecDeque<u32>>,
    sequence: AtomicU64,
}

impl Default for ReteEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ReteEngine {
    /// Creates a fresh RETE engine with empty, bounded Alpha memories.
    pub fn new() -> Self {
        Self {
            har_alpha: RwLock::new(HashMap::new()),
            osquery_alpha: RwLock::new(HashMap::new()),
            rea_alpha: RwLock::new(HashMap::new()),
            eviction_queue_har: RwLock::new(VecDeque::new()),
            eviction_queue_osquery: RwLock::new(VecDeque::new()),
            eviction_queue_rea: RwLock::new(VecDeque::new()),
            sequence: AtomicU64::new(1),
        }
    }

    /// Inserts or updates a network flow fact into HAR Alpha memory with FIFO bounding.
    pub fn insert_har_fact(&self, fact: HarFlowFact) {
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let pid = fact.pid;
        let mut map = self.har_alpha.write().unwrap();
        let mut q = self.eviction_queue_har.write().unwrap();

        if !map.contains_key(&pid) {
            if map.len() >= MAX_ALPHA_ENTRIES {
                if let Some(oldest_pid) = q.pop_front() {
                    map.remove(&oldest_pid);
                }
            }
            q.push_back(pid);
        }
        map.insert(pid, (seq, fact));
    }

    /// Inserts or updates an osquery host process fact with FIFO bounding.
    pub fn insert_osquery_fact(&self, fact: OsqueryProcessFact) {
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let pid = fact.pid;
        let mut map = self.osquery_alpha.write().unwrap();
        let mut q = self.eviction_queue_osquery.write().unwrap();

        if !map.contains_key(&pid) {
            if map.len() >= MAX_ALPHA_ENTRIES {
                if let Some(oldest_pid) = q.pop_front() {
                    map.remove(&oldest_pid);
                }
            }
            q.push_back(pid);
        }
        map.insert(pid, (seq, fact));
    }

    /// Inserts or updates an REA binary forensics fact with FIFO bounding.
    pub fn insert_rea_fact(&self, fact: ReaBinaryFact) {
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let pid = fact.pid;
        let mut map = self.rea_alpha.write().unwrap();
        let mut q = self.eviction_queue_rea.write().unwrap();

        if !map.contains_key(&pid) {
            if map.len() >= MAX_ALPHA_ENTRIES {
                if let Some(oldest_pid) = q.pop_front() {
                    map.remove(&oldest_pid);
                }
            }
            q.push_back(pid);
        }
        map.insert(pid, (seq, fact));
    }

    /// Evaluates the Beta Join across Alpha memories on `pid`.
    pub fn evaluate_beta_join(&self, pid: u32) -> Option<CorrelatedEvidenceBundle> {
        let flow_opt = self
            .har_alpha
            .read()
            .unwrap()
            .get(&pid)
            .map(|(_, f)| f.clone());
        let proc_opt = self
            .osquery_alpha
            .read()
            .unwrap()
            .get(&pid)
            .map(|(_, p)| p.clone());
        let rea_opt = self
            .rea_alpha
            .read()
            .unwrap()
            .get(&pid)
            .map(|(_, r)| r.clone());

        if flow_opt.is_none() && proc_opt.is_none() && rea_opt.is_none() {
            return None;
        }

        let proto = flow_opt
            .as_ref()
            .map(|f| f.protocol)
            .unwrap_or(NetworkProtocol::HttpHttps);

        let dst_host = flow_opt
            .as_ref()
            .map(|f| f.dst_host.clone())
            .unwrap_or_else(|| "unknown_destination".to_string());

        Some(CorrelatedEvidenceBundle {
            pid,
            flow: flow_opt,
            process: proc_opt,
            binary: rea_opt,
            protocol: proto,
            dst_host,
        })
    }

    /// Returns current sizes of (HAR, Osquery, REA) Alpha memories.
    pub fn alpha_memory_sizes(&self) -> (usize, usize, usize) {
        (
            self.har_alpha.read().unwrap().len(),
            self.osquery_alpha.read().unwrap().len(),
            self.rea_alpha.read().unwrap().len(),
        )
    }

    /// Clears all Alpha memories.
    pub fn clear(&self) {
        self.har_alpha.write().unwrap().clear();
        self.osquery_alpha.write().unwrap().clear();
        self.rea_alpha.write().unwrap().clear();
        self.eviction_queue_har.write().unwrap().clear();
        self.eviction_queue_osquery.write().unwrap().clear();
        self.eviction_queue_rea.write().unwrap().clear();
    }
}

// ============================================================================
// 5. 3-Voter Ensemble, Quorum, & Hard Invariants
// ============================================================================

/// Action determined by the EDR consensus engine for throttled streams.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EdrAction {
    AllowAndWhitelistWindow {
        duration_secs: u64,
        reason: String,
        final_malicious_prob: f64,
    },
    LogBenignThrottlingWarning {
        reason: String,
        final_malicious_prob: f64,
    },
    ContainProcessWfpBlock {
        pid: u32,
        dst_host: String,
        reason: String,
        final_malicious_prob: f64,
        wfp_rule_name: String,
    },
}

/// Output of an individual voter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoterVerdict {
    pub voter_name: String,
    pub weight: f64,
    pub malicious_prob: f64,
    pub confidence: f64,
    pub reason: String,
}

/// Final aggregated consensus decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoterConsensus {
    pub action: EdrAction,
    pub final_malicious_prob: f64,
    pub confidence_score: f64,
    pub voters: Vec<VoterVerdict>,
    pub override_applied: bool,
    pub explanation: String,
}

/// Evaluates physical timing properties: RFC 6298 / RFC 9002 curve compliance,
/// clock skew, and inter-attempt interval floors.
pub struct DeterministicPhysicsVoter;

impl DeterministicPhysicsVoter {
    pub const WEIGHT: f64 = 1.0;

    pub fn vote(bundle: &CorrelatedEvidenceBundle) -> VoterVerdict {
        if let Some(ref flow) = bundle.flow {
            if flow.flood_detected {
                return VoterVerdict {
                    voter_name: "DeterministicPhysicsVoter".to_string(),
                    weight: Self::WEIGHT,
                    malicious_prob: 0.95,
                    confidence: 1.0,
                    reason: "Flood detected: physical retry intervals violated RTO floor and throttle signal".to_string(),
                };
            }
            if flow.backoff_compliant && flow.honors_retry_after {
                let jitter_adj = if flow.observed_jitter_present {
                    0.03
                } else {
                    0.08
                };
                return VoterVerdict {
                    voter_name: "DeterministicPhysicsVoter".to_string(),
                    weight: Self::WEIGHT,
                    malicious_prob: jitter_adj,
                    confidence: 0.98,
                    reason:
                        "Compliant physical truncated exponential backoff and Retry-After satisfied"
                            .to_string(),
                };
            }
            if flow.backoff_compliant {
                return VoterVerdict {
                    voter_name: "DeterministicPhysicsVoter".to_string(),
                    weight: Self::WEIGHT,
                    malicious_prob: 0.15,
                    confidence: 0.90,
                    reason: "Exponential backoff compliant without explicit Retry-After"
                        .to_string(),
                };
            }
            return VoterVerdict {
                voter_name: "DeterministicPhysicsVoter".to_string(),
                weight: Self::WEIGHT,
                malicious_prob: 0.50,
                confidence: 0.75,
                reason: "Throttled requests without backoff compliance".to_string(),
            };
        }

        VoterVerdict {
            voter_name: "DeterministicPhysicsVoter".to_string(),
            weight: Self::WEIGHT,
            malicious_prob: 0.40,
            confidence: 0.50,
            reason: "No physical flow samples attached".to_string(),
        }
    }
}

/// Evaluates host execution context: interactive user status, binary packing, direct syscalls, and entropy.
pub struct OpenJevDecisionVoter;

impl OpenJevDecisionVoter {
    pub const WEIGHT: f64 = 1.0;

    pub fn vote(bundle: &CorrelatedEvidenceBundle) -> VoterVerdict {
        let mut score: f64 = 0.40;
        let mut reasons = Vec::new();

        if let Some(ref proc) = bundle.process {
            if proc.is_interactive {
                score -= 0.30;
                reasons.push("interactive_session");
            } else {
                score += 0.10;
                reasons.push("background_service");
            }
        }

        if let Some(ref rea) = bundle.binary {
            if rea.is_packed {
                score += 0.40;
                reasons.push("packed_binary");
            }
            if rea.direct_syscall_count > 0 {
                score += 0.40;
                reasons.push("direct_syscalls_present");
            }
            if rea.obfuscation_entropy >= 6.4 {
                score += 0.35;
                reasons.push("high_obfuscation_entropy");
            }
            if rea.is_authenticode_signed {
                score -= 0.30;
                reasons.push("authenticode_signed");
            }
            if !rea.yara_detections.is_empty() {
                score += 0.45;
                reasons.push("yara_detections");
            }
        }

        let prob = score.clamp(0.01, 0.99);
        VoterVerdict {
            voter_name: "OpenJevDecisionVoter".to_string(),
            weight: Self::WEIGHT,
            malicious_prob: prob,
            confidence: 0.95,
            reason: format!("Host context: [{}]", reasons.join(", ")),
        }
    }
}

/// Evaluates command line and process role semantics (e.g., standard dev tools vs C2 / brute-force tools).
pub struct GenerativeLlmVoter;

impl GenerativeLlmVoter {
    pub const WEIGHT: f64 = 0.8;

    pub fn vote(bundle: &CorrelatedEvidenceBundle) -> VoterVerdict {
        let proc_name = bundle
            .process
            .as_ref()
            .map(|p| p.process_name.to_ascii_lowercase())
            .unwrap_or_default();
        let cmdline = bundle
            .process
            .as_ref()
            .map(|p| p.cmdline.to_ascii_lowercase())
            .unwrap_or_default();

        let known_dev_tools = [
            "python",
            "python.exe",
            "python3",
            "python3.exe",
            "node",
            "node.exe",
            "npm",
            "npm.cmd",
            "curl",
            "curl.exe",
            "cargo",
            "cargo.exe",
            "git",
            "git.exe",
            "pytest",
            "powershell.exe",
            "cmd.exe",
            "rustc.exe",
            "osoosi.exe",
        ];

        let has_yara = bundle
            .binary
            .as_ref()
            .map(|r| !r.yara_detections.is_empty())
            .unwrap_or(false);

        let is_dev_tool = known_dev_tools
            .iter()
            .any(|&tool| proc_name == tool || proc_name.ends_with(&format!("\\{}", tool)));

        if is_dev_tool && !has_yara {
            return VoterVerdict {
                voter_name: "GenerativeLlmVoter".to_string(),
                weight: Self::WEIGHT,
                malicious_prob: 0.12,
                confidence: 0.85,
                reason: format!("Recognized benign developer tool semantics ({})", proc_name),
            };
        }

        let attack_keywords = [
            "stuff",
            "hydra",
            "spray",
            "brute",
            "beacon",
            "infiltrate",
            "exfil",
            "reverse_shell",
        ];
        if attack_keywords.iter().any(|&k| cmdline.contains(k)) || has_yara {
            return VoterVerdict {
                voter_name: "GenerativeLlmVoter".to_string(),
                weight: Self::WEIGHT,
                malicious_prob: 0.88,
                confidence: 0.92,
                reason: "Suspicious commandline semantics / credential-stuffing patterns detected"
                    .to_string(),
            };
        }

        VoterVerdict {
            voter_name: "GenerativeLlmVoter".to_string(),
            weight: Self::WEIGHT,
            malicious_prob: 0.45,
            confidence: 0.70,
            reason: "Neutral commandline semantics".to_string(),
        }
    }
}

/// 3-Voter Ensemble orchestrator enforcing consensus quorum and 4 hard invariants.
pub struct RateLimitVoterEnsemble;

impl RateLimitVoterEnsemble {
    /// Evaluates all 3 voters, calculates weighted consensus, and enforces the 4 Hard Invariants.
    pub fn evaluate_and_vote(&self, bundle: &CorrelatedEvidenceBundle) -> VoterConsensus {
        // --- Hard Invariant 0: User Override Gate ---
        if RateLimitAllowlist::is_released(&bundle.dst_host, bundle.protocol, Some(bundle.pid)) {
            let action = EdrAction::AllowAndWhitelistWindow {
                duration_secs: 86400,
                reason: "User manual rate-limit release override active".to_string(),
                final_malicious_prob: 0.0,
            };
            return VoterConsensus {
                action,
                final_malicious_prob: 0.0,
                confidence_score: 1.0,
                voters: Vec::new(),
                override_applied: true,
                explanation: format!(
                    "Allowlisted by user manual override for {}",
                    bundle.dst_host
                ),
            };
        }

        let v1 = DeterministicPhysicsVoter::vote(bundle);
        let v2 = OpenJevDecisionVoter::vote(bundle);
        let v3 = GenerativeLlmVoter::vote(bundle);

        let voters = vec![v1, v2, v3];

        let mut weighted_prob_sum = 0.0;
        let mut weighted_conf_sum = 0.0;
        let mut total_weight = 0.0;

        for v in &voters {
            weighted_prob_sum += v.weight * v.malicious_prob * v.confidence;
            weighted_conf_sum += v.weight * v.confidence;
            total_weight += v.weight;
        }

        let final_malicious_prob = if weighted_conf_sum > 0.0 {
            (weighted_prob_sum / weighted_conf_sum).clamp(0.0, 1.0)
        } else {
            0.50
        };

        let confidence_score = if total_weight > 0.0 {
            (weighted_conf_sum / total_weight).clamp(0.0, 1.0)
        } else {
            0.50
        };

        // Extract key context properties
        let backoff_compliant = bundle
            .flow
            .as_ref()
            .map(|f| f.backoff_compliant)
            .unwrap_or(false);
        let honors_retry_after = bundle
            .flow
            .as_ref()
            .map(|f| f.honors_retry_after)
            .unwrap_or(false);
        let entropy = bundle
            .binary
            .as_ref()
            .map(|b| b.obfuscation_entropy)
            .unwrap_or(0.0);
        let is_interactive = bundle
            .process
            .as_ref()
            .map(|p| p.is_interactive)
            .unwrap_or(false);
        let is_packed = bundle.binary.as_ref().map(|b| b.is_packed).unwrap_or(false);
        let direct_syscalls = bundle
            .binary
            .as_ref()
            .map(|b| b.direct_syscall_count)
            .unwrap_or(0);

        let is_interactive_unpacked = is_interactive && !is_packed && direct_syscalls == 0;

        // --- Hard Invariant 1: Compliant Exponential Backoff ---
        if backoff_compliant && honors_retry_after && entropy < 6.4 {
            let action = EdrAction::AllowAndWhitelistWindow {
                duration_secs: 3600,
                reason: "Compliant exponential backoff with jitter and verified binary".to_string(),
                final_malicious_prob,
            };
            return VoterConsensus {
                action,
                final_malicious_prob,
                confidence_score,
                voters,
                override_applied: false,
                explanation: "Hard Invariant 1: Compliant exponential backoff satisfied; whitelisting window granted".to_string(),
            };
        }

        // --- Hard Invariant 2: Benign Developer Script Protection ---
        if is_interactive_unpacked {
            let action = EdrAction::LogBenignThrottlingWarning {
                reason:
                    "Interactive developer process unthrottled: warning logged without containment"
                        .to_string(),
                final_malicious_prob,
            };
            return VoterConsensus {
                action,
                final_malicious_prob,
                confidence_score,
                voters,
                override_applied: false,
                explanation:
                    "Hard Invariant 2: Interactive user session protected against containment"
                        .to_string(),
            };
        }

        // --- Hard Invariant 3: Hostile Containment via Native WFP ---
        if final_malicious_prob >= 0.82 && !is_interactive_unpacked {
            let rule_name = format!(
                "OSHOOSI_RL_{}_{}",
                bundle.pid,
                bundle.dst_host.replace(':', "_")
            );

            // Actuate native WFP block
            Self::actuate_wfp_containment(&bundle.dst_host, bundle.pid, &rule_name);

            let action = EdrAction::ContainProcessWfpBlock {
                pid: bundle.pid,
                dst_host: bundle.dst_host.clone(),
                reason: format!(
                    "Hostile flood or credential stuffing detected (prob={:.2})",
                    final_malicious_prob
                ),
                final_malicious_prob,
                wfp_rule_name: rule_name,
            };
            return VoterConsensus {
                action,
                final_malicious_prob,
                confidence_score,
                voters,
                override_applied: false,
                explanation: "Hard Invariant 3: Hostile containment threshold exceeded; native WFP filter applied".to_string(),
            };
        }

        // Default tiering based on final probability
        let action = if final_malicious_prob >= 0.60 {
            EdrAction::LogBenignThrottlingWarning {
                reason: format!(
                    "Elevated throttling risk detected (prob={:.2})",
                    final_malicious_prob
                ),
                final_malicious_prob,
            }
        } else {
            EdrAction::AllowAndWhitelistWindow {
                duration_secs: 1800,
                reason: "Nominal risk within tolerable baseline".to_string(),
                final_malicious_prob,
            }
        };

        VoterConsensus {
            action,
            final_malicious_prob,
            confidence_score,
            voters,
            override_applied: false,
            explanation: "Consensus quorum evaluated without invariant trigger".to_string(),
        }
    }

    /// Triggers native Windows Filtering Platform kernel block if running on Windows.
    fn actuate_wfp_containment(dst_host: &str, pid: u32, rule_name: &str) {
        #[cfg(windows)]
        {
            let ips: Vec<std::net::IpAddr> = if let Ok(ip) = dst_host.parse::<std::net::IpAddr>() {
                vec![ip]
            } else {
                std::net::ToSocketAddrs::to_socket_addrs(&(dst_host, 80))
                    .map(|iter| iter.map(|sa| sa.ip()).collect())
                    .unwrap_or_default()
            };

            if !ips.is_empty() {
                let _ = crate::wfp::block_destination_native(rule_name, None, Some(pid), &ips);
                info!(
                    rule_name = %rule_name,
                    dst_host = %dst_host,
                    pid = pid,
                    "Native WFP rate-limit containment filter actuated"
                );
            }
        }
        #[cfg(not(windows))]
        {
            info!(
                rule_name = %rule_name,
                dst_host = %dst_host,
                pid = pid,
                "Non-Windows WFP stub simulated containment"
            );
        }
    }
}

// ============================================================================
// 6. User Override Allowlist (`database/rate_limit_released_allowlist.json`)
// ============================================================================

/// Record of an analyst/user manual release override.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitReleaseEntry {
    pub destination_host: String,
    pub protocol: String,
    pub pid: Option<u32>,
    pub operator: String,
    pub reason: String,
    pub timestamp_epoch_secs: u64,
}

static ALLOWLIST_CACHE: LazyLock<RwLock<Vec<RateLimitReleaseEntry>>> =
    LazyLock::new(|| RwLock::new(Vec::new()));
static ALLOWLIST_LOADED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Manages analyst/user manual rate-limit release overrides persisted in JSON.
pub struct RateLimitAllowlist;

impl RateLimitAllowlist {
    /// Resolves canonical path for `database/rate_limit_released_allowlist.json`.
    pub fn file_path() -> PathBuf {
        if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
            let manifest_path = PathBuf::from(manifest_dir);
            if let Some(crates_dir) = manifest_path.parent() {
                if let Some(root_dir) = crates_dir.parent() {
                    let candidate = root_dir
                        .join("database")
                        .join("rate_limit_released_allowlist.json");
                    if candidate.exists() || candidate.parent().map(|p| p.exists()).unwrap_or(false)
                    {
                        return candidate;
                    }
                }
            }
        }

        let direct = PathBuf::from("database/rate_limit_released_allowlist.json");
        if direct.exists() || direct.parent().map(|p| p.exists()).unwrap_or(false) {
            return direct;
        }

        direct
    }

    /// Loads allowlist from disk into in-memory cache.
    pub fn reload() {
        let p = Self::file_path();
        let mut lock = ALLOWLIST_CACHE.write().unwrap();
        let entries: Vec<RateLimitReleaseEntry> = if p.exists() {
            fs::read_to_string(&p)
                .ok()
                .and_then(|c| serde_json::from_str(&c).ok())
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        *lock = entries;
        ALLOWLIST_LOADED.store(true, Ordering::SeqCst);
    }

    /// Checks if a release override exists matching destination host, protocol, or PID.
    pub fn is_released(host: &str, proto: NetworkProtocol, pid: Option<u32>) -> bool {
        if !ALLOWLIST_LOADED.load(Ordering::SeqCst) {
            Self::reload();
        }

        let lock = ALLOWLIST_CACHE.read().unwrap();
        let h_lower = host.trim().to_ascii_lowercase();
        let proto_str = proto.as_str().to_ascii_lowercase();

        lock.iter().any(|entry| {
            let entry_host = entry.destination_host.trim().to_ascii_lowercase();
            let host_match = entry_host == "*" || entry_host == h_lower;

            let entry_proto = entry.protocol.trim().to_ascii_lowercase();
            let proto_match = entry_proto == "*" || entry_proto == proto_str;

            let pid_match = match (entry.pid, pid) {
                (Some(ep), Some(target_p)) => ep == target_p,
                (None, _) => true,
                _ => false,
            };

            host_match && proto_match && pid_match
        })
    }

    /// Appends a new release override entry and persists to disk.
    pub fn add_entry(entry: RateLimitReleaseEntry) -> anyhow::Result<()> {
        let p = Self::file_path();
        if let Some(parent) = p.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let mut lock = ALLOWLIST_CACHE.write().unwrap();
        if !ALLOWLIST_LOADED.load(Ordering::SeqCst) {
            if p.exists() {
                if let Ok(c) = fs::read_to_string(&p) {
                    if let Ok(entries) = serde_json::from_str::<Vec<RateLimitReleaseEntry>>(&c) {
                        *lock = entries;
                    }
                }
            }
        }

        lock.retain(|e| {
            !(e.destination_host
                .eq_ignore_ascii_case(&entry.destination_host)
                && e.protocol.eq_ignore_ascii_case(&entry.protocol)
                && e.pid == entry.pid)
        });
        lock.push(entry);

        let json_str = serde_json::to_string_pretty(&*lock)?;
        let _ = fs::write(&p, json_str);
        ALLOWLIST_LOADED.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Returns a snapshot of all active release entries.
    pub fn list_entries() -> Vec<RateLimitReleaseEntry> {
        if !ALLOWLIST_LOADED.load(Ordering::Relaxed) {
            Self::reload();
        }
        ALLOWLIST_CACHE.read().unwrap().clone()
    }

    /// Clears all entries from allowlist.
    pub fn clear() -> anyhow::Result<()> {
        let p = Self::file_path();
        {
            let mut lock = ALLOWLIST_CACHE.write().unwrap();
            lock.clear();
            let json_str = serde_json::to_string_pretty(&*lock)?;
            if p.exists() || p.parent().map(|d| d.exists()).unwrap_or(false) {
                let _ = fs::write(&p, json_str);
            }
        }
        ALLOWLIST_LOADED.store(true, Ordering::SeqCst);
        Ok(())
    }
}

// ============================================================================
// 7. Global Singletons
// ============================================================================

static GLOBAL_RETE: LazyLock<ReteEngine> = LazyLock::new(ReteEngine::new);
static GLOBAL_ENSEMBLE: LazyLock<RateLimitVoterEnsemble> = LazyLock::new(|| RateLimitVoterEnsemble);

/// Returns reference to global shared RETE pattern matching engine.
pub fn global_rete_engine() -> &'static ReteEngine {
    &GLOBAL_RETE
}

/// Returns reference to global shared RateLimitVoterEnsemble.
pub fn global_rate_limit_ensemble() -> &'static RateLimitVoterEnsemble {
    &GLOBAL_ENSEMBLE
}

// ============================================================================
// 8. Unit Tests for Acceptance Criteria Scenarios 1–6
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_scenario_1_http_google_api_backoff_allow() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let rete = ReteEngine::new();

        let samples = vec![
            HarEntrySample {
                timestamp_ms: 1000,
                status: 429,
                retry_after_ms: Some(2000),
                url: "https://api.google.com/v1/resource".into(),
                method: "GET".into(),
                protocol: NetworkProtocol::HttpHttps,
                duration_ms: 15,
            },
            HarEntrySample {
                timestamp_ms: 3150, // 2150ms delta >= 1700ms minimum skew
                status: 200,
                retry_after_ms: None,
                url: "https://api.google.com/v1/resource".into(),
                method: "GET".into(),
                protocol: NetworkProtocol::HttpHttps,
                duration_ms: 22,
            },
        ];

        let report = GoogleApiBackoffAnalyzer::evaluate_har_stream(&samples);
        assert!(report.backoff_compliant, "Must be backoff compliant");
        assert!(report.honors_retry_after, "Must honor retry-after");
        assert!(!report.flood_detected, "Must not be flood");

        let flow = HarFlowFact {
            flow_id: "flow_s1".into(),
            pid: 101,
            protocol: NetworkProtocol::HttpHttps,
            dst_host: "api.google.com".into(),
            dst_port: 443,
            samples,
            backoff_compliant: report.backoff_compliant,
            observed_jitter_present: report.observed_jitter_present,
            honors_retry_after: report.honors_retry_after,
            flood_detected: report.flood_detected,
        };

        let proc = OsqueryProcessFact {
            pid: 101,
            process_name: "curl.exe".into(),
            cmdline: "curl https://api.google.com/v1/resource".into(),
            is_interactive: false,
            parent_pid: 1,
            username: "svc_acct".into(),
        };

        let binary = ReaBinaryFact {
            pid: 101,
            binary_path: "C:\\Program Files\\Git\\usr\\bin\\curl.exe".into(),
            is_packed: false,
            direct_syscall_count: 0,
            obfuscation_entropy: 5.1,
            is_authenticode_signed: true,
            yara_detections: vec![],
        };

        // Wire facts into ReteEngine Alpha memories
        rete.insert_har_fact(flow);
        rete.insert_osquery_fact(proc);
        rete.insert_rea_fact(binary);

        assert_eq!(rete.alpha_memory_sizes(), (1, 1, 1));

        // Evaluate Beta Join on PID 101
        let bundle = rete
            .evaluate_beta_join(101)
            .expect("Beta join must succeed for populated Alpha memories");
        assert_eq!(bundle.pid, 101);
        assert!(bundle.flow.is_some());
        assert!(bundle.process.is_some());
        assert!(bundle.binary.is_some());

        let consensus = RateLimitVoterEnsemble.evaluate_and_vote(&bundle);
        assert!(
            matches!(consensus.action, EdrAction::AllowAndWhitelistWindow { .. }),
            "Expected AllowAndWhitelistWindow, got {:?}",
            consensus.action
        );
    }

    #[test]
    fn test_scenario_2_naive_dev_script_log_warning() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let rete = ReteEngine::new();

        let samples = vec![
            HarEntrySample {
                timestamp_ms: 1000,
                status: 429,
                retry_after_ms: None,
                url: "https://dev.api.internal/items".into(),
                method: "POST".into(),
                protocol: NetworkProtocol::HttpHttps,
                duration_ms: 5,
            },
            HarEntrySample {
                timestamp_ms: 1030, // 30ms rapid interval, no backoff
                status: 429,
                retry_after_ms: None,
                url: "https://dev.api.internal/items".into(),
                method: "POST".into(),
                protocol: NetworkProtocol::HttpHttps,
                duration_ms: 5,
            },
            HarEntrySample {
                timestamp_ms: 1060,
                status: 429,
                retry_after_ms: None,
                url: "https://dev.api.internal/items".into(),
                method: "POST".into(),
                protocol: NetworkProtocol::HttpHttps,
                duration_ms: 5,
            },
        ];

        let report = GoogleApiBackoffAnalyzer::evaluate_har_stream(&samples);

        let flow = HarFlowFact {
            flow_id: "flow_s2".into(),
            pid: 202,
            protocol: NetworkProtocol::HttpHttps,
            dst_host: "dev.api.internal".into(),
            dst_port: 8080,
            samples,
            backoff_compliant: report.backoff_compliant,
            observed_jitter_present: report.observed_jitter_present,
            honors_retry_after: report.honors_retry_after,
            flood_detected: report.flood_detected,
        };

        let proc = OsqueryProcessFact {
            pid: 202,
            process_name: "python.exe".into(),
            cmdline: "python test_loop.py".into(),
            is_interactive: true,
            parent_pid: 1200,
            username: "developer".into(),
        };

        let binary = ReaBinaryFact {
            pid: 202,
            binary_path: "C:\\Python311\\python.exe".into(),
            is_packed: false,
            direct_syscall_count: 0,
            obfuscation_entropy: 5.4,
            is_authenticode_signed: true,
            yara_detections: vec![],
        };

        rete.insert_har_fact(flow);
        rete.insert_osquery_fact(proc);
        rete.insert_rea_fact(binary);

        let bundle = rete
            .evaluate_beta_join(202)
            .expect("Beta join must succeed for PID 202");
        let consensus = RateLimitVoterEnsemble.evaluate_and_vote(&bundle);
        assert!(
            matches!(
                consensus.action,
                EdrAction::LogBenignThrottlingWarning { .. }
            ),
            "Expected LogBenignThrottlingWarning for interactive dev script, got {:?}",
            consensus.action
        );
    }

    #[test]
    fn test_scenario_3_malicious_c2_stuffer_contain_wfp() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let rete = ReteEngine::new();

        let samples = vec![
            HarEntrySample {
                timestamp_ms: 1000,
                status: 429,
                retry_after_ms: None,
                url: "https://auth.target.corp/login".into(),
                method: "POST".into(),
                protocol: NetworkProtocol::HttpHttps,
                duration_ms: 2,
            },
            HarEntrySample {
                timestamp_ms: 1005,
                status: 429,
                retry_after_ms: None,
                url: "https://auth.target.corp/login".into(),
                method: "POST".into(),
                protocol: NetworkProtocol::HttpHttps,
                duration_ms: 2,
            },
            HarEntrySample {
                timestamp_ms: 1010,
                status: 429,
                retry_after_ms: None,
                url: "https://auth.target.corp/login".into(),
                method: "POST".into(),
                protocol: NetworkProtocol::HttpHttps,
                duration_ms: 2,
            },
        ];

        let report = GoogleApiBackoffAnalyzer::evaluate_har_stream(&samples);
        assert!(report.flood_detected, "Must detect flood on 5ms intervals");

        let flow = HarFlowFact {
            flow_id: "flow_s3".into(),
            pid: 666,
            protocol: NetworkProtocol::HttpHttps,
            dst_host: "auth.target.corp".into(),
            dst_port: 443,
            samples,
            backoff_compliant: report.backoff_compliant,
            observed_jitter_present: report.observed_jitter_present,
            honors_retry_after: report.honors_retry_after,
            flood_detected: report.flood_detected,
        };

        let proc = OsqueryProcessFact {
            pid: 666,
            process_name: "payload.exe".into(),
            cmdline: "payload.exe --stuff-credentials --threads 50".into(),
            is_interactive: false,
            parent_pid: 1,
            username: "SYSTEM".into(),
        };

        let binary = ReaBinaryFact {
            pid: 666,
            binary_path: "C:\\Windows\\Temp\\payload.exe".into(),
            is_packed: true,
            direct_syscall_count: 8,
            obfuscation_entropy: 7.2,
            is_authenticode_signed: false,
            yara_detections: vec!["CredentialStuffer_Generic".into()],
        };

        rete.insert_har_fact(flow);
        rete.insert_osquery_fact(proc);
        rete.insert_rea_fact(binary);

        let bundle = rete
            .evaluate_beta_join(666)
            .expect("Beta join must succeed for PID 666");
        let consensus = RateLimitVoterEnsemble.evaluate_and_vote(&bundle);
        assert!(
            consensus.final_malicious_prob >= 0.82,
            "Expected prob >= 0.82, got {}",
            consensus.final_malicious_prob
        );
        assert!(
            matches!(consensus.action, EdrAction::ContainProcessWfpBlock { .. }),
            "Expected ContainProcessWfpBlock, got {:?}",
            consensus.action
        );
    }

    #[test]
    fn test_scenario_4_tcp_rfc6298_backoff_vs_flood() {
        let rete = ReteEngine::new();

        // Part A: Compliant RFC 6298 TCP exponential retries
        let compliant_tcp_samples = vec![
            HarEntrySample {
                timestamp_ms: 1000,
                status: 111, // ECONNREFUSED
                retry_after_ms: None,
                url: "tcp://192.168.1.50:445".into(),
                method: "CONNECT".into(),
                protocol: NetworkProtocol::Tcp,
                duration_ms: 5,
            },
            HarEntrySample {
                timestamp_ms: 2050, // ~1s wait + jitter
                status: 111,
                retry_after_ms: None,
                url: "tcp://192.168.1.50:445".into(),
                method: "CONNECT".into(),
                protocol: NetworkProtocol::Tcp,
                duration_ms: 5,
            },
            HarEntrySample {
                timestamp_ms: 4120, // ~2s wait + jitter
                status: 111,
                retry_after_ms: None,
                url: "tcp://192.168.1.50:445".into(),
                method: "CONNECT".into(),
                protocol: NetworkProtocol::Tcp,
                duration_ms: 5,
            },
            HarEntrySample {
                timestamp_ms: 8200, // ~4s wait + jitter
                status: 200,
                retry_after_ms: None,
                url: "tcp://192.168.1.50:445".into(),
                method: "CONNECT".into(),
                protocol: NetworkProtocol::Tcp,
                duration_ms: 10,
            },
        ];

        let rep_a = GoogleApiBackoffAnalyzer::evaluate_protocol_stream(
            NetworkProtocol::Tcp,
            &compliant_tcp_samples,
        );
        assert!(
            rep_a.backoff_compliant,
            "TCP RFC 6298 exponential curve must be compliant"
        );
        assert!(!rep_a.flood_detected, "Must not be flood");

        let flow_a = HarFlowFact {
            flow_id: "tcp_flow_a".into(),
            pid: 401,
            protocol: NetworkProtocol::Tcp,
            dst_host: "192.168.1.50".into(),
            dst_port: 445,
            samples: compliant_tcp_samples,
            backoff_compliant: rep_a.backoff_compliant,
            observed_jitter_present: rep_a.observed_jitter_present,
            honors_retry_after: rep_a.honors_retry_after,
            flood_detected: rep_a.flood_detected,
        };
        rete.insert_har_fact(flow_a);
        let bundle_a = rete.evaluate_beta_join(401).expect("Beta join on PID 401");
        assert_eq!(bundle_a.protocol, NetworkProtocol::Tcp);

        // Part B: Aggressive TCP SYN flood at 1ms intervals
        let flood_tcp_samples = vec![
            HarEntrySample {
                timestamp_ms: 1000,
                status: 111,
                retry_after_ms: None,
                url: "tcp://192.168.1.50:445".into(),
                method: "CONNECT".into(),
                protocol: NetworkProtocol::Tcp,
                duration_ms: 1,
            },
            HarEntrySample {
                timestamp_ms: 1001,
                status: 111,
                retry_after_ms: None,
                url: "tcp://192.168.1.50:445".into(),
                method: "CONNECT".into(),
                protocol: NetworkProtocol::Tcp,
                duration_ms: 1,
            },
            HarEntrySample {
                timestamp_ms: 1002,
                status: 111,
                retry_after_ms: None,
                url: "tcp://192.168.1.50:445".into(),
                method: "CONNECT".into(),
                protocol: NetworkProtocol::Tcp,
                duration_ms: 1,
            },
        ];

        let rep_b = GoogleApiBackoffAnalyzer::evaluate_protocol_stream(
            NetworkProtocol::Tcp,
            &flood_tcp_samples,
        );
        assert!(rep_b.flood_detected, "TCP SYN flood must be detected");
    }

    #[test]
    fn test_scenario_5_udp_quic_dns_backoff_vs_flood() {
        let rete = ReteEngine::new();

        // Part A: DNS SERVFAIL resolver backoff
        let dns_backoff_samples = vec![
            HarEntrySample {
                timestamp_ms: 1000,
                status: 2, // SERVFAIL
                retry_after_ms: None,
                url: "dns://8.8.8.8:53/example.com".into(),
                method: "QUERY".into(),
                protocol: NetworkProtocol::Dns,
                duration_ms: 20,
            },
            HarEntrySample {
                timestamp_ms: 1500, // 500ms wait
                status: 2,
                retry_after_ms: None,
                url: "dns://8.8.8.8:53/example.com".into(),
                method: "QUERY".into(),
                protocol: NetworkProtocol::Dns,
                duration_ms: 20,
            },
            HarEntrySample {
                timestamp_ms: 2600, // 1100ms wait
                status: 0,          // NOERROR
                retry_after_ms: None,
                url: "dns://8.8.8.8:53/example.com".into(),
                method: "QUERY".into(),
                protocol: NetworkProtocol::Dns,
                duration_ms: 15,
            },
        ];

        let rep_dns = GoogleApiBackoffAnalyzer::evaluate_protocol_stream(
            NetworkProtocol::Dns,
            &dns_backoff_samples,
        );
        assert!(rep_dns.backoff_compliant, "DNS backoff must be compliant");

        let flow_dns = HarFlowFact {
            flow_id: "dns_flow".into(),
            pid: 501,
            protocol: NetworkProtocol::Dns,
            dst_host: "8.8.8.8".into(),
            dst_port: 53,
            samples: dns_backoff_samples,
            backoff_compliant: rep_dns.backoff_compliant,
            observed_jitter_present: rep_dns.observed_jitter_present,
            honors_retry_after: rep_dns.honors_retry_after,
            flood_detected: rep_dns.flood_detected,
        };
        rete.insert_har_fact(flow_dns);
        let bundle_dns = rete.evaluate_beta_join(501).expect("Beta join on PID 501");
        assert_eq!(bundle_dns.protocol, NetworkProtocol::Dns);

        // Part B: UDP tunneling packet flood
        let udp_flood_samples = vec![
            HarEntrySample {
                timestamp_ms: 5000,
                status: 1, // ICMP Unreachable
                retry_after_ms: None,
                url: "udp://10.0.0.1:51820".into(),
                method: "DATAGRAM".into(),
                protocol: NetworkProtocol::Udp,
                duration_ms: 1,
            },
            HarEntrySample {
                timestamp_ms: 5005,
                status: 1,
                retry_after_ms: None,
                url: "udp://10.0.0.1:51820".into(),
                method: "DATAGRAM".into(),
                protocol: NetworkProtocol::Udp,
                duration_ms: 1,
            },
            HarEntrySample {
                timestamp_ms: 5010,
                status: 1,
                retry_after_ms: None,
                url: "udp://10.0.0.1:51820".into(),
                method: "DATAGRAM".into(),
                protocol: NetworkProtocol::Udp,
                duration_ms: 1,
            },
        ];

        let rep_udp = GoogleApiBackoffAnalyzer::evaluate_protocol_stream(
            NetworkProtocol::Udp,
            &udp_flood_samples,
        );
        assert!(rep_udp.flood_detected, "UDP packet flood must be detected");
    }

    #[test]
    fn test_scenario_6_one_click_ui_rate_limit_rejection() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let rete = ReteEngine::new();

        let target_host = "test-override.cloud.corp";
        let target_pid = 777;

        let entry = RateLimitReleaseEntry {
            destination_host: target_host.to_string(),
            protocol: "*".to_string(),
            pid: Some(target_pid),
            operator: "security_analyst".to_string(),
            reason: "One-click UI rate limit rejection".to_string(),
            timestamp_epoch_secs: 1729864800,
        };
        RateLimitAllowlist::add_entry(entry).unwrap();

        assert!(RateLimitAllowlist::is_released(
            target_host,
            NetworkProtocol::HttpHttps,
            Some(target_pid)
        ));

        let flow = HarFlowFact {
            flow_id: "flow_s6".into(),
            pid: target_pid,
            protocol: NetworkProtocol::HttpHttps,
            dst_host: target_host.into(),
            dst_port: 443,
            samples: vec![],
            backoff_compliant: false,
            observed_jitter_present: false,
            honors_retry_after: false,
            flood_detected: true,
        };

        rete.insert_har_fact(flow);
        let bundle = rete
            .evaluate_beta_join(target_pid)
            .expect("Beta join on target_pid");

        let consensus = RateLimitVoterEnsemble.evaluate_and_vote(&bundle);
        assert!(consensus.override_applied, "Override flag must be true");
        assert!(
            matches!(consensus.action, EdrAction::AllowAndWhitelistWindow { .. }),
            "Expected AllowAndWhitelistWindow under override, got {:?}",
            consensus.action
        );

        let _ = RateLimitAllowlist::clear();
    }

    #[test]
    fn test_mathematical_formulas_precision() {
        // T_wait = min(T_base * 2^attempt + jitter, T_max)
        assert_eq!(calculate_exponential_backoff_ms(0, 500, 60_000, 50), 550);
        assert_eq!(calculate_exponential_backoff_ms(1, 500, 60_000, 50), 1050);
        assert_eq!(calculate_exponential_backoff_ms(2, 500, 60_000, 50), 2050);
        assert_eq!(calculate_exponential_backoff_ms(3, 500, 60_000, 50), 4050);
        assert_eq!(calculate_exponential_backoff_ms(10, 500, 60_000, 0), 60_000); // capped at max

        // RFC 6298: RTO_next = min(2 * RTO, RTO_max)
        assert_eq!(rfc6298_next_rto_ms(1000, 60_000), 2000);
        assert_eq!(rfc6298_next_rto_ms(2000, 60_000), 4000);
        assert_eq!(rfc6298_next_rto_ms(35_000, 60_000), 60_000);
        assert_eq!(rfc6298_rto_after_attempts_ms(1000, 3, 60_000), 8000);

        // RFC 9002: PTO_next = PTO * 2^pto_count
        assert_eq!(rfc9002_next_pto_ms(200, 0, 60_000), 200);
        assert_eq!(rfc9002_next_pto_ms(200, 1, 60_000), 400);
        assert_eq!(rfc9002_next_pto_ms(200, 2, 60_000), 800);
        assert_eq!(rfc9002_next_pto_ms(200, 3, 60_000), 1600);
    }

    #[test]
    fn test_flat_intervals_rejected_as_non_compliant() {
        // Flat constant polling sequence: [500ms, 500ms, 500ms, 500ms]
        let samples = vec![
            HarEntrySample {
                timestamp_ms: 1000,
                status: 429,
                retry_after_ms: None,
                url: "https://api.flat.com/data".into(),
                method: "GET".into(),
                protocol: NetworkProtocol::HttpHttps,
                duration_ms: 10,
            },
            HarEntrySample {
                timestamp_ms: 1500, // 500ms
                status: 429,
                retry_after_ms: None,
                url: "https://api.flat.com/data".into(),
                method: "GET".into(),
                protocol: NetworkProtocol::HttpHttps,
                duration_ms: 10,
            },
            HarEntrySample {
                timestamp_ms: 2000, // 500ms
                status: 429,
                retry_after_ms: None,
                url: "https://api.flat.com/data".into(),
                method: "GET".into(),
                protocol: NetworkProtocol::HttpHttps,
                duration_ms: 10,
            },
            HarEntrySample {
                timestamp_ms: 2500, // 500ms
                status: 200,
                retry_after_ms: None,
                url: "https://api.flat.com/data".into(),
                method: "GET".into(),
                protocol: NetworkProtocol::HttpHttps,
                duration_ms: 10,
            },
        ];

        let report = GoogleApiBackoffAnalyzer::evaluate_har_stream(&samples);
        assert!(
            !report.backoff_compliant,
            "Flat constant intervals MUST NOT be certified as exponential backoff!"
        );
    }

    #[test]
    fn test_linear_intervals_rejected_as_non_compliant() {
        // Linear arithmetic retry progression: [500ms, 600ms, 700ms, 800ms]
        let samples = vec![
            HarEntrySample {
                timestamp_ms: 1000,
                status: 429,
                retry_after_ms: None,
                url: "https://api.linear.com/data".into(),
                method: "GET".into(),
                protocol: NetworkProtocol::HttpHttps,
                duration_ms: 10,
            },
            HarEntrySample {
                timestamp_ms: 1500, // 500ms
                status: 429,
                retry_after_ms: None,
                url: "https://api.linear.com/data".into(),
                method: "GET".into(),
                protocol: NetworkProtocol::HttpHttps,
                duration_ms: 10,
            },
            HarEntrySample {
                timestamp_ms: 2100, // 600ms
                status: 429,
                retry_after_ms: None,
                url: "https://api.linear.com/data".into(),
                method: "GET".into(),
                protocol: NetworkProtocol::HttpHttps,
                duration_ms: 10,
            },
            HarEntrySample {
                timestamp_ms: 2800, // 700ms
                status: 429,
                retry_after_ms: None,
                url: "https://api.linear.com/data".into(),
                method: "GET".into(),
                protocol: NetworkProtocol::HttpHttps,
                duration_ms: 10,
            },
            HarEntrySample {
                timestamp_ms: 3600, // 800ms
                status: 200,
                retry_after_ms: None,
                url: "https://api.linear.com/data".into(),
                method: "GET".into(),
                protocol: NetworkProtocol::HttpHttps,
                duration_ms: 10,
            },
        ];

        let report = GoogleApiBackoffAnalyzer::evaluate_har_stream(&samples);
        assert!(
            !report.backoff_compliant,
            "Linear arithmetic retry intervals MUST NOT be certified as exponential backoff!"
        );
    }

    #[test]
    fn test_rete_pattern_matching_alpha_beta_join() {
        let rete = ReteEngine::new();
        assert_eq!(rete.alpha_memory_sizes(), (0, 0, 0));

        let flow = HarFlowFact {
            flow_id: "test_flow".into(),
            pid: 999,
            protocol: NetworkProtocol::Tcp,
            dst_host: "10.0.0.1".into(),
            dst_port: 80,
            samples: vec![],
            backoff_compliant: true,
            observed_jitter_present: false,
            honors_retry_after: true,
            flood_detected: false,
        };
        let proc = OsqueryProcessFact {
            pid: 999,
            process_name: "test.exe".into(),
            cmdline: "test.exe".into(),
            is_interactive: true,
            parent_pid: 1,
            username: "tester".into(),
        };
        let binary = ReaBinaryFact {
            pid: 999,
            binary_path: "C:\\test.exe".into(),
            is_packed: false,
            direct_syscall_count: 0,
            obfuscation_entropy: 4.5,
            is_authenticode_signed: true,
            yara_detections: vec![],
        };

        rete.insert_har_fact(flow);
        assert_eq!(rete.alpha_memory_sizes(), (1, 0, 0));

        rete.insert_osquery_fact(proc);
        assert_eq!(rete.alpha_memory_sizes(), (1, 1, 0));

        rete.insert_rea_fact(binary);
        assert_eq!(rete.alpha_memory_sizes(), (1, 1, 1));

        let joined = rete
            .evaluate_beta_join(999)
            .expect("Beta join should return joined bundle");
        assert_eq!(joined.pid, 999);
        assert_eq!(joined.dst_host, "10.0.0.1");
        assert_eq!(joined.protocol, NetworkProtocol::Tcp);
        assert!(joined.flow.is_some());
        assert!(joined.process.is_some());
        assert!(joined.binary.is_some());

        rete.clear();
        assert_eq!(rete.alpha_memory_sizes(), (0, 0, 0));
        assert!(rete.evaluate_beta_join(999).is_none());
    }
}
