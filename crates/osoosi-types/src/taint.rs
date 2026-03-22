//! EDR-specific taint tracking for telemetry.
//!
//! Implements a lattice-based taint model for telemetry.
//! Adapted for security: files from suspicious IPs, process injection targets,
//! etc. When a tainted file tries to inject into another process, the agent
//! can block based on provenance.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;

/// Taint labels for EDR telemetry provenance.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaintLabel {
    /// Data from a suspicious or blocklisted IP (e.g. Sysmon Event 3).
    SuspiciousNetwork,
    /// File downloaded from external source.
    DownloadedFile,
    /// Process that performed code injection (Sysmon Event 8).
    ProcessInjectionSource,
    /// Target of process injection.
    ProcessInjectionTarget,
    /// Raw disk access (Sysmon Event 9).
    RawAccessRead,
    /// Registry modification in sensitive key.
    SensitiveRegistry,
    /// File created by untrusted/sandboxed script.
    UntrustedScript,
    /// Peer with low reputation score (below threshold).
    LowReputation,
    /// Peer from suspicious or blocklisted network.
    SuspiciousPeer,
}

impl fmt::Display for TaintLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TaintLabel::SuspiciousNetwork => write!(f, "SuspiciousNetwork"),
            TaintLabel::DownloadedFile => write!(f, "DownloadedFile"),
            TaintLabel::ProcessInjectionSource => write!(f, "ProcessInjectionSource"),
            TaintLabel::ProcessInjectionTarget => write!(f, "ProcessInjectionTarget"),
            TaintLabel::RawAccessRead => write!(f, "RawAccessRead"),
            TaintLabel::SensitiveRegistry => write!(f, "SensitiveRegistry"),
            TaintLabel::UntrustedScript => write!(f, "UntrustedScript"),
            TaintLabel::LowReputation => write!(f, "LowReputation"),
            TaintLabel::SuspiciousPeer => write!(f, "SuspiciousPeer"),
        }
    }
}

/// A value annotated with taint labels (e.g. file path, process ID).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintedValue {
    pub value: String,
    pub labels: HashSet<TaintLabel>,
    pub source: String,
}

impl TaintedValue {
    pub fn new(value: impl Into<String>, labels: HashSet<TaintLabel>, source: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            labels,
            source: source.into(),
        }
    }

    pub fn clean(value: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            labels: HashSet::new(),
            source: source.into(),
        }
    }

    pub fn merge_taint(&mut self, other: &TaintedValue) {
        for label in &other.labels {
            self.labels.insert(label.clone());
        }
    }

    pub fn check_sink(&self, sink: &TaintSink) -> Result<(), TaintViolation> {
        for label in &self.labels {
            if sink.blocked_labels.contains(label) {
                return Err(TaintViolation {
                    label: label.clone(),
                    sink_name: sink.name.clone(),
                    source: self.source.clone(),
                });
            }
        }
        Ok(())
    }

    pub fn declassify(&mut self, label: &TaintLabel) {
        self.labels.remove(label);
    }

    pub fn is_tainted(&self) -> bool {
        !self.labels.is_empty()
    }
}

/// Build a TaintedValue for a peer during grant access. Derives labels from reputation and metadata.
pub fn tainted_value_for_peer(
    peer_id: impl Into<String>,
    reputation_score: f32,
    multiaddr: Option<&str>,
) -> TaintedValue {
    let peer_id = peer_id.into();
    let mut labels = HashSet::new();
    if reputation_score < 0.3 {
        labels.insert(TaintLabel::LowReputation);
    }
    // Future: parse multiaddr for suspicious IP ranges and add SuspiciousPeer
    let _ = multiaddr;
    let source = format!("pending_join:{}", peer_id);
    if labels.is_empty() {
        TaintedValue::clean(peer_id.clone(), source)
    } else {
        TaintedValue::new(peer_id, labels, source)
    }
}

/// Sink that restricts which taint labels may flow into it.
#[derive(Debug, Clone)]
pub struct TaintSink {
    pub name: String,
    pub blocked_labels: HashSet<TaintLabel>,
}

impl TaintSink {
    /// Block tainted files from injecting into processes.
    pub fn process_injection() -> Self {
        let mut blocked = HashSet::new();
        blocked.insert(TaintLabel::SuspiciousNetwork);
        blocked.insert(TaintLabel::DownloadedFile);
        blocked.insert(TaintLabel::ProcessInjectionSource);
        blocked.insert(TaintLabel::UntrustedScript);
        Self {
            name: "process_injection".to_string(),
            blocked_labels: blocked,
        }
    }

    /// Block tainted data from reaching sensitive registry.
    pub fn registry_write() -> Self {
        let mut blocked = HashSet::new();
        blocked.insert(TaintLabel::SuspiciousNetwork);
        blocked.insert(TaintLabel::UntrustedScript);
        Self {
            name: "registry_write".to_string(),
            blocked_labels: blocked,
        }
    }

    /// Block tainted scripts from shell execution.
    pub fn shell_exec() -> Self {
        let mut blocked = HashSet::new();
        blocked.insert(TaintLabel::SuspiciousNetwork);
        blocked.insert(TaintLabel::DownloadedFile);
        blocked.insert(TaintLabel::UntrustedScript);
        Self {
            name: "shell_exec".to_string(),
            blocked_labels: blocked,
        }
    }

    /// Block tainted peers from joining the mesh. Applied during grant access.
    pub fn mesh_join() -> Self {
        let mut blocked = HashSet::new();
        blocked.insert(TaintLabel::SuspiciousNetwork);
        blocked.insert(TaintLabel::LowReputation);
        blocked.insert(TaintLabel::SuspiciousPeer);
        Self {
            name: "mesh_join".to_string(),
            blocked_labels: blocked,
        }
    }

    /// Deception sink: Allows trap spawning even for tainted events.
    pub fn deception() -> Self {
        let mut blocked = HashSet::new();
        // We only block extremely high-risk labels for deception
        blocked.insert(TaintLabel::SuspiciousNetwork);
        Self {
            name: "deception".to_string(),
            blocked_labels: blocked,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TaintViolation {
    pub label: TaintLabel,
    pub sink_name: String,
    pub source: String,
}

impl fmt::Display for TaintViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "taint violation: label '{}' from source '{}' is not allowed to reach sink '{}'",
            self.label, self.source, self.sink_name
        )
    }
}

impl std::error::Error for TaintViolation {}
