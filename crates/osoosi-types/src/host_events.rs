//! Cross-platform host security event types.
//!
//! Normalized events from Windows Event Log, Linux auditd, macOS audit, etc.
//! All sources map to a common format for the policy engine.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// OS-specific event source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostEventSource {
    WindowsEventLog,
    LinuxAudit,
    LinuxAuthLog,
    MacAudit,
    MacUnifiedLog,
}

/// Normalized host security event (all OS).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostSecurityEvent {
    pub source: HostEventSource,
    pub event_id: u32,
    pub timestamp: DateTime<Utc>,
    pub computer: String,
    pub data: serde_json::Value,
    /// CEREBUS-Einstein: The hash of the previous event in this process's light-cone.
    pub causal_parent: Option<String>,
}
