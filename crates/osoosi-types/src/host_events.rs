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

impl HostSecurityEvent {
    /// Convert to SysmonEvent for policy engine (preserves Image, CommandLine, etc.).
    pub fn to_sysmon_event(&self) -> crate::SysmonEvent {
        use crate::SysmonEventId;
        let event_id =
            SysmonEventId::try_from(self.event_id as u16).unwrap_or(SysmonEventId::Generic);
        crate::SysmonEvent {
            event_id,
            timestamp: self.timestamp,
            computer: self.computer.clone(),
            data: self.data.clone(),
            product_version: None,
        }
    }
}
