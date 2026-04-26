//! Sysmon and File System Telemetry.
//!
//! Manages event ingestion, hashing, and real-time watching.
//! Supports Windows Event Log, Linux auditd, and macOS audit.

pub mod discovery;
pub mod file_watch;
pub mod hash;
pub mod host_events;
pub mod provisioning;
pub mod sysmon;

pub use discovery::*;
pub use file_watch::*;
pub use hash::*;
pub use host_events::*;
pub use provisioning::*;
pub use sysmon::*;
