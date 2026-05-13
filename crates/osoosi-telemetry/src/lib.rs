//! Native ETW/eBPF and File System Telemetry.
//!
//! Manages event ingestion, hashing, and real-time watching.
//! Supports Windows ETW, Linux auditd/eBPF, and macOS ESF.

pub mod discovery;
pub mod file_watch;
pub mod hash;
pub mod host_events;
pub mod injector;
pub mod native;
pub mod linux_ebpf;
pub mod provisioning;

pub use discovery::*;
pub use file_watch::*;
pub use hash::*;
pub use host_events::*;
pub use provisioning::*;
pub use injector::*;
