//! Native ETW/eBPF and File System Telemetry.
//!
//! Manages event ingestion, hashing, and real-time watching.
//! Supports Windows ETW, Linux auditd/eBPF, and macOS ESF.

pub mod canary;
pub mod discovery;
pub mod file_watch;
pub mod hash;
pub mod hollowing;
pub mod host_events;
pub mod injector;
pub mod linux_ebpf;
pub mod native;
pub mod provisioning;

pub use canary::*;
pub use discovery::*;
pub use file_watch::*;
pub use hash::*;
pub use hollowing::*;
pub use host_events::*;
pub use injector::*;
pub use provisioning::*;
