//! Osoosi Types — Core types for the Agentic EDR.
//!
//! Core conceptual model for taint tracking, audit actions, and config.
//! Adapted for security telemetry (Native ETW/eBPF, TTP detection, mesh defense).

pub mod blocking;
pub mod config;
pub mod error;
pub mod executor;
pub mod holograph;
pub mod host_events;
pub mod reg_utils;
pub mod repair;
pub mod taint;
pub mod tarpit;
pub mod threat;
pub mod trust;
pub mod utils;

pub use blocking::*;
pub use config::*;
pub use error::*;
pub use executor::*;
pub use holograph::*;
pub use host_events::*;
pub use reg_utils::*;
pub use repair::*;
pub use taint::*;
pub use tarpit::*;
pub use threat::*;
pub use trust::*;
pub use utils::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum Priority {
    Low = 0,
    Normal = 1,
    High = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ResourceCategory {
    AI,
    IO,
    Net,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TelemetryMode {
    Silent, // Minimal events (Process creation only)
    Normal, // Standard EDR profile
    Burst,  // Full fidelity (Network, Registry, FileSystem, DLLs)
}

pub trait TelemetryControllerInterface: Send + Sync {
    fn spawn_adaptive(&self, category: ResourceCategory, priority: Priority, task: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>);
    fn report_event(&self);
    fn is_burst_mode(&self) -> bool;
    fn is_silent_mode(&self) -> bool;
    fn is_socket_exhaustion(&self) -> bool;
    fn set_socket_exhaustion(&self, value: bool);
    /// Get the current effective concurrency limit for the controller's main resource pool (usually IO).
    fn get_concurrency_limit(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = usize> + Send + '_>>;
}
