//! Threat Detection Policy Engine.
//!
//! Uses NVD CVE and CISA KEV feeds to identify active threats.
//! Correlates telemetry (Sysmon) with known vulnerabilities.

pub mod engine;
pub mod feed;
pub mod semantic;
pub mod graph;
pub mod traffic_adapter;
pub mod predictive;
pub mod sigma;
pub mod verified;

pub mod admin;

pub use engine::*;
pub use feed::*;
pub use semantic::*;
pub use graph::*;
pub use traffic_adapter::*;
pub use sigma::*;
pub use crate::admin::*;
