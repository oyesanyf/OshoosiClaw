//! Threat Detection Policy Engine.
//!
//! Uses NVD CVE and CISA KEV feeds to identify active threats.
//! Correlates telemetry (Sysmon) with known vulnerabilities.

pub mod engine;
pub mod otx_connection;
pub mod feed;
pub mod semantic;
pub mod graph;
pub mod traffic_adapter;
pub mod predictive;
pub mod sigma;
pub mod voters;
pub mod verified;

pub mod admin;

pub use engine::*;
pub use otx_connection::{
    normalize_ip_for_otx, otx_consensus_weight, otx_match_destination_ip, otx_match_sysmon_event,
    otx_match_with_policy_state, OTX_CONSENSUS_CONFIDENCE,
};
pub use feed::*;
pub use semantic::*;
pub use graph::*;
pub use traffic_adapter::*;
pub use sigma::*;
pub use crate::admin::*;
