//! 7-Ring Continuous Cedar Reference Monitor, Causal Provenance Graph, & Capability-Based Effect Gate
//!
//! Submodule decomposition of the breakout gate architecture.

#![allow(unused_imports, dead_code)]

use hmac::Hmac;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub const CEDAR_BREAKOUT_POLICY_VERSION: &str = "cedar-7ring-v2.4.0";
pub const DEFAULT_WORKSPACE_SIGNING_KEY: &[u8; 32] = b"OSHOOSICLAW_L1_MERKLE_HMAC_KEY32";
pub const DEFAULT_SUPERVISOR_DECLASSIFY_KEY: &[u8; 32] = b"OSHOOSICLAW_SUPERVISOR_ZK_KEY_32";
pub const DEFAULT_CONTROL_PLANE_KEY: &[u8; 32] = b"OSHOOSICLAW_CTRLPLANE_PQ_KEY__32";

pub mod authority;
pub mod cedar_types;
pub mod temporal;
pub mod causal_graph;
pub mod loopback;
pub mod capability_cache;
pub mod protected_store;
pub mod ring7_authorizer;
pub mod composition;

pub use authority::*;
pub use cedar_types::*;
pub use temporal::*;
pub use causal_graph::*;
pub use loopback::*;
pub use capability_cache::*;
pub use protected_store::*;
pub use ring7_authorizer::*;
pub use composition::*;
