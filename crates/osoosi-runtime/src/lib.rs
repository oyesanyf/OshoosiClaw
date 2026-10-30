//! Active Response Runtime.
//!
//! Manages deception (Ghost Files), Tarpit (Throttling), and automated patching.

#![allow(clippy::manual_c_str_literals)]

pub mod canary_cage;
pub mod deception;
pub mod honeytokens;
pub mod kernel_driver;
pub mod mesh_guard;
pub mod mitigations;
pub mod sleeper;
pub mod tarpit;
pub mod tpm_ratchet;

pub use canary_cage::*;
pub use deception::*;
pub use honeytokens::*;
pub use kernel_driver::*;
pub use mesh_guard::*;
pub use mitigations::*;
pub use sleeper::*;
pub use tarpit::*;
pub use tpm_ratchet::*;
