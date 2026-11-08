#![allow(clippy::collapsible_if, clippy::suspicious_open_options)]

//! OpenỌ̀ṣọ́ọ̀sì CLI Library

pub use osoosi_core::console_defense as console_hardening;

pub mod hook_cli;
pub mod service;
pub mod verify;

pub use verify::{PhaseReport, SubsystemVerifier, VerificationReport};
