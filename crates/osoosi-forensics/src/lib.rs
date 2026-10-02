//! Embedded Velociraptor Forensic Extraction Service for OpenỌ̀ṣọ́ọ̀sì.
//!
//! Provides isolated, headless child process execution of Velociraptor over OS pipes (`stdin`/`stdout`),
//! typed VQL generation with strict parameter sanitization, asynchronous backpressure-driven JSONL streaming,
//! and out-of-band corroboration for unbacked process injection and raw MFT rootkit cloaking.

pub mod client;
pub mod correlator;
pub mod mock;
pub mod models;
pub mod stream;
pub mod vql;

pub use client::VelociraptorClient;
pub use correlator::{corroborate_mft_rootkit_hiding, corroborate_process_injection};
pub use models::{
    ForensicInvestigationReport, MftDiscrepancyArtifact, NetworkSocketArtifact,
    PersistenceArtifact, VadMemoryArtifact,
};
