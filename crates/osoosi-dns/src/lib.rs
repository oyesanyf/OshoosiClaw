//! OpenỌ̀ṣọ́ọ̀sì DNS Shield
//!
//! A local DNS proxy that intercepts, analyzes, and optionally blocks DNS queries.
//! Provides:
//!   - C2 domain sinkholing (blocklist-based)
//!   - DGA (Domain Generation Algorithm) detection via Shannon entropy
//!   - DNS tunneling detection via label length analysis
//!   - Full query logging for forensic telemetry
//!   - DNS-over-HTTPS upstream forwarding for privacy
//!
//! Cross-platform: Windows, Linux, macOS.

pub mod analysis;
pub mod blocklist;
pub mod proxy;

pub use analysis::{DnsAnalysis, DnsVerdict};
pub use blocklist::DnsBlocklist;
pub use proxy::DnsShield;
