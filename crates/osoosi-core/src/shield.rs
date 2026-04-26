//! Shielded Execution Layer for OpenỌ̀ṣọ́ọ̀sì.
//!
//! Provides defense-in-depth by wrapping high-risk logic in secondary
//! security layers: SSRF protection, Taint gates, and WASM logic.

use osoosi_types::{SysmonEvent, TaintLabel, TaintSink};
use std::collections::HashSet;
use tracing::warn;

pub struct ShieldLayer {
    pub ssrf_enabled: bool,
    pub strict_taint: bool,
}

impl Default for ShieldLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl ShieldLayer {
    pub fn new() -> Self {
        Self {
            ssrf_enabled: true,
            strict_taint: true,
        }
    }

    /// Check if an action is allowed based on the event's provenance (Taint).
    pub fn verify_taint_flow(&self, event: &SysmonEvent, sink: &TaintSink) -> bool {
        // Derive labels from event metadata
        let mut labels = HashSet::new();

        // Example logic: if it's a network event from an untrusted IP
        if let Some(ip) = event.data.get("DestinationIp").and_then(|v| v.as_str()) {
            if self.is_suspicious_ip(ip) {
                labels.insert(TaintLabel::SuspiciousNetwork);
            }
        }

        // If it's a file event in a temp directory
        if let Some(path) = event.data.get("TargetFilename").and_then(|v| v.as_str()) {
            if path.contains("AppData\\Local\\Temp") || path.contains("/tmp/") {
                labels.insert(TaintLabel::DownloadedFile);
            }
        }

        for label in labels {
            if sink.blocked_labels.contains(&label) {
                warn!(
                    "Shield Violation: Taint label '{}' blocked by sink '{}'",
                    label, sink.name
                );
                return false;
            }
        }
        true
    }

    /// Verify an outbound URL against SSRF protection policies.
    pub fn verify_outbound_url(&self, url: &str) -> bool {
        if !self.ssrf_enabled {
            return true;
        }

        let blocked = [
            "localhost",
            "127.0.0.1",
            "169.254.169.254",
            "metadata.google.internal",
        ];
        for b in blocked {
            if url.contains(b) {
                warn!("Shield Violation: SSRF attempt to '{}' blocked", url);
                return false;
            }
        }
        true
    }

    fn is_suspicious_ip(&self, ip: &str) -> bool {
        // Placeholder for real blocklist check
        ip.starts_with("45.") || ip.starts_with("185.")
    }
}
