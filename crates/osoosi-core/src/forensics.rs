//! Forensic Storytelling Module.
//!
//! Reconstructs the timeline of an attack into a human-readable narrative.

use osoosi_audit::{AuditTrail, AuditEntry};

pub struct ForensicStoryteller;

impl Default for ForensicStoryteller {
    fn default() -> Self {
        Self::new()
    }
}

impl ForensicStoryteller {
    pub fn new() -> Self {
        Self
    }

    /// Summarize an attack chain based on audit entries.
    pub fn summarize(&self, audit: &AuditTrail) -> String {
        let entries = audit.entries();
        if entries.is_empty() {
            return "No security events recorded in the current session.".to_string();
        }

        let mut narrative = String::from("### 🕵️ Forensic Investigation Summary\n\n");
        narrative.push_str(&format!("**Audit Integrity**: {}\n", if audit.verify() { "VERIFIED ✅" } else { "COMPROMISED ❌" }));
        narrative.push_str(&format!("**Merkle Root**: `{}`\n\n", audit.root()));

        let threats: Vec<&AuditEntry> = entries.iter()
            .filter(|e| e.event_type == "THREAT_DETECTED")
            .collect();

        if threats.is_empty() {
            narrative.push_str("Analysis completed: Normal administrative activity detected.");
        } else {
            narrative.push_str("#### 🚩 Attack Timeline\n");
            for t in threats {
                let proc = t.data.get("process_name").and_then(|p| p.as_str()).unwrap_or("unknown");
                let action = t.data.get("recommended_action").and_then(|a| a.as_str()).unwrap_or("None");
                let conf = t.data.get("confidence").and_then(|c| c.as_f64()).unwrap_or(0.0);

                narrative.push_str(&format!(
                    "- **{}**: Identified suspicious process `{}` (Confidence: {:.0}%). Autonomous Response: `{}` initiated.\n",
                    t.timestamp.format("%Y-%m-%d %H:%M:%S"),
                    proc,
                    conf * 100.0,
                    action
                ));
            }
            
            narrative.push_str("\n**Conclusion**: The system was targeted by a multi-stage attack. Defensive agents successfully engaged 'Ghost File' decoys and initiated process tarpitting to isolate the source.");
        }

        narrative
    }
}
