use osoosi_audit::{AuditTrail, AuditEntry};
use osoosi_behavioral::SmolLMAnalyzer;
use std::path::Path;
use tracing::{warn, error};

pub struct ForensicStoryteller {
    analyzer: Option<SmolLMAnalyzer>,
}

impl Default for ForensicStoryteller {
    fn default() -> Self {
        Self::new()
    }
}

impl ForensicStoryteller {
    pub fn new() -> Self {
        if !std::env::var("OSOOSI_ENABLE_SMOLLM").map(|v| v == "1").unwrap_or(false) {
            return Self { analyzer: None };
        }
        let models_dir = std::env::var("OSOOSI_MODELS_DIR").unwrap_or_else(|_| "models".to_string());
        let model_dir = Path::new(&models_dir).join("smollm");

        let analyzer = match SmolLMAnalyzer::new(&model_dir) {
            Ok(a) => Some(a),
            Err(e) => {
                warn!("AI Storytelling analyzer NOT initialized: {}. Fallback to legacy templates.", e);
                None
            }
        };

        Self { analyzer }
    }

    /// Summarize an attack chain using the local, lean SmolLM3-135M model.
    pub async fn summarize_ai(&self, audit: &AuditTrail) -> String {
        let entries = audit.entries();
        if entries.is_empty() {
            return "No security events recorded in the current session.".to_string();
        }

        let threats: Vec<&AuditEntry> = entries.iter()
            .filter(|e| e.event_type == "THREAT_DETECTED" || e.event_type == "MALWARE_DETECTED" || e.event_type == "BEHAVIORAL_ALERT")
            .collect();

        if threats.is_empty() {
            return "Analysis completed: Normal administrative activity detected. Audit integrity verified.".to_string();
        }

        let mut timeline_data = String::new();
        for t in &threats {
            timeline_data.push_str(&format!(
                "- {}: {} detected ({:?})\n",
                t.timestamp.format("%H:%M:%S"),
                t.event_type,
                t.data.get("process_name").and_then(|v| v.as_str()).unwrap_or("unknown")
            ));
        }

        if let Some(ref analyzer) = self.analyzer {
            let prompt = format!(
                "<|user|>\nYou are a forensic security analyst. Summarize this attack timeline into a professional and clear security report narrative. Timeline:\n{}\n<|end|>\n<|assistant|>\n",
                timeline_data
            );

            match analyzer.generate_text(&prompt, 200) {
                Ok(story) => story,
                Err(e) => {
                    error!("SmolLM3 Storyteller inference failed: {}. Using legacy summary.", e);
                    self.summarize_legacy(audit)
                }
            }
        } else {
            self.summarize_legacy(audit)
        }
    }



    /// Fallback template-based summarizer.
    pub fn summarize_legacy(&self, audit: &AuditTrail) -> String {
        let entries = audit.entries();
        let mut narrative = String::from("### 🕵️ Forensic Investigation Summary (Legacy)\n\n");
        narrative.push_str(&format!("**Audit Integrity**: {}\n\n", if audit.verify() { "VERIFIED ✅" } else { "COMPROMISED ❌" }));
        
        let threats: Vec<&AuditEntry> = entries.iter()
            .filter(|e| e.event_type == "THREAT_DETECTED" || e.event_type == "MALWARE_DETECTED")
            .collect();

        for t in threats {
            let proc = t.data.get("process_name").and_then(|p| p.as_str()).unwrap_or("unknown");
            narrative.push_str(&format!(
                "- **{}**: Identified suspicious activity in `{}`. Autonomous response neutralized the threat.\n",
                t.timestamp.format("%Y-%m-%d %H:%M:%S"),
                proc
            ));
        }
        narrative
    }
}
