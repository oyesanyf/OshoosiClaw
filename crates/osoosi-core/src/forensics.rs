use osoosi_audit::{AuditEntry, AuditTrail};
use osoosi_behavioral::SmolLMAnalyzer;
use std::path::Path;
use std::collections::HashMap;
use tracing::{error, warn};

pub struct ForensicStoryteller {
    analyzer: Option<SmolLMAnalyzer>,
    judge: Option<std::sync::Arc<osoosi_behavioral::Gemma4Analyzer>>,
}

impl Default for ForensicStoryteller {
    fn default() -> Self {
        Self::new(None)
    }
}

struct StoryGroup {
    first_seen: chrono::DateTime<chrono::Utc>,
    last_seen: chrono::DateTime<chrono::Utc>,
    count: usize,
    process_name: String,
    event_type: String,
}

impl ForensicStoryteller {
    pub fn new(judge: Option<std::sync::Arc<osoosi_behavioral::Gemma4Analyzer>>) -> Self {
        if !std::env::var("OSOOSI_ENABLE_SMOLLM")
            .map(|v| v == "1")
            .unwrap_or(false)
            && judge.is_none()
        {
            return Self { analyzer: None, judge: None };
        }
        let models_dir =
            std::env::var("OSOOSI_MODELS_DIR").unwrap_or_else(|_| "models".to_string());
        let model_dir = Path::new(&models_dir).join("smollm");

        let analyzer = match SmolLMAnalyzer::new(&model_dir) {
            Ok(a) => Some(a),
            Err(e) => {
                warn!(
                    "AI Storytelling analyzer NOT initialized: {}. Fallback to legacy templates.",
                    e
                );
                None
            }
        };

        Self { analyzer, judge }
    }

    fn extract_process_name(entry: &AuditEntry) -> String {
        let keys = ["process_name", "process_path", "Image", "SourceImage", "ParentImage", "path", "basename"];
        for key in keys {
            if let Some(val) = entry.data.get(key).and_then(|v| v.as_str()) {
                let path = Path::new(val);
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    return name.to_string();
                }
                return val.to_string();
            }
        }
        "unknown".to_string()
    }

    fn aggregate_threats<'a>(threats: impl IntoIterator<Item = &'a AuditEntry>) -> Vec<StoryGroup> {
        let mut groups: HashMap<String, StoryGroup> = HashMap::new();

        for t in threats {
            let proc = Self::extract_process_name(t);
            let key = format!("{}:{}", proc, t.event_type);
            
            let entry = groups.entry(key).or_insert(StoryGroup {
                first_seen: t.timestamp,
                last_seen: t.timestamp,
                count: 0,
                process_name: proc,
                event_type: t.event_type.clone(),
            });

            entry.count += 1;
            if t.timestamp < entry.first_seen {
                entry.first_seen = t.timestamp;
            }
            if t.timestamp > entry.last_seen {
                entry.last_seen = t.timestamp;
            }
        }

        let mut result: Vec<StoryGroup> = groups.into_values().collect();
        result.sort_by(|a, b| a.first_seen.cmp(&b.first_seen));
        result
    }

    /// Summarize an attack chain using the local, lean SmolLM3-135M model.
    pub async fn summarize_ai(&self, audit: &AuditTrail) -> String {
        let entries = audit.entries();
        if entries.is_empty() {
            return "No security events recorded in the current session.".to_string();
        }

        let threats: Vec<&AuditEntry> = entries
            .iter()
            .filter(|e| {
                let et = e.event_type.to_uppercase();
                et.contains("THREAT")
                    || et.contains("MALWARE")
                    || et.contains("ALERT")
                    || et.contains("SYSMON")
                    || et.contains("YARA")
                    || et.contains("BEHAVIORAL")
                    || et.contains("ENTANGLE")
            })
            .collect();

        if threats.is_empty() {
            return "Analysis completed: Monitoring system baseline. Audit integrity verified. No immediate threats require narrative synthesis.".to_string();
        }

        let aggregated = Self::aggregate_threats(threats);
        let mut timeline_data = String::new();
        for g in aggregated {
            if g.count > 1 {
                timeline_data.push_str(&format!(
                    "- {}-{}: {} detected in `{}` ({} occurrences)\n",
                    g.first_seen.format("%H:%M:%S"),
                    g.last_seen.format("%H:%M:%S"),
                    g.event_type,
                    g.process_name,
                    g.count
                ));
            } else {
                timeline_data.push_str(&format!(
                    "- {}: {} detected in `{}`\n",
                    g.first_seen.format("%H:%M:%S"),
                    g.event_type,
                    g.process_name
                ));
            }
        }

        if let Some(ref judge) = self.judge {
            let prompt = format!(
                "<|user|>\nYou are a professional forensic security analyst. Summarize this aggregated security timeline into a high-fidelity narrative report for a CISO. Focus on the 'story' of the attack, its progression, and the autonomous defensive actions taken. Timeline:\n{}\n<|end|>\n<|assistant|>\n",
                timeline_data
            );

            match judge.generate_text(&prompt, 400).await {
                Ok(story) => return story,
                Err(e) => {
                    warn!("Gemma4 Storyteller inference failed: {}. Trying SmolLM fallback.", e);
                }
            }
        }

        if let Some(ref analyzer) = self.analyzer {
            let prompt = format!(
                "<|user|>\nYou are a security expert. Summarize this aggregated security timeline into a concise professional report. Focus on the progression of activity. Timeline:\n{}\n<|end|>\n<|assistant|>\n",
                timeline_data
            );

            match analyzer.generate_text(&prompt, 200).await {
                Ok(story) => story,
                Err(e) => {
                    error!(
                        "SmolLM3 Storyteller inference failed: {}. Using legacy summary.",
                        e
                    );
                    self.summarize_legacy_internal(audit)
                }
            }
        } else {
            self.summarize_legacy_internal(audit)
        }
    }

    /// Fallback template-based summarizer.
    pub fn summarize_legacy(&self, audit: &AuditTrail) -> String {
        self.summarize_legacy_internal(audit)
    }

    fn summarize_legacy_internal(&self, audit: &AuditTrail) -> String {
        let entries = audit.entries();
        let mut narrative = String::from("### 🕵️ Forensic Investigation Summary\n\n");
        narrative.push_str(&format!(
            "**Audit Integrity**: {}\n\n",
            if audit.verify() {
                "VERIFIED ✅"
            } else {
                "COMPROMISED ❌"
            }
        ));

        let threats: Vec<&AuditEntry> = entries
            .iter()
            .filter(|e| {
                let et = e.event_type.to_uppercase();
                et.contains("THREAT")
                    || et.contains("MALWARE")
                    || et.contains("ALERT")
                    || et.contains("SYSMON")
                    || et.contains("YARA")
                    || et.contains("BEHAVIORAL")
                    || et.contains("ENTANGLE")
            })
            .collect();

        if threats.is_empty() {
            narrative.push_str("No significant threats detected in the audit trail.");
            return narrative;
        }

        let aggregated = Self::aggregate_threats(threats);
        for g in aggregated {
            if g.count > 1 {
                narrative.push_str(&format!(
                    "- **{}**: Identified suspicious activity in `{}` (Seen **{}** times between {} and {}). Autonomous response neutralized the threat.\n",
                    g.first_seen.format("%Y-%m-%d %H:%M:%S"),
                    g.process_name,
                    g.count,
                    g.first_seen.format("%H:%M:%S"),
                    g.last_seen.format("%H:%M:%S")
                ));
            } else {
                narrative.push_str(&format!(
                    "- **{}**: Identified suspicious activity in `{}`. Autonomous response neutralized the threat.\n",
                    g.first_seen.format("%Y-%m-%d %H:%M:%S"),
                    g.process_name
                ));
            }
        }
        narrative
    }
}
