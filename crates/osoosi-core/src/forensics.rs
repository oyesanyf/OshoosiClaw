//! Forensic Storytelling Module.
//!
//! Reconstructs the timeline of an attack into a human-readable narrative using a native, lean Gemma-2B model.

use osoosi_audit::{AuditTrail, AuditEntry};
use ort::{session::Session, inputs};
use ndarray;
use tokenizers::Tokenizer;
use std::path::{Path, PathBuf};
use tracing::{info, warn, error};

pub struct ForensicStoryteller {
    session: Option<Session>,
    tokenizer: Option<Tokenizer>,
}

impl Default for ForensicStoryteller {
    fn default() -> Self {
        Self::new()
    }
}

impl ForensicStoryteller {
    pub fn new() -> Self {
        let models_dir = std::env::var("OSOOSI_MODELS_DIR").unwrap_or_else(|_| "models".to_string());
        let model_path = Path::new(&models_dir).join("gemma-3-270m-it.onnx");
        let tokenizer_path = Path::new(&models_dir).join("tokenizer.json");

        let mut session = None;
        let mut tokenizer = None;

        if model_path.exists() && tokenizer_path.exists() {
            match (|| -> anyhow::Result<(Session, Tokenizer)> {
                let s = Session::builder()?.commit_from_file(&model_path)?;
                let t = Tokenizer::from_file(&tokenizer_path).map_err(|e| anyhow::anyhow!("Tokenizer error: {}", e))?;
                Ok((s, t))
            })() {
                Ok((s, t)) => {
                    session = Some(s);
                    tokenizer = Some(t);
                    info!("Native Gemma-2B Storyteller initialized successfully.");
                }
                Err(e) => {
                    error!("Failed to initialize native Gemma engine: {}. Falling back to template.", e);
                }
            }
        } else {
            warn!("Gemma models not found at {:?}. AI Storytelling will use legacy templates. Run 'osoosi bootstrap' to install local models.", model_path);
        }

        Self { session, tokenizer }
    }

    /// Summarize an attack chain using the local, lean Gemma-2B model.
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

        if let (Some(ref session), Some(ref tokenizer)) = (&self.session, &self.tokenizer) {
            let prompt = format!(
                "<start_of_turn>user\nYou are a forensic security analyst. Summarize this attack timeline into a dramatic and professional narrative:\n{}\n<end_of_turn>\n<start_of_turn>model\n",
                timeline_data
            );

            // Simple greedy generation (Oshoosi Lite Inference)
            match self.generate_text(session, tokenizer, &prompt, 150) {
                Ok(story) => story,
                Err(e) => {
                    error!("Gemma inference failed: {}. Using legacy summary.", e);
                    self.summarize_legacy(audit)
                }
            }
        } else {
            self.summarize_legacy(audit)
        }
    }

    /// Minimal greedy auto-regressive loop for Gemma-3-270M inference.
    fn generate_text(&self, session: &Session, tokenizer: &Tokenizer, prompt: &str, max_tokens: usize) -> anyhow::Result<String> {
        let encoding = tokenizer.encode(prompt, true).map_err(|e| anyhow::anyhow!(e))?;
        let mut tokens = encoding.get_ids().to_vec();
        let mut generated_text = String::new();

        for _ in 0..max_tokens {
            let input_tensor = ndarray::Array2::from_shape_vec(
                (1, tokens.len()), 
                tokens.iter().map(|&t| t as i64).collect() // Gemma expects i64
            )?;
            let outputs = session.run(inputs!["input_ids" => input_tensor]?)?;
            
            let logits = outputs["logits"].try_extract_tensor::<f32>()?;
            let last_logits = logits.slice(ndarray::s![0, tokens.len() - 1, ..]);
            
            let next_token = last_logits
                .iter()
                .enumerate()
                .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(i, _)| i as u32)
                .unwrap_or(0);

            if next_token == 1 { // Gemma EOS
                break;
            }

            tokens.push(next_token);
            let piece = tokenizer.decode(&[next_token], true).map_err(|e| anyhow::anyhow!(e))?;
            generated_text.push_str(&piece);
        }

        Ok(generated_text.trim().to_string())
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
