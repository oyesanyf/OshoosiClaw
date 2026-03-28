//! Behavioral classifier: rule-based (first detection) + ONNX-ready for SecureBERT.
//!
//! Uses suspicious patterns to flag events. When SecureBERT ONNX model is available,
//! inference can be added. Supports continual training via labeled feedback.

use crate::{event_to_behavioral_sentence, feedback::FeedbackStore, LogEvent};
use ort::session::{builder::SessionBuilder, Session};
use ort::value::Value;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;
use tokenizers::Tokenizer;
use tracing::{debug, info, warn};
use std::sync::Arc;
use crate::gemma::GemmaAnalyzer;

/// Result of behavioral classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralResult {
    pub sentence: String,
    pub is_suspicious: bool,
    pub score: f32,
    pub reason: String,
    pub event_id: u32,
    pub source: String,
}

/// Classifier for behavioral sentences.
/// Uses SecureBERT (ONNX) + Rule-based + Feedback-driven learning.
pub struct BehavioralClassifier {
    suspicious_patterns: Vec<Regex>,
    model: Option<Mutex<Session>>,
    tokenizer: Option<Tokenizer>,
    feedback: Option<FeedbackStore>,
    gemma: Option<Arc<GemmaAnalyzer>>,
    openai_key: String,
    client: reqwest::Client,
}

impl BehavioralClassifier {
    pub async fn new() -> Self {
        let suspicious_patterns = Self::build_suspicious_patterns();
        let models_dir = std::env::var("OSOOSI_MODELS_DIR").unwrap_or_else(|_| "models".to_string());
        let behavioral_dir = Path::new(&models_dir).join("behavioral");
        
        let feedback_path = std::env::var("OSOOSI_DATA_DIR")
            .unwrap_or_else(|_| "data".to_string());
        let _ = std::fs::create_dir_all(&feedback_path);
        let feedback_db = Path::new(&feedback_path).join("behavioral_learning.db");
        
        let feedback = match FeedbackStore::new(&feedback_db) {
            Ok(fs) => Some(fs),
            Err(e) => {
                warn!("Failed to initialize behavioral feedback store at {:?}: {}", feedback_db, e);
                None
            }
        };

        let model_path = behavioral_dir.join("model.onnx");
        let tokenizer_path = behavioral_dir.join("tokenizer.json");

        let no_ort = std::env::var("OSOOSI_NO_ORT").map(|v| v == "1").unwrap_or(false);
        let (model, tokenizer) = if !no_ort && model_path.exists() && tokenizer_path.exists() {
            info!("Loading SecureBERT model from {:?}", model_path);
            let session_res = (|| -> anyhow::Result<Session> {
                let builder = SessionBuilder::new()?;
                let session = builder.commit_from_file(&model_path)?;
                Ok(session)
            })();
            
            let tok = Tokenizer::from_file(&tokenizer_path);
            
            match (session_res, tok) {
                (Ok(s), Ok(t)) => (Some(Mutex::new(s)), Some(t)),
                (Err(e), _) => {
                    warn!("Failed to load ONNX session: {}", e);
                    (None, None)
                }
                (_, Err(e)) => {
                    warn!("Failed to load tokenizer: {}", e);
                    (None, None)
                }
            }
        } else {
            info!("Behavioral classifier: ONNX engine disabled (missing model.onnx or tokenizer.json). Falling back to native Gemma 3 4B.");
            (None, None)
        };

        let openai_key = std::env::var("OPENAI_API_KEY")
            .or_else(|_| std::env::var("OSOOSI_OPENAI_API_KEY"))
            .unwrap_or_default();

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        let gemma = if model.is_none() {
            // Attempt to load native Gemma 3 4B from models/gemma/
            let gemma_dir = Path::new(&models_dir).join("gemma");
            match GemmaAnalyzer::new(&gemma_dir) {
                Ok(g) => {
                    info!("Native Gemma 3 4B initialization successful.");
                    Some(Arc::new(g))
                }
                Err(e) => {
                    warn!("Failed to initialize native Gemma from {:?}: {}. Falling back to Rule-based + OpenAI.", gemma_dir, e);
                    None
                }
            }
        } else {
            None
        };

        Self {
            suspicious_patterns,
            model,
            tokenizer,
            feedback,
            gemma,
            openai_key,
            client,
        }
    }

    fn build_suspicious_patterns() -> Vec<Regex> {
        [
            r"(?i)powershell\s+-enc",
            r"(?i)powershell\s+-encodedcommand",
            r"(?i)invoke-mimikatz",
            r"(?i)invoke-?shellcode",
            r"(?i)downloadstring\s*\(",
            r"(?i)frombase64string",
            r"(?i)iex\s*\(",
            r"(?i)bypass\s+-executionpolicy",
            r"(?i)hidden\s+-window",
            r"(?i)wscript\.shell",
            r"(?i)cmd\.exe\s+/c\s+echo",
            r"(?i)certutil\s+-urlcache",
            r"(?i)bitsadmin",
            r"(?i)reg\s+add.*persistence",
            r"(?i)schtasks\s+/create",
            r"(?i)sc\s+create.*binpath",
            r"(?i)net\s+user.*/add",
            r"(?i)vssadmin\s+delete",
            r"(?i)wbadmin\s+delete",
            r"(?i)bcdedit\s+/set",
            r"(?i)mshta\s+http",
            r"(?i)rundll32.*javascript",
            r"(?i)cmstp\.exe.*\.inf",
            r"(?i)msiexec\s+/i\s+http",
            r"(?i)\.onion\b",
            r"(?i)pastebin\.com",
            r"(?i)transfer\.sh",
        ]
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect()
    }

    /// Add feedback for a sentence (True/False Positive)
    pub fn learn(&self, sentence: &str, is_suspicious: bool) {
        if let Some(ref fb) = self.feedback {
            let _ = fb.add_feedback(sentence, is_suspicious);
        }
    }

    /// Classify a log event. Returns BehavioralResult with sentence and suspicion score.
    pub async fn classify(&self, event: &LogEvent) -> BehavioralResult {
        let sentence = event_to_behavioral_sentence(event);
        let (is_suspicious, score, reason) = self.classify_sentence(&sentence).await;
        BehavioralResult {
            sentence: sentence.clone(),
            is_suspicious,
            score,
            reason,
            event_id: event.event_id,
            source: event.source.clone(),
        }
    }

    async fn classify_sentence(&self, sentence: &str) -> (bool, f32, String) {
        // 1. Check feedback (continual learning)
        if let Some(ref fb) = self.feedback {
            if let Ok(Some(label)) = fb.get_feedback(sentence) {
                return (label, if label { 1.0 } else { 0.0 }, "Feedback matched".to_string());
            }
        }

        let mut max_score = 0.0f32;
        let mut reasons = Vec::new();

        // 0. Benign Allowlist (High-confidence benign events)
        let lower = sentence.to_lowercase();
        if lower.contains("session established") && lower.contains("from local") {
            return (false, 0.1, "Common benign local session".to_string());
        }
        if lower.contains("process started") && (lower.contains("git.exe") || lower.contains("conhost.exe") || lower.contains("cargo.exe")) {
            return (false, 0.05, "Trusted development process".to_string());
        }

        // 2. Rule-based checks (IOAs)
        for re in &self.suspicious_patterns {
            if re.is_match(sentence) {
                let snippet = re.find(sentence).map(|m| m.as_str().to_string()).unwrap_or_default();
                max_score = max_score.max(0.85);
                reasons.push(format!("Pattern match: {}", snippet));
            }
        }

        // Length heuristic: very long encoded commands
        if sentence.contains("base64") && sentence.len() > 200 {
            max_score = max_score.max(0.7);
            reasons.push("Long base64-like content".to_string());
        }

        // Process names often abused
        let lower = sentence.to_lowercase();
        for proc in ["mshta", "cscript", "wscript", "cmstp", "regsvr32", "rundll32", "msiexec"] {
            if lower.contains(proc) && (lower.contains("http") || lower.contains("\\\\")) {
                max_score = max_score.max(0.75);
                reasons.push(format!("Suspicious process {} with network/UNC path", proc));
            }
        }

        // 3. Model inference (SecureBERT)
        if let (Some(ref model_mutex), Some(ref tokenizer)) = (&self.model, &self.tokenizer) {
            match model_mutex.lock() {
                Ok(mut model) => {
                    match self.infer(sentence, &mut model, tokenizer) {
                        Ok(bert_score) => {
                            max_score = max_score.max(bert_score);
                            if bert_score >= 0.7 {
                                reasons.push(format!("SecureBERT predictive analysis: {:.2}", bert_score));
                            }
                        }
                        Err(e) => {
                            debug!("ML inference failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to lock behavioral model mutex: {}", e);
                }
            }
        } else {
            // 4. Native Gemma Fallback (Deep Security Reasoning)
            if let Some(ref gemma) = self.gemma {
                match gemma.analyze_log(sentence) {
                    Ok(gemma_score) => {
                        max_score = max_score.max(gemma_score);
                        if gemma_score >= 0.7 {
                            reasons.push(format!("Native Gemma 3 4B analysis: {:.2}", gemma_score));
                        }
                    }
                    Err(e) => {
                        debug!("Gemma inference failed, trying OpenAI: {}", e);
                        self.openai_fallback(sentence, &mut max_score, &mut reasons).await;
                    }
                }
            } else {
                // 5. OpenAI Final Fallback
                self.openai_fallback(sentence, &mut max_score, &mut reasons).await;
            }
        }

        let is_suspicious = max_score >= 0.7;
        if is_suspicious {
            info!("Behavioral alert: {} (score={:.2}, reasons={:?})", 
                sentence.chars().take(80).collect::<String>(), max_score, reasons);
        }

        (
            is_suspicious,
            max_score,
            if reasons.is_empty() {
                "No suspicious indicators".to_string()
            } else {
                reasons.join(", ")
            },
        )
    }

    fn infer(&self, sentence: &str, model: &mut Session, tokenizer: &Tokenizer) -> anyhow::Result<f32> {
        let encoding = tokenizer.encode(sentence, true)
            .map_err(|e| anyhow::anyhow!("Tokenization failed: {}", e))?;
        
        let input_ids: Vec<i64> = encoding.get_ids().iter().map(|&id| id as i64).collect();
        let attention_mask: Vec<i64> = encoding.get_attention_mask().iter().map(|&mask| mask as i64).collect();
        
        // For ort 2.x, we can use the [shape] array and data vector for Tensor creation.
        let val_input_ids = Value::from_array(([1, input_ids.len()], input_ids))?;
        let val_attention_mask = Value::from_array(([1, attention_mask.len()], attention_mask))?;

        let outputs = model.run(ort::inputs![
            "input_ids" => val_input_ids,
            "attention_mask" => val_attention_mask,
        ])?;

        // SecureBERT classification output is usually a logit.
        let logits = outputs.get("logits")
            .or_else(|| outputs.get("output_0"))
            .ok_or_else(|| anyhow::anyhow!("Failed to find logits in model output"))?;
        
        // Use Type-safe extraction
        let logits_extracted = logits.try_extract_tensor::<f32>()?;
        let (_shape, logits_data) = (logits_extracted.0, logits_extracted.1);
        
        // Softmax or sigmoid for score. Assuming binary classification for behavioral suspiciousness.
        let score = if logits_data.len() >= 2 {
            // Binary classification [benign, malicious]
            let exp0 = logits_data[0].exp();
            let exp1 = logits_data[1].exp();
            exp1 / (exp0 + exp1)
        } else {
            // Regression or single output sigmoid
            1.0 / (1.0 + (-logits_data[0]).exp())
        };

        Ok(score)
    }

    async fn openai_fallback(&self, sentence: &str, max_score: &mut f32, reasons: &mut Vec<String>) {
        if !self.openai_key.is_empty() {
            match self.infer_openai(sentence).await {
                Ok(openai_score) => {
                    *max_score = max_score.max(openai_score);
                    if openai_score >= 0.7 {
                        reasons.push(format!("OpenAI GPT-4o analysis: {:.2}", openai_score));
                    }
                }
                Err(oe) => {
                    debug!("OpenAI inference fallback failed: {}", oe);
                }
            }
        }
    }

    async fn infer_openai(&self, sentence: &str) -> anyhow::Result<f32> {
        let url = "https://api.openai.com/v1/chat/completions";
        let prompt = format!(
            "Analyze the following log sentence and determine if it indicates malicious or highly suspicious activity (e.g. lateral movement, exfiltration, persistence). \
             Respond ONLY with a JSON object containing a 'score' field (0.0 to 1.0). \n\nLog: {}", 
            sentence
        );

        let res = self.client.post(url)
            .header("Authorization", format!("Bearer {}", self.openai_key))
            .json(&serde_json::json!({
                "model": "gpt-4o",
                "messages": [
                    { "role": "system", "content": "You are a professional security analyst. Return JSON scores." },
                    { "role": "user", "content": prompt }
                ],
                "response_format": { "type": "json_object" },
                "temperature": 0.0
            }))
            .send().await?;

        if !res.status().is_success() {
            let status = res.status();
            let err = res.text().await?;
            return Err(anyhow::anyhow!("OpenAI API error {}: {}", status, err));
        }

        let body: serde_json::Value = res.json().await?;
        let content = body["choices"][0]["message"]["content"].as_str().unwrap_or("{}");
        
        #[derive(serde::Deserialize)]
        struct ScoreRes { score: f32 }
        let parsed: ScoreRes = serde_json::from_str(content)?;
        
        Ok(parsed.score)
    }
}
