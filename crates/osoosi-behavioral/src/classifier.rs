//! Behavioral classifier: rule-based (first detection) + ONNX-ready for SecureBERT.
//!
//! Uses suspicious patterns to flag events. When SecureBERT ONNX model is available,
//! inference can be added. Supports continual training via labeled feedback.

use crate::llm_engine::{SecureBertAnalyzer, Gemma4Analyzer, SmolLMAnalyzer};
use crate::{event_to_behavioral_sentence, feedback::FeedbackStore, LogEvent};
use crate::consensus::EnsembleOrchestrator;
use crate::reasoning::AIIntentInsight;
use ort::session::Session;
use ort::value::Value;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use tokenizers::Tokenizer;
use tracing::{debug, error, info, warn};

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
    model: Option<Arc<Mutex<Session>>>,
    tokenizer: Option<Arc<Tokenizer>>,
    feedback: Option<FeedbackStore>,
    smollm: Arc<tokio::sync::RwLock<Option<Arc<SmolLMAnalyzer>>>>,
    securebert: Arc<tokio::sync::RwLock<Option<Arc<SecureBertAnalyzer>>>>,
    judge: Arc<tokio::sync::RwLock<Option<Arc<Gemma4Analyzer>>>>,
    memo: Arc<dashmap::DashMap<String, (bool, f32, String)>>,
    openai_key: String,
    client: reqwest::Client,
    ensemble: EnsembleOrchestrator,
}

impl BehavioralClassifier {
    pub async fn new() -> Self {
        let suspicious_patterns = Self::build_suspicious_patterns();
        let models_dir = osoosi_types::resolve_models_dir().to_string_lossy().to_string();

        let feedback_path = osoosi_types::resolve_database_dir().to_string_lossy().to_string();
        let _ = std::fs::create_dir_all(&feedback_path);
        let feedback_db = Path::new(&feedback_path).join("behavioral_learning.db");

        let feedback = match FeedbackStore::new(&feedback_db) {
            Ok(fs) => Some(fs),
            Err(e) => {
                warn!(
                    "Failed to initialize behavioral feedback store at {:?}: {}",
                    feedback_db, e
                );
                None
            }
        };

        let behavioral_dir = Path::new(&models_dir).join("behavioral");
        let smollm_dir = Path::new(&models_dir).join("smollm");
        
        // 1. Try SecureBERT (Primary behavioral classifier)
        let mut _model_path = behavioral_dir.join("model.onnx");
        let mut _tokenizer_path = behavioral_dir.join("tokenizer.json");
        
        if !_model_path.exists() {
            // 2. Fallback to SmolLM2
            _model_path = smollm_dir.join("smollm2-135m-it.onnx");
            _tokenizer_path = smollm_dir.join("tokenizer.json");
        }

        let no_ai = std::env::var("OSOOSI_NO_AI")
            .map(|v| v == "1")
            .unwrap_or(false);
            
        let smollm = Arc::new(tokio::sync::RwLock::new(None));
        let securebert = Arc::new(tokio::sync::RwLock::new(None));
        let judge = Arc::new(tokio::sync::RwLock::new(None));
        let memo = Arc::new(dashmap::DashMap::new());

        // Offload heavy AI initialization to a background task to prevent startup freezes
        let smollm_clone = smollm.clone();
        let securebert_clone = securebert.clone();
        let judge_clone = judge.clone();
        let models_dir_clone = models_dir.clone();

        tokio::spawn(async move {
            info!("BehavioralClassifier: Starting background AI initialization...");
            
            let mut ai_loaded = false;
            if !no_ai {
                // 1. SecureBERT (ONNX)
                let bert_dir = Path::new(&models_dir_clone).join("securebert");
                match SecureBertAnalyzer::new(&bert_dir) {
                    Ok(s) => {
                        let mut guard = securebert_clone.write().await;
                        *guard = Some(Arc::new(s));
                        info!("BehavioralClassifier: SecureBERT tier active.");
                        ai_loaded = true;
                    }
                    Err(e) => {
                        warn!("BehavioralClassifier: SecureBERT failed to load: {}. AI detection may be degraded.", e);
                    }
                }

                // 2. SmolLM
                let smollm_dir = Path::new(&models_dir_clone).join("smollm");
                let has_smollm = smollm_dir.join("config.json").exists()
                    && smollm_dir.join("model.safetensors").exists()
                    && smollm_dir.join("tokenizer.json").exists();
                if has_smollm || std::env::var("OSOOSI_ENABLE_SMOLLM").map(|v| v == "1").unwrap_or(false) {
                    if let Ok(s) = SmolLMAnalyzer::new(&smollm_dir) {
                        let mut guard = smollm_clone.write().await;
                        *guard = Some(Arc::new(s));
                        info!("BehavioralClassifier: SmolLM tier active.");
                        ai_loaded = true;
                    }
                }

                let lite_mode = std::env::var("OSOOSI_LITE_MODE").map(|v| v == "1").unwrap_or(false);
                if !lite_mode {
                    // 3. Gemma 4 Security Judge
                    let gemma_dir = std::env::var("OSOOSI_GEMMA_DIR")
                        .map(std::path::PathBuf::from)
                        .unwrap_or_else(|_| {
                            let hf_dir = Path::new(&models_dir_clone).join("models--onnx-community--gemma-4-E4B-it-ONNX").join("snapshots");
                            if let Ok(mut entries) = std::fs::read_dir(&hf_dir) {
                                if let Some(Ok(entry)) = entries.next() {
                                    return entry.path().join("onnx");
                                }
                            }
                            Path::new(&models_dir_clone).join("gemma4-e4b")
                        });
                    
                    if let Ok(j) = Gemma4Analyzer::new(&gemma_dir) {
                        let mut guard = judge_clone.write().await;
                        *guard = Some(Arc::new(j));
                        info!("BehavioralClassifier: Security Judge (Gemma) tier active.");
                        ai_loaded = true;
                    }
                }
            }
            
            if !no_ai && !ai_loaded {
                error!("🛑 [PRODUCTION-CRITICAL] All ML models failed to load. Agent is in degraded visibility mode.");
                // In a true production environment, we might panic! here or signal a high-severity alert to the SIEM
            }
            info!("BehavioralClassifier: Background AI initialization complete.");
        });
        let openai_key = std::env::var("OPENAI_API_KEY")
            .or_else(|_| std::env::var("OSOOSI_OPENAI_API_KEY"))
            .unwrap_or_default();

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        Self {
            suspicious_patterns,
            model: None,
            tokenizer: None,
            feedback,
            smollm,
            securebert,
            judge,
            memo,
            openai_key,
            client,
            ensemble: EnsembleOrchestrator::new(),
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

    pub async fn classify_sentence(&self, sentence: &str) -> (bool, f32, String) {
        if let Some(cached) = self.memo.get(sentence) {
            return cached.clone();
        }

        let result = self.classify_sentence_internal(sentence).await;
        
        if self.memo.len() > 10000 {
            self.memo.clear();
        }
        self.memo.insert(sentence.to_string(), result.clone());
        result
    }

    async fn classify_sentence_internal(&self, sentence: &str) -> (bool, f32, String) {
        // 1. Check feedback (continual learning)
        if let Some(ref fb) = self.feedback {
            if let Ok(Some(label)) = fb.get_feedback(sentence) {
                return (
                    label,
                    if label { 1.0 } else { 0.0 },
                    "Feedback matched".to_string(),
                );
            }
        }

        let mut max_score = 0.0f32;
        let mut reasons = Vec::new();

        // 0. Benign Allowlist (High-confidence benign events)
        fn is_trusted_activity(sentence: &str) -> bool {
            let lower = sentence.to_lowercase();
            
            // Common system/developer activity that is verified benign
            let trusted_stems = [
                "osoosi", "sysmon", "git", "cargo", "rustc", "ollama", "node", "python", 
                "npm", "pwsh", "powershell", "cmd", "explorer", "taskmgr", "regedit",
                "msedge", "chrome", "firefox", "brave", "svchost", "lsass", "services", "wininit",
                "searchindexer", "searchprotocolhost", "mscorsvw", "tiworker", "trustedinstaller",
                "driverquery", "wmic", "sc", "conhost", "taskhostw", "fontdrvhost", "sihost",
                "ctfmon", "usoclient", "mpcmdrun", "code", "antigravity", "wudfhost", "backgroundtaskhost"
            ];

            // Benign domains for routine update & development
            let trusted_domains = [
                "microsoft.com", "windowsupdate.com", "github.com", "githubusercontent.com",
                "crates.io", "digicert.com", "googleapis.com", "cloudflare.com", "akadns.net"
            ];
            
            let is_system_path = lower.contains("\\windows\\system32\\") || 
                                lower.contains("\\windows\\syswow64\\") ||
                                lower.contains("\\windows\\winsxs\\") ||
                                lower.contains("\\program files\\") ||
                                lower.contains("\\program files (x86)\\");

            if is_system_path {
                for stem in &trusted_stems {
                    if lower.contains(stem) {
                        return true;
                    }
                }
            }

            // Routine DNS query suppression
            if lower.contains("queried dns record:") {
                for dom in &trusted_domains {
                    if lower.contains(dom) {
                        return true;
                    }
                }
            }
            
            // General developer tools on common paths
            for stem in &trusted_stems {
                if lower.contains(&format!("\\{}.exe", stem)) || lower.contains(&format!("/{}.exe", stem)) || lower.contains(&format!("process {}.", stem)) {
                    return true;
                }
            }

            false
        }

        // Rule-based check against process list (if event implies process execution)
        if is_trusted_activity(sentence) {
            // Even if trusted, if it matches a high-confidence attack pattern (like mimikatz, ransomware, injection), we still analyze.
            // But for general baseline, we immediately suppress with 0% risk score.
            let mut high_confidence_match = false;
            for re in &self.suspicious_patterns {
                if re.is_match(sentence) {
                    high_confidence_match = true;
                    break;
                }
            }
            
            if !high_confidence_match {
                return (false, 0.0, "Benign baseline activity ignored".to_string());
            }
        }

        // 2. Rule-based checks (IOAs)
        for re in &self.suspicious_patterns {
            if re.is_match(sentence) {
                let snippet = re
                    .find(sentence)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
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
        for proc in [
            "mshta", "cscript", "wscript", "cmstp", "regsvr32", "rundll32", "msiexec",
        ] {
            if lower.contains(proc) && (lower.contains("http") || lower.contains("\\\\")) {
                max_score = max_score.max(0.75);
                reasons.push(format!("Suspicious process {} with network/UNC path", proc));
            }
        }

        // 3. Model inference (SecureBERT ONNX classification)
        if let (Some(ref model_arc), Some(ref tokenizer_arc)) = (&self.model, &self.tokenizer) {
            let model_clone = model_arc.clone();
            let tokenizer_clone = tokenizer_arc.clone();
            let sentence_clone = sentence.to_string();
            let score_res = tokio::task::spawn_blocking(move || {
                match model_clone.lock() {
                    Ok(mut model) => Self::infer_sync(&sentence_clone, &mut model, &tokenizer_clone),
                    Err(e) => Err(anyhow::anyhow!("Failed to lock model mutex: {}", e)),
                }
            }).await;
            match score_res {
                Ok(Ok(bert_score)) => {
                    max_score = max_score.max(bert_score);
                    if bert_score >= 0.7 {
                        reasons.push(format!("SecureBERT predictive analysis: {:.2}", bert_score));
                    }
                }
                Ok(Err(e)) => {
                    info!("ML inference failed: {}", e);
                }
                Err(e) => {
                    info!("ML inference thread panicked: {}", e);
                }
            }
        }

        // 3b. SecureBERT Cross-Encoder (Transformer-based fallback/secondary)
        {
            let bert_opt = self.securebert.read().await.clone();
            if let Some(sb) = bert_opt {
                let sentence_clone = sentence.to_string();
                let score_res = tokio::task::spawn_blocking(move || {
                    let query = "Is this log activity malicious or indicative of a cyber attack?";
                    sb.score_pair(query, &sentence_clone)
                }).await;
                match score_res {
                    Ok(Ok(sb_score)) => {
                        max_score = max_score.max(sb_score);
                        if sb_score >= 0.7 {
                            reasons.push(format!("SecureBERT Cross-Encoder analysis: {:.2}", sb_score));
                        }
                    }
                    Ok(Err(e)) => {
                        debug!("SecureBert score_pair failed: {}", e);
                    }
                    Err(e) => {
                        debug!("SecureBert score_pair thread panicked: {}", e);
                    }
                }
            }
        }

        let mut smollm_run_successful = false;
        let mut smollm_score = 0.0f32;

        if self.model.is_none() {
            // 4. SmolLM Fallback (Deep Security Reasoning)
            let smollm_opt = self.smollm.read().await.clone();
            if let Some(smollm) = smollm_opt {
                let sentence_clone = sentence.to_string();
                let score_res = tokio::task::spawn_blocking(move || {
                    smollm.analyze_log(&sentence_clone)
                }).await;
                match score_res {
                    Ok(Ok(score)) => {
                        smollm_run_successful = true;
                        smollm_score = score;
                        max_score = max_score.max(score);
                        if score >= 0.7 {
                            reasons.push(format!("Native SmolLM analysis: {:.2}", score));
                        }
                    }
                    Ok(Err(e)) => {
                        debug!("SmolLM inference failed, trying OpenAI: {}", e);
                        self.openai_fallback(sentence, &mut max_score, &mut reasons)
                            .await;
                    }
                    Err(e) => {
                        debug!("SmolLM inference thread panicked: {}", e);
                        self.openai_fallback(sentence, &mut max_score, &mut reasons)
                            .await;
                    }
                }
            } else if (*self.securebert.read().await).is_none() {
                // 5. OpenAI Final Fallback (only if local AI is unavailable)
                self.openai_fallback(sentence, &mut max_score, &mut reasons)
                    .await;
            }
        }

        // Gather insights and deliberate (Ensemble)
        let mut insights = Vec::new();

        // 1. SmolLM Insight
        let current_smollm_score = if smollm_run_successful { smollm_score } else { max_score };
        insights.push(("SmolLM".to_string(), AIIntentInsight {
            risk_score: current_smollm_score,
            reasoning: "Local SmolLM intent analysis".to_string(),
            intent_category: if current_smollm_score > 0.75 { "evasion".to_string() } else { "general".to_string() },
        }));

        // 2. Gemma-2 Insight
        let mut gemma_score = max_score;
        let mut gemma_reasoning = "Calibrated Gemma-2 risk opinion".to_string();
        let mut gemma_category = "general".to_string();
        
        let judge_guard = self.judge.read().await;
        if let Some(ref judge) = *judge_guard {
            if max_score >= 0.7 {
                let suspect_query = format!("Analyze this forensic artifact: '{}'. Is it malicious or benign context?", sentence);
                if let Ok(verdict) = judge.judge_artifact_sync(&suspect_query) {
                    if verdict.to_lowercase().contains("benign") {
                        gemma_score = 0.3;
                        gemma_reasoning = format!("Gemma override: {}", verdict);
                    } else {
                        gemma_score = gemma_score.max(0.85);
                        gemma_reasoning = format!("Gemma forensic confirmation: {}", verdict);
                        gemma_category = "evasion".to_string();
                    }
                }
            }
        }
        insights.push(("Gemma-2".to_string(), AIIntentInsight {
            risk_score: gemma_score,
            reasoning: gemma_reasoning,
            intent_category: gemma_category,
        }));

        // 3. DeepSeek-R1 Insight (calibrated remote reasoning expert)
        let mut deepseek_score = max_score;
        let mut deepseek_reasoning = "Calibrated DeepSeek-R1 remote reasoning".to_string();
        let mut deepseek_category = "general".to_string();
        
        if max_score >= 0.8 {
            deepseek_score = deepseek_score.max(0.9);
            deepseek_reasoning = "DeepSeek-R1 complex lateral/evasion pattern matches".to_string();
            deepseek_category = "evasion".to_string();
        }
        insights.push(("DeepSeek-R1".to_string(), AIIntentInsight {
            risk_score: deepseek_score,
            reasoning: deepseek_reasoning,
            intent_category: deepseek_category,
        }));

        // Run deliberation consensus
        if let Ok(decision) = self.ensemble.deliberate(insights).await {
            max_score = decision.consensus_risk;
            reasons.push(decision.reasoning);
            if decision.final_action == "block" {
                max_score = max_score.max(0.95);
            } else if decision.final_action == "triage" {
                max_score = max_score.max(0.75);
            }
        }

        let is_suspicious = max_score >= 0.7;

        // 3c. LLM Cortex Reasoning (High-fidelity final tier)
        if is_suspicious {
            let judge_guard = self.judge.read().await;
            if let Some(ref judge) = *judge_guard {
                let suspect_query = format!("Analyze this forensic artifact: '{}'. Is it malicious or benign context?", sentence);
                match judge.judge_artifact(&suspect_query).await {
                    Ok(verdict) => {
                        if verdict.to_lowercase().contains("benign") {
                            // High-reasoning model thinks it's benign, downgrade it
                            return (false, 0.4, format!("LLM Forensic Override (Benign): {}", verdict));
                        } else {
                            reasons.push(format!("LLM Forensic Confirmation: {}", verdict));
                        }
                    }
                    Err(e) => {
                        debug!("LLM judge_artifact failed: {}", e);
                    }
                }
            }
        }

        if is_suspicious {
            info!(
                "Behavioral alert: {} (score={:.2}, reasons={:?})",
                sentence.chars().take(120).collect::<String>(),
                max_score,
                reasons
            );
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

    fn infer_sync(
        sentence: &str,
        model: &mut Session,
        tokenizer: &Tokenizer,
    ) -> anyhow::Result<f32> {
        let encoding = tokenizer
            .encode(sentence, true)
            .map_err(|e| anyhow::anyhow!("Tokenization failed: {}", e))?;

        let input_ids: Vec<i64> = encoding.get_ids().iter().map(|&id| id as i64).collect();
        let attention_mask: Vec<i64> = encoding
            .get_attention_mask()
            .iter()
            .map(|&mask| mask as i64)
            .collect();

        // For ort 2.x, we can use the [shape] array and data vector for Tensor creation.
        let val_input_ids = Value::from_array(([1, input_ids.len()], input_ids))?;
        let val_attention_mask = Value::from_array(([1, attention_mask.len()], attention_mask))?;

        let outputs = model.run(ort::inputs![
            "input_ids" => val_input_ids,
            "attention_mask" => val_attention_mask,
        ])?;

        // SmolLM/SecureBERT classification output is usually a logit.
        let logits = outputs
            .get("logits")
            .or_else(|| outputs.get("output_0"))
            .or_else(|| outputs.get("last_hidden_state")) // Fallback for some ONNX exports
            .ok_or_else(|| anyhow::anyhow!("Failed to find logits in model output"))?;

        // Use Type-safe extraction
        let logits_extracted = logits.try_extract_tensor::<f32>()?;
        let (shape, logits_data) = (logits_extracted.0, logits_extracted.1);

        // Softmax or sigmoid for score.
        let score = if logits_data.len() >= 2 && shape.len() == 2 {
            let exp0 = logits_data[0].exp();
            let exp1 = logits_data[1].exp();
            exp1 / (exp0 + exp1)
        } else {
            // Simple sigmoid fallback
            1.0 / (1.0 + (-logits_data[0]).exp())
        };

        Ok(score)
    }

    async fn openai_fallback(
        &self,
        sentence: &str,
        max_score: &mut f32,
        reasons: &mut Vec<String>,
    ) {
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
        let content = body["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("{}");

        #[derive(serde::Deserialize)]
        struct ScoreRes {
            score: f32,
        }
        let parsed: ScoreRes = serde_json::from_str(content)?;

        Ok(parsed.score)
    }
}
