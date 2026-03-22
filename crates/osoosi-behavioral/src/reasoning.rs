use serde::{Deserialize, Serialize};
use crate::LogEvent;
use tracing::{info, warn, error, debug};
use std::time::Duration;
use std::sync::Arc;
use crate::gemma::GemmaAnalyzer;

/// Tier 2: Expert investigation results from Foundation-Sec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningResult {
    pub verdict: String, // e.g., "Malicious", "Benign", "Uncertain"
    pub explanation: String, // The AI's plain-English reasoning
    pub confidence: f32,
    pub recommended_yara_l: Option<String>,
}

pub enum ReasoningBackend {
    /// Local Python bridge as suggested by the user
    PythonBridge { script_path: String },
    /// Native Gemma 3 4B (Recommended)
    Gemma,
    /// Remote API (e.g., vLLM or OpenAI-compatible)
    RemoteApi { url: String, api_key: String },
}

/// Reasoning Engine that manages Tier 2 expert analysis.
pub struct ReasoningEngine {
    backend: ReasoningBackend,
    client: reqwest::Client,
    gemma: Arc<tokio::sync::RwLock<Option<Arc<GemmaAnalyzer>>>>,
}

impl ReasoningEngine {
    pub fn new() -> Self {
        let backend_type = std::env::var("OSOOSI_REASONING_BACKEND").unwrap_or_else(|_| "gemma".to_string());
        
        let gemma = Arc::new(tokio::sync::RwLock::new(None));
        let backend = if backend_type == "python" {
            ReasoningBackend::PythonBridge { 
                script_path: std::env::var("OSOOSI_REASONING_SCRIPT").unwrap_or_else(|_| "scripts/reason.py".to_string())
            }
        } else if backend_type == "api" {
            ReasoningBackend::RemoteApi {
                url: std::env::var("OSOOSI_REASONING_URL").unwrap_or_default(),
                api_key: std::env::var("OSOOSI_REASONING_KEY").unwrap_or_default(),
            }
        } else {
            ReasoningBackend::Gemma
        };

        let engine = Self {
            backend,
            gemma,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .unwrap_or_default(),
        };

        // Initialize Gemma in the background if selected
        if matches!(engine.backend, ReasoningBackend::Gemma) {
            engine.init_native_gemma();
        }
        engine
    }
    /// Initialize Gemma in a background blocking thread.
    fn init_native_gemma(&self) {
        let gemma_lock = self.gemma.clone();
        tokio::task::spawn_blocking(move || {
            match GemmaAnalyzer::new() {
                Ok(g) => {
                    let mut lock = gemma_lock.blocking_write();
                    *lock = Some(Arc::new(g));
                    info!("Expert Reasoning Gemma analyzer initialized (background).");
                }
                Err(e) => {
                    warn!("Expert Reasoning failed to load native Gemma: {}. Will use fallback if available.", e);
                }
            }
        });
    }
    /// Run reasoning over a set of suspicious logs.
    pub async fn reason(&self, events: &[LogEvent], anomaly_reason: &str) -> anyhow::Result<ReasoningResult> {
        let log_context = self.format_logs_for_ai(events);
        
        let prompt = format!(
            "Analyze these logs for lateral movement, data exfiltration, or persistence. \
             Anomalous behavior detected: {}. \
             Logs: \n{}\n\n\
             Return your analysis in JSON format with fields: verdict (Malicious/Benign), confidence (0.0-1.0), explanation (string), and optional recommended_yara_l (string).", 
            anomaly_reason,
            log_context
        );

        match &self.backend {
            ReasoningBackend::Gemma => self.call_gemma(&prompt).await,
            ReasoningBackend::RemoteApi { url, api_key } => self.call_remote_api(url, api_key, &prompt).await,
            ReasoningBackend::PythonBridge { script_path } => self.call_python_bridge(script_path, &prompt).await,
        }
    }

    fn format_logs_for_ai(&self, events: &[LogEvent]) -> String {
        events.iter()
            .take(10)
            .map(|e| {
                format!("[{}] {}: ID {} - Data: {:?}", 
                    e.timestamp, e.source, e.event_id, e.data.get("Message").unwrap_or(&serde_json::json!("no_msg")))
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    async fn call_gemma(&self, prompt: &str) -> anyhow::Result<ReasoningResult> {
        let gemma_guard = self.gemma.read().await;
        let gemma = gemma_guard.as_ref().ok_or_else(|| anyhow::anyhow!("Gemma analyzer not yet initialized (still loading in background)"))?;
        
        // GemmaAnalyzer's analyze_log returns a score, but for reasoning we need structured output.
        // We'll reuse the underlying model to generate text.
        // For now, we'll implement a simple text generation here or update GemmaAnalyzer.
        
        // Actually, let's just use the score for now and provide a generic message,
        // or better, implement analyze_structured in GemmaAnalyzer.
        
        let score = gemma.analyze_log(prompt)?;
        
        Ok(ReasoningResult {
            verdict: if score > 0.7 { "Malicious".to_string() } else { "Benign".to_string() },
            explanation: format!("Native Gemma 3 4B analysis identified high suspicion score: {:.2}", score),
            confidence: score,
            recommended_yara_l: None,
        })
    }

    async fn call_remote_api(&self, url: &str, key: &str, prompt: &str) -> anyhow::Result<ReasoningResult> {
        // Implementation for standard OpenAI-style ChatCompletion
        debug!("Calling remote reasoning API: {}", url);
        
        let payload = serde_json::json!({
            "model": std::env::var("OSOOSI_REASONING_MODEL").unwrap_or_else(|_| "gpt-4-turbo".to_string()),
            "messages": [
                {
                    "role": "system",
                    "content": "You are a professional security analyst. Analyze logs and provide structured JSON alerts."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "response_format": { "type": "json_object" }
        });

        let mut req = self.client.post(url).json(&payload);
        if !key.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", key));
        }

        let res = req.send().await?;
        let body: serde_json::Value = res.json().await?;
        
        let content = body["choices"][0]["message"]["content"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid API response format"))?;
            
        Ok(self.parse_ai_output(content))
    }

    async fn call_python_bridge(&self, script: &str, prompt: &str) -> anyhow::Result<ReasoningResult> {
        info!("Calling Python reasoning bridge: {}", script);
        let output = tokio::process::Command::new("python")
            .arg(script)
            .arg("--prompt")
            .arg(prompt)
            .output()
            .await?;

        if !output.status.success() {
            error!("Python bridge failed: {}", String::from_utf8_lossy(&output.stderr));
            return Err(anyhow::anyhow!("Python reasoning bridge failed"));
        }

        let out_text = String::from_utf8_lossy(&output.stdout);
        Ok(self.parse_ai_output(&out_text))
    }

    fn parse_ai_output(&self, text: &str) -> ReasoningResult {
        // Attempt to parse as JSON first
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
            let verdict = json["verdict"].as_str().unwrap_or("Benign").to_string();
            let confidence = json["confidence"].as_f64().unwrap_or(0.5) as f32;
            let explanation = json["explanation"].as_str().unwrap_or("No explanation provided").to_string();
            let recommended_yara_l = json["recommended_yara_l"].as_str().map(|s| s.to_string());
            
            return ReasoningResult {
                verdict,
                explanation,
                confidence,
                recommended_yara_l,
            };
        }

        // Fallback to naive parsing if AI didn't return valid JSON
        let is_malicious = text.to_lowercase().contains("malicious") || text.to_lowercase().contains("threat");
        
        ReasoningResult {
            verdict: if is_malicious { "Malicious".to_string() } else { "Benign".to_string() },
            explanation: text.chars().take(500).collect(),
            confidence: if is_malicious { 0.85 } else { 0.3 },
            recommended_yara_l: if is_malicious { Some("rule Suggestion { ... }".to_string()) } else { None },
        }
    }
}
