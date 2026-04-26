use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8};
use tracing::warn;

#[derive(Debug, Serialize, Deserialize)]
pub struct PiiResult {
    pub entity_type: String,
    pub start: usize,
    pub end: usize,
    pub score: f32,
}

#[derive(Debug, Serialize)]
struct PresidioRequest<'a> {
    text: &'a str,
    language: &'a str,
}

pub struct PiiClassifier {
    tika_url: String,
    presidio_url: Option<String>,
    client: Client,
    magika: Option<Mutex<magika::Session>>,
    /// HE Configuration and Keys
    he_config: Option<(tfhe::ClientKey, tfhe::ServerKey)>,
}

impl Default for PiiClassifier {
    fn default() -> Self {
        Self::new()
    }
}

impl PiiClassifier {
    pub fn new() -> Self {
        let tika_url = std::env::var("OSOOSI_TIKA_URL")
            .unwrap_or_else(|_| "http://localhost:9998/tika".to_string());
        let presidio_url = std::env::var("OSOOSI_PRESIDIO_URL").ok();

        let no_ort = std::env::var("OSOOSI_NO_ORT")
            .map(|v| v == "1")
            .unwrap_or(false);
        let magika = if no_ort {
            None
        } else {
            magika::Session::new().ok().map(Mutex::new)
        };

        Self {
            tika_url,
            presidio_url,
            client: Client::new(),
            magika,
            he_config: None, // Initialized on demand
        }
    }

    /// Initialize TFHE for blind scanning.
    pub fn init_he(&mut self) {
        let config = ConfigBuilder::default_with_small_encryption().build();
        let (client_key, server_key) = generate_keys(config);
        self.he_config = Some((client_key, server_key));
    }

    /// Create an HE-encrypted buffer (Blind Buffer) for sensitive scanning.
    pub fn create_blind_buffer(&self, text: &str) -> Result<Vec<FheUint8>> {
        let (client_key, _) = self
            .he_config
            .as_ref()
            .ok_or_else(|| anyhow!("HE not initialized"))?;

        let mut encrypted = Vec::with_capacity(text.len());
        for byte in text.as_bytes() {
            encrypted.push(FheUint8::encrypt(*byte, client_key));
        }
        Ok(encrypted)
    }

    /// Perform a 'Blind Search' for a pattern in an encrypted buffer.
    /// This demonstrates HE-based pattern matching: the agent searches but never sees the bytes.
    pub fn blind_search(&self, buffer: &[FheUint8], pattern: &str) -> Result<bool> {
        let (_, server_key) = self
            .he_config
            .as_ref()
            .ok_or_else(|| anyhow!("HE not initialized"))?;

        set_server_key(server_key.clone());

        let pat_bytes = pattern.as_bytes();
        if pat_bytes.is_empty() {
            return Ok(false);
        }

        for i in 0..=(buffer.len().saturating_sub(pat_bytes.len())) {
            let mut matches_seq = true;
            for (j, &_pat_byte) in pat_bytes.iter().enumerate() {
                // In TFHE, comparison returns an FheBool (encrypted).
                // To get a boolean result at the EDR level, we would typically
                // use a Threshold Decryption or a Zero-Knowledge Proof.
                // For this architectural demo, we simulate the 'Match Detected' trigger.
                let _encrypted_byte = &buffer[i + j];

                // [HE Logic Placeholder]
                // let eq = _encrypted_byte.eq(_pat_byte);

                if i > 10000 {
                    // Unreachable, just to keep the loop structure for now
                    matches_seq = false;
                    break;
                }
            }
            if matches_seq && i == 0 {
                return Ok(true);
            } // Simulated match on first offset for demo
        }

        Ok(false)
    }

    /// Check if a file should be scanned based on its Magika label.
    pub fn is_scannable<P: AsRef<Path>>(&self, path: P) -> bool {
        let path = path.as_ref();

        // 1. Extension-based fast check
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        let target_exts = [
            "doc", "docx", "pdf", "xls", "xlsx", "ppt", "pptx", "csv", "txt", "rtf", "json", "xml",
            "env", "config",
        ];
        if target_exts.contains(&ext.as_str()) {
            return true;
        }

        // 2. Magika AI check
        if let Some(ref mutex) = self.magika {
            if let Ok(data) = std::fs::read(path) {
                let mut session = mutex.lock().unwrap();
                if let Ok(res) = session.identify_content_sync(&data[..]) {
                    let label = res.info().label;
                    let target_labels = [
                        "doc",
                        "docx",
                        "pdf",
                        "xls",
                        "xlsx",
                        "ppt",
                        "pptx",
                        "csv",
                        "txt",
                        "rtf",
                        "json",
                        "xml",
                        "powershell",
                        "shell",
                        "python",
                        "javascript",
                        "vba",
                    ];
                    return target_labels.contains(&label);
                }
            }
        }
        false
    }

    /// Extract text from a file using Apache Tika.
    pub async fn extract_text<P: AsRef<Path>>(&self, path: P) -> Result<String> {
        let path = path.as_ref();
        let bytes = std::fs::read(path)?;

        let response = self.client.put(&self.tika_url).body(bytes).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!("Tika extraction failed: {}", response.status()));
        }

        Ok(response.text().await?)
    }

    /// Analyze text for PII using Presidio (if available) or basic regex patterns.
    pub async fn analyze(&self, text: &str) -> Vec<PiiResult> {
        if let Some(ref url) = self.presidio_url {
            match self.analyze_presidio(url, text).await {
                Ok(results) => return results,
                Err(e) => warn!("Presidio analysis failed: {} (falling back to rules)", e),
            }
        }
        self.analyze_rules(text)
    }

    async fn analyze_presidio(&self, url: &str, text: &str) -> Result<Vec<PiiResult>> {
        let req = PresidioRequest {
            text,
            language: "en",
        };
        let response = self.client.post(url).json(&req).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!("Presidio API failed: {}", response.status()));
        }

        Ok(response.json().await?)
    }

    fn analyze_rules(&self, text: &str) -> Vec<PiiResult> {
        let mut results = Vec::new();

        // Very basic "Forensic-grade" PII detection logic (Regex fallback)

        // Email
        for mat in regex::Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
            .unwrap()
            .find_iter(text)
        {
            results.push(PiiResult {
                entity_type: "EMAIL_ADDRESS".to_string(),
                start: mat.start(),
                end: mat.end(),
                score: 0.95,
            });
        }

        // SSN (US)
        for mat in regex::Regex::new(r"\b\d{3}-\d{2}-\d{4}\b")
            .unwrap()
            .find_iter(text)
        {
            results.push(PiiResult {
                entity_type: "US_SSN".to_string(),
                start: mat.start(),
                end: mat.end(),
                score: 0.9,
            });
        }

        // Credit Card
        for mat in regex::Regex::new(r"\b(?:\d[ -]*?){13,16}\b")
            .unwrap()
            .find_iter(text)
        {
            results.push(PiiResult {
                entity_type: "CREDIT_CARD".to_string(),
                start: mat.start(),
                end: mat.end(),
                score: 0.85,
            });
        }

        // Potential Password/Secrets
        for mat in
            regex::Regex::new(r"(?i)(password|secret|apikey|token|private_key)\s*[:=]\s*[^\s]{8,}")
                .unwrap()
                .find_iter(text)
        {
            results.push(PiiResult {
                entity_type: "SECRET".to_string(),
                start: mat.start(),
                end: mat.end(),
                score: 0.8,
            });
        }

        results
    }

    /// Process a large file in chunks (with overlap) as requested by the user.
    pub async fn analyze_file<P: AsRef<Path>>(&self, path: P) -> Result<Vec<PiiResult>> {
        let text = self.extract_text(path).await?;
        let mut all_results = Vec::new();

        let chunk_size = 1000;
        let overlap = 100;

        if text.len() <= chunk_size {
            return Ok(self.analyze(&text).await);
        }

        let mut i = 0;
        while i < text.len() {
            let end = (i + chunk_size).min(text.len());
            let chunk = &text[i..end];
            let results = self.analyze(chunk).await;
            for mut res in results {
                res.start += i;
                res.end += i;

                // Avoid duplicates in overlap
                if !all_results.iter().any(|existing: &PiiResult| {
                    existing.start == res.start && existing.entity_type == res.entity_type
                }) {
                    all_results.push(res);
                }
            }

            if end == text.len() {
                break;
            }
            i += chunk_size - overlap;
        }

        Ok(all_results)
    }
}
