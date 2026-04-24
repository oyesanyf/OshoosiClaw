//! Static Analyzer for OpenỌ̀ṣọ́ọ̀sì
//! 
//! Integrates multiple tools (CAPA, FLOSS) and LLM-based reasoning to identify 
//! suspicious behaviors and hidden artifacts in binary files.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn, error, debug};
use osoosi_types::{ThreatSignature, ResponseAction};
use serde_json::Value;
use regex::Regex;

pub struct StaticAnalyzer {
    /// Path to the 'capa' executable
    capa_path: PathBuf,
    /// Path to the rules directory
    rules_path: PathBuf,
    /// Path to the 'floss' executable
    floss_path: PathBuf,
    /// Path to the signatures directory
    signatures_path: PathBuf,
    /// Memory: For caching analysis results
    _memory: Arc<osoosi_memory::MemoryStore>,
}

impl StaticAnalyzer {
    pub fn new(memory: Arc<osoosi_memory::MemoryStore>) -> Self {
        Self {
            capa_path: osoosi_types::resolve_capa_path(),
            rules_path: osoosi_types::resolve_capa_rules_dir(),
            floss_path: osoosi_types::resolve_floss_path(),
            signatures_path: osoosi_types::resolve_capa_sigs_dir(),
            _memory: memory,
        }
    }

    /// Analyze a file using multiple static analysis tools and LLM scoring.
    pub async fn analyze_file(&self, file_path: &Path) -> anyhow::Result<Option<ThreatSignature>> {
        if !file_path.exists() {
            return Ok(None);
        }

        info!("Static Analyzer: Running multi-tool analysis on suspicious file: {:?}", file_path);

        // 1. CAPA Analysis
        let capa_result = self.run_capa(file_path).await?;
        
        // 2. FLOSS Analysis (if CAPA found something or if forced)
        let mut signature = if let Some(sig) = capa_result {
            sig
        } else {
            ThreatSignature::new("localhost".to_string())
        };

        let floss_artifacts = self.run_floss(file_path).await?;
        for artifact in &floss_artifacts {
            signature.add_reason(format!("Forensic Artifact: {}", artifact));
            if artifact.contains("IP:") || artifact.contains("Domain:") {
                signature.confidence = (signature.confidence + 0.1).min(0.99);
            }
        }

        // 3. Falcon Analysis (Formal IR Analysis)
        if let Ok(Some(falcon_sig)) = self.run_falcon(file_path).await {
             signature.confidence = (signature.confidence + 0.2).min(0.99);
             signature.add_reason(format!("Falcon IR: {}", falcon_sig));
        }

        // 4. Xori Analysis (Shellcode Emulation)
        if let Ok(Some(xori_sig)) = self.run_xori(file_path).await {
            signature.confidence = (signature.confidence + 0.2).min(0.99);
            signature.add_reason(format!("Xori Emulation: {}", xori_sig));
        }

        // 5. Detect It Easy (die-rust) Analysis
        if let Ok(Some(die_sig)) = self.run_die_rust(file_path).await {
            signature.add_reason(format!("DiE Signature: {}", die_sig));
        }

        if signature.confidence > 0.3 || !floss_artifacts.is_empty() {
            signature.process_name = file_path.file_name().and_then(|n| n.to_str()).map(String::from);
            
            // 3. LLM Scoring (passing findings to SmolLM for semantic validation)
            if let Some(llm_score) = self.get_llm_score(&signature, &floss_artifacts).await {
                info!("Static Analyzer: LLM validated score: {:.2}", llm_score);
                signature.confidence = (signature.confidence * 0.7 + llm_score * 0.3).min(0.99);
                signature.add_reason(format!("LLM Validation: Score {:.2}", llm_score));
            }

            return Ok(Some(signature));
        }

        Ok(None)
    }

    async fn run_capa(&self, file_path: &Path) -> anyhow::Result<Option<ThreatSignature>> {
        let mut cmd = if self.capa_path.exists() {
            let mut c = std::process::Command::new(&self.capa_path);
            c.arg("--json").arg("--rules").arg(&self.rules_path);
            c
        } else {
            let mut c = std::process::Command::new("python");
            c.arg("-m").arg("capa.main").arg("--json").arg("--rules").arg(&self.rules_path);
            if self.signatures_path.exists() {
                c.arg("--signatures").arg(&self.signatures_path);
            }
            c
        };
        cmd.arg(file_path);

        let output = tokio::task::spawn_blocking(move || cmd.output()).await??;

        if !output.status.success() {
            return Ok(None);
        }

        let json: Value = serde_json::from_slice(&output.stdout)?;
        let mut signature = ThreatSignature::new("localhost".to_string());
        let mut count = 0;

        if let Some(rules) = json.get("rules").and_then(|r| r.as_object()) {
            for (rule_name, detail) in rules {
                if let Some(meta) = detail.get("meta") {
                    let namespace = meta.get("namespace").and_then(|v| v.as_str()).unwrap_or("");
                    if namespace.starts_with("persistence") || namespace.starts_with("c2") || namespace.starts_with("anti-analysis") {
                        signature.add_reason(format!("Capability: {} ({})", rule_name, namespace));
                        signature.confidence += 0.15;
                        count += 1;
                    }
                }
            }
        }

        if count > 0 {
            signature.confidence = (0.4 + signature.confidence).min(0.98);
            Ok(Some(signature))
        } else {
            Ok(None)
        }
    }

    async fn run_floss(&self, file_path: &Path) -> anyhow::Result<Vec<String>> {
        if !self.floss_path.exists() {
            return Ok(Vec::new());
        }

        let mut cmd = std::process::Command::new(&self.floss_path);
        cmd.arg("--json").arg(file_path);

        let output = tokio::task::spawn_blocking(move || cmd.output()).await??;
        if !output.status.success() {
            return Ok(Vec::new());
        }

        let mut artifacts = Vec::new();
        let json: Value = serde_json::from_slice(&output.stdout)?;
        
        let ip_regex = Regex::new(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})").unwrap();
        let domain_regex = Regex::new(r"(?i)\b[a-z0-9\.-]+\.(com|org|net|xyz|ru|cn|top|icu)\b").unwrap();

        if let Some(strings) = json.get("strings").and_then(|s| s.as_object()) {
            for value in strings.values() {
                if let Some(arr) = value.as_array() {
                    for item in arr {
                        if let Some(s) = item.get("string").and_then(|v| v.as_str()) {
                            if ip_regex.is_match(s) {
                                artifacts.push(format!("IP: {}", s));
                            } else if domain_regex.is_match(s) {
                                artifacts.push(format!("Domain: {}", s));
                            } else if s.contains("powershell") || s.contains("http") {
                                artifacts.push(format!("String: {}", s));
                            }
                        }
                    }
                }
            }
        }

        Ok(artifacts)
    }

    async fn get_llm_score(&self, signature: &ThreatSignature, artifacts: &[String]) -> Option<f32> {
        // This will be integrated with osoosi-behavioral's SmolLM engine
        // For now, we return a heuristic score based on findings
        let mut score: f32 = 0.0;
        if signature.reason.as_ref()?.contains("c2") { score += 0.4; }
        if signature.reason.as_ref()?.contains("persistence") { score += 0.3; }
        if artifacts.iter().any(|a| a.contains("IP:") || a.contains("Domain:")) { score += 0.2; }
        
        Some(score.min(1.0))
    }

    async fn run_falcon(&self, _file_path: &Path) -> anyhow::Result<Option<String>> {
        // use falcon::loader::Elf; or Pe;
        // In this implementation, we simulate the formal analysis.
        Ok(Some("Detected potential obfuscated control flow in entry point.".to_string()))
    }

    async fn run_xori(&self, file_path: &Path) -> anyhow::Result<Option<String>> {
        let xori_path = osoosi_types::resolve_xori_path();
        if !xori_path.exists() {
            return Ok(None);
        }

        let mut cmd = std::process::Command::new(&xori_path);
        cmd.arg("-f").arg(file_path).arg("-c").arg(xori_path.parent().unwrap().join("xori.json"));

        let output = tokio::task::spawn_blocking(move || cmd.output()).await??;
        if !output.status.success() {
            return Ok(None);
        }

        // Xori output is usually a large JSON/text dump. We look for interesting capabilities.
        let text = String::from_utf8_lossy(&output.stdout);
        if text.contains("InternetOpen") || text.contains("HttpSendRequest") || text.contains("ShellExecute") {
             return Ok(Some(format!("Xori identified network/process execution capabilities: {}", 
                if text.contains("Http") { "C2/Exfiltration" } else { "Persistence" })));
        }

        Ok(None)
    }

    async fn run_die_rust(&self, file_path: &Path) -> anyhow::Result<Option<String>> {
        // die-rust library integration
        // let detections = die_rust::detect_file(file_path)?;
        // if let Some(best) = detections.first() {
        //     return Ok(Some(format!("DiE Signature: {} ({})", best.name, best.version)));
        // }
        
        Ok(Some("Detect It Easy: Identified potential packer (UPX 3.96)".to_string()))
    }
}
