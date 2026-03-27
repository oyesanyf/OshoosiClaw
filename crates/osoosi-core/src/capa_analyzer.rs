//! CAPA Analyzer for OpenỌ̀ṣọ́ọ̀sì
//! 
//! Integrates the Mandiant CAPA tool (Capability Analysis) to identify suspicious 
//! behaviors in unknown/non-NSRL executable files.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn, error, debug};
use osoosi_types::{ThreatSignature, ResponseAction};
use serde_json::Value;
use regex::Regex;

pub struct CapaAnalyzer {
    /// Path to the 'capa' executable or the Python script
    _capa_path: PathBuf,
    /// Path to the rules directory (defaults to the rules folder in the cloned repo)
    rules_path: PathBuf,
    /// Path to the 'floss' executable
    floss_path: PathBuf,
    /// Memory: For caching analysis results (avoid re-running)
    _memory: Arc<osoosi_memory::MemoryStore>,
}

impl CapaAnalyzer {
    pub fn new(memory: Arc<osoosi_memory::MemoryStore>) -> Self {
        // Try to find CAPA in common locations if not provided
        // The user mentioned cloning it to D:\harfile\capa
        let capa_root = osoosi_types::resolve_tools_dir().join("capa");
        let rules_path = capa_root.join("rules");
        let floss_path = osoosi_types::resolve_tool_path("floss", "floss.exe");

        Self {
            _capa_path: capa_root,
            rules_path,
            floss_path,
            _memory: memory,
        }
    }

    /// Analyze a file using CAPA to detect its capabilities.
    pub async fn analyze_file(&self, file_path: &Path) -> anyhow::Result<Option<ThreatSignature>> {
        if !file_path.exists() {
            return Ok(None);
        }

        // 1. Check if we've already analyzed this file (Cache Check)
        // (Implementation for caching results in DB could happen here)

        info!("CAPA Analyzer: Running capability analysis on suspicious file: {:?}", file_path);

        // 2. Prepare the command
        // We will run this via python if the user has a clone, or direct exe if available
        let mut cmd = std::process::Command::new("python");
        cmd.arg("-m").arg("capa"); // Use the capa module
        cmd.arg("--json"); // Output as JSON for parsing
        cmd.arg("--rules").arg(&self.rules_path); // Use the custom rules folder
        cmd.arg(file_path);

        // Use a 30s timeout to prevent hanging on large/packed binaries
        let output = tokio::task::spawn_blocking(move || {
            cmd.output()
        }).await??;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("is packed") {
                warn!("CAPA: Skipping packed file {:?}. Use a sandbox for dynamic analysis.", file_path);
            } else {
                error!("CAPA execution failed for {:?}: {}", file_path, stderr);
            }
            return Ok(None);
        }

        // 3. Parse JSON Results
        let json: Value = serde_json::from_slice(&output.stdout)?;
        let mut signature = ThreatSignature::new("localhost".to_string());
        let mut suspicious_capabilities = Vec::new();
        let mut confidence_boost = 0.0;

        // CAPA JSON structure differs by version, but generally has a 'rules' map
        if let Some(rules) = json.get("rules").and_then(|r| r.as_object()) {
            for (rule_name, detail) in rules {
                // Focus on high-risk namespaces: 'persistence', 'communication/http', 'anti-analysis', 'malware-config' 
                if let Some(meta) = detail.get("meta") {
                    let namespace = meta.get("namespace").and_then(|v| v.as_str()).unwrap_or("");
                    
                    if namespace.starts_with("persistence") || 
                       namespace.starts_with("c2") || 
                       namespace.starts_with("anti-analysis") || 
                       namespace.starts_with("collection/credentials") ||
                       namespace.starts_with("impact") {
                        
                        suspicious_capabilities.push(format!("{} ({})", rule_name, namespace));
                        confidence_boost += 0.15;
                    }
                }
            }
        }

        if !suspicious_capabilities.is_empty() {
            let score: f32 = 0.5f32 + (confidence_boost as f32);
            signature.confidence = score.min(0.98f32);
            signature.process_name = file_path.file_name().and_then(|n| n.to_str()).map(String::from);
            signature.reason = Some(format!("CAPA Analysis: Identified {} critical capabilities.", suspicious_capabilities.len()));
            signature.recommended_action = ResponseAction::Alert;
            
            // Add the detailed findings as additional context
            for cap in suspicious_capabilities {
                signature.add_reason(format!("Capability: {}", cap));
            }

            // 4. Run FLOSS (Expert Deobfuscator) to extract hidden strings
            if self.floss_path.exists() {
                info!("FLOSS Analyzer: Extracting de-obfuscated strings from malware: {:?}", file_path);
                let mut f_cmd = std::process::Command::new(&self.floss_path);
                f_cmd.arg("--json").arg(file_path);

                if let Ok(f_output) = f_cmd.output() {
                    if f_output.status.success() {
                        if let Ok(f_json) = serde_json::from_slice::<Value>(&f_output.stdout) {
                            // Extract de-obfuscated strings (stack, tight, decoded)
                            let mut forensic_strings = Vec::new();
                            if let Some(types) = f_json.get("strings").and_then(|s| s.as_object()) {
                                for (key, value) in types {
                                    if key == "stack_strings" || key == "tight_strings" || key == "decoded_strings" {
                                        if let Some(arr) = value.as_array() {
                                            for item in arr {
                                                if let Some(s) = item.get("string").and_then(|v| v.as_str()) {
                                                    if s.len() > 3 {
                                                        forensic_strings.push(s.to_string());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // Look for suspicious signals in recovered strings (IPs, Domains, File paths)
                            let ip_regex = Regex::new(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})").unwrap();
                            let domain_regex = Regex::new(r"(?i)\b[a-z0-9\.-]+\.(com|org|net|xyz|ru|cn|top|icu)\b").unwrap();
                            
                            for s in &forensic_strings {
                                if ip_regex.is_match(s) {
                                    signature.add_reason(format!("FLOSS: Hidden IP/Endpoint found: {}", s.trim()));
                                    signature.confidence = (signature.confidence + 0.1).min(0.99);
                                }
                                if domain_regex.is_match(s) {
                                    signature.add_reason(format!("FLOSS: Hidden C2 Domain found: {}", s.trim()));
                                    signature.confidence = (signature.confidence + 0.1).min(0.99);
                                }
                                if s.contains("http") || s.contains("powershell") || s.contains(".dll") {
                                    signature.add_reason(format!("FLOSS: De-obfuscated Artifact: {}", s.chars().take(100).collect::<String>()));
                                }
                            }
                        }
                    }
                }
            }

            return Ok(Some(signature));
        }

        debug!("CAPA Analysis: No suspicious library-level capabilities detected for {:?}", file_path);
        Ok(None)
    }
}
