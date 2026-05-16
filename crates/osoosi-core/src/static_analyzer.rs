//! Static Analyzer for OpenỌ̀ṣọ́ọ̀sì
//!
//! Integrates multiple tools (CAPA, FLOSS) and LLM-based reasoning to identify
//! suspicious behaviors and hidden artifacts in binary files.

use osoosi_types::{ThreatSignature, ResponseAction, ActionState, Priority, ResourceCategory};
use regex::Regex;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info};
use sha2::{Sha256, Digest};

pub struct StaticAnalyzer {
    /// Executor for running tools (Direct or OpenShell)
    _executor: Arc<dyn osoosi_types::SecuredExecutor>,
    /// Malware scanner for feedback loops
    malware_scanner: Arc<osoosi_model::MalwareScanner>,
    /// In-memory session cache for static analysis results (SHA256 -> ThreatSignature)
    analysis_cache: dashmap::DashMap<String, Option<ThreatSignature>>,
    /// Native Yara-X engine
    yara_engine: Arc<yara_x::Rules>,
    /// Adaptive concurrency controller
    adaptive: Arc<crate::adaptive::TelemetryController>,
}

impl StaticAnalyzer {
    pub fn new(
        _memory: Arc<osoosi_memory::MemoryStore>,
        executor: Arc<dyn osoosi_types::SecuredExecutor>,
        malware_scanner: Arc<osoosi_model::MalwareScanner>,
        yara_rules: Arc<yara_x::Rules>,
        adaptive: Arc<crate::adaptive::TelemetryController>,
    ) -> Self {
        Self {
            _executor: executor,
            malware_scanner,
            analysis_cache: dashmap::DashMap::new(),
            yara_engine: yara_rules,
            adaptive,
        }
    }

    /// Analyze a file using multiple static analysis tools and LLM scoring.
    pub async fn analyze_file(&self, file_path: &Path) -> anyhow::Result<Option<ThreatSignature>> {
        if !file_path.exists() {
            return Ok(None);
        }

        // Limit to 64MB to avoid memory/CPU exhaustion on huge binaries
        if let Ok(meta) = file_path.metadata() {
            if meta.len() > 64 * 1024 * 1024 {
                debug!("Static Analyzer: skipping huge file {:?}", file_path);
                return Ok(None);
            }
        }

        if Self::is_oshoosi_managed_tool(file_path) {
            debug!(
                "Static Analyzer: skipping threat emission for Oshoosi-managed tool {:?}",
                file_path
            );
            return Ok(None);
        }

        // Calculate hash first for caching
        let path_buf = file_path.to_path_buf();
        let hash = tokio::task::spawn_blocking(move || {
            Self::calculate_sha256_sync(&path_buf).unwrap_or_else(|_| "unknown".to_string())
        }).await.unwrap_or_else(|_| "unknown".to_string());

        if hash != "unknown" {
            if let Some(cached) = self.analysis_cache.get(&hash) {
                return Ok(cached.clone());
            }
        }

        info!(
            "Static Analyzer: Running multi-tool analysis on suspicious file: {:?}",
            file_path
        );

        // 1. Run Native Yara-X (Zero-Process replacement for external scanners)
        let yara_res = self.run_yara_x(file_path).await?;
        
        // 2. Run Composition Analysis (Nabla-style Heuristic Scoring)
        let composition = self.run_composition_analysis(file_path).await?;

        // 3. Extract Strings and find IOCs natively
        let artifacts = self.run_native_strings(file_path).await?;

        // Combine findings into a ThreatSignature
        if let Some(yara_sig) = yara_res {
             let mut signature = ThreatSignature {
                id: format!("STATIC-{}", hash.chars().take(8).collect::<String>()),
                hash_blake3: Some(hash.clone()),
                process_name: file_path.file_name().map(|n| n.to_string_lossy().to_string()),
                confidence: 0.8,
                reason: Some(format!("YARA-X Match: {}", yara_sig)),
                detector_count: 1,
                detected_at: chrono::Utc::now(),
                source_node: "local".to_string(),
                recommended_action: ResponseAction::Isolate,
                action_state: ActionState::Pending,
                ..Default::default()
            };

            if let Some(comp) = composition {
                if comp.composition_score > 0.0 {
                    signature.confidence = (signature.confidence + (comp.composition_score * 0.2)).min(1.0);
                    signature.reason = Some(format!("{} | NablaScore: {:.2} | SuspiciousDeps: {:?}", signature.reason.unwrap(), comp.composition_score, comp.suspicious_dependencies));
                }
            }

            if !artifacts.is_empty() {
                signature.confidence = (signature.confidence + 0.1).min(1.0);
                signature.reason = Some(format!("{} | Artifacts: {:?}", signature.reason.unwrap(), artifacts));
            }

            self.analysis_cache.insert(hash, Some(signature.clone()));
            return Ok(Some(signature));
        }

        if let Some(comp) = composition {
            if comp.composition_score >= 0.5 {
                let signature = ThreatSignature {
                    id: format!("COMP-{}", hash.chars().take(8).collect::<String>()),
                    hash_blake3: Some(hash.clone()),
                    process_name: file_path.file_name().map(|n| n.to_string_lossy().to_string()),
                    confidence: comp.composition_score.min(1.0) as f32,
                    reason: Some(format!("Composition Analysis (Nabla): Suspicious binary structure detected. Score: {:.2} | Dependencies: {:?}", comp.composition_score, comp.suspicious_dependencies)),
                    detector_count: 1,
                    detected_at: chrono::Utc::now(),
                    source_node: "local".to_string(),
                    recommended_action: ResponseAction::Isolate,
                    action_state: ActionState::Pending,
                    ..Default::default()
                };
                self.analysis_cache.insert(hash, Some(signature.clone()));
                return Ok(Some(signature));
            }
        }

        Ok(None)
    }

    fn is_oshoosi_managed_tool(path: &Path) -> bool {
        let p = path.to_string_lossy().to_lowercase();
        p.contains("\\oshoosiclaw\\") || p.contains("/oshoosiclaw/")
    }

    fn calculate_sha256_sync(path: &Path) -> anyhow::Result<String> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 { break; }
            hasher.update(&buffer[..n]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }

    async fn run_yara_x(&self, file_path: &Path) -> anyhow::Result<Option<String>> {
        let bytes = std::fs::read(file_path)?;
        let yara_engine = self.yara_engine.clone();
        let malware_scanner = self.malware_scanner.clone();
        let path = file_path.to_path_buf();

        let yara_res = self.adaptive.run_adaptive(ResourceCategory::AI, Priority::High, async move {
            let mut scanner = yara_x::Scanner::new(&yara_engine);
            if let Ok(results) = scanner.scan(&bytes) {
                results.matching_rules().next().map(|r| r.identifier().to_string())
            } else {
                None
            }
        }).await.ok().flatten();

        if let Some(sig_name) = yara_res {
            // FEEDBACK LOOP: Report the malicious sample to MalConv for fine-tuning
            let _ = malware_scanner.report_label_to_malconv(&path, 1.0).await;
            return Ok(Some(sig_name));
        }
        
        Ok(None)
    }

    pub fn calculate_entropy(&self, path: &Path) -> anyhow::Result<f32> {
        let bytes = std::fs::read(path)?;
        if bytes.is_empty() { return Ok(0.0); }
        let mut counts = [0usize; 256];
        for &b in &bytes { counts[b as usize] += 1; }
        let mut entropy = 0.0f32;
        let len = bytes.len() as f32;
        for count in counts {
            if count > 0 {
                let p = count as f32 / len;
                entropy -= p * p.log2();
            }
        }
        Ok(entropy)
    }

    async fn run_native_strings(&self, file_path: &Path) -> anyhow::Result<Vec<String>> {
        let bytes = std::fs::read(file_path)?;
        
        self.adaptive.run_adaptive(ResourceCategory::IO, Priority::Normal, async move {
            let mut artifacts = Vec::new();
            // Simple native string extraction (basic replacement for MalChela/FLOSS)
            let min_len = 4;
            let mut current_string = Vec::new();
            let mut strings = Vec::new();

            for &b in &bytes {
                if b.is_ascii_graphic() || b == b' ' {
                    current_string.push(b);
                } else {
                    if current_string.len() >= min_len {
                        if let Ok(s) = String::from_utf8(current_string.clone()) {
                            strings.push(s);
                        }
                    }
                    current_string.clear();
                }
            }

            let ip_regex = Regex::new(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})").unwrap();
            let domain_regex = Regex::new(r"(?i)\b[a-z0-9\.-]+\.(com|org|net|xyz|ru|cn|top|icu)\b").unwrap();

            let known_good_domains: &[&str] = &[
                "ocsp.", "crl.", "microsoft.com", "github.com", "digicert.com", "sectigo.com"
            ];

            for s in strings {
                if ip_regex.is_match(&s) {
                    artifacts.push(format!("IP: {}", s));
                } else if domain_regex.is_match(&s) {
                    let is_known_good = known_good_domains.iter().any(|&good| s.to_lowercase().contains(good));
                    if !is_known_good {
                        artifacts.push(format!("Domain: {}", s));
                    }
                } else if s.to_lowercase().contains("powershell") || s.contains("http") {
                    if s.len() < 100 {
                        artifacts.push(format!("String: {}", s));
                    }
                }
            }

            Ok(artifacts)
        }).await?
    }

    async fn run_composition_analysis(&self, file_path: &Path) -> anyhow::Result<Option<crate::pe_inspector::InspectionFindings>> {
        #[cfg(target_os = "windows")]
        {
            let path = file_path.to_path_buf();
            let result = self.adaptive.run_adaptive(ResourceCategory::IO, Priority::Normal, async move {
                if let Ok(findings) = crate::pe_inspector::inspect_file(&path) {
                    Some(findings)
                } else {
                    None
                }
            }).await;
            match result {
                Ok(opt) => Ok(opt),
                Err(_) => Ok(None),
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok(None)
        }
    }
}
