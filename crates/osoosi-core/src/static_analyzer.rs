//! Static Analyzer for OpenỌ̀ṣọ́ọ̀sì
//!
//! Integrates multiple tools (CAPA, FLOSS) and LLM-based reasoning to identify
//! suspicious behaviors and hidden artifacts in binary files.

use osoosi_types::ThreatSignature;
use regex::Regex;
use serde_json::Value;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info};

pub struct StaticAnalyzer {
    /// Path to the 'capa' executable
    capa_path: PathBuf,
    /// Path to the rules directory
    rules_path: PathBuf,
    /// Path to the 'floss' executable
    floss_path: PathBuf,
    /// Path to the signatures directory
    signatures_path: PathBuf,
    /// Executor for running tools (Direct or OpenShell)
    executor: Arc<dyn osoosi_types::SecuredExecutor>,
    /// Malware scanner for feedback loops
    malware_scanner: Arc<osoosi_model::MalwareScanner>,
    /// In-memory session cache for static analysis results (SHA256 -> ThreatSignature)
    analysis_cache: dashmap::DashMap<String, Option<ThreatSignature>>,
}

impl StaticAnalyzer {
    pub fn new(
        _memory: Arc<osoosi_memory::MemoryStore>,
        executor: Arc<dyn osoosi_types::SecuredExecutor>,
        malware_scanner: Arc<osoosi_model::MalwareScanner>,
    ) -> Self {
        Self {
            capa_path: osoosi_types::resolve_capa_path(),
            rules_path: osoosi_types::resolve_capa_rules_dir(),
            floss_path: osoosi_types::resolve_floss_path(),
            signatures_path: osoosi_types::resolve_capa_sigs_dir(),
            executor,
            malware_scanner,
            analysis_cache: dashmap::DashMap::new(),
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

        // 0. Calculate Shannon Entropy
        let path_buf_ent = file_path.to_path_buf();
        let entropy = tokio::task::spawn_blocking(move || {
            Self::calculate_entropy_sync(&path_buf_ent).unwrap_or(0.0)
        }).await.unwrap_or(0.0);

        debug!(
            "Static Analyzer: File {:?} entropy: {:.2}",
            file_path, entropy
        );

        // 1-5. Parallel Analysis Layer (CAPA, FLOSS, Falcon, Xori, DiE)
        // We use a semaphore to limit concurrent heavy tool executions globally
        static TOOL_SEMAPHORE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
        let _permit = TOOL_SEMAPHORE.acquire().await.unwrap();

        let (capa_res, floss_res, falcon_res, xori_res, die_res) = tokio::join!(
            self.run_capa(file_path),
            self.run_floss(file_path),
            self.run_falcon(file_path),
            self.run_xori(file_path),
            self.run_die_rust(file_path)
        );

        let capa_result = capa_res?;
        let floss_artifacts = floss_res?;

        let mut signature = if let Some(sig) = capa_result {
            sig
        } else {
            ThreatSignature::new("localhost".to_string())
        };

        for artifact in &floss_artifacts {
            signature.add_reason(format!("Forensic Artifact: {}", artifact));
            if artifact.contains("IP:") || artifact.contains("Domain:") {
                signature.confidence = (signature.confidence + 0.1).min(0.99);
            }
        }

        if let Ok(Some(falcon_sig)) = falcon_res {
            signature.confidence = (signature.confidence + 0.2).min(0.99);
            signature.add_reason(format!("Falcon IR: {}", falcon_sig));
        }

        if let Ok(Some(xori_sig)) = xori_res {
            signature.confidence = (signature.confidence + 0.2).min(0.99);
            signature.add_reason(format!("Xori Emulation: {}", xori_sig));
        }

        if let Ok(Some(die_sig)) = die_res {
            signature.add_reason(format!("DiE Signature: {}", die_sig));
        }

        if signature.confidence > 0.3 || !floss_artifacts.is_empty() || entropy > 7.2 {
            signature.process_name = file_path
                .file_name()
                .and_then(|n| n.to_str())
                .map(String::from);

            // 6. Entropy Adjustment
            if entropy > 7.5 {
                signature.add_reason(format!(
                    "High Entropy ({:.2}): Binary likely packed or encrypted",
                    entropy
                ));
                signature.confidence = (signature.confidence + 0.25).min(0.99);
            } else if entropy < 6.5 {
                signature.add_reason(format!(
                    "Low Entropy ({:.2}): Binary likely not obfuscated",
                    entropy
                ));
                // Suppress packer/UPX findings when entropy is low — low entropy is
                // strong counter-evidence against packing (packed files are high entropy)
                let had_packer_reason = signature.reason.as_ref()
                    .map(|r| r.to_lowercase().contains("packer") || r.to_lowercase().contains("upx"))
                    .unwrap_or(false);
                if had_packer_reason {
                    // Halve confidence: low entropy + packer flag = likely false positive
                    signature.confidence *= 0.5;
                    signature.add_reason(
                        "[Low entropy discounts packer flag — packed binaries have high entropy]".to_string()
                    );
                } else {
                    signature.confidence *= 0.8; // General suppression for low-entropy binaries
                }
            }

            // 7. ClamAV Analysis (Voting Integration)
            if let Ok(Some(clam_sig)) = self.run_clamav(file_path).await {
                signature.confidence = (signature.confidence + 0.5).min(1.0);
                signature.add_reason(format!("ClamAV Detection: {}", clam_sig));
                info!(
                    "Static Analyzer: ClamAV voted MALICIOUS for {:?}",
                    file_path
                );
            } else {
                // If ClamAV says it's clean, slightly reduce confidence (unless it's an exploit)
                signature.confidence *= 0.9;
                debug!("Static Analyzer: ClamAV voted CLEAN for {:?}", file_path);
            }

            // 8. LLM Scoring (passing findings to SmolLM for semantic validation)
            if let Some(llm_score) = self.get_llm_score(&signature, &floss_artifacts).await {
                info!("Static Analyzer: LLM validated score: {:.2}", llm_score);
                signature.confidence = (signature.confidence * 0.7 + llm_score * 0.3).min(0.99);
                signature.add_reason(format!("LLM Validation: Score {:.2}", llm_score));
            }

            if hash != "unknown" {
                self.analysis_cache.insert(hash, Some(signature.clone()));
            }
            return Ok(Some(signature));
        }

        if hash != "unknown" {
            self.analysis_cache.insert(hash, None);
        }
        Ok(None)
    }

    fn calculate_sha256_sync(path: &Path) -> anyhow::Result<String> {
        use sha2::{Digest, Sha256};
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 65536]; // 64KB buffer
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }

    async fn run_clamav(&self, file_path: &Path) -> anyhow::Result<Option<String>> {
        let clam_path = osoosi_types::resolve_clamscan_path();
        if !clam_path.exists() {
            return Ok(None); // ClamAV not installed or not in PATH
        }

        let mut cmd = std::process::Command::new(&clam_path);
        cmd.arg("--no-summary").arg(file_path);

        let output = self.executor.execute(cmd).await?;

        // clamscan returns 0 if clean, 1 if infected, 2 if error
        if output.status.code() == Some(1) {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Example output: /path/to/file: Win.Trojan.Agent-12345 FOUND
            if let Some(detection) = stdout.lines().find(|l| l.contains("FOUND")) {
                let sig_name = detection
                    .split(':')
                    .last()
                    .unwrap_or("Unknown Malware")
                    .replace("FOUND", "")
                    .trim()
                    .to_string();
                
                // FEEDBACK LOOP: Report the malicious sample to MalConv for fine-tuning
                let _ = self.malware_scanner.report_label_to_malconv(file_path, 1.0).await;

                return Ok(Some(sig_name));
            }
            
            let _ = self.malware_scanner.report_label_to_malconv(file_path, 1.0).await;
            return Ok(Some("Generic Malware Signature".to_string()));
        }

        Ok(None)
    }

    fn is_oshoosi_managed_tool(file_path: &Path) -> bool {
        if std::env::var("OSOOSI_ANALYZE_OWN_TOOLS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("on"))
            .unwrap_or(false)
        {
            return false;
        }

        let Ok(path) = file_path.canonicalize() else {
            return false;
        };
        let tools_dir = osoosi_types::resolve_tools_dir()
            .canonicalize()
            .unwrap_or_else(|_| osoosi_types::resolve_tools_dir());
        let project_target = osoosi_types::resolve_tools_dir()
            .parent()
            .map(|p| p.join("target"))
            .and_then(|p| p.canonicalize().ok());

        path.starts_with(&tools_dir)
            || project_target
                .as_ref()
                .map(|target| path.starts_with(target))
                .unwrap_or(false)
    }

    async fn run_capa(&self, file_path: &Path) -> anyhow::Result<Option<ThreatSignature>> {
        let mut cmd = if self.capa_path.exists() {
            let mut c = std::process::Command::new(&self.capa_path);
            c.arg("--json").arg("--rules").arg(&self.rules_path);
            c
        } else {
            let mut c = std::process::Command::new("python");
            c.arg("-m")
                .arg("capa.main")
                .arg("--json")
                .arg("--rules")
                .arg(&self.rules_path);
            if self.signatures_path.exists() {
                c.arg("--signatures").arg(&self.signatures_path);
            }
            c
        };
        cmd.arg(file_path);

        let output = self.executor.execute(cmd).await?;

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
                    if namespace.starts_with("persistence")
                        || namespace.starts_with("c2")
                        || namespace.starts_with("anti-analysis")
                    {
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

        let output = self.executor.execute(cmd).await?;
        if !output.status.success() {
            return Ok(Vec::new());
        }

        let mut artifacts = Vec::new();
        let json: Value = serde_json::from_slice(&output.stdout)?;

        let ip_regex = Regex::new(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})").unwrap();
        let domain_regex =
            Regex::new(r"(?i)\b[a-z0-9\.-]+\.(com|org|net|xyz|ru|cn|top|icu)\b").unwrap();

        // Known-good infrastructure domains: OCSP, CRL, CDNs used by Windows certificate validation.
        // Seeing these does NOT indicate malice — it indicates normal TLS certificate checking.
        let known_good_domains: &[&str] = &[
            "ocsp.sectigo.com", "ocsp.comodoca.com", "ocsp.digicert.com",
            "crl.sectigo.com", "crl.comodoca.com", "crl.microsoft.com",
            "ocsp.usertrust.com", "crt.sectigo.com", "ocsp2.globalsign.com",
            "ocsp.globalsign.com", "crl.globalsign.com",
            // Windows Update / telemetry (not malicious)
            "windowsupdate.microsoft.com", "update.microsoft.com",
            "ctldl.windowsupdate.com", "www.microsoft.com",
            // GitHub CDN (git.exe, dev tools)
            "github.com", "objects.githubusercontent.com", "raw.githubusercontent.com",
            "api.github.com",
        ];

        if let Some(strings) = json.get("strings").and_then(|s| s.as_object()) {
            for value in strings.values() {
                if let Some(arr) = value.as_array() {
                    for item in arr {
                        if let Some(s) = item.get("string").and_then(|v| v.as_str()) {
                            if ip_regex.is_match(s) {
                                artifacts.push(format!("IP: {}", s));
                            } else if domain_regex.is_match(s) {
                                // Skip known-good domains — they reduce noise, not raise it
                                let is_known_good = known_good_domains.iter()
                                    .any(|&good| s.to_lowercase().contains(good));
                                if !is_known_good {
                                    artifacts.push(format!("Domain: {}", s));
                                }
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

    async fn get_llm_score(
        &self,
        signature: &ThreatSignature,
        artifacts: &[String],
    ) -> Option<f32> {
        // This will be integrated with osoosi-behavioral's SmolLM engine
        // For now, we return a heuristic score based on findings
        let mut score: f32 = 0.0;
        if signature.reason.as_ref()?.contains("c2") {
            score += 0.4;
        }
        if signature.reason.as_ref()?.contains("persistence") {
            score += 0.3;
        }
        if artifacts
            .iter()
            .any(|a| a.contains("IP:") || a.contains("Domain:"))
        {
            score += 0.2;
        }

        Some(score.min(1.0))
    }

    async fn run_falcon(&self, _file_path: &Path) -> anyhow::Result<Option<String>> {
        // TODO: Integrate falcon-rs library for formal binary analysis
        // When implemented, this will perform IL lifting and data-flow analysis
        // to detect obfuscated control flow, shellcode, and unpacking stubs.
        Ok(None) // Return None until real integration is complete (prevents false positives)
    }

    async fn run_xori(&self, file_path: &Path) -> anyhow::Result<Option<String>> {
        let xori_path = osoosi_types::resolve_xori_path();
        if !xori_path.exists() {
            return Ok(None);
        }

        let mut cmd = std::process::Command::new(&xori_path);
        cmd.arg("-f")
            .arg(file_path)
            .arg("-c")
            .arg(xori_path.parent().unwrap().join("xori.json"));

        let output = self.executor.execute(cmd).await?;
        if !output.status.success() {
            return Ok(None);
        }

        // Xori output is usually a large JSON/text dump. We look for interesting capabilities.
        let text = String::from_utf8_lossy(&output.stdout);
        if text.contains("InternetOpen")
            || text.contains("HttpSendRequest")
            || text.contains("ShellExecute")
        {
            return Ok(Some(format!(
                "Xori identified network/process execution capabilities: {}",
                if text.contains("Http") {
                    "C2/Exfiltration"
                } else {
                    "Persistence"
                }
            )));
        }

        Ok(None)
    }

    async fn run_die_rust(&self, _file_path: &Path) -> anyhow::Result<Option<String>> {
        // TODO: Integrate die-rust library when stable API is available
        // When implemented:
        //   let detections = die_rust::detect_file(file_path)?;
        //   if let Some(best) = detections.first() {
        //       return Ok(Some(format!("DiE Signature: {} ({})", best.name, best.version)));
        //   }
        Ok(None) // Return None until real integration is complete (prevents false positives)
    }

    /// Calculate Shannon Entropy of a file to detect packing/encryption.
    pub fn calculate_entropy(&self, path: &Path) -> anyhow::Result<f32> {
        Self::calculate_entropy_sync(path)
    }

    /// Calculate Shannon Entropy of a file to detect packing/encryption (Synchronous helper).
    pub fn calculate_entropy_sync(path: &Path) -> anyhow::Result<f32> {
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        if buffer.is_empty() {
            return Ok(0.0);
        }

        let mut frequencies = [0usize; 256];
        for &byte in &buffer {
            frequencies[byte as usize] += 1;
        }

        let mut entropy = 0.0;
        let len = buffer.len() as f32;
        for &count in &frequencies {
            if count > 0 {
                let p = count as f32 / len;
                entropy -= p * p.log2();
            }
        }
        Ok(entropy)
    }
}
