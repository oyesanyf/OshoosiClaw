pub use crate::agentic_voter::AgenticPolicyVoter;
use crate::engine::{ThreatVoter, VoteResult};
use async_trait::async_trait;
use osoosi_audit::MerkleAuditTree;
use osoosi_dp::{DifferentialPrivacy, PrivacyConfig};
use osoosi_model::ThreatModel;
use osoosi_types::HostSecurityEvent;
use std::sync::Arc;
use tracing::{debug, warn};

/// Zero-Day Vulnerability Voter
/// Checks for known "In the Wild" exploits from Google's Zero-Day Tracker.
pub struct ZeroDayVoter {
    pub vulnerabilities: Vec<ZeroDayInfo>,
}

#[derive(serde::Deserialize, Clone, Debug)]
pub struct ZeroDayInfo {
    pub cve: String,
    pub vendor: String,
    pub product: String,
    pub description: String,
}

impl Default for ZeroDayVoter {
    fn default() -> Self {
        Self::new()
    }
}

impl ZeroDayVoter {
    pub fn new() -> Self {
        let path = std::path::Path::new("config/google_zero_days.json");
        let vulnerabilities = if path.exists() {
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    let data: serde_json::Value =
                        serde_json::from_str(&content).unwrap_or_default();
                    serde_json::from_value(data["vulnerabilities"].clone()).unwrap_or_default()
                }
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };
        Self { vulnerabilities }
    }
}

#[async_trait]
impl ThreatVoter for ZeroDayVoter {
    fn name(&self) -> String {
        "ZeroDayTracker".to_string()
    }
    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        let image = event
            .data
            .get("Image")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        let _version = event
            .data
            .get("ProductVersion")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        for vuln in &self.vulnerabilities {
            // Match vendor or product in the image path or product name metadata
            let vendor_match = image.contains(&vuln.vendor.to_lowercase());
            let product_match = image.contains(&vuln.product.to_lowercase());

            if vendor_match && product_match {
                return Some(VoteResult {
                    confidence: 0.95,
                    reason: format!(
                        "Zero-Day Match: Known 'In the Wild' exploit ({}) detected for {} {}. Description: {}",
                        vuln.cve, vuln.vendor, vuln.product, vuln.description
                    ),
                    weight: 1.0,
                });
            }
        }
        None
    }
}

/// Sandbox Attack Surface Voter
/// Ports logic from Google Project Zero's Sandbox Analysis Tools.
/// Analyzes token integrity, privileges, and AppContainer status.
pub struct SandboxSurfaceVoter;

#[async_trait]
impl ThreatVoter for SandboxSurfaceVoter {
    fn name(&self) -> String {
        "SandboxSurfaceAnalysis".to_string()
    }
    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        // Only vote on process creation (Event ID 1)
        if event.event_id != 1 {
            return None;
        }

        let pid = event
            .data
            .get("ProcessId")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        if pid == 0 {
            return None;
        }

        if let Ok(info) = crate::sandbox_surface::analyze_process_sandbox(pid) {
            let mut risk_score: f32 = 0.0;
            let mut reasons = Vec::new();

            // Flag high-risk privileges
            for priv_name in &info.privileges {
                risk_score += 0.3;
                reasons.push(format!("Has high-risk privilege: {}", priv_name));
            }

            // Flag suspicious integrity levels for non-system processes
            if info.integrity_level == "High" || info.integrity_level == "System" {
                let image = event
                    .data
                    .get("Image")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if !image.to_lowercase().contains("windows\\system32") {
                    risk_score += 0.4;
                    reasons.push(
                        "Running with High/System integrity from non-standard path".to_string(),
                    );
                }
            }

            if risk_score > 0.0 {
                return Some(VoteResult {
                    confidence: risk_score.min(0.9),
                    reason: format!(
                        "Sandbox Surface Warning: {} (Integrity: {}, AppContainer: {}). Reasons: {}",
                        if info.is_elevated { "Elevated" } else { "Non-elevated" },
                        info.integrity_level,
                        info.is_app_container,
                        reasons.join(", ")
                    ),
                    weight: 1.0,
                });
            }
        }
        None
    }
}

/// Semantic Intent Voter (Algorithm 2)
pub struct SemanticVoter {
    pub engine: crate::semantic::SemanticEngine,
}

#[async_trait]
impl ThreatVoter for SemanticVoter {
    fn name(&self) -> String {
        "SemanticIntent".to_string()
    }
    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        if let Some(cmd_line) = event.data.get("CommandLine").and_then(|c| c.as_str()) {
            let drift = self.engine.verify_intent(cmd_line);
            if drift > 0.8 {
                return Some(VoteResult {
                    confidence: drift,
                    reason: format!("Semantic drift (score {:.2}): command line intent deviates from expected process behavior", drift),
                    weight: 0.7,
                });
            }
        }
        None
    }
}

/// OTX Indicator Voter (C2/Malware hashes)
pub struct OtxVoter {
    pub indicators: Arc<std::sync::RwLock<crate::feed::OtxIndicators>>,
    pub memory: Arc<osoosi_memory::MemoryStore>,
}

#[async_trait]
impl ThreatVoter for OtxVoter {
    fn name(&self) -> String {
        "OTX-C2".to_string()
    }
    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        let guard = self.indicators.read().ok()?;
        let hit =
            crate::otx_connection::otx_match_sysmon_event_normalized(&guard, &self.memory, event);

        hit.map(|reason| VoteResult {
            confidence: crate::otx_connection::OTX_CONSENSUS_CONFIDENCE,
            reason,
            weight: crate::otx_connection::otx_consensus_weight(event),
        })
    }
}

/// LLM Reasoning Voter (The "Autonomous Cortex")
/// Uses the configured LLM (DeepSeek R1, etc.) to reason about security events.
/// Rate-limited to prevent GPU/CPU saturation from high-volume Sysmon telemetry.
pub struct GemmaVoter {
    pub analyzer: Arc<osoosi_behavioral::Gemma4Analyzer>,
    last_call: std::sync::Mutex<std::time::Instant>,
}

impl GemmaVoter {
    pub fn new(analyzer: Arc<osoosi_behavioral::Gemma4Analyzer>) -> Self {
        Self {
            analyzer,
            last_call: std::sync::Mutex::new(
                std::time::Instant::now() - std::time::Duration::from_secs(60),
            ),
        }
    }

    /// Pre-filter: skip known-safe system processes to avoid wasting LLM inference.
    pub fn is_known_safe(image_path: &str) -> bool {
        let path = image_path.to_ascii_lowercase();
        let stem = std::path::Path::new(image_path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        let trusted_path = path.contains("\\windows\\system32\\")
            || path.contains("\\windows\\syswow64\\")
            || path.contains("\\program files\\")
            || path.contains("\\program files (x86)\\")
            || path.contains("\\programdata\\chocolatey\\")
            || path.contains("\\programdata\\scoop\\")
            || path.contains("\\tools\\git\\")
            || path.contains("\\oshoosiclaw\\tools\\")
            || path.contains("\\oshoosiclaw\\target\\")
            || path.contains("/oshoosiclaw/tools/")
            || path.contains("/oshoosiclaw/target/")
            || path.contains("\\appdata\\local\\programs\\python\\");

        const TRUSTED_STEMS: &[&str] = &[
            "osoosi",
            "osoosi-cli",
            "sysmon",
            "sysmon64",
            "csrss",
            "lsass",
            "winlogon",
            "services",
            "svchost",
            "explorer",
            "taskmgr",
            "runtimebroker",
            "searchindexer",
            "conhost",
            "openconsole",
            "windowsterminal",
            "wsl",
            "wslhost",
            "wslservice",
            "sc",
            "ipconfig",
            "velociraptor",
            "velociraptor.e",
            "clibrowser",
            "wix",
            "wixnative",
            "llvm-rc",
            "lld-link",
            "rust-lld",
            "signtool",
            "rustc",
            "cargo",
            "python",
            "git",
            "chrome",
            "msedge",
            "cursor",
            "antigravity",
            "code",
            "node",
            "ollama",
            "npm",
            "powershell",
            "cmd",
        ];

        trusted_path || TRUSTED_STEMS.contains(&stem.as_str())
    }
}

/// Behavioral Threat Model Voter (The "Learned Core")
/// Uses the 100,000 CVE bulk-trained model to assess risk based on process name, version, and lineage.
pub struct BehavioralThreatVoter {
    pub model: Arc<tokio::sync::RwLock<ThreatModel>>,
}

#[async_trait]
impl ThreatVoter for BehavioralThreatVoter {
    fn name(&self) -> String {
        "Behavioral-Threat-Model".to_string()
    }
    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        let image = event.data.get("Image").and_then(|v| v.as_str());
        if let Some(img) = image {
            let cmd = event
                .data
                .get("CommandLine")
                .or_else(|| event.data.get("command_line"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let has_suspicious_cmd = cmd.contains("-enc")
                || cmd.contains("frombase64string")
                || cmd.contains("mimikatz")
                || cmd.contains("sekurlsa")
                || cmd.contains("comsvcs")
                || cmd.contains("lsass")
                || cmd.contains("keymgr");
            if GemmaVoter::is_known_safe(img)
                && !has_suspicious_cmd
                && !matches!(event.event_id, 8 | 10 | 25)
            {
                return None;
            }
        }
        let process_name = image
            .and_then(|p| std::path::Path::new(p).file_name())
            .and_then(|n| n.to_str());
        let parent_image = event.data.get("ParentImage").and_then(|v| v.as_str());
        let parent_name = parent_image
            .and_then(|p| std::path::Path::new(p).file_name())
            .and_then(|n| n.to_str());
        let version = event.data.get("ProductVersion").and_then(|v| v.as_str());

        // Perform inference using the bulk-trained model
        let model_read = self.model.read().await;
        let mut lineage = Vec::new();
        if let Some(p) = parent_name {
            lineage.push(p.to_string());
        }
        let score = model_read.infer(process_name, None, version, lineage);

        if score > 0.8 {
            return Some(VoteResult {
                confidence: score,
                reason: format!("Behavioral Threat Model: High-risk pattern detected ({:.4}) based on process lineage and version context.", score),
                weight: 1.0,
            });
        } else if score > 0.4 {
            return Some(VoteResult {
                confidence: score,
                reason: format!(
                    "Behavioral Threat Model: Suspicious behavioral context ({:.4}).",
                    score
                ),
                weight: 0.6,
            });
        }

        None
    }
}

#[async_trait]
impl ThreatVoter for GemmaVoter {
    fn name(&self) -> String {
        "LLM-Reasoning".to_string()
    }
    fn is_heavy(&self) -> bool {
        true
    }
    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        let image = event
            .data
            .get("Image")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // Skip known-safe system processes (no need for LLM reasoning)
        if Self::is_known_safe(image) {
            return None;
        }

        // Rate limit: at most 1 LLM call per 30 seconds to protect CPU/GPU
        {
            let mut last = match self.last_call.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            if last.elapsed() < std::time::Duration::from_secs(30) {
                return None;
            }
            *last = std::time::Instant::now();
        }

        let cmd_line = event
            .data
            .get("CommandLine")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let version = event
            .data
            .get("ProductVersion")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let summary = format!(
            "Process Create: image={} version={} cmdline={}",
            image, version, cmd_line
        );

        if let Ok(raw_reasoning) = self.analyzer.reason_about_attack(&summary).await {
            // Strip DeepSeek <think>...</think> reasoning trace
            let reasoning = strip_think_tags(&raw_reasoning);

            // Ignore empty/garbage responses (timeout, model confusion, etc.)
            if reasoning.len() < 10 {
                return None;
            }

            let r_lower = reasoning.to_lowercase();
            if r_lower.contains("malicious")
                || r_lower.contains("attack")
                || r_lower.contains("suspicious")
            {
                // Truncate to 200 chars for clean log output
                let display: String = reasoning.chars().take(200).collect();
                return Some(VoteResult {
                    confidence: 0.9,
                    reason: format!("LLM Reasoning: {}", display),
                    weight: 0.9, // LLM reasoning has high weight for complex TTPs
                });
            }
        }
        None
    }
}

/// Strip DeepSeek R1 `<think>...</think>` reasoning traces from LLM output,
/// returning only the final vote/answer content.
fn strip_think_tags(raw: &str) -> String {
    if let Some(end_idx) = raw.find("</think>") {
        raw[end_idx + "</think>".len()..].trim().to_string()
    } else if raw.contains("<think>") {
        // Incomplete think block — model timed out mid-thought
        raw.replace("<think>", "").trim().to_string()
    } else {
        raw.trim().to_string()
    }
}

/// Cisco Foundation-Sec-8B Voter
pub struct FoundationSecVoter {
    pub analyzer: Arc<osoosi_behavioral::FoundationSecAnalyzer>,
    last_call: std::sync::Mutex<std::time::Instant>,
}

impl FoundationSecVoter {
    pub fn new(analyzer: Arc<osoosi_behavioral::FoundationSecAnalyzer>) -> Self {
        Self {
            analyzer,
            last_call: std::sync::Mutex::new(
                std::time::Instant::now() - std::time::Duration::from_secs(60),
            ),
        }
    }
}

#[async_trait]
impl ThreatVoter for FoundationSecVoter {
    fn name(&self) -> String {
        "Foundation-Sec-Reasoning".to_string()
    }
    fn is_heavy(&self) -> bool {
        true
    }
    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        let image = event
            .data
            .get("Image")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        if GemmaVoter::is_known_safe(image) {
            return None;
        }

        {
            let mut last = match self.last_call.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            if last.elapsed() < std::time::Duration::from_secs(30) {
                return None;
            }
            *last = std::time::Instant::now();
        }

        let cmd_line = event
            .data
            .get("CommandLine")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let version = event
            .data
            .get("ProductVersion")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let summary = format!(
            "Process Create: image={} version={} cmdline={}",
            image, version, cmd_line
        );

        if let Ok(raw_reasoning) = self.analyzer.reason_about_attack(&summary).await {
            let reasoning = strip_think_tags(&raw_reasoning);

            if reasoning.len() < 10 {
                return None;
            }

            let r_lower = reasoning.to_lowercase();
            if r_lower.contains("malicious")
                || r_lower.contains("attack")
                || r_lower.contains("suspicious")
            {
                let display: String = reasoning.chars().take(200).collect();
                return Some(VoteResult {
                    confidence: 0.92,
                    reason: format!("Foundation-Sec: {}", display),
                    weight: 0.95,
                });
            }
        }
        None
    }
}

/// Native Instrumentation Voter (Ported from OpenEDR architectural patterns)
/// Votes on self-protection violations, USB exfiltration, and registry anomalies.
pub struct NativeVoter {
    pub memory: Arc<osoosi_memory::MemoryStore>,
}

#[async_trait]
impl ThreatVoter for NativeVoter {
    fn name(&self) -> String {
        "Native-Instrumentation".to_string()
    }
    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        // 1. Self-Protection: Check if unauthorized process is touching Oshoosi files/registry
        if let Some(path) = event.data.get("TargetFilename").and_then(|v| v.as_str()) {
            if osoosi_types::reg_utils::is_self_protection_file_path(path) {
                // If it's not Oshoosi itself or a trusted system process
                let image = event
                    .data
                    .get("Image")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if !image.to_lowercase().contains("osoosi")
                    && !image.to_lowercase().contains("system32")
                {
                    return Some(VoteResult {
                        confidence: 0.95,
                        reason: format!("Self-Protection Violation: process {} attempted to access EDR binary/data at {}", image, path),
                        weight: 1.0, // Critical violation
                    });
                }
            }
        }

        if let Some(key) = event.data.get("TargetObject").and_then(|v| v.as_str()) {
            let normalized = osoosi_types::reg_utils::normalize_registry_path(key);
            if osoosi_types::reg_utils::is_self_protection_reg_path(&normalized) {
                let image = event
                    .data
                    .get("Image")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if !image.to_lowercase().contains("osoosi") {
                    return Some(VoteResult {
                        confidence: 0.95,
                        reason: format!("Self-Protection Violation: process {} attempted to modify EDR registry key {}", image, key),
                        weight: 1.0,
                    });
                }
            }

            // 2. Normalized Registry Persistence Check
            if normalized.contains("software\\microsoft\\windows\\currentversion\\run")
                || normalized.contains("system\\currentcontrolset\\services")
            {
                // Suspicious if not from a known installer
                let image = event
                    .data
                    .get("Image")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if !image.to_lowercase().contains("msiexec")
                    && !image.to_lowercase().contains("setup")
                {
                    return Some(VoteResult {
                        confidence: 0.75,
                        reason: format!(
                            "Suspicious Persistence: process {} modifying boot/service key {}",
                            image, normalized
                        ),
                        weight: 0.6,
                    });
                }
            }
        }

        // 3. USB Exfiltration Detection (using OpenEDR pattern)
        if event.event_id == 11 {
            // 11: FileCreate
            if let Some(path) = event.data.get("TargetFilename").and_then(|v| v.as_str()) {
                // If it's a drive usually associated with USB (D:, E:, etc. that isn't the system drive)
                let p = path.to_lowercase();
                if (p.starts_with("d:\\") || p.starts_with("e:\\") || p.starts_with("f:\\"))
                    && !p.contains("osoosi")
                {
                    return Some(VoteResult {
                        confidence: 0.6,
                        reason: format!(
                            "Potential USB Exfiltration: file creation on removable media at {}",
                            path
                        ),
                        weight: 0.5,
                    });
                }
            }
        }

        None
    }
}

/// Trusted Vendor Voter (Signature Check)
/// Verifies the Authenticode signature via Sysmon telemetry.
/// If signed by a trusted vendor, subtracts from the threat score.
pub struct TrustedVendorVoter;

#[async_trait]
impl ThreatVoter for TrustedVendorVoter {
    fn name(&self) -> String {
        "Trusted-Vendor".to_string()
    }
    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        // Only verify PE metadata on process-create and image-load events where a PE is actually
        // on disk. All other event IDs (file, network, registry) have no PE binary to inspect
        // and calling get_pe_metadata() would hit disk unnecessarily on every event.
        if !matches!(event.event_id, 1 | 7) {
            return None;
        }
        // 1. Get the image path from telemetry
        let full_path = event.data.get("Image").and_then(|v| v.as_str())?;

        // 2. Extract Metadata natively (Goblin + X509-Parser)
        let meta = match osoosi_types::get_pe_metadata(std::path::Path::new(full_path)) {
            Some(m) => m,
            None => return None,
        };

        // 3. Verify identity against trusted publishers
        if let Some(publisher) = meta.publisher {
            let publisher_lc = publisher.to_lowercase();
            let trusted_publishers = [
                "microsoft",
                "github, inc.",
                "google",
                "apple",
                "mozilla",
                "oracle",
                "amazon",
                "digicert",
                "sectigo",
                "comodo",
            ];

            if trusted_publishers.iter().any(|&p| publisher_lc.contains(p)) {
                // If WinVerifyTrust also says it's signed, we have high confidence
                let weight = if meta.is_signed { -1.0 } else { -0.5 };

                return Some(VoteResult {
                    confidence: 0.0,
                    reason: format!(
                        "Trusted Vendor (Native Verify): {} (Integrity: {})",
                        publisher,
                        if meta.is_signed {
                            "Verified"
                        } else {
                            "Identity-only"
                        }
                    ),
                    weight,
                });
            }
        }

        // Fallback to telemetry-based check if native extraction failed or publisher is missing
        let status = event
            .data
            .get("SignatureStatus")
            .or_else(|| event.data.get("Signature Status"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let telemetry_publisher = event
            .data
            .get("Signature")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();

        if (status.to_lowercase() == "valid" || status.to_lowercase().contains("trusted"))
            && !telemetry_publisher.is_empty()
        {
            let trusted_publishers = [
                "microsoft",
                "github, inc.",
                "google",
                "apple",
                "mozilla",
                "oracle",
                "amazon",
                "digicert",
                "sectigo",
                "comodo",
            ];

            if trusted_publishers
                .iter()
                .any(|&p| telemetry_publisher.contains(p))
            {
                return Some(VoteResult {
                    confidence: 0.0,
                    reason: format!(
                        "Trusted Vendor (Telemetry): {} (Status: {})",
                        telemetry_publisher, status
                    ),
                    weight: -0.4,
                });
            }
        }

        None
    }
}

/// Git Noise Voter (Forensic "Allow-Strings")
/// Specifically suppresses alerts for legitimate Git behavior (CRL checks, etc.)
pub struct GitNoiseVoter;

#[async_trait]
impl ThreatVoter for GitNoiseVoter {
    fn name(&self) -> String {
        "Git-Noise-Filter".to_string()
    }
    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        let image = event
            .data
            .get("Image")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        if image.contains("git.exe") || image.contains("git-remote-http.exe") {
            // Check for known benign Git artifacts
            let cmd_line = event
                .data
                .get("CommandLine")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            let query = event
                .data
                .get("QueryName")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();

            let benign_git_strings = [
                "crl.comodo.net",
                "crl.sectigo.com",
                "crl.digicert.com",
                "github.com",
                "bitbucket.org",
                "gitlab.com",
                "git-receive-pack",
                "git-upload-pack",
            ];

            if benign_git_strings
                .iter()
                .any(|&s| cmd_line.contains(s) || query.contains(s))
            {
                return Some(VoteResult {
                    confidence: 0.0,
                    reason: "Benign Git Forensic Artifact: legitimate Git network/CRL behavior detected.".to_string(),
                    weight: -1.0, // Significant suppression
                });
            }
        }
        None
    }
}

pub struct NsrlVoter {
    pub cache: Arc<dashmap::DashMap<String, bool>>,
    pub memory: Arc<osoosi_memory::MemoryStore>,
}

pub(crate) fn extract_all_candidate_hashes(event: &HostSecurityEvent) -> Vec<String> {
    let mut hashes = Vec::new();
    if let Some(h_str) = event.data.get("Hashes").and_then(|v| v.as_str()) {
        for part in h_str.split(',') {
            let p = part.trim();
            for prefix in &["SHA1=", "SHA1:", "SHA256=", "SHA256:", "MD5=", "MD5:"] {
                if let Some(rest) = p.strip_prefix(prefix) {
                    hashes.push(rest.trim().to_ascii_lowercase());
                }
            }
        }
    }
    for field in &[
        "SHA1", "sha1", "SHA256", "sha256", "MD5", "md5", "Hash", "hash", "blake3",
    ] {
        if let Some(val) = event.data.get(*field).and_then(|v| v.as_str()) {
            let trimmed = val.trim().to_ascii_lowercase();
            if !trimmed.is_empty() && !hashes.contains(&trimmed) {
                hashes.push(trimmed);
            }
        }
    }
    hashes
}

#[async_trait]
impl ThreatVoter for NsrlVoter {
    fn name(&self) -> String {
        "NSRL-Veto".to_string()
    }
    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        let candidate_hashes = extract_all_candidate_hashes(event);
        for h in &candidate_hashes {
            if self.cache.get(h).map(|e| *e.value()).unwrap_or(false) {
                return Some(vote_result_nsrl_veto());
            }
            if self.memory.is_nsrl_known_good(h).unwrap_or(false) {
                self.cache.insert(h.clone(), true);
                return Some(vote_result_nsrl_veto());
            }
        }

        let image_path = event
            .data
            .get("Image")
            .or_else(|| event.data.get("image"))
            .or_else(|| event.data.get("ImagePath"))
            .and_then(|v| v.as_str());

        if let Some(img) = image_path {
            if self.cache.get(img).map(|e| *e.value()).unwrap_or(false) {
                return Some(vote_result_nsrl_veto());
            }

            if osoosi_audit::nsrl_aslr_merkle::global_nsrl_aslr_guard()
                .nsrl_engine()
                .get_profile(img)
                .is_some()
            {
                self.cache.insert(img.to_string(), true);
                return Some(vote_result_nsrl_veto());
            }

            // On Linux/Unix, compute hash of host binary on disk if readable
            let path = std::path::Path::new(img);
            if path.is_file() {
                if let Ok(bytes) = std::fs::read(path) {
                    use sha2::Digest;
                    let sha256_hex = hex::encode(sha2::Sha256::digest(&bytes));
                    if self.memory.is_nsrl_known_good(&sha256_hex).unwrap_or(false) {
                        self.cache.insert(img.to_string(), true);
                        return Some(vote_result_nsrl_veto());
                    }
                }
                self.cache.insert(img.to_string(), false);
            }
        }

        None
    }
}

fn vote_result_nsrl_veto() -> VoteResult {
    VoteResult {
        confidence: 0.0, // Veto: no "malice" score
        reason: "NSRL: File hash in NIST known-good set. Vetoing threat block.".to_string(),
        weight: -2.0,
    }
}

/// Decompile Voter (Spider Eyes Mechanistic Analyst)
/// Uses Gemma 4 + Capstone to analyze the intent of a running process on-demand.
pub struct DecompileVoter {
    pub spider: Arc<osoosi_behavioral::SpiderEyes>,
}

#[async_trait]
impl ThreatVoter for DecompileVoter {
    fn name(&self) -> String {
        "Decompile".to_string()
    }
    fn is_heavy(&self) -> bool {
        true
    }
    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        // We only decompile on ProcessCreate (1) or ImageLoad (7) to catch entry-point intent
        if !matches!(event.event_id, 1 | 7) {
            return None;
        }

        let pid = event
            .data
            .get("ProcessId")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)?;

        // Deep analysis: SpiderEyes watches the process, disassembles, and reasons with Gemma 4
        match self.spider.watch_process(pid).await {
            Ok(report) => {
                let r_lower = report.to_lowercase();
                if r_lower.contains("malicious")
                    || r_lower.contains("attack")
                    || r_lower.contains("injection")
                    || r_lower.contains("hollowing")
                {
                    return Some(VoteResult {
                        confidence: 0.98,
                        reason: format!("Decompile/SpiderEyes High-Confidence Hit: {}", report),
                        weight: 1.5, // Decompile hits are extremely high rank
                    });
                } else if r_lower.contains("suspicious") || r_lower.contains("obfuscated") {
                    return Some(VoteResult {
                        confidence: 0.85,
                        reason: format!("Decompile/SpiderEyes Suspicious Finding: {}", report),
                        weight: 1.1,
                    });
                }
            }
            Err(_) => {
                // Silently abstain if decompile fails (e.g. process exited too fast)
            }
        }
        None
    }
}

/// Yara-X Memory Voter (C2 Beacon Scanning)
pub struct YaraXMemoryVoter {
    pub rules: Arc<yara_x::Rules>,
}

#[async_trait]
impl ThreatVoter for YaraXMemoryVoter {
    fn name(&self) -> String {
        "YaraX-Memory".to_string()
    }
    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        #[cfg(target_os = "windows")]
        {
            use windows::Win32::Foundation::CloseHandle;
            use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
            use windows::Win32::System::Threading::{
                OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
            };

            if let Some(pid) = event
                .data
                .get("ProcessId")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32)
            {
                let rules = self.rules.clone();
                return tokio::task::spawn_blocking(move || {
                    unsafe {
                        let proc_handle =
                            OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)
                                .ok()?;
                        let mut buffer = vec![0u8; 8192]; // Use 8KB for better coverage
                        let mut bytes_read = 0usize;

                        // Placeholder: in a real EDR we'd walk the VAD (Virtual Address Descriptor)
                        // or use VirtualQueryEx to find executable/private regions.
                        // Here we scan a 8KB chunk of the potential image base.
                        let _ = ReadProcessMemory(
                            proc_handle,
                            0x400000 as *const _,
                            buffer.as_mut_ptr() as *mut _,
                            buffer.len(),
                            Some(&mut bytes_read),
                        );
                        let _ = CloseHandle(proc_handle);

                        if bytes_read > 0 {
                            buffer.truncate(bytes_read);
                            let mut scanner = yara_x::Scanner::new(&rules);
                            let results = scanner.scan(&buffer).ok()?;
                            if results.matching_rules().any(|r| {
                                !osoosi_model::malware::is_informational_or_crt_yara_rule(
                                    r.identifier(),
                                )
                            }) {
                                return Some(VoteResult {
                                    confidence: 0.98,
                                    reason: "Yara-X: Detected malicious pattern in process memory"
                                        .to_string(),
                                    weight: 1.0,
                                });
                            }
                        }
                    }
                    None
                })
                .await
                .unwrap_or(None);
            }
        }
        None
    }
}

/// KEV `product` text → compare **tokens** to the executable **stem** (e.g. `git.exe` ↔ "Git" / "Windows Git"),
/// not loose `contains` (which turned every `git.exe` / `chrome.exe` into a KEV hit).
fn kev_product_matches_stem(stem: &str, product: &str) -> bool {
    let stem = stem.trim().to_lowercase();
    let product_lower = product.trim().to_lowercase();
    if stem.len() < 3 || product_lower.is_empty() {
        return false;
    }
    if stem == product_lower {
        return true;
    }
    const GENERIC_AMBIGUOUS_STEMS: &[&str] = &[
        "setup",
        "file",
        "server",
        "client",
        "update",
        "updater",
        "install",
        "installer",
        "service",
        "agent",
        "browser",
        "manager",
        "system",
        "windows",
        "linux",
        "action",
        "http",
        "app",
        "host",
        "tool",
        "cli",
        "env",
        "expand",
        "unzip",
        "perl",
        "sed",
    ];
    if GENERIC_AMBIGUOUS_STEMS.contains(&stem.as_str()) {
        return false;
    }
    for token in product_lower.split(|c: char| !c.is_alphanumeric()) {
        if token.len() < 3 {
            continue;
        }
        if stem == token {
            return true;
        }
    }
    false
}

fn kev_requires_exact_version(event: &HostSecurityEvent, full_path: &str) -> bool {
    let lifecycle = matches!(
        event.event_id,
        1 | 5 | 7 // 1: ProcessCreate, 5: ProcessTerminate, 7: ImageLoad
    );
    if !lifecycle {
        return false;
    }
    let p = full_path.to_ascii_lowercase();
    p.contains("\\windows\\")
        || p.contains("\\program files")
        || p.contains("\\tools\\git\\")
        || p.contains("\\oshoosiclaw\\")
}

/// Suppress CISA-KEV on **ProcessCreate** and **ProcessTerminate** for ubiquitous tools in typical install
/// locations (huge FP rate — e.g. `git.exe` + KEV "Git" on portable/custom paths, terminate events).
/// Set `OSOOSI_KEV_QUIET_SYSTEM_TOOLS=0` to restore KEV on those events. **NetworkConnect / DNS / Image** still evaluated.
fn kev_quiet_benign_process_lifecycle(
    path: &str,
    stem: &str,
    config: &osoosi_types::PolicyConfig,
) -> bool {
    if std::env::var("OSOOSI_KEV_QUIET_SYSTEM_TOOLS")
        .map(|v| v == "0" || v.eq_ignore_ascii_case("false") || v.eq_ignore_ascii_case("off"))
        .unwrap_or(false)
    {
        return false;
    }
    let p = path.to_lowercase();

    // Configuration-driven suppression
    if config
        .consensus_trusted_paths
        .iter()
        .any(|t| p.contains(&t.to_lowercase()))
    {
        return true;
    }
    if config
        .consensus_noisy_stems
        .iter()
        .any(|s| stem.eq_ignore_ascii_case(s))
    {
        return true;
    }

    let trusted = p.contains("program files")
        || p.contains("programdata\\chocolatey")
        || p.contains("programdata\\scoop")
        || p.contains("\\oshoosiclaw\\tools\\")
        || p.contains("\\oshoosiclaw\\target\\")
        || p.contains("\\windows\\system32")
        || p.contains("\\windows\\syswow64")
        || p.contains("\\tools\\git\\")
        || p.contains("git\\cmd")
        // Git for Windows (standard + portable, e.g. C:\tools\git\mingw64\bin\git.exe)
        || p.contains("\\mingw64\\")
        || p.contains("\\mingw32\\")
        || p.contains("git\\mingw");
    if !trusted {
        return false;
    }
    const NOISY: &[&str] = &[
        "chrome",
        "msedge",
        "firefox",
        "brave",
        "opera",
        "git",
        "git-remote-http",
        "git-remote-https",
        "devenv",
        "code",
        "code-insiders",
        "wsl",
        "wslhost",
        "wslservice",
        "node",
        "net",
        "smartscreen",
        "sysmon",
        "sysmon64",
        "osoosi",
        "capa",
        "hayabusa",
        "chainsaw",
        "hollows_hunter",
        "xori",
        "rustc",
        "cargo",
        "python",
        "cursor",
        "antigravity",
        "language_server_windows_x64",
        "filecoauth",
    ];
    NOISY.contains(&stem)
}

/// CISA KEV (Known Exploited Vulnerabilities) Voter
pub struct KevVoter {
    pub memory: std::sync::Arc<osoosi_memory::MemoryStore>,
    pub config: osoosi_types::PolicyConfig,
}

#[async_trait]
impl ThreatVoter for KevVoter {
    fn name(&self) -> String {
        "CISA-KEV".to_string()
    }
    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        let full_path = event.data.get("Image").and_then(|v| v.as_str())?;
        let stem = std::path::Path::new(full_path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_lowercase();
        let file_name = std::path::Path::new(full_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_lowercase();

        if matches!(
            event.event_id,
            1 | 5 // 1: ProcessCreate, 5: ProcessTerminate
        ) && kev_quiet_benign_process_lifecycle(full_path, &stem, &self.config)
        {
            return None;
        }

        let is_known_good = self
            .memory
            .get_file_integrity(full_path)
            .map(|opt| opt.map(|(_, nsrl, _)| nsrl).unwrap_or(false))
            .unwrap_or(false);

        if let Ok(kevs) = self.memory.get_all_kevs() {
            for kev in kevs {
                if !kev_product_matches_stem(&stem, &kev.product) {
                    continue;
                }

                // VERSION-AWARE LOGIC: If we have a resolved product version, and it looks like a modern/patched version,
                // we down-rank the confidence significantly.
                let mut confidence = if is_known_good { 0.45 } else { 0.85 };
                let mut exact_version = event
                    .data
                    .get("ProductVersion")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|version| {
                        !version.is_empty() && !version.eq_ignore_ascii_case("unknown")
                    })
                    .map(|s| s.to_string());

                // Fallback: If version is missing from event, try to read it from the file (Windows only)
                #[cfg(target_os = "windows")]
                {
                    if exact_version.is_none() {
                        if let Ok(info) = win32_version_info::VersionInfo::from_file(full_path) {
                            if !info.file_version.is_empty() {
                                exact_version = Some(info.file_version);
                            }
                        }
                    }
                }
                if kev_requires_exact_version(event, full_path) && exact_version.is_none() {
                    return None;
                }

                if let Some(version) = exact_version.as_deref() {
                    use version_compare::{compare, Cmp};
                    let mut in_vulnerable_range = true;

                    if let Some(start) = &kev.version_start_including {
                        if let Ok(Cmp::Lt) = compare(version, start) {
                            in_vulnerable_range = false;
                        }
                    }
                    if let Some(end) = &kev.version_end_excluding {
                        if let Ok(Cmp::Eq) | Ok(Cmp::Gt) = compare(version, end) {
                            in_vulnerable_range = false;
                        }
                    }

                    if !in_vulnerable_range {
                        confidence *= 0.1; // Downgrade to Alert-only range
                        return Some(VoteResult {
                            confidence,
                            reason: format!(
                                "CISA KEV/NVD [PATCHED]: {} matches product {} ({}), but running version {} is outside the vulnerable range.",
                                file_name, kev.product, kev.cve_id, version
                            ),
                            weight: 0.2,
                        });
                    }
                }

                // Prefer KEV when tied to **network / file / image** telemetry; down-weight bare ProcessCreate (1).
                let (weight, reason_note) = if event.event_id == 1 {
                    (
                        0.75,
                        " (ProcessCreate: correlate with network/DNS/patch; lower vote weight)",
                    )
                } else {
                    (1.0, "")
                };

                return Some(VoteResult {
                    confidence,
                    reason: format!(
                        "CISA KEV: {} matches KEV product {} ({}){}",
                        file_name, kev.product, kev.cve_id, reason_note
                    ),
                    weight,
                });
            }
        }
        None
    }
}

/// CveLookupVoter: Bridge to real-time NVD Vulnerability Intelligence.
/// If a binary has a matching CVE, it provides the "tie-breaker" to elevate Alert to Isolate.
pub struct CveLookupVoter {
    pub fetcher: Arc<crate::feed::ThreatFeedFetcher>,
    pub memory: Arc<osoosi_memory::MemoryStore>,
    pub cve_cache: Option<Arc<tokio::sync::Mutex<crate::cve_cache::CveCache>>>,
    pub broadcaster: Arc<
        tokio::sync::RwLock<Option<Arc<dyn Fn(osoosi_types::GlobalIntelligence) + Send + Sync>>>,
    >,
    pub node_id: String,
}

#[async_trait]
impl ThreatVoter for CveLookupVoter {
    fn name(&self) -> String {
        "NVD-CVE-Lookup".to_string()
    }
    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        // Only query NVD on process-create and image-load events. get_pe_metadata() performs a
        // synchronous disk read; calling it on every event type (network, file, registry, dns)
        // causes unnecessary blocking I/O with no benefit since non-PE events carry no version.
        if !matches!(event.event_id, 1 | 7) {
            return None;
        }
        let full_path = event.data.get("Image").and_then(|v| v.as_str())?;

        // 1. Extract Metadata (Product, Version, Signature) from PE
        let meta = match osoosi_types::get_pe_metadata(std::path::Path::new(full_path)) {
            Some(m) => m,
            None => return None,
        };

        let prod_trim = meta.product_name.trim();
        let ver_trim = meta.version.trim();
        if prod_trim.is_empty()
            || prod_trim.eq_ignore_ascii_case("unknown")
            || ver_trim.is_empty()
            || ver_trim == "0.0.0"
            || ver_trim == "0.0.0.0"
            || ver_trim.eq_ignore_ascii_case("unknown")
        {
            return None;
        }

        // NEW: Suppress NVD lookup for signed Microsoft binaries or system files to avoid Consensus Veto spam.
        // We also check if the hash is in the NSRL known-good set.
        let is_microsoft = meta.product_name.to_lowercase().contains("microsoft")
            || meta.product_name.to_lowercase().contains("windows")
            || meta
                .publisher
                .as_ref()
                .map(|p| p.to_lowercase().contains("microsoft"))
                .unwrap_or(false)
            || full_path.to_lowercase().contains("\\windows\\system32");

        if meta.is_signed && is_microsoft {
            return None; // Abstain to prevent log spam/veto on core OS processes
        }

        let candidate_hashes = extract_all_candidate_hashes(event);
        for h in &candidate_hashes {
            if self.memory.is_nsrl_known_good(h).unwrap_or(false) {
                return None; // Abstain for known-good files
            }
        }

        // 2. Check Local Cache first
        let mut cached_cves = Vec::new();

        // Try the new SQLite cache first
        if let Some(ref cache) = self.cve_cache {
            let cache_guard = cache.lock().await;
            if let Ok(cves) = cache_guard.get_cves(&meta.product_name, &meta.version) {
                cached_cves.extend(cves);
            }
        }

        // Fallback to old in-memory cache if SQLite cache is empty
        if cached_cves.is_empty() {
            if let Ok(cached) = self
                .memory
                .get_cached_cves(&meta.product_name, &meta.version)
            {
                cached_cves.extend(cached);
            }
            if cached_cves.is_empty() {
                if let Ok(cached) = self.memory.get_cached_cves(&meta.product_name, "any") {
                    cached_cves.extend(cached);
                }
            }
        }

        if !cached_cves.is_empty() {
            let mut confidence = 0.95;
            let mut reason_note = " [CACHED]";
            if meta.is_signed {
                confidence = 0.65;
                reason_note = " [CACHED, CONFIDENCE DOWNGRADED: SIGNED]";
            }
            let cve_list: Vec<String> = cached_cves
                .iter()
                .take(3)
                .map(|(id, summary)| format!("{} ({:.50}...)", id, summary))
                .collect();
            return Some(VoteResult {
                confidence,
                reason: format!(
                    "Vulnerability Database Match: {} v{} has known CVEs: {}{}",
                    meta.product_name,
                    meta.version,
                    cve_list.join(", "),
                    reason_note
                ),
                weight: 1.5,
            });
        }

        // 3. Query NVD API (or local cache via fetcher)
        let api_key = osoosi_types::resolve_nvd_api_key();
        match self
            .fetcher
            .query_cve_by_product(&meta.product_name, &meta.version, api_key.as_deref())
            .await
        {
            Ok(cves) if !cves.is_empty() => {
                let mut confidence = 0.95;
                let mut reason_note = "";

                // Downgrade confidence if binary is signed by a valid vendor
                if meta.is_signed {
                    confidence = 0.65;
                    reason_note = " [CONFIDENCE DOWNGRADED: SIGNED BINARY]";
                }

                // Cache the results locally and broadcast to mesh
                for cve in &cves {
                    let _ = self.memory.insert_cve_cache(
                        &meta.product_name,
                        &meta.version,
                        &cve.id,
                        &cve.summary,
                    );
                    if let Some(ref cache) = self.cve_cache {
                        let cache_guard = cache.lock().await;
                        let _ = cache_guard.insert_cves(
                            &meta.product_name,
                            &meta.version,
                            &[osoosi_types::Kev {
                                cve_id: cve.id.clone(),
                                vendor_project: "".to_string(),
                                product: meta.product_name.clone(),
                                vulnerability_name: cve.summary.clone(),
                                date_added: chrono::Utc::now(),
                                required_action: "".to_string(),
                                due_date: chrono::Utc::now(),
                                known_exploited: false,
                                version_start_including: None,
                                version_end_excluding: None,
                            }],
                        );
                    }

                    let broadcaster_guard = self.broadcaster.read().await;
                    if let Some(ref broadcast) = *broadcaster_guard {
                        broadcast(osoosi_types::GlobalIntelligence {
                            source_url: "https://nvd.nist.gov".to_string(),
                            summary: format!(
                                "NVD Discovery: {} v{} has vulnerability {}",
                                meta.product_name, meta.version, cve.id
                            ),
                            priority: 0.8,
                            defense: Some(osoosi_types::ZeroDayDefense {
                                cve_id: cve.id.clone(),
                                title: format!("NVD: {}", cve.id),
                                description: cve.summary.clone(),
                                severity: 0.8,
                                learned_rule: "".to_string(),
                                software_target: meta.product_name.clone(),
                                software_version: Some(meta.version.clone()),
                                date_learned: chrono::Utc::now(),
                            }),
                            timestamp: chrono::Utc::now(),
                            source_node: self.node_id.clone(),
                            epsilon: None,
                            merkle_proof: None,
                        });
                    }
                }

                let cve_list: Vec<String> = cves
                    .iter()
                    .take(3)
                    .map(|c| format!("{} ({:.50}...)", c.id, c.summary))
                    .collect();
                let cve_display = cve_list.join(", ");

                Some(VoteResult {
                    confidence,
                    reason: format!(
                        "Vulnerability Database Match: {} v{} has known CVEs: {}{}",
                        meta.product_name, meta.version, cve_display, reason_note
                    ),
                    weight: 1.5, // Tie-breaker weight
                })
            }
            Ok(_) => {
                // If NO CVE found, we return a "neutral" vote. We no longer veto,
                // as missing CVE data is common for benign system processes.
                Some(VoteResult {
                    confidence: 0.0,
                    reason: format!(
                        "NVD: No matching CVEs found for {} v{}",
                        meta.product_name, meta.version
                    ),
                    weight: 0.0,
                })
            }
            Err(e) if e.to_string().contains("Rate limit") => {
                warn!("[CveLookupVoter] NVD API Rate Limit Hit: {}", e);
                None // Abstain if rate limited
            }
            Err(e) => {
                debug!(
                    "[CveLookupVoter] Query failed for {}: {}",
                    meta.product_name, e
                );
                None
            }
        }
    }
}

/// A privacy-preserving voter that uses Differential Privacy and Merkle Auditing.
pub struct PrivacyVoter {
    dp: DifferentialPrivacy,
    #[allow(dead_code)]
    audit: Arc<MerkleAuditTree>,
}

impl PrivacyVoter {
    pub fn new(config: PrivacyConfig, audit: Arc<MerkleAuditTree>) -> Self {
        Self {
            dp: DifferentialPrivacy::new(config),
            audit,
        }
    }
}

#[async_trait]
impl ThreatVoter for PrivacyVoter {
    fn name(&self) -> String {
        "Privacy-Enforced-Voter".to_string()
    }

    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        // 1. Calculate a base "suspicion" score (placeholder logic)
        let mut base_score = 0.0;
        if let Some(cmd) = event.data.get("CommandLine").and_then(|v| v.as_str()) {
            if cmd.contains("powershell") || cmd.contains("base64") {
                base_score = 0.65;
            }
        }

        if base_score > 0.0 {
            // 2. APPLY DIFFERENTIAL PRIVACY: Add Laplacian noise to the score
            let noisy_score = (base_score + self.dp.laplace_noise()).clamp(0.0, 1.0);

            // Logging every privacy vote to the Merkle audit chain caused a SHA-256 + mutex
            // lock on every powershell commandline event. Threats are already audited at the
            // orchestrator level via THREAT_DETECTED; this per-vote entry is redundant.
            Some(VoteResult {
                confidence: noisy_score,
                reason: format!(
                    "Privacy-preserving detection (DP noise applied, score={:.3}).",
                    noisy_score
                ),
                weight: 0.8,
            })
        } else {
            None
        }
    }
}

/// Injection Telemetry Voter (Ported from OpenEDR hooking engine)
///
/// Evaluates telemetry events generated by the `osoosi-inject` in-process hooks.
/// Detects:
///   - Screen capture spyware (BitBlt hook telemetry)
///   - Process hollowing / shellcode injection (NtAllocateVirtualMemory with RWX)
///   - Credential dumping (ReadProcessMemory targeting lsass.exe)
///   - Execution of suspicious commands (CreateProcessW / execve interceptions)
///   - C2 beacon patterns in network send() payloads
pub struct InjectionTelemetryVoter;

#[async_trait]
impl ThreatVoter for InjectionTelemetryVoter {
    fn name(&self) -> String {
        "Injection-Telemetry".to_string()
    }

    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        // The hook payload tags events with a "HookSource" data field when it reports
        // intercepted API calls back to the orchestrator via the telemetry channel.
        let hook_source = event.data.get("HookSource").and_then(|v| v.as_str())?;

        match hook_source {
            // --- Screen Capture Spyware Detection (BitBlt hook) ---
            "BitBlt" => {
                let image = event
                    .data
                    .get("Image")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                // Trusted screen-capture processes (RDP, screenshot tools) are excluded
                let img_lower = image.to_lowercase();
                if img_lower.contains("sniphost")
                    || img_lower.contains("snippingtool")
                    || img_lower.contains("mstsc")
                    || img_lower.contains("teamviewer")
                    || img_lower.contains("obs")
                    || img_lower.contains("osoosi")
                {
                    return None;
                }
                Some(VoteResult {
                    confidence: 0.85,
                    reason: format!("Screen Capture Detected: process {} called BitBlt (potential spyware/stalkerware)", image),
                    weight: 0.7,
                })
            }

            // --- Process Hollowing / Shellcode Injection Detection ---
            "NtAllocateVirtualMemory" => {
                let protect = event
                    .data
                    .get("Protection")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let image = event
                    .data
                    .get("Image")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                // PAGE_EXECUTE_READWRITE (0x40) is almost always shellcode injection
                if protect.contains("RWX") || protect.contains("0x40") {
                    // Exclude known legitimate JIT engines
                    let img_lower = image.to_lowercase();
                    if img_lower.contains("java")
                        || img_lower.contains("dotnet")
                        || img_lower.contains("node")
                        || img_lower.contains("chrome")
                        || img_lower.contains("firefox")
                    {
                        return None;
                    }
                    return Some(VoteResult {
                        confidence: 0.92,
                        reason: format!("Process Injection Suspected: {} allocated RWX memory (shellcode/hollowing indicator)", image),
                        weight: 0.85,
                    });
                }
                None
            }

            // --- Module Overloading Detection (NtProtectVirtualMemory hook) ---
            "NtProtectVirtualMemory" => {
                let protect = event
                    .data
                    .get("Protection")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let image = event
                    .data
                    .get("Image")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                // Changing existing memory (often module memory) to RWX is a major indicator of module overloading or hooking.
                if protect.contains("RWX") || protect.contains("0x40") {
                    // Exclude known legitimate JIT engines
                    let img_lower = image.to_lowercase();
                    if img_lower.contains("java")
                        || img_lower.contains("dotnet")
                        || img_lower.contains("node")
                        || img_lower.contains("chrome")
                        || img_lower.contains("firefox")
                    {
                        return None;
                    }
                    return Some(VoteResult {
                        confidence: 0.95,
                        reason: format!("Module Overloading Detected: {} changed memory protection to RWX (Image -> Private transition)", image),
                        weight: 0.9,
                    });
                }
                None
            }

            // --- Credential Dumping Detection (ReadProcessMemory / ptrace) ---
            "ReadProcessMemory" | "ptrace" => {
                let target = event
                    .data
                    .get("TargetProcess")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let image = event
                    .data
                    .get("Image")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let target_lower = target.to_lowercase();
                // lsass.exe is THE target for credential dumping (Mimikatz, etc.)
                if target_lower.contains("lsass") {
                    return Some(VoteResult {
                        confidence: 0.98,
                        reason: format!("CRITICAL: Credential Dumping Attempt! Process {} read memory of lsass.exe", image),
                        weight: 1.0, // Maximum weight — this is an active attack
                    });
                }
                // Reading EDR memory is also a self-protection violation
                if target_lower.contains("osoosi") {
                    return Some(VoteResult {
                        confidence: 0.95,
                        reason: format!(
                            "Self-Defense: Process {} attempted to read EDR process memory",
                            image
                        ),
                        weight: 1.0,
                    });
                }
                None
            }

            // --- Execution Blocking (CreateProcessW / execve) ---
            "CreateProcessW" | "execve" => {
                let cmd_line = event
                    .data
                    .get("CommandLine")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let cmd_lower = cmd_line.to_lowercase();

                // Detect encoded PowerShell commands (common malware evasion)
                if cmd_lower.contains("-encodedcommand")
                    || cmd_lower.contains("-enc ")
                    || cmd_lower.contains("-e ")
                {
                    return Some(VoteResult {
                        confidence: 0.88,
                        reason: format!("Encoded Execution Detected: child process launched with obfuscated arguments: {}", 
                            &cmd_line[..cmd_line.len().min(120)]),
                        weight: 0.8,
                    });
                }

                // Detect reverse shells
                if (cmd_lower.contains("/dev/tcp") || cmd_lower.contains("bash -i"))
                    || (cmd_lower.contains("nc ") && cmd_lower.contains(" -e "))
                    || cmd_lower.contains("ncat") && cmd_lower.contains("--sh-exec")
                {
                    return Some(VoteResult {
                        confidence: 0.95,
                        reason: format!(
                            "Reverse Shell Detected: {}",
                            &cmd_line[..cmd_line.len().min(120)]
                        ),
                        weight: 0.95,
                    });
                }

                None
            }

            // --- C2 Beacon Detection (send / WSASend) ---
            "send" | "WSASend" => {
                let payload_hint = event
                    .data
                    .get("PayloadHint")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let hint_lower = payload_hint.to_lowercase();

                // DNS tunneling patterns: unusually long subdomain labels
                if hint_lower.contains(".onion") || hint_lower.contains(".i2p") {
                    return Some(VoteResult {
                        confidence: 0.9,
                        reason: "Darknet Communication: outbound traffic to anonymization network detected".to_string(),
                        weight: 0.85,
                    });
                }

                // HTTP beaconing with suspicious User-Agents
                if hint_lower.contains("user-agent:")
                    && (hint_lower.contains("cobalt")
                        || hint_lower.contains("meterpreter")
                        || hint_lower.contains("empire")
                        || hint_lower.contains("covenant"))
                {
                    return Some(VoteResult {
                            confidence: 0.95,
                            reason: "C2 Framework Beacon: known attack framework User-Agent detected in outbound HTTP".to_string(),
                            weight: 0.9,
                        });
                }

                None
            }

            _ => None,
        }
    }
}

/// DNS Shield Voter
///
/// Evaluates DNS query telemetry from the `osoosi-dns` proxy.
/// Detects:
///   - Known-malicious domains (blocklist sinkholing)
///   - DGA-generated domains (Shannon entropy analysis)
///   - DNS tunneling (oversized labels / excessive depth)
///   - Darknet TLD communication (.onion, .i2p, .bit)
pub struct DnsShieldVoter;

#[async_trait]
impl ThreatVoter for DnsShieldVoter {
    fn name(&self) -> String {
        "DNS-Shield".to_string()
    }

    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        // The DNS Shield tags events with "DnsQuery" in the HookSource field
        let hook_source = event.data.get("HookSource").and_then(|v| v.as_str())?;
        if hook_source != "DnsShield" {
            return None;
        }

        let domain = event
            .data
            .get("DnsQuery")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let verdict = event
            .data
            .get("DnsVerdict")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let reason = event
            .data
            .get("DnsReason")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let entropy: f64 = event
            .data
            .get("DnsEntropy")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let image = event
            .data
            .get("Image")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        match verdict {
            "BLOCKED" => {
                // Determine severity based on block reason
                let (confidence, weight) = if reason.contains("DGA") {
                    (0.92, 0.85)
                } else if reason.contains("tunneling") {
                    (0.95, 0.9)
                } else if reason.contains("Darknet") || reason.contains(".onion") {
                    (0.9, 0.85)
                } else {
                    // Blocklist hit
                    (0.88, 0.8)
                };

                Some(VoteResult {
                    confidence,
                    reason: format!("DNS Shield BLOCKED: process {} queried '{}'. {}", image, domain, reason),
                    weight,
                })
            }
            "SUSPICIOUS" => {
                Some(VoteResult {
                    confidence: 0.6,
                    reason: format!("DNS Shield ALERT: process {} queried suspicious domain '{}' (entropy: {:.2}). {}", image, domain, entropy, reason),
                    weight: 0.5,
                })
            }
            _ => None,
        }
    }
}

/// Sysmon DNS Query Voter (Event ID 22)
///
/// Processes native Sysmon DNS telemetry which tells us WHICH PROCESS made WHICH DNS query.
/// This is more powerful than the DNS proxy because Sysmon provides process-level attribution
/// (Image, PID, User) for every single DNS lookup on the host.
///
/// Pipeline:
///   1. Extracts QueryName from Sysmon Event 22
///   2. Runs DGA/entropy analysis via osoosi_dns::analysis
///   3. Checks the domain against the DNS blocklist
///   4. Correlates the originating process (Image) to determine if the lookup is anomalous
///   5. For suspicious patterns, builds a context string that the LLM voter can reason about
pub struct SysmonDnsVoter {
    pub blocklist: std::sync::Arc<osoosi_dns::DnsBlocklist>,
}

#[async_trait]
impl ThreatVoter for SysmonDnsVoter {
    fn name(&self) -> String {
        "Sysmon-DNS-Voter".to_string()
    }

    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        // Only process Sysmon Event ID 22 (DnsQuery)
        if event.event_id != 22 {
            return None;
        }

        let query_name = event.data.get("QueryName").and_then(|v| v.as_str())?;
        let image = event
            .data
            .get("Image")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let pid = event
            .data
            .get("ProcessId")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let query_results = event
            .data
            .get("QueryResults")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let query_status = event
            .data
            .get("QueryStatus")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Extract process name from full image path
        let proc_name = image
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(image)
            .to_lowercase();

        // --- 1. Blocklist check ---
        if let Some(block_reason) = self.blocklist.is_blocked(query_name) {
            return Some(VoteResult {
                confidence: 0.93,
                reason: format!(
                    "DNS BLOCKLIST HIT: Process '{}' (PID {}) queried '{}'. Reason: {}",
                    proc_name, pid, query_name, block_reason
                ),
                weight: 0.9,
            });
        }

        // --- 2. DGA/Entropy/Tunneling analysis ---
        let analysis = osoosi_dns::analysis::analyze_domain(query_name);

        match analysis.verdict {
            osoosi_dns::DnsVerdict::Block => {
                return Some(VoteResult {
                    confidence: 0.92,
                    reason: format!(
                        "DNS THREAT (Process Attribution): '{}' (PID {}) resolved '{}'. {} [Entropy: {:.2}]",
                        proc_name, pid, query_name, analysis.reason, analysis.entropy
                    ),
                    weight: 0.85,
                });
            }
            osoosi_dns::DnsVerdict::Suspicious => {
                // For suspicious domains, check if the process is unusual for making DNS queries
                let is_unusual_resolver = !matches!(
                    proc_name.as_str(),
                    "chrome.exe"
                        | "firefox.exe"
                        | "msedge.exe"
                        | "svchost.exe"
                        | "dns.exe"
                        | "dnscache"
                        | "systemd-resolved"
                        | "mDNSResponder"
                        | "curl.exe"
                        | "wget"
                        | "powershell.exe"
                        | "cmd.exe"
                        | "explorer.exe"
                        | "teams.exe"
                        | "slack.exe"
                        | "outlook.exe"
                        | "code.exe"
                        | "osoosi"
                        | "osoosi.exe"
                        | "git.exe"
                );

                if is_unusual_resolver {
                    return Some(VoteResult {
                        confidence: 0.7,
                        reason: format!(
                            "SUSPICIOUS DNS: Unusual process '{}' (PID {}) querying '{}'. {}",
                            proc_name, pid, query_name, analysis.reason
                        ),
                        weight: 0.6,
                    });
                }

                // Known process but suspicious domain — lower weight
                return Some(VoteResult {
                    confidence: 0.5,
                    reason: format!(
                        "DNS Monitor: '{}' queried suspicious domain '{}'. Entropy: {:.2}",
                        proc_name, query_name, analysis.entropy
                    ),
                    weight: 0.4,
                });
            }
            osoosi_dns::DnsVerdict::Allow => {}
        }

        // --- 3. Process-based anomaly detection ---
        // Even if the domain is clean, certain processes should NEVER make DNS queries
        let never_resolves = matches!(
            proc_name.as_str(),
            "lsass.exe"
                | "csrss.exe"
                | "smss.exe"
                | "wininit.exe"
                | "services.exe"
                | "winlogon.exe"
                | "dwm.exe"
        );

        if never_resolves {
            return Some(VoteResult {
                confidence: 0.88,
                reason: format!(
                    "ANOMALOUS DNS: System process '{}' (PID {}) made DNS query to '{}'. \
                     This process should never make outbound DNS queries. \
                     Possible code injection or process hollowing.",
                    proc_name, pid, query_name
                ),
                weight: 0.85,
            });
        }

        // --- 4. Rapid-fire DGA beaconing detection ---
        // If the query resolved to NXDOMAIN (failure), it might be DGA probing
        if query_status.contains("NXDOMAIN") || query_status == "5" || query_results.is_empty() {
            // Failed DNS lookups from non-browser processes are suspicious
            let is_browser = matches!(
                proc_name.as_str(),
                "chrome.exe" | "firefox.exe" | "msedge.exe" | "safari"
            );
            if !is_browser && analysis.entropy > 3.0 {
                return Some(VoteResult {
                    confidence: 0.75,
                    reason: format!(
                        "DGA PROBE: '{}' (PID {}) queried '{}' which resolved to NXDOMAIN. \
                         Entropy {:.2} suggests algorithmically generated domain. \
                         Possible C2 channel probing.",
                        proc_name, pid, query_name, analysis.entropy
                    ),
                    weight: 0.7,
                });
            }
        }

        None
    }
}

/// Sigma Detection Voter
pub struct SigmaVoter {
    pub engine: Arc<crate::sigma::SigmaEngine>,
}

#[async_trait]
impl ThreatVoter for SigmaVoter {
    fn name(&self) -> String {
        "Sigma-Engine".to_string()
    }
    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        let matches = self.engine.check(event);
        if matches.is_empty() {
            return None;
        }

        let mut reason = String::new();
        let mut max_confidence = 0.0f32;

        for rule in matches {
            let tags_str = if !rule.tags.is_empty() {
                format!(" Tags: [{}]", rule.tags.join(", "))
            } else {
                String::new()
            };
            reason.push_str(&format!("[{}{}] ", rule.title, tags_str));
            let conf = match rule.level.as_deref() {
                Some("critical") => 0.98,
                Some("high") => 0.85,
                Some("medium") => 0.65,
                _ => 0.50,
            };
            max_confidence = max_confidence.max(conf);
        }

        Some(VoteResult {
            confidence: max_confidence,
            reason: format!("Sigma Match: {}", reason),
            weight: 1.0,
        })
    }
    fn stats(&self) -> serde_json::Value {
        serde_json::json!({
            "total_detections": self.engine.total_detections.load(std::sync::atomic::Ordering::Relaxed),
            "rule_count": self.engine.check_rule_count()
        })
    }
}

/// Atomic IOC Voter
pub struct IocVoter {
    pub engine: Arc<crate::ioc::IocEngine>,
}

#[async_trait]
impl ThreatVoter for IocVoter {
    fn name(&self) -> String {
        "IOC-Scanner".to_string()
    }
    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        let matches = self.engine.check_event(event);
        if matches.is_empty() {
            return None;
        }

        let m = &matches[0];
        Some(VoteResult {
            confidence: 1.0, // IOCs are high fidelity
            reason: format!(
                "IOC Match ({:?}): {} (Source: {})",
                m.kind, m.indicator, m.source
            ),
            weight: 1.0,
        })
    }
    fn stats(&self) -> serde_json::Value {
        serde_json::json!({
            "total_detections": self.engine.total_detections.load(std::sync::atomic::Ordering::Relaxed),
            "indicator_count": self.engine.indicator_count()
        })
    }
}

/// Multi-Vector Credential, Vault, Secret Store & DLL Proxy Guard (MITRE ATT&CK T1003 / T1555 / T1552)
/// Covers process memory dumping, Credential Manager, Vault, DPAPI, SAM/LSA, NTDS, IIS & Browser stores.
#[derive(Default, Clone, Copy)]
pub struct CredentialGuardVoter;

#[async_trait]
impl ThreatVoter for CredentialGuardVoter {
    fn name(&self) -> String {
        "CredentialGuard-Memory".to_string()
    }

    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        let has_cmdline = event.data.get("CommandLine").is_some()
            || event.data.get("command_line").is_some()
            || event.data.get("cmdline").is_some();

        if event.event_id != 1 && event.event_id != 10 && event.event_id != 4688 && !has_cmdline {
            return None;
        }

        let raw_cmdline = event
            .data
            .get("CommandLine")
            .or_else(|| event.data.get("command_line"))
            .or_else(|| event.data.get("cmdline"))
            .or_else(|| event.data.get("Command"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let cmdline = deobfuscate_command_line(raw_cmdline).to_ascii_lowercase();

        let image = event
            .data
            .get("Image")
            .or_else(|| event.data.get("NewProcessName"))
            .or_else(|| event.data.get("ProcessName"))
            .or_else(|| event.data.get("ImagePath"))
            .or_else(|| event.data.get("SourceImage"))
            .or_else(|| event.data.get("image"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        let target_image = event
            .data
            .get("TargetImage")
            .or_else(|| event.data.get("target_image"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        let granted_access = event
            .data
            .get("GrantedAccess")
            .or_else(|| event.data.get("granted_access"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        let call_trace = event
            .data
            .get("CallTrace")
            .or_else(|| event.data.get("call_trace"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        // Vector 1: LSASS & Process Memory Dumpers (T1003.001)
        if (cmdline.contains("comsvcs.dll") || image.contains("comsvcs.dll"))
            && (cmdline.contains("minidump")
                || cmdline.contains("lsass")
                || cmdline.contains("#24")
                || cmdline.contains("full"))
        {
            return Some(VoteResult {
                confidence: 0.96,
                reason: format!("[CredentialGuard-Memory]: LSASS Memory Dumper (T1003.001): comsvcs.dll MiniDump invocation: {}", cmdline),
                weight: 1.25,
            });
        }

        let known_dumpers = [
            "procdump", "nanodump", "pypykatz", "mimikatz", "sekurlsa", "lsadump", "dumpert",
            "outflank",
        ];
        for tool in &known_dumpers {
            if image.contains(tool) || cmdline.contains(tool) {
                let is_dedicated = matches!(
                    *tool,
                    "pypykatz" | "mimikatz" | "sekurlsa" | "lsadump" | "nanodump" | "outflank"
                );
                let targets_lsass = cmdline.contains("lsass")
                    || cmdline.contains("-ma")
                    || target_image.ends_with("lsass.exe")
                    || target_image.contains("\\lsass.exe");
                if is_dedicated || targets_lsass {
                    return Some(VoteResult {
                        confidence: 0.96,
                        reason: format!("[CredentialGuard-Memory]: LSASS Memory Dumper (T1003.001): Known dumper tool pattern ({}): {}", tool, cmdline),
                        weight: 1.25,
                    });
                }
            }
        }

        if (image.contains("rdrleakdiag.exe") || cmdline.contains("rdrleakdiag"))
            && (cmdline.contains("/fullmemdmp") || cmdline.contains("/p") || cmdline.contains("-p"))
        {
            return Some(VoteResult {
                confidence: 0.96,
                reason: format!("[CredentialGuard-Memory]: LSASS Memory Dumper (T1003.001): rdrleakdiag memory dumper abuse: {}", cmdline),
                weight: 1.25,
            });
        }

        if (image.contains("tttracer.exe") || cmdline.contains("tttracer"))
            && (cmdline.contains("-dumpfull") || cmdline.contains("-attach"))
        {
            return Some(VoteResult {
                confidence: 0.96,
                reason: format!("[CredentialGuard-Memory]: LSASS Memory Dumper (T1003.001): tttracer time travel tracer memory dump abuse: {}", cmdline),
                weight: 1.25,
            });
        }

        if (image.contains("sqldumper.exe") || cmdline.contains("sqldumper"))
            && cmdline.contains("0x01100")
        {
            return Some(VoteResult {
                confidence: 0.96,
                reason: format!("[CredentialGuard-Memory]: LSASS Memory Dumper (T1003.001): sqldumper memory dumper abuse: {}", cmdline),
                weight: 1.25,
            });
        }

        if (image.contains("createdump.exe") || cmdline.contains("createdump"))
            && (cmdline.contains("-u") || cmdline.contains("-f"))
        {
            return Some(VoteResult {
                confidence: 0.96,
                reason: format!("[CredentialGuard-Memory]: LSASS Memory Dumper (T1003.001): createdump core dump abuse: {}", cmdline),
                weight: 1.25,
            });
        }

        if (image.contains("werfault.exe") || cmdline.contains("werfault"))
            && cmdline.contains("-u")
            && cmdline.contains("-p")
        {
            return Some(VoteResult {
                confidence: 0.96,
                reason: format!("[CredentialGuard-Memory]: LSASS Memory Dumper (T1003.001): WerFault crash report dump abuse: {}", cmdline),
                weight: 1.25,
            });
        }

        // Vector 2: Windows Credential Manager, Vault, DPAPI & GUI/DLL Applets (T1003 / T1555.004)
        if cmdline.contains("keymgr.dll")
            || cmdline.contains("krshowkeymgr")
            || ((image.contains("rundll32") || cmdline.contains("rundll32"))
                && cmdline.contains("keymgr"))
        {
            return Some(VoteResult {
                confidence: 0.98,
                reason: format!("[CredentialGuard-Memory]: Windows Credential Manager & Vault Extraction (T1003.007 / T1003 / T1555.004): keymgr.dll invocation: {}", cmdline),
                weight: 1.50,
            });
        }

        if image.ends_with("credwiz.exe") || cmdline.contains("credwiz") {
            return Some(VoteResult {
                confidence: 0.96,
                reason: format!("[CredentialGuard-Memory]: Windows Credential Manager & Vault Extraction (T1003): credwiz.exe credential backup wizard: {}", cmdline),
                weight: 1.25,
            });
        }

        if (image.ends_with("vaultcmd.exe") || cmdline.contains("vaultcmd"))
            && (cmdline.contains("/list")
                || cmdline.contains("/listcreds")
                || cmdline.contains("/listproperties")
                || cmdline.contains("/listschema")
                || cmdline.is_empty())
        {
            return Some(VoteResult {
                confidence: 0.96,
                reason: format!("[CredentialGuard-Memory]: Windows Credential Manager & Vault Extraction (T1555.004): vaultcmd.exe credential enumeration: {}", cmdline),
                weight: 1.25,
            });
        }

        if (image.ends_with("cmdkey.exe") || cmdline.contains("cmdkey"))
            && (cmdline.contains("/list") || cmdline.contains("/generic") || cmdline.contains("-l"))
        {
            return Some(VoteResult {
                confidence: 0.96,
                reason: format!("[CredentialGuard-Memory]: Windows Credential Manager & Vault Extraction (T1555.004): cmdkey credential enumeration: {}", cmdline),
                weight: 1.25,
            });
        }

        if (image.contains("control.exe")
            || cmdline.contains("control.exe")
            || cmdline.contains("control "))
            && (cmdline.contains("credentialmanager")
                || cmdline.contains("srchadmin.dll")
                || cmdline.contains("/name microsoft.credentialmanager"))
        {
            return Some(VoteResult {
                confidence: 0.96,
                reason: format!("[CredentialGuard-Memory]: Windows Credential Manager & Vault Extraction (T1003): control.exe credential manager applet: {}", cmdline),
                weight: 1.25,
            });
        }

        if cmdline.contains("dpapi::")
            || cmdline.contains("cryptunprotectdata")
            || cmdline.contains("passwordvault")
            || cmdline.contains("credenumerate")
            || cmdline.contains("get-storedcredential")
        {
            return Some(VoteResult {
                confidence: 0.96,
                reason: format!("[CredentialGuard-Memory]: Windows Credential Manager & Vault Extraction (T1555.004): DPAPI or password vault extraction: {}", cmdline),
                weight: 1.25,
            });
        }

        // Vector 3: Registry SAM / SECURITY / SYSTEM / LSA Secrets Extraction (T1003.002 / T1003.004)
        let is_reg_tool = image.ends_with("reg.exe")
            || cmdline.starts_with("reg ")
            || cmdline.contains("reg.exe ")
            || image.ends_with("esentutl.exe")
            || cmdline.contains("esentutl");
        let has_save_op = cmdline.contains("save")
            || cmdline.contains("export")
            || cmdline.contains("/y")
            || cmdline.contains("/vss");
        let has_hive_target = cmdline.contains("hklm\\sam")
            || cmdline.contains("hklm\\system")
            || cmdline.contains("hklm\\security")
            || cmdline.contains("\\sam")
            || cmdline.contains("\\system")
            || cmdline.contains("\\security")
            || cmdline.contains("policy\\secrets")
            || cmdline.contains("lsa\\jd")
            || cmdline.contains("lsa\\skew1")
            || cmdline.contains("lsa\\gbg")
            || cmdline.contains("lsa\\data");

        if is_reg_tool && has_save_op && has_hive_target {
            return Some(VoteResult {
                confidence: 0.96,
                reason: format!("[CredentialGuard-Memory]: SAM/SECURITY Hive Extraction (T1003.002): Registry hive extraction detected: {}", cmdline),
                weight: 1.25,
            });
        }

        let lsa_tools = [
            "powerdump",
            "dumper.ps1",
            "invoke-powerdump",
            "get-lsasecret",
            "get-bootkey",
            "secretsdump",
        ];
        for tool in &lsa_tools {
            if cmdline.contains(tool) || image.contains(tool) {
                return Some(VoteResult {
                    confidence: 0.96,
                    reason: format!("[CredentialGuard-Memory]: SAM/SECURITY Hive Extraction (T1003.002): LSA / SAM secret dumping script pattern ({}): {}", tool, cmdline),
                    weight: 1.25,
                });
            }
        }

        // Vector 4: Active Directory NTDS.dit, Volume Shadow Copy & DCSync (T1003.003 / T1003.006)
        if (image.ends_with("ntdsutil.exe") || cmdline.contains("ntdsutil"))
            && (cmdline.contains("ac i ntds")
                || cmdline.contains("ifm")
                || cmdline.contains("create full")
                || cmdline.contains("activate instance ntds"))
        {
            return Some(VoteResult {
                confidence: 0.96,
                reason: format!("[CredentialGuard-Memory]: Active Directory NTDS.dit Dumping (T1003.003): ntdsutil IFM credential extraction: {}", cmdline),
                weight: 1.25,
            });
        }

        let is_shadow_tool = image.ends_with("vssadmin.exe")
            || cmdline.contains("vssadmin")
            || image.ends_with("diskshadow.exe")
            || cmdline.contains("diskshadow")
            || image.ends_with("wmic.exe")
            || cmdline.contains("wmic");
        if is_shadow_tool
            && (cmdline.contains("shadow")
                || cmdline.contains("ntds.dit")
                || cmdline.contains("system32\\config\\sam")
                || cmdline.contains("create"))
            && (cmdline.contains("ntds.dit")
                || cmdline.contains("config\\sam")
                || cmdline.contains("create"))
        {
            return Some(VoteResult {
                    confidence: 0.96,
                    reason: format!("[CredentialGuard-Memory]: Active Directory NTDS.dit Dumping (T1003.003): Shadow copy credential extraction: {}", cmdline),
                    weight: 1.25,
                });
        }

        if cmdline.contains("dcsync")
            || cmdline.contains("get-adreplaccount")
            || cmdline.contains("dsinternals")
            || cmdline.contains("ntds.dit")
        {
            return Some(VoteResult {
                confidence: 0.96,
                reason: format!("[CredentialGuard-Memory]: Active Directory NTDS.dit Dumping (T1003.006): DCSync / NTDS replication extraction: {}", cmdline),
                weight: 1.25,
            });
        }

        // Vector 5: Service, IIS, NetworkProvider & Browser Credential Harvesting (T1003 / T1552 / T1555.003)
        if image.contains("gsecdump")
            || cmdline.contains("gsecdump")
            || cmdline.contains("nppspy")
            || cmdline.contains("networkprovider\\order")
            || (cmdline.contains("wdigest") && cmdline.contains("uselogoncredential"))
        {
            return Some(VoteResult {
                confidence: 0.96,
                reason: format!("[CredentialGuard-Memory]: Service & App Credential Harvesting (T1003): Credential filter/provider extraction: {}", cmdline),
                weight: 1.25,
            });
        }

        if (image.ends_with("appcmd.exe") || cmdline.contains("appcmd"))
            && (cmdline.contains("list apppool")
                || cmdline.contains("list vdir")
                || cmdline.contains("/text:*")
                || cmdline.contains("password")
                || cmdline.contains("processmodel"))
        {
            return Some(VoteResult {
                confidence: 0.96,
                reason: format!("[CredentialGuard-Memory]: Service & App Credential Harvesting (T1552): appcmd IIS plaintext credential dump: {}", cmdline),
                weight: 1.25,
            });
        }

        let browser_targets = ["login data", "web data", "key4.db", "logins.json"];
        let copy_tools = [
            "copy",
            "cp",
            "esentutl",
            "sqlite",
            "python",
            "powershell",
            "cmd",
        ];
        let targets_browser_db = browser_targets.iter().any(|bt| cmdline.contains(bt));
        let uses_copy_tool = copy_tools
            .iter()
            .any(|ct| image.contains(ct) || cmdline.contains(ct));
        if targets_browser_db && uses_copy_tool {
            return Some(VoteResult {
                confidence: 0.96,
                reason: format!("[CredentialGuard-Memory]: Browser Credential Harvesting (T1555.003): Unauthorized browser database extraction: {}", cmdline),
                weight: 1.25,
            });
        }

        // Vector 6: Direct LSASS Process Handle Access (T1003.001)
        if event.event_id == 10
            && (target_image.ends_with("lsass.exe") || target_image.ends_with("\\lsass.exe"))
        {
            let high_priv_access = [
                "0x1fffff", "0x1410", "0x1010", "0x1438", "0x143a", "0x1400", "0x1f0fff",
                "0x1f1fff", "0x1f2fff", "0x1f3fff",
            ]
            .iter()
            .any(|mask| granted_access.contains(mask));

            // Whitelist legitimate core OS and security services opening LSASS
            let is_legit_source = image.ends_with("\\csrss.exe")
                || image.ends_with("\\wininit.exe")
                || image.ends_with("\\services.exe")
                || image.ends_with("\\svchost.exe")
                || image.ends_with("\\msmpeng.exe")
                || image.ends_with("\\securityhealthservice.exe")
                || image.ends_with("\\osoosi.exe")
                || image.ends_with("\\oshoosi.exe");

            if high_priv_access && !is_legit_source {
                return Some(VoteResult {
                    confidence: 0.96,
                    reason: format!(
                        "[CredentialGuard-Memory]: Direct LSASS Process Handle Access (T1003.001): Suspicious ProcessAccess {} to LSASS with GrantedAccess {} (CallTrace: {})",
                        image, granted_access, call_trace.chars().take(80).collect::<String>()
                    ),
                    weight: 1.25,
                });
            }
        }

        // Vector 7: Linux & Cross-Platform Local Credential Dumping & Post-Compromise Extraction (T1003.007 / T1003.008 / T1552)
        // 7a. Dedicated Linux credential dumpers
        let linux_dumpers = [
            "mimipenguin",
            "lazagne",
            "unshadow",
            "linpeas",
            "linuxprivchecker",
            "sudokill",
            "3snake",
        ];
        if linux_dumpers
            .iter()
            .any(|d| image.contains(d) || cmdline.contains(d))
        {
            return Some(VoteResult {
                confidence: 0.98,
                reason: format!(
                    "[CredentialGuard-Memory]: Linux Credential Dumper Tool Detected (T1003.007 / T1552): {}",
                    cmdline
                ),
                weight: 1.50,
            });
        }

        // 7b. Unauthorized /etc/shadow, /etc/gshadow, /etc/security/opasswd, /etc/master.passwd dumping
        let shadow_targets = [
            "/etc/shadow",
            "/etc/gshadow",
            "/etc/security/opasswd",
            "/etc/master.passwd",
        ];
        if shadow_targets.iter().any(|t| cmdline.contains(t)) {
            let reader_tools = [
                "cat ", "grep ", "awk ", "sed ", "cp ", "tar ", "base64", "head ", "tail ",
                "less ", "more ", "strings ", "xxd", "od ", "dd ", "python", "perl", "ruby", "php",
                "node", "curl", "wget",
            ];
            let legit_auth = [
                "sshd",
                "passwd",
                "unix_chkpwd",
                "useradd",
                "usermod",
                "userdel",
                "chage",
                "gpasswd",
                "newusers",
                "chpasswd",
                "login",
                "su",
                "sudo",
                "systemd",
                "pam",
            ];
            let is_legit_auth = legit_auth
                .iter()
                .any(|b| image.ends_with(b) || image.contains(&format!("/{b}")));
            let is_reader = reader_tools
                .iter()
                .any(|r| cmdline.contains(r) || image.contains(r.trim()));
            if is_reader && !is_legit_auth {
                return Some(VoteResult {
                    confidence: 0.98,
                    reason: format!(
                        "[CredentialGuard-Memory]: Unauthorized Linux Shadow Password File Dumping (T1003.008 / T1552.001): {}",
                        cmdline
                    ),
                    weight: 1.50,
                });
            }
        }

        // 7c. Linux process memory dumping targeting credential processes or /proc memory scraping
        let is_gdb_or_gcore = (image.contains("gcore") || cmdline.contains("gcore"))
            || ((image.contains("gdb") || cmdline.contains("gdb"))
                && (cmdline.contains("-p")
                    || cmdline.contains("--pid")
                    || cmdline.contains("attach")
                    || cmdline.contains("dump memory")));
        let is_proc_mem_scrape = cmdline.contains("/mem")
            && (cmdline.contains("/proc/")
                || image.contains("dd")
                || image.contains("cat")
                || image.contains("python")
                || cmdline.contains("dd ")
                || cmdline.contains("cat "));

        let cred_procs = [
            "sshd",
            "sudo",
            "su",
            "gpg-agent",
            "ssh-agent",
            "gnome-keyring",
            "kwalletd",
            "vsftpd",
            "postgres",
            "mysqld",
        ];
        let targets_cred_proc = cred_procs
            .iter()
            .any(|p| cmdline.contains(p) || target_image.contains(p));
        if (is_gdb_or_gcore && (targets_cred_proc || cmdline.contains("dump")))
            || (is_proc_mem_scrape && (targets_cred_proc || cmdline.contains("/proc/self/mem")))
        {
            return Some(VoteResult {
                confidence: 0.98,
                reason: format!(
                    "[CredentialGuard-Memory]: Linux Process Memory Credential Dumping (T1003.007): {}",
                    cmdline
                ),
                weight: 1.50,
            });
        }

        // 7d. /etc/ld.so.preload rootkit tampering
        if cmdline.contains("/etc/ld.so.preload")
            || event
                .data
                .get("TargetFilename")
                .and_then(|v| v.as_str())
                .map(|f| f.contains("/etc/ld.so.preload"))
                .unwrap_or(false)
        {
            return Some(VoteResult {
                confidence: 0.98,
                reason: format!(
                    "[CredentialGuard-Memory]: Linux Shared Library Hijack / Rootkit Tampering via /etc/ld.so.preload (T1574.006): {}",
                    cmdline
                ),
                weight: 1.50,
            });
        }

        None
    }
}

/// Browser & HTTP Archive (HAR) Layer-7 Inspector Voter
/// Evaluates W3C .har logs and HTTP stream artifacts across prompt injection,
/// credential exfiltration, SSRF, drive-by payloads, and C2 beaconing.
pub struct HarTrafficVoter;

#[async_trait]
impl ThreatVoter for HarTrafficVoter {
    fn name(&self) -> String {
        "HAR-L7-Inspector".to_string()
    }

    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        let is_har_event = event.event_id == 77
            || event.data.get("HarContent").is_some()
            || event
                .data
                .get("TargetFilename")
                .or_else(|| event.data.get("FilePath"))
                .or_else(|| event.data.get("TargetFile"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_ascii_lowercase().ends_with(".har"))
                .unwrap_or(false);

        if !is_har_event {
            return None;
        }

        let har_json = if let Some(content) = event.data.get("HarContent").and_then(|v| v.as_str())
        {
            Some(content.to_string())
        } else if let Some(target) = event
            .data
            .get("TargetFilename")
            .or_else(|| event.data.get("FilePath"))
            .or_else(|| event.data.get("TargetFile"))
            .and_then(|v| v.as_str())
        {
            std::fs::read_to_string(target).ok()
        } else {
            None
        };

        if let Some(raw) = har_json {
            let label = event
                .data
                .get("TargetFilename")
                .or_else(|| event.data.get("FilePath"))
                .and_then(|v| v.as_str())
                .unwrap_or("HAR-Inspection");
            if let Ok(report) = crate::traffic_adapter::parse_and_inspect_har_json(&raw, label) {
                if report.highest_threat_score >= 0.50 {
                    return Some(VoteResult {
                        confidence: report.highest_threat_score.min(0.98),
                        reason: format!(
                            "[HAR-L7-Inspector]: {} malicious entries detected across [{}] - {}",
                            report.malicious_entries,
                            report.detected_vectors.join(", "),
                            report.primary_verdict
                        ),
                        weight: 1.25,
                    });
                }
            }
        }

        None
    }
}

/// Liquid Mercury Fluid-Dynamics & Multi-Pore Containment Voter
/// Evaluates agent actuation bursts, pore entropy, and Rayleigh-Plateau impact shattering.
#[derive(Default, Clone, Copy)]
pub struct MercuryFluidVoter;

#[async_trait]
impl ThreatVoter for MercuryFluidVoter {
    fn name(&self) -> String {
        "Mercury-Fluid-Dynamics".to_string()
    }

    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        let is_mercury_event = event.data.get("MercuryPhysics").is_some()
            || event.data.get("PoreClass").is_some()
            || event.data.get("WeberNumber").is_some()
            || event.data.get("AgentLineageId").is_some()
            || event.data.get("AgentBreakoutVector").is_some();

        if is_mercury_event {
            let weber = event
                .data
                .get("WeberNumber")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let state = event
                .data
                .get("PassivationState")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown");
            let pore = event
                .data
                .get("PoreClass")
                .and_then(|v| v.as_str())
                .unwrap_or("Pore");
            let confidence =
                if weber >= 12.0 || state.contains("Passivated") || state.contains("Shattered") {
                    0.96
                } else {
                    0.85
                };

            return Some(VoteResult {
                confidence,
                reason: format!(
                    "[Mercury-Fluid-Dynamics]: Multi-pore agent breakout containment trigger (Pore={}, We={:.2}, State={})",
                    pore, weber, state
                ),
                weight: 1.30,
            });
        }

        None
    }
}

/// Nonlinear Spider-Web Continuum Mechanics & Exposure-Bounded Containment Voter
/// Evaluates dragline silk strain regimes, sacrificial autotomy, and the Cranford-Buehler inequality:
/// Maximum Exposure E_max <= R_enforced * (T_detect + T_contain) <= B_max.
#[derive(Default, Clone, Copy)]
pub struct SpiderWebPhysicsVoter;

#[async_trait]
impl ThreatVoter for SpiderWebPhysicsVoter {
    fn name(&self) -> String {
        "SpiderWeb-Containment".to_string()
    }

    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        let is_spider_event = event.data.get("SpiderWeb").is_some()
            || event.data.get("SilkRegime").is_some()
            || event.data.get("StrainEpsilon").is_some()
            || event.data.get("SacrificialFracture").is_some()
            || event.data.get("BusinessPolicyViolation").is_some()
            || event.data.get("ExposureBoundTracker").is_some()
            || event.data.get("AgentIdentityToken").is_some()
            || event.data.get("UntrustedSource").is_some()
            || event.data.get("PromptInjectionExfil").is_some();

        if is_spider_event {
            let regime = event
                .data
                .get("SilkRegime")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let strain = event
                .data
                .get("StrainEpsilon")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let fracture = event
                .data
                .get("SacrificialFracture")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let viol = event
                .data
                .get("BusinessPolicyViolation")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let (confidence, weight) = if fracture
                || strain >= 0.35
                || regime.contains("Sacrificial")
                || regime.contains("REGIME_IV")
            {
                (0.98, 1.40)
            } else if strain >= 0.20
                || regime.contains("StrainStiffening")
                || regime.contains("REGIME_III")
            {
                (0.90, 1.30)
            } else if strain >= 0.02
                || regime.contains("EntropicUnfolding")
                || regime.contains("REGIME_II")
            {
                (0.75, 1.15)
            } else {
                (0.60, 1.0)
            };

            return Some(VoteResult {
                confidence,
                reason: format!(
                    "[SpiderWeb-Containment]: Nonlinear silk continuum threshold triggered (Regime={}, Strain={:.3}, Fracture={}, Violation={})",
                    if regime.is_empty() { "ActiveRegime" } else { regime },
                    strain,
                    fracture,
                    if viol.is_empty() { "None" } else { viol }
                ),
                weight,
            });
        }

        None
    }
}

/// Strips Windows command-line obfuscation characters (`^`, `` ` ``, empty quotes `""` and `''`),
/// detects PowerShell `-EncodedCommand` / `-enc` / `-e` Base64 payloads (tokens of length >= 12
/// matching `[A-Za-z0-9+/=]+` after `-e` / `-enc` / `-encodedcommand`), decodes them using
/// `base64::engine::general_purpose::STANDARD` (both UTF-16LE and UTF-8), and appends the decoded
/// command string to the normalized string.
pub fn deobfuscate_command_line(raw: &str) -> String {
    use base64::Engine;

    let mut cleaned = raw
        .replace("\"\"", "")
        .replace("''", "")
        .replace(['^', '`'], "");

    let tokens: Vec<&str> = cleaned.split_whitespace().collect();
    let mut decoded_parts: Vec<String> = Vec::new();

    for (i, token) in tokens.iter().enumerate() {
        let t_lower = token.to_ascii_lowercase();
        let candidate_b64 = if t_lower == "-e"
            || t_lower == "-enc"
            || t_lower == "-encodedcommand"
            || t_lower == "/e"
            || t_lower == "/enc"
            || t_lower == "/encodedcommand"
        {
            tokens.get(i + 1).copied()
        } else if t_lower.starts_with("-enc:")
            || t_lower.starts_with("/enc:")
            || t_lower.starts_with("-e:")
            || t_lower.starts_with("/e:")
        {
            token.split_once(':').map(|x| x.1)
        } else if t_lower.starts_with("-encodedcommand:") || t_lower.starts_with("/encodedcommand:")
        {
            token.split_once(':').map(|x| x.1)
        } else {
            None
        };

        if let Some(cand) = candidate_b64 {
            let cand_clean = cand.trim_matches(|c| c == '"' || c == '\'' || c == '^' || c == '`');
            if cand_clean.len() >= 12
                && cand_clean
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
            {
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(cand_clean) {
                    if bytes.len() >= 4 {
                        // Attempt UTF-16LE decoding (standard for PowerShell -EncodedCommand)
                        if bytes.len() % 2 == 0 {
                            let u16s: Vec<u16> = bytes
                                .as_chunks::<2>()
                                .0
                                .iter()
                                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                                .collect();
                            let utf16_str = String::from_utf16_lossy(&u16s);
                            if utf16_str.chars().any(|c| c.is_alphanumeric()) {
                                decoded_parts.push(utf16_str);
                            }
                        }
                        // Attempt UTF-8 decoding
                        if let Ok(utf8_str) = std::str::from_utf8(&bytes) {
                            if utf8_str.chars().any(|c| c.is_alphanumeric()) {
                                decoded_parts.push(utf8_str.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    if !decoded_parts.is_empty() {
        cleaned.push(' ');
        cleaned.push_str(&decoded_parts.join(" "));
    }

    cleaned
}

pub struct ProcessInjectionVoter;

#[async_trait]
impl ThreatVoter for ProcessInjectionVoter {
    fn name(&self) -> String {
        "ProcessInjection-Memory".to_string()
    }

    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        if event.event_id == 8 {
            let source_image = event
                .data
                .get("SourceImage")
                .or_else(|| event.data.get("source_image"))
                .or_else(|| event.data.get("Image"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let target_image = event
                .data
                .get("TargetImage")
                .or_else(|| event.data.get("target_image"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();

            if !source_image.is_empty() && !target_image.is_empty() {
                let src_lower = source_image.to_ascii_lowercase();
                let tgt_lower = target_image.to_ascii_lowercase();

                let is_trusted_csr = src_lower.ends_with("csrss.exe")
                    || src_lower.ends_with("wininit.exe")
                    || src_lower.ends_with("services.exe");

                if src_lower != tgt_lower && !is_trusted_csr {
                    return Some(VoteResult {
                        confidence: 0.95,
                        reason: format!(
                            "Remote thread injection detected (T1055.001): {} injected thread into {}",
                            source_image, target_image
                        ),
                        weight: 1.25,
                    });
                }
            }
        } else if event.event_id == 25 {
            let image = event
                .data
                .get("Image")
                .or_else(|| event.data.get("NewProcessName"))
                .or_else(|| event.data.get("image"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let proc_str = if image.is_empty() { "process" } else { image };
            return Some(VoteResult {
                confidence: 0.98,
                reason: format!(
                    "Process image tampering / hollowing detected (T1055.012) on {}",
                    proc_str
                ),
                weight: 1.3,
            });
        }

        None
    }
}

/// Phase-Space Attractor & Zero-Genesis Invariant Voter (`edr-phaselock` + `zero-genesis-capacity` + `zero-algebraic-kernel`).
///
/// Tracks per-PID Takens delay-coordinate manifolds, Rosenstein maximal Lyapunov exponents ($\lambda_{\max}$),
/// pre-visible embryonic wavefunction energy ($\langle \psi \mid \hat{H}_{\text{threat}} \mid \psi \rangle$),
/// and Givens-rotated algebraic kernel null-space leakage.
pub struct PhaseLockAttractorVoter {
    pid_manifolds: dashmap::DashMap<u32, (std::time::Instant, edr_phaselock::PhaseSpaceMonitor)>,
    genesis_vessel: std::sync::Mutex<zero_genesis_capacity::GenesisVessel>,
    algebraic_kernel: std::sync::Mutex<zero_algebraic_kernel::AlgebraicKernelMonitor>,
}

impl Default for PhaseLockAttractorVoter {
    fn default() -> Self {
        Self::new()
    }
}

impl PhaseLockAttractorVoter {
    pub fn new() -> Self {
        Self {
            pid_manifolds: dashmap::DashMap::new(),
            genesis_vessel: std::sync::Mutex::new(
                zero_genesis_capacity::GenesisVessel::default_edr_vessel(
                    b"osoosi-zero-genesis-policy-origin-v1",
                ),
            ),
            algebraic_kernel: std::sync::Mutex::new(
                zero_algebraic_kernel::AlgebraicKernelMonitor::default_edr_monitor(),
            ),
        }
    }
}

#[async_trait]
impl ThreatVoter for PhaseLockAttractorVoter {
    fn name(&self) -> String {
        "EDR-PhaseLock-Attractor".to_string()
    }

    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        let pid = event
            .data
            .get("ProcessId")
            .or_else(|| event.data.get("ProcessID"))
            .or_else(|| event.data.get("process_id"))
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.trim().parse::<u64>().ok()))
            })
            .unwrap_or(0) as u32;

        if pid <= 4 {
            return None;
        }

        if let Some(img) = event.data.get("Image").and_then(|v| v.as_str()) {
            if GemmaVoter::is_known_safe(img) && !matches!(event.event_id, 8 | 10 | 25) {
                return None;
            }
        }

        let cmdline = event
            .data
            .get("CommandLine")
            .or_else(|| event.data.get("command_line"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Compute Shannon byte entropy of command line / payload
        let cmd_entropy = if cmdline.is_empty() {
            0.0
        } else {
            let mut counts = [0usize; 256];
            for &b in cmdline.as_bytes() {
                counts[b as usize] += 1;
            }
            let len = cmdline.len() as f64;
            counts
                .iter()
                .filter(|&&c| c > 0)
                .map(|&c| {
                    let p = (c as f64) / len;
                    -p * p.log2()
                })
                .sum::<f64>()
        };

        let now = std::time::Instant::now();
        let mut entry = self
            .pid_manifolds
            .entry(pid)
            .or_insert_with(|| (now, edr_phaselock::PhaseSpaceMonitor::default_edr_monitor()));
        let delta_ms = now.duration_since(entry.0).as_secs_f64() * 1000.0;
        entry.0 = now;

        let metric = edr_phaselock::PhaseSpaceMonitor::compute_syscall_phase_metric(
            event.event_id,
            delta_ms,
            cmd_entropy,
        );
        let verdict_opt = entry.1.observe_event(metric).ok();
        drop(entry);

        // Evaluate Zero Before Visible Form & Radix-Weighted Origin Displacement on high-risk events
        let is_high_risk_event = matches!(event.event_id, 8 | 10 | 25);
        let (embryo_energy, origin_displacement) = if is_high_risk_event {
            if let Ok(mut gv) = self.genesis_vessel.lock() {
                let ga = gv.observe_transition(
                    &[1.0, cmd_entropy.max(0.5)],
                    &[1.5, 2.0],
                    0.5,
                    &[0.1, 0.2, cmd_entropy * 0.5, 1.0],
                    1,
                    3,
                );
                (ga.pre_form_energy, ga.origin_displacement)
            } else {
                (0.0, 0.0)
            }
        } else {
            (0.0, 0.0)
        };

        if let Some(verdict) = verdict_opt {
            if verdict.is_chaotic_breakout {
                let null_leakage = if let Ok(mut ak) = self.algebraic_kernel.lock() {
                    ak.inspect_and_rotate_kernel(
                        &[
                            verdict.lyapunov_exponent,
                            verdict.mahalanobis_drift,
                            cmd_entropy,
                            embryo_energy,
                        ],
                        0.15,
                    )
                } else {
                    0.0
                };

                return Some(VoteResult {
                    confidence: 0.94,
                    reason: format!(
                        "[EDR-PhaseLock-Attractor]: Chaotic phase-space trajectory breakout on PID {} (Lyapunov λ_max={:.3}, Mahalanobis drift={:.2}, Null-space leakage={:.2}, Embryo energy={:.2}, Origin D0={:.2})",
                        pid,
                        verdict.lyapunov_exponent,
                        verdict.mahalanobis_drift,
                        null_leakage,
                        embryo_energy,
                        origin_displacement
                    ),
                    weight: 1.35,
                });
            }
        }

        None
    }
}

/// Cryptographic BLAKE3 Merkle Allowlist Veto Gate for noisy developer tools
/// (`cargo.exe`, `python.exe`, `rustc.exe`, `node.exe`, `git.exe`, `code.exe`, etc.).
///
/// Verifies tool identities via constant-time Merkle audit path inclusion proofs
/// (`osoosi_audit::nsrl_aslr_merkle::verify_merkle_audit_path`) and suppresses false-positive
/// static/dynamic telemetry noise on engineering workstations unless active inline code
/// execution or process injection/hollowing is present.
#[derive(Debug, Clone)]
pub struct MerkleAllowlistVetoGate {
    merkle_root: String,
    tool_proofs: std::collections::HashMap<String, (String, Vec<(String, bool)>)>,
}

impl Default for MerkleAllowlistVetoGate {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleAllowlistVetoGate {
    pub const CANONICAL_DEV_TOOLS: &'static [&'static str] = &[
        "cargo",
        "cargo.exe",
        "rustc",
        "rustc.exe",
        "rustup",
        "rustup.exe",
        "rust-lld",
        "rust-lld.exe",
        "lld-link",
        "lld-link.exe",
        "link",
        "link.exe",
        "cl",
        "cl.exe",
        "clang",
        "clang.exe",
        "signtool",
        "signtool.exe",
        "wix",
        "wix.exe",
        "candle",
        "candle.exe",
        "light",
        "light.exe",
        "python",
        "python.exe",
        "python3",
        "python3.exe",
        "node",
        "node.exe",
        "git",
        "git.exe",
        "code",
        "code.exe",
        "cc1",
        "ld",
    ];

    pub fn new() -> Self {
        Self::from_tools(Self::CANONICAL_DEV_TOOLS)
    }

    pub fn from_tools(tools: &[&str]) -> Self {
        let mut normalized_tools: Vec<String> = tools
            .iter()
            .map(|t| t.trim().to_ascii_lowercase())
            .filter(|t| !t.is_empty())
            .collect();
        normalized_tools.sort();
        normalized_tools.dedup();

        let leaves: Vec<String> = normalized_tools
            .iter()
            .enumerate()
            .map(|(idx, tool)| {
                osoosi_audit::nsrl_aslr_merkle::compute_nsrl_page_leaf_hash(idx, tool.as_bytes())
            })
            .collect();

        let levels = osoosi_audit::nsrl_aslr_merkle::build_merkle_tree_levels(&leaves);
        let merkle_root = levels
            .last()
            .and_then(|lvl| lvl.first())
            .cloned()
            .unwrap_or_else(|| "0".repeat(64));

        let mut tool_proofs = std::collections::HashMap::with_capacity(normalized_tools.len());
        for (idx, tool) in normalized_tools.into_iter().enumerate() {
            let audit_path =
                osoosi_audit::nsrl_aslr_merkle::generate_merkle_audit_path(&levels, idx);
            tool_proofs.insert(tool, (leaves[idx].clone(), audit_path));
        }

        Self {
            merkle_root,
            tool_proofs,
        }
    }

    pub fn merkle_root(&self) -> &str {
        &self.merkle_root
    }

    /// Evaluates whether the event's binary/command-line qualifies for a deterministic Merkle allowlist veto.
    ///
    /// Returns `Some((canonical_tool, merkle_root))` when:
    /// 1. The event is NOT an explicit injection/hollowing/LSASS access transition (`event_id` 8, 10, 25),
    /// 2. The command line does NOT carry inline code execution (`python -c`, `node -e`, etc., checked via
    ///    `osoosi_types::is_protected_os_shell_or_desktop_binary`), and
    /// 3. The tool's leaf hash passes constant-time BLAKE3 Merkle audit path verification against `merkle_root`.
    pub fn verify_tool_veto(
        &self,
        image_path: &str,
        cmd_line: &str,
        event_id: u32,
    ) -> Option<(String, String)> {
        if matches!(event_id, 8 | 10 | 25) {
            return None;
        }

        let probe_target = if !cmd_line.trim().is_empty() {
            cmd_line.trim()
        } else {
            image_path.trim()
        };
        if probe_target.is_empty() {
            return None;
        }

        // Reject if inline interpreter execution (-c / -e / --eval) is present
        if !osoosi_types::is_protected_os_shell_or_desktop_binary(probe_target)
            && !osoosi_types::is_protected_os_shell_or_desktop_binary(image_path)
        {
            return None;
        }

        let normalized_image = image_path.trim().trim_matches('"').replace('/', "\\");
        let basename = normalized_image
            .rsplit('\\')
            .next()
            .unwrap_or(&normalized_image)
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();

        let (leaf_hash, audit_path) = self.tool_proofs.get(&basename).or_else(|| {
            let stem = basename.strip_suffix(".exe").unwrap_or(&basename);
            self.tool_proofs.get(stem)
        })?;

        if osoosi_audit::nsrl_aslr_merkle::verify_merkle_audit_path(
            leaf_hash,
            audit_path,
            &self.merkle_root,
        ) {
            Some((basename, self.merkle_root.clone()))
        } else {
            None
        }
    }
}

/// Discrete two-channel projection result ($S_1$ static structural entropy vs. $S_2$ runtime privilege/memory transitions).
#[derive(Debug, Clone, PartialEq)]
pub struct DualChannelProjection {
    /// Static structural entropy & packing channel ($S_1 \in [0.0, 1.0]$).
    pub s1_static_entropy: f32,
    /// Runtime privilege & memory transition channel ($S_2 \in [0.0, 1.0]$).
    pub s2_runtime_transition: f32,
    /// Joint nonlinear discrimination score ($D(S_1, S_2) \in [0.0, 1.0]$).
    pub joint_score: f32,
    /// Triggered transition reasons.
    pub transitions: Vec<String>,
}

/// Dual-Channel Discrimination Voter (`S1` Static Structural Entropy vs. `S2` Runtime Privilege & Memory Transitions)
/// coupled with a `MerkleAllowlistVetoGate` for noisy developer tools (`cargo.exe`, `python.exe`, `rustc.exe`, `node.exe`, `git.exe`, `rust-lld.exe`, `signtool.exe`)
/// and an `AdaptiveDevMerkleGuard` for live developer-recompiled workspace binaries (`target/release`, `target/debug`).
///
/// Operates deterministically on discrete event states without continuous microsecond polling.
#[derive(Clone)]
pub struct DualChannelDiscriminationVoter {
    pub veto_gate: MerkleAllowlistVetoGate,
    pub adaptive_merkle_guard: std::sync::Arc<osoosi_audit::nsrl_aslr_merkle::NsrlAslrMerkleGuard>,
}

impl std::fmt::Debug for DualChannelDiscriminationVoter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DualChannelDiscriminationVoter")
            .field("veto_gate", &self.veto_gate)
            .finish()
    }
}

impl Default for DualChannelDiscriminationVoter {
    fn default() -> Self {
        Self::new()
    }
}

impl DualChannelDiscriminationVoter {
    pub fn new() -> Self {
        Self {
            veto_gate: MerkleAllowlistVetoGate::new(),
            adaptive_merkle_guard: std::sync::Arc::new(
                osoosi_audit::nsrl_aslr_merkle::NsrlAslrMerkleGuard::new(),
            ),
        }
    }

    /// Computes Shannon byte entropy in bits per byte $[0.0, 8.0]$.
    pub fn compute_shannon_entropy(bytes: &[u8]) -> f32 {
        if bytes.is_empty() {
            return 0.0;
        }
        let mut counts = [0usize; 256];
        for &b in bytes {
            counts[b as usize] += 1;
        }
        let len = bytes.len() as f32;
        counts
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = (c as f32) / len;
                -p * p.log2()
            })
            .sum::<f32>()
    }

    /// Projects an event's static structural entropy ($S_1$) against its runtime privilege and memory transitions ($S_2$).
    pub fn project_channels(event: &HostSecurityEvent) -> DualChannelProjection {
        let image = event
            .data
            .get("Image")
            .or_else(|| event.data.get("SourceImage"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let cmdline = event
            .data
            .get("CommandLine")
            .or_else(|| event.data.get("command_line"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // --- Channel S1: Static Structural Entropy & Packing ---
        let raw_entropy = event
            .data
            .get("Entropy")
            .or_else(|| event.data.get("ShannonEntropy"))
            .or_else(|| event.data.get("StaticEntropy"))
            .and_then(|v| v.as_f64())
            .map(|v| v as f32)
            .unwrap_or_else(|| {
                if !image.is_empty() {
                    let path = std::path::Path::new(image);
                    if path.is_file() {
                        // Use open_shared_for_merkle (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                        // so entropy inspection never blocks cargo/rust-lld/signtool atomic file replacements!
                        if let Ok(mut f) =
                            osoosi_audit::nsrl_aslr_merkle::open_shared_for_merkle(path)
                        {
                            use std::io::Read;
                            let mut buf = vec![0u8; 65536];
                            if let Ok(n) = f.read(&mut buf) {
                                if n > 0 {
                                    return Self::compute_shannon_entropy(&buf[..n]);
                                }
                            }
                        }
                    }
                }
                Self::compute_shannon_entropy(cmdline.as_bytes())
            });

        let mut s1 = ((raw_entropy - 4.5) / 3.5).clamp(0.0, 1.0);
        if event
            .data
            .get("IsPacked")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            s1 = (s1 + 0.35).clamp(0.0, 1.0);
        }
        if event
            .data
            .get("RWXSection")
            .or_else(|| event.data.get("HasRwxSection"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            s1 = (s1 + 0.30).clamp(0.0, 1.0);
        }

        // --- Channel S2: Runtime Privilege & Memory Transitions ---
        let mut s2: f32 = 0.0;
        let mut transitions = Vec::new();

        if event.event_id == 8 {
            s2 += 0.85;
            transitions.push("CreateRemoteThread(EID=8)".to_string());
        } else if event.event_id == 25 {
            s2 += 0.95;
            transitions.push("ProcessHollowing/Tampering(EID=25)".to_string());
        } else if event.event_id == 10 {
            let target = event
                .data
                .get("TargetImage")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if target.contains("lsass.exe")
                || target.contains("winlogon.exe")
                || target.contains("csrss.exe")
            {
                s2 += 0.92;
                transitions.push(format!("SensitiveProcessAccess({})", target));
            }
        }

        let mem_transition = event
            .data
            .get("MemoryTransition")
            .or_else(|| event.data.get("Protection"))
            .or_else(|| event.data.get("AllocationProtection"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_uppercase();
        if mem_transition.contains("RWX")
            || mem_transition.contains("PAGE_EXECUTE_READWRITE")
            || mem_transition.contains("PROT_EXEC")
            || mem_transition.contains("VIRTUALALLOCEX")
            || mem_transition.contains("NTPROTECTVIRTUALMEMORY")
        {
            s2 += 0.65;
            transitions.push(format!("MemoryTransition({})", mem_transition));
        }

        let priv_transition = event
            .data
            .get("PrivilegeTransition")
            .or_else(|| event.data.get("EnabledPrivileges"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if priv_transition.contains("SeDebugPrivilege")
            || priv_transition.contains("SeTcbPrivilege")
            || priv_transition.contains("SeLoadDriverPrivilege")
            || priv_transition.contains("CAP_SYS_ADMIN")
            || priv_transition.contains("CAP_SYS_PTRACE")
        {
            s2 += 0.55;
            transitions.push(format!("PrivilegeTransition({})", priv_transition));
        }

        if event
            .data
            .get("PrivilegeEscalation")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            s2 += 0.50;
            transitions.push("PrivilegeEscalation".to_string());
        }

        s2 = s2.clamp(0.0, 1.0);
        let joint_score = (0.40 * s1 + 0.60 * s2 + 0.35 * (s1 * s2)).clamp(0.0, 1.0);

        DualChannelProjection {
            s1_static_entropy: s1,
            s2_runtime_transition: s2,
            joint_score,
            transitions,
        }
    }
}

#[async_trait]
impl ThreatVoter for DualChannelDiscriminationVoter {
    fn name(&self) -> String {
        "DualChannel-S1S2-Discriminator".to_string()
    }

    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        let image = event
            .data
            .get("Image")
            .or_else(|| event.data.get("SourceImage"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let cmdline = event
            .data
            .get("CommandLine")
            .or_else(|| event.data.get("command_line"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // 1. Check Merkle Allowlist Veto Gate for noisy developer tools first
        let has_explicit_mem_or_priv_transition = event.data.get("MemoryTransition").is_some()
            || event.data.get("PrivilegeTransition").is_some()
            || event
                .data
                .get("PrivilegeEscalation")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

        if !has_explicit_mem_or_priv_transition {
            if let Some((tool_name, root)) =
                self.veto_gate
                    .verify_tool_veto(image, cmdline, event.event_id)
            {
                return Some(VoteResult {
                    confidence: 0.0,
                    reason: format!(
                        "[DualChannel-Merkle-Veto]: Verified developer tool '{}' via BLAKE3 Merkle allowlist inclusion proof (root={}..); vetoing workstation noise.",
                        tool_name,
                        &root[..12.min(root.len())]
                    ),
                    weight: -1.25,
                });
            }

            // 1b. Adaptive BLAKE3 Merkle Self-Defense & Dev-Recompile Auto-Adaptation for workspace build artifacts
            let target_file = event
                .data
                .get("TargetFilename")
                .or_else(|| event.data.get("TargetImage"))
                .and_then(|v| v.as_str())
                .unwrap_or(image);
            let norm_target = target_file.replace('\\', "/").to_ascii_lowercase();
            let is_workspace_build_artifact = norm_target.contains("/target/release/")
                || norm_target.contains("/target/debug/")
                || norm_target.contains("osoosi-linux-target/release/");

            if is_workspace_build_artifact && !matches!(event.event_id, 8 | 10 | 25) {
                let target_path = std::path::Path::new(target_file);
                if target_path.is_file() {
                    match self
                        .adaptive_merkle_guard
                        .verify_or_adapt_binary(target_path)
                    {
                        osoosi_audit::nsrl_aslr_merkle::AdaptiveMerkleVerdict::Intact {
                            page_merkle_root,
                            build_generation,
                            ..
                        } => {
                            return Some(VoteResult {
                                confidence: 0.0,
                                reason: format!(
                                    "[Adaptive-Merkle-Guard]: Verified workspace build artifact (gen={}, epoch={}, root={}..); vetoing self-lockout.",
                                    build_generation,
                                    build_generation,
                                    &page_merkle_root[..12.min(page_merkle_root.len())]
                                ),
                                weight: -1.35,
                            });
                        }
                        osoosi_audit::nsrl_aslr_merkle::AdaptiveMerkleVerdict::AdaptedToRecompile {
                            new_page_merkle_root,
                            build_generation,
                            ..
                        } => {
                            return Some(VoteResult {
                                confidence: 0.0,
                                reason: format!(
                                    "[Adaptive-Merkle-Guard]: Authorized developer recompile adapted (gen={}, epoch={}, new_root={}..); TPM 2.0 Merkle root rotated.",
                                    build_generation,
                                    build_generation,
                                    &new_page_merkle_root[..12.min(new_page_merkle_root.len())]
                                ),
                                weight: -1.35,
                            });
                        }
                        osoosi_audit::nsrl_aslr_merkle::AdaptiveMerkleVerdict::UnauthorizedTampering {
                            reason,
                            ..
                        } => {
                            return Some(VoteResult {
                                confidence: 0.96,
                                reason: format!(
                                    "[Adaptive-Merkle-Tamper-Alert]: {}",
                                    reason
                                ),
                                weight: 1.50,
                            });
                        }
                    }
                }
            }
        }

        // 2. Discrete Two-Channel (S1 Static Entropy vs S2 Runtime Transition) Projection
        let proj = Self::project_channels(event);
        if proj.s2_runtime_transition > 0.0
            && (proj.joint_score >= 0.55
                || (proj.s1_static_entropy >= 0.45 && proj.s2_runtime_transition >= 0.45))
        {
            return Some(VoteResult {
                confidence: proj.joint_score.max(0.82),
                reason: format!(
                    "[DualChannel-S1S2-Discriminator]: Coupled static/runtime transition detected (S1_entropy={:.2}, S2_runtime={:.2}, Joint={:.2}, Transitions=[{}])",
                    proj.s1_static_entropy,
                    proj.s2_runtime_transition,
                    proj.joint_score,
                    proj.transitions.join(", ")
                ),
                weight: 1.30,
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use osoosi_types::{HostEventSource, HostSecurityEvent};
    use serde_json::json;

    fn make_proc_event(image: &str, cmdline: &str) -> HostSecurityEvent {
        HostSecurityEvent {
            source: HostEventSource::WindowsEventLog,
            event_id: 1,
            timestamp: Utc::now(),
            computer: "TEST-HOST".to_string(),
            data: json!({
                "Image": image,
                "CommandLine": cmdline
            }),
            causal_parent: None,
        }
    }

    #[tokio::test]
    async fn test_credential_guard_voter_all_vectors() {
        let voter = CredentialGuardVoter;

        // 1. rundll32.exe keymgr.dll,KRShowKeyMgr (T1003) and extensionless keymgr,KRShowKeyMgr
        let ev1 = make_proc_event(
            "C:\\Windows\\System32\\rundll32.exe",
            "rundll32.exe keymgr.dll,KRShowKeyMgr",
        );
        let res1 = voter.vote(&ev1).await;
        assert!(
            res1.is_some(),
            "keymgr.dll KRShowKeyMgr must trigger CredentialGuard"
        );
        let v1 = res1.unwrap();
        assert_eq!(v1.confidence, 0.98);
        assert!(v1.reason.contains("T1003"));
        assert!(v1.reason.contains("keymgr.dll"));

        let ev1_extless = make_proc_event(
            "C:\\WINDOWS\\system32\\rundll32.exe",
            "\"C:\\WINDOWS\\system32\\rundll32.exe\" keymgr,KRShowKeyMgr",
        );
        let res1_extless = voter.vote(&ev1_extless).await;
        assert!(
            res1_extless.is_some(),
            "extensionless keymgr,KRShowKeyMgr must trigger CredentialGuard"
        );
        assert_eq!(res1_extless.unwrap().confidence, 0.98);

        // 2. credwiz.exe
        let ev2 = make_proc_event("C:\\Windows\\System32\\credwiz.exe", "credwiz.exe");
        let res2 = voter.vote(&ev2).await;
        assert!(res2.is_some(), "credwiz.exe must trigger CredentialGuard");
        assert!(res2.unwrap().reason.contains("credwiz.exe"));

        // 3. vaultcmd.exe /listcreds:"Windows Credentials"
        let ev3 = make_proc_event(
            "C:\\Windows\\System32\\vaultcmd.exe",
            "vaultcmd.exe /listcreds:\"Windows Credentials\"",
        );
        let res3 = voter.vote(&ev3).await;
        assert!(res3.is_some(), "vaultcmd.exe must trigger CredentialGuard");
        let v3 = res3.unwrap();
        assert!(v3.reason.contains("T1555.004"));

        // 4. cmdkey.exe /list
        let ev4 = make_proc_event("C:\\Windows\\System32\\cmdkey.exe", "cmdkey.exe /list");
        let res4 = voter.vote(&ev4).await;
        assert!(res4.is_some(), "cmdkey.exe must trigger CredentialGuard");
        assert!(res4.unwrap().reason.contains("cmdkey"));

        // 5. reg.exe save HKLM\SAM sam.hiv (T1003.002)
        let ev5 = make_proc_event(
            "C:\\Windows\\System32\\reg.exe",
            "reg.exe save HKLM\\SAM sam.hiv",
        );
        let res5 = voter.vote(&ev5).await;
        assert!(
            res5.is_some(),
            "reg save HKLM\\SAM must trigger CredentialGuard"
        );
        let v5 = res5.unwrap();
        assert!(v5.reason.contains("T1003.002"));

        // 6. ntdsutil "ac i ntds" "ifm" "create full c:\temp" (T1003.003)
        let ev6 = make_proc_event(
            "C:\\Windows\\System32\\ntdsutil.exe",
            "ntdsutil \"ac i ntds\" \"ifm\" \"create full c:\\temp\"",
        );
        let res6 = voter.vote(&ev6).await;
        assert!(
            res6.is_some(),
            "ntdsutil IFM dump must trigger CredentialGuard"
        );
        let v6 = res6.unwrap();
        assert!(v6.reason.contains("T1003.003"));

        // 7. gsecdump -a & appcmd.exe list apppool /text:*
        let ev7a = make_proc_event("C:\\temp\\gsecdump.exe", "gsecdump -a");
        assert!(
            voter.vote(&ev7a).await.is_some(),
            "gsecdump must trigger CredentialGuard"
        );

        let ev7b = make_proc_event(
            "C:\\Windows\\System32\\inetsrv\\appcmd.exe",
            "appcmd.exe list apppool /text:*",
        );
        let res7b = voter.vote(&ev7b).await;
        assert!(
            res7b.is_some(),
            "appcmd.exe credential dump must trigger CredentialGuard"
        );
        assert!(res7b.unwrap().reason.contains("T1552"));

        // 8. Benign: rundll32.exe shell32.dll,Control_RunDLL (must return None - zero false positives!)
        let ev_benign = make_proc_event(
            "C:\\Windows\\System32\\rundll32.exe",
            "rundll32.exe shell32.dll,Control_RunDLL",
        );
        let res_benign = voter.vote(&ev_benign).await;
        assert!(
            res_benign.is_none(),
            "Benign Control_RunDLL must NOT trigger CredentialGuard"
        );
    }

    #[test]
    fn test_deobfuscate_command_line() {
        // Strip caret and empty quotes
        let obf1 = "c^m^d.e^x^e /c \"\"wh^o^am^i\"\"";
        assert_eq!(deobfuscate_command_line(obf1), "cmd.exe /c whoami");

        // PowerShell -EncodedCommand with UTF-16LE payload
        // "whoami" in UTF-16LE: [119, 0, 104, 0, 111, 0, 97, 0, 109, 0, 105, 0] -> d2hvYW1p
        // Base64 for "whoami" UTF-16LE: "dwBoAG8AYQBtAGkA"
        let ps_cmd = "powershell.exe -enc dwBoAG8AYQBtAGkA";
        let deobf = deobfuscate_command_line(ps_cmd);
        assert!(deobf.contains("powershell.exe -enc dwBoAG8AYQBtAGkA"));
        assert!(deobf.contains("whoami"));
    }

    #[tokio::test]
    async fn test_process_injection_voter() {
        let voter = ProcessInjectionVoter;

        // Sysmon Event 8: CreateRemoteThread
        let ev8 = HostSecurityEvent {
            source: HostEventSource::WindowsEventLog,
            event_id: 8,
            timestamp: Utc::now(),
            computer: "TEST-HOST".to_string(),
            data: json!({
                "SourceImage": "C:\\Windows\\Temp\\malware.exe",
                "TargetImage": "C:\\Windows\\System32\\svchost.exe"
            }),
            causal_parent: None,
        };
        let res8 = voter.vote(&ev8).await;
        assert!(res8.is_some());
        let v8 = res8.unwrap();
        assert_eq!(v8.confidence, 0.95);
        assert!(v8.reason.contains("T1055.001"));

        // Sysmon Event 25: ProcessTampering
        let ev25 = HostSecurityEvent {
            source: HostEventSource::WindowsEventLog,
            event_id: 25,
            timestamp: Utc::now(),
            computer: "TEST-HOST".to_string(),
            data: json!({
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "Type": "Image is replaced"
            }),
            causal_parent: None,
        };
        let res25 = voter.vote(&ev25).await;
        assert!(res25.is_some());
        let v25 = res25.unwrap();
        assert_eq!(v25.confidence, 0.98);
        assert!(v25.reason.contains("T1055.012"));
    }

    #[tokio::test]
    async fn test_dual_channel_discrimination_and_merkle_allowlist_veto_gate() {
        let voter = DualChannelDiscriminationVoter::new();
        assert_eq!(voter.veto_gate.merkle_root().len(), 64);

        // 1. Noisy developer tools (cargo.exe, python.exe, rustc.exe, node.exe, git.exe, rust-lld.exe, signtool.exe, wix.exe) without inline code
        //    must pass the BLAKE3 Merkle allowlist inclusion proof and emit a negative veto vote (weight = -1.25).
        for (img, cmd) in [
            (
                "C:\\Users\\dev\\.cargo\\bin\\cargo.exe",
                "cargo.exe build --release",
            ),
            (
                "C:\\Python312\\python.exe",
                "python.exe scripts/submit_to_wdsi.py --all",
            ),
            ("/usr/bin/rustc", "rustc --edition 2021 src/lib.rs"),
            (
                "C:\\Program Files\\nodejs\\node.exe",
                "node.exe dashboard/tests/webui_parity.test.mjs",
            ),
            ("C:\\Program Files\\Git\\cmd\\git.exe", "git.exe status -s"),
            (
                "C:\\Users\\dev\\.rustup\\toolchains\\stable\\bin\\rust-lld.exe",
                "rust-lld.exe -flavor link /OUT:target\\release\\osoosi.exe",
            ),
            (
                "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\x64\\signtool.exe",
                "signtool.exe sign /fd SHA256 target\\release\\osoosi.exe",
            ),
            (
                "C:\\Users\\dev\\wix_tools\\wix.exe",
                "wix.exe build wix\\OshoosiClaw.wxs -arch x64 -out OshoosiClaw.msi",
            ),
        ] {
            let ev = make_proc_event(img, cmd);
            let res = voter
                .vote(&ev)
                .await
                .expect("Dev tool must trigger Merkle veto vote");
            assert_eq!(res.confidence, 0.0);
            assert!(
                res.weight <= -1.0,
                "Expected veto weight <= -1.0, got {}",
                res.weight
            );
            assert!(res.reason.contains("[DualChannel-Merkle-Veto]"));
        }

        // 1b. Workspace build artifact (target/release/*.exe) verified and adapted across recompiles via AdaptiveDevMerkleGuard
        let temp_ws = std::env::temp_dir()
            .join("osoosi_voter_ws_test")
            .join("target")
            .join("release");
        let _ = std::fs::create_dir_all(&temp_ws);
        let ws_bin = temp_ws.join("osoosi_custom_bin.exe");
        let make_valid_rust_bin = |marker: &[u8]| -> Vec<u8> {
            let mut elf = vec![0u8; 8192];
            elf[0..4].copy_from_slice(b"\x7FELF");
            elf[4] = 2;
            elf[5] = 1;
            elf[6] = 1;
            elf[16..18].copy_from_slice(&3u16.to_le_bytes());
            elf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
            elf[20..24].copy_from_slice(&1u32.to_le_bytes());
            elf[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
            elf[32..40].copy_from_slice(&64u64.to_le_bytes());
            elf[52..54].copy_from_slice(&64u16.to_le_bytes());
            elf[54..56].copy_from_slice(&56u16.to_le_bytes());
            elf[56..58].copy_from_slice(&1u16.to_le_bytes());
            let ph = 64;
            elf[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
            elf[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
            elf[ph + 8..ph + 16].copy_from_slice(&4096u64.to_le_bytes());
            elf[ph + 16..ph + 24].copy_from_slice(&0x1000u64.to_le_bytes());
            elf[ph + 24..ph + 32].copy_from_slice(&0x1000u64.to_le_bytes());
            elf[ph + 32..ph + 40].copy_from_slice(&4096u64.to_le_bytes());
            elf[ph + 40..ph + 48].copy_from_slice(&4096u64.to_le_bytes());
            elf[ph + 48..ph + 56].copy_from_slice(&4096u64.to_le_bytes());
            elf[4096..4096 + marker.len()].copy_from_slice(marker);
            elf
        };
        std::fs::write(
            &ws_bin,
            make_valid_rust_bin(b"rustc 1.85.0 .dep-v0 WORKSPACE_BUILD_EPOCH_1"),
        )
        .unwrap();
        let ws_bin_str = ws_bin.to_string_lossy().to_string();

        let ev_ws_v1 = HostSecurityEvent {
            source: HostEventSource::WindowsEventLog,
            event_id: 1,
            timestamp: Utc::now(),
            computer: "TEST-HOST".to_string(),
            data: json!({
                "Image": ws_bin_str,
                "CommandLine": format!("{} --version", ws_bin_str),
                "ParentImage": "C:\\Users\\dev\\.cargo\\bin\\cargo.exe"
            }),
            causal_parent: None,
        };
        let res_ws_v1 = voter
            .vote(&ev_ws_v1)
            .await
            .expect("Workspace build artifact must receive Adaptive-Merkle-Guard veto");
        assert_eq!(res_ws_v1.confidence, 0.0);
        assert!(res_ws_v1.weight <= -1.30);
        assert!(res_ws_v1.reason.contains("[Adaptive-Merkle-Guard]"));

        // Recompile the binary in place with valid compiler provenance and verify automatic Merkle root rotation (Epoch 2)
        std::fs::write(
            &ws_bin,
            make_valid_rust_bin(b"rustc 1.85.0 .dep-v0 WORKSPACE_BUILD_EPOCH_2_RECOMPILED"),
        )
        .unwrap();
        let res_ws_v2 = voter
            .vote(&ev_ws_v1)
            .await
            .expect("Recompiled workspace binary must rotate Merkle root");
        assert_eq!(res_ws_v2.confidence, 0.0);
        assert!(res_ws_v2.weight <= -1.30);
        assert!(res_ws_v2.reason.contains("epoch=2"));

        // Overwrite with unauthorized non-compiler payload -> must emit high-confidence tamper alert (0.96)
        std::fs::write(&ws_bin, b"MZ\x90\x00UNAUTHORIZED_SHELLCODE_TAMPER").unwrap();
        let res_ws_tampered = voter
            .vote(&ev_ws_v1)
            .await
            .expect("Unauthorized binary tampering must emit high-confidence alert");
        assert_eq!(res_ws_tampered.confidence, 0.96);
        assert!(res_ws_tampered
            .reason
            .contains("[Adaptive-Merkle-Tamper-Alert]"));
        let _ = std::fs::remove_dir_all(std::env::temp_dir().join("osoosi_voter_ws_test"));

        // 2. Developer tool abused with inline code (`python -c "..."`) + runtime RWX memory transition
        //    must NOT be vetoed and must trigger S1/S2 dual-channel discrimination!
        let ev_abused_py = HostSecurityEvent {
            source: HostEventSource::WindowsEventLog,
            event_id: 1,
            timestamp: Utc::now(),
            computer: "TEST-HOST".to_string(),
            data: json!({
                "Image": "C:\\Python312\\python.exe",
                "CommandLine": "python.exe -c \"import ctypes; ctypes.windll.kernel32.VirtualAlloc(0, 4096, 0x3000, 0x40)\"",
                "Entropy": 7.4,
                "MemoryTransition": "PAGE_EXECUTE_READWRITE"
            }),
            causal_parent: None,
        };
        let res_abused = voter
            .vote(&ev_abused_py)
            .await
            .expect("Inline code + RWX transition must trigger positive S1/S2 vote");
        assert!(res_abused.confidence >= 0.82);
        assert!(res_abused.weight > 1.0);
        assert!(res_abused
            .reason
            .contains("[DualChannel-S1S2-Discriminator]"));

        // 3. Static high-entropy binary at rest without runtime transition (S2 == 0) must NOT false-positive.
        let ev_static_only = HostSecurityEvent {
            source: HostEventSource::WindowsEventLog,
            event_id: 1,
            timestamp: Utc::now(),
            computer: "TEST-HOST".to_string(),
            data: json!({
                "Image": "C:\\App\\compressed_installer.exe",
                "CommandLine": "compressed_installer.exe --silent",
                "Entropy": 7.8,
                "IsPacked": true
            }),
            causal_parent: None,
        };
        assert!(
            voter.vote(&ev_static_only).await.is_none(),
            "High S1 static entropy without S2 runtime transition must not trigger DualChannel vote"
        );
    }

    #[test]
    fn test_law4_martingale_zero_drift_detector_villes_inequality_slow_drip() {
        let mut detector = MartingaleZeroDriftDetector::new(0.15, 0.75);
        // Zero-drift benign fluctuations around mu_0 = 0.15
        for _ in 0..15 {
            let v = detector.observe_risk_score("agent_worker_1", 0.14);
            assert!(!v.ville_threshold_crossed);
        }

        // Slow-drip low-and-slow exfiltration / beacon ticks at X_k = 0.65 (below single-event 0.85 cutoff)
        let mut crossed = false;
        for _ in 0..60 {
            let v = detector.observe_risk_score("agent_worker_1", 0.65);
            if v.ville_threshold_crossed {
                crossed = true;
                assert!(v.ville_e_process_value >= 1_000_000.0);
                assert!(v.compensator_a_t > 0.0);
                break;
            }
        }
        assert!(
            crossed,
            "Slow-drip positive drift must cross Ville's inequality threshold 1/alpha = 10^6"
        );
    }
}

// ============================================================================
// Law 4: Doob-Meyer Martingale Zero-Drift Law (E[M_{t+1} - M_t | F_t] = 0)
// & Ville's Inequality (P(sup_t E_t >= 1/alpha) <= alpha)
// ============================================================================

/// Verdict emitted by `MartingaleZeroDriftDetector` under Law 4.
#[derive(Debug, Clone, PartialEq)]
pub struct MartingaleDriftVerdict {
    pub stream_id: String,
    pub sample_count: usize,
    pub cumulative_martingale_m_t: f64,
    pub compensator_a_t: f64,
    pub ville_e_process_value: f64,
    pub ville_threshold_crossed: bool,
    pub rationale: String,
}

/// Law 4 Voter / Detector: Tracks the Doob-Meyer decomposition $X_t = M_t + A_t$
/// and Ville's test supermartingale $E_t = \prod_{k=1}^t (1 + \lambda (X_k - \mu_0))$
/// to catch low-and-slow C2 beaconing and slow-drip data exfiltration with false-alarm
/// probability bounded by $\alpha = 10^{-6}$ ($1/\alpha = 10^6$).
#[derive(Debug, Clone)]
pub struct MartingaleZeroDriftDetector {
    pub baseline_mean_mu0: f64,
    pub betting_fraction_lambda: f64,
    pub ville_threshold: f64,
    pub e_process: f64,
    pub cumulative_m_t: f64,
    pub compensator_a_t: f64,
    samples: Vec<f64>,
}

impl MartingaleZeroDriftDetector {
    pub const MAX_SAMPLES: usize = 256;

    pub fn new(baseline_mean_mu0: f64, betting_fraction_lambda: f64) -> Self {
        Self {
            baseline_mean_mu0,
            betting_fraction_lambda: betting_fraction_lambda.clamp(0.05, 0.95),
            ville_threshold: 1_000_000.0,
            e_process: 1.0,
            cumulative_m_t: 0.0,
            compensator_a_t: 0.0,
            samples: Vec::with_capacity(64),
        }
    }

    /// Observes a single event anomaly/DLP risk score $X_k \in [0, 1]$, updates the
    /// Doob-Meyer compensator $A_t$ and Ville $e$-process $E_t$, and shrinks internal
    /// history capacity (`Situation 3`).
    pub fn observe_risk_score(&mut self, stream_id: &str, x_k: f64) -> MartingaleDriftVerdict {
        let innovation = x_k - self.baseline_mean_mu0;
        self.cumulative_m_t += innovation;
        if innovation > 0.0 {
            self.compensator_a_t += innovation;
        }
        let factor = (1.0 + self.betting_fraction_lambda * innovation).max(0.05);
        self.e_process = (self.e_process * factor).clamp(1e-6, 1e18);

        if self.samples.len() >= Self::MAX_SAMPLES {
            self.samples.drain(0..(Self::MAX_SAMPLES / 2));
            self.samples.shrink_to(Self::MAX_SAMPLES);
        }
        self.samples.push(x_k);

        let ville_threshold_crossed = self.e_process >= self.ville_threshold;
        let rationale = if ville_threshold_crossed {
            format!(
                "[Law4-Martingale-Drift-Alert]: Ville's inequality threshold crossed for '{}': E_t={:.2e} >= 10^6, A_t={:.3}",
                stream_id, self.e_process, self.compensator_a_t
            )
        } else {
            format!(
                "[Law4-Martingale-Zero-Drift]: Zero-drift martingale intact for '{}': E_t={:.2}, A_t={:.3}",
                stream_id, self.e_process, self.compensator_a_t
            )
        };

        MartingaleDriftVerdict {
            stream_id: stream_id.to_string(),
            sample_count: self.samples.len(),
            cumulative_martingale_m_t: self.cumulative_m_t,
            compensator_a_t: self.compensator_a_t,
            ville_e_process_value: self.e_process,
            ville_threshold_crossed,
            rationale,
        }
    }
}

#[cfg(test)]
mod hybrid_cve_and_kev_tests {
    use super::kev_product_matches_stem;

    #[test]
    fn test_kev_product_rejects_generic_single_word_stem_collisions() {
        assert!(!kev_product_matches_stem("setup", "action-setup"));
        assert!(!kev_product_matches_stem("file", "HTTP File Server"));
        assert!(!kev_product_matches_stem("server", "HTTP File Server"));
        assert!(!kev_product_matches_stem(
            "update",
            "Windows Update Service"
        ));
        assert!(!kev_product_matches_stem(
            "client",
            "Enterprise Client Agent"
        ));
    }

    #[test]
    fn test_kev_product_matches_specific_products_accurately() {
        assert!(kev_product_matches_stem("action-setup", "action-setup"));
        assert!(kev_product_matches_stem("log4j", "log4j"));
        assert!(kev_product_matches_stem("log4j", "Apache Log4j"));
        assert!(kev_product_matches_stem("winrar", "WinRAR"));
    }
}
