use async_trait::async_trait;
use crate::engine::{ThreatVoter, VoteResult};
use osoosi_types::{SysmonEvent, SysmonEventId};
use osoosi_dp::{DifferentialPrivacy, PrivacyConfig};
use osoosi_audit::MerkleAuditTree;
use std::sync::Arc;
use tracing::{debug, warn};

/// Semantic Intent Voter (Algorithm 2)
pub struct SemanticVoter {
    pub engine: crate::semantic::SemanticEngine,
}

#[async_trait]
impl ThreatVoter for SemanticVoter {
    fn name(&self) -> String {
        "SemanticIntent".to_string()
    }
    async fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
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
    async fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        let guard = self.indicators.read().ok()?;
        let hit = crate::otx_connection::otx_match_sysmon_event(&guard, &self.memory, event);

        hit.map(|reason| VoteResult {
            confidence: crate::otx_connection::OTX_CONSENSUS_CONFIDENCE,
            reason,
            weight: crate::otx_connection::otx_consensus_weight(event),
        })
    }
}

/// Sigma Rule Voter
pub struct SigmaVoter {
    pub engine: Arc<std::sync::RwLock<crate::sigma::SigmaEngine>>,
}

#[async_trait]
impl ThreatVoter for SigmaVoter {
    fn name(&self) -> String {
        "Sigma".to_string()
    }
    async fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        if let Ok(guard) = self.engine.read() {
            let matches = guard.check(event);
            if !matches.is_empty() {
                let rule = &matches[0];
                return Some(VoteResult {
                    confidence: if rule.level == "critical" { 0.95 } else { 0.85 },
                    reason: format!(
                        "Sigma Rule [{}]: {}",
                        rule.title,
                        rule.description.as_deref().unwrap_or("No description")
                    ),
                    weight: 0.8,
                });
            }
        }
        None
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
            last_call: std::sync::Mutex::new(std::time::Instant::now() - std::time::Duration::from_secs(60)),
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
            "osoosi", "sysmon", "sysmon64", "csrss", "lsass", "winlogon", "services", 
            "svchost", "explorer", "taskmgr", "runtimebroker", "searchindexer", 
            "rustc", "cargo", "python", "git", "cursor", "antigravity", "code", "node", "ollama", "npm", "powershell", "cmd"
        ];

        trusted_path || TRUSTED_STEMS.contains(&stem.as_str())
    }
}

#[async_trait]
impl ThreatVoter for GemmaVoter {
    fn name(&self) -> String {
        "LLM-Reasoning".to_string()
    }
    async fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
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
            let mut last = self.last_call.lock().unwrap();
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
        let version = event.product_version.as_deref().unwrap_or("unknown");

        let summary = format!(
            "Process Create: image={} version={} cmdline={}",
            image, version, cmd_line
        );

        match self.analyzer.reason_about_attack(&summary).await {
            Ok(raw_reasoning) => {
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
            Err(_) => {}
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
    async fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        // 1. Self-Protection: Check if unauthorized process is touching Oshoosi files/registry
        if let Some(path) = event.data.get("TargetFilename").and_then(|v| v.as_str()) {
            if osoosi_types::reg_utils::is_self_protection_file_path(path) {
                // If it's not Oshoosi itself or a trusted system process
                let image = event.data.get("Image").and_then(|v| v.as_str()).unwrap_or("");
                if !image.to_lowercase().contains("osoosi") && !image.to_lowercase().contains("system32") {
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
                let image = event.data.get("Image").and_then(|v| v.as_str()).unwrap_or("");
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
               || normalized.contains("system\\currentcontrolset\\services") {
                // Suspicious if not from a known installer
                let image = event.data.get("Image").and_then(|v| v.as_str()).unwrap_or("");
                if !image.to_lowercase().contains("msiexec") && !image.to_lowercase().contains("setup") {
                    return Some(VoteResult {
                        confidence: 0.75,
                        reason: format!("Suspicious Persistence: process {} modifying boot/service key {}", image, normalized),
                        weight: 0.6,
                    });
                }
            }
        }

        // 3. USB Exfiltration Detection (using OpenEDR pattern)
        if event.event_id == SysmonEventId::FileCreate {
            if let Some(path) = event.data.get("TargetFilename").and_then(|v| v.as_str()) {
                // If it's a drive usually associated with USB (D:, E:, etc. that isn't the system drive)
                let p = path.to_lowercase();
                if (p.starts_with("d:\\") || p.starts_with("e:\\") || p.starts_with("f:\\")) 
                   && !p.contains("osoosi") {
                    return Some(VoteResult {
                        confidence: 0.6,
                        reason: format!("Potential USB Exfiltration: file creation on removable media at {}", path),
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
    async fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        let status = event.data.get("SignatureStatus").or_else(|| event.data.get("Signature Status"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        
        let publisher = event.data.get("Signature").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
        
        if status.to_lowercase() == "valid" || status.to_lowercase().contains("trusted") {
            let trusted_publishers = [
                "microsoft", "github, inc.", "google", "apple", "mozilla", 
                "oracle", "amazon", "digicert", "sectigo", "comodo"
            ];
            
            if trusted_publishers.iter().any(|&p| publisher.contains(p)) {
                return Some(VoteResult {
                    confidence: 0.0,
                    reason: format!("Trusted Vendor: {} (Signature: {})", publisher, status),
                    weight: -0.5, // Subtract significant amount from threat score
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
    async fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        let image = event.data.get("Image").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
        if image.contains("git.exe") || image.contains("git-remote-http.exe") {
            // Check for known benign Git artifacts
            let cmd_line = event.data.get("CommandLine").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
            let query = event.data.get("QueryName").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
            
            let benign_git_strings = [
                "crl.comodo.net", "crl.sectigo.com", "crl.digicert.com", 
                "github.com", "bitbucket.org", "gitlab.com",
                "git-receive-pack", "git-upload-pack"
            ];
            
            if benign_git_strings.iter().any(|&s| cmd_line.contains(s) || query.contains(s)) {
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

fn sha1_from_sysmon_hashes(event: &SysmonEvent) -> Option<String> {
    let hashes = event.data.get("Hashes")?.as_str()?;
    for part in hashes.split(',') {
        let p = part.trim();
        if let Some(rest) = p.strip_prefix("SHA1=").or_else(|| p.strip_prefix("SHA1:")) {
            return Some(rest.trim().to_ascii_lowercase());
        }
    }
    None
}

#[async_trait]
impl ThreatVoter for NsrlVoter {
    fn name(&self) -> String {
        "NSRL-Veto".to_string()
    }
    async fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        let sha1 = sha1_from_sysmon_hashes(event)?;
        if self.cache.get(&sha1).map(|e| *e.value()).unwrap_or(false) {
            return Some(vote_result_nsrl_veto());
        }
        if self.memory.is_nsrl_known_good(&sha1).unwrap_or(false) {
            self.cache.insert(sha1, true);
            return Some(vote_result_nsrl_veto());
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
    async fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        // We only decompile on ProcessCreate or ImageLoad to catch entry-point intent
        if !matches!(event.event_id, SysmonEventId::ProcessCreate | SysmonEventId::ImageLoad) {
            return None;
        }

        let pid = event.process_id()?;
        
        // Deep analysis: SpiderEyes watches the process, disassembles, and reasons with Gemma 4
        match self.spider.watch_process(pid).await {
            Ok(report) => {
                let r_lower = report.to_lowercase();
                if r_lower.contains("malicious") || r_lower.contains("attack") || r_lower.contains("injection") || r_lower.contains("hollowing") {
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
    async fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        #[cfg(target_os = "windows")]
        {
            use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ, PROCESS_QUERY_INFORMATION};
            use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
            use windows::Win32::Foundation::CloseHandle;

            if let Some(pid) = event.process_id() {
                let rules = self.rules.clone();
                return tokio::task::spawn_blocking(move || {
                    unsafe {
                        let proc_handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid).ok()?;
                        let mut buffer = vec![0u8; 8192]; // Use 8KB for better coverage
                        let mut bytes_read = 0usize;
                        
                        // Placeholder: in a real EDR we'd walk the VAD (Virtual Address Descriptor) 
                        // or use VirtualQueryEx to find executable/private regions.
                        // Here we scan a 8KB chunk of the potential image base.
                        let _ = ReadProcessMemory(proc_handle, 0x400000 as *const _, buffer.as_mut_ptr() as *mut _, buffer.len(), Some(&mut bytes_read));
                        let _ = CloseHandle(proc_handle);

                        if bytes_read > 0 {
                            buffer.truncate(bytes_read);
                            let mut scanner = yara_x::Scanner::new(&rules);
                            let results = scanner.scan(&buffer).ok()?;
                            if results.matching_rules().count() > 0 {
                                return Some(VoteResult {
                                    confidence: 0.98,
                                    reason: "Yara-X: Detected malicious pattern in process memory".to_string(),
                                    weight: 1.0,
                                });
                            }
                        }
                    }
                    None
                }).await.unwrap_or(None);
            }
        }
        None
    }
}

/// KEV `product` text → compare **tokens** to the executable **stem** (e.g. `git.exe` ↔ "Git" / "Windows Git"),
/// not loose `contains` (which turned every `git.exe` / `chrome.exe` into a KEV hit).
fn kev_product_matches_stem(stem: &str, product: &str) -> bool {
    let stem = stem.to_lowercase();
    for token in product.split(|c: char| !c.is_alphanumeric()) {
        let t = token.to_lowercase();
        if t.len() < 3 {
            continue;
        }
        if stem == t {
            return true;
        }
    }
    false
}

fn kev_requires_exact_version(event: &SysmonEvent, full_path: &str) -> bool {
    let lifecycle = matches!(
        event.event_id,
        SysmonEventId::ProcessCreate | SysmonEventId::ProcessTerminate | SysmonEventId::ImageLoad
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
fn kev_quiet_benign_process_lifecycle(path: &str, stem: &str, config: &osoosi_types::PolicyConfig) -> bool {
    if std::env::var("OSOOSI_KEV_QUIET_SYSTEM_TOOLS")
        .map(|v| v == "0" || v.eq_ignore_ascii_case("false") || v.eq_ignore_ascii_case("off"))
        .unwrap_or(false)
    {
        return false;
    }
    let p = path.to_lowercase();

    // Configuration-driven suppression
    if config.consensus_trusted_paths.iter().any(|t| p.contains(&t.to_lowercase())) {
        return true;
    }
    if config.consensus_noisy_stems.iter().any(|s| stem.eq_ignore_ascii_case(s)) {
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
    async fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
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
            SysmonEventId::ProcessCreate | SysmonEventId::ProcessTerminate
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
                    .product_version
                    .as_deref()
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

                // Prefer KEV when tied to **network / file / image** telemetry; down-weight bare ProcessCreate.
                let (weight, reason_note) = if event.event_id == SysmonEventId::ProcessCreate {
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
    pub broadcaster: Arc<tokio::sync::RwLock<Option<Arc<dyn Fn(osoosi_types::GlobalIntelligence) + Send + Sync>>>>,
    pub node_id: String,
}

#[async_trait]
impl ThreatVoter for CveLookupVoter {
    fn name(&self) -> String {
        "NVD-CVE-Lookup".to_string()
    }
    async fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        let full_path = event.data.get("Image").and_then(|v| v.as_str())?;
        
        // 1. Extract Metadata (Product, Version, Signature) from PE
        let meta = match osoosi_types::get_pe_metadata(std::path::Path::new(full_path)) {
            Some(m) => m,
            None => return None,
        };

        // NEW: Suppress NVD lookup for signed Microsoft binaries or system files to avoid Consensus Veto spam.
        // We also check if the hash is in the NSRL known-good set.
        let is_microsoft = meta.product_name.to_lowercase().contains("microsoft") || 
                           meta.product_name.to_lowercase().contains("windows") ||
                           full_path.to_lowercase().contains("\\windows\\system32");

        if meta.is_signed && is_microsoft {
            return None; // Abstain to prevent log spam/veto on core OS processes
        }

        let sha1 = event.data.get("SHA1").and_then(|v| v.as_str());
        if let Some(s) = sha1 {
            if self.memory.is_nsrl_known_good(s).unwrap_or(false) {
                return None; // Abstain for known-good files
            }
        }

        // 2. Check Local Cache first
        let mut cached_cves = Vec::new();
        if let Ok(cached) = self.memory.get_cached_cves(&meta.product_name, &meta.version) {
            cached_cves.extend(cached);
        }
        // Fallback to "any" version cache
        if cached_cves.is_empty() {
            if let Ok(cached) = self.memory.get_cached_cves(&meta.product_name, "any") {
                cached_cves.extend(cached);
            }
        }

        if !cached_cves.is_empty() {
            let mut confidence = 0.95;
            let mut reason_note = " [CACHED]";
            if meta.is_signed {
                confidence = 0.65;
                reason_note = " [CACHED, CONFIDENCE DOWNGRADED: SIGNED]";
            }
            let cve_list: Vec<String> = cached_cves.iter().take(3).map(|(id, summary)| format!("{} ({:.50}...)", id, summary)).collect();
            return Some(VoteResult {
                confidence,
                reason: format!("Vulnerability Database Match: {} v{} has known CVEs: {}{}", meta.product_name, meta.version, cve_list.join(", "), reason_note),
                weight: 1.5,
            });
        }

        // 3. Query NVD API (or local cache via fetcher)
        let api_key = osoosi_types::resolve_nvd_api_key();
        match self.fetcher.query_cve_by_product(&meta.product_name, &meta.version, api_key.as_deref()).await {
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
                    let _ = self.memory.insert_cve_cache(&meta.product_name, &meta.version, &cve.id, &cve.summary);
                    
                    let broadcaster_guard = self.broadcaster.read().await;
                    if let Some(ref broadcast) = *broadcaster_guard {
                        broadcast(osoosi_types::GlobalIntelligence {
                            source_url: "https://nvd.nist.gov".to_string(),
                            summary: format!("NVD Discovery: {} v{} has vulnerability {}", meta.product_name, meta.version, cve.id),
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
                        });
                    }
                }

                let cve_list: Vec<String> = cves.iter().take(3).map(|c| format!("{} ({:.50}...)", c.id, c.summary)).collect();
                let cve_display = cve_list.join(", ");

                Some(VoteResult {
                    confidence,
                    reason: format!("Vulnerability Database Match: {} v{} has known CVEs: {}{}", meta.product_name, meta.version, cve_display, reason_note),
                    weight: 1.5, // Tie-breaker weight
                })
            }
            Ok(_) => {
                // If NO CVE found, we return a "neutral" vote. We no longer veto,
                // as missing CVE data is common for benign system processes.
                Some(VoteResult {
                    confidence: 0.0,
                    reason: format!("NVD: No matching CVEs found for {} v{}", meta.product_name, meta.version),
                    weight: 0.0, 
                })
            }
            Err(e) if e.to_string().contains("Rate limit") => {
                warn!("[CveLookupVoter] NVD API Rate Limit Hit: {}", e);
                None // Abstain if rate limited
            }
            Err(e) => {
                debug!("[CveLookupVoter] Query failed for {}: {}", meta.product_name, e);
                None
            }
        }
    }
}

/// A privacy-preserving voter that uses Differential Privacy and Merkle Auditing.
pub struct PrivacyVoter {
    dp: DifferentialPrivacy,
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

    async fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
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

            // 3. LOG TO MERKLE AUDIT TREE: Ensure the decision is tamper-proof
            let root = self.audit.log("PRIVACY_VOTE_EMITTED", serde_json::json!({
                "event_id": event.event_id,
                "noisy_score": noisy_score,
                "computer": event.computer,
            }));

            Some(VoteResult {
                confidence: noisy_score,
                reason: format!("Privacy-preserving detection (DP enabled). Merkle Root: {}", root),
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

    async fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        // The hook payload tags events with a "HookSource" data field when it reports
        // intercepted API calls back to the orchestrator via the telemetry channel.
        let hook_source = event.data.get("HookSource").and_then(|v| v.as_str())?;

        match hook_source {
            // --- Screen Capture Spyware Detection (BitBlt hook) ---
            "BitBlt" => {
                let image = event.data.get("Image").and_then(|v| v.as_str()).unwrap_or("unknown");
                // Trusted screen-capture processes (RDP, screenshot tools) are excluded
                let img_lower = image.to_lowercase();
                if img_lower.contains("sniphost") || img_lower.contains("snippingtool")
                    || img_lower.contains("mstsc") || img_lower.contains("teamviewer")
                    || img_lower.contains("obs") || img_lower.contains("osoosi") {
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
                let protect = event.data.get("Protection").and_then(|v| v.as_str()).unwrap_or("");
                let image = event.data.get("Image").and_then(|v| v.as_str()).unwrap_or("unknown");
                // PAGE_EXECUTE_READWRITE (0x40) is almost always shellcode injection
                if protect.contains("RWX") || protect.contains("0x40") {
                    // Exclude known legitimate JIT engines
                    let img_lower = image.to_lowercase();
                    if img_lower.contains("java") || img_lower.contains("dotnet")
                        || img_lower.contains("node") || img_lower.contains("chrome")
                        || img_lower.contains("firefox") {
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

            // --- Credential Dumping Detection (ReadProcessMemory / ptrace) ---
            "ReadProcessMemory" | "ptrace" => {
                let target = event.data.get("TargetProcess").and_then(|v| v.as_str()).unwrap_or("");
                let image = event.data.get("Image").and_then(|v| v.as_str()).unwrap_or("unknown");
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
                        reason: format!("Self-Defense: Process {} attempted to read EDR process memory", image),
                        weight: 1.0,
                    });
                }
                None
            }

            // --- Execution Blocking (CreateProcessW / execve) ---
            "CreateProcessW" | "execve" => {
                let cmd_line = event.data.get("CommandLine").and_then(|v| v.as_str()).unwrap_or("");
                let cmd_lower = cmd_line.to_lowercase();

                // Detect encoded PowerShell commands (common malware evasion)
                if cmd_lower.contains("-encodedcommand") || cmd_lower.contains("-enc ") || cmd_lower.contains("-e ") {
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
                    || cmd_lower.contains("ncat") && cmd_lower.contains("--sh-exec") {
                    return Some(VoteResult {
                        confidence: 0.95,
                        reason: format!("Reverse Shell Detected: {}", &cmd_line[..cmd_line.len().min(120)]),
                        weight: 0.95,
                    });
                }

                None
            }

            // --- C2 Beacon Detection (send / WSASend) ---
            "send" | "WSASend" => {
                let payload_hint = event.data.get("PayloadHint").and_then(|v| v.as_str()).unwrap_or("");
                let hint_lower = payload_hint.to_lowercase();

                // DNS tunneling patterns: unusually long subdomain labels
                if hint_lower.contains(".onion") || hint_lower.contains(".i2p") {
                    return Some(VoteResult {
                        confidence: 0.9,
                        reason: format!("Darknet Communication: outbound traffic to anonymization network detected"),
                        weight: 0.85,
                    });
                }

                // HTTP beaconing with suspicious User-Agents
                if hint_lower.contains("user-agent:") {
                    if hint_lower.contains("cobalt") || hint_lower.contains("meterpreter")
                        || hint_lower.contains("empire") || hint_lower.contains("covenant") {
                        return Some(VoteResult {
                            confidence: 0.95,
                            reason: format!("C2 Framework Beacon: known attack framework User-Agent detected in outbound HTTP"),
                            weight: 0.9,
                        });
                    }
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

    async fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        // The DNS Shield tags events with "DnsQuery" in the HookSource field
        let hook_source = event.data.get("HookSource").and_then(|v| v.as_str())?;
        if hook_source != "DnsShield" {
            return None;
        }

        let domain = event.data.get("DnsQuery").and_then(|v| v.as_str()).unwrap_or("");
        let verdict = event.data.get("DnsVerdict").and_then(|v| v.as_str()).unwrap_or("");
        let reason = event.data.get("DnsReason").and_then(|v| v.as_str()).unwrap_or("");
        let entropy: f64 = event.data.get("DnsEntropy")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let image = event.data.get("Image").and_then(|v| v.as_str()).unwrap_or("unknown");

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

    async fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        // Only process Sysmon Event ID 22 (DnsQuery)
        if event.event_id != SysmonEventId::DnsQuery {
            return None;
        }

        let query_name = event.data.get("QueryName").and_then(|v| v.as_str())?;
        let image = event.data.get("Image").and_then(|v| v.as_str()).unwrap_or("unknown");
        let pid = event.process_id().unwrap_or(0);
        let query_results = event.data.get("QueryResults").and_then(|v| v.as_str()).unwrap_or("");
        let query_status = event.data.get("QueryStatus").and_then(|v| v.as_str()).unwrap_or("");

        // Extract process name from full image path
        let proc_name = image.rsplit(['\\', '/']).next().unwrap_or(image).to_lowercase();

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
                    "chrome.exe" | "firefox.exe" | "msedge.exe" | "svchost.exe"
                    | "dns.exe" | "dnscache" | "systemd-resolved" | "mDNSResponder"
                    | "curl.exe" | "wget" | "powershell.exe" | "cmd.exe"
                    | "explorer.exe" | "teams.exe" | "slack.exe" | "outlook.exe"
                    | "code.exe" | "osoosi" | "osoosi.exe" | "git.exe"
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
            "lsass.exe" | "csrss.exe" | "smss.exe" | "wininit.exe"
            | "services.exe" | "winlogon.exe" | "dwm.exe"
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
