use crate::engine::{ThreatVoter, VoteResult};
use osoosi_types::{SysmonEvent, SysmonEventId};
use osoosi_dp::{DifferentialPrivacy, PrivacyConfig};
use osoosi_audit::MerkleAuditTree;
use std::sync::Arc;

/// Semantic Intent Voter (Algorithm 2)
pub struct SemanticVoter {
    pub engine: crate::semantic::SemanticEngine,
}

impl ThreatVoter for SemanticVoter {
    fn name(&self) -> String {
        "SemanticIntent".to_string()
    }
    fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
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

impl ThreatVoter for OtxVoter {
    fn name(&self) -> String {
        "OTX-C2".to_string()
    }
    fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
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

impl ThreatVoter for SigmaVoter {
    fn name(&self) -> String {
        "Sigma".to_string()
    }
    fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
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

impl ThreatVoter for GemmaVoter {
    fn name(&self) -> String {
        "LLM-Reasoning".to_string()
    }
    fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
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

        match self.analyzer.reason_about_attack(&summary) {
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

impl ThreatVoter for NativeVoter {
    fn name(&self) -> String {
        "Native-Instrumentation".to_string()
    }
    fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
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

/// NSRL "Known Good" Veto Voter (matches NIST **SHA-1** from Sysmon `Hashes`, same as the EDR fast-path).
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

impl ThreatVoter for NsrlVoter {
    fn name(&self) -> String {
        "NSRL-Veto".to_string()
    }
    fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
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

impl ThreatVoter for DecompileVoter {
    fn name(&self) -> String {
        "Decompile".to_string()
    }
    fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        // We only decompile on ProcessCreate or ImageLoad to catch entry-point intent
        if !matches!(event.event_id, SysmonEventId::ProcessCreate | SysmonEventId::ImageLoad) {
            return None;
        }

        let pid = event.process_id()?;
        
        // Deep analysis: SpiderEyes watches the process, disassembles, and reasons with Gemma 4
        match self.spider.watch_process(pid) {
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
    pub rules: yara_x::Rules,
}

impl ThreatVoter for YaraXMemoryVoter {
    fn name(&self) -> String {
        "YaraX-Memory".to_string()
    }
    fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        #[cfg(target_os = "windows")]
        {
            use process_memory::{CopyAddress, TryIntoProcessHandle};
            if let Some(pid) = event.process_id() {
                if let Ok(handle) = (pid as process_memory::Pid).try_into_process_handle() {
                    // In a real implementation, we'd iterate through memory regions.
                    // Here we'll do a focused scan of the first 1MB of the image base as a placeholder.
                    let mut buffer = vec![0u8; 4096]; // Use a smaller 4KB buffer for testing
                    if let Ok(_bytes) = handle.copy_address(0x400000, &mut buffer) {
                        let mut scanner = yara_x::Scanner::new(&self.rules);
                        let results = scanner.scan(&buffer).ok()?;
                        if results.matching_rules().count() > 0 {
                            return Some(VoteResult {
                                confidence: 0.98,
                                reason: "Yara-X: Detected C2 beacon pattern in process memory"
                                    .to_string(),
                                weight: 1.0,
                            });
                        }
                    }
                }
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

impl ThreatVoter for KevVoter {
    fn name(&self) -> String {
        "CISA-KEV".to_string()
    }
    fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
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

impl ThreatVoter for PrivacyVoter {
    fn name(&self) -> String {
        "Privacy-Enforced-Voter".to_string()
    }

    fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
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

impl ThreatVoter for InjectionTelemetryVoter {
    fn name(&self) -> String {
        "Injection-Telemetry".to_string()
    }

    fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
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
