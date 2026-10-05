//! Configuration types for OpenỌ̀ṣọ́ọ̀sì.
//! Loaded from config file (e.g. osoosi.toml) — no hardcoding.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub asset_id: String,
    pub node_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    #[serde(default = "default_event_channel")]
    pub event_channel: String,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    /// Paths to watch for file changes (e.g. C:\, D:\)
    #[serde(default = "default_watch_paths")]
    pub watch_paths: Vec<String>,
    /// Paths to exclude from monitoring (e.g. C:\Temp)
    #[serde(default)]
    pub exclude_paths: Vec<String>,
}

fn default_event_channel() -> String {
    #[cfg(target_os = "windows")]
    {
        "Security".to_string()
    }
    #[cfg(not(target_os = "windows"))]
    {
        "default".to_string()
    }
}

fn default_poll_interval() -> u64 {
    1
}

fn default_watch_paths() -> Vec<String> {
    vec![".".to_string()]
}

/// Return all physical/fixed drive root paths for file monitoring.
/// Windows: C:\, D:\, etc. (all existing drives)
/// Linux: /
/// macOS: /
pub fn all_physical_drive_paths() -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Storage::FileSystem::{GetDriveTypeW, GetVolumeInformationW};
        use windows::core::PCWSTR;

        let mut drives = Vec::new();
        for letter in b'A'..=b'Z' {
            let root = format!("{}:\\", letter as char);
            let root_wide: Vec<u16> = root.encode_utf16().chain(Some(0)).collect();
            let root_pcwstr = PCWSTR(root_wide.as_ptr());

            unsafe {
                if GetDriveTypeW(root_pcwstr) == 3 { // 3 = DRIVE_FIXED
                    let mut volume_name = [0u16; 256];
                    let mut filesystem_name = [0u16; 256];
                    
                    let res = GetVolumeInformationW(
                        root_pcwstr,
                        Some(&mut volume_name),
                        None,
                        None,
                        None,
                        Some(&mut filesystem_name),
                    );

                    if res.is_ok() {
                        let vol_str = String::from_utf16_lossy(&volume_name).trim_matches('\0').to_lowercase();
                        let fs_str = String::from_utf16_lossy(&filesystem_name).trim_matches('\0').to_lowercase();

                        // Exclude Google Drive and other known virtual/cloud mappings
                        if vol_str.contains("google drive") || fs_str.contains("googledrive") 
                           || vol_str.contains("onedrive") || vol_str.contains("dropbox")
                        {
                            debug!("Excluding cloud/virtual mapping: {} (Volume: {}, FS: {})", root, vol_str, fs_str);
                            continue;
                        }
                    }
                    
                    drives.push(root);
                }
            }
        }
        if drives.is_empty() {
            drives.push("C:\\".to_string()); // fallback
        }
        drives
    }
    #[cfg(target_os = "linux")]
    {
        vec!["/".to_string()]
    }
    #[cfg(target_os = "macos")]
    {
        vec!["/".to_string()]
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        vec![".".to_string()]
    }
}

/// Check if a path is a system directory (Windows System32/Program Files, Linux /bin, etc.).
/// Used to prevent high-risk autonomous actions like hex-patching on critical OS files.
pub fn is_system_path(path: &str) -> bool {
    let p = path.to_lowercase();
    let p = p.replace('/', "\\"); // Normalize slashes for comparison

    #[cfg(target_os = "windows")]
    {
        // Check for common Windows system paths
        let system_root = std::env::var("SystemRoot")
            .unwrap_or_else(|_| "C:\\Windows".to_string())
            .to_lowercase();
        let program_files = std::env::var("ProgramFiles")
            .unwrap_or_else(|_| "C:\\Program Files".to_string())
            .to_lowercase();
        let program_files_x86 = std::env::var("ProgramFiles(x86)")
            .unwrap_or_else(|_| "C:\\Program Files (x86)".to_string())
            .to_lowercase();

        if p.starts_with(&system_root)
            || p.starts_with(&program_files)
            || p.starts_with(&program_files_x86)
        {
            return true;
        }
        // Direct checks for common roots if env vars missing
        if p.starts_with("c:\\windows") || p.contains("\\system32\\") || p.contains("\\syswow64\\")
            || p.contains("\\servicing\\") || p.contains("\\winsxs\\")
        {
            return true;
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // Re-normalize to forward slashes for Unix
        let p = path;
        let system_prefixes = [
            "/bin/",
            "/sbin/",
            "/usr/bin/",
            "/usr/sbin/",
            "/etc/",
            "/lib/",
            "/lib64/",
            "/usr/lib/",
            "/usr/lib64/",
            "/boot/",
            "/sys/",
            "/proc/",
            "/dev/",
        ];
        if system_prefixes.iter().any(|prefix| p.starts_with(prefix)) {
            return true;
        }
        #[cfg(target_os = "macos")]
        {
            if p.starts_with("/System/") || p.starts_with("/Library/") {
                return true;
            }
        }
    }

    false
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            event_channel: default_event_channel(),
            poll_interval_secs: default_poll_interval(),
            watch_paths: default_watch_paths(),
            exclude_paths: Vec::new(),
        }
    }
}

/// Backup configuration. Runs on agent start.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    /// Enable backup on agent start
    #[serde(default)]
    pub enabled: bool,
    /// Backup type: "restore_point" (Win), "file_sync" (all), "full_image" (Win, needs admin)
    #[serde(default = "default_backup_type")]
    pub backup_type: String,
    /// Target path/drive for backup (e.g. E:\\, /mnt/backup)
    #[serde(default)]
    pub target: String,
    /// Paths to include (for file_sync). Empty = use platform defaults (e.g. user Documents)
    #[serde(default)]
    pub include_paths: Vec<String>,
    /// Minimum interval in seconds between backups (throttling). Default: 86400 (24h).
    #[serde(default)]
    pub interval_secs: Option<u64>,
}

fn default_backup_type() -> String {
    "file_sync".to_string()
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backup_type: default_backup_type(),
            target: String::new(),
            include_paths: Vec::new(),
            interval_secs: None,
        }
    }
}

/// Quarantine admin controls for releasing quarantined peers.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QuarantineAdminConfig {
    /// Dedicated admin host IP allowlist (used for remote quarantine release).
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Shared secret key expected in x-osoosi-quarantine-key header.
    #[serde(default)]
    pub key: String,
}

/// Autonomy config: auto-approve peers, auto-quarantine malware, sensible action thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutonomyConfig {
    /// Reputation threshold (0.0–1.0). Peers with score >= this are auto-approved. Defaults to 0.4 (auto-approve unknown peers).
    #[serde(default = "default_auto_approve_threshold")]
    pub auto_approve_reputation_threshold: f32,
    /// When true, move detected malware to quarantine folder (only when confidence meets threshold).
    #[serde(default)]
    pub auto_quarantine_malware: bool,
    /// Path for quarantined malware files.
    #[serde(default = "default_quarantine_path")]
    pub quarantine_path: String,
    /// Minimum confidence (0.0–1.0) to quarantine malware. Below this, only alert. EICAR/ClamAV always quarantined.
    #[serde(default = "default_quarantine_confidence")]
    pub quarantine_confidence_threshold: f32,
    /// Path substrings to exclude from quarantine (e.g. cloud sync temp folders). Prevents infinite quarantine loop when sync re-downloads.
    #[serde(default = "default_quarantine_exclude_paths")]
    pub quarantine_exclude_paths: Vec<String>,
    /// Minimum confidence (0.0–1.0) to take active response (Tarpit, Deception, etc.) on telemetry. Below this, Alert only.
    #[serde(default = "default_action_confidence")]
    pub action_confidence_threshold: f32,
    /// When true and a replacement URL exists in software_replacement map, replace compromised binary instead of quarantine.
    #[serde(default = "default_auto_replace_malware")]
    pub auto_replace_malware_binaries: bool,
}

fn default_auto_approve_threshold() -> f32 {
    0.4 // Auto-approve unknown peers (0.5) by default for mesh discovery
}
fn default_quarantine_path() -> String {
    "./quarantine".to_string()
}
fn default_quarantine_confidence() -> f32 {
    0.95 // Extremely high confidence for automatic quarantine to avoid false positives on OS files
}
fn default_quarantine_exclude_paths() -> Vec<String> {
    vec![
        ".tmp.driveupload".to_string(),
        "Google Drive".to_string(),
        "OneDrive".to_string(),
        "Dropbox".to_string(),
    ]
}
fn default_action_confidence() -> f32 {
    0.80 // Higher threshold for active response to ensure system stability
}
fn default_auto_replace_malware() -> bool {
    true // Try to replace with clean version when mapping exists
}

impl Default for AutonomyConfig {
    fn default() -> Self {
        Self {
            auto_approve_reputation_threshold: default_auto_approve_threshold(),
            auto_quarantine_malware: false,
            quarantine_path: default_quarantine_path(),
            quarantine_confidence_threshold: default_quarantine_confidence(),
            quarantine_exclude_paths: default_quarantine_exclude_paths(),
            action_confidence_threshold: default_action_confidence(),
            auto_replace_malware_binaries: default_auto_replace_malware(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AutonomyMode {
    Audit,
    Active,
    Lockdown,
    Custom,
}

impl AutonomyMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            AutonomyMode::Audit => "audit",
            AutonomyMode::Active => "active",
            AutonomyMode::Lockdown => "lockdown",
            AutonomyMode::Custom => "custom",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            AutonomyMode::Audit => "Audit / Monitor",
            AutonomyMode::Active => "Active Autonomous Prevention",
            AutonomyMode::Lockdown => "Strict Zero-Trust Lockdown",
            AutonomyMode::Custom => "Custom Configuration",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            AutonomyMode::Audit => {
                "Telemetry, Sigma rules, and YARA-X detections are logged and alerted. Zero automated process termination or quarantine. Actions require analyst sign-off."
            }
            AutonomyMode::Active => {
                "High-speed autonomous containment. High-confidence malware and memory injections are automatically killed, quarantined, and isolated via WFP."
            }
            AutonomyMode::Lockdown => {
                "Aggressive zero-trust lockdown for red-team pentests or active compromise. Low-threshold behavioral anomalies trigger immediate process kill."
            }
            AutonomyMode::Custom => {
                "Customized confidence thresholds and autonomous response parameters configured by administrator."
            }
        }
    }
}

impl AutonomyConfig {
    pub fn current_mode(&self) -> AutonomyMode {
        if !self.auto_quarantine_malware && (self.action_confidence_threshold - 0.80).abs() < 0.05 {
            AutonomyMode::Audit
        } else if self.auto_quarantine_malware && (self.action_confidence_threshold - 0.50).abs() < 0.05 {
            AutonomyMode::Active
        } else if self.auto_quarantine_malware && (self.action_confidence_threshold - 0.35).abs() < 0.05 {
            AutonomyMode::Lockdown
        } else {
            AutonomyMode::Custom
        }
    }

    pub fn apply_preset(&mut self, mode: &str) {
        match mode.trim().to_ascii_lowercase().as_str() {
            "audit" | "monitor" => {
                self.auto_quarantine_malware = false;
                self.action_confidence_threshold = 0.80;
                self.quarantine_confidence_threshold = 0.95;
            }
            "active" | "armed" | "enforce" => {
                self.auto_quarantine_malware = true;
                self.action_confidence_threshold = 0.50;
                self.quarantine_confidence_threshold = 0.80;
            }
            "lockdown" | "strict" => {
                self.auto_quarantine_malware = true;
                self.action_confidence_threshold = 0.35;
                self.quarantine_confidence_threshold = 0.60;
            }
            _ => {}
        }
    }
}

/// Helper to update [autonomy] section within TOML content, preserving comments and formatting.
pub fn update_autonomy_content(content: &str, cfg: &AutonomyConfig) -> String {
    let mut lines: Vec<String> = Vec::new();
    let mut in_autonomy = false;
    let mut found_autonomy = false;

    let mut set_auto_approve = false;
    let mut set_auto_quarantine = false;
    let mut set_quarantine_conf = false;
    let mut set_action_conf = false;
    let mut set_auto_replace = false;

    let append_missing = |target_lines: &mut Vec<String>,
                          set_auto_approve: &mut bool,
                          set_auto_quarantine: &mut bool,
                          set_quarantine_conf: &mut bool,
                          set_action_conf: &mut bool,
                          set_auto_replace: &mut bool| {
        if !*set_auto_approve {
            target_lines.push(format!("auto_approve_reputation_threshold = {:.2}", cfg.auto_approve_reputation_threshold));
            *set_auto_approve = true;
        }
        if !*set_auto_quarantine {
            target_lines.push(format!("auto_quarantine_malware = {}", cfg.auto_quarantine_malware));
            *set_auto_quarantine = true;
        }
        if !*set_quarantine_conf {
            target_lines.push(format!("quarantine_confidence_threshold = {:.2}", cfg.quarantine_confidence_threshold));
            *set_quarantine_conf = true;
        }
        if !*set_action_conf {
            target_lines.push(format!("action_confidence_threshold = {:.2}", cfg.action_confidence_threshold));
            *set_action_conf = true;
        }
        if !*set_auto_replace {
            target_lines.push(format!("auto_replace_malware_binaries = {}", cfg.auto_replace_malware_binaries));
            *set_auto_replace = true;
        }
    };

    let has_crlf = content.contains("\r\n");

    for line in content.lines() {
        let trimmed = line.trim();

        // Check if this line is a table header (e.g. `[section]` or `[[section]]` or `[section] # comment`)
        let code_without_comment = if let Some(idx) = trimmed.find('#') {
            trimmed[..idx].trim()
        } else {
            trimmed
        };

        if code_without_comment.starts_with('[') && code_without_comment.ends_with(']') {
            let inner = code_without_comment[1..code_without_comment.len() - 1].trim();
            // Handle array of tables [[table]]
            let table_name = if inner.starts_with('[') && inner.ends_with(']') {
                inner[1..inner.len() - 1].trim()
            } else {
                inner
            };

            if in_autonomy {
                append_missing(
                    &mut lines,
                    &mut set_auto_approve,
                    &mut set_auto_quarantine,
                    &mut set_quarantine_conf,
                    &mut set_action_conf,
                    &mut set_auto_replace,
                );
                in_autonomy = false;
            }

            if table_name.eq_ignore_ascii_case("autonomy") {
                in_autonomy = true;
                found_autonomy = true;
                lines.push(line.to_string());
                continue;
            }
        }

        if in_autonomy {
            // Check for key = value (ignore comment-only lines)
            if !trimmed.starts_with('#') {
                if let Some((key, val_part)) = trimmed.split_once('=') {
                    let key = key.trim();
                    let indent = line.chars().take_while(|c| c.is_whitespace()).collect::<String>();
                    let inline_comment = if let Some(c_idx) = val_part.find('#') {
                        format!(" {}", val_part[c_idx..].trim_end())
                    } else {
                        String::new()
                    };

                    match key {
                        "auto_quarantine_malware" => {
                            lines.push(format!("{}auto_quarantine_malware = {}{}", indent, cfg.auto_quarantine_malware, inline_comment));
                            set_auto_quarantine = true;
                            continue;
                        }
                        "quarantine_confidence_threshold" => {
                            lines.push(format!("{}quarantine_confidence_threshold = {:.2}{}", indent, cfg.quarantine_confidence_threshold, inline_comment));
                            set_quarantine_conf = true;
                            continue;
                        }
                        "action_confidence_threshold" => {
                            lines.push(format!("{}action_confidence_threshold = {:.2}{}", indent, cfg.action_confidence_threshold, inline_comment));
                            set_action_conf = true;
                            continue;
                        }
                        "auto_approve_reputation_threshold" => {
                            lines.push(format!("{}auto_approve_reputation_threshold = {:.2}{}", indent, cfg.auto_approve_reputation_threshold, inline_comment));
                            set_auto_approve = true;
                            continue;
                        }
                        "auto_replace_malware_binaries" => {
                            lines.push(format!("{}auto_replace_malware_binaries = {}{}", indent, cfg.auto_replace_malware_binaries, inline_comment));
                            set_auto_replace = true;
                            continue;
                        }
                        _ => {}
                    }
                }
            }
        }

        lines.push(line.to_string());
    }

    if in_autonomy {
        append_missing(
            &mut lines,
            &mut set_auto_approve,
            &mut set_auto_quarantine,
            &mut set_quarantine_conf,
            &mut set_action_conf,
            &mut set_auto_replace,
        );
    }

    if !found_autonomy {
        if !lines.is_empty() && !lines.last().map(|s| s.is_empty()).unwrap_or(false) {
            lines.push(String::new());
        }
        lines.push("[autonomy]".to_string());
        append_missing(
            &mut lines,
            &mut set_auto_approve,
            &mut set_auto_quarantine,
            &mut set_quarantine_conf,
            &mut set_action_conf,
            &mut set_auto_replace,
        );
    }

    let separator = if has_crlf { "\r\n" } else { "\n" };
    let mut res = lines.join(separator);
    if content.is_empty() || content.ends_with('\n') {
        res.push_str(separator);
    }
    res
}

/// Save autonomy config to a specific path (modifying in-place or creating).
pub fn save_autonomy_config_to_path(cfg: &AutonomyConfig, path: &std::path::Path) -> anyhow::Result<()> {
    let content = if path.exists() {
        std::fs::read_to_string(path)?
    } else {
        String::new()
    };

    let updated = update_autonomy_content(&content, cfg);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, updated)?;
    Ok(())
}

/// Save autonomy config to the resolved configuration file (defaults to osoosi.toml).
pub fn save_autonomy_config(cfg: &AutonomyConfig) -> anyhow::Result<()> {
    let path = if let Ok(p) = std::env::var("OSOOSI_CONFIG") {
        let trimmed = p.trim();
        if !trimmed.is_empty() {
            PathBuf::from(trimmed)
        } else {
            resolve_config_path().unwrap_or_else(|| PathBuf::from("osoosi.toml"))
        }
    } else {
        resolve_config_path().unwrap_or_else(|| PathBuf::from("osoosi.toml"))
    };
    save_autonomy_config_to_path(cfg, &path)
}


/// Partial wire config for loading from file (peer rules only; listen_addr etc. from env/args).
#[derive(Debug, Deserialize, Default)]
struct WireConfigPartial {
    #[serde(default)]
    pub listen_addr: Option<String>,
    #[serde(default)]
    pub peers: Vec<String>,
    #[serde(default)]
    pub peer_rules: PeerRulesConfig,
    #[serde(default)]
    pub master_node_public_key: Option<String>,
    #[serde(default)]
    pub membership_proof: Option<String>,
    #[serde(default)]
    pub zone: Option<String>,
    #[serde(default)]
    pub nostr_relays: Vec<String>,
    #[serde(default = "default_true")]
    pub allow_public_relays: bool,
    #[serde(default = "default_duckdns_domain")]
    pub duckdns_domain: Option<String>,
    #[serde(default = "default_true")]
    pub auto_bootstrap_duckdns: bool,
    #[serde(default = "default_duckdns_port")]
    pub duckdns_port: u16,
}

/// Partial config for loading from file (only sections we need; rest use defaults).
#[derive(Debug, Deserialize)]
struct FileConfig {
    #[serde(default)]
    telemetry: TelemetryConfig,
    #[serde(default)]
    backup: BackupConfig,
    #[serde(default)]
    quarantine_admin: QuarantineAdminConfig,
    #[serde(default)]
    autonomy: AutonomyConfig,
    #[serde(default)]
    wire: WireConfigPartial,
    #[serde(default)]
    repair: RepairConfig,
    #[serde(default)]
    runtime: RuntimeConfig,
    #[serde(default)]
    sandbox: SandboxSecurityConfigPartial,
    #[serde(default)]
    hex_patch: HexPatchConfig,
    #[serde(default)]
    pub ai: AiConfig,
    #[serde(default)]
    pub heavener: HeavenerConfig,
    /// Policy engine settings: rules paths, global exclusions, and noise suppression.
    #[serde(default)]
    pub policy: PolicyConfig,
    /// AlienVault OTX / NVD keys — see `load_external_api_config` and `resolve_*_api_key`.
    #[serde(default)]
    external_api: ExternalApiConfig,
    /// Log retention and intelligent rotation configuration.
    #[serde(default)]
    pub log_retention: LogRetentionConfig,
    /// WikiSkill autonomous self-evolving coding and threat detection engine configuration.
    #[serde(default)]
    pub skills: SkillsConfig,
    /// Embedded Velociraptor forensic extraction service configuration.
    #[serde(default)]
    pub forensics: ForensicsConfig,
    /// Non-autoregressive Clef Decision Model configuration.
    #[serde(default)]
    pub decision_model: DecisionModelConfig,
    /// LangGraph Autonomous Multi-Agent Defense Swarm configuration.
    #[serde(default)]
    pub swarm: SwarmConfig,
    /// Hardware resource thresholds and model gating configuration.
    #[serde(default)]
    pub resources: ResourcesConfig,
}

/// Hex-patch agent config: auto-patch files when rules match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexPatchConfig {
    /// Enable hex-patch agent loop.
    #[serde(default)]
    pub enabled: bool,
    /// Interval in seconds between patch cycles.
    #[serde(default = "default_hexpatch_interval")]
    pub interval_secs: u64,
    /// Rules: path (file to patch) + script (patch logic).
    #[serde(default)]
    pub rules: Vec<HexPatchRule>,
    /// CVE-triggered rules: when a CVE is detected for a binary (e.g. git.exe), patch it.
    #[serde(default)]
    pub cve_rules: Vec<HexPatchCveRule>,
}

/// When CVE is detected for a process, patch the binary.
/// Use either (find_hex, replace_hex) for dynamic patching, or script for a patch file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexPatchCveRule {
    /// CVE ID (e.g. CVE-2024-1234) or prefix (e.g. CVE-2024-).
    pub cve_id: String,
    /// Process basename (e.g. git.exe, ssh.exe).
    pub basename: String,
    /// Path to the patch script (optional when find_hex+replace_hex are set).
    #[serde(default)]
    pub script: Option<String>,
    /// Hex pattern to find (dynamic patch; used with replace_hex).
    #[serde(default)]
    pub find_hex: Option<String>,
    /// Hex bytes to replace with (dynamic patch; used with find_hex).
    #[serde(default)]
    pub replace_hex: Option<String>,
}

fn default_hexpatch_interval() -> u64 {
    3600
}

impl Default for HexPatchConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: 3600,
            rules: Vec::new(),
            cve_rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexPatchRule {
    /// Path to the binary to patch (exact path).
    pub path: String,
    /// Path to the patch script (e.g. config/patch_logic.lua).
    pub script: String,
}

/// Sandbox security config for loading from file. Maps to osoosi_sandbox::SandboxSecurityConfig.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SandboxSecurityConfigPartial {
    #[serde(default)]
    pub allowed_wasm_hashes: Vec<String>,
    #[serde(default)]
    pub wasm_hash_required: bool,
    #[serde(default)]
    pub url_allowlist: Vec<String>,
    #[serde(default)]
    pub url_allowlist_mode: bool,
    #[serde(default)]
    pub command_whitelist: Vec<String>,
    #[serde(default)]
    pub command_whitelist_mode: bool,
    #[serde(default)]
    pub query_allowed_tables: Vec<String>,
    #[serde(default)]
    pub query_restrict_tables: bool,
    #[serde(default = "default_max_host_calls")]
    pub max_host_calls_per_session: usize,
}
fn default_max_host_calls() -> usize {
    256
}

/// Resolve the base directory of the agent (where the EXE is located).
/// This is used for all internal tool paths to prevent "os error 3" when
/// starting the agent from a different CWD.
pub fn resolve_base_dir() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            return parent.to_path_buf();
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

/// Resolve the bin directory for tools (ClamAV, etc.). Uses project root when found.
/// Env overrides: OSOOSI_BIN or OSOOSI_SIGCHECK_INSTALL_DIR (legacy, same as OSOOSI_BIN).
pub fn resolve_bin_dir() -> PathBuf {
    if let Ok(p) = std::env::var("OSOOSI_BIN") {
        let path = PathBuf::from(p.trim());
        if !path.as_os_str().is_empty() {
            return path;
        }
    }
    if let Ok(p) = std::env::var("OSOOSI_SIGCHECK_INSTALL_DIR") {
        let path = PathBuf::from(p.trim());
        if !path.as_os_str().is_empty() {
            return path;
        }
    }
    if let Some(project_root) = resolve_project_root() {
        return project_root.join("bin");
    }
    if let Some(config_path) = resolve_config_path() {
        if let Some(parent) = config_path.parent() {
            return parent.join("bin");
        }
    }
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("bin")
}

/// Resolve the tools directory (floss, capa, hollows_hunter).
/// Env override: OSOOSI_TOOLS_ROOT.
/// Defaults to project_root/tools or project_root/harfile if found.
pub fn resolve_tools_dir() -> PathBuf {
    if let Ok(p) = std::env::var("OSOOSI_TOOLS_ROOT") {
        return PathBuf::from(p.trim());
    }

    if let Some(root) = resolve_project_root() {
        // 1. Try 'tools' in project root (modern default)
        let t = root.join("tools");
        if t.is_dir() {
            return t;
        }
        // 2. Try 'harfile' in project root (legacy default)
        let h = root.join("harfile");
        if h.is_dir() {
            return h;
        }
        // 3. Default to project_root/tools (will be created by provisioner)
        return t;
    }

    // Fallback to current_dir/tools
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("tools")
}

/// Resolve the global cache directory for transient/downloaded data (feeds, models).
pub fn resolve_cache_dir() -> PathBuf {
    if let Ok(p) = std::env::var("OSOOSI_CACHE_DIR") {
        return PathBuf::from(p.trim());
    }

    if let Some(root) = resolve_project_root() {
        let c = root.join("cache");
        if c.is_dir() {
            return c;
        }
    }

    // Search upward for 'cache' directory
    let mut dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    loop {
        let c = dir.join("cache");
        if c.is_dir() {
            return c;
        }
        if let Some(parent) = dir.parent() {
            dir = parent.to_path_buf();
        } else {
            break;
        }
    }

    // Ultimate fallback: current_dir/cache
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("cache")
}

pub fn resolve_kev_cache_path() -> PathBuf {
    resolve_cache_dir().join("kev.json")
}

/// Resolve a specific tool path dynamically.
pub fn resolve_tool_path(tool_name: &str, executable_name: &str) -> PathBuf {
    resolve_tools_dir().join(tool_name).join(executable_name)
}

/// Resolve the models directory for ML/LLM models (Malware, SmolLM, etc.).
/// Env override: OSOOSI_MODELS_DIR.
/// Defaults to current_dir/models or project_root/models if found.
pub fn resolve_models_dir() -> PathBuf {
    if let Ok(p) = std::env::var("OSOOSI_MODELS_DIR") {
        let pb = PathBuf::from(p.trim());
        if !pb.as_os_str().is_empty() {
            return pb;
        }
    }

    // Fallback to searching upward for 'models' directory
    let mut dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    loop {
        let m = dir.join("models");
        if m.is_dir() {
            return m;
        }
        if let Some(parent) = dir.parent() {
            dir = parent.to_path_buf();
        } else {
            break;
        }
    }

    // Ultimate fallback: current_dir/models
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("models")
}

/// Resolve the database directory for persistent storage.
/// Env override: OSOOSI_DATABASE_DIR.
pub fn resolve_database_dir() -> PathBuf {
    if let Ok(p) = std::env::var("OSOOSI_DATABASE_DIR") {
        return PathBuf::from(p.trim());
    }

    if let Some(root) = resolve_project_root() {
        let d = root.join("database");
        if d.is_dir() {
            return d;
        }
    }

    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("database")
}

pub fn resolve_log_directory() -> PathBuf {
    if let Ok(p) = std::env::var("OSOOSI_LOG_DIR") {
        let pb = PathBuf::from(p.trim());
        if !pb.as_os_str().is_empty() {
            return pb;
        }
    }

    if let Some(root) = resolve_project_root() {
        let l = root.join("logs");
        return l;
    }

    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("logs")
}

/// Resolve the rules directory (YARA, Sigma).
/// Env override: OSOOSI_RULES_DIR.
/// Defaults to project_root/rules or current_dir/rules if found.
pub fn resolve_rules_dir() -> PathBuf {
    if let Ok(p) = std::env::var("OSOOSI_RULES_DIR") {
        return PathBuf::from(p.trim());
    }

    if let Some(root) = resolve_project_root() {
        let r = root.join("rules");
        if r.is_dir() {
            return r;
        }
    }

    // Fallback to searching upward for 'rules' directory
    let mut dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    loop {
        let r = dir.join("rules");
        if r.is_dir() {
            return r;
        }
        if let Some(parent) = dir.parent() {
            dir = parent.to_path_buf();
        } else {
            break;
        }
    }

    // Ultimate fallback: current_dir/rules
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("rules")
}

/// Resolve the directory for YARA rules.
pub fn resolve_yara_rules_dir() -> PathBuf {
    if let Ok(p) = std::env::var("OSOOSI_YARA_DIR") {
        return PathBuf::from(p.trim());
    }
    let rules_dir = resolve_rules_dir();
    // Check for rules/yara or use rules/ directly
    let yara = rules_dir.join("yara");
    if yara.is_dir() {
        yara
    } else {
        rules_dir
    }
}

/// Resolve the directory for Sigma rules.
pub fn resolve_sigma_rules_dir() -> PathBuf {
    if let Ok(p) = std::env::var("OSOOSI_SIGMA_DIR") {
        return PathBuf::from(p.trim());
    }
    let rules_dir = resolve_rules_dir();
    // Check for rules/sigma or use rules/ directly
    let sigma = rules_dir.join("sigma");
    if sigma.is_dir() {
        sigma
    } else {
        rules_dir
    }
}

/// Resolve the path to the authoritative MITRE ATT&CK & ATLAS Enterprise Catalog.
pub fn resolve_mitre_catalog_path() -> PathBuf {
    if let Ok(p) = std::env::var("OSOOSI_MITRE_CATALOG") {
        let pb = PathBuf::from(p.trim());
        if pb.is_file() {
            return pb;
        }
    }

    if let Some(root) = resolve_project_root() {
        let candidate = root.join("config").join("mitre_attack_catalog.json");
        if candidate.is_file() {
            return candidate;
        }
    }

    for start in [
        std::env::current_dir().ok(),
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf())),
    ]
    .into_iter()
    .flatten()
    {
        let mut dir = Some(start);
        for _ in 0..10 {
            let Some(d) = dir else { break };
            let candidate = d.join("config").join("mitre_attack_catalog.json");
            if candidate.is_file() {
                return candidate;
            }
            dir = d.parent().map(|p| p.to_path_buf());
        }
    }

    PathBuf::from("config/mitre_attack_catalog.json")
}

/// Resolve the path to the authoritative combined MITRE ATT&CK + ATLAS STIX 2.1 bundle.
pub fn resolve_stix_bundle_path() -> PathBuf {
    if let Ok(p) = std::env::var("OSOOSI_STIX_BUNDLE") {
        let pb = PathBuf::from(p.trim());
        if pb.is_file() {
            return pb;
        }
    }

    if let Some(root) = resolve_project_root() {
        let candidate = root.join("config").join("stix-atlas-attack-enterprise.json");
        if candidate.is_file() {
            return candidate;
        }
    }

    for start in [
        std::env::current_dir().ok(),
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf())),
    ]
    .into_iter()
    .flatten()
    {
        let mut dir = Some(start);
        for _ in 0..10 {
            let Some(d) = dir else { break };
            let candidate = d.join("config").join("stix-atlas-attack-enterprise.json");
            if candidate.is_file() {
                return candidate;
            }
            dir = d.parent().map(|p| p.to_path_buf());
        }
    }

    PathBuf::from("config/stix-atlas-attack-enterprise.json")
}

/// Automatically sets critical OSOOSI_* environment variables by discovering the project root.
/// This ensures that even if the agent is run from target/release or a nested directory,
/// all internal logic and sub-processes correctly resolve their assets.
pub fn persist_environment_paths() {
    let models_dir = resolve_models_dir();
    if std::env::var("OSOOSI_MODELS_DIR").is_err() {
        std::env::set_var("OSOOSI_MODELS_DIR", models_dir.to_string_lossy().to_string());
    }

    let bin_dir = resolve_bin_dir();
    if std::env::var("OSOOSI_BIN").is_err() {
        std::env::set_var("OSOOSI_BIN", bin_dir.to_string_lossy().to_string());
    }

    let tools_dir = resolve_tools_dir();
    if std::env::var("OSOOSI_TOOLS_ROOT").is_err() {
        std::env::set_var("OSOOSI_TOOLS_ROOT", tools_dir.to_string_lossy().to_string());
    }

    let cache_dir = resolve_cache_dir();
    if std::env::var("OSOOSI_CACHE_DIR").is_err() {
        std::env::set_var("OSOOSI_CACHE_DIR", cache_dir.to_string_lossy().to_string());
    }

    let db_dir = resolve_database_dir();
    if std::env::var("OSOOSI_DATABASE_DIR").is_err() {
        std::env::set_var("OSOOSI_DATABASE_DIR", db_dir.to_string_lossy().to_string());
    }

    let yara_dir = resolve_yara_rules_dir();
    if std::env::var("OSOOSI_YARA_DIR").is_err() {
        std::env::set_var("OSOOSI_YARA_DIR", yara_dir.to_string_lossy().to_string());
    }

    let sigma_dir = resolve_sigma_rules_dir();
    if std::env::var("OSOOSI_SIGMA_DIR").is_err() {
        std::env::set_var("OSOOSI_SIGMA_DIR", sigma_dir.to_string_lossy().to_string());
    }

    let catalog_path = resolve_mitre_catalog_path();
    if std::env::var("OSOOSI_MITRE_CATALOG").is_err() {
        std::env::set_var("OSOOSI_MITRE_CATALOG", catalog_path.to_string_lossy().to_string());
    }
}

pub fn resolve_smollm_dir() -> PathBuf {
    resolve_models_dir().join("smollm")
}

pub fn resolve_smollm_onnx_path() -> PathBuf {
    resolve_smollm_dir().join("smollm2-135m-it.onnx")
}

static MODEL_PROVISIONING_ACTIVE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Returns true if model provisioning/downloading is currently in progress.
pub fn is_model_provisioning() -> bool {
    if MODEL_PROVISIONING_ACTIVE.load(std::sync::atomic::Ordering::Relaxed) {
        return true;
    }
    if std::env::var("OSOOSI_MODELS_PROVISIONING").map(|v| v == "1").unwrap_or(false) {
        return true;
    }
    let marker = resolve_models_dir().join(".provisioning");
    if marker.exists() {
        if let Ok(meta) = std::fs::metadata(&marker) {
            if let Ok(mod_time) = meta.modified() {
                if let Ok(elapsed) = mod_time.elapsed() {
                    // Stale marker check: ignore if older than 2 hours
                    return elapsed.as_secs() < 7200;
                }
            }
        }
        return true;
    }
    false
}

/// Set or clear the model provisioning state.
pub fn set_model_provisioning(provisioning: bool) {
    MODEL_PROVISIONING_ACTIVE.store(provisioning, std::sync::atomic::Ordering::Relaxed);
    let marker = resolve_models_dir().join(".provisioning");
    if provisioning {
        std::env::set_var("OSOOSI_MODELS_PROVISIONING", "1");
        let _ = std::fs::write(&marker, format!("{}", std::process::id()));
    } else {
        std::env::remove_var("OSOOSI_MODELS_PROVISIONING");
        let _ = std::fs::remove_file(&marker);
    }
}

/// Verify the integrity of a configuration file against a .lock signature.
pub fn verify_config_integrity(path: &std::path::Path) -> anyhow::Result<()> {
    use sha2::{Sha256, Digest};
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 { break; }
        hasher.update(&buffer[..n]);
    }
    let current_hash = format!("{:x}", hasher.finalize());

    let sign_path = path.with_extension(format!(
        "{}.sign",
        path.extension().map(|e| e.to_string_lossy().to_string()).unwrap_or_default()
    ));
    let xml_lock_path = path.with_extension("xml.lock");

    let lock_path = if sign_path.exists() {
        sign_path.clone()
    } else if xml_lock_path.exists() {
        xml_lock_path.clone()
    } else {
        std::fs::write(&xml_lock_path, &current_hash)?;
        info!("Created cryptographic lock for config at {:?}", xml_lock_path);
        return Ok(());
    };

    let locked_hash = std::fs::read_to_string(&lock_path)?;
    if current_hash.trim() != locked_hash.trim() {
        // If .sign matches current content, heal outdated xml.lock
        if sign_path.exists() && std::fs::read_to_string(&sign_path).map(|h| h.trim() == current_hash.trim()).unwrap_or(false) {
            let _ = std::fs::write(&xml_lock_path, &current_hash);
            return Ok(());
        }
        return Err(anyhow::anyhow!("Configuration hash mismatch! Expected {}, got {}. Possible tampering detected.", locked_hash, current_hash));
    }

    Ok(())
}

/// Re-sign all configuration locks (xml.lock and .sign sidecars) to match current file contents.
pub fn sign_all_configs() {
    if let Some(path) = resolve_config_path() {
        use sha2::{Sha256, Digest};
        use std::io::Read;

        if let Ok(mut file) = std::fs::File::open(&path) {
            let mut hasher = Sha256::new();
            let mut buffer = [0; 1024];
            while let Ok(n) = file.read(&mut buffer) {
                if n == 0 { break; }
                hasher.update(&buffer[..n]);
            }
            let current_hash = format!("{:x}", hasher.finalize());
            let _ = std::fs::write(path.with_extension("xml.lock"), &current_hash);
            let sig_ext = format!(
                "{}.sign",
                path.extension().map(|e| e.to_string_lossy().to_string()).unwrap_or_default()
            );
            let _ = std::fs::write(path.with_extension(sig_ext), &current_hash);
            info!("Updated cryptographic locks and signatures for config at {:?}", path);
        }
    }
}

pub fn resolve_openssl_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        PathBuf::from("openssl.exe")
    } // Usually on PATH after install
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("openssl")
    }
}

pub fn resolve_xori_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        resolve_tools_dir().join("xori").join("xori.exe")
    }
    #[cfg(not(target_os = "windows"))]
    {
        resolve_tools_dir().join("xori").join("xori")
    }
}

/// Walk up from current_dir to find project/workspace root (osoosi.toml or Cargo.toml with [workspace]).
fn resolve_project_root() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        if dir.join("osoosi.toml").is_file() {
            return Some(dir);
        }
        if dir.join("Cargo.toml").is_file() {
            if let Ok(content) = std::fs::read_to_string(dir.join("Cargo.toml")) {
                if content.contains("[workspace]") {
                    return Some(dir);
                }
            }
        }
        dir = dir.parent()?.to_path_buf();
    }
}

/// Resolve config file path: OSOOSI_CONFIG env, ./osoosi.toml, or ~/.config/osoosi/osoosi.toml.
pub fn resolve_config_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("OSOOSI_CONFIG") {
        let path = PathBuf::from(&p);
        if path.exists() {
            return Some(path);
        }
    }
    let cwd = std::env::current_dir().ok()?;
    
    // 1. Try project root discovery (walks up to find osoosi.toml)
    if let Some(root) = resolve_project_root() {
        let path = root.join("osoosi.toml");
        if path.exists() {
            return Some(path);
        }
    }

    let local = cwd.join("osoosi.toml");
    if local.exists() {
        return Some(local);
    }

    // Check parent directory (useful when running from target/release)
    if let Some(parent) = cwd.parent() {
        let parent_local = parent.join("osoosi.toml");
        if parent_local.exists() {
            return Some(parent_local);
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Some(home) = dirs::config_dir() {
            let global = home.join("osoosi").join("osoosi.toml");
            if global.exists() {
                return Some(global);
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(home) = dirs::config_dir() {
            let global = home.join("osoosi").join("osoosi.toml");
            if global.exists() {
                return Some(global);
            }
        }
    }
    None
}

/// Load watch paths from config file. Returns None if no config or parse error.
/// Use "all" or "*" in watch_paths to expand to all physical drives.
pub fn load_watch_paths_from_config() -> Option<Vec<String>> {
    let path = resolve_config_path()?;
    let content = std::fs::read_to_string(&path).ok()?;
    let cfg: FileConfig = toml::from_str(&content).ok()?;
    
    // PRODUCTION READINESS: Verify config integrity
    if let Err(e) = verify_config_integrity(&path) {
        warn!("⚠️ [PRODUCTION-SECURITY] Config integrity check failed: {}. Continuing in untrusted mode.", e);
    }

    let mut paths: Vec<String> = cfg
        .telemetry
        .watch_paths
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if paths
        .iter()
        .any(|s| s.eq_ignore_ascii_case("all") || s == "*")
    {
        paths = all_physical_drive_paths();
    }
    if paths.is_empty() {
        None
    } else {
        Some(paths)
    }
}

/// Load exclude paths from config file.
pub fn load_exclude_paths_from_config() -> Vec<String> {
    if let Some(path) = resolve_config_path() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(cfg) = toml::from_str::<FileConfig>(&content) {
                return cfg.telemetry.exclude_paths;
            }
        }
    }
    Vec::new()
}

/// Load runtime config (db_path, traps_path, etc.). Env: OSOOSI_DB_PATH, OSOOSI_TRAPS_PATH.
pub fn load_runtime_config() -> RuntimeConfig {
    let mut cfg = if let Some(path) = resolve_config_path() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(fc) = toml::from_str::<FileConfig>(&content) {
                fc.runtime
            } else {
                RuntimeConfig::default()
            }
        } else {
            RuntimeConfig::default()
        }
    } else {
        RuntimeConfig::default()
    };
    if let Ok(v) = std::env::var("OSOOSI_DB_PATH") {
        if !v.trim().is_empty() {
            cfg.db_path = v.trim().to_string();
        }
    }
    if let Ok(v) = std::env::var("OSOOSI_TRAPS_PATH") {
        if !v.trim().is_empty() {
            cfg.traps_path = v.trim().to_string();
        }
    }
    if let Ok(v) = std::env::var("OSOOSI_SECURE_RUNTIME") {
        cfg.secure_runtime = Some(v.trim().to_string());
    }
    if let Ok(v) = std::env::var("OSOOSI_OPENSHELL_SANDBOX") {
        cfg.openshell_sandbox = v.trim().to_string();
    }
    if let Ok(v) = std::env::var("OSOOSI_OPENSHELL_POLICY") {
        cfg.openshell_policy = Some(v.trim().to_string());
    }
    cfg
}

/// Load sandbox security config from config file. Env: OSOOSI_WASM_HASH_REQUIRED.
pub fn load_sandbox_security_config() -> SandboxSecurityConfigPartial {
    let mut cfg = if let Some(path) = resolve_config_path() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(fc) = toml::from_str::<FileConfig>(&content) {
                fc.sandbox
            } else {
                SandboxSecurityConfigPartial::default()
            }
        } else {
            SandboxSecurityConfigPartial::default()
        }
    } else {
        SandboxSecurityConfigPartial::default()
    };
    if let Ok(v) = std::env::var("OSOOSI_WASM_HASH_REQUIRED") {
        cfg.wasm_hash_required = v == "1" || v.eq_ignore_ascii_case("true");
    }
    cfg
}

/// Load backup config from config file.
pub fn load_backup_config() -> BackupConfig {
    if let Some(path) = resolve_config_path() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(cfg) = toml::from_str::<FileConfig>(&content) {
                return cfg.backup;
            }
        }
    }
    BackupConfig::default()
}

/// Load repair config from config file. Env override: OSOOSI_PATCH_TEMPORARY_ADMIN_USER.
pub fn load_repair_config() -> RepairConfig {
    let mut cfg = if let Some(path) = resolve_config_path() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(fc) = toml::from_str::<FileConfig>(&content) {
                fc.repair
            } else {
                RepairConfig::default()
            }
        } else {
            RepairConfig::default()
        }
    } else {
        RepairConfig::default()
    };
    if let Ok(user) = std::env::var("OSOOSI_PATCH_TEMPORARY_ADMIN_USER") {
        let u = user.trim().to_string();
        if !u.is_empty() {
            cfg.patch_temporary_admin_user = Some(u);
        }
    }
    if let Ok(grp) = std::env::var("OSOOSI_PATCH_TEMPORARY_ADMIN_GROUP") {
        let g = grp.trim().to_string();
        if !g.is_empty() {
            cfg.patch_temporary_admin_group = Some(g);
        }
    }
    if let Ok(p) = std::env::var("OSOOSI_PATCH_HASH_STORE") {
        let path = p.trim().to_string();
        if !path.is_empty() {
            cfg.patch_hash_store_path = Some(path);
        }
    }
    if let Ok(v) = std::env::var("OSOOSI_REQUIRE_PATCH_HASH_VERIFICATION") {
        cfg.require_patch_hash_verification = v == "1" || v.eq_ignore_ascii_case("true");
    }
    cfg
}

/// Load hex-patch config from config file. Env: OSOOSI_HEXPATCH_ENABLED, OSOOSI_HEXPATCH_INTERVAL.
pub fn load_hexpatch_config() -> HexPatchConfig {
    let mut cfg = if let Some(path) = resolve_config_path() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(fc) = toml::from_str::<FileConfig>(&content) {
                fc.hex_patch
            } else {
                HexPatchConfig::default()
            }
        } else {
            HexPatchConfig::default()
        }
    } else {
        HexPatchConfig::default()
    };
    if let Ok(v) = std::env::var("OSOOSI_HEXPATCH_ENABLED") {
        cfg.enabled = v == "1" || v.eq_ignore_ascii_case("true");
    }
    if let Ok(v) = std::env::var("OSOOSI_HEXPATCH_INTERVAL") {
        if let Ok(n) = v.trim().parse::<u64>() {
            cfg.interval_secs = n.max(60);
        }
    }
    cfg
}

/// Load quarantine admin config from config file.
pub fn load_quarantine_admin_config() -> QuarantineAdminConfig {
    if let Some(path) = resolve_config_path() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(cfg) = toml::from_str::<FileConfig>(&content) {
                return cfg.quarantine_admin;
            }
        }
    }
    QuarantineAdminConfig::default()
}

/// Load autonomy config. Env overrides: OSOOSI_AUTO_APPROVE_THRESHOLD, OSOOSI_AUTO_QUARANTINE_MALWARE, OSOOSI_QUARANTINE_PATH.
pub fn load_autonomy_config() -> AutonomyConfig {
    let mut cfg = if let Some(path) = resolve_config_path() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(fc) = toml::from_str::<FileConfig>(&content) {
                fc.autonomy
            } else {
                AutonomyConfig::default()
            }
        } else {
            AutonomyConfig::default()
        }
    } else {
        AutonomyConfig::default()
    };
    if let Ok(v) = std::env::var("OSOOSI_AUTO_APPROVE_THRESHOLD") {
        if let Ok(f) = v.trim().parse::<f32>() {
            cfg.auto_approve_reputation_threshold = f.clamp(0.0, 1.0);
        }
    }
    if let Ok(v) = std::env::var("OSOOSI_AUTO_QUARANTINE_MALWARE") {
        cfg.auto_quarantine_malware = v == "1" || v.eq_ignore_ascii_case("true");
    }
    if let Ok(v) = std::env::var("OSOOSI_QUARANTINE_PATH") {
        if !v.trim().is_empty() {
            cfg.quarantine_path = v.trim().to_string();
        }
    }
    if let Ok(v) = std::env::var("OSOOSI_QUARANTINE_CONFIDENCE") {
        if let Ok(f) = v.trim().parse::<f32>() {
            cfg.quarantine_confidence_threshold = f.clamp(0.0, 1.0);
        }
    }
    if let Ok(v) = std::env::var("OSOOSI_QUARANTINE_EXCLUDE_PATHS") {
        let paths: Vec<String> = v
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !paths.is_empty() {
            cfg.quarantine_exclude_paths = paths;
        }
    }
    if let Ok(v) = std::env::var("OSOOSI_ACTION_CONFIDENCE") {
        if let Ok(f) = v.trim().parse::<f32>() {
            cfg.action_confidence_threshold = f.clamp(0.0, 1.0);
        }
    }
    cfg
}

/// Load peer rules from config file. Env: OSOOSI_REQUIRE_PATCHED, OSOOSI_REQUIRE_SUPPORTED_OS.
pub fn load_peer_rules_config() -> PeerRulesConfig {
    let mut cfg = if let Some(path) = resolve_config_path() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(fc) = toml::from_str::<FileConfig>(&content) {
                fc.wire.peer_rules
            } else {
                PeerRulesConfig::default()
            }
        } else {
            PeerRulesConfig::default()
        }
    } else {
        PeerRulesConfig::default()
    };
    if let Ok(v) = std::env::var("OSOOSI_REQUIRE_PATCHED") {
        cfg.require_patched = v == "1" || v.eq_ignore_ascii_case("true");
    }
    if let Ok(v) = std::env::var("OSOOSI_REQUIRE_SUPPORTED_OS") {
        cfg.require_supported_os = v == "1" || v.eq_ignore_ascii_case("true");
    }
    cfg
}
pub struct WireListenConfig {
    pub listen_addrs: Vec<String>,
    pub bootstrap_peers: Vec<String>,
    pub master_node_public_key: Option<String>,
    pub membership_proof: Option<String>,
    pub zone: String,
    pub nostr_relays: Vec<String>,
    pub allow_public_relays: bool,
    pub duckdns_domain: Option<String>,
    pub auto_bootstrap_duckdns: bool,
    pub duckdns_port: u16,
}

pub fn load_mesh_listen_config_extended() -> WireListenConfig {
    let mut listen_addrs = Vec::new();
    let mut bootstrap_peers = Vec::new();
    let mut master_node_public_key = None;
    let mut membership_proof = None;
    let mut zone = "Global".to_string();
    let mut nostr_relays = Vec::new();
    let mut allow_public_relays = true; // Default to true for better out-of-the-box connectivity
    let mut duckdns_domain = default_duckdns_domain();
    let mut auto_bootstrap_duckdns = true;
    let mut duckdns_port = default_duckdns_port();

    if let Some(path) = resolve_config_path() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(fc) = toml::from_str::<FileConfig>(&content) {
                master_node_public_key = fc.wire.master_node_public_key.clone();
                membership_proof = fc.wire.membership_proof.clone();
                if let Some(addr) = fc.wire.listen_addr {
                    // Convert "0.0.0.0:9876" to libp2p multiaddr if it's not already one
                    if addr.starts_with('/') {
                        listen_addrs.push(addr);
                    } else if let Ok(socket_addr) = addr.parse::<std::net::SocketAddr>() {
                        let ip = socket_addr.ip();
                        let port = socket_addr.port();
                        if ip.is_ipv4() {
                            listen_addrs.push(format!("/ip4/{}/tcp/{}", ip, port));
                        } else {
                            listen_addrs.push(format!("/ip6/{}/tcp/{}", ip, port));
                        }
                    }
                }
                for p in fc.wire.peers {
                    if p.starts_with('/') {
                        bootstrap_peers.push(p);
                    } else if let Ok(socket_addr) = p.parse::<std::net::SocketAddr>() {
                        let ip = socket_addr.ip();
                        let port = socket_addr.port();
                        if ip.is_ipv4() {
                            bootstrap_peers.push(format!("/ip4/{}/tcp/{}", ip, port));
                        } else {
                            bootstrap_peers.push(format!("/ip6/{}/tcp/{}", ip, port));
                        }
                    }
                }
                if let Some(z) = fc.wire.zone.clone() {
                    zone = z;
                }
                nostr_relays = fc.wire.nostr_relays.clone();
                allow_public_relays = fc.wire.allow_public_relays;
                duckdns_domain = fc.wire.duckdns_domain.clone();
                auto_bootstrap_duckdns = fc.wire.auto_bootstrap_duckdns;
                duckdns_port = fc.wire.duckdns_port;
            }
        }
    }

    // Overrides from ENV
    let env_listens = parse_csv_env_internal("OSOOSI_MESH_LISTEN_ADDRS");
    if !env_listens.is_empty() {
        listen_addrs = env_listens;
    }
    let env_peers = parse_csv_env_internal("OSOOSI_MESH_BOOTSTRAP_PEERS");
    if !env_peers.is_empty() {
        bootstrap_peers = env_peers;
    }
    if let Ok(pk) = std::env::var("OSOOSI_MASTER_NODE_PUBLIC_KEY") {
        master_node_public_key = Some(pk.trim().to_string());
    }
    if let Ok(proof) = std::env::var("OSOOSI_MEMBERSHIP_PROOF") {
        membership_proof = Some(proof.trim().to_string());
    }
    if let Ok(z) = std::env::var("OSOOSI_MESH_ZONE") {
        zone = z.trim().to_string();
    }
    if let Ok(v) = std::env::var("OSOOSI_ALLOW_PUBLIC_RELAYS") {
        allow_public_relays = v == "1" || v.eq_ignore_ascii_case("true");
    }
    if let Ok(d) = std::env::var("OSOOSI_DUCKDNS_DOMAIN") {
        let trimmed = d.trim();
        if !trimmed.is_empty() {
            duckdns_domain = Some(trimmed.to_string());
        }
    }
    if let Ok(v) = std::env::var("OSOOSI_AUTO_BOOTSTRAP_DUCKDNS") {
        auto_bootstrap_duckdns = v == "1" || v.eq_ignore_ascii_case("true");
    }
    if let Ok(p) = std::env::var("OSOOSI_DUCKDNS_PORT") {
        if let Ok(port) = p.trim().parse::<u16>() {
            duckdns_port = port;
        }
    }

    if listen_addrs.is_empty() {
        listen_addrs.push("/ip4/0.0.0.0/tcp/4001".to_string());
    }

    WireListenConfig {
        listen_addrs,
        bootstrap_peers,
        master_node_public_key,
        membership_proof,
        zone,
        nostr_relays,
        allow_public_relays,
        duckdns_domain,
        auto_bootstrap_duckdns,
        duckdns_port,
    }
}

pub fn load_mesh_listen_config() -> WireListenConfig {
    load_mesh_listen_config_extended()
}

/// Load bootstrap peers explicitly configured in osoosi.toml under [wire].peers.
pub fn load_wire_bootstrap_peers() -> Vec<String> {
    if let Some(path) = resolve_config_path() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(fc) = toml::from_str::<FileConfig>(&content) {
                return fc.wire.peers;
            }
        }
    }
    Vec::new()
}

/// Load DuckDNS configuration explicitly from osoosi.toml under [wire].
pub fn load_wire_duckdns_config() -> (Option<String>, bool, u16) {
    if let Some(path) = resolve_config_path() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(fc) = toml::from_str::<FileConfig>(&content) {
                return (fc.wire.duckdns_domain, fc.wire.auto_bootstrap_duckdns, fc.wire.duckdns_port);
            }
        }
    }
    (default_duckdns_domain(), true, default_duckdns_port())
}

fn parse_csv_env_internal(var_name: &str) -> Vec<String> {
    std::env::var(var_name)
        .ok()
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub sigma_rules_paths: Vec<PathBuf>,
    #[serde(default)]
    pub yara_rules_paths: Vec<PathBuf>,
    #[serde(default)]
    pub default_action: PolicyAction,
    /// Paths to exclude from consensus scanning (suppresses ALL voters for matching paths).
    #[serde(default)]
    pub consensus_exclude_paths: Vec<String>,
    /// Path substrings that should be considered 'trusted' by voters (quiets noisy voters like KEV).
    #[serde(default)]
    pub consensus_trusted_paths: Vec<String>,
    /// Executable stems (e.g. "git", "chrome") that are known to be noisy and should be suppressed by KEV/Intel voters.
    #[serde(default)]
    pub consensus_noisy_stems: Vec<String>,
    /// Alert suppression period in seconds (cooldown). Default: 600 (10 minutes).
    #[serde(default = "default_suppression_secs")]
    pub alert_suppression_secs: u64,
    /// Dynamic list of trusted file paths (case-insensitive substring match).
    #[serde(default = "default_trusted_paths")]
    pub trusted_paths: Vec<String>,
    /// Dynamic list of trusted executable stems (e.g. "git.exe").
    #[serde(default = "default_trusted_stems")]
    pub trusted_stems: Vec<String>,
}

fn default_trusted_paths() -> Vec<String> {
    vec![
        "\\windows\\system32".to_string(),
        "\\windows\\syswow64".to_string(),
        "\\.rustup\\".to_string(),
        "\\.cargo\\".to_string(),
        "\\program files\\git\\".to_string(),
        "\\tools\\git\\".to_string(),
    ]
}

fn default_trusted_stems() -> Vec<String> {
    vec![
        "rustc.exe".to_string(),
        "cargo.exe".to_string(),
        "git.exe".to_string(),
        "git-remote-http.exe".to_string(),
        "git-remote-https.exe".to_string(),
        "svchost.exe".to_string(),
        "conhost.exe".to_string(),
        "wermgr.exe".to_string(),
        "wmic.exe".to_string(),
        "where.exe".to_string(),
        "updater.exe".to_string(),
        "googleupdater.exe".to_string(),
    ]
}


fn default_suppression_secs() -> u64 {
    600
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            sigma_rules_paths: Vec::new(),
            yara_rules_paths: Vec::new(),
            default_action: PolicyAction::Alert,
            consensus_exclude_paths: Vec::new(),
            consensus_trusted_paths: Vec::new(),
            consensus_noisy_stems: Vec::new(),
            alert_suppression_secs: 600,
            trusted_paths: default_trusted_paths(),
            trusted_stems: default_trusted_stems(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    #[default]
    Alert,
    Block,
    Allow,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    pub db_path: String,
    #[serde(default)]
    pub tpm_signing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    #[serde(default = "default_fuel_limit")]
    pub action_fuel_limit: u64,
    #[serde(default = "default_max_memory")]
    pub action_max_memory: usize,
    /// SQLite database path. Env: OSOOSI_DB_PATH
    #[serde(default = "default_db_path")]
    pub db_path: String,
    /// Path for deception ghost files (HDS). Env: OSOOSI_TRAPS_PATH
    #[serde(default = "default_traps_path")]
    pub traps_path: String,
    /// Secure runtime to use for internet-facing tasks (e.g. "openshell", "none"). Env: OSOOSI_SECURE_RUNTIME
    #[serde(default)]
    pub secure_runtime: Option<String>,
    /// Name of the OpenShell sandbox to use. Env: OSOOSI_OPENSHELL_SANDBOX
    #[serde(default = "default_openshell_sandbox")]
    pub openshell_sandbox: String,
    /// Path to the OpenShell egress policy YAML. Env: OSOOSI_OPENSHELL_POLICY
    #[serde(default)]
    pub openshell_policy: Option<String>,
}

fn default_fuel_limit() -> u64 {
    500_000
}
fn default_max_memory() -> usize {
    8_388_608
}
fn default_db_path() -> String {
    "./database/osoosi.db".to_string()
}
fn default_traps_path() -> String {
    "./traps".to_string()
}
fn default_openshell_sandbox() -> String {
    "osoosi-agent".to_string()
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            action_fuel_limit: default_fuel_limit(),
            action_max_memory: default_max_memory(),
            db_path: default_db_path(),
            traps_path: default_traps_path(),
            secure_runtime: None,
            openshell_sandbox: default_openshell_sandbox(),
            openshell_policy: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub url: String,
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExporterConfig {
    #[serde(default)]
    pub webhooks: Vec<WebhookConfig>,
}

/// Repair/patch configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RepairConfig {
    /// User to temporarily add to admin group before patching, then remove after.
    /// Use "current" to grant the current user. Requires agent to run as Administrator/root.
    /// Windows: net localgroup administrators &lt;user&gt; /add, /delete
    /// Linux: gpasswd -a &lt;user&gt; &lt;group&gt; (group from patch_temporary_admin_group, default sudo/wheel)
    /// macOS: dseditgroup -o edit -a &lt;user&gt; -t user admin
    #[serde(default)]
    pub patch_temporary_admin_user: Option<String>,
    /// Linux only: group for temporary admin (sudo or wheel). Default: auto-detect (sudo then wheel).
    #[serde(default)]
    pub patch_temporary_admin_group: Option<String>,
    /// Path to patch hash store (JSON) for legitimacy verification. Default: data/patch_hashes.json
    #[serde(default)]
    pub patch_hash_store_path: Option<String>,
    /// Require hash verification before applying patches from download URLs. Reject if hash unknown or mismatch.
    #[serde(default)]
    pub require_patch_hash_verification: bool,
}

/// Peer join rules: unpatched or out-of-support OS cannot join the mesh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRulesConfig {
    /// Block peers with pending security patches (default: true).
    #[serde(default = "default_true")]
    pub require_patched: bool,
    /// Block peers on out-of-support OS (default: true).
    #[serde(default = "default_true")]
    pub require_supported_os: bool,
    /// Require TPM 2.0 remote attestation for mesh join (default: false).
    #[serde(default)]
    pub require_tpm_attestation: bool,
}

impl Default for PeerRulesConfig {
    fn default() -> Self {
        Self {
            require_patched: true,
            require_supported_os: true,
            require_tpm_attestation: false,
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireConfig {
    pub listen_addr: String,
    pub shared_secret: String,
    #[serde(default)]
    pub peers: Vec<String>,
    /// Minimum reputation score (0.0–1.0) required for auto-approval; below this, user must approve
    #[serde(default = "default_min_reputation")]
    pub min_reputation_auto_approve: f32,
    #[serde(default)]
    pub peer_rules: PeerRulesConfig,
    /// Public key of the Master Node (ed25519 hex). If set, only peers signed by this key can join.
    #[serde(default)]
    pub master_node_public_key: Option<String>,
    /// Zonal Sharding: The logical zone for this node (e.g. Finance, HR).
    #[serde(default)]
    pub zone: Option<String>,
    /// Nostr Relays for decentralized threat intelligence sharing.
    #[serde(default)]
    pub nostr_relays: Vec<String>,
    /// Security: Allow fallback to public Nostr relays.
    #[serde(default = "default_true")]
    pub allow_public_relays: bool,
    #[serde(default = "default_duckdns_domain")]
    pub duckdns_domain: Option<String>,
    #[serde(default = "default_true")]
    pub auto_bootstrap_duckdns: bool,
    #[serde(default = "default_duckdns_port")]
    pub duckdns_port: u16,
}

pub fn default_duckdns_domain() -> Option<String> {
    Some("oshoosi".to_string())
}

pub fn default_duckdns_port() -> u16 {
    4001
}

fn default_min_reputation() -> f32 {
    1.0 // Require explicit approval by default (no auto-approve)
}

/// AI configuration: enable/disable ML features.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    /// Enable AI features (ONNX, SmolLM, etc.).
    #[serde(default = "default_ai_enabled")]
    pub enabled: bool,
    /// Optional HTTPS URL to MalConv **Candle** weights as `.safetensors` (tensor names must match `osoosi_model::MalConv`).
    /// Note: [cycloevan/malconv](https://huggingface.co/cycloevan/malconv) is a TensorFlow/Keras **training** reference (`.h5`);
    /// it is not a Hugging Face Inference deployment and does not supply this format by default—use a converted weights URL or bundled repo below.
    #[serde(default)]
    pub malconv_weights_url: Option<String>,
    /// Ollama model used for LLM reasoning (e.g. "deepseek-r1:1.5b").
    #[serde(default = "default_reasoning_model")]
    pub reasoning_model: String,
    /// Maximum seconds an LLM inference call may run before being killed.
    #[serde(default = "default_llm_timeout")]
    pub llm_timeout_secs: u64,
    /// Ollama API endpoint URL.
    #[serde(default = "default_reasoning_url")]
    pub reasoning_url: String,
    /// Ordered fallback model list when the primary is not available.
    #[serde(default = "default_fallback_models")]
    pub fallback_models: Vec<String>,
    /// COLOG anomaly threshold (0.0–1.0).  Events above trigger anomaly.
    #[serde(default = "default_colog_threshold")]
    pub colog_threshold: f64,
    /// Enable Foundation-Sec model.
    #[serde(default = "default_true")]
    pub foundation_sec_enabled: bool,
    /// Model name/path for Foundation-Sec (e.g. "fenkohq/foundation-sec-8b").
    #[serde(default = "default_foundation_sec_model")]
    pub foundation_sec_model: String,
}

fn default_ai_enabled() -> bool {
    true
}

fn default_reasoning_model() -> String {
    "deepseek-r1:1.5b".to_string()
}
fn default_llm_timeout() -> u64 {
    90
}
fn default_reasoning_url() -> String {
    "http://127.0.0.1:11434/v1/chat/completions".to_string()
}
fn default_fallback_models() -> Vec<String> {
    vec!["gemma3:1b".into(), "gemma3:4b".into(), "qwen2.5:1.5b".into(), "phi3:mini".into()]
}
fn default_colog_threshold() -> f64 {
    0.85
}
fn default_foundation_sec_model() -> String {
    "fenkohq/foundation-sec-8b".to_string()
}

fn apply_ai_env_overrides(mut c: AiConfig) -> AiConfig {
    if let Ok(v) = std::env::var("OSOOSI_NO_AI") {
        if v == "1" || v.eq_ignore_ascii_case("true") {
            c.enabled = false;
        }
    }
    if let Ok(url) = std::env::var("OSOOSI_MALCONV_WEIGHTS_URL") {
        let t = url.trim();
        if !t.is_empty() {
            c.malconv_weights_url = Some(t.to_string());
        }
    }
    if let Ok(v) = std::env::var("OSOOSI_REASONING_MODEL") {
        c.reasoning_model = v;
    } else if let Ok(v) = std::env::var("OSOOSI_OLLAMA_MODEL") {
        c.reasoning_model = v;
    }
    if let Ok(v) = std::env::var("OSOOSI_LLM_TIMEOUT_SECS") {
        if let Ok(s) = v.parse() {
            c.llm_timeout_secs = s;
        }
    }
    if let Ok(v) = std::env::var("OSOOSI_REASONING_URL") {
        c.reasoning_url = v;
    }
    if let Ok(v) = std::env::var("OSOOSI_FOUNDATION_SEC_ENABLED") {
        c.foundation_sec_enabled = v == "1" || v.eq_ignore_ascii_case("true");
    }
    if let Ok(v) = std::env::var("OSOOSI_FOUNDATION_SEC_MODEL") {
        c.foundation_sec_model = v;
    }
    c
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            // Bundled weights mirror (Candle safetensors). cycloevan/malconv is TF `.h5` + training code, not HF inference.
            malconv_weights_url: Some("https://huggingface.co/oyesanyf/OshoosiClaw-Weights/resolve/main/malconv.safetensors?download=true".to_string()),
            reasoning_model: default_reasoning_model(),
            llm_timeout_secs: default_llm_timeout(),
            reasoning_url: default_reasoning_url(),
            fallback_models: default_fallback_models(),
            colog_threshold: default_colog_threshold(),
            foundation_sec_enabled: true,
            foundation_sec_model: default_foundation_sec_model(),
        }
    }
}

pub fn load_ai_config() -> AiConfig {
    if let Some(path) = resolve_config_path() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(cfg) = toml::from_str::<FileConfig>(&content) {
                return apply_ai_env_overrides(cfg.ai);
            }
        }
    }
    apply_ai_env_overrides(AiConfig::default())
}

/// Heavener EDR configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeavenerConfig {
    #[serde(default = "default_true")]
    pub enable_unhooking_scanner: bool,
    #[serde(default = "default_true")]
    pub enable_stack_spoof_check: bool,
    #[serde(default = "default_true")]
    pub enable_creator_pid_validation: bool,
}

impl Default for HeavenerConfig {
    fn default() -> Self {
        Self {
            enable_unhooking_scanner: true,
            enable_stack_spoof_check: true,
            enable_creator_pid_validation: true,
        }
    }
}

pub fn load_heavener_config() -> HeavenerConfig {
    if let Some(path) = resolve_config_path() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(cfg) = toml::from_str::<FileConfig>(&content) {
                return cfg.heavener;
            }
        }
    }
    HeavenerConfig::default()
}

/// Keys under `[external_api]` in `osoosi.toml` (e.g. OTX, NVD). Environment always wins; see
/// `resolve_otx_api_key` / `resolve_nvd_api_key`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExternalApiConfig {
    #[serde(default)]
    pub otx_api_key: Option<String>,
    #[serde(default)]
    pub nvd_api_key: Option<String>,
}

/// Loads `[external_api]` from the resolved `osoosi.toml` (if present).
pub fn load_external_api_config() -> ExternalApiConfig {
    if let Some(path) = resolve_config_path() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(cfg) = toml::from_str::<FileConfig>(&content) {
                return cfg.external_api;
            }
        }
    }
    ExternalApiConfig::default()
}

/// OTX API key: `OTX_API_KEY` overrides `[external_api].otx_api_key` in `osoosi.toml`.
pub fn resolve_otx_api_key() -> Option<String> {
    if let Ok(v) = std::env::var("OTX_API_KEY") {
        let t = v.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    load_external_api_config().otx_api_key.and_then(|s| {
        let t = s.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    })
}

/// NVD API key: `NVD_API_KEY` overrides `[external_api].nvd_api_key` in `osoosi.toml`.
pub fn resolve_nvd_api_key() -> Option<String> {
    if let Ok(v) = std::env::var("NVD_API_KEY") {
        let t = v.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    load_external_api_config().nvd_api_key.and_then(|s| {
        let t = s.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    })
}

/// Load policy config from config file. Env overrides: OSOOSI_POLICY_EXCLUDE_PATHS, OSOOSI_POLICY_TRUSTED_PATHS, OSOOSI_POLICY_NOISY_STEMS.
pub fn load_policy_config() -> PolicyConfig {
    let mut cfg = if let Some(path) = resolve_config_path() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(fc) = toml::from_str::<FileConfig>(&content) {
                fc.policy
            } else {
                PolicyConfig::default()
            }
        } else {
            PolicyConfig::default()
        }
    } else {
        PolicyConfig::default()
    };
    if let Ok(v) = std::env::var("OSOOSI_POLICY_EXCLUDE_PATHS") {
        cfg.consensus_exclude_paths.extend(v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
    }
    if let Ok(v) = std::env::var("OSOOSI_POLICY_TRUSTED_PATHS") {
        cfg.consensus_trusted_paths.extend(v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
    }
    if let Ok(v) = std::env::var("OSOOSI_POLICY_NOISY_STEMS") {
        cfg.consensus_noisy_stems.extend(v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
    }
    cfg
}

/// Log retention and intelligent rotation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRetentionConfig {
    #[serde(default = "default_max_log_days")]
    pub max_log_days: u32, // default: 14
    #[serde(default = "default_max_total_size_mb")]
    pub max_total_size_mb: u64, // default: 500
    #[serde(default = "default_max_single_file_size_mb")]
    pub max_single_file_size_mb: u64, // default: 50
}

fn default_max_log_days() -> u32 {
    14
}

fn default_max_total_size_mb() -> u64 {
    500
}

fn default_max_single_file_size_mb() -> u64 {
    50
}

impl Default for LogRetentionConfig {
    fn default() -> Self {
        Self {
            max_log_days: default_max_log_days(),
            max_total_size_mb: default_max_total_size_mb(),
            max_single_file_size_mb: default_max_single_file_size_mb(),
        }
    }
}

/// Loads `[log_retention]` from `osoosi.toml` (if present), or returns defaults.
pub fn load_log_retention_config() -> LogRetentionConfig {
    if let Some(path) = resolve_config_path() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(fc) = toml::from_str::<FileConfig>(&content) {
                return fc.log_retention;
            }
        }
    }
    LogRetentionConfig::default()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillsConfig {
    /// Whether the WikiSkill engine is enabled.
    #[serde(default = "default_skills_enabled")]
    pub enabled: bool,
    /// Whether to automatically initialize and run the self-evolution loop on EDR daemon startup.
    #[serde(default = "default_skills_auto_evolve")]
    pub auto_evolve_on_start: bool,
    /// Evolution workspace directory path.
    #[serde(default = "default_skills_workspace")]
    pub workspace: String,
    /// Path to the ground-truth tasks catalog JSON.
    #[serde(default = "default_skills_tasks_file")]
    pub tasks_file: String,
    #[serde(default = "default_skills_scorer")]
    pub scorer: String,
    /// Interval in seconds between evolution / evaluation cycles (default: 300s / 5m).
    #[serde(default = "default_skills_poll_interval")]
    pub poll_interval_secs: u64,
}

fn default_skills_enabled() -> bool { true }
fn default_skills_auto_evolve() -> bool { true }
fn default_skills_workspace() -> String { "runs/edr-evolution".to_string() }
fn default_skills_tasks_file() -> String { "examples/edr-skill-evolution/tasks.json".to_string() }
fn default_skills_scorer() -> String { "examples/edr-skill-evolution/scorer.py".to_string() }
fn default_skills_poll_interval() -> u64 { 300 }

impl Default for SkillsConfig {
    fn default() -> Self {
        Self {
            enabled: default_skills_enabled(),
            auto_evolve_on_start: default_skills_auto_evolve(),
            workspace: default_skills_workspace(),
            tasks_file: default_skills_tasks_file(),
            scorer: default_skills_scorer(),
            poll_interval_secs: default_skills_poll_interval(),
        }
    }
}

pub fn load_skills_config() -> SkillsConfig {
    let path = resolve_config_path().unwrap_or_else(|| PathBuf::from("osoosi.toml"));
    if path.exists() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(cfg) = toml::from_str::<FileConfig>(&content) {
                return cfg.skills;
            }
        }
    }
    SkillsConfig::default()
}

fn default_forensics_enabled() -> bool {
    true
}

fn default_forensics_binary() -> String {
    "tools/velociraptor/velociraptor.exe".to_string()
}

fn default_forensics_timeout() -> u64 {
    30
}

fn default_forensics_max_mem() -> u64 {
    512
}

fn default_forensics_max_lines() -> usize {
    10000
}

fn default_forensics_staging() -> String {
    "runs/forensics".to_string()
}

fn default_forensics_auto() -> bool {
    true
}

fn default_forensics_min_conf() -> f32 {
    0.80
}

fn default_forensics_techniques() -> Vec<String> {
    vec![
        "T1055".to_string(),
        "T1055.012".to_string(),
        "T1003".to_string(),
        "T1014".to_string(),
        "T1547".to_string(),
        "T1059".to_string(),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicsConfig {
    #[serde(default = "default_forensics_enabled")]
    pub enabled: bool,
    #[serde(default = "default_forensics_binary")]
    pub binary_path: String,
    #[serde(default = "default_forensics_timeout")]
    pub execution_timeout_secs: u64,
    #[serde(default = "default_forensics_max_mem")]
    pub max_memory_mb: u64,
    #[serde(default = "default_forensics_max_lines")]
    pub max_output_lines: usize,
    #[serde(default = "default_forensics_staging")]
    pub staging_dir: String,
    #[serde(default = "default_forensics_auto")]
    pub auto_investigate: bool,
    #[serde(default = "default_forensics_min_conf")]
    pub min_trigger_confidence: f32,
    #[serde(default = "default_forensics_techniques")]
    pub trigger_techniques: Vec<String>,
}

impl Default for ForensicsConfig {
    fn default() -> Self {
        Self {
            enabled: default_forensics_enabled(),
            binary_path: default_forensics_binary(),
            execution_timeout_secs: default_forensics_timeout(),
            max_memory_mb: default_forensics_max_mem(),
            max_output_lines: default_forensics_max_lines(),
            staging_dir: default_forensics_staging(),
            auto_investigate: default_forensics_auto(),
            min_trigger_confidence: default_forensics_min_conf(),
            trigger_techniques: default_forensics_techniques(),
        }
    }
}

pub fn load_forensics_config() -> ForensicsConfig {
    let path = resolve_config_path().unwrap_or_else(|| PathBuf::from("osoosi.toml"));
    if path.exists() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(cfg) = toml::from_str::<FileConfig>(&content) {
                return cfg.forensics;
            }
        }
    }
    ForensicsConfig::default()
}

fn default_decision_provider() -> String {
    "local".to_string()
}

fn default_decision_model() -> String {
    "@cf/cloudflare/clef-flash".to_string()
}

fn default_decision_timeout_ms() -> u64 {
    500
}

fn default_min_action_confidence() -> f64 {
    0.80
}

fn default_decision_model_dir() -> String {
    "models/clef".to_string()
}

fn default_hybrid_strategy() -> String {
    "cascade".to_string()
}

fn default_strands_endpoint() -> Option<String> {
    Some("http://127.0.0.1:4003".to_string())
}

fn default_strands_model() -> String {
    "StrandsAgents/strands-decider-2B-hobson-v19".to_string()
}

fn default_strands_timeout_ms() -> u64 {
    800
}

/// Configuration for the non-autoregressive Clef Decision Model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionModelConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Provider: "local", "cloudflare", "auto" (default: "local" for air-gapped self-hosted execution)
    #[serde(default = "default_decision_provider")]
    pub provider: String,
    /// Model ID on Workers AI (e.g. "@cf/cloudflare/clef-flash" or "@cf/cloudflare/clef") or local model
    #[serde(default = "default_decision_model")]
    pub model: String,
    #[serde(default)]
    pub cloudflare_account_id: Option<String>,
    #[serde(default)]
    pub cloudflare_api_token: Option<String>,
    /// Execution timeout in milliseconds (default: 500ms)
    #[serde(default = "default_decision_timeout_ms")]
    pub timeout_ms: u64,
    /// Fallback to local non-autoregressive evaluator if Cloudflare fails or is offline
    #[serde(default = "default_true")]
    pub fallback_to_local: bool,
    /// Minimum probability threshold to trigger automated containment (default: 0.80)
    #[serde(default = "default_min_action_confidence")]
    pub min_action_confidence: f64,
    /// Automatically trigger background causal reasoning (FoundationSec) when flagged
    #[serde(default = "default_true")]
    pub auto_escalate_to_cortex: bool,
    /// Path to local weights / calibration tables (default: "models/clef")
    #[serde(default = "default_decision_model_dir")]
    pub model_dir: String,
    /// Hybrid strategy: "cascade", "consensus", "local_first"
    #[serde(default = "default_hybrid_strategy")]
    pub hybrid_strategy: String,
    /// Local or remote endpoint for Strands Decider 2B service
    #[serde(default = "default_strands_endpoint")]
    pub strands_endpoint: Option<String>,
    /// Strands Decider 2B model name / repo
    #[serde(default = "default_strands_model")]
    pub strands_model: String,
    /// Timeout for Strands Decider 2B in milliseconds (default: 800ms)
    #[serde(default = "default_strands_timeout_ms")]
    pub strands_timeout_ms: u64,
}

impl Default for DecisionModelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            provider: default_decision_provider(),
            model: default_decision_model(),
            cloudflare_account_id: None,
            cloudflare_api_token: None,
            timeout_ms: default_decision_timeout_ms(),
            fallback_to_local: true,
            min_action_confidence: default_min_action_confidence(),
            auto_escalate_to_cortex: true,
            model_dir: default_decision_model_dir(),
            hybrid_strategy: default_hybrid_strategy(),
            strands_endpoint: default_strands_endpoint(),
            strands_model: default_strands_model(),
            strands_timeout_ms: default_strands_timeout_ms(),
        }
    }
}

pub fn load_decision_model_config() -> DecisionModelConfig {
    let path = resolve_config_path().unwrap_or_else(|| PathBuf::from("osoosi.toml"));
    let mut cfg = if path.exists() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(fc) = toml::from_str::<FileConfig>(&content) {
                fc.decision_model
            } else {
                DecisionModelConfig::default()
            }
        } else {
            DecisionModelConfig::default()
        }
    } else {
        DecisionModelConfig::default()
    };

    if let Ok(val) = std::env::var("OSOOSI_DECISION_PROVIDER") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            cfg.provider = trimmed.to_string();
        }
    }
    if let Ok(val) = std::env::var("OSOOSI_DECISION_MODEL") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            cfg.model = trimmed.to_string();
        }
    }
    if let Ok(val) = std::env::var("CLOUDFLARE_ACCOUNT_ID") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            cfg.cloudflare_account_id = Some(trimmed.to_string());
        }
    }
    if let Ok(val) = std::env::var("CLOUDFLARE_API_TOKEN") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            cfg.cloudflare_api_token = Some(trimmed.to_string());
        }
    }
    if let Ok(val) = std::env::var("OSOOSI_HYBRID_STRATEGY") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            cfg.hybrid_strategy = trimmed.to_string();
        }
    }
    if let Ok(val) = std::env::var("STRANDS_ENDPOINT") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            cfg.strands_endpoint = Some(trimmed.to_string());
        }
    }
    if let Ok(val) = std::env::var("STRANDS_MODEL") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            cfg.strands_model = trimmed.to_string();
        }
    }
    if let Ok(val) = std::env::var("STRANDS_TIMEOUT_MS") {
        if let Ok(ms) = val.trim().parse::<u64>() {
            cfg.strands_timeout_ms = ms;
        }
    }

    cfg
}

/// LangGraph Autonomous Multi-Agent Defense Swarm configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmConfig {
    #[serde(default = "default_swarm_enabled")]
    pub enabled: bool,
    #[serde(default = "default_swarm_url")]
    pub service_url: String,
    #[serde(default = "default_swarm_auto_trigger")]
    pub auto_trigger_on_threat: bool,
    #[serde(default = "default_swarm_min_confidence")]
    pub min_trigger_confidence: f32,
    #[serde(default = "default_swarm_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_swarm_enabled() -> bool {
    true
}

fn default_swarm_url() -> String {
    "http://127.0.0.1:4002".to_string()
}

fn default_swarm_auto_trigger() -> bool {
    true
}

fn default_swarm_min_confidence() -> f32 {
    0.85
}

fn default_swarm_timeout_secs() -> u64 {
    30
}

impl Default for SwarmConfig {
    fn default() -> Self {
        Self {
            enabled: default_swarm_enabled(),
            service_url: default_swarm_url(),
            auto_trigger_on_threat: default_swarm_auto_trigger(),
            min_trigger_confidence: default_swarm_min_confidence(),
            timeout_secs: default_swarm_timeout_secs(),
        }
    }
}

pub fn load_swarm_config() -> SwarmConfig {
    let path = resolve_config_path().unwrap_or_else(|| PathBuf::from("osoosi.toml"));
    let mut cfg = if path.exists() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(fc) = toml::from_str::<FileConfig>(&content) {
                fc.swarm
            } else {
                SwarmConfig::default()
            }
        } else {
            SwarmConfig::default()
        }
    } else {
        SwarmConfig::default()
    };

    if let Ok(val) = std::env::var("OSOOSI_SWARM_ENABLED") {
        let trimmed = val.trim();
        if trimmed == "0" || trimmed.eq_ignore_ascii_case("false") {
            cfg.enabled = false;
        } else if trimmed == "1" || trimmed.eq_ignore_ascii_case("true") {
            cfg.enabled = true;
        }
    }
    if let Ok(val) = std::env::var("OSOOSI_SWARM_URL") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            cfg.service_url = trimmed.to_string();
        }
    }
    if let Ok(val) = std::env::var("OSOOSI_SWARM_AUTO_TRIGGER") {
        let trimmed = val.trim();
        if trimmed == "0" || trimmed.eq_ignore_ascii_case("false") {
            cfg.auto_trigger_on_threat = false;
        } else if trimmed == "1" || trimmed.eq_ignore_ascii_case("true") {
            cfg.auto_trigger_on_threat = true;
        }
    }
    if let Ok(val) = std::env::var("OSOOSI_SWARM_MIN_CONFIDENCE") {
        if let Ok(num) = val.trim().parse::<f32>() {
            cfg.min_trigger_confidence = num;
        }
    }
    if let Ok(val) = std::env::var("OSOOSI_SWARM_TIMEOUT_SECS") {
        if let Ok(num) = val.trim().parse::<u64>() {
            cfg.timeout_secs = num;
        }
    }

    cfg
}

/// Hardware performance tiers dynamically resolved from available system resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HardwareTier {
    UltraLite,  // < 4 GB total RAM or < 1.5 GB free: Magika, EMBER, Local Brier only; no browser
    Lite,       // 4-8 GB total RAM or 1.5-4 GB free: SOREL, SecureBERT, Clef Flash; no browser unless forced
    Standard,   // 8-16 GB total RAM: Strands Decider 2B, LangGraph swarm, browser allowed
    Enterprise, // > 16 GB total RAM: Full models including FoundationSec-8B and full NSRL
}

/// Dynamic system resource thresholds and model execution gating configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesConfig {
    /// Hardware profile: "auto", "ultralite", "lite", "standard", "enterprise"
    #[serde(default = "default_resource_profile")]
    pub profile: String,
    /// Minimum available free RAM in MB required to auto-launch external browser (default: 2500 MB)
    #[serde(default = "default_min_free_ram_browser")]
    pub min_free_ram_mb_for_browser: u64,
    /// Minimum free RAM in MB for FoundationSec / Gemma 4 (default: 8192 MB)
    #[serde(default = "default_min_free_ram_foundation")]
    pub min_free_ram_mb_for_foundation_sec: u64,
    /// Minimum free RAM in MB for Strands Decider 2B SLM (default: 3500 MB)
    #[serde(default = "default_min_free_ram_strands")]
    pub min_free_ram_mb_for_strands_decider: u64,
    /// Minimum free RAM in MB for SecureBERT ONNX (default: 800 MB)
    #[serde(default = "default_min_free_ram_securebert")]
    pub min_free_ram_mb_for_securebert: u64,
    /// Minimum free RAM in MB for SOREL-20M (default: 350 MB)
    #[serde(default = "default_min_free_ram_sorel")]
    pub min_free_ram_mb_for_sorel: u64,
    /// Minimum free RAM in MB for MalConv / EMBER (default: 150 MB)
    #[serde(default = "default_min_free_ram_malconv")]
    pub min_free_ram_mb_for_malconv: u64,
    /// Automatically suppress heavy external browser if available RAM < min_free_ram_mb_for_browser
    #[serde(default = "default_true")]
    pub auto_suppress_browser_on_low_ram: bool,
    /// Automatically skip heavy AI downloads and model loads if RAM is insufficient
    #[serde(default = "default_true")]
    pub auto_throttle_ai_on_low_ram: bool,
    /// NSRL cache entry limit based on memory (None = dynamic based on tier)
    #[serde(default)]
    pub nsrl_cache_limit: Option<usize>,
}

fn default_resource_profile() -> String {
    "auto".to_string()
}

fn default_min_free_ram_browser() -> u64 {
    2500
}

fn default_min_free_ram_foundation() -> u64 {
    8192
}

fn default_min_free_ram_strands() -> u64 {
    3500
}

fn default_min_free_ram_securebert() -> u64 {
    800
}

fn default_min_free_ram_sorel() -> u64 {
    350
}

fn default_min_free_ram_malconv() -> u64 {
    150
}

impl Default for ResourcesConfig {
    fn default() -> Self {
        Self {
            profile: default_resource_profile(),
            min_free_ram_mb_for_browser: default_min_free_ram_browser(),
            min_free_ram_mb_for_foundation_sec: default_min_free_ram_foundation(),
            min_free_ram_mb_for_strands_decider: default_min_free_ram_strands(),
            min_free_ram_mb_for_securebert: default_min_free_ram_securebert(),
            min_free_ram_mb_for_sorel: default_min_free_ram_sorel(),
            min_free_ram_mb_for_malconv: default_min_free_ram_malconv(),
            auto_suppress_browser_on_low_ram: true,
            auto_throttle_ai_on_low_ram: true,
            nsrl_cache_limit: None,
        }
    }
}

pub fn load_resources_config() -> ResourcesConfig {
    let path = resolve_config_path().unwrap_or_else(|| PathBuf::from("osoosi.toml"));
    let mut cfg = if path.exists() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(fc) = toml::from_str::<FileConfig>(&content) {
                fc.resources
            } else {
                ResourcesConfig::default()
            }
        } else {
            ResourcesConfig::default()
        }
    } else {
        ResourcesConfig::default()
    };

    if let Ok(val) = std::env::var("OSOOSI_RESOURCE_PROFILE") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            cfg.profile = trimmed.to_string();
        }
    }

    cfg
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsoosiConfig {
    pub agent: AgentConfig,
    pub telemetry: TelemetryConfig,
    pub policy: PolicyConfig,
    pub audit: AuditConfig,
    pub runtime: RuntimeConfig,
    pub exporter: ExporterConfig,
    pub wire: WireConfig,
    #[serde(default)]
    pub resources: ResourcesConfig,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_autonomy_mode_and_presets() {
        let mut cfg = AutonomyConfig::default();
        // default is auto_quarantine: false, action_threshold: 0.80 -> Audit
        assert_eq!(cfg.current_mode(), AutonomyMode::Audit);
        assert_eq!(cfg.current_mode().as_str(), "audit");

        cfg.apply_preset("active");
        assert!(cfg.auto_quarantine_malware);
        assert!((cfg.action_confidence_threshold - 0.50).abs() < 1e-4);
        assert!((cfg.quarantine_confidence_threshold - 0.80).abs() < 1e-4);
        assert_eq!(cfg.current_mode(), AutonomyMode::Active);
        assert_eq!(cfg.current_mode().as_str(), "active");

        cfg.apply_preset("lockdown");
        assert!(cfg.auto_quarantine_malware);
        assert!((cfg.action_confidence_threshold - 0.35).abs() < 1e-4);
        assert!((cfg.quarantine_confidence_threshold - 0.60).abs() < 1e-4);
        assert_eq!(cfg.current_mode(), AutonomyMode::Lockdown);
        assert_eq!(cfg.current_mode().as_str(), "lockdown");

        cfg.apply_preset("audit");
        assert!(!cfg.auto_quarantine_malware);
        assert!((cfg.action_confidence_threshold - 0.80).abs() < 1e-4);
        assert!((cfg.quarantine_confidence_threshold - 0.95).abs() < 1e-4);
        assert_eq!(cfg.current_mode(), AutonomyMode::Audit);

        // Custom mode
        cfg.action_confidence_threshold = 0.22;
        assert_eq!(cfg.current_mode(), AutonomyMode::Custom);
        assert_eq!(cfg.current_mode().as_str(), "custom");
    }

    #[test]
    fn test_save_autonomy_config() {
        let temp_dir = std::env::temp_dir().join(format!("osoosi_test_{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let config_file = temp_dir.join("osoosi.toml");

        let initial_toml = r#"
# Global AI configuration
[ai]
enabled = true

[autonomy]
# Reputation threshold
auto_approve_reputation_threshold = 0.40
auto_quarantine_malware = false
quarantine_confidence_threshold = 0.95
action_confidence_threshold = 0.80
auto_replace_malware_binaries = true
quarantine_path = "./quarantine"

[runtime]
db_path = "./test.db"
"#;
        std::fs::write(&config_file, initial_toml).unwrap();

        let mut cfg = AutonomyConfig::default();
        cfg.apply_preset("active");
        cfg.auto_approve_reputation_threshold = 0.65;
        cfg.auto_replace_malware_binaries = false;

        save_autonomy_config_to_path(&cfg, &config_file).unwrap();

        let read_back = std::fs::read_to_string(&config_file).unwrap();
        // Preserved [ai] and [runtime]
        assert!(read_back.contains("[ai]"));
        assert!(read_back.contains("enabled = true"));
        assert!(read_back.contains("[runtime]"));
        assert!(read_back.contains("db_path = \"./test.db\""));
        assert!(read_back.contains("# Reputation threshold"));

        // Updated autonomy values
        assert!(read_back.contains("auto_quarantine_malware = true"));
        assert!(read_back.contains("action_confidence_threshold = 0.50"));
        assert!(read_back.contains("quarantine_confidence_threshold = 0.80"));
        assert!(read_back.contains("auto_approve_reputation_threshold = 0.65"));
        assert!(read_back.contains("auto_replace_malware_binaries = false"));

        // Also test save_autonomy_config via OSOOSI_CONFIG env var
        std::env::set_var("OSOOSI_CONFIG", &config_file);
        let mut cfg_lockdown = AutonomyConfig::default();
        cfg_lockdown.apply_preset("lockdown");
        save_autonomy_config(&cfg_lockdown).unwrap();
        std::env::remove_var("OSOOSI_CONFIG");

        let final_content = std::fs::read_to_string(&config_file).unwrap();
        assert!(final_content.contains("action_confidence_threshold = 0.35"));
        assert!(final_content.contains("quarantine_confidence_threshold = 0.60"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_update_autonomy_content_edge_cases() {
        // 1. Whitespace in table headers and inline comments
        let complex_toml = r#"
# Heading
[ autonomy ] # Main Autonomy Settings
auto_quarantine_malware = false # Disable by default for non-intrusive mode
quarantine_confidence_threshold = 0.95
action_confidence_threshold = 0.80 # Action threshold
auto_approve_reputation_threshold = 0.40
auto_replace_malware_binaries = true
quarantine_path = "./quarantine"

[ runtime ] # Secondary section
db_path = "./db.sqlite"
"#;
        let mut cfg = AutonomyConfig::default();
        cfg.apply_preset("  ACTIVE  \n");
        assert_eq!(cfg.current_mode(), AutonomyMode::Active);

        let updated = update_autonomy_content(complex_toml, &cfg);
        // Ensure no duplicate [autonomy] was added
        assert_eq!(updated.matches("autonomy").count(), 1);
        // Ensure inline comments on key lines are preserved
        assert!(updated.contains("auto_quarantine_malware = true # Disable by default for non-intrusive mode"));
        assert!(updated.contains("action_confidence_threshold = 0.50 # Action threshold"));
        // Ensure subsequent section is preserved intact
        assert!(updated.contains("[ runtime ] # Secondary section"));
        assert!(updated.contains("db_path = \"./db.sqlite\""));

        // 2. Empty content initialization
        let empty_updated = update_autonomy_content("", &cfg);
        assert!(empty_updated.starts_with("[autonomy]\n"));
        assert!(empty_updated.ends_with('\n'));
        assert!(empty_updated.contains("auto_quarantine_malware = true"));
        assert!(empty_updated.contains("action_confidence_threshold = 0.50"));

        // 3. Verify CRLF preservation
        let crlf_toml = "[autonomy]\r\nauto_quarantine_malware = false\r\n";
        let crlf_updated = update_autonomy_content(crlf_toml, &cfg);
        assert!(crlf_updated.contains("\r\n"));
        // Ensure no lone LF without preceding CR
        let without_crlf = crlf_updated.replace("\r\n", "");
        assert!(!without_crlf.contains('\n'));
    }

    #[test]
    fn test_skills_config_defaults_and_parsing() {
        let default_cfg = SkillsConfig::default();
        assert!(default_cfg.enabled);
        assert!(default_cfg.auto_evolve_on_start);
        assert_eq!(default_cfg.workspace, "runs/edr-evolution");
        assert_eq!(default_cfg.tasks_file, "examples/edr-skill-evolution/tasks.json");
        assert_eq!(default_cfg.scorer, "examples/edr-skill-evolution/scorer.py");
        assert_eq!(default_cfg.poll_interval_secs, 300);

        let custom_toml = r#"
[skills]
enabled = false
auto_evolve_on_start = false
workspace = "custom/workspace"
tasks_file = "custom/tasks.json"
scorer = "custom/scorer.py"
poll_interval_secs = 60
"#;
        let fc: FileConfig = toml::from_str(custom_toml).expect("Must parse FileConfig with [skills]");
        assert!(!fc.skills.enabled);
        assert!(!fc.skills.auto_evolve_on_start);
        assert_eq!(fc.skills.workspace, "custom/workspace");
        assert_eq!(fc.skills.tasks_file, "custom/tasks.json");
        assert_eq!(fc.skills.scorer, "custom/scorer.py");
        assert_eq!(fc.skills.poll_interval_secs, 60);
    }

    #[test]
    fn test_forensics_config_defaults_and_parsing() {
        let default_cfg = ForensicsConfig::default();
        assert!(default_cfg.enabled);
        assert_eq!(default_cfg.binary_path, "tools/velociraptor/velociraptor.exe");
        assert_eq!(default_cfg.execution_timeout_secs, 30);
        assert_eq!(default_cfg.max_memory_mb, 512);
        assert_eq!(default_cfg.max_output_lines, 10000);
        assert_eq!(default_cfg.staging_dir, "runs/forensics");
        assert!(default_cfg.auto_investigate);
        assert!((default_cfg.min_trigger_confidence - 0.80).abs() < 1e-4);
        assert!(default_cfg.trigger_techniques.contains(&"T1055".to_string()));

        let custom_toml = r#"
[forensics]
enabled = false
binary_path = "C:/tools/velociraptor.exe"
execution_timeout_secs = 60
max_memory_mb = 1024
max_output_lines = 50000
staging_dir = "runs/custom-forensics"
auto_investigate = false
min_trigger_confidence = 0.95
trigger_techniques = ["T1055", "T1003"]
"#;
        let fc: FileConfig = toml::from_str(custom_toml).expect("Must parse FileConfig with [forensics]");
        assert!(!fc.forensics.enabled);
        assert_eq!(fc.forensics.binary_path, "C:/tools/velociraptor.exe");
        assert_eq!(fc.forensics.execution_timeout_secs, 60);
        assert_eq!(fc.forensics.max_memory_mb, 1024);
        assert_eq!(fc.forensics.max_output_lines, 50000);
        assert_eq!(fc.forensics.staging_dir, "runs/custom-forensics");
        assert!(!fc.forensics.auto_investigate);
        assert!((fc.forensics.min_trigger_confidence - 0.95).abs() < 1e-4);
        assert_eq!(fc.forensics.trigger_techniques.len(), 2);
    }

    #[test]
    fn test_decision_model_config_defaults_and_parsing() {
        let default_cfg = DecisionModelConfig::default();
        assert!(default_cfg.enabled);
        assert_eq!(default_cfg.provider, "local");
        assert_eq!(default_cfg.model, "@cf/cloudflare/clef-flash");
        assert_eq!(default_cfg.timeout_ms, 500);
        assert!((default_cfg.min_action_confidence - 0.80).abs() < 1e-4);
        assert!(default_cfg.fallback_to_local);
        assert!(default_cfg.auto_escalate_to_cortex);
        assert_eq!(default_cfg.model_dir, "models/clef");
        assert_eq!(default_cfg.hybrid_strategy, "cascade");
        assert_eq!(default_cfg.strands_endpoint.as_deref(), Some("http://127.0.0.1:4003"));
        assert_eq!(default_cfg.strands_model, "StrandsAgents/strands-decider-2B-hobson-v19");
        assert_eq!(default_cfg.strands_timeout_ms, 800);

        let custom_toml = r#"
[decision_model]
enabled = false
provider = "hybrid"
hybrid_strategy = "consensus"
model = "@cf/cloudflare/clef"
cloudflare_account_id = "test-account-id"
cloudflare_api_token = "test-token"
timeout_ms = 750
fallback_to_local = false
min_action_confidence = 0.92
auto_escalate_to_cortex = false
model_dir = "custom/models/clef"
strands_endpoint = "http://10.0.0.42:4003"
strands_model = "custom/strands-slm"
strands_timeout_ms = 1200
"#;
        let fc: FileConfig = toml::from_str(custom_toml).expect("Must parse FileConfig with [decision_model]");
        assert!(!fc.decision_model.enabled);
        assert_eq!(fc.decision_model.provider, "hybrid");
        assert_eq!(fc.decision_model.hybrid_strategy, "consensus");
        assert_eq!(fc.decision_model.model, "@cf/cloudflare/clef");
        assert_eq!(fc.decision_model.cloudflare_account_id.as_deref(), Some("test-account-id"));
        assert_eq!(fc.decision_model.cloudflare_api_token.as_deref(), Some("test-token"));
        assert_eq!(fc.decision_model.timeout_ms, 750);
        assert!(!fc.decision_model.fallback_to_local);
        assert!((fc.decision_model.min_action_confidence - 0.92).abs() < 1e-4);
        assert!(!fc.decision_model.auto_escalate_to_cortex);
        assert_eq!(fc.decision_model.model_dir, "custom/models/clef");
        assert_eq!(fc.decision_model.strands_endpoint.as_deref(), Some("http://10.0.0.42:4003"));
        assert_eq!(fc.decision_model.strands_model, "custom/strands-slm");
        assert_eq!(fc.decision_model.strands_timeout_ms, 1200);
    }

    #[test]
    fn test_wire_config_duckdns_defaults_and_parsing() {
        let minimal_toml = r#"
listen_addr = "/ip4/0.0.0.0/tcp/4001"
shared_secret = "secret123"
"#;
        let wc: WireConfig = toml::from_str(minimal_toml).expect("Must parse minimal WireConfig");
        assert_eq!(wc.duckdns_domain, Some("oshoosi".to_string()));
        assert!(wc.auto_bootstrap_duckdns);
        assert_eq!(wc.duckdns_port, 4001);
        assert!(wc.allow_public_relays);

        let custom_toml = r#"
listen_addr = "/ip4/0.0.0.0/tcp/4001"
shared_secret = "secret123"
duckdns_domain = "custom-node"
auto_bootstrap_duckdns = false
duckdns_port = 5001
"#;
        let wc_custom: WireConfig = toml::from_str(custom_toml).expect("Must parse custom WireConfig");
        assert_eq!(wc_custom.duckdns_domain, Some("custom-node".to_string()));
        assert!(!wc_custom.auto_bootstrap_duckdns);
        assert_eq!(wc_custom.duckdns_port, 5001);

        // Verify serialization preserves fields
        let serialized = toml::to_string(&wc).expect("Must serialize WireConfig");
        assert!(serialized.contains("duckdns_domain"));
        assert!(serialized.contains("auto_bootstrap_duckdns"));
        assert!(serialized.contains("duckdns_port"));

        // Verify FileConfig parsing with [wire]
        let file_toml = r#"
[wire]
duckdns_domain = "my-fleet"
auto_bootstrap_duckdns = true
duckdns_port = 4001
"#;
        let fc: FileConfig = toml::from_str(file_toml).expect("Must parse FileConfig [wire]");
        assert_eq!(fc.wire.duckdns_domain, Some("my-fleet".to_string()));
        assert!(fc.wire.auto_bootstrap_duckdns);
        assert_eq!(fc.wire.duckdns_port, 4001);
    }

    #[test]
    fn test_swarm_config_defaults_and_parsing() {
        let default_cfg = SwarmConfig::default();
        assert!(default_cfg.enabled);
        assert_eq!(default_cfg.service_url, "http://127.0.0.1:4002");
        assert!(default_cfg.auto_trigger_on_threat);
        assert!((default_cfg.min_trigger_confidence - 0.85).abs() < 1e-4);
        assert_eq!(default_cfg.timeout_secs, 30);

        let custom_toml = r#"
[swarm]
enabled = false
service_url = "http://10.0.0.50:8000"
auto_trigger_on_threat = false
min_trigger_confidence = 0.90
timeout_secs = 60
"#;
        let fc: FileConfig = toml::from_str(custom_toml).expect("Must parse FileConfig with [swarm]");
        assert!(!fc.swarm.enabled);
        assert_eq!(fc.swarm.service_url, "http://10.0.0.50:8000");
        assert!(!fc.swarm.auto_trigger_on_threat);
        assert!((fc.swarm.min_trigger_confidence - 0.90).abs() < 1e-4);
        assert_eq!(fc.swarm.timeout_secs, 60);
    }

    #[test]
    fn test_resources_config_defaults_and_parsing() {
        let default_cfg = ResourcesConfig::default();
        assert_eq!(default_cfg.profile, "auto");
        assert_eq!(default_cfg.min_free_ram_mb_for_browser, 2500);
        assert_eq!(default_cfg.min_free_ram_mb_for_foundation_sec, 8192);
        assert_eq!(default_cfg.min_free_ram_mb_for_strands_decider, 3500);
        assert_eq!(default_cfg.min_free_ram_mb_for_securebert, 800);
        assert_eq!(default_cfg.min_free_ram_mb_for_sorel, 350);
        assert_eq!(default_cfg.min_free_ram_mb_for_malconv, 150);
        assert!(default_cfg.auto_suppress_browser_on_low_ram);
        assert!(default_cfg.auto_throttle_ai_on_low_ram);
        assert_eq!(default_cfg.nsrl_cache_limit, None);

        let custom_toml = r#"
[resources]
profile = "lite"
min_free_ram_mb_for_browser = 3000
min_free_ram_mb_for_foundation_sec = 10000
min_free_ram_mb_for_strands_decider = 4000
min_free_ram_mb_for_securebert = 900
min_free_ram_mb_for_sorel = 400
min_free_ram_mb_for_malconv = 200
auto_suppress_browser_on_low_ram = false
auto_throttle_ai_on_low_ram = false
nsrl_cache_limit = 50000
"#;
        let fc: FileConfig = toml::from_str(custom_toml).expect("Must parse FileConfig with [resources]");
        assert_eq!(fc.resources.profile, "lite");
        assert_eq!(fc.resources.min_free_ram_mb_for_browser, 3000);
        assert_eq!(fc.resources.min_free_ram_mb_for_foundation_sec, 10000);
        assert_eq!(fc.resources.min_free_ram_mb_for_strands_decider, 4000);
        assert_eq!(fc.resources.min_free_ram_mb_for_securebert, 900);
        assert_eq!(fc.resources.min_free_ram_mb_for_sorel, 400);
        assert_eq!(fc.resources.min_free_ram_mb_for_malconv, 200);
        assert!(!fc.resources.auto_suppress_browser_on_low_ram);
        assert!(!fc.resources.auto_throttle_ai_on_low_ram);
        assert_eq!(fc.resources.nsrl_cache_limit, Some(50000));
    }
}


