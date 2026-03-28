//! Configuration types for OpenỌ̀ṣọ́ọ̀sì.
//! Loaded from config file (e.g. osoosi.toml) — no hardcoding.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
    { "Microsoft-Windows-Sysmon/Operational".to_string() }
    #[cfg(not(target_os = "windows"))]
    { "default".to_string() }
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
        let mut drives = Vec::new();
        for letter in b'A'..=b'Z' {
            let path = format!("{}:\\", letter as char);
            if std::path::Path::new(&path).exists() {
                drives.push(path);
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
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string()).to_lowercase();
        let program_files = std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".to_string()).to_lowercase();
        let program_files_x86 = std::env::var("ProgramFiles(x86)").unwrap_or_else(|_| "C:\\Program Files (x86)".to_string()).to_lowercase();

        if p.starts_with(&system_root) || p.starts_with(&program_files) || p.starts_with(&program_files_x86) {
            return true;
        }
        // Direct checks for common roots if env vars missing
        if p.starts_with("c:\\windows") || p.contains("\\system32\\") || p.contains("\\syswow64\\") {
            return true;
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // Re-normalize to forward slashes for Unix
        let p = path; 
        let system_prefixes = [
            "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/etc/", 
            "/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/",
            "/boot/", "/sys/", "/proc/", "/dev/"
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
        }
    }
}

/// Quarantine admin controls for releasing quarantined peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
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
/// Env override: OSOOSI_TOOLS_ROOT or OSOOSI_HARFILE (legacy).
/// Defaults to current_dir/harfile or project_root/harfile if found.
pub fn resolve_tools_dir() -> PathBuf {
    if let Ok(p) = std::env::var("OSOOSI_TOOLS_ROOT") {
        return PathBuf::from(p.trim());
    }
    if let Ok(p) = std::env::var("OSOOSI_HARFILE") {
        return PathBuf::from(p.trim());
    }
    
    // Check if harfile exists in project root or current dir
    if let Some(root) = resolve_project_root() {
        let h = root.join("harfile");
        if h.is_dir() {
            return h;
        }
    }
    
    // Fallback to searching upward for 'harfile' directory
    let mut dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    loop {
        let h = dir.join("harfile");
        if h.is_dir() {
            return h;
        }
        if let Some(parent) = dir.parent() {
            dir = parent.to_path_buf();
        } else {
            break;
        }
    }
    
    // Ultimate fallback: current_dir/harfile
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join("harfile")
}

/// Resolve a specific tool path dynamically.
pub fn resolve_tool_path(tool_name: &str, executable_name: &str) -> PathBuf {
    resolve_tools_dir().join(tool_name).join(executable_name)
}

/// Resolve the models directory for ML/LLM models (Malware, Gemma, etc.).
/// Env override: OSOOSI_MODELS_DIR.
/// Defaults to current_dir/models or project_root/models if found.
pub fn resolve_models_dir() -> PathBuf {
    if let Ok(p) = std::env::var("OSOOSI_MODELS_DIR") {
        return PathBuf::from(p.trim());
    }
    
    if let Some(root) = resolve_project_root() {
        let m = root.join("models");
        if m.is_dir() {
            return m;
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
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join("models")
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
    let local = cwd.join("osoosi.toml");
    if local.exists() {
        return Some(local);
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
    let mut paths: Vec<String> = cfg.telemetry.watch_paths
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if paths.iter().any(|s| s.eq_ignore_ascii_case("all") || s == "*") {
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
        let paths: Vec<String> = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
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
}

pub fn load_mesh_listen_config_extended() -> WireListenConfig {
    let mut listen_addrs = Vec::new();
    let mut bootstrap_peers = Vec::new();
    let mut master_node_public_key = None;
    let mut membership_proof = None;

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

    if listen_addrs.is_empty() {
        listen_addrs.push("/ip4/0.0.0.0/tcp/4001".to_string());
    }

    WireListenConfig {
        listen_addrs,
        bootstrap_peers,
        master_node_public_key,
        membership_proof,
    }
}

pub fn load_mesh_listen_config() -> WireListenConfig {
    load_mesh_listen_config_extended()
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
    pub sigma_rules_paths: Vec<PathBuf>,
    pub yara_rules_paths: Vec<PathBuf>,
    #[serde(default)]
    pub default_action: PolicyAction,
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
}

fn default_fuel_limit() -> u64 {
    500_000
}
fn default_max_memory() -> usize {
    8_388_608
}
fn default_db_path() -> String {
    "./osoosi.db".to_string()
}
fn default_traps_path() -> String {
    "./traps".to_string()
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            action_fuel_limit: default_fuel_limit(),
            action_max_memory: default_max_memory(),
            db_path: default_db_path(),
            traps_path: default_traps_path(),
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
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
}

impl Default for PeerRulesConfig {
    fn default() -> Self {
        Self { require_patched: true, require_supported_os: true }
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
}

fn default_min_reputation() -> f32 {
    1.0 // Require explicit approval by default (no auto-approve)
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
}
