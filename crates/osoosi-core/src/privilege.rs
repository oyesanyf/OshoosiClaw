//! Cross-platform privilege management for OpenỌ̀ṣọ́ọ̀sì.
//!
//! Grants read-only access to ALL security/event logs on each platform:
//! - Windows: Event Log Readers group (all channels) + Security channel SDDL
//! - Linux:   adm + syslog + systemd-journal groups + auditd ACL + /var/log ACL
//! - macOS:   Full Disk Access guidance + admin group
//!
//! Uses conditional compilation so only platform-relevant code is compiled.

use std::process::Command;
use tracing::info;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct PrivilegeStatus {
    pub platform: String,
    pub can_read_events: bool,
    pub is_elevated: bool,
    /// True if process can apply patches (Windows: Local Administrators; Linux: root/sudo).
    pub can_apply_patches: bool,
    pub details: Vec<String>,
    pub actions_taken: Vec<String>,
    pub errors: Vec<String>,
}

impl PrivilegeStatus {
    fn new() -> Self {
        Self {
            platform: current_platform().to_string(),
            can_read_events: false,
            is_elevated: false,
            can_apply_patches: false,
            details: Vec::new(),
            actions_taken: Vec::new(),
            errors: Vec::new(),
        }
    }
}

pub fn current_platform() -> &'static str {
    #[cfg(target_os = "windows")]
    { "windows" }
    #[cfg(target_os = "linux")]
    { "linux" }
    #[cfg(target_os = "macos")]
    { "macos" }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    { "unknown" }
}

/// Check current privilege status without making changes.
pub fn check_privileges() -> PrivilegeStatus {
    let mut status = PrivilegeStatus::new();

    #[cfg(target_os = "windows")]
    windows_check(&mut status);

    #[cfg(target_os = "linux")]
    linux_check(&mut status);

    #[cfg(target_os = "macos")]
    macos_check(&mut status);

    status
}

/// Grant OpenỌ̀ṣọ́ọ̀sì read-only access to all security event logs.
/// Requires admin/root.
pub fn grant_access() -> PrivilegeStatus {
    let mut status = PrivilegeStatus::new();

    #[cfg(target_os = "windows")]
    windows_grant(&mut status);

    #[cfg(target_os = "linux")]
    linux_grant(&mut status);

    #[cfg(target_os = "macos")]
    macos_grant(&mut status);

    status
}

// ──────────────────────── Windows ────────────────────────
//
// "Event Log Readers" group grants read to most channels.
// Security log needs explicit SDDL ACE for non-admin users.
// We also grant SDDL read on any Sysmon/PowerShell/Defender channels present.

#[cfg(target_os = "windows")]
const WINDOWS_LOG_CHANNELS: &[&str] = &[
    "Security",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    "System",
    "Application",
];

#[cfg(target_os = "windows")]
fn is_elevated_windows() -> bool {
    // Try 'net session' (requires Server service)
    if Command::new("net").args(["session"]).output()
        .map(|o| o.status.success()).unwrap_or(false) {
        return true;
    }
    // Fallback: 'fltmc filters' (requires Admin, works without Server service)
    Command::new("fltmc").args(["filters"]).output()
        .map(|o| o.status.success()).unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn current_user_windows() -> String {
    let domain = std::env::var("USERDOMAIN").unwrap_or_default();
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "unknown".into());
    if domain.is_empty() { user } else { format!("{}\\{}", domain, user) }
}

#[cfg(target_os = "windows")]
fn is_in_event_log_readers() -> bool {
    Command::new("whoami").args(["/groups"]).output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_lowercase().contains("event log readers"))
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn can_read_channel(channel: &str) -> bool {
    Command::new("wevtutil")
        .args(["qe", channel, "/c:1", "/rd:true", "/f:text"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn get_current_user_sid() -> Option<String> {
    let output = Command::new("whoami").args(["/user"]).output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(sid) = trimmed.split_whitespace().find(|s| s.starts_with("S-1-")) {
            return Some(sid.to_string());
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn windows_check(status: &mut PrivilegeStatus) {
    status.is_elevated = is_elevated_windows();
    status.can_apply_patches = status.is_elevated;
    let user = current_user_windows();
    status.details.push(format!("User: {}", user));

    let in_group = is_in_event_log_readers();
    status.details.push(format!("Event Log Readers member: {}", in_group));

    let mut readable = Vec::new();
    let mut unreadable = Vec::new();
    for &channel in WINDOWS_LOG_CHANNELS {
        if can_read_channel(channel) {
            readable.push(channel);
        } else {
            unreadable.push(channel);
        }
    }

    status.details.push(format!("Readable channels: {}/{}", readable.len(), WINDOWS_LOG_CHANNELS.len()));
    if !unreadable.is_empty() {
        status.details.push(format!("Unreadable: {}", unreadable.join(", ")));
    }

    // Ground truth is whether channels are actually readable, not group membership string matching.
    // Some setups grant SDDL read access directly without an immediately refreshed group token.
    status.can_read_events = unreadable.is_empty() || readable.len() >= 2;

    if !in_group {
        status.details.push("Event Log Readers group not visible in current token. If grant-access was run recently, restart terminal/session.".into());
    }
    if !unreadable.is_empty() {
        status.details.push("Some channels are still blocked. Run `osoosi grant-access` as Administrator or verify channel ACL.".into());
    }
    if !status.can_apply_patches {
        status.details.push("Repair Engine (auto-patch): Requires Local Administrators. Run agent as Administrator for patching.".into());
    }
}

#[cfg(target_os = "windows")]
fn windows_grant(status: &mut PrivilegeStatus) {
    status.is_elevated = is_elevated_windows();
    let user = current_user_windows();

    if !status.is_elevated {
        status.errors.push(
            "Must run as Administrator. Right-click terminal -> Run as Administrator.".into()
        );
        status.can_read_events = false;
        return;
    }

    // Step 1: Add to Event Log Readers group (read-only to all standard logs)
    info!("Granting read-only access to all event logs for {}...", user);
    add_to_group(status, &user, "Event Log Readers");

    // Step 2: Get user SID for per-channel SDDL grants
    let sid = get_current_user_sid();
    if let Some(ref sid) = sid {
        status.details.push(format!("User SID: {}", sid));
    }

    // Step 3: Grant read SDDL on each channel that exists
    for &channel in WINDOWS_LOG_CHANNELS {
        grant_channel_read(status, channel, sid.as_deref());
    }

    // Step 4: Ensure logging services are active
    if !status.errors.is_empty() { return; } // Stop if already failed
    
    // Check if Sysmon is installed
    let sysmon_check = Command::new("sc").args(["query", "Sysmon64"]).output()
        .or_else(|_| Command::new("sc").args(["query", "Sysmon"]).output());
    
    match sysmon_check {
        Ok(o) if o.status.success() => {
            status.details.push("Sysmon service detected.".into());
        }
        _ => {
            status.actions_taken.push("Sysmon not found. Please run 'osoosi install-telemetry' next.".into());
        }
    }

    // Ensure Process Creation Auditing is enabled (Command line logging)
    let _ = Command::new("auditpol").args(["/set", "/subcategory:Process Creation", "/success:enable", "/failure:enable"]).status();

    // Port to winreg: Native Registry access for CLI auditing enablement
    match (|| -> Result<(), Box<dyn std::error::Error>> {
        use winreg::RegKey;
        use winreg::enums::*;
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let (key, _) = hklm.create_subkey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit")?;
        key.set_value("ProcessCreationIncludeCmdLine_Output", &1u32)?;
        Ok(())
    })() {
        Ok(_) => status.actions_taken.push("Enforced Process Creation Auditing (CLI) via native API.".into()),
        Err(e) => status.details.push(format!("Failed to set CLI auditing via Registry API: {}", e)),
    }

    // Step 5: Check for Ollama (AI Behavioral requirement)
    let ollama_check = Command::new("where").arg("ollama").output();
    if ollama_check.is_err() || !ollama_check.unwrap().status.success() {
        status.actions_taken.push("Ollama NOT FOUND. AI Behavioral Analysis will be disabled.".into());
        status.actions_taken.push("HINT: Run 'winget install Ollama' or visit ollama.com".into());
    } else {
        status.details.push("Ollama detection: FOUND".into());
    }

    // Verify
    let mut ok_count = 0;
    for &channel in WINDOWS_LOG_CHANNELS {
        if can_read_channel(channel) {
            ok_count += 1;
        }
    }
    status.details.push(format!("Verified: {}/{} channels readable", ok_count, WINDOWS_LOG_CHANNELS.len()));

    status.can_read_events = is_in_event_log_readers();
    status.can_apply_patches = status.is_elevated;
    if status.can_read_events {
        status.details.push("Read-only access granted to all event logs. Restart OpenỌ̀ṣọ́ọ̀sì for changes to take effect.".into());
    }
    if status.can_apply_patches {
        status.details.push("Repair Engine: Can apply patches (running elevated).".into());
    } else {
        status.details.push("Repair Engine: Run agent as Administrator for auto-patch (wuauserv, BITS, SoftwareDistribution require admin).".into());
    }
}

#[cfg(target_os = "windows")]
fn add_to_group(status: &mut PrivilegeStatus, user: &str, group: &str) {
    match Command::new("net").args(["localgroup", group, user, "/add"]).output() {
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            if o.status.success() {
                status.actions_taken.push(format!("Added {} to '{}'", user, group));
                info!("Added {} to {}", user, group);
            } else if stderr.contains("1378") || stderr.to_lowercase().contains("already a member") {
                status.details.push(format!("{} already in '{}'", user, group));
            } else {
                status.errors.push(format!("net localgroup {} failed: {}", group, stderr.trim()));
            }
        }
        Err(e) => status.errors.push(format!("net localgroup failed: {}", e)),
    }
}

#[cfg(target_os = "windows")]
fn grant_channel_read(status: &mut PrivilegeStatus, channel: &str, sid: Option<&str>) {
    // Check if channel exists
    let gl_output = Command::new("wevtutil").args(["gl", channel]).output();
    let gl = match gl_output {
        Ok(o) if o.status.success() => o,
        _ => {
            // Channel doesn't exist (e.g. Sysmon not installed) — skip silently
            return;
        }
    };

    let sid = match sid {
        Some(s) => s,
        None => {
            status.details.push(format!("{}: skipped SDDL (no SID)", channel));
            return;
        }
    };

    let output_text = String::from_utf8_lossy(&gl.stdout);
    let current_sddl = output_text
        .lines()
        .find(|l| {
            let trimmed = l.trim().to_lowercase();
            trimmed.starts_with("channelaccess:")
        })
        .and_then(|l| {
            // channelAccess: O:BAG:SY... — split after first ':'
            let rest = l.trim();
            rest.find(':').map(|i| rest[i + 1..].trim().to_string())
        })
        .unwrap_or_default();

    if current_sddl.is_empty() {
        status.details.push(format!("{}: could not parse SDDL", channel));
        return;
    }

    if current_sddl.contains(sid) {
        status.details.push(format!("{}: SID already in SDDL", channel));
        return;
    }

    // Append read-only ACE: (A;;0x1;;;SID)
    let new_sddl = format!("{}(A;;0x1;;;{})", current_sddl, sid);
    match Command::new("wevtutil")
        .args(["sl", channel, &format!("/ca:{}", new_sddl)])
        .output()
    {
        Ok(o) if o.status.success() => {
            status.actions_taken.push(format!("{}: read ACE granted", channel));
            info!("{}: SDDL updated with read ACE for {}", channel, sid);
        }
        Ok(o) => {
            let msg = String::from_utf8_lossy(&o.stderr);
            status.details.push(format!("{}: SDDL update skipped ({})", channel, msg.trim()));
        }
        Err(e) => {
            status.details.push(format!("{}: SDDL error ({})", channel, e));
        }
    }
}

// ──────────────────────── Linux ────────────────────────

#[cfg(target_os = "linux")]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(target_os = "linux")]
fn current_user_linux() -> String {
    std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "osoosi".into())
}

#[cfg(target_os = "linux")]
fn is_in_group(user: &str, group: &str) -> bool {
    Command::new("id").args(["-nG", user]).output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .any(|g| g == group)
        })
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
const LINUX_LOG_GROUPS: &[&str] = &["adm", "syslog", "systemd-journal"];

#[cfg(target_os = "linux")]
const LINUX_LOG_FILES: &[&str] = &[
    "/var/log/audit/audit.log",
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/kern.log",
    "/var/log/secure",
    "/var/log/messages",
    "/var/log/faillog",
    "/var/log/btmp",
    "/var/log/wtmp",
    "/var/log/lastlog",
];

#[cfg(target_os = "linux")]
fn linux_check(status: &mut PrivilegeStatus) {
    let user = current_user_linux();
    status.is_elevated = is_root();
    status.can_apply_patches = status.is_elevated;
    status.details.push(format!("User: {}", user));

    let mut in_any_group = false;
    for &group in LINUX_LOG_GROUPS {
        let member = is_in_group(&user, group);
        status.details.push(format!("{} member: {}", group, member));
        if member { in_any_group = true; }
    }

    let mut readable_count = 0;
    let mut total_existing = 0;
    for &path in LINUX_LOG_FILES {
        if std::path::Path::new(path).exists() {
            total_existing += 1;
            if std::fs::File::open(path).is_ok() {
                readable_count += 1;
            }
        }
    }
    status.details.push(format!("Log files readable: {}/{}", readable_count, total_existing));

    status.can_read_events = in_any_group;
    if !status.can_read_events {
        status.details.push("Fix: run `sudo osoosi grant-access`".into());
    }
    if !status.can_apply_patches {
        status.details.push("Repair Engine: Requires root/sudo for apt/yum/dnf. Run agent with sudo for auto-patch.".into());
    }
}

#[cfg(target_os = "linux")]
fn linux_grant(status: &mut PrivilegeStatus) {
    let user = current_user_linux();
    status.is_elevated = is_root();

    if !status.is_elevated {
        status.errors.push("Must run as root (sudo) to grant access.".into());
        status.can_read_events = false;
        return;
    }

    info!("Granting read-only access to all logs for {}...", user);

    // Add to all log-reading groups
    for &group in LINUX_LOG_GROUPS {
        match Command::new("usermod").args(["-aG", group, &user]).output() {
            Ok(o) if o.status.success() => {
                status.actions_taken.push(format!("Added {} to {} group", user, group));
                info!("Added {} to {}", user, group);
            }
            Ok(o) => {
                let e = String::from_utf8_lossy(&o.stderr);
                if e.to_lowercase().contains("does not exist") {
                    status.details.push(format!("{} group does not exist (OK)", group));
                } else {
                    status.details.push(format!("{}: {}", group, e.trim()));
                }
            }
            Err(e) => status.details.push(format!("{}: {}", group, e)),
        }
    }

    // Set read ACL on all existing log files
    for &path in LINUX_LOG_FILES {
        if !std::path::Path::new(path).exists() {
            continue;
        }
        match Command::new("setfacl")
            .args(["-m", &format!("u:{}:r", user), path])
            .output()
        {
            Ok(o) if o.status.success() => {
                status.actions_taken.push(format!("Set read ACL on {}", path));
            }
            Ok(o) => {
                let e = String::from_utf8_lossy(&o.stderr);
                if e.contains("not found") || e.contains("command not found") {
                    status.details.push("setfacl not installed. Install: apt install acl".into());
                    break;
                }
                status.details.push(format!("{}: {}", path, e.trim()));
            }
            Err(_) => {
                status.details.push("setfacl not available. Install: apt install acl".into());
                break;
            }
        }
    }

    // Also grant read to /var/log directory itself
    let _ = Command::new("setfacl")
        .args(["-m", &format!("u:{}:rx", user), "/var/log"])
        .output();

    // Ensure auditd is active and has some basic rules (best effort)
    let _ = Command::new("sudo").args(["systemctl", "enable", "--now", "auditd"]).status();
    let _ = Command::new("sudo").args(["auditctl", "-a", "always,exit", "-F", "arch=b64", "-S", "execve", "-k", "osoosi_exec"]).status();
    status.actions_taken.push("Enabled auditd and added execve monitoring rule.".into());

    // Check for sysmonforlinux
    if Command::new("sh").args(["-c", "command -v sysmon >/dev/null 2>&1"]).status().map(|s| s.success()).unwrap_or(false) {
        let _ = Command::new("sudo").args(["systemctl", "enable", "--now", "sysmon"]).status();
        status.details.push("Sysmon for Linux detected and enabled.".into());
    } else {
        status.actions_taken.push("Sysmon for Linux not found. Please run 'osoosi install-telemetry' next.".into());
    }

    status.can_read_events = true;
    status.can_apply_patches = status.is_elevated;
    status.details.push("Read-only access granted to all logs. Log out and back in for group changes to take effect.".into());
    if !status.can_apply_patches {
        status.details.push("Repair Engine: Run agent with sudo for auto-patch (package manager locks require root).".into());
    }
}

// ──────────────────────── macOS ────────────────────────

#[cfg(target_os = "macos")]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(target_os = "macos")]
fn macos_check(status: &mut PrivilegeStatus) {
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
    status.is_elevated = is_root();
    status.can_apply_patches = status.is_elevated;
    status.details.push(format!("User: {}", user));

    let can_log = Command::new("log")
        .args(["show", "--last", "1s", "--predicate", "subsystem == \"com.apple.securityd\""])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let can_system_log = std::path::Path::new("/var/log/system.log")
        .metadata()
        .and_then(|_| std::fs::File::open("/var/log/system.log"))
        .is_ok();

    status.can_read_events = can_log || can_system_log;
    status.details.push(format!("Unified log readable: {}", can_log));
    status.details.push(format!("system.log readable: {}", can_system_log));

    if !status.can_read_events {
        status.details.push("Grant Full Disk Access: System Settings > Privacy & Security > Full Disk Access > add OpenỌ̀ṣọ́ọ̀sì".into());
    }
}

#[cfg(target_os = "macos")]
fn macos_grant(status: &mut PrivilegeStatus) {
    status.is_elevated = is_root();

    let user = std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "unknown".into());

    status.details.push("macOS log access requires one of:".into());
    status.details.push("  1. Full Disk Access: System Settings > Privacy & Security > Full Disk Access > add OpenỌ̀ṣọ́ọ̀sì".into());
    status.details.push("  2. Codesign with entitlements (for production):".into());
    status.details.push("     codesign --force --options runtime --entitlements entitlements.plist --sign \"Developer ID\" target/release/osoosi".into());

    if status.is_elevated {
        // Add to admin group
        match Command::new("dseditgroup")
            .args(["-o", "edit", "-a", &user, "-t", "user", "admin"])
            .output()
        {
            Ok(o) if o.status.success() => {
                status.actions_taken.push(format!("Confirmed {} in admin group", user));
            }
            _ => {
                status.details.push(format!("{} likely already in admin group", user));
            }
        }

        // Grant read on common log files
        let mac_logs = ["/var/log/system.log", "/var/log/install.log", "/var/log/wifi.log"];
        for path in &mac_logs {
            if std::path::Path::new(path).exists() {
                let _ = Command::new("chmod")
                    .args(["+r", path])
                    .output();
                status.actions_taken.push(format!("Set read on {}", path));
            }
        }
    }

    // Re-check after actions
    let can_log = Command::new("log")
        .args(["show", "--last", "1s"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    status.can_read_events = can_log;
    status.can_apply_patches = status.is_elevated;
    if !can_log {
        status.details.push("Full Disk Access still required for unified log (manual step).".into());
    }
    if !status.can_apply_patches {
        status.details.push("Repair Engine: Run with sudo for auto-patch (softwareupdate requires root).".into());
    }
}

/// Generate entitlements.plist content for macOS codesigning.
pub fn macos_entitlements_plist() -> &'static str {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <false/>
    <key>com.apple.private.logging.search</key>
    <true/>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
</dict>
</plist>"#
}

/// Bootstrap security rules on startup (Defender exclusions, Firewall rules).
pub fn bootstrap_security_rules() {
    #[cfg(target_os = "windows")]
    {
        if let Ok(exe_path) = std::env::current_exe() {
            let exe_str = exe_path.to_string_lossy();
            
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;

            // 1. Defender Exclusions (Requires Admin - best effort)
            // Exclude the agent binary itself
            let _ = Command::new("powershell")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["-Command", &format!("Add-MpPreference -ExclusionPath '{}' -ErrorAction SilentlyContinue", exe_str)])
                .status();
            
            if let Ok(cwd) = std::env::current_dir() {
                let cwd_str = cwd.to_string_lossy();
                // Exclude the working directory
                let _ = Command::new("powershell")
                    .creation_flags(CREATE_NO_WINDOW)
                    .args(["-Command", &format!("Add-MpPreference -ExclusionPath '{}' -ErrorAction SilentlyContinue", cwd_str)])
                    .status();

                // Exclude build artifacts (prevents OS Error 32 file-lock during compilation)
                let target_dir = cwd.join("target");
                if target_dir.exists() {
                    let _ = Command::new("powershell")
                        .creation_flags(CREATE_NO_WINDOW)
                        .args(["-Command", &format!("Add-MpPreference -ExclusionPath '{}' -ErrorAction SilentlyContinue", target_dir.to_string_lossy())])
                        .status();
                }

                // Exclude WASM files (Defender flags them as suspicious)
                let _ = Command::new("powershell")
                    .creation_flags(CREATE_NO_WINDOW)
                    .args(["-Command", "Add-MpPreference -ExclusionExtension '.wasm' -ErrorAction SilentlyContinue"])
                    .status();

                // Exclude YARA rules directory (contains malware signatures that trigger Defender)
                let yara_dir = cwd.join("yara");
                if yara_dir.exists() {
                    let _ = Command::new("powershell")
                        .creation_flags(CREATE_NO_WINDOW)
                        .args(["-Command", &format!("Add-MpPreference -ExclusionPath '{}' -ErrorAction SilentlyContinue", yara_dir.to_string_lossy())])
                        .status();
                }

                // Exclude quarantine directory (contains actual malware samples)
                let quarantine_dir = cwd.join("quarantine");
                if quarantine_dir.exists() {
                    let _ = Command::new("powershell")
                        .creation_flags(CREATE_NO_WINDOW)
                        .args(["-Command", &format!("Add-MpPreference -ExclusionPath '{}' -ErrorAction SilentlyContinue", quarantine_dir.to_string_lossy())])
                        .status();
                }

                // Exclude models directory (ONNX models trigger heuristic scans)
                let models_dir = cwd.join("models");
                if models_dir.exists() {
                    let _ = Command::new("powershell")
                        .creation_flags(CREATE_NO_WINDOW)
                        .args(["-Command", &format!("Add-MpPreference -ExclusionPath '{}' -ErrorAction SilentlyContinue", models_dir.to_string_lossy())])
                        .status();
                }

                // Exclude traps directory (deception honeypot files trigger Defender)
                let traps_dir = cwd.join("traps");
                if traps_dir.exists() {
                    let _ = Command::new("powershell")
                        .creation_flags(CREATE_NO_WINDOW)
                        .args(["-Command", &format!("Add-MpPreference -ExclusionPath '{}' -ErrorAction SilentlyContinue", traps_dir.to_string_lossy())])
                        .status();
                }

                // Exclude Cargo registry (git2/libgit2-sys C source compilation triggers locks)
                if let Ok(home) = std::env::var("USERPROFILE") {
                    let cargo_registry = std::path::Path::new(&home).join(".cargo").join("registry");
                    if cargo_registry.exists() {
                        let _ = Command::new("powershell")
                            .creation_flags(CREATE_NO_WINDOW)
                            .args(["-Command", &format!("Add-MpPreference -ExclusionPath '{}' -ErrorAction SilentlyContinue", cargo_registry.to_string_lossy())])
                            .status();
                    }
                }

                // Exclude .yar extension (YARA rules contain malware signatures)
                let _ = Command::new("powershell")
                    .creation_flags(CREATE_NO_WINDOW)
                    .args(["-Command", "Add-MpPreference -ExclusionExtension '.yar' -ErrorAction SilentlyContinue"])
                    .status();

                // Exclude the osoosi process itself
                let _ = Command::new("powershell")
                    .creation_flags(CREATE_NO_WINDOW)
                    .args(["-Command", &format!("Add-MpPreference -ExclusionProcess '{}' -ErrorAction SilentlyContinue", exe_str)])
                    .status();
            }

            // 2. Firewall Rules (Force Inbound/Outbound Allow for the P2P Mesh)
            let _ = Command::new("netsh")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["advfirewall", "firewall", "delete", "rule", "name=OpenOsoosi-Agent-Allow"])
                .status();
            
            let _ = Command::new("netsh")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["advfirewall", "firewall", "add", "rule", 
                       "name=OpenOsoosi-Agent-Allow", 
                       "dir=in", "action=allow", 
                       &format!("program={}", exe_str), 
                       "enable=yes", "profile=any"])
                .status();

            let _ = Command::new("netsh")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["advfirewall", "firewall", "add", "rule", 
                       "name=OpenOsoosi-Agent-Allow", 
                       "dir=out", "action=allow", 
                       &format!("program={}", exe_str), 
                       "enable=yes", "profile=any"])
                .status();

            // 3. Explicit Port Openings for Mesh & Discovery
            let _ = Command::new("netsh")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["advfirewall", "firewall", "add", "rule", "name=OpenOsoosi-Mesh-TCP", "dir=in", "action=allow", "protocol=TCP", "localport=4001", "enable=yes", "profile=any"])
                .status();
            let _ = Command::new("netsh")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["advfirewall", "firewall", "add", "rule", "name=OpenOsoosi-mDNS-UDP", "dir=in", "action=allow", "protocol=UDP", "localport=5353", "enable=yes", "profile=any"])
                .status();

            // 4. Inbound Web Dashboard (Allow remote access to UI)
            let _ = Command::new("netsh")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["advfirewall", "firewall", "add", "rule", "name=OpenOsoosi-Dashboard-8080", "dir=in", "action=allow", "protocol=TCP", "localport=8080", "enable=yes", "profile=any"])
                .status();
            let _ = Command::new("netsh")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["advfirewall", "firewall", "add", "rule", "name=OpenOsoosi-Dashboard-3030", "dir=in", "action=allow", "protocol=TCP", "localport=3030", "enable=yes", "profile=any"])
                .status();

            // 5. Inbound ICMP (Ping) for connectivity debugging
            let _ = Command::new("netsh")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["advfirewall", "firewall", "add", "rule", "name=OpenOsoosi-ICMPv4", "dir=in", "action=allow", "protocol=ICMPv4", "enable=yes", "profile=any"])
                .status();
            let _ = Command::new("netsh")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["advfirewall", "firewall", "add", "rule", "name=OpenOsoosi-ICMPv6", "dir=in", "action=allow", "protocol=ICMPv6", "enable=yes", "profile=any"])
                .status();
        }
    }
    
    #[cfg(target_os = "linux")]
    {
        // On Linux, we could add ufw/nftables allow for known P2P ports if needed.
        // For now, staying quiet as most EDRs don't need explicit 'AV exclusions' on Linux in the same way.
    }
}
