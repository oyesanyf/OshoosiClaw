#![allow(unused_imports)]

use super::*;
use osoosi_audit::AuditTrail;
use osoosi_model::{MalwareScanner, ModelConfig, ThreatModel};
use osoosi_policy::{PolicyEngine, ThreatFeedFetcher};
use osoosi_repair::PatchEngine;
use osoosi_runtime::DeceptionManager;
use osoosi_trust::TrustManager;
use osoosi_types::{
    load_runtime_config, resolve_nvd_api_key, resolve_otx_api_key, HostSecurityEvent, Priority,
    ResourceCategory, SecuredExecutor, TelemetryMode,
};
use osoosi_wire::{JoinGate, MeshCommand, MeshNode};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Once};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

pub(crate) static OTX_FEED_KEY_SOURCE_LOG: Once = Once::new();
pub(crate) static OTX_FEED_DISABLED_LOG: Once = Once::new();

pub type RepairStatus = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    u32,
    Option<String>,
);

pub(crate) fn is_trusted_operational_image(
    event: &osoosi_types::HostSecurityEvent,
    config: &osoosi_types::PolicyConfig,
) -> bool {
    let image_path = event
        .data
        .get("Image")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if image_path.is_empty() {
        return false;
    }
    let path = std::path::Path::new(image_path);
    if crate::win_trust::is_trusted_signed_binary(path) {
        return true;
    }

    // Check pre-approved BLAKE3 hash inventory
    if let Ok(meta) = path.metadata() {
        if meta.len() > 0 && meta.len() <= 16 * 1024 * 1024 {
            if let Ok(bytes) = std::fs::read(path) {
                let b3 = blake3::hash(&bytes)
                    .to_hex()
                    .to_string()
                    .to_ascii_lowercase();
                if crate::rea::is_protected_local_binary_hash(&b3) {
                    return true;
                }
            }
        }
    }

    let path_lc = image_path.to_lowercase();

    // 1. Check dynamic whitelists from config
    let is_trusted_path = config
        .trusted_paths
        .iter()
        .any(|p| path_lc.contains(&p.to_lowercase()));
    let is_trusted_stem = config.trusted_stems.iter().any(|s| {
        let s_lc = s.to_lowercase();
        path_lc.ends_with(&s_lc)
            || path_lc.contains(&format!("\\{}\\", s_lc))
            || path_lc.ends_with(&format!("\\{}", s_lc))
    });

    if is_trusted_path || is_trusted_stem {
        // 2. Obtain signature and Signer Identity from the file on disk
        if let Some(metadata) = osoosi_types::get_pe_metadata(path) {
            let is_trusted = osoosi_types::is_trusted_vendor(&metadata.product_name)
                || metadata
                    .publisher
                    .as_ref()
                    .map(|pub_name| osoosi_types::is_trusted_vendor(pub_name))
                    .unwrap_or(false);

            if metadata.is_signed && is_trusted {
                return true;
            }
        }

        // 3. Fallback to Native telemetry signature check
        let sig_status = event
            .data
            .get("SignatureStatus")
            .or_else(|| event.data.get("Signature Status"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();

        if sig_status == "valid" || sig_status.contains("trusted") {
            return true;
        }
    }

    // Last resort path-substring fallback DECOMMISSIONED (R1 requirement)
    false
}

/// A strict check to prevent OshoosiClaw from committing accidental suicide on the host OS.
/// Protects core Windows infrastructure (PIDs 0, 1, 4, smss.exe, csrss.exe, wininit.exe,
/// services.exe, lsass.exe, winlogon.exe, dwm.exe).
/// Concurrent in-memory debouncing cache mapping tarpitted PIDs to their last tarpit initiation time.
pub static RECENT_TARPITTED_PIDS: std::sync::LazyLock<dashmap::DashMap<u32, std::time::Instant>> =
    std::sync::LazyLock::new(dashmap::DashMap::new);

/// Helper to extract raw process PID from event body fields without self/kernel filtering.
/// Checks strictly in order: ProcessId, NewProcessId, SourceProcessId, TargetProcessId, pid.
/// Explicitly ignores LoggingProcessId, ProviderProcessId, and ExecutionProcessId.
pub fn extract_raw_event_pid(event: &osoosi_types::HostSecurityEvent) -> Option<u32> {
    event
        .data
        .get("ProcessId")
        .or_else(|| event.data.get("NewProcessId"))
        .or_else(|| event.data.get("SourceProcessId"))
        .or_else(|| event.data.get("TargetProcessId"))
        .or_else(|| event.data.get("pid"))
        .and_then(|v| {
            v.as_u64().map(|n| n as u32).or_else(|| {
                v.as_str().and_then(|s| {
                    let s_clean = s.trim();
                    if let Some(hex) = s_clean
                        .strip_prefix("0x")
                        .or_else(|| s_clean.strip_prefix("0X"))
                    {
                        u32::from_str_radix(hex, 16).ok()
                    } else {
                        s_clean.parse::<u32>().ok()
                    }
                })
            })
        })
}

/// Safely extract and parse process PID from event body fields (numeric, decimal string, or hex 0x...).
/// Strictly checks event body fields (ProcessId, NewProcessId, SourceProcessId, TargetProcessId, pid).
/// Explicitly ignores LoggingProcessId, ProviderProcessId, and ExecutionProcessId.
/// Guards against EDR self-targeting and kernel PIDs: returns None for 0, 1, 4, or std::process::id().
pub fn extract_event_pid(event: &osoosi_types::HostSecurityEvent) -> Option<u32> {
    let pid = extract_raw_event_pid(event)?;
    if pid == 0 || pid == 1 || pid == 4 || pid == std::process::id() {
        return None;
    }
    Some(pid)
}

/// Check if a process ID or image corresponds to a known security provider or EDR instrumentation.
pub fn is_security_provider_process(pid: u32, image_name: &str) -> bool {
    if pid > 0 && pid == std::process::id() {
        return true;
    }
    let lower_img = image_name.trim().trim_matches('"').to_lowercase();
    let filename = lower_img
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(lower_img.as_str());

    if matches!(
        filename,
        "sysmon.exe"
            | "sysmon64.exe"
            | "osoosi.exe"
            | "oshoosi.exe"
            | "osoosi"
            | "osoosi-edr"
            | "msmpeng.exe"
            | "securityhealthservice.exe"
            | "nissrv.exe"
            | "senseir.exe"
            | "sensendr.exe"
            | "mpcmdrun.exe"
    ) {
        return true;
    }

    // If image_name is empty or unknown, attempt process name lookup via runtime if pid is non-zero
    if (filename.is_empty() || filename == "unknown") && pid > 4 {
        let proc_name = osoosi_runtime::tarpit::get_process_name(pid).to_lowercase();
        let proc_fn = proc_name
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(proc_name.as_str());
        if matches!(
            proc_fn,
            "sysmon.exe"
                | "sysmon64.exe"
                | "osoosi.exe"
                | "oshoosi.exe"
                | "osoosi"
                | "osoosi-edr"
                | "msmpeng.exe"
                | "securityhealthservice.exe"
                | "nissrv.exe"
                | "senseir.exe"
                | "sensendr.exe"
                | "mpcmdrun.exe"
        ) {
            return true;
        }
    }

    false
}

/// A strict check to prevent OshoosiClaw from committing accidental suicide on the host OS.
/// Protects core Windows infrastructure (PIDs 0, 1, 4, smss.exe, csrss.exe, wininit.exe,
/// services.exe, lsass.exe, winlogon.exe, dwm.exe, sysmon, Defender) executing from genuine Windows system paths.
/// Explicitly excludes administrative CLI tools / LOLBins (net.exe, net1.exe, powershell.exe,
/// cmd.exe, wmic.exe, schtasks.exe, etc.) so malicious actions like T1136 or T1003 can be contained.
pub fn is_system_critical(event: &osoosi_types::HostSecurityEvent) -> bool {
    // Core kernel & system init PIDs or self
    if let Some(p) = extract_raw_event_pid(event) {
        if p == 0 || p == 1 || p == 4 || p == std::process::id() {
            return true;
        }
    }

    // Any child process spawned directly by this osoosi daemon process is protected
    if let Some(ppid) = event
        .data
        .get("ParentProcessId")
        .or_else(|| event.data.get("parent_process_id"))
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
        })
    {
        if ppid as u32 == std::process::id() {
            return true;
        }
    }

    let raw_image_path = event
        .data
        .get("Image")
        .or_else(|| event.data.get("NewProcessName"))
        .or_else(|| event.data.get("image"))
        .or_else(|| event.data.get("ImagePath"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let normalized_image = osoosi_types::normalize_nt_device_path(raw_image_path);
    let image_path = normalized_image.as_str();

    let pid = extract_raw_event_pid(event).unwrap_or(0);
    // Security Provider PIDs: Check immediately!
    if is_security_provider_process(pid, image_path) {
        return true;
    }

    if image_path.is_empty() {
        return false;
    }

    // Administrative LOLBins must NEVER be shielded as system-critical when executing commands!
    if crate::system_check::is_administrative_lolbin(image_path) {
        return false;
    }

    let path_lc = image_path.to_lowercase().replace('/', "\\");
    let path_unix = image_path.to_lowercase().replace('\\', "/");
    let filename = path_lc.rsplit(['\\', '/']).next().unwrap_or("");

    // Path Constraint: Must execute from core OS directories on Windows, Linux, or macOS.
    let is_critical_path = path_lc.contains("\\windows\\system32\\")
        || path_lc.contains("\\windows\\syswow64\\")
        || path_lc.contains("\\windows\\servicing\\")
        || path_lc.contains("\\windows\\winsxs\\")
        || path_lc.contains("\\windows\\systemapps\\")
        || path_lc.contains("\\windows\\immersivecontrolpanel\\")
        || path_lc.contains("\\program files\\windowsapps\\microsoft.")
        || path_lc.ends_with("\\windows\\explorer.exe")
        || path_unix.starts_with("/bin/")
        || path_unix.starts_with("/sbin/")
        || path_unix.starts_with("/usr/bin/")
        || path_unix.starts_with("/usr/sbin/")
        || path_unix.starts_with("/usr/lib/")
        || path_unix.starts_with("/usr/libexec/")
        || path_unix.starts_with("/lib/")
        || path_unix.starts_with("/lib64/")
        || path_unix.starts_with("/system/library/")
        || path_unix.starts_with("/system/applications/");

    // Explicitly protect true core operating system, Shell, Search, and System Tray infrastructure across Windows, Linux, and macOS
    let is_core_os_binary = osoosi_types::is_protected_os_shell_or_desktop_binary(image_path)
        || matches!(
            filename,
            "smss.exe"
                | "csrss.exe"
                | "wininit.exe"
                | "services.exe"
                | "lsass.exe"
                | "winlogon.exe"
                | "userinit.exe"
                | "logonui.exe"
                | "dwm.exe"
                | "ntoskrnl.exe"
                | "system"
                | "svchost.exe"
                | "explorer.exe"
                | "sihost.exe"
                | "searchhost.exe"
                | "searchapp.exe"
                | "searchindexer.exe"
                | "searchprotocolhost.exe"
                | "searchfilterhost.exe"
                | "searchui.exe"
                | "startmenuexperiencehost.exe"
                | "shellexperiencehost.exe"
                | "shellhost.exe"
                | "textinputhost.exe"
                | "runtimebroker.exe"
                | "ctfmon.exe"
                | "taskhostw.exe"
                | "dllhost.exe"
                | "backgroundtaskhost.exe"
                | "applicationframehost.exe"
                | "systemsettings.exe"
                | "widgets.exe"
                | "widgetservice.exe"
                | "widgetboard.exe"
                | "msedgewebview2.exe"
                | "smartscreen.exe"
                | "wmiprvse.exe"
                | "wmiapsrv.exe"
                | "tiworker.exe"
                | "trustedinstaller.exe"
                | "vssvc.exe"
                | "spoolsv.exe"
                | "fontdrvhost.exe"
                | "audiodg.exe"
                | "taskmgr.exe"
                | "conhost.exe"
                | "openconsole.exe"
                | "windowsterminal.exe"
                | "wt.exe"
                | "sysmon.exe"
                | "sysmon64.exe"
                | "osoosi.exe"
                | "oshoosi.exe"
                | "msmpeng.exe"
                | "securityhealthservice.exe"
                | "securityhealthsystray.exe"
                | "securityhealthhost.exe"
        );
    if is_core_os_binary
        && (is_critical_path
            || is_security_provider_process(pid, filename)
            || filename == "system"
            || filename == "ntoskrnl.exe"
            || (!path_lc.contains('\\') && !path_unix.contains('/')))
    {
        return true;
    }

    // Digital signature check via win_trust or get_pe_metadata
    let path = std::path::Path::new(image_path);
    if crate::win_trust::is_trusted_signed_binary(path) {
        return true;
    }
    if let Some(metadata) = osoosi_types::get_pe_metadata(path) {
        let product = metadata.product_name.to_lowercase();
        let publisher = metadata.publisher.as_deref().unwrap_or("").to_lowercase();
        let is_microsoft = product.contains("microsoft")
            || product.contains("windows")
            || publisher.contains("microsoft")
            || publisher.contains("windows");

        if metadata.is_signed && is_microsoft {
            return true;
        }
    }

    false
}

/// Helper to tokenize a command line string respecting single, double, and backtick quotes.
pub fn split_cmd_tokens(cmd: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote_char: Option<char> = None;

    for c in cmd.chars() {
        match quote_char {
            Some(q) => {
                if c == q {
                    quote_char = None;
                } else {
                    current.push(c);
                }
            }
            None => {
                if c == '"' || c == '\'' || c == '`' {
                    quote_char = Some(c);
                } else if c.is_whitespace() {
                    if !current.is_empty() {
                        tokens.push(current);
                        current = String::new();
                    }
                } else {
                    current.push(c);
                }
            }
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Extract unauthorized account username from command lines executing T1136.001.
pub fn extract_created_username(cmd: &str) -> Option<String> {
    let cmd_clean = cmd.trim();
    if cmd_clean.is_empty() {
        return None;
    }

    let raw_tokens = split_cmd_tokens(cmd_clean);
    if raw_tokens.is_empty() {
        return None;
    }

    let tokens: Vec<String> = raw_tokens
        .into_iter()
        .map(|t| {
            t.trim_matches(|c| c == '"' || c == '\'' || c == '`')
                .to_string()
        })
        .collect();

    // Check net / net1 user ... /add
    if let Some(user_idx) = tokens.iter().position(|t| t.eq_ignore_ascii_case("user")) {
        let is_net = user_idx > 0 && {
            let prev = &tokens[user_idx - 1];
            let prev_fn = std::path::Path::new(prev)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(prev);
            prev_fn.eq_ignore_ascii_case("net")
                || prev_fn.eq_ignore_ascii_case("net.exe")
                || prev_fn.eq_ignore_ascii_case("net1")
                || prev_fn.eq_ignore_ascii_case("net1.exe")
        };
        let has_add = tokens.iter().any(|t| {
            let t_lc = t.to_ascii_lowercase();
            t_lc == "/add"
                || t_lc == "-add"
                || t_lc.starts_with("/add:")
                || t_lc.starts_with("-add:")
        });
        if is_net && has_add {
            for t in &tokens[user_idx + 1..] {
                if t.starts_with('/') || t.starts_with('-') {
                    continue;
                }
                let user = t.trim_matches(|c| c == '"' || c == '\'' || c == '`');
                if !user.is_empty() {
                    return Some(user.to_string());
                }
            }
        }
    }

    // Check New-LocalUser -Name <username>
    let cmd_lower = cmd_clean.to_ascii_lowercase();
    if cmd_lower.contains("new-localuser") {
        for (i, t) in tokens.iter().enumerate() {
            let t_lc = t.to_ascii_lowercase();
            if t_lc == "-name" || t_lc == "-n" {
                if let Some(next) = tokens.get(i + 1) {
                    let user = next.trim_matches(|c| c == '"' || c == '\'' || c == '`');
                    if !user.is_empty() && !user.starts_with('-') && !user.starts_with('/') {
                        return Some(user.to_string());
                    }
                }
            } else if t_lc.starts_with("-name:") || t_lc.starts_with("-name=") {
                let user = t[6..].trim_matches(|c| c == '"' || c == '\'' || c == '`');
                if !user.is_empty() {
                    return Some(user.to_string());
                }
            }
        }
        if let Some(cmd_idx) = tokens
            .iter()
            .position(|t| t.to_ascii_lowercase().contains("new-localuser"))
        {
            for t in &tokens[cmd_idx + 1..] {
                if t.starts_with('-') || t.starts_with('/') {
                    continue;
                }
                let user = t.trim_matches(|c| c == '"' || c == '\'' || c == '`');
                if !user.is_empty() {
                    return Some(user.to_string());
                }
            }
        }
    }

    None
}

/// Known protected Windows system, administrative, and service accounts safelist
pub const PROTECTED_SYSTEM_ACCOUNTS: &[&str] = &[
    "administrator",
    "admin",
    "guest",
    "defaultaccount",
    "wdagutilityaccount",
    "owner",
    "system",
    "localsystem",
    "localservice",
    "networkservice",
    "trustedinstaller",
    "iusr",
    "iis_iusrs",
    "all application packages",
    "everyone",
];

/// Checks if a username corresponds to a protected Windows system/service account or active user.
pub fn is_protected_system_account(username: &str) -> bool {
    let clean = username.trim().to_ascii_lowercase();
    if clean.is_empty() {
        return false;
    }

    if PROTECTED_SYSTEM_ACCOUNTS.contains(&clean.as_str()) {
        return true;
    }

    for env_var in ["USERNAME", "USER", "LOGNAME"] {
        if let Ok(val) = std::env::var(env_var) {
            let env_clean = val.trim().to_ascii_lowercase();
            if !env_clean.is_empty() && clean == env_clean {
                return true;
            }
        }
    }

    false
}

/// Baseline pre-existing accounts and protected accounts to prevent Confused Deputy rollback attacks.
pub fn query_system_accounts() -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();

    // 1. Insert all hardcoded protected accounts
    for acc in PROTECTED_SYSTEM_ACCOUNTS {
        set.insert(acc.to_string());
    }

    // 2. Insert active logged-in user from environment
    for env_var in ["USERNAME", "USER", "LOGNAME"] {
        if let Ok(val) = std::env::var(env_var) {
            let val_clean = val.trim().to_ascii_lowercase();
            if !val_clean.is_empty() {
                set.insert(val_clean);
            }
        }
    }

    // 3. On Windows, discover all pre-existing local accounts
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let mut discovered = false;
        {
            use windows::core::PCWSTR;
            use windows::Win32::NetworkManagement::NetManagement::{
                NetApiBufferFree, NetUserEnum, FILTER_NORMAL_ACCOUNT, USER_INFO_0,
            };

            let mut bufptr: *mut u8 = std::ptr::null_mut();
            let mut entries_read = 0u32;
            let mut total_entries = 0u32;
            let mut resume_handle = 0u32;

            unsafe {
                let status = NetUserEnum(
                    PCWSTR::null(),
                    0,
                    FILTER_NORMAL_ACCOUNT,
                    &mut bufptr,
                    u32::MAX,
                    &mut entries_read,
                    &mut total_entries,
                    Some(&mut resume_handle),
                );
                if status == 0 && !bufptr.is_null() {
                    let slice = std::slice::from_raw_parts(
                        bufptr as *const USER_INFO_0,
                        entries_read as usize,
                    );
                    for info in slice {
                        if !info.usri0_name.is_null() {
                            if let Ok(name) = info.usri0_name.to_string() {
                                let user = name.trim().to_ascii_lowercase();
                                if !user.is_empty() {
                                    set.insert(user);
                                    discovered = true;
                                }
                            }
                        }
                    }
                    let _ = NetApiBufferFree(Some(bufptr as *const _));
                }
            }
        }

        // Fallback to net.exe user if powershell failed or yielded nothing
        if !discovered {
            if let Ok(output) =
                std::process::Command::new(osoosi_types::resolve_system_binary("net.exe"))
                    .args(["user"])
                    .creation_flags(CREATE_NO_WINDOW)
                    .output()
            {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let mut capturing = false;
                    for line in stdout.lines() {
                        let trimmed = line.trim();
                        if trimmed.starts_with("---") {
                            capturing = true;
                            continue;
                        }
                        if capturing {
                            if trimmed.is_empty() || trimmed.starts_with("The command completed") {
                                continue;
                            }
                            for user in trimmed.split_whitespace() {
                                let user_clean = user.trim().to_ascii_lowercase();
                                if !user_clean.is_empty() {
                                    set.insert(user_clean);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    set
}

pub const NON_DESTRUCTIVE_ACCOUNT_CONTAINMENT_EVENT: &str = "NON_DESTRUCTIVE_ACCOUNT_CONTAINMENT";
pub const NON_DESTRUCTIVE_ACCOUNT_CONTAINMENT_STATUS: &str = "contained_disabled_non_destructive";
pub const NON_DESTRUCTIVE_ACCOUNT_CONTAINMENT_METHOD: &str =
    "net user /active:no or Disable-LocalUser";

/// Helper to get non-destructive account disabling arguments for net.exe.
/// Strictly non-destructive: uses `/active:no` rather than `/delete`.
pub fn get_account_containment_net_args(username: &str) -> [&str; 3] {
    ["user", username, "/active:no"]
}

/// Helper to escape single quotes for safe embedding in PowerShell single-quoted literals.
pub fn escape_powershell_arg(arg: &str) -> String {
    arg.replace('\'', "''")
}

/// Helper to get non-destructive account disabling command for PowerShell.
/// Strictly non-destructive: uses `Disable-LocalUser` rather than `Remove-LocalUser`.
/// Safely escapes single quotes to prevent injection and syntax errors.
pub fn get_account_containment_powershell_cmd(username: &str) -> String {
    let clean = escape_powershell_arg(username);
    format!(
        "Disable-LocalUser -Name '{}' -ErrorAction SilentlyContinue",
        clean
    )
}

#[cfg(target_os = "windows")]
pub(crate) fn win32_user_exists(username: &str) -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::NetworkManagement::NetManagement::{NetApiBufferFree, NetUserGetInfo};

    let wide_user: Vec<u16> = username.encode_utf16().chain(std::iter::once(0)).collect();
    let mut bufptr: *mut u8 = std::ptr::null_mut();
    unsafe {
        let status = NetUserGetInfo(PCWSTR::null(), PCWSTR(wide_user.as_ptr()), 0, &mut bufptr);
        if status == 0 && !bufptr.is_null() {
            let _ = NetApiBufferFree(Some(bufptr as *const _));
            true
        } else {
            false
        }
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn win32_disable_user(username: &str) -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::NetworkManagement::NetManagement::{
        NetUserSetInfo, UF_ACCOUNTDISABLE, USER_INFO_1008,
    };

    let wide_user: Vec<u16> = username.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let info_1008 = USER_INFO_1008 {
            usri1008_flags: UF_ACCOUNTDISABLE,
        };
        let mut parm_err = 0u32;
        let status = NetUserSetInfo(
            PCWSTR::null(),
            PCWSTR(wide_user.as_ptr()),
            1008,
            &info_1008 as *const _ as *const u8,
            Some(&mut parm_err),
        );
        status == 0
    }
}

/// Helper to check whether account containment is allowed against a given baseline.
/// Strictly refuses empty usernames, CLI flags (/ or -), command separators, control characters, protected accounts, and pre-existing baseline accounts.
pub fn is_account_containment_allowed(
    username: &str,
    baseline: &std::collections::HashSet<String>,
) -> bool {
    let clean = username.trim().to_ascii_lowercase();
    if clean.is_empty()
        || clean.starts_with('/')
        || clean.starts_with('-')
        || clean.contains('\0')
        || clean.contains('\r')
        || clean.contains('\n')
        || clean.contains(';')
        || clean.contains('&')
        || clean.contains('|')
    {
        return false;
    }
    !is_protected_system_account(&clean) && !baseline.contains(&clean)
}

/// Helper to check whether account rollback is allowed against a given baseline (alias to is_account_containment_allowed).
pub fn is_account_rollback_allowed(
    username: &str,
    baseline: &std::collections::HashSet<String>,
) -> bool {
    is_account_containment_allowed(username, baseline)
}

/// Identify confirmed, high-severity critical attacks that warrant fast-path containment.
/// Generic user execution (AML.T0011, T1204), routine scripts (T1059), and discovery (T1082, T1033)
/// must NEVER trigger an Audit Override!
pub(crate) fn is_critical_security_attack(
    sig: &osoosi_types::ThreatSignature,
    event: &osoosi_types::HostSecurityEvent,
) -> bool {
    // High-severity destructive mutations (ransomware, shadow copies, boot config, system integrity, credential dumpers)
    if is_destructive_mutation(sig, event) {
        return true;
    }

    let tech_id = sig
        .mitre_technique
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_ascii_uppercase();

    // Routine user execution, scripting, and discovery below 0.85 confidence must never escalate to critical attack
    // so the host remains 100% usable in all modes (including Lockdown Mode).
    let is_routine_noise_tech = tech_id.starts_with("AML.T0011")
        || tech_id.starts_with("T1204")
        || tech_id.starts_with("T1059")
        || tech_id.starts_with("T1082")
        || tech_id.starts_with("T1033");
    if is_routine_noise_tech && sig.confidence < 0.85 {
        return false;
    }

    if sig.confidence >= 0.75 && (tech_id.starts_with('T') || tech_id.starts_with("AML.T")) {
        return true;
    }

    false
}

/// Helper to determine if a detected threat signature matches any cataloged attack pattern.
/// Delegates to is_critical_security_attack to prevent low-severity or routine execution false positives.
#[inline]
pub(crate) fn is_mitre_catalog_attack(
    sig: &osoosi_types::ThreatSignature,
    event: &osoosi_types::HostSecurityEvent,
) -> bool {
    is_critical_security_attack(sig, event)
}

/// Identify high-confidence destructive mutations that demand immediate containment/termination.
pub(crate) fn is_destructive_mutation(
    sig: &osoosi_types::ThreatSignature,
    event: &osoosi_types::HostSecurityEvent,
) -> bool {
    let cmd = event
        .data
        .get("CommandLine")
        .or_else(|| event.data.get("command_line"))
        .or_else(|| event.data.get("cmdline"))
        .or_else(|| event.data.get("Command"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    let img = event
        .data
        .get("Image")
        .or_else(|| event.data.get("NewProcessName"))
        .or_else(|| event.data.get("ProcessName"))
        .or_else(|| event.data.get("image"))
        .or_else(|| event.data.get("ImagePath"))
        .or_else(|| event.data.get("SourceImage"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    let reason = sig.reason.as_deref().unwrap_or("").to_lowercase();
    let tech = sig.mitre_technique.as_deref().unwrap_or("");
    let tech_upper = tech.to_ascii_uppercase();

    // System Integrity Tampering & Direct Volume Access (T1006 / T1601)
    if tech_upper.starts_with("T1006")
        || tech_upper.starts_with("T1601")
        || reason.contains("system integrity")
        || reason.contains("direct volume")
        || reason.contains("disk tampering")
    {
        return true;
    }

    // Unauthorized account creation (T1136)
    if tech_upper.starts_with("T1136")
        || ((cmd.contains("net user") || cmd.contains("net1 user")) && cmd.contains("/add"))
        || cmd.contains("new-localuser")
    {
        return true;
    }

    // Shadow copy / backup deletion / recovery inhibition (T1490 / T1489)
    if tech_upper.starts_with("T1490")
        || tech_upper.starts_with("T1489")
        || cmd.contains("vssadmin delete shadows")
        || cmd.contains("wbadmin delete catalog")
        || (cmd.contains("bcdedit") && cmd.contains("recoveryenabled no"))
    {
        return true;
    }

    // Ransomware encryption & data destruction (T1486 / T1485)
    if tech_upper.starts_with("T1486")
        || tech_upper.starts_with("T1485")
        || reason.contains("ransomware")
        || reason.contains("encryption")
        || reason.contains("wiper")
    {
        return true;
    }

    // Credential dumping, Vault, Secret store & LSASS/Shadow dumping (T1003 / T1555 / T1552 — Windows & Linux)
    if tech_upper.starts_with("T1003")
        || tech_upper.starts_with("T1555")
        || tech_upper.starts_with("T1552")
        || cmd.contains("procdump")
        || cmd.contains("comsvcs.dll")
        || cmd.contains("minidump")
        || img.contains("mimikatz")
        || cmd.contains("mimikatz")
        || cmd.contains("keymgr")
        || cmd.contains("krshowkeymgr")
        || img.ends_with("credwiz.exe")
        || cmd.contains("credwiz")
        || img.ends_with("vaultcmd.exe")
        || cmd.contains("vaultcmd")
        || img.ends_with("cmdkey.exe")
        || cmd.contains("cmdkey")
        || cmd.contains("gsecdump")
        || cmd.contains("nppspy")
        || cmd.contains("ntdsutil")
        || cmd.contains("lsadump")
        || cmd.contains("sekurlsa")
        || cmd.contains("dcsync")
        || cmd.contains("rdrleakdiag")
        || cmd.contains("tttracer")
        || cmd.contains("sqldumper")
        || cmd.contains("createdump")
        || cmd.contains("mimipenguin")
        || cmd.contains("unshadow")
        || cmd.contains("/etc/shadow")
        || cmd.contains("/etc/gshadow")
        || cmd.contains("ld.so.preload")
        || ((cmd.contains("reg save")
            || cmd.contains("reg export")
            || cmd.contains("reg.exe save"))
            && (cmd.contains("sam") || cmd.contains("security") || cmd.contains("system")))
    {
        return true;
    }

    // Process Hollowing / Remote Injection (T1055)
    if tech_upper.starts_with("T1055")
        || reason.contains("hollowing")
        || reason.contains("injection")
    {
        return true;
    }

    // Defense Impairment & Trust Subversion (T1562 / T1553)
    if tech_upper.starts_with("T1562")
        || tech_upper.starts_with("T1553")
        || (cmd.contains("sc stop") && cmd.contains("windefend"))
        || cmd.contains("disable-antivirus")
        || cmd.contains("set-mppreference -disablerealtimemonitoring")
    {
        return true;
    }

    // Persistence & Autostart Tampering (T1542, T1543, T1546, T1547, T1556, T1574)
    if tech_upper.starts_with("T1542")
        || tech_upper.starts_with("T1543")
        || tech_upper.starts_with("T1546")
        || tech_upper.starts_with("T1547")
        || tech_upper.starts_with("T1556")
        || tech_upper.starts_with("T1574")
    {
        return true;
    }

    false
}

pub fn is_developer_tool(name: &str, exe_path: Option<&std::path::Path>) -> bool {
    let name_lc = name.to_ascii_lowercase();
    let filename_lc = name_lc
        .rsplit(['\\', '/'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(&name_lc);
    let base_name = filename_lc.strip_suffix(".exe").unwrap_or(filename_lc);

    let is_dev_name = matches!(
        base_name,
        "git"
            | "git-remote-http"
            | "git-remote-https"
            | "git-upload-pack"
            | "git-receive-pack"
            | "git-credential-manager"
            | "git-lfs"
            | "cargo"
            | "rustc"
            | "rust-analyzer"
            | "cargo-clippy"
            | "cargo-watch"
            | "node"
            | "npm"
            | "npx"
            | "yarn"
            | "pnpm"
            | "bun"
            | "deno"
            | "python"
            | "python3"
            | "py"
            | "code"
            | "code - insiders"
            | "code-insiders"
            | "devenv"
            | "msbuild"
            | "cl"
            | "link"
            | "cmake"
            | "ninja"
            | "idea64"
            | "clion64"
            | "pycharm64"
            | "goland64"
            | "webstorm64"
            | "rustrover64"
            | "llama-server"
            | "ollama"
            | "ollama_llama_server"
            | "vllm"
            | "text-generation-launcher"
            | "tritonserver"
            | "local-ai"
            | "tabby"
            | "tabby-cpu"
            | "system"
            | "registry"
            | "smss"
            | "csrss"
            | "wininit"
            | "services"
            | "lsass"
            | "ssdupdate"
            | "softwarecomponentinv"
            | "appxinventory"
            | "extdrvrinv"
            | "peripheralfrmwinv"
            | "nvmehostmetadata"
            | "msedge"
            | "msedge_proxy"
            | "pwahelper"
            | "old_msedge"
            | "chrome"
            | "firefox"
            | "brave"
    ) || base_name.starts_with("git-")
        || base_name.starts_with("cargo-")
        || base_name.starts_with("rust-");

    if !is_dev_name {
        return false;
    }

    if let Some(p) = exe_path {
        if crate::rea::is_untrusted_writable_or_temp_path(&p.to_string_lossy()) {
            return false;
        }
        return crate::rea::verify_dynamic_binary_trust(p);
    }

    is_dev_name
}

pub fn should_skip_file_malware_scan(path: &std::path::Path) -> bool {
    let s = path.to_string_lossy();
    if s.contains(".tmp.driveupload") || s.contains(".tmp.drivedownload") {
        return true;
    }
    crate::voters::scanner_skip_path(&s)
}

pub fn is_internal_or_deception_path(path_str: &str) -> bool {
    if path_str.trim().is_empty() {
        return false;
    }
    let lower = path_str.to_lowercase().replace('/', "\\");
    let trimmed = lower.trim_matches('\\');
    if trimmed == "traps"
        || trimmed == "database"
        || trimmed == "runs"
        || trimmed == "logs"
        || trimmed == "models"
        || trimmed == ".agents"
        || trimmed == ".gemini"
    {
        return true;
    }
    let padded = format!("\\{}\\", trimmed);
    padded.contains("\\traps\\")
        || padded.contains("\\database\\")
        || padded.contains("osoosi.db")
        || padded.contains("osoosi.log")
        || padded.contains("osoosi_core.log")
        || padded.contains("\\runs\\")
        || padded.contains("\\logs\\")
        || padded.contains("\\models\\")
        || padded.contains("\\.agents\\")
        || padded.contains("\\.gemini\\")
        || padded.contains(".tmp.driveupload")
        || padded.contains(".tmp.drivedownload")
}

pub fn is_cloud_storage_service(name: &str, exe_path: Option<&std::path::Path>) -> bool {
    let name_lc = name.to_ascii_lowercase();
    let filename_lc = std::path::Path::new(&name_lc)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&name_lc);
    let base = filename_lc.strip_suffix(".exe").unwrap_or(filename_lc);
    let is_name_match = matches!(
        base,
        "googledrivefs"
            | "googledrivesync"
            | "googledrive"
            | "drivefs"
            | "onedrive"
            | "onedriveupdater"
            | "onedrivestandaloneupdater"
            | "filecoauth"
            | "dropbox"
            | "dropboxupdate"
            | "dropboxservice"
            | "nextcloud"
            | "owncloud"
            | "box"
            | "boxsync"
            | "boxedit"
            | "icloudservices"
            | "iclouddrive"
            | "icloud"
            | "seafile"
            | "seafile-applet"
            | "insync"
            | "kbfs"
            | "megasync"
            | "synologydrive"
            | "synology-drive"
            | "pcloud"
            | "tresorit"
            | "rclone"
            | "dokanmounter"
            | "dokan"
            | "winfsp-x64"
            | "winfsp-x86"
            | "winfsp"
    );
    if !is_name_match {
        return false;
    }

    if let Some(p) = exe_path {
        if crate::rea::is_untrusted_writable_or_temp_path(&p.to_string_lossy()) {
            return false;
        }
        return crate::win_trust::is_trusted_signed_binary(p);
    }

    is_name_match
}

pub(crate) fn register_internal_assets(memory: &MemoryStore) {
    let mut assets: Vec<(std::path::PathBuf, &'static str)> = Vec::new();

    let tools_dir = osoosi_types::resolve_tools_dir();
    assets.push((tools_dir.clone(), "tools"));
    if let Some(root) = tools_dir.parent() {
        for (name, kind) in [
            ("dashboard", "dashboard"),
            ("target", "build-output"),
            ("cache", "cache"),
            ("models", "models"),
            ("logs", "logs"),
            ("traps", "deception"),
            (".git", "repo-metadata"),
        ] {
            assets.push((root.join(name), kind));
        }
        assets.push((root.join("osoosi.toml"), "config"));
    }

    if let Ok(user_profile) = std::env::var("USERPROFILE") {
        let user = std::path::PathBuf::from(user_profile);
        assets.push((user.join(".codex"), "assistant-state"));
        assets.push((user.join(".gemini"), "assistant-state"));
    }

    for (path, kind) in assets {
        if let Some(path) = path.to_str() {
            if let Err(err) = memory.upsert_internal_asset(path, kind, None) {
                debug!("Failed to register internal asset {}: {}", path, err);
            }
        }
    }
}

/// Behavioral YARA-X rules: Matches on event JSON bytes to replace Sigma/Hayabusa logic.
pub(crate) fn try_build_behavioral_yara_voter(
    adaptive: Arc<crate::adaptive::TelemetryController>,
) -> Option<crate::voters::BehavioralYaraVoter> {
    use crate::voters::BehavioralYaraVoter;
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> anyhow::Result<BehavioralYaraVoter> {
            let mut compiler = yara_x::Compiler::new();

            // Replicate core Sigma-style behavioral rules in YARA-X (matches on HostSecurityEvent JSON)
            compiler
                .add_source(
                    r#"
            rule Suspicious_Curl_Download {
                strings:
                    $curl = "curl.exe"
                    $http = "http"
                    $out = "-o"
                condition:
                    all of them
            }
            rule Encoded_PowerShell {
                strings:
                    $ps = "powershell"
                    $enc = " -enc" nocase
                    $encoded = " -EncodedCommand" nocase
                condition:
                    $ps and ($enc or $encoded)
            }
            rule Shadow_Copy_Deletion {
                strings:
                    $vss = "vssadmin" nocase
                    $del = "delete" nocase
                    $shadows = "shadows" nocase
                condition:
                    all of them
            }
            rule Credential_Dumping_LSASS {
                strings:
                    $proc = "EventID\":10"
                    $lsass = "lsass.exe" nocase
                    $access = "0x1410" // common dump access mask
                condition:
                    all of them
            }
        "#,
                )
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            // Optionally load external rules if they exist
            let behavioral_yar = osoosi_types::resolve_rules_dir().join("behavioral.yar");
            if behavioral_yar.exists() {
                if let Ok(src) = std::fs::read_to_string(&behavioral_yar) {
                    let _ = compiler.add_source(src.as_str());
                }
            }

            Ok(BehavioralYaraVoter {
                rules: Arc::new(compiler.build()),
                adaptive,
                total_detections: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            })
        },
    ));
    match r {
        Ok(Ok(v)) => Some(v),
        Ok(Err(e)) => {
            warn!(
                "YARA-X: Behavioral rule compile error: {}; skipping BehavioralYaraVoter",
                e
            );
            None
        }
        Err(_) => {
            warn!("YARA-X: Behavioral rule build panicked; skipping BehavioralYaraVoter");
            None
        }
    }
}

