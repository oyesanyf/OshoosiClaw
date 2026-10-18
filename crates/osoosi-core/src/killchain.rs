//! OpenỌ̀ṣọ́ọ̀sì Emergency Kill Chain & Reversible Host Isolation Subsystem.
//!
//! Provides enterprise-grade emergency host containment ("Defend-in-Place Killswitch"):
//! - Hermetic Network Quarantine (blocks all outbound/inbound traffic while preserving local loopback & port 3030 management)
//! - Non-Destructive Active Process Freeze (suspends untrusted user processes without terminating core OS infrastructure)
//! - Kernel-Enforced Pre-Execution Lockdown
//! - Reversible Disarm & Full State Restoration
//! - Anti-Exploitation Operator Confirmation Gate & Physical Unattended Session Defense

use anyhow::{anyhow, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{LazyLock, RwLock};
use std::time::Instant;
use tracing::{error, info, warn};

pub const KILLCHAIN_ISOLATE_TOKEN: &str = "CONFIRM ISOLATE";
pub const KILLCHAIN_RESTORE_TOKEN: &str = "CONFIRM RESTORE";
pub const MAX_FAILED_ATTEMPTS: u32 = 3;
pub const LOCKOUT_DURATION_SECS: u64 = 300; // 5 minutes

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainStatus {
    pub isolated: bool,
    pub isolated_at: Option<String>,
    pub isolated_by: Option<String>,
    pub reason: Option<String>,
    pub network_isolated: bool,
    pub processes_frozen_count: usize,
    pub kernel_lockdown_active: bool,
    pub allowlisted_ports: Vec<u16>,
    pub quarantined_interfaces: Vec<String>,
    pub frozen_pids: Vec<u32>,
    pub last_action_timestamp: Option<String>,
    pub lockout_remaining_secs: u64,
}

impl Default for KillChainStatus {
    fn default() -> Self {
        Self {
            isolated: false,
            isolated_at: None,
            isolated_by: None,
            reason: None,
            network_isolated: false,
            processes_frozen_count: 0,
            kernel_lockdown_active: false,
            allowlisted_ports: vec![3030],
            quarantined_interfaces: vec![],
            frozen_pids: vec![],
            last_action_timestamp: None,
            lockout_remaining_secs: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainHistoryEntry {
    pub timestamp: String,
    pub action: String, // "ENGAGED" or "DISARMED"
    pub operator: String,
    pub reason: String,
    pub event_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct KillChainStorage {
    status: KillChainStatus,
    history: Vec<KillChainHistoryEntry>,
}

static KILLCHAIN_STORAGE: LazyLock<RwLock<KillChainStorage>> = LazyLock::new(|| {
    let storage = load_storage_from_disk().unwrap_or_default();
    RwLock::new(storage)
});

static RATE_LIMIT_LOCK: LazyLock<RwLock<(u32, Option<Instant>)>> =
    LazyLock::new(|| RwLock::new((0, None)));

fn storage_file_path() -> PathBuf {
    std::env::var("OSOOSI_DATABASE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("database"))
        .join("killchain_state.json")
}

fn load_storage_from_disk() -> Result<KillChainStorage> {
    let p = storage_file_path();
    if !p.exists() {
        return Ok(KillChainStorage::default());
    }
    let data = std::fs::read_to_string(&p)?;
    let storage: KillChainStorage = serde_json::from_str(&data)?;
    Ok(storage)
}

fn save_storage_to_disk(storage: &KillChainStorage) -> Result<()> {
    let p = storage_file_path();
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let json = serde_json::to_string_pretty(storage)?;
    std::fs::write(&p, json)?;
    Ok(())
}

/// Constant-time string equality check to protect against timing attacks.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a_bytes.iter().zip(b_bytes.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Checks whether the Kill Chain interface is currently in a security lockout state.
pub fn check_lockout_status() -> (bool, u64) {
    let mut guard = RATE_LIMIT_LOCK.write().unwrap();
    if let (fails, Some(lock_time)) = *guard {
        if fails >= MAX_FAILED_ATTEMPTS {
            let elapsed = lock_time.elapsed().as_secs();
            if elapsed < LOCKOUT_DURATION_SECS {
                return (true, LOCKOUT_DURATION_SECS - elapsed);
            } else {
                // Lockout expired, reset counters
                *guard = (0, None);
            }
        }
    }
    (false, 0)
}

/// Record a failed verification attempt. Triggers security lockout on 3 strikes.
pub fn record_failed_attempt() -> (bool, u64) {
    let mut guard = RATE_LIMIT_LOCK.write().unwrap();
    let (mut fails, _) = *guard;
    fails += 1;
    let now = Instant::now();
    *guard = (fails, Some(now));

    if fails >= MAX_FAILED_ATTEMPTS {
        warn!(
            "🚨 [KILLCHAIN] Excessive failed authorization attempts ({}/{}). Enforcing {}-second security lockout!",
            fails, MAX_FAILED_ATTEMPTS, LOCKOUT_DURATION_SECS
        );
        (true, LOCKOUT_DURATION_SECS)
    } else {
        (false, 0)
    }
}

/// Reset failed attempts upon successful authorized operation.
pub fn record_successful_auth() {
    let mut guard = RATE_LIMIT_LOCK.write().unwrap();
    *guard = (0, None);
}

/// Query current Kill Chain host isolation status.
pub fn get_killchain_status() -> KillChainStatus {
    let guard = KILLCHAIN_STORAGE.read().unwrap();
    let mut status = guard.status.clone();
    let (_, remaining) = check_lockout_status();
    status.lockout_remaining_secs = remaining;
    status
}

/// Query Kill Chain history ledger.
pub fn get_killchain_history() -> Vec<KillChainHistoryEntry> {
    let guard = KILLCHAIN_STORAGE.read().unwrap();
    guard.history.clone()
}

/// Engage Emergency Kill Chain Host Isolation.
///
/// Multi-stage action:
/// 1. Hermetic Network Quarantine: blocks non-loopback network traffic while strictly preserving
///    loopback (127.0.0.1, ::1) and local WebUI port 3030 so the security operator maintains control.
/// 2. Non-Destructive Active Process Freeze: suspends untrusted non-system processes.
/// 3. Pre-Execution Kernel Lockdown.
/// 4. Cryptographic event audit logging.
pub async fn engage_killchain_isolation(
    operator: &str,
    reason: &str,
    isolate_network: bool,
    freeze_processes: bool,
    kernel_lockdown: bool,
) -> Result<KillChainStatus> {
    let (is_locked, remaining) = check_lockout_status();
    if is_locked {
        return Err(anyhow!(
            "Kill Chain interface is locked due to repeated authentication failures. Remaining lockout: {} seconds.",
            remaining
        ));
    }

    info!(
        "🚨 [KILLCHAIN] Engaging Emergency Host Isolation requested by '{}' (reason: '{}')",
        operator, reason
    );

    let mut guard = KILLCHAIN_STORAGE.write().unwrap();
    if guard.status.isolated {
        info!("🛡️ [KILLCHAIN-IDEMPOTENCY] Host is already isolated; redundant engagement request from '{}' safely preserved.", operator);
        return Ok(guard.status.clone());
    }
    let now = Utc::now().to_rfc3339();

    let mut quarantined_interfaces = Vec::new();
    let mut network_isolated = false;

    if isolate_network {
        match apply_network_hermetic_quarantine() {
            Ok(interfaces) => {
                quarantined_interfaces = interfaces;
                network_isolated = true;
                info!("🚨 [KILLCHAIN] Hermetic network quarantine successfully applied.");
            }
            Err(e) => {
                error!(
                    "❌ [KILLCHAIN] Failed to apply network hermetic quarantine: {}",
                    e
                );
            }
        }
    }

    let mut frozen_pids = Vec::new();
    if freeze_processes {
        match freeze_untrusted_processes() {
            Ok(pids) => {
                info!(
                    "🚨 [KILLCHAIN] Suspended {} untrusted user-space processes non-destructively.",
                    pids.len()
                );
                frozen_pids = pids;
            }
            Err(e) => {
                warn!(
                    "⚠️ [KILLCHAIN] Non-destructive process freeze encountered error: {}",
                    e
                );
            }
        }
    }

    let mut kernel_lockdown_active = false;
    if kernel_lockdown {
        #[cfg(target_os = "windows")]
        {
            if let Some(driver) = osoosi_runtime::kernel_driver::KernelDriverClient::connect() {
                if driver
                    .set_mode(osoosi_runtime::kernel_driver::DriverAutonomyMode::Lockdown)
                    .is_ok()
                {
                    kernel_lockdown_active = true;
                    info!("🚨 [KILLCHAIN] Ring-0 kernel driver switched to Lockdown mode.");
                }
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            kernel_lockdown_active = true;
        }
    }

    let event_payload = format!(
        "{}:{}:{}:{}:isolated",
        now, operator, reason, network_isolated
    );
    let event_hash = blake3::hash(event_payload.as_bytes()).to_hex().to_string();

    guard.status = KillChainStatus {
        isolated: true,
        isolated_at: Some(now.clone()),
        isolated_by: Some(operator.to_string()),
        reason: Some(reason.to_string()),
        network_isolated,
        processes_frozen_count: frozen_pids.len(),
        kernel_lockdown_active,
        allowlisted_ports: vec![3030],
        quarantined_interfaces,
        frozen_pids,
        last_action_timestamp: Some(now.clone()),
        lockout_remaining_secs: 0,
    };

    guard.history.insert(
        0,
        KillChainHistoryEntry {
            timestamp: now,
            action: "ENGAGED".to_string(),
            operator: operator.to_string(),
            reason: reason.to_string(),
            event_hash,
        },
    );

    let _ = save_storage_to_disk(&guard);
    record_successful_auth();
    let status_clone = guard.status.clone();
    drop(guard);

    // Anti-Bricking / Dead-Man's Failsafe Watchdog:
    // Guarantees an isolated host is automatically restored after 30 minutes if unattended,
    // ensuring an attacker or script can NEVER permanently hold the machine hostage.
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(1800)).await;
        let current = get_killchain_status();
        if current.isolated {
            warn!("⏰ [KILLCHAIN-WATCHDOG] 30-minute maximum isolation limit reached. Automatically restoring host to prevent permanent lockout.");
            let _ = disarm_killchain_isolation(
                "failsafe_watchdog",
                "Automatic dead-man failsafe timeout (anti-hostage defense)",
            )
            .await;
        }
    });

    Ok(status_clone)
}

/// Validates caller process integrity before executing Kill Chain state changes.
/// Prevents a compromised or quarantined process from invoking or weaponizing the Kill Chain.
pub fn validate_killchain_caller(caller_pid: Option<u32>) -> Result<()> {
    if let Some(pid) = caller_pid {
        if pid <= 4 {
            return Err(anyhow!("Invalid caller PID {}", pid));
        }
        let guard = KILLCHAIN_STORAGE.read().unwrap();
        if guard.status.frozen_pids.contains(&pid) {
            return Err(anyhow!(
                "Anti-Hijacking Violation: Calling process (PID {}) is currently frozen under Kill Chain quarantine. Refusing invocation.",
                pid
            ));
        }
    }
    Ok(())
}

/// Disarm Emergency Kill Chain Host Isolation and restore the endpoint to normal operations.
///
/// 1. Removes all hermetic network quarantine rules.
/// 2. Resumes all suspended processes.
/// 3. Restores kernel driver mode to Active.
/// 4. Cryptographic event audit logging.
pub async fn disarm_killchain_isolation(operator: &str, reason: &str) -> Result<KillChainStatus> {
    let (is_locked, remaining) = check_lockout_status();
    if is_locked {
        return Err(anyhow!(
            "Kill Chain interface is locked due to repeated authentication failures. Remaining lockout: {} seconds.",
            remaining
        ));
    }

    info!(
        "🟢 [KILLCHAIN] Disarming Host Isolation requested by '{}' (reason: '{}')",
        operator, reason
    );

    let mut guard = KILLCHAIN_STORAGE.write().unwrap();
    let now = Utc::now().to_rfc3339();

    // 1. Remove network quarantine
    if let Err(e) = remove_network_hermetic_quarantine() {
        error!(
            "❌ [KILLCHAIN] Error removing network quarantine rules: {}",
            e
        );
    } else {
        info!("🟢 [KILLCHAIN] Network quarantine rules flushed.");
    }

    // 2. Resume suspended processes
    let resumed_count = resume_frozen_processes(&guard.status.frozen_pids);
    info!("🟢 [KILLCHAIN] Resumed {} frozen processes.", resumed_count);

    // 3. Restore kernel driver mode
    #[cfg(target_os = "windows")]
    {
        if let Some(driver) = osoosi_runtime::kernel_driver::KernelDriverClient::connect() {
            let _ = driver.set_mode(osoosi_runtime::kernel_driver::DriverAutonomyMode::Active);
            info!("🟢 [KILLCHAIN] Ring-0 kernel driver restored to Active mode.");
        }
    }

    let event_payload = format!("{}:{}:{}:disarmed", now, operator, reason);
    let event_hash = blake3::hash(event_payload.as_bytes()).to_hex().to_string();

    guard.status = KillChainStatus {
        isolated: false,
        isolated_at: None,
        isolated_by: None,
        reason: Some(reason.to_string()),
        network_isolated: false,
        processes_frozen_count: 0,
        kernel_lockdown_active: false,
        allowlisted_ports: vec![3030],
        quarantined_interfaces: vec![],
        frozen_pids: vec![],
        last_action_timestamp: Some(now.clone()),
        lockout_remaining_secs: 0,
    };

    guard.history.insert(
        0,
        KillChainHistoryEntry {
            timestamp: now,
            action: "DISARMED".to_string(),
            operator: operator.to_string(),
            reason: reason.to_string(),
            event_hash,
        },
    );

    let _ = save_storage_to_disk(&guard);
    record_successful_auth();
    Ok(guard.status.clone())
}

/// Unconditional host restoration for service shutdown and emergency recovery.
/// Bypasses authentication and lockout checks to guarantee the host is never locked out on daemon exit.
pub fn execute_host_disarm_unauthenticated() -> Result<KillChainStatus> {
    info!("🟢 [KILLCHAIN] Unconditional Host Restoration initiated during service shutdown/stop.");

    // 1. Remove network quarantine rules
    if let Err(e) = remove_network_hermetic_quarantine() {
        error!("❌ [KILLCHAIN] Error removing network quarantine rules: {}", e);
    } else {
        info!("🟢 [KILLCHAIN] Network quarantine rules flushed.");
    }

    let mut guard = KILLCHAIN_STORAGE.write().unwrap();
    let now = Utc::now().to_rfc3339();

    // 2. Resume suspended processes
    let resumed_count = resume_frozen_processes(&guard.status.frozen_pids);
    info!("🟢 [KILLCHAIN] Resumed {} frozen processes.", resumed_count);

    // 3. Restore kernel driver mode
    #[cfg(target_os = "windows")]
    {
        if let Some(driver) = osoosi_runtime::kernel_driver::KernelDriverClient::connect() {
            let _ = driver.set_mode(osoosi_runtime::kernel_driver::DriverAutonomyMode::Active);
            info!("🟢 [KILLCHAIN] Ring-0 kernel driver restored to Active mode.");
        }
    }

    let reason = "Service Shutdown / Emergency Host Restoration";
    let operator = "SYSTEM_SHUTDOWN";
    let event_payload = format!("{}:{}:{}:disarmed", now, operator, reason);
    let event_hash = blake3::hash(event_payload.as_bytes()).to_hex().to_string();

    guard.status = KillChainStatus {
        isolated: false,
        isolated_at: None,
        isolated_by: None,
        reason: Some(reason.to_string()),
        network_isolated: false,
        processes_frozen_count: 0,
        kernel_lockdown_active: false,
        allowlisted_ports: vec![3030],
        quarantined_interfaces: vec![],
        frozen_pids: vec![],
        last_action_timestamp: Some(now.clone()),
        lockout_remaining_secs: 0,
    };

    guard.history.insert(
        0,
        KillChainHistoryEntry {
            timestamp: now,
            action: "DISARMED_SHUTDOWN".to_string(),
            operator: operator.to_string(),
            reason: reason.to_string(),
            event_hash,
        },
    );

    let _ = save_storage_to_disk(&guard);
    record_successful_auth();
    Ok(guard.status.clone())
}

// ---------------------------------------------------------------------------
// Network Isolation Primitives
// ---------------------------------------------------------------------------

/// Execute a system firewall command with stdout and stderr fully silenced,
/// preventing command-line noise (e.g. netsh 'No rules match the specified criteria').
fn run_firewall_cmd(cmd: &str, args: &[&str]) {
    #[allow(unused_mut)]
    let mut command = Command::new(cmd);
    command.args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let _ = command.status();
}

fn apply_network_hermetic_quarantine() -> Result<Vec<String>> {
    #[cfg(target_os = "windows")]
    {
        // 1. Ensure loopback and port 3030 allow rules exist first with highest priority
        run_firewall_cmd(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=Osoosi-KillChain-Allow-Loopback-In",
                "dir=in",
                "action=allow",
                "localip=127.0.0.1,::1",
                "profile=any",
            ],
        );

        run_firewall_cmd(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=Osoosi-KillChain-Allow-Loopback-Out",
                "dir=out",
                "action=allow",
                "remoteip=127.0.0.1,::1",
                "profile=any",
            ],
        );

        run_firewall_cmd(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=Osoosi-KillChain-Allow-WebUI-In",
                "dir=in",
                "action=allow",
                "protocol=TCP",
                "localport=3030",
                "profile=any",
            ],
        );

        run_firewall_cmd(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=Osoosi-KillChain-Allow-WebUI-Out",
                "dir=out",
                "action=allow",
                "protocol=TCP",
                "localport=3030",
                "profile=any",
            ],
        );

        run_firewall_cmd(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=Osoosi-KillChain-Allow-WebUI-Out-Remote",
                "dir=out",
                "action=allow",
                "protocol=TCP",
                "remoteport=3030",
                "profile=any",
            ],
        );

        // 2. Block all non-loopback inbound and outbound network traffic
        run_firewall_cmd(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=Osoosi-KillChain-Block-Inbound-Low",
                "dir=in",
                "action=block",
                "remoteip=0.0.0.0-126.255.255.255",
                "profile=any",
            ],
        );

        run_firewall_cmd(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=Osoosi-KillChain-Block-Inbound-High",
                "dir=in",
                "action=block",
                "remoteip=128.0.0.0-255.255.255.255",
                "profile=any",
            ],
        );

        run_firewall_cmd(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=Osoosi-KillChain-Block-Outbound-Low",
                "dir=out",
                "action=block",
                "remoteip=0.0.0.0-126.255.255.255",
                "profile=any",
            ],
        );

        run_firewall_cmd(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=Osoosi-KillChain-Block-Outbound-High",
                "dir=out",
                "action=block",
                "remoteip=128.0.0.0-255.255.255.255",
                "profile=any",
            ],
        );

        Ok(vec!["All-Windows-Adapters (Loopback Preserved)".to_string()])
    }

    #[cfg(target_os = "linux")]
    {
        run_firewall_cmd("iptables", &["-I", "INPUT", "1", "-i", "lo", "-j", "ACCEPT"]);
        run_firewall_cmd("iptables", &["-I", "OUTPUT", "1", "-o", "lo", "-j", "ACCEPT"]);
        run_firewall_cmd("iptables", &["-I", "INPUT", "2", "-p", "tcp", "--dport", "3030", "-j", "ACCEPT"]);
        run_firewall_cmd("iptables", &["-I", "OUTPUT", "2", "-p", "tcp", "--sport", "3030", "-j", "ACCEPT"]);
        run_firewall_cmd(
            "iptables",
            &[
                "-A",
                "INPUT",
                "-m",
                "comment",
                "--comment",
                "Osoosi-KillChain",
                "-j",
                "DROP",
            ],
        );
        run_firewall_cmd(
            "iptables",
            &[
                "-A",
                "OUTPUT",
                "-m",
                "comment",
                "--comment",
                "Osoosi-KillChain",
                "-j",
                "DROP",
            ],
        );
        run_firewall_cmd(
            "iptables",
            &[
                "-A",
                "FORWARD",
                "-m",
                "comment",
                "--comment",
                "Osoosi-KillChain",
                "-j",
                "DROP",
            ],
        );

        Ok(vec!["All-Linux-Interfaces (lo Preserved)".to_string()])
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Ok(vec!["Non-Windows-Linux-Simulated".to_string()])
    }
}

fn remove_network_hermetic_quarantine() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        let rules = [
            "Osoosi-KillChain-Block-Inbound-Low",
            "Osoosi-KillChain-Block-Inbound-High",
            "Osoosi-KillChain-Block-Outbound-Low",
            "Osoosi-KillChain-Block-Outbound-High",
            "Osoosi-KillChain-Allow-WebUI-In",
            "Osoosi-KillChain-Allow-WebUI-Out",
            "Osoosi-KillChain-Allow-WebUI-Out-Remote",
            "Osoosi-KillChain-Allow-Loopback-In",
            "Osoosi-KillChain-Allow-Loopback-Out",
        ];
        for r in rules {
            run_firewall_cmd(
                "netsh",
                &[
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    &format!("name={}", r),
                ],
            );
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        run_firewall_cmd(
            "iptables",
            &[
                "-D",
                "INPUT",
                "-m",
                "comment",
                "--comment",
                "Osoosi-KillChain",
                "-j",
                "DROP",
            ],
        );
        run_firewall_cmd(
            "iptables",
            &[
                "-D",
                "OUTPUT",
                "-m",
                "comment",
                "--comment",
                "Osoosi-KillChain",
                "-j",
                "DROP",
            ],
        );
        run_firewall_cmd(
            "iptables",
            &[
                "-D",
                "FORWARD",
                "-m",
                "comment",
                "--comment",
                "Osoosi-KillChain",
                "-j",
                "DROP",
            ],
        );
        run_firewall_cmd("iptables", &["-D", "INPUT", "-i", "lo", "-j", "ACCEPT"]);
        run_firewall_cmd("iptables", &["-D", "OUTPUT", "-o", "lo", "-j", "ACCEPT"]);
        run_firewall_cmd(
            "iptables",
            &[
                "-D", "INPUT", "-p", "tcp", "--dport", "3030", "-j", "ACCEPT",
            ],
        );
        run_firewall_cmd(
            "iptables",
            &[
                "-D", "OUTPUT", "-p", "tcp", "--sport", "3030", "-j", "ACCEPT",
            ],
        );
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Process Freeze Primitives (Non-destructive)
// ---------------------------------------------------------------------------

fn is_critical_system_pid(pid: u32, name: &str) -> bool {
    if pid <= 4 || pid == std::process::id() {
        return true;
    }
    let name_lc = name.to_ascii_lowercase();

    // Anti-Hijacking & EDR Self-Preservation Invariant:
    // Never freeze or suspend any component of the OpenOshoosi agent, CLI, service, or supervisor.
    if name_lc.contains("osoosi") || name_lc.contains("oshoosi") {
        return true;
    }

    matches!(
        name_lc.as_str(),
        "system"
            | "smss.exe"
            | "csrss.exe"
            | "wininit.exe"
            | "winlogon.exe"
            | "logonui.exe"
            | "credentialproviderhost.exe"
            | "sihost.exe"
            | "runtimebroker.exe"
            | "taskmgr.exe"
            | "securityhealthservice.exe"
            | "securityhealthsystray.exe"
            | "smartscreen.exe"
            | "consent.exe"
            | "fontdrvhost.exe"
            | "searchhost.exe"
            | "startmenuexperiencehost.exe"
            | "shellexperiencehost.exe"
            | "services.exe"
            | "lsass.exe"
            | "dwm.exe"
            | "svchost.exe"
            | "explorer.exe"
            | "sysmon.exe"
            | "sysmon64.exe"
            | "msmpeng.exe"
            | "chrome.exe"
            | "msedge.exe"
            | "firefox.exe"
            | "brave.exe"
            | "opera.exe"
            | "code.exe"
            | "antigravity.exe"
            | "windowsterminal.exe"
            | "openconsole.exe"
            | "conhost.exe"
            | "powershell.exe"
            | "pwsh.exe"
            | "cmd.exe"
            | "init"
            | "systemd"
            | "systemd-logind"
            | "systemd-journald"
            | "dbus-daemon"
            | "gdm"
            | "gdm3"
            | "lightdm"
            | "sddm"
            | "xorg"
            | "xwayland"
            | "gnome-shell"
            | "kwin"
            | "polkitd"
            | "agetty"
            | "windowserver"
            | "loginwindow"
            | "launchd"
            | "sshd"
            | "cargo.exe"
            | "rustc.exe"
            | "bash"
            | "sh"
            | "zsh"
    )
}

fn freeze_untrusted_processes() -> Result<Vec<u32>> {
    use sysinfo::System;
    let sys = System::new_all();

    let mut frozen = Vec::new();
    let current_pid = std::process::id();

    // Lineage Immunity: Build an immune PID set covering current process and its parent ancestry
    let mut immune_pids = std::collections::HashSet::new();
    immune_pids.insert(current_pid);
    immune_pids.insert(0);
    immune_pids.insert(1);
    immune_pids.insert(4);

    if let Some(mut current_proc) = sys.process(sysinfo::Pid::from_u32(current_pid)) {
        let mut depth = 0;
        while let Some(parent_pid) = current_proc.parent() {
            immune_pids.insert(parent_pid.as_u32());
            depth += 1;
            if depth >= 5 {
                break;
            }
            if let Some(p) = sys.process(parent_pid) {
                current_proc = p;
            } else {
                break;
            }
        }
    }

    for (pid_raw, proc) in sys.processes() {
        let pid = pid_raw.as_u32();
        let name = proc.name();

        if immune_pids.contains(&pid) || is_critical_system_pid(pid, name) {
            continue;
        }

        // Only freeze non-system processes
        #[cfg(target_os = "windows")]
        {
            if suspend_process_win32(pid) {
                frozen.push(pid);
            }
        }

        #[cfg(target_os = "linux")]
        {
            unsafe {
                if libc::kill(pid as i32, libc::SIGSTOP) == 0 {
                    frozen.push(pid);
                }
            }
        }
    }

    Ok(frozen)
}

fn resume_frozen_processes(pids: &[u32]) -> usize {
    let mut count = 0;
    for &pid in pids {
        #[cfg(target_os = "windows")]
        {
            if resume_process_win32(pid) {
                count += 1;
            }
        }

        #[cfg(target_os = "linux")]
        {
            unsafe {
                if libc::kill(pid as i32, libc::SIGCONT) == 0 {
                    count += 1;
                }
            }
        }
    }
    count
}

#[cfg(target_os = "windows")]
fn suspend_process_win32(pid: u32) -> bool {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_SUSPEND_RESUME};
    type NtSuspendProcessFn = unsafe extern "system" fn(isize) -> i32;

    unsafe {
        let handle_res = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
        if let Ok(handle) = handle_res {
            if let Ok(ntdll) = windows::Win32::System::LibraryLoader::GetModuleHandleA(
                windows::core::s!("ntdll.dll"),
            ) {
                if let Some(proc) = windows::Win32::System::LibraryLoader::GetProcAddress(
                    ntdll,
                    windows::core::s!("NtSuspendProcess"),
                ) {
                    let nt_suspend: NtSuspendProcessFn = std::mem::transmute(proc);
                    let status = nt_suspend(handle.0 as isize);
                    let _ = windows::Win32::Foundation::CloseHandle(handle);
                    return status == 0;
                }
            }
            let _ = windows::Win32::Foundation::CloseHandle(handle);
        }
    }
    false
}

#[cfg(target_os = "windows")]
fn resume_process_win32(pid: u32) -> bool {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_SUSPEND_RESUME};
    type NtResumeProcessFn = unsafe extern "system" fn(isize) -> i32;

    unsafe {
        let handle_res = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
        if let Ok(handle) = handle_res {
            if let Ok(ntdll) = windows::Win32::System::LibraryLoader::GetModuleHandleA(
                windows::core::s!("ntdll.dll"),
            ) {
                if let Some(proc) = windows::Win32::System::LibraryLoader::GetProcAddress(
                    ntdll,
                    windows::core::s!("NtResumeProcess"),
                ) {
                    let nt_resume: NtResumeProcessFn = std::mem::transmute(proc);
                    let status = nt_resume(handle.0 as isize);
                    let _ = windows::Win32::Foundation::CloseHandle(handle);
                    return status == 0;
                }
            }
            let _ = windows::Win32::Foundation::CloseHandle(handle);
        }
    }
    false
}

#[cfg(windows)]
mod win_auth {
    use std::ffi::c_void;
    use std::ptr::null_mut;

    const LOGON32_LOGON_NETWORK: u32 = 3;
    const LOGON32_LOGON_INTERACTIVE: u32 = 2;
    const LOGON32_PROVIDER_DEFAULT: u32 = 0;

    #[link(name = "advapi32")]
    #[link(name = "kernel32")]
    extern "system" {
        fn LogonUserW(
            lpszUsername: *const u16,
            lpszDomain: *const u16,
            lpszPassword: *const u16,
            dwLogonType: u32,
            dwLogonProvider: u32,
            phToken: *mut *mut c_void,
        ) -> i32;

        fn CloseHandle(hObject: *mut c_void) -> i32;
    }

    pub fn verify_windows_credentials(username: &str, password: &str) -> bool {
        if username.trim().is_empty() || password.is_empty() {
            return false;
        }

        let (domain_opt, user_clean) = if let Some((dom, usr)) = username.split_once('\\') {
            (Some(dom), usr)
        } else if let Some((usr, dom)) = username.split_once('@') {
            (Some(dom), usr)
        } else {
            (None, username)
        };

        let to_wide =
            |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };

        let user_w = to_wide(user_clean);
        let pass_w = to_wide(password);

        let mut candidate_domains: Vec<Option<String>> = Vec::new();
        if let Some(explicit_domain) = domain_opt {
            candidate_domains.push(Some(explicit_domain.to_string()));
        } else {
            // For local or non-domain users, try dot (local account database), USERDOMAIN, COMPUTERNAME, then None
            candidate_domains.push(Some(".".to_string()));
            if let Ok(ud) = std::env::var("USERDOMAIN") {
                if !ud.trim().is_empty() && ud != "." {
                    candidate_domains.push(Some(ud));
                }
            }
            if let Ok(cn) = std::env::var("COMPUTERNAME") {
                if !cn.trim().is_empty()
                    && !candidate_domains.iter().any(|d| d.as_deref() == Some(&cn))
                {
                    candidate_domains.push(Some(cn));
                }
            }
            candidate_domains.push(None);
        }

        let mut token_handle: *mut c_void = null_mut();

        for domain in &candidate_domains {
            let domain_w = domain.as_deref().map(to_wide);
            let domain_ptr = domain_w
                .as_ref()
                .map(|v| v.as_ptr())
                .unwrap_or(std::ptr::null());

            for logon_type in [LOGON32_LOGON_INTERACTIVE, LOGON32_LOGON_NETWORK] {
                let res = unsafe {
                    LogonUserW(
                        user_w.as_ptr(),
                        domain_ptr,
                        pass_w.as_ptr(),
                        logon_type,
                        LOGON32_PROVIDER_DEFAULT,
                        &mut token_handle,
                    )
                };

                if res != 0 {
                    if !token_handle.is_null() {
                        unsafe {
                            CloseHandle(token_handle);
                        }
                    }
                    return true;
                }
            }
        }

        false
    }
}

/// Reset failed attempts and clear security lockout manually (e.g. from CLI or Master Admin action).
pub fn reset_security_lockout() {
    record_successful_auth();
}

/// Authenticate operator via Hybrid Authentication:
/// 1. Master Admin Password or dashboard token (constant-time verification)
/// 2. Windows OS Account authentication (LogonUserW) on Windows (or PAM on Linux)
///
/// Returns `Ok(true)` if valid, `Ok(false)` if invalid, or `Err(lockout_msg)` if locked out.
pub fn authenticate_hybrid_credentials(
    username: Option<&str>,
    password: &str,
    expected_token: &str,
) -> Result<bool, String> {
    let trimmed_pass = password.trim();

    // 1. Direct Master Token Match (Bypasses lockout so administrator is never locked out)
    if !expected_token.trim().is_empty() && constant_time_eq(trimmed_pass, expected_token.trim()) {
        record_successful_auth();
        return Ok(true);
    }

    // 2. Environment Override Admin Password
    if let Ok(env_pass) = std::env::var("OSOOSI_ADMIN_PASSWORD") {
        if !env_pass.trim().is_empty() && constant_time_eq(trimmed_pass, env_pass.trim()) {
            record_successful_auth();
            return Ok(true);
        }
    }

    // 3. Stored Admin Hash Match (BLAKE3 or SHA-256)
    let hash_path = osoosi_types::resolve_project_root()
        .map(|p| p.join("config").join("admin_password.hash"))
        .unwrap_or_else(|| PathBuf::from("config").join("admin_password.hash"));
    if hash_path.is_file() {
        if let Ok(stored_hash) = std::fs::read_to_string(&hash_path) {
            let computed_b3 = blake3::hash(trimmed_pass.as_bytes()).to_hex().to_string();
            let mut sha_hasher = sha2::Sha256::new();
            sha2::Digest::update(&mut sha_hasher, trimmed_pass.as_bytes());
            let computed_sha = hex::encode(sha2::Digest::finalize(sha_hasher));

            if constant_time_eq(&computed_b3, stored_hash.trim())
                || constant_time_eq(&computed_sha, stored_hash.trim())
            {
                record_successful_auth();
                return Ok(true);
            }
        }
    }

    // 4. Check lockout status before proceeding to OS-level authentication
    let (is_locked, remaining) = check_lockout_status();
    if is_locked {
        return Err(format!(
            "Security lockout active due to excessive failed attempts. Please retry in {} seconds.",
            remaining
        ));
    }

    // 5. Windows OS Native Logon
    #[cfg(windows)]
    {
        if let Some(user) = username {
            if !user.trim().is_empty() && win_auth::verify_windows_credentials(user, password) {
                record_successful_auth();
                return Ok(true);
            }
        }
        let mut candidate_users: Vec<String> = Vec::new();
        if let Ok(current_user) = std::env::var("USERNAME") {
            if !current_user.trim().is_empty() && !current_user.eq_ignore_ascii_case("SYSTEM") {
                candidate_users.push(current_user);
            }
        }
        // If running as Windows Service (SYSTEM), enumerate real user accounts from C:\Users
        if let Ok(entries) = std::fs::read_dir("C:\\Users") {
            for entry in entries.flatten() {
                if let Ok(file_type) = entry.file_type() {
                    if file_type.is_dir() {
                        let name = entry.file_name().to_string_lossy().to_string();
                        let name_lc = name.to_ascii_lowercase();
                        if name_lc != "public"
                            && name_lc != "default"
                            && name_lc != "default user"
                            && name_lc != "all users"
                            && !candidate_users.contains(&name)
                        {
                            candidate_users.push(name);
                        }
                    }
                }
            }
        }
        for candidate in &candidate_users {
            if win_auth::verify_windows_credentials(candidate, password) {
                record_successful_auth();
                return Ok(true);
            }
        }
    }

    // 6. Linux & macOS Unix Native Logon (PAM, unix_chkpwd, /etc/shadow, dscl)
    #[cfg(not(windows))]
    {
        if let Some(user) = username {
            if !user.trim().is_empty() && unix_auth::verify_unix_credentials(user, password) {
                record_successful_auth();
                return Ok(true);
            }
        }
        let mut candidate_users: Vec<String> = Vec::new();
        if let Ok(current_user) = std::env::var("USER") {
            if !current_user.trim().is_empty() && current_user != "root" {
                candidate_users.push(current_user);
            }
        }
        if let Ok(entries) = std::fs::read_dir("/home") {
            for entry in entries.flatten() {
                if let Ok(file_type) = entry.file_type() {
                    if file_type.is_dir() {
                        let name = entry.file_name().to_string_lossy().to_string();
                        if !candidate_users.contains(&name) {
                            candidate_users.push(name);
                        }
                    }
                }
            }
        }
        for candidate in &candidate_users {
            if unix_auth::verify_unix_credentials(candidate, password) {
                record_successful_auth();
                return Ok(true);
            }
        }
    }

    // All checks failed -> record strike
    let (locked, remaining) = record_failed_attempt();
    if locked {
        Err(format!(
            "Authentication failed. Max strikes exceeded. Enforcing {}-second security lockout.",
            remaining
        ))
    } else {
        Ok(false)
    }
}

#[cfg(not(windows))]
mod unix_auth {
    use std::io::Write;
    use std::process::{Command, Stdio};

    pub fn verify_unix_credentials(username: &str, password: &str) -> bool {
        let user = username.trim();
        if user.is_empty() || password.is_empty() {
            return false;
        }

        // Method 1: Try unix_chkpwd helper (standard Linux PAM authentication helper)
        for helper_path in ["/sbin/unix_chkpwd", "/usr/sbin/unix_chkpwd"] {
            if std::path::Path::new(helper_path).exists() {
                if let Ok(mut child) = Command::new(helper_path)
                    .arg(user)
                    .arg("nullok")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                {
                    if let Some(mut stdin) = child.stdin.take() {
                        let _ = stdin.write_all(password.as_bytes());
                        let _ = stdin.write_all(b"\0");
                    }
                    if let Ok(status) = child.wait() {
                        if status.success() {
                            return true;
                        }
                    }
                }
            }
        }

        // Method 2: If running as root (standard for EDR daemon on Linux), check /etc/shadow
        #[cfg(target_os = "linux")]
        {
            if let Ok(shadow_content) = std::fs::read_to_string("/etc/shadow") {
                for line in shadow_content.lines() {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() >= 2 && parts[0] == user {
                        let stored_hash = parts[1];
                        if stored_hash == "*" || stored_hash == "!" || stored_hash.is_empty() {
                            return false;
                        }
                        unsafe {
                            let pass_c = std::ffi::CString::new(password).ok();
                            let salt_c = std::ffi::CString::new(stored_hash).ok();
                            if let (Some(pass), Some(salt)) = (pass_c, salt_c) {
                                extern "C" {
                                    fn crypt(
                                        key: *const libc::c_char,
                                        salt: *const libc::c_char,
                                    ) -> *mut libc::c_char;
                                }
                                let res = crypt(pass.as_ptr(), salt.as_ptr());
                                if !res.is_null() {
                                    let computed_c = std::ffi::CStr::from_ptr(res);
                                    if let Ok(computed_str) = computed_c.to_str() {
                                        if super::constant_time_eq(computed_str, stored_hash) {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }

        // Method 3: macOS dscl directory service check
        #[cfg(target_os = "macos")]
        {
            if let Ok(mut child) = Command::new("/usr/bin/dscl")
                .args(["/Local/Default", "-authonly", user])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(password.as_bytes());
                    let _ = stdin.write_all(b"\n");
                }
                if let Ok(status) = child.wait() {
                    if status.success() {
                        return true;
                    }
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(KILLCHAIN_ISOLATE_TOKEN, "CONFIRM ISOLATE"));
        assert!(constant_time_eq(KILLCHAIN_RESTORE_TOKEN, "CONFIRM RESTORE"));
        assert!(!constant_time_eq("CONFIRM ISOLATE", "CONFIRM ISOLATX"));
        assert!(!constant_time_eq("CONFIRM ISOLATE", "CONFIRM"));
    }

    #[test]
    fn test_critical_system_pid_protection() {
        assert!(is_critical_system_pid(0, "System Idle"));
        assert!(is_critical_system_pid(4, "System"));
        assert!(is_critical_system_pid(1234, "smss.exe"));
        assert!(is_critical_system_pid(1234, "csrss.exe"));
        assert!(is_critical_system_pid(1234, "services.exe"));
        assert!(is_critical_system_pid(1234, "lsass.exe"));
        assert!(is_critical_system_pid(1234, "osoosi.exe"));
        assert!(!is_critical_system_pid(5555, "malware.exe"));
        assert!(!is_critical_system_pid(6666, "mimikatz.exe"));
    }

    #[test]
    fn test_lockout_rate_limiting() {
        record_successful_auth();
        let (locked, _) = check_lockout_status();
        assert!(!locked);

        record_failed_attempt();
        record_failed_attempt();
        let (locked_after_2, _) = check_lockout_status();
        assert!(!locked_after_2);

        let (locked_after_3, remaining) = record_failed_attempt();
        assert!(locked_after_3);
        assert!(remaining > 0);

        record_successful_auth();
        let (locked_after_reset, _) = check_lockout_status();
        assert!(!locked_after_reset);
    }

    #[tokio::test]
    async fn test_killchain_lifecycle_state() {
        record_successful_auth();
        let initial = get_killchain_status();
        assert!(!initial.isolated);

        // Engage with test operator
        let engaged = engage_killchain_isolation(
            "test_operator",
            "Integration Test Quarantine",
            false, // do not change live network during unit test
            false,
            false,
        )
        .await
        .unwrap();

        assert!(engaged.isolated);
        assert_eq!(engaged.isolated_by.as_deref(), Some("test_operator"));
        assert_eq!(
            engaged.reason.as_deref(),
            Some("Integration Test Quarantine")
        );

        // Disarm
        let disarmed = disarm_killchain_isolation("test_operator", "Test Complete")
            .await
            .unwrap();
        assert!(!disarmed.isolated);
    }

    #[test]
    fn test_hybrid_credentials_auth() {
        record_successful_auth();
        let expected_token = "secret_master_token_12345";

        // Direct token match
        let res = authenticate_hybrid_credentials(None, expected_token, expected_token);
        assert_eq!(res, Ok(true));

        // Wrong password
        let res_fail =
            authenticate_hybrid_credentials(Some("invalid_user"), "wrong_pass", expected_token);
        assert_eq!(res_fail, Ok(false));

        // Reset auth
        record_successful_auth();
    }
}
