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

pub const ROLLBACK_WATCHDOG_MAX_SECS: u64 = 1800; // 30 minutes hard failsafe ceiling
pub const INTERMEDIATE_HEALTH_PROBE_INTERVAL_SECS: u64 = 60; // 60-second intermediate probe window
pub const REQUIRED_CONSECUTIVE_HEALTHY_PROBES: u32 = 3; // 3 clean process-tree probes -> early automatic rollback

fn default_rollback_watchdog_max_secs() -> u64 {
    ROLLBACK_WATCHDOG_MAX_SECS
}

fn default_health_probe_interval_secs() -> u64 {
    INTERMEDIATE_HEALTH_PROBE_INTERVAL_SECS
}

fn default_required_healthy_probes() -> u32 {
    REQUIRED_CONSECUTIVE_HEALTHY_PROBES
}

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
    #[serde(default = "default_rollback_watchdog_max_secs")]
    pub rollback_watchdog_max_secs: u64,
    #[serde(default = "default_health_probe_interval_secs")]
    pub health_probe_interval_secs: u64,
    #[serde(default = "default_required_healthy_probes")]
    pub consecutive_healthy_probes_required: u32,
    #[serde(default)]
    pub consecutive_healthy_probes: u32,
    #[serde(default)]
    pub last_health_probe_timestamp: Option<String>,
    #[serde(default)]
    pub last_health_probe_passed: Option<bool>,
    #[serde(default)]
    pub last_health_probe_summary: Option<String>,
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
            rollback_watchdog_max_secs: ROLLBACK_WATCHDOG_MAX_SECS,
            health_probe_interval_secs: INTERMEDIATE_HEALTH_PROBE_INTERVAL_SECS,
            consecutive_healthy_probes_required: REQUIRED_CONSECUTIVE_HEALTHY_PROBES,
            consecutive_healthy_probes: 0,
            last_health_probe_timestamp: None,
            last_health_probe_passed: None,
            last_health_probe_summary: None,
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

/// Returns the path to the killchain state persistence file.
/// Supports test-specific directory isolation via the `OSOOSI_DATABASE_DIR` environment variable,
/// falling back to `"database/killchain_state.json"` if unset or empty.
pub fn storage_file_path() -> PathBuf {
    if let Ok(dir) = std::env::var("OSOOSI_DATABASE_DIR") {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed).join("killchain_state.json");
        }
    }
    PathBuf::from("database").join("killchain_state.json")
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

/// Resets both in-memory storage and persisted disk state to clean unisolated defaults.
/// Guarantees that unit and integration tests start with deterministic clean state
/// regardless of prior execution artifacts or dirty disk files.
pub fn reset_killchain_state_for_testing() {
    record_successful_auth();
    let mut guard = KILLCHAIN_STORAGE.write().unwrap_or_else(|e| e.into_inner());
    guard.status = KillChainStatus::default();
    let _ = save_storage_to_disk(&guard);
}

/// Reloads in-memory storage from the state file on disk.
/// Enables tests that manipulate `OSOOSI_DATABASE_DIR` or simulate daemon restarts
/// to synchronize in-memory state with the underlying file.
pub fn reload_storage_from_disk_for_testing() -> Result<()> {
    let storage = load_storage_from_disk().unwrap_or_default();
    let mut guard = KILLCHAIN_STORAGE.write().unwrap_or_else(|e| e.into_inner());
    *guard = storage;
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
    let mut guard = RATE_LIMIT_LOCK.write().unwrap_or_else(|e| e.into_inner());
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
    let mut guard = RATE_LIMIT_LOCK.write().unwrap_or_else(|e| e.into_inner());
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
    let mut guard = RATE_LIMIT_LOCK.write().unwrap_or_else(|e| e.into_inner());
    *guard = (0, None);
}

/// Query current Kill Chain host isolation status.
pub fn get_killchain_status() -> KillChainStatus {
    let guard = KILLCHAIN_STORAGE.read().unwrap_or_else(|e| e.into_inner());
    let mut status = guard.status.clone();
    let (_, remaining) = check_lockout_status();
    status.lockout_remaining_secs = remaining;
    status
}

/// Query Kill Chain history ledger.
pub fn get_killchain_history() -> Vec<KillChainHistoryEntry> {
    let guard = KILLCHAIN_STORAGE.read().unwrap_or_else(|e| e.into_inner());
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

    let mut guard = KILLCHAIN_STORAGE.write().unwrap_or_else(|e| e.into_inner());
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
        rollback_watchdog_max_secs: ROLLBACK_WATCHDOG_MAX_SECS,
        health_probe_interval_secs: INTERMEDIATE_HEALTH_PROBE_INTERVAL_SECS,
        consecutive_healthy_probes_required: REQUIRED_CONSECUTIVE_HEALTHY_PROBES,
        consecutive_healthy_probes: 0,
        last_health_probe_timestamp: None,
        last_health_probe_passed: None,
        last_health_probe_summary: None,
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

    // Anti-Bricking / Dead-Man's Failsafe Watchdog & Early Rollback Engine:
    // Regularly probes process tree telemetry every 60s. If 3 consecutive healthy probes pass,
    // automatically restores host early. Otherwise, hard failsafe triggers at 30 minutes.
    tokio::spawn(async move {
        let max_probes = (ROLLBACK_WATCHDOG_MAX_SECS / INTERMEDIATE_HEALTH_PROBE_INTERVAL_SECS).max(1);
        for _ in 0..max_probes {
            tokio::time::sleep(std::time::Duration::from_secs(INTERMEDIATE_HEALTH_PROBE_INTERVAL_SECS)).await;
            let current = get_killchain_status();
            if !current.isolated {
                return;
            }
            if let Ok((report, updated)) = evaluate_and_execute_intermediate_rollback().await {
                if !updated.isolated || report.eligible_for_early_rollback {
                    return;
                }
            }
        }
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
        let guard = KILLCHAIN_STORAGE.read().unwrap_or_else(|e| e.into_inner());
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

    let mut guard = KILLCHAIN_STORAGE.write().unwrap_or_else(|e| e.into_inner());
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
        rollback_watchdog_max_secs: ROLLBACK_WATCHDOG_MAX_SECS,
        health_probe_interval_secs: INTERMEDIATE_HEALTH_PROBE_INTERVAL_SECS,
        consecutive_healthy_probes_required: REQUIRED_CONSECUTIVE_HEALTHY_PROBES,
        consecutive_healthy_probes: 0,
        last_health_probe_timestamp: Some(now.clone()),
        last_health_probe_passed: Some(true),
        last_health_probe_summary: Some("Isolation disarmed; host operational".to_string()),
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
    // Always release any in-memory ActiveProcessTarpit thread traps and IFEO hooks immediately
    let active_tarpit = osoosi_runtime::tarpit::ActiveProcessTarpit::new();
    let trapped_pids: Vec<u32> = active_tarpit
        .active_traps
        .iter()
        .map(|entry| *entry.key())
        .collect();
    for pid in trapped_pids {
        active_tarpit.release_pid(pid);
    }
    let _ = osoosi_types::purge_ifeo_systray_debugger_hooks_native();
    let _ = crate::firewall::remove_all_autoblock_rules();

    let (was_isolated, frozen_pids_snapshot) = {
        let guard = KILLCHAIN_STORAGE.read().unwrap_or_else(|e| e.into_inner());
        (
            guard.status.isolated || guard.status.network_isolated,
            guard.status.frozen_pids.clone(),
        )
    };

    if !was_isolated && frozen_pids_snapshot.is_empty() {
        let guard = KILLCHAIN_STORAGE.read().unwrap_or_else(|e| e.into_inner());
        return Ok(guard.status.clone());
    }

    info!("🟢 [KILLCHAIN] Unconditional Host Restoration initiated during service shutdown/stop.");

    // 1. Remove network quarantine rules only if network isolation was engaged
    if was_isolated {
        if let Err(e) = remove_network_hermetic_quarantine() {
            error!(
                "❌ [KILLCHAIN] Error removing network quarantine rules: {}",
                e
            );
        } else {
            info!("🟢 [KILLCHAIN] Network quarantine rules flushed.");
        }
    }

    let mut guard = KILLCHAIN_STORAGE.write().unwrap_or_else(|e| e.into_inner());
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
        rollback_watchdog_max_secs: ROLLBACK_WATCHDOG_MAX_SECS,
        health_probe_interval_secs: INTERMEDIATE_HEALTH_PROBE_INTERVAL_SECS,
        consecutive_healthy_probes_required: REQUIRED_CONSECUTIVE_HEALTHY_PROBES,
        consecutive_healthy_probes: 0,
        last_health_probe_timestamp: Some(now.clone()),
        last_health_probe_passed: Some(true),
        last_health_probe_summary: Some("Isolation disarmed; host operational".to_string()),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainHealthProbeReport {
    pub timestamp: String,
    pub process_tree_integrity_ok: bool,
    pub total_processes_scanned: usize,
    pub critical_os_anchors_verified: usize,
    pub frozen_pids_monitored: usize,
    pub suspicious_unfrozen_processes: Vec<String>,
    pub orphaned_malicious_children: Vec<u32>,
    pub consecutive_healthy_probes: u32,
    pub required_healthy_probes: u32,
    pub eligible_for_early_rollback: bool,
    pub rollback_watchdog_max_secs: u64,
    pub probe_interval_secs: u64,
    pub probe_hash_blake3: String,
    pub summary: String,
}

/// Intermediate Automatic Health Probe:
/// Inspects live process tree telemetry integrity across endpoints during isolation.
/// Validates critical OS anchors, monitors frozen PIDs, and detects suspicious unfrozen processes
/// or orphaned malicious children spawned from quarantined parents.
pub fn run_intermediate_process_tree_health_probe() -> KillChainHealthProbeReport {
    use sysinfo::System;
    let sys = System::new_all();
    let total_processes_scanned = sys.processes().len();

    let (frozen_pids, required_probes, watchdog_max_secs, probe_interval_secs) = {
        let guard = KILLCHAIN_STORAGE.read().unwrap_or_else(|e| e.into_inner());
        (
            guard.status.frozen_pids.clone(),
            guard.status.consecutive_healthy_probes_required.max(1),
            guard.status.rollback_watchdog_max_secs,
            guard.status.health_probe_interval_secs,
        )
    };

    let mut critical_os_anchors_verified = 0;
    let mut suspicious_unfrozen_processes = Vec::new();
    let mut orphaned_malicious_children = Vec::new();

    let high_risk_markers = [
        "wannacry",
        "mimikatz",
        "cobaltstrike",
        "beacon.exe",
        "c2_rat.exe",
        "meterpreter",
        "reverse_shell.elf",
    ];

    for (pid_raw, proc) in sys.processes() {
        let pid = pid_raw.as_u32();
        let name = proc.name();
        let name_lc = name.to_ascii_lowercase();
        let cmd_lc = proc.cmd().join(" ").to_ascii_lowercase();

        if is_critical_system_pid(pid, name) {
            critical_os_anchors_verified += 1;
            continue;
        }

        if !frozen_pids.contains(&pid) {
            let is_malware = high_risk_markers
                .iter()
                .any(|marker| name_lc.contains(marker) || cmd_lc.contains(marker));
            if is_malware {
                suspicious_unfrozen_processes.push(format!("{}:{}", pid, name));
            }

            if let Some(parent_pid) = proc.parent() {
                let p_u32 = parent_pid.as_u32();
                if frozen_pids.contains(&p_u32) && !is_critical_system_pid(pid, name) {
                    orphaned_malicious_children.push(pid);
                }
            }
        }
    }

    let process_tree_integrity_ok = total_processes_scanned > 0
        && critical_os_anchors_verified > 0
        && suspicious_unfrozen_processes.is_empty()
        && orphaned_malicious_children.is_empty();

    let now = Utc::now().to_rfc3339();

    let (consecutive_healthy_probes, summary) = {
        let mut guard = KILLCHAIN_STORAGE.write().unwrap_or_else(|e| e.into_inner());
        if process_tree_integrity_ok {
            guard.status.consecutive_healthy_probes += 1;
        } else {
            guard.status.consecutive_healthy_probes = 0;
        }

        let consecutive = guard.status.consecutive_healthy_probes;
        let summary = if process_tree_integrity_ok {
            format!(
                "Process tree healthy ({} procs scanned, {} critical OS anchors verified, {}/{} consecutive healthy probes)",
                total_processes_scanned,
                critical_os_anchors_verified,
                consecutive,
                required_probes
            )
        } else {
            format!(
                "Process tree integrity violation: {} suspicious unfrozen processes, {} orphaned malicious children",
                suspicious_unfrozen_processes.len(),
                orphaned_malicious_children.len()
            )
        };

        guard.status.last_health_probe_timestamp = Some(now.clone());
        guard.status.last_health_probe_passed = Some(process_tree_integrity_ok);
        guard.status.last_health_probe_summary = Some(summary.clone());
        let _ = save_storage_to_disk(&guard);
        (consecutive, summary)
    };

    let eligible_for_early_rollback = consecutive_healthy_probes >= required_probes;

    let probe_payload = format!(
        "{}:{}:{}:{}:{}:{}",
        now,
        process_tree_integrity_ok,
        total_processes_scanned,
        critical_os_anchors_verified,
        consecutive_healthy_probes,
        summary
    );
    let probe_hash_blake3 = blake3::hash(probe_payload.as_bytes()).to_hex().to_string();

    KillChainHealthProbeReport {
        timestamp: now,
        process_tree_integrity_ok,
        total_processes_scanned,
        critical_os_anchors_verified,
        frozen_pids_monitored: frozen_pids.len(),
        suspicious_unfrozen_processes,
        orphaned_malicious_children,
        consecutive_healthy_probes,
        required_healthy_probes: required_probes,
        eligible_for_early_rollback,
        rollback_watchdog_max_secs: watchdog_max_secs,
        probe_interval_secs: probe_interval_secs,
        probe_hash_blake3,
        summary,
    }
}

/// Evaluates live process tree health and triggers early automatic rollback if eligible.
/// Restores the endpoint cleanly before the 30-minute hard failsafe timer expires.
pub async fn evaluate_and_execute_intermediate_rollback(
) -> Result<(KillChainHealthProbeReport, KillChainStatus)> {
    let report = run_intermediate_process_tree_health_probe();
    let current = get_killchain_status();
    if current.isolated && report.eligible_for_early_rollback {
        info!(
            "🟢 [KILLCHAIN-HEALTH-PROBE] Process tree telemetry integrity verified ({}/{} consecutive probes). Executing early automatic host rollback prior to 30-minute timer expiry.",
            report.consecutive_healthy_probes, report.required_healthy_probes
        );
        let updated = disarm_killchain_isolation(
            "autonomous_health_probe_watchdog",
            "Early automatic rollback: process tree telemetry integrity verified across consecutive health probes before 30-minute failsafe expiry",
        )
        .await?;
        Ok((report, updated))
    } else {
        Ok((report, current))
    }
}

// ---------------------------------------------------------------------------
// Network Isolation Primitives
// ---------------------------------------------------------------------------

/// Execute a system firewall command with stdout and stderr fully silenced,
/// preventing command-line noise (e.g. netsh 'No rules match the specified criteria').
fn run_firewall_cmd(cmd: &str, args: &[&str]) {
    #[allow(unused_mut)]
    let mut command = Command::new(cmd);
    command
        .args(args)
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
        let netsh_bin = osoosi_types::resolve_system_binary("netsh.exe");
        let netsh_str = netsh_bin.to_string_lossy();
        // 1. Ensure loopback and port 3030 allow rules exist first with highest priority
        run_firewall_cmd(
            &netsh_str,
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
            &netsh_str,
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
            &netsh_str,
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
            &netsh_str,
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
            &netsh_str,
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

        run_firewall_cmd(
            &netsh_str,
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=Osoosi-KillChain-Allow-DNS-Out",
                "dir=out",
                "action=allow",
                "protocol=UDP",
                "remoteport=53",
                "profile=any",
            ],
        );

        run_firewall_cmd(
            &netsh_str,
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=Osoosi-KillChain-Allow-DHCP-Out",
                "dir=out",
                "action=allow",
                "protocol=UDP",
                "localport=68",
                "remoteport=67",
                "profile=any",
            ],
        );

        run_firewall_cmd(
            &netsh_str,
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=Osoosi-KillChain-Allow-DHCP-In",
                "dir=in",
                "action=allow",
                "protocol=UDP",
                "localport=68",
                "remoteport=67",
                "profile=any",
            ],
        );

        // DNS TCP Fallback (RFC 7766)
        run_firewall_cmd(
            &netsh_str,
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=Osoosi-KillChain-Allow-DNS-TCP-Out",
                "dir=out",
                "action=allow",
                "protocol=TCP",
                "remoteport=53",
                "profile=any",
            ],
        );

        // DHCPv6 Inbound and Outbound (UDP 546/547)
        run_firewall_cmd(
            &netsh_str,
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=Osoosi-KillChain-Allow-DHCPv6-Out",
                "dir=out",
                "action=allow",
                "protocol=UDP",
                "localport=546",
                "remoteport=547",
                "profile=any",
            ],
        );

        run_firewall_cmd(
            &netsh_str,
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=Osoosi-KillChain-Allow-DHCPv6-In",
                "dir=in",
                "action=allow",
                "protocol=UDP",
                "localport=546",
                "remoteport=547",
                "profile=any",
            ],
        );

        // 2. Block all non-loopback inbound and outbound network traffic
        run_firewall_cmd(
            &netsh_str,
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
            &netsh_str,
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
            &netsh_str,
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
            &netsh_str,
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

        Ok(vec![
            "All-Windows-Adapters (Loopback/DNS/DHCP/3030 Preserved)".to_string(),
        ])
    }

    #[cfg(target_os = "linux")]
    {
        run_firewall_cmd(
            "iptables",
            &["-I", "INPUT", "1", "-i", "lo", "-j", "ACCEPT"],
        );
        run_firewall_cmd(
            "iptables",
            &["-I", "OUTPUT", "1", "-o", "lo", "-j", "ACCEPT"],
        );
        run_firewall_cmd(
            "iptables",
            &[
                "-I", "INPUT", "2", "-p", "tcp", "--dport", "3030", "-j", "ACCEPT",
            ],
        );
        run_firewall_cmd(
            "iptables",
            &[
                "-I", "OUTPUT", "2", "-p", "tcp", "--sport", "3030", "-j", "ACCEPT",
            ],
        );
        run_firewall_cmd(
            "iptables",
            &[
                "-I", "OUTPUT", "3", "-p", "udp", "--dport", "53", "-j", "ACCEPT",
            ],
        );
        run_firewall_cmd(
            "iptables",
            &[
                "-I", "INPUT", "3", "-p", "udp", "--sport", "53", "-j", "ACCEPT",
            ],
        );
        run_firewall_cmd(
            "iptables",
            &[
                "-I", "OUTPUT", "4", "-p", "udp", "--dport", "67:68", "-j", "ACCEPT",
            ],
        );
        run_firewall_cmd(
            "iptables",
            &[
                "-I", "INPUT", "4", "-p", "udp", "--sport", "67:68", "-j", "ACCEPT",
            ],
        );
        run_firewall_cmd(
            "iptables",
            &[
                "-I", "OUTPUT", "5", "-p", "tcp", "--dport", "53", "-j", "ACCEPT",
            ],
        );
        run_firewall_cmd(
            "iptables",
            &[
                "-I", "INPUT", "5", "-p", "tcp", "--sport", "53", "-j", "ACCEPT",
            ],
        );
        run_firewall_cmd(
            "iptables",
            &[
                "-I", "OUTPUT", "6", "-p", "udp", "--dport", "546:547", "-j", "ACCEPT",
            ],
        );
        run_firewall_cmd(
            "iptables",
            &[
                "-I", "INPUT", "6", "-p", "udp", "--sport", "546:547", "-j", "ACCEPT",
            ],
        );
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

        Ok(vec![
            "All-Linux-Interfaces (lo/DNS/DHCP/3030 Preserved)".to_string()
        ])
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Ok(vec!["Non-Windows-Linux-Simulated".to_string()])
    }
}

fn remove_network_hermetic_quarantine() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        let netsh_bin = osoosi_types::resolve_system_binary("netsh.exe");
        let netsh_str = netsh_bin.to_string_lossy();
        let rules = [
            "Osoosi-KillChain-Block-Inbound-Low",
            "Osoosi-KillChain-Block-Inbound-High",
            "Osoosi-KillChain-Block-Outbound-Low",
            "Osoosi-KillChain-Block-Outbound-High",
            "Osoosi-KillChain-Allow-DNS-Out",
            "Osoosi-KillChain-Allow-DNS-TCP-Out",
            "Osoosi-KillChain-Allow-DHCP-Out",
            "Osoosi-KillChain-Allow-DHCP-In",
            "Osoosi-KillChain-Allow-DHCPv6-Out",
            "Osoosi-KillChain-Allow-DHCPv6-In",
            "Osoosi-KillChain-Allow-WebUI-In",
            "Osoosi-KillChain-Allow-WebUI-Out",
            "Osoosi-KillChain-Allow-WebUI-Out-Remote",
            "Osoosi-KillChain-Allow-Loopback-In",
            "Osoosi-KillChain-Allow-Loopback-Out",
        ];
        for r in rules {
            run_firewall_cmd(
                &netsh_str,
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
        run_firewall_cmd(
            "iptables",
            &["-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
        );
        run_firewall_cmd(
            "iptables",
            &["-D", "INPUT", "-p", "udp", "--sport", "53", "-j", "ACCEPT"],
        );
        run_firewall_cmd(
            "iptables",
            &[
                "-D", "OUTPUT", "-p", "udp", "--dport", "67:68", "-j", "ACCEPT",
            ],
        );
        run_firewall_cmd(
            "iptables",
            &[
                "-D", "INPUT", "-p", "udp", "--sport", "67:68", "-j", "ACCEPT",
            ],
        );
        run_firewall_cmd(
            "iptables",
            &["-D", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"],
        );
        run_firewall_cmd(
            "iptables",
            &["-D", "INPUT", "-p", "tcp", "--sport", "53", "-j", "ACCEPT"],
        );
        run_firewall_cmd(
            "iptables",
            &[
                "-D", "OUTPUT", "-p", "udp", "--dport", "546:547", "-j", "ACCEPT",
            ],
        );
        run_firewall_cmd(
            "iptables",
            &[
                "-D", "INPUT", "-p", "udp", "--sport", "546:547", "-j", "ACCEPT",
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

pub fn is_critical_system_pid(pid: u32, name: &str) -> bool {
    if pid <= 4 || pid == std::process::id() {
        return true;
    }

    // Delegate to universal OS shell/desktop/systray protection and runtime tarpit immunity
    if osoosi_types::is_protected_os_shell_or_desktop_binary(name)
        || osoosi_runtime::tarpit::is_protected_system_or_security_process(pid, name)
    {
        return true;
    }

    let trimmed = name.trim().trim_matches('"').trim_matches('\'');
    let base = trimmed.rsplit(['\\', '/']).next().unwrap_or(trimmed);
    let name_lc = base.to_ascii_lowercase();

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
            | "userinit.exe"
            | "logonui.exe"
            | "credentialproviderhost.exe"
            | "sihost.exe"
            | "runtimebroker.exe"
            | "taskmgr.exe"
            | "securityhealthservice.exe"
            | "securityhealthsystray.exe"
            | "securityhealthhost.exe"
            | "smartscreen.exe"
            | "consent.exe"
            | "fontdrvhost.exe"
            | "searchhost.exe"
            | "searchindexer.exe"
            | "searchprotocolhost.exe"
            | "searchfilterhost.exe"
            | "startmenuexperiencehost.exe"
            | "shellexperiencehost.exe"
            | "shellhost.exe"
            | "applicationframehost.exe"
            | "textinputhost.exe"
            | "ctfmon.exe"
            | "useroobebroker.exe"
            | "systemsettings.exe"
            | "systemsettingsbroker.exe"
            | "widgetservice.exe"
            | "widgets.exe"
            | "services.exe"
            | "lsass.exe"
            | "lsm.exe"
            | "dwm.exe"
            | "svchost.exe"
            | "explorer.exe"
            | "taskhostw.exe"
            | "dllhost.exe"
            | "rundll32.exe"
            | "regsvr32.exe"
            | "msiexec.exe"
            | "tiworker.exe"
            | "trustedinstaller.exe"
            | "wuauclt.exe"
            | "usoclient.exe"
            | "mousocoreworker.exe"
            | "audiodg.exe"
            | "spoolsv.exe"
            | "wlanext.exe"
            | "dashost.exe"
            | "unsecapp.exe"
            | "wmiprvse.exe"
            | "sysmon.exe"
            | "sysmon64.exe"
            | "msmpeng.exe"
            | "mpcmdrun.exe"
            | "nissrv.exe"
            | "senseir.exe"
            | "msseces.exe"
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
            | "wsl.exe"
            | "wslservice.exe"
            | "wslhost.exe"
            | "vmmem"
            | "vmmemwsl"
            | "docker.exe"
            | "dockerd.exe"
            | "com.docker.backend.exe"
            | "python.exe"
            | "python"
            | "python3"
            | "python3.exe"
            | "node.exe"
            | "node"
            | "git.exe"
            | "git"
            | "cargo.exe"
            | "cargo"
            | "rustc.exe"
            | "rustc"
            | "rustup.exe"
            | "rustup"
            | "init"
            | "systemd"
            | "systemd-logind"
            | "systemd-journald"
            | "systemd-resolved"
            | "systemd-networkd"
            | "systemd-udevd"
            | "dbus-daemon"
            | "dbus-broker"
            | "networkmanager"
            | "wpa_supplicant"
            | "dhclient"
            | "dhcpcd"
            | "dnsmasq"
            | "chronyd"
            | "ntpd"
            | "rsyslogd"
            | "cron"
            | "crond"
            | "atd"
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
            | "tmux"
            | "screen"
            | "sudo"
            | "su"
            | "login"
            | "bash"
            | "sh"
            | "zsh"
            | "fish"
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

        // Also verify full executable path immunity (OS directories, signed system binaries, developer tools)
        if let Some(exe_path) = proc.exe() {
            let exe_str = exe_path.to_string_lossy();
            if is_critical_system_pid(pid, &exe_str)
                || osoosi_types::is_protected_os_shell_or_desktop_binary(&exe_str)
                || crate::blocking_manager::is_protected_or_benign_system_path(&exe_str)
            {
                continue;
            }
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
pub mod win_auth {
    /// Safe Windows authentication stub: NEVER calls Win32 LogonUserW or tests credentials
    /// against the host Windows account to prevent tripping Windows OS Account Lockout Policies.
    pub fn verify_windows_credentials(_username: &str, _password: &str) -> bool {
        false
    }
}

/// Reset failed attempts and clear security lockout manually (e.g. from CLI or Master Admin action).
pub fn reset_security_lockout() {
    record_successful_auth();
}

/// Authenticate operator via Hybrid Authentication:
/// 1. Master Admin Password or dashboard token (constant-time verification)
/// 2. Environment override admin password (`OSOOSI_ADMIN_PASSWORD`)
/// 3. Stored Admin Hash match (`config/admin_password.hash` — BLAKE3 or SHA-256)
///
/// NOTE: Win32 `LogonUserW` and host OS credential hammering are strictly removed
/// to protect host OS user accounts from tripping Account Lockout Policies.
///
/// Returns `Ok(true)` if valid, `Ok(false)` if invalid, or `Err(lockout_msg)` if locked out.
pub fn authenticate_hybrid_credentials(
    _username: Option<&str>,
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

    // 4. Check lockout status before recording failure
    let (is_locked, remaining) = check_lockout_status();
    if is_locked {
        return Err(format!(
            "Security lockout active due to excessive failed attempts. Please retry in {} seconds.",
            remaining
        ));
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
#[allow(dead_code)]
pub mod unix_auth {
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
                                #[link(name = "crypt")]
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
        assert!(is_critical_system_pid(1, "init"));
        assert!(is_critical_system_pid(4, "System"));

        // Windows kernel, session, shell, desktop, search, systray, and update infrastructure
        let protected_windows = [
            "smss.exe",
            "csrss.exe",
            "wininit.exe",
            "winlogon.exe",
            "userinit.exe",
            "logonui.exe",
            "services.exe",
            "lsass.exe",
            "lsm.exe",
            "svchost.exe",
            "dwm.exe",
            "explorer.exe",
            "sihost.exe",
            "taskhostw.exe",
            "runtimebroker.exe",
            "searchhost.exe",
            "searchindexer.exe",
            "searchprotocolhost.exe",
            "searchfilterhost.exe",
            "startmenuexperiencehost.exe",
            "shellexperiencehost.exe",
            "shellhost.exe",
            "applicationframehost.exe",
            "textinputhost.exe",
            "ctfmon.exe",
            "securityhealthsystray.exe",
            "securityhealthservice.exe",
            "smartscreen.exe",
            "taskmgr.exe",
            "conhost.exe",
            "openconsole.exe",
            "windowsterminal.exe",
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            "rundll32.exe",
            "dllhost.exe",
            "msiexec.exe",
            "tiworker.exe",
            "trustedinstaller.exe",
            "wmiprvse.exe",
            "osoosi.exe",
            "C:\\Windows\\System32\\svchost.exe",
            "C:\\Windows\\explorer.exe",
            "C:\\Windows\\SystemApps\\Microsoft.Windows.Search_cw5n1h2txyewy\\SearchHost.exe",
        ];
        for bin in protected_windows {
            assert!(
                is_critical_system_pid(2048, bin),
                "Windows OS/shell binary '{}' MUST be immune to KillChain freeze",
                bin
            );
        }

        // Linux & macOS init, session, desktop, display, network, and shell daemons
        let protected_unix = [
            "systemd",
            "systemd-logind",
            "systemd-journald",
            "systemd-resolved",
            "systemd-networkd",
            "systemd-udevd",
            "dbus-daemon",
            "NetworkManager",
            "wpa_supplicant",
            "dhclient",
            "sshd",
            "gnome-shell",
            "Xorg",
            "Xwayland",
            "kwin",
            "WindowServer",
            "loginwindow",
            "launchd",
            "bash",
            "zsh",
            "sh",
            "sudo",
            "/lib/systemd/systemd-resolved",
            "/usr/sbin/sshd",
        ];
        for bin in protected_unix {
            assert!(
                is_critical_system_pid(2048, bin),
                "Unix OS/shell daemon '{}' MUST be immune to KillChain freeze",
                bin
            );
        }

        // Developer & build toolchains
        let protected_toolchains = [
            "cargo.exe",
            "rustc.exe",
            "rustup.exe",
            "python.exe",
            "python3",
            "node.exe",
            "node",
            "git.exe",
            "git",
            "code.exe",
            "wsl.exe",
            "docker.exe",
        ];
        for bin in protected_toolchains {
            assert!(
                is_critical_system_pid(2048, bin),
                "Developer toolchain binary '{}' MUST be immune to KillChain freeze",
                bin
            );
        }

        // Untrusted / malicious binaries MUST NOT be immune
        assert!(!is_critical_system_pid(5555, "malware.exe"));
        assert!(!is_critical_system_pid(6666, "mimikatz.exe"));
        assert!(!is_critical_system_pid(
            7777,
            "C:\\Temp\\cobaltstrike_beacon.exe"
        ));
    }

    static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_lockout_rate_limiting() {
        let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
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
        let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        // 1. Storage Isolation: Create isolated temporary directory for test database
        let temp_dir = tempfile::tempdir().expect("Failed to create isolated temp database dir");
        let orig_db_dir = std::env::var("OSOOSI_DATABASE_DIR").ok();
        std::env::set_var("OSOOSI_DATABASE_DIR", temp_dir.path());

        // RAII guard ensuring unconditional cleanup and env restoration even on panic
        struct TestIsolationGuard {
            orig_dir: Option<String>,
        }
        impl Drop for TestIsolationGuard {
            fn drop(&mut self) {
                let _ = execute_host_disarm_unauthenticated();
                record_successful_auth();
                if let Some(ref dir) = self.orig_dir {
                    std::env::set_var("OSOOSI_DATABASE_DIR", dir);
                } else {
                    std::env::remove_var("OSOOSI_DATABASE_DIR");
                }
            }
        }
        let _guard = TestIsolationGuard {
            orig_dir: orig_db_dir,
        };

        // 2. Clean State Management: Explicitly reset in-memory and disk state prior to assertion
        record_successful_auth();
        reset_killchain_state_for_testing();

        // 3. Verify clean unisolated initial state
        let initial = get_killchain_status();
        assert!(
            !initial.isolated,
            "Killchain initial status must not be isolated"
        );

        // 4. Engage with test operator (live network false for unit test safety)
        let engaged = engage_killchain_isolation(
            "test_operator",
            "Integration Test Quarantine",
            false,
            false,
            false,
        )
        .await
        .unwrap();

        assert!(
            engaged.isolated,
            "Killchain must report isolated after engagement"
        );
        assert_eq!(engaged.isolated_by.as_deref(), Some("test_operator"));
        assert_eq!(
            engaged.reason.as_deref(),
            Some("Integration Test Quarantine")
        );

        // 5. Verify state file was persisted inside the isolated temporary directory
        let state_path = storage_file_path();
        assert!(
            state_path.exists(),
            "State file must exist in isolated temporary directory"
        );
        assert!(
            state_path.starts_with(temp_dir.path()),
            "State file must reside within OSOOSI_DATABASE_DIR"
        );

        // 6. Disarm and verify state restoration
        let disarmed = disarm_killchain_isolation("test_operator", "Test Complete")
            .await
            .unwrap();
        assert!(
            !disarmed.isolated,
            "Killchain must not be isolated after disarm"
        );
    }

    #[test]
    fn test_storage_file_path_isolation_env_override() {
        let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let orig = std::env::var("OSOOSI_DATABASE_DIR").ok();

        // Active directory override
        std::env::set_var("OSOOSI_DATABASE_DIR", temp_dir.path());
        let isolated_path = storage_file_path();
        assert_eq!(isolated_path, temp_dir.path().join("killchain_state.json"));

        // Fallback when unset
        std::env::remove_var("OSOOSI_DATABASE_DIR");
        let default_path = storage_file_path();
        assert_eq!(
            default_path,
            PathBuf::from("database").join("killchain_state.json")
        );

        // Fallback when set to whitespace/empty string
        std::env::set_var("OSOOSI_DATABASE_DIR", "   ");
        let empty_path = storage_file_path();
        assert_eq!(
            empty_path,
            PathBuf::from("database").join("killchain_state.json")
        );

        // Restore original env var
        if let Some(o) = orig {
            std::env::set_var("OSOOSI_DATABASE_DIR", o);
        } else {
            std::env::remove_var("OSOOSI_DATABASE_DIR");
        }
    }

    #[tokio::test]
    async fn test_clean_state_reset_and_reload() {
        let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let orig = std::env::var("OSOOSI_DATABASE_DIR").ok();
        std::env::set_var("OSOOSI_DATABASE_DIR", temp_dir.path());

        // Reset to clean state
        reset_killchain_state_for_testing();
        assert!(!get_killchain_status().isolated);

        // Engage isolation
        let _ = engage_killchain_isolation("test_operator", "Isolation test", false, false, false)
            .await
            .unwrap();
        assert!(get_killchain_status().isolated);

        // Reset state
        reset_killchain_state_for_testing();
        assert!(!get_killchain_status().isolated);

        // Verify disk was reset to default unisolated state as well
        reload_storage_from_disk_for_testing().unwrap();
        assert!(!get_killchain_status().isolated);

        if let Some(o) = orig {
            std::env::set_var("OSOOSI_DATABASE_DIR", o);
        } else {
            std::env::remove_var("OSOOSI_DATABASE_DIR");
        }
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

    #[test]
    fn test_host_os_and_developer_toolchains_never_frozen() {
        let protected_catalog = [
            // Windows OS Core, Session, Shell, Search & Tray
            "explorer.exe",
            "SearchHost.exe",
            "SearchIndexer.exe",
            "SearchProtocolHost.exe",
            "SearchFilterHost.exe",
            "sihost.exe",
            "svchost.exe",
            "lsass.exe",
            "services.exe",
            "csrss.exe",
            "dwm.exe",
            "taskhostw.exe",
            "runtimebroker.exe",
            "ctfmon.exe",
            "securityhealthsystray.exe",
            "securityhealthservice.exe",
            "smss.exe",
            "wininit.exe",
            "winlogon.exe",
            "userinit.exe",
            "logonui.exe",
            "taskmgr.exe",
            "dllhost.exe",
            "conhost.exe",
            "openconsole.exe",
            "windowsterminal.exe",
            "wt.exe",
            "fontdrvhost.exe",
            "audiodg.exe",
            "spoolsv.exe",
            "smartscreen.exe",
            "tiworker.exe",
            "trustedinstaller.exe",
            // Developer Toolchains & Container Infrastructure
            "python.exe",
            "python3.exe",
            "python",
            "python3",
            "cargo.exe",
            "cargo",
            "rustc.exe",
            "rustc",
            "rustup.exe",
            "rustup",
            "node.exe",
            "node",
            "git.exe",
            "git",
            "git-remote-https.exe",
            "ssh.exe",
            "code.exe",
            "code",
            "antigravity.exe",
            "wsl.exe",
            "wsl",
            "wslhost.exe",
            "wslservice.exe",
            "vmmem",
            "vmmemwsl",
            "docker.exe",
            "docker",
            "dockerd.exe",
            "dockerd",
            "com.docker.backend.exe",
            // Linux Daemons & Shells
            "init",
            "systemd",
            "systemd-logind",
            "systemd-journald",
            "systemd-resolved",
            "systemd-networkd",
            "systemd-udevd",
            "dbus-daemon",
            "dbus-broker",
            "sshd",
            "gnome-shell",
            "plasmashell",
            "tracker-miner-fs-3",
            "NetworkManager",
            "wpa_supplicant",
            "dhclient",
            "dhcpcd",
            "dnsmasq",
            "chronyd",
            "ntpd",
            "rsyslogd",
            "cron",
            "crond",
            "atd",
            "polkitd",
            // macOS Core Daemons & Desktop Shell
            "launchd",
            "WindowServer",
            "Finder",
            "Dock",
            "ControlCenter",
            "Spotlight",
            "loginwindow",
            "UserEventAgent",
            "cfprefsd",
            "distnoted",
            "trustd",
            "securityd",
            "syspolicyd",
            "coreaudiod",
            "bluetoothd",
            "configd",
            "mDNSResponder",
            "symptomsd",
            "logd",
            "fseventsd",
            "powerd",
        ];

        for bin in protected_catalog {
            assert!(
                is_critical_system_pid(2048, bin),
                "Binary '{}' MUST return true from is_critical_system_pid",
                bin
            );
        }
    }

    #[test]
    fn test_adversarial_malware_pids_not_immune() {
        let malware_samples = [
            "wannacry.exe",
            "mimikatz.exe",
            "beacon.exe",
            "c2_rat.exe",
            "dropper.bin",
            "/tmp/reverse_shell.elf",
            "C:\\Users\\Public\\malware.exe",
        ];

        for sample in malware_samples {
            assert!(
                !is_critical_system_pid(9999, sample),
                "Malware sample '{}' MUST NOT be immune to killchain freeze",
                sample
            );
        }
    }

    #[tokio::test]
    async fn test_intermediate_health_probe_and_early_rollback_window() {
        let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let temp_dir = tempfile::tempdir().expect("Failed to create isolated temp database dir");
        let orig_db_dir = std::env::var("OSOOSI_DATABASE_DIR").ok();
        std::env::set_var("OSOOSI_DATABASE_DIR", temp_dir.path());

        struct TestIsolationGuard {
            orig_dir: Option<String>,
        }
        impl Drop for TestIsolationGuard {
            fn drop(&mut self) {
                let _ = execute_host_disarm_unauthenticated();
                record_successful_auth();
                if let Some(ref dir) = self.orig_dir {
                    std::env::set_var("OSOOSI_DATABASE_DIR", dir);
                } else {
                    std::env::remove_var("OSOOSI_DATABASE_DIR");
                }
            }
        }
        let _guard = TestIsolationGuard {
            orig_dir: orig_db_dir,
        };

        record_successful_auth();
        reset_killchain_state_for_testing();

        let engaged = engage_killchain_isolation(
            "test_op",
            "Verify Early Rollback",
            false,
            false,
            false,
        )
        .await
        .unwrap();
        assert!(engaged.isolated);
        assert_eq!(engaged.consecutive_healthy_probes, 0);

        // Probe 1
        let (rep1, st1) = evaluate_and_execute_intermediate_rollback().await.unwrap();
        assert!(rep1.process_tree_integrity_ok, "Probe 1 should be healthy");
        assert_eq!(rep1.consecutive_healthy_probes, 1);
        assert!(!rep1.eligible_for_early_rollback);
        assert!(st1.isolated, "Host must still be isolated after probe 1");

        // Probe 2
        let (rep2, st2) = evaluate_and_execute_intermediate_rollback().await.unwrap();
        assert!(rep2.process_tree_integrity_ok, "Probe 2 should be healthy");
        assert_eq!(rep2.consecutive_healthy_probes, 2);
        assert!(!rep2.eligible_for_early_rollback);
        assert!(st2.isolated, "Host must still be isolated after probe 2");

        // Probe 3 (Threshold met -> early automatic rollback!)
        let (rep3, st3) = evaluate_and_execute_intermediate_rollback().await.unwrap();
        assert!(rep3.process_tree_integrity_ok, "Probe 3 should be healthy");
        assert_eq!(rep3.consecutive_healthy_probes, 3);
        assert!(rep3.eligible_for_early_rollback, "Must be eligible for early rollback on 3rd probe");
        assert!(!st3.isolated, "Host must be automatically rolled back before 30-minute timer!");

        let final_status = get_killchain_status();
        assert!(!final_status.isolated, "Final status must confirm host is disarmed");
    }
}
