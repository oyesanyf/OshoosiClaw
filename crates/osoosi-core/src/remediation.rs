//! Remediation Engine for Autonomous Response.
//!
//! Provides capabilities to neutralize threats: network isolation, process termination, and rollback.

use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
#[cfg(target_os = "windows")]
use tracing::debug;
use tracing::{info, warn};

static LAST_ISOLATION_TIME: parking_lot::Mutex<Option<Instant>> = parking_lot::Mutex::new(None);
static ISOLATION_COUNT: AtomicU64 = AtomicU64::new(0);

static LAST_KILL_TIME: parking_lot::Mutex<Option<Instant>> = parking_lot::Mutex::new(None);
static KILL_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn is_administrative_or_ssh_session(name: &str, cmd: &[String]) -> bool {
    let lower_name = name.to_lowercase();
    if lower_name == "sshd"
        || lower_name.starts_with("sshd:")
        || lower_name == "ansible"
        || lower_name.starts_with("ansible-")
        || lower_name.starts_with("ansible_module")
    {
        return true;
    }
    for arg in cmd {
        let lower_arg = arg.to_lowercase();
        if lower_arg.contains("ansible")
            || lower_arg.contains("sshd:")
            || lower_arg.contains("pts/")
        {
            return true;
        }
    }
    false
}

pub struct RemediationController;

impl Default for RemediationController {
    fn default() -> Self {
        Self::new()
    }
}

impl RemediationController {
    pub fn new() -> Self {
        Self
    }

    /// Isolate the host from the network (except for the Oshoosi P2P mesh and management access).
    pub fn isolate_node(&self) -> anyhow::Result<()> {
        let allow_isolation = std::env::var("OSOOSI_ALLOW_HOST_ISOLATION")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        if !allow_isolation {
            warn!("AUTONOMOUS RESPONSE: Host network isolation skipped (set OSOOSI_ALLOW_HOST_ISOLATION=1 to enable).");
            return Ok(());
        }

        let is_dry_run = std::env::var("OSOOSI_DRY_RUN")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        if is_dry_run {
            info!("AUTONOMOUS RESPONSE: [DRY-RUN] Network isolation simulated successfully.");
            return Ok(());
        }

        // Rate limiter: maximum 2 host isolations within 60 seconds
        {
            let mut last_time = LAST_ISOLATION_TIME.lock();
            let now = Instant::now();
            if let Some(prev) = *last_time {
                if now.duration_since(prev).as_secs() < 60 {
                    let count = ISOLATION_COUNT.fetch_add(1, Ordering::Relaxed);
                    if count >= 2 {
                        warn!("AUTONOMOUS RESPONSE: Host isolation rate limit exceeded (max 2 per 60s). Throttling.");
                        return Err(anyhow::anyhow!("Rate limit exceeded for host network isolation: max 2 isolations per 60s"));
                    }
                } else {
                    ISOLATION_COUNT.store(1, Ordering::Relaxed);
                    *last_time = Some(now);
                }
            } else {
                ISOLATION_COUNT.store(1, Ordering::Relaxed);
                *last_time = Some(now);
            }
        }

        info!("AUTONOMOUS RESPONSE: Initiating network isolation...");

        #[cfg(target_os = "windows")]
        {
            #[allow(unused_imports)]
            use std::os::windows::process::CommandExt;
            let netsh_bin = osoosi_types::resolve_system_binary("netsh.exe");
            // Block all inbound/outbound except common P2P mesh ports (4001, 8080) and remote admin (22, 3389)
            let mut cmd1 = Command::new(&netsh_bin);
            cmd1.stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            #[cfg(windows)]
            cmd1.creation_flags(0x08000000);
            let _ = cmd1
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=Oshoosi-Isolation-In",
                    "dir=in",
                    "action=block",
                    "profile=any",
                ])
                .status();

            let mut cmd2 = Command::new(&netsh_bin);
            cmd2.stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            #[cfg(windows)]
            cmd2.creation_flags(0x08000000);
            let _ = cmd2
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=Oshoosi-Isolation-Out",
                    "dir=out",
                    "action=block",
                    "profile=any",
                ])
                .status();

            let mut cmd3 = Command::new(&netsh_bin);
            cmd3.stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            #[cfg(windows)]
            cmd3.creation_flags(0x08000000);
            let _ = cmd3
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=Oshoosi-Isolation-Mesh",
                    "dir=in",
                    "action=allow",
                    "protocol=TCP",
                    "localport=4001,8080,22,3389",
                    "profile=any",
                ])
                .status();

            info!("Network isolation applied via Windows Firewall (netsh). Preserved admin ports (22, 3389) and mesh ports (4001, 8080).");
            Ok(())
        }

        #[cfg(target_os = "linux")]
        {
            // Apply iptables isolation safely with explicit argument arrays, preserving loopback, established connections, and SSH (port 22)
            let commands = [
                vec!["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
                vec!["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
                vec![
                    "-A",
                    "INPUT",
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "ESTABLISHED,RELATED",
                    "-j",
                    "ACCEPT",
                ],
                vec![
                    "-A",
                    "OUTPUT",
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "ESTABLISHED,RELATED",
                    "-j",
                    "ACCEPT",
                ],
                vec!["-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"],
                vec!["-A", "OUTPUT", "-p", "tcp", "--sport", "22", "-j", "ACCEPT"],
                vec![
                    "-A", "INPUT", "-p", "tcp", "--dport", "4001", "-j", "ACCEPT",
                ],
                vec![
                    "-A", "OUTPUT", "-p", "tcp", "--dport", "4001", "-j", "ACCEPT",
                ],
                vec![
                    "-A", "INPUT", "-p", "tcp", "--dport", "8080", "-j", "ACCEPT",
                ],
                vec![
                    "-A", "OUTPUT", "-p", "tcp", "--dport", "8080", "-j", "ACCEPT",
                ],
                vec!["-P", "INPUT", "DROP"],
                vec!["-P", "OUTPUT", "DROP"],
            ];

            for args in &commands {
                let status = Command::new("iptables").args(args).status();
                if let Err(e) = status {
                    warn!("Failed to execute iptables {:?}: {}", args, e);
                }
            }

            info!("Network isolation applied via iptables. Preserved loopback, established connections, SSH (22), and mesh ports (4001, 8080).");
            Ok(())
        }

        #[cfg(target_os = "macos")]
        {
            warn!("Network isolation on macOS requires MDM or manual PF configuration. Not fully autonomous yet.");
            Ok(())
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Err(anyhow::anyhow!(
                "Network isolation not supported on this platform."
            ))
        }
    }

    /// Terminate a process and all its children.
    pub fn kill_process_tree(&self, pid: u32) -> anyhow::Result<()> {
        let is_dry_run = std::env::var("OSOOSI_DRY_RUN")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let autonomy = osoosi_types::load_autonomy_config();
        let is_monitor_mode = autonomy.current_mode() == osoosi_types::AutonomyMode::Audit;

        if is_dry_run || is_monitor_mode {
            info!(
                "AUTONOMOUS RESPONSE: [MONITOR-MODE/DRY-RUN] Process tree termination simulated for PID {} (no processes killed).",
                pid
            );
            return Ok(());
        }

        // Rate limiter: maximum 5 process tree terminations within 60 seconds
        {
            let mut last_time = LAST_KILL_TIME.lock();
            let now = Instant::now();
            if let Some(prev) = *last_time {
                if now.duration_since(prev).as_secs() < 60 {
                    let count = KILL_COUNT.fetch_add(1, Ordering::Relaxed);
                    if count >= 5 {
                        warn!("AUTONOMOUS RESPONSE: Process tree termination rate limit exceeded (max 5 per 60s). Throttling.");
                        return Err(anyhow::anyhow!(
                            "Rate limit exceeded for process tree termination: max 5 kills per 60s"
                        ));
                    }
                } else {
                    KILL_COUNT.store(1, Ordering::Relaxed);
                    *last_time = Some(now);
                }
            } else {
                KILL_COUNT.store(1, Ordering::Relaxed);
                *last_time = Some(now);
            }
        }

        if pid <= 4 || pid == std::process::id() {
            warn!(
                "AUTONOMOUS RESPONSE: Refusing to kill protected system or self process (PID {})",
                pid
            );
            return Err(anyhow::anyhow!("Cannot kill protected process PID {}", pid));
        }

        use sysinfo::{Pid, ProcessRefreshKind, RefreshKind, System};
        let mut sys = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::new()),
        );
        sys.refresh_processes();

        let target_pid = Pid::from(pid as usize);

        // Pre-kill Administrative / SSH Session Shield check on target
        if let Some(proc) = sys.process(target_pid) {
            if is_administrative_or_ssh_session(proc.name(), proc.cmd()) {
                warn!(
                    "AUTONOMOUS RESPONSE: Refusing to kill administrative or SSH session PID {} ({})",
                    pid,
                    proc.name()
                );
                return Err(anyhow::anyhow!(
                    "Cannot kill administrative or SSH session PID {} ({})",
                    pid,
                    proc.name()
                ));
            }
        }

        // Collect all descendants while enforcing session shields
        let mut to_kill = vec![target_pid];
        let mut i = 0;
        while i < to_kill.len() {
            let parent_pid = to_kill[i];
            for (p, proc) in sys.processes() {
                if proc.parent() == Some(parent_pid) && !to_kill.contains(p) {
                    if is_administrative_or_ssh_session(proc.name(), proc.cmd()) {
                        warn!(
                            "AUTONOMOUS RESPONSE: Process tree descendant PID {} ({}) is an administrative / SSH session. Aborting kill tree.",
                            p,
                            proc.name()
                        );
                        return Err(anyhow::anyhow!(
                            "Cannot kill process tree containing administrative or SSH session PID {}",
                            p
                        ));
                    }
                    to_kill.push(*p);
                }
            }
            i += 1;
        }

        info!(
            "AUTONOMOUS RESPONSE: Terminating process tree for PID {} ({} processes)...",
            pid,
            to_kill.len()
        );

        #[cfg(target_os = "windows")]
        {
            use windows::Win32::Foundation::CloseHandle;
            use windows::Win32::System::Threading::{
                OpenProcess, TerminateProcess, PROCESS_TERMINATE,
            };

            if let Ok(handle) = unsafe { OpenProcess(PROCESS_TERMINATE, false, pid) } {
                let _ = unsafe { TerminateProcess(handle, 1) };
                let _ = unsafe { CloseHandle(handle) };
                debug!("Immediate Win32 TerminateProcess executed for PID {}", pid);
            }
        }

        // Kill in reverse order (children first) to ensure clean termination
        for p in to_kill.into_iter().rev() {
            if let Some(proc) = sys.process(p) {
                info!("Terminating process: {} (PID {})", proc.name(), p);
                proc.kill();
            }
        }

        Ok(())
    }

    /// Restore a file from a baseline snapshot (using PatchEngine/backup).
    pub fn rollback_file(&self, path: &str) -> anyhow::Result<()> {
        info!(
            "AUTONOMOUS RESPONSE: Attempting rollback for compromised file {}...",
            path
        );
        // This would integrate with PatchEngine's backup store.
        // For now, it logs the intent.
        warn!(
            "Snapshot rollback for {} is pending integration with PatchEngine.",
            path
        );
        Ok(())
    }
}
