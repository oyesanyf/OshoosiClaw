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
    let base_name = lower_name.rsplit(['\\', '/']).next().unwrap_or(&lower_name);
    let stem = base_name.strip_suffix(".exe").unwrap_or(base_name);

    // 1. Direct administrative session markers on process name
    if lower_name == "sshd"
        || lower_name.starts_with("sshd:")
        || lower_name.contains("sshd:")
        || lower_name.contains("pts/")
        || lower_name == "ansible"
        || lower_name.starts_with("ansible-")
        || lower_name.starts_with("ansible_module")
    {
        return true;
    }

    // 2. Protected OS shell, desktop, search, and system init binaries
    // (Excluding generic script interpreters unless they are administrative runners)
    let is_interpreter = matches!(
        stem,
        "python"
            | "python3"
            | "node"
            | "perl"
            | "ruby"
            | "bash"
            | "sh"
            | "zsh"
            | "powershell"
            | "cmd"
    );

    if !is_interpreter
        && (osoosi_types::is_protected_os_shell_or_desktop_binary(&lower_name)
            || osoosi_types::is_protected_os_shell_or_desktop_binary(base_name)
            || osoosi_runtime::tarpit::is_protected_system_or_security_process(
                999_999,
                &lower_name,
            )
            || osoosi_runtime::tarpit::is_protected_system_or_security_process(999_999, base_name)
            || matches!(
                stem,
                "chrome"
                    | "chrome_proxy"
                    | "googleupdate"
                    | "msedge"
                    | "firefox"
                    | "brave"
                    | "explorer"
                    | "systray"
                    | "wsl"
                    | "wslhost"
                    | "wslservice"
                    | "systemd"
                    | "dbus-daemon"
                    | "tmux"
                    | "screen"
            ))
    {
        return true;
    }

    // 3. Dedicated administrative session markers across command-line arguments
    // (Only dedicated markers: sshd:, pts/, and ansible - NEVER arbitrary developer toolchain stems)
    for arg in cmd {
        let lower_arg = arg.to_lowercase();
        if lower_arg.contains("ansible")
            || lower_arg.contains("sshd:")
            || lower_arg.contains("pts/")
        {
            return true;
        }
    }

    // 4. Benign Windows Control Panel / Shell `rundll32.exe` applets (excluding LOLBin payloads)
    if stem == "rundll32" && !cmd.is_empty() {
        let joined = cmd.join(" ").to_ascii_lowercase();
        let has_lolbin_payload = joined.contains("comsvcs")
            || joined.contains("minidump")
            || joined.contains("javascript:")
            || joined.contains("vbscript:")
            || joined.contains("mshtml")
            || joined.contains("scrobj")
            || joined.contains("url.dll")
            || joined.contains("pcwutl")
            || joined.contains("dfshim")
            || joined.contains("http://")
            || joined.contains("https://")
            || joined.contains("\\\\");
        if !has_lolbin_payload {
            return true;
        }
    }

    // 5. Developer toolchain processes when invoked directly (name or cmd[0])
    // Developer toolchains (cargo, git, docker, rustc, rustup) or Windows SDK executables (python.exe, node.exe)
    // are shielded when not executing inline evaluation flags or originating from untrusted drop paths.
    let is_toolchain_proc = matches!(stem, "cargo" | "rustc" | "rustup" | "git" | "docker")
        || (base_name.ends_with(".exe") && matches!(stem, "python" | "python3" | "node"));

    if is_toolchain_proc {
        let cmd_joined = cmd.join(" ");
        if !osoosi_types::has_inline_script_evaluation_flag(&cmd_joined)
            && !osoosi_types::is_untrusted_staging_path(name)
        {
            return true;
        }
    }

    // 6. Primary executable / invocation binary check (cmd[0])
    // If argv[0] is an OS protected shell or system binary (e.g. unknown_wrapper launching systemd-logind)
    if let Some(first_arg) = cmd.first() {
        let lower_cmd0 = first_arg.to_lowercase();
        let base_cmd0 = lower_cmd0.rsplit(['\\', '/']).next().unwrap_or(&lower_cmd0);
        let stem_cmd0 = base_cmd0.strip_suffix(".exe").unwrap_or(base_cmd0);

        let is_cmd0_toolchain =
            matches!(stem_cmd0, "cargo" | "rustc" | "rustup" | "git" | "docker")
                || (base_cmd0.ends_with(".exe")
                    && matches!(stem_cmd0, "python" | "python3" | "node"));

        if is_cmd0_toolchain {
            let cmd_joined = cmd.join(" ");
            if !osoosi_types::has_inline_script_evaluation_flag(&cmd_joined)
                && !osoosi_types::is_untrusted_staging_path(first_arg)
            {
                return true;
            }
        }

        let is_cmd0_interpreter = matches!(
            stem_cmd0,
            "python"
                | "python3"
                | "node"
                | "perl"
                | "ruby"
                | "bash"
                | "sh"
                | "zsh"
                | "powershell"
                | "cmd"
        );
        if !is_cmd0_interpreter
            && (osoosi_types::is_protected_os_shell_or_desktop_binary(&lower_cmd0)
                || osoosi_types::is_protected_os_shell_or_desktop_binary(base_cmd0))
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

    /// Isolate the host from the network (except for loopback, DNS/DHCP, WebUI, Oshoosi P2P mesh, and management access).
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
            let rules: &[&[&str]] = &[
                &[
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=Oshoosi-Isolation-Loopback-In",
                    "dir=in",
                    "action=allow",
                    "remoteip=127.0.0.1,::1",
                    "profile=any",
                ],
                &[
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=Oshoosi-Isolation-Loopback-Out",
                    "dir=out",
                    "action=allow",
                    "remoteip=127.0.0.1,::1",
                    "profile=any",
                ],
                &[
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=Oshoosi-Isolation-Core-UDP",
                    "dir=out",
                    "action=allow",
                    "protocol=UDP",
                    "remoteport=53,67,68",
                    "profile=any",
                ],
                &[
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=Oshoosi-Isolation-Mesh",
                    "dir=in",
                    "action=allow",
                    "protocol=TCP",
                    "localport=4001,8080,3030,22,3389",
                    "profile=any",
                ],
                &[
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=Oshoosi-Isolation-Mesh-Out",
                    "dir=out",
                    "action=allow",
                    "protocol=TCP",
                    "localport=4001,8080,3030,22,3389",
                    "profile=any",
                ],
                &[
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=Oshoosi-Isolation-In",
                    "dir=in",
                    "action=block",
                    "profile=any",
                ],
                &[
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=Oshoosi-Isolation-Out",
                    "dir=out",
                    "action=block",
                    "profile=any",
                ],
            ];
            for rule_args in rules {
                let mut cmd = Command::new(&netsh_bin);
                cmd.stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
                #[cfg(windows)]
                cmd.creation_flags(0x08000000);
                let _ = cmd.args(*rule_args).status();
            }

            info!("Network isolation applied via Windows Firewall (netsh). Preserved loopback, DNS/DHCP (53, 67, 68), WebUI (3030), admin ports (22, 3389), and mesh ports (4001, 8080).");
            Ok(())
        }

        #[cfg(target_os = "linux")]
        {
            // Apply iptables isolation safely with explicit argument arrays, preserving loopback, DNS/DHCP, WebUI (3030), established connections, and SSH (port 22)
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
                vec!["-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
                vec![
                    "-A", "OUTPUT", "-p", "udp", "--dport", "67:68", "-j", "ACCEPT",
                ],
                vec!["-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"],
                vec!["-A", "OUTPUT", "-p", "tcp", "--sport", "22", "-j", "ACCEPT"],
                vec![
                    "-A", "INPUT", "-p", "tcp", "--dport", "3030", "-j", "ACCEPT",
                ],
                vec![
                    "-A", "OUTPUT", "-p", "tcp", "--sport", "3030", "-j", "ACCEPT",
                ],
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
        if pid <= 4 || pid == std::process::id() {
            warn!(
                "AUTONOMOUS RESPONSE: Refusing to kill protected system or self process (PID {})",
                pid
            );
            return Err(anyhow::anyhow!("Cannot kill protected process PID {}", pid));
        }

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

        use sysinfo::{Pid, ProcessRefreshKind, RefreshKind, System};
        let mut sys = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::new()),
        );
        sys.refresh_processes();

        let target_pid = Pid::from(pid as usize);

        // Pre-kill Administrative / SSH / OS Shell Session Shield check on target
        if let Some(proc) = sys.process(target_pid) {
            let exe_str = proc
                .exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            if is_administrative_or_ssh_session(proc.name(), proc.cmd())
                || (!exe_str.is_empty()
                    && (osoosi_types::is_protected_os_shell_or_desktop_binary(&exe_str)
                        || osoosi_runtime::tarpit::is_protected_system_or_security_process(
                            pid, &exe_str,
                        )
                        || crate::killchain::is_critical_system_pid(pid, &exe_str)))
            {
                warn!(
                    "AUTONOMOUS RESPONSE: Refusing to kill administrative, SSH, or protected OS session PID {} ({})",
                    pid,
                    proc.name()
                );
                return Err(anyhow::anyhow!(
                    "Cannot kill administrative or protected OS session PID {} ({})",
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
                    let exe_str = proc
                        .exe()
                        .map(|path| path.to_string_lossy().to_string())
                        .unwrap_or_default();
                    let child_pid = p.as_u32();
                    // Unconditional invariant: Never kill PID <= 4 or self PID
                    if child_pid <= 4 || child_pid == std::process::id() {
                        warn!(
                            "AUTONOMOUS RESPONSE: Process tree descendant PID {} is protected system or self process. Aborting kill tree.",
                            child_pid
                        );
                        return Err(anyhow::anyhow!(
                            "Cannot kill process tree containing critical system or self PID {}",
                            child_pid
                        ));
                    }
                    if is_administrative_or_ssh_session(proc.name(), proc.cmd())
                        || (!exe_str.is_empty()
                            && (osoosi_types::is_protected_os_shell_or_desktop_binary(&exe_str)
                                || osoosi_runtime::tarpit::is_protected_system_or_security_process(
                                    child_pid, &exe_str,
                                )
                                || crate::killchain::is_critical_system_pid(child_pid, &exe_str)))
                    {
                        warn!(
                            "AUTONOMOUS RESPONSE: Process tree descendant PID {} ({}) is an administrative / SSH / protected OS session. Aborting kill tree.",
                            p,
                            proc.name()
                        );
                        return Err(anyhow::anyhow!(
                            "Cannot kill process tree containing administrative or protected OS session PID {}",
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
                let _ = unsafe { TerminateProcess(handle, 5) };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remediation_protects_windows_linux_macos_shell_search_and_init_processes() {
        for protected in &[
            "sihost.exe",
            "explorer.exe",
            "SearchHost.exe",
            "SearchIndexer.exe",
            "SearchFilterHost.exe",
            "SearchProtocolHost.exe",
            "ShellHost.exe",
            "ShellExperienceHost.exe",
            "StartMenuExperienceHost.exe",
            "SecurityHealthSystray.exe",
            "ctfmon.exe",
            "OpenConsole.exe",
            "WindowsTerminal.exe",
            r"\Device\HarddiskVolume4\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe",
            "systemd",
            "/usr/lib/systemd/systemd-resolved",
            "/usr/libexec/tracker-miner-fs-3",
            "/usr/libexec/xdg-desktop-portal",
            "gnome-shell",
            "plasmashell",
            "kwin_wayland",
            "sshd",
            "launchd",
            "WindowServer",
            "Finder",
            "Dock",
            "SystemUIServer",
            "ControlCenter",
            "Spotlight",
            "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
        ] {
            assert!(
                is_administrative_or_ssh_session(protected, &[]),
                "Process/path must be shielded from RemediationController kill: {}",
                protected
            );
        }

        // Command-line argument shield check
        assert!(is_administrative_or_ssh_session(
            "unknown_wrapper",
            &["/usr/lib/systemd/systemd-logind".to_string()]
        ));

        // SSH/PTY interactive shells and benign Windows Control Panel rundll32 applets must be shielded
        assert!(is_administrative_or_ssh_session(
            "bash",
            &["pts/0".to_string()]
        ));
        assert!(is_administrative_or_ssh_session(
            "rundll32.exe",
            &["shell32.dll,Control_RunDLL".to_string()]
        ));

        // Non-protected arbitrary binaries, encoded PowerShell, and LOLBin rundll32 must NOT be shielded
        assert!(!is_administrative_or_ssh_session(
            "evil_payload.exe",
            &["--beacon".to_string()]
        ));
        assert!(!is_administrative_or_ssh_session(
            "powershell.exe",
            &["-enc".to_string(), "AAAA".to_string()]
        ));
        assert!(!is_administrative_or_ssh_session(
            "rundll32.exe",
            &["comsvcs.dll,MiniDump".to_string(), "652".to_string()]
        ));
    }
}
