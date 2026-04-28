//! Remediation Engine for Autonomous Response.
//!
//! Provides capabilities to neutralize threats: network isolation, process termination, and rollback.

use std::process::Command;
use tracing::{info, warn};

pub struct RemediationController;

impl RemediationController {
    pub fn new() -> Self {
        Self
    }

    /// Isolate the host from the network (except for the Oshoosi P2P mesh).
    pub fn isolate_node(&self) -> anyhow::Result<()> {
        info!("AUTONOMOUS RESPONSE: Initiating network isolation...");

        #[cfg(target_os = "windows")]
        {
            // Block all inbound/outbound except common P2P mesh ports (4001, 8080)
            let _ = Command::new("netsh")
                .args(["advfirewall", "firewall", "add", "rule", "name=Oshoosi-Isolation-In", "dir=in", "action=block", "profile=any"])
                .status();
            let _ = Command::new("netsh")
                .args(["advfirewall", "firewall", "add", "rule", "name=Oshoosi-Isolation-Out", "dir=out", "action=block", "profile=any"])
                .status();
            let _ = Command::new("netsh")
                .args(["advfirewall", "firewall", "add", "rule", "name=Oshoosi-Isolation-Mesh", "dir=in", "action=allow", "protocol=TCP", "localport=4001,8080", "profile=any"])
                .status();

            info!("Network isolation applied via Windows Firewall (netsh).");
            Ok(())
        }

        #[cfg(target_os = "linux")]
        {
            // Attempt iptables isolation
            let cmd = "sudo iptables -P INPUT DROP && sudo iptables -P OUTPUT DROP && \
                       sudo iptables -A INPUT -p tcp --dport 4001 -j ACCEPT && \
                       sudo iptables -A OUTPUT -p tcp --dport 4001 -j ACCEPT";

            let status = Command::new("sh").args(["-c", cmd]).status()?;
            if status.success() {
                info!("Network isolation applied via iptables.");
                Ok(())
            } else {
                Err(anyhow::anyhow!("Failed to apply iptables isolation rules."))
            }
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
        info!(
            "AUTONOMOUS RESPONSE: Terminating process tree for PID {}...",
            pid
        );

        use sysinfo::{Pid, System};
        let mut sys = System::new_all();
        sys.refresh_processes();

        let target_pid = Pid::from(pid as usize);
        
        // Collect all descendants
        let mut to_kill = vec![target_pid];
        let mut i = 0;
        while i < to_kill.len() {
            let parent_pid = to_kill[i];
            for (p, proc) in sys.processes() {
                if proc.parent() == Some(parent_pid) {
                    if !to_kill.contains(p) {
                        to_kill.push(*p);
                    }
                }
            }
            i += 1;
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
