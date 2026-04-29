//! Resource Tarpit (Throttling malicious processes).
//!
//! Exerts computational pressure or delays to slow down attackers.
//! On Windows, uses `SetPriorityClass` + `SetProcessWorkingSetSize` to throttle.
//! Falls back to CPU-priority-only if memory throttle fails.

use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

pub struct TarpitManager;

impl Default for TarpitManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TarpitManager {
    pub fn new() -> Self {
        Self
    }

    /// Enter a "Tarpit" state for a specific process ID.
    /// On Windows: drops the process to IDLE priority and shrinks its working set.
    /// After `duration_secs`, restores normal priority.
    pub async fn apply_tarpit(&self, pid: u32, duration_secs: u64) {
        use sysinfo::{Pid, System};

        warn!(
            "Applying Resource Tarpit to PID {}: Throttling to IDLE priority...",
            pid
        );

        let s = System::new_all();
        if let Some(process) = s.process(Pid::from(pid as usize)) {
            let pname = process.name();
            info!("Throttling process: {} (PID {})", pname, pid);
        } else {
            warn!("Tarpit: PID {} not found in process list — may have exited.", pid);
        }

        // Platform-specific priority throttle
        #[cfg(target_os = "windows")]
        {
            Self::windows_throttle(pid, true);
        }

        #[cfg(target_os = "linux")]
        {
            Self::linux_throttle(pid, true);
        }

        sleep(Duration::from_secs(duration_secs)).await;

        // Restore after tarpit window closes
        #[cfg(target_os = "windows")]
        {
            Self::windows_throttle(pid, false);
        }

        #[cfg(target_os = "linux")]
        {
            Self::linux_throttle(pid, false);
        }

        warn!("Tarpit duration window closed for PID {}. Priority restored.", pid);
    }

    /// Windows: Use native Win32 API to set IDLE priority and shrink working set.
    #[cfg(target_os = "windows")]
    fn windows_throttle(pid: u32, throttle: bool) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            OpenProcess, SetPriorityClass,
            IDLE_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS,
            PROCESS_SET_INFORMATION, PROCESS_SET_QUOTA,
        };

        let access = PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA;
        let handle = unsafe { OpenProcess(access, false, pid) };

        match handle {
            Ok(h) => {
                let priority = if throttle {
                    IDLE_PRIORITY_CLASS
                } else {
                    NORMAL_PRIORITY_CLASS
                };

                let action = if throttle { "IDLE" } else { "NORMAL" };

                unsafe {
                    if let Err(e) = SetPriorityClass(h, priority) {
                        warn!("Tarpit: SetPriorityClass({}) failed for PID {}: {}", action, pid, e);
                    } else {
                        info!("Tarpit: PID {} priority set to {}", pid, action);
                    }

                    // Shrink working set to force paging (aggressive throttle)
                    if throttle {
                        use windows::Win32::System::Memory::{SetProcessWorkingSetSizeEx, QUOTA_LIMITS_HARDWS_MIN_DISABLE};
                        // SIZE_T(-1) tells Windows to trim the working set
                        let _ = SetProcessWorkingSetSizeEx(h, usize::MAX, usize::MAX, QUOTA_LIMITS_HARDWS_MIN_DISABLE);
                        info!("Tarpit: PID {} working set trimmed (memory pressure applied)", pid);
                    }

                    let _ = CloseHandle(h);
                }
            }
            Err(e) => {
                warn!(
                    "Tarpit: Cannot open PID {} for throttle ({}). Process may have exited or requires elevation.",
                    pid, e
                );
            }
        }
    }

    /// Linux: Use `renice` to set the process to lowest priority.
    #[cfg(target_os = "linux")]
    fn linux_throttle(pid: u32, throttle: bool) {
        let nice_val = if throttle { "19" } else { "0" };
        match std::process::Command::new("renice")
            .args(["-n", nice_val, "-p", &pid.to_string()])
            .status()
        {
            Ok(s) if s.success() => {
                info!("Tarpit: PID {} renice set to {}", pid, nice_val);
            }
            Ok(s) => {
                warn!("Tarpit: renice for PID {} exited with {:?}", pid, s.code());
            }
            Err(e) => {
                warn!("Tarpit: Failed to renice PID {}: {}", pid, e);
            }
        }
        // Also apply ionice if available (best-effort)
        if throttle {
            let _ = std::process::Command::new("ionice")
                .args(["-c", "3", "-p", &pid.to_string()])
                .status();
        }
    }
}
