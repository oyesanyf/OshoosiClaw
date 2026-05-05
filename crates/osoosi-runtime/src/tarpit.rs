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

        let mut s = System::new();
        let target_pid = Pid::from(pid as usize);
        s.refresh_process(target_pid);
        if let Some(process) = s.process(target_pid) {
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

    /// Start the Phantom Memory Flux engine.
    /// This allocates and frees random, deceptive memory regions to frustrate memory scanners.
    #[cfg(target_os = "windows")]
    pub fn start_phantom_memory_flux(
        &self,
        flux_regions: std::sync::Arc<tokio::sync::RwLock<std::collections::HashSet<usize>>>,
    ) {
        use rand::Rng;
        use windows::Win32::System::Memory::{
            VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
        };

        tokio::spawn(async move {
            info!("Phantom Memory Flux Engine started.");
            loop {
                // Sleep randomly between 5 and 45 seconds before the next flux
                let sleep_secs = {
                    let mut rng = rand::thread_rng();
                    rng.gen_range(5..=45)
                };
                tokio::time::sleep(tokio::time::Duration::from_secs(sleep_secs)).await;

                // Allocate standard page-aligned size (e.g., 64KB)
                let region_size = 64 * 1024;

                // PRODUCTION READINESS: Fully randomized ASLR memory allocation base addresses
                // Instead of letting Windows choose (None), we pick a random high-address base to frustrate scanners.
                let random_base: usize = {
                    let mut rng = rand::thread_rng();
                    rng.gen_range(0x00000100_00000000..0x00007FFF_00000000) & !0xFFFF // Page aligned
                };
                
                let ptr_addr = unsafe {
                    let ptr = VirtualAlloc(
                        Some(random_base as *const std::ffi::c_void),
                        region_size,
                        windows::Win32::System::Memory::VIRTUAL_ALLOCATION_TYPE(MEM_COMMIT.0 | MEM_RESERVE.0),
                        windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(PAGE_READWRITE.0),
                    );
                    
                    if ptr.is_null() {
                        // Fallback to auto-allocation if the random address is occupied
                        VirtualAlloc(
                            None,
                            region_size,
                            windows::Win32::System::Memory::VIRTUAL_ALLOCATION_TYPE(MEM_COMMIT.0 | MEM_RESERVE.0),
                            windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(PAGE_READWRITE.0),
                        ) as usize
                    } else {
                        ptr as usize
                    }
                };

                if ptr_addr == 0 {
                    warn!("Phantom Flux: VirtualAlloc failed.");
                    continue;
                }

                // Register region so our own scanners ignore it
                {
                    let mut regions = flux_regions.write().await;
                    regions.insert(ptr_addr);
                }

                // Bait the Tarpit: Fake MZ header + NOP sleds
                unsafe {
                    let slice = std::slice::from_raw_parts_mut(ptr_addr as *mut u8, region_size);
                    // Fake MZ Header (4D 5A)
                    slice[0] = 0x4D;
                    slice[1] = 0x5A;
                    // NOP Sled (0x90) for the rest
                    for i in 2..region_size {
                        slice[i] = 0x90;
                    }
                }

                info!("Phantom Memory allocated bait at {:#x}", ptr_addr);

                // Hold the Tarpit for 2 to 10 seconds
                let hold_secs = {
                    let mut rng = rand::thread_rng();
                    rng.gen_range(2..=10)
                };
                tokio::time::sleep(tokio::time::Duration::from_secs(hold_secs)).await;

                // Vanish: Free the memory completely
                unsafe {
                    let _ = VirtualFree(ptr_addr as *mut std::ffi::c_void, 0, windows::Win32::System::Memory::VIRTUAL_FREE_TYPE(MEM_RELEASE.0));
                }

                // Deregister the region
                {
                    let mut regions = flux_regions.write().await;
                    regions.remove(&ptr_addr);
                }

                info!("Phantom Memory vanished from {:#x}", ptr_addr);
            }
        });
    }

    #[cfg(not(target_os = "windows"))]
    pub fn start_phantom_memory_flux(
        &self,
        _flux_regions: std::sync::Arc<tokio::sync::RwLock<std::collections::HashSet<usize>>>,
    ) {
        // Fallback for non-Windows (e.g. Linux mmap)
        warn!("Phantom Memory Flux is currently only implemented for Windows.");
    }
}
