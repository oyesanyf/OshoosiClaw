//! Resource Tarpit (Throttling and Asymmetric Containment of malicious processes).
//!
//! Exerts computational pressure or delays to slow down attackers.
//! On Windows, uses Toolhelp32 snapshots with `OpenThread`, `SuspendThread`, and `ResumeThread`
//! combined with `SetPriorityClass` + `SetProcessWorkingSetSize` to throttle.
//! Falls back to CPU-priority-only if memory throttle fails.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, trace, warn};

static GLOBAL_TRAPS: OnceLock<Arc<dashmap::DashMap<u32, Arc<AtomicBool>>>> = OnceLock::new();

fn get_global_traps() -> Arc<dashmap::DashMap<u32, Arc<AtomicBool>>> {
    GLOBAL_TRAPS.get_or_init(|| Arc::new(dashmap::DashMap::new())).clone()
}

static INACCESSIBLE_PIDS: OnceLock<Arc<dashmap::DashMap<u32, tokio::time::Instant>>> = OnceLock::new();

pub fn get_inaccessible_pids() -> Arc<dashmap::DashMap<u32, tokio::time::Instant>> {
    INACCESSIBLE_PIDS.get_or_init(|| Arc::new(dashmap::DashMap::new())).clone()
}

pub fn is_pid_inaccessible_cooldown(pid: u32) -> bool {
    let map = get_inaccessible_pids();
    if let Some(entry) = map.get(&pid) {
        if entry.elapsed() < Duration::from_secs(60) {
            return true;
        } else {
            drop(entry);
            map.remove(&pid);
        }
    }
    false
}

pub fn mark_pid_inaccessible(pid: u32) {
    let map = get_inaccessible_pids();
    map.insert(pid, tokio::time::Instant::now());
}

/// Query the process name for a given PID.
/// On Windows, queries process image info or falls back to sysinfo.
pub fn get_process_name(pid: u32) -> String {
    if pid == 0 {
        return "System Idle Process".to_string();
    }
    if pid == 4 {
        return "System".to_string();
    }

    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
            PROCESS_QUERY_LIMITED_INFORMATION,
        };

        if let Ok(handle) = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
            let mut buf = [0u16; 1024];
            let mut size = buf.len() as u32;
            let success = unsafe {
                QueryFullProcessImageNameW(
                    handle,
                    PROCESS_NAME_FORMAT(0),
                    windows::core::PWSTR(buf.as_mut_ptr()),
                    &mut size,
                )
            };
            let _ = unsafe { CloseHandle(handle) };
            if success.is_ok() && size > 0 {
                let full_path = String::from_utf16_lossy(&buf[..size as usize]);
                if let Some(filename) = std::path::Path::new(&full_path).file_name().and_then(|n| n.to_str()) {
                    return filename.to_string();
                }
            }
        }

        // Secondary Win32 fallback for elevated/protected processes where OpenProcess is refused:
        // Use CreateToolhelp32Snapshot which does not require opening individual process handles
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
            TH32CS_SNAPPROCESS,
        };
        if let Ok(snapshot) = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
            let mut entry = PROCESSENTRY32 {
                dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
                ..Default::default()
            };
            unsafe {
                if Process32First(snapshot, &mut entry).is_ok() {
                    loop {
                        if entry.th32ProcessID == pid {
                            let name: String = entry
                                .szExeFile
                                .iter()
                                .take_while(|&&c| c != 0)
                                .map(|&c| c as u8 as char)
                                .collect();
                            let _ = CloseHandle(snapshot);
                            if !name.is_empty() {
                                return name;
                            }
                            break;
                        }
                        if Process32Next(snapshot, &mut entry).is_err() {
                            break;
                        }
                    }
                }
                let _ = CloseHandle(snapshot);
            }
        }
    }

    let mut s = sysinfo::System::new();
    let target_pid = sysinfo::Pid::from(pid as usize);
    s.refresh_process(target_pid);
    if let Some(process) = s.process(target_pid) {
        let name = process.name().to_string();
        if !name.is_empty() {
            return name;
        }
    }

    "unknown".to_string()
}

pub fn is_protected_system_or_security_process(pid: u32, proc_name: &str) -> bool {
    if pid <= 4 || pid == std::process::id() {
        return true;
    }
    let lower = proc_name.to_lowercase();
    let fn_only = std::path::Path::new(&lower)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(lower.as_str());

    matches!(
        fn_only,
        "sysmon.exe"
            | "sysmon64.exe"
            | "osoosi.exe"
            | "oshoosi.exe"
            | "msmpeng.exe"
            | "securityhealthservice.exe"
            | "nissrv.exe"
            | "senseir.exe"
            | "sensendr.exe"
            | "mpcmdrun.exe"
            | "csrss.exe"
            | "lsass.exe"
            | "services.exe"
            | "smss.exe"
            | "wininit.exe"
            | "winlogon.exe"
            | "dwm.exe"
            | "svchost.exe"
            | "system"
            | "ntoskrnl.exe"
    )
}

/// Active thread-level asymmetric tarpit engine.
#[derive(Clone)]
pub struct ActiveProcessTarpit {
    pub active_traps: Arc<dashmap::DashMap<u32, Arc<AtomicBool>>>,
}

impl Default for ActiveProcessTarpit {
    fn default() -> Self {
        Self::new()
    }
}

impl ActiveProcessTarpit {
    pub fn new() -> Self {
        Self {
            active_traps: get_global_traps(),
        }
    }

    /// Creates an isolated tarpit instance not bound to the process-global trap registry (for tests and sub-orchestrators).
    pub fn new_isolated() -> Self {
        Self {
            active_traps: Arc::new(dashmap::DashMap::new()),
        }
    }

    pub fn is_trapped(&self, pid: u32) -> bool {
        self.active_traps
            .get(&pid)
            .map(|flag| flag.load(Ordering::Relaxed))
            .unwrap_or(false)
    }

    pub fn release_pid(&self, pid: u32) {
        if let Some((_, flag)) = self.active_traps.remove(&pid) {
            flag.store(false, Ordering::SeqCst);
            let proc_name = get_process_name(pid);
            info!("ActiveProcessTarpit: Released PID {} ({})", pid, proc_name);
        }
    }

    #[cfg(target_os = "windows")]
    pub fn trap_pid(&self, pid: u32, interval: Duration, max_duration: Duration) {
        if is_pid_inaccessible_cooldown(pid) {
            return;
        }
        if pid <= 4 || pid == std::process::id() {
            return;
        }
        let proc_name = get_process_name(pid);
        if is_protected_system_or_security_process(pid, &proc_name) {
            warn!(
                "[SECURITY SAFEGUARD] Tarpit refused for PID {} ({}): Protected system or security instrumentation binary.",
                pid, proc_name
            );
            return;
        }

        // Prevent duplicate concurrent trapping loops on the same PID
        if let Some(existing) = self.active_traps.get(&pid) {
            if existing.load(Ordering::Relaxed) {
                info!("ActiveProcessTarpit: PID {} ({}) is already actively trapped", pid, proc_name);
                return;
            }
        }

        #[derive(Clone, Copy)]
        struct SendHandle(windows::Win32::Foundation::HANDLE);
        unsafe impl Send for SendHandle {}
        unsafe impl Sync for SendHandle {}

        // Collect all threads belonging to pid using Toolhelp32 snapshot
        let handles: Vec<SendHandle> = unsafe {
            use windows::Win32::Foundation::CloseHandle;
            use windows::Win32::System::Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32,
                TH32CS_SNAPTHREAD,
            };
            use windows::Win32::System::Threading::{
                OpenThread, THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME,
            };

            let mut list = Vec::new();
            if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
                let mut entry = THREADENTRY32 {
                    dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                    ..Default::default()
                };

                if Thread32First(snapshot, &mut entry).is_ok() {
                    loop {
                        if entry.th32OwnerProcessID == pid {
                            match OpenThread(
                                THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                                false,
                                entry.th32ThreadID,
                            ) {
                                Ok(h) => list.push(SendHandle(h)),
                                Err(e) => {
                                    trace!(
                                        "ActiveProcessTarpit: OpenThread failed for TID {} in PID {} ({}): {}",
                                        entry.th32ThreadID, pid, proc_name, e
                                    );
                                }
                            }
                        }
                        if Thread32Next(snapshot, &mut entry).is_err() {
                            break;
                        }
                    }
                }
                let _ = CloseHandle(snapshot);
            }
            list
        };

        if handles.is_empty() {
            warn!(
                "ActiveProcessTarpit: No accessible threads found to trap for PID {} ({})",
                pid, proc_name
            );
            mark_pid_inaccessible(pid);
            return;
        }

        let run_flag = Arc::new(AtomicBool::new(true));
        self.active_traps.insert(pid, run_flag.clone());
        let traps = self.active_traps.clone();
        let proc_name_clone = proc_name.clone();

        tokio::spawn(async move {
            info!(
                "ActiveProcessTarpit: Starting asymmetric thread containment loop for PID {} ({}) ({} thread(s) trapped)",
                pid, proc_name_clone, handles.len()
            );
            let start = tokio::time::Instant::now();

            let mut is_currently_suspended = false;
            while run_flag.load(Ordering::Relaxed) && start.elapsed() < max_duration {
                // Call SuspendThread(hThread) on each thread
                for &h in &handles {
                    unsafe {
                        let _ = windows::Win32::System::Threading::SuspendThread(h.0);
                    }
                }
                is_currently_suspended = true;

                // Sleep for interval (chunked so release_pid can cancel promptly)
                let sleep_chunk = Duration::from_millis(25);
                let mut slept = Duration::ZERO;
                while slept < interval && run_flag.load(Ordering::Relaxed) && start.elapsed() < max_duration {
                    let step = sleep_chunk.min(interval - slept);
                    tokio::time::sleep(step).await;
                    slept += step;
                }

                if !run_flag.load(Ordering::Relaxed) || start.elapsed() >= max_duration {
                    break;
                }

                // Briefly call ResumeThread(hThread) for 5-10ms for telemetry observation
                for &h in &handles {
                    unsafe {
                        let _ = windows::Win32::System::Threading::ResumeThread(h.0);
                    }
                }
                is_currently_suspended = false;

                tokio::time::sleep(Duration::from_millis(8)).await;
            }

            // Ensure all threads are resumed upon loop exit
            if is_currently_suspended {
                for &h in &handles {
                    unsafe {
                        let mut count = windows::Win32::System::Threading::ResumeThread(h.0);
                        while count > 1 && count != u32::MAX {
                            count = windows::Win32::System::Threading::ResumeThread(h.0);
                        }
                    }
                }
            }

            // Close all thread handles
            for h in handles {
                unsafe {
                    let _ = windows::Win32::Foundation::CloseHandle(h.0);
                }
            }

            traps.remove(&pid);
            info!(
                "ActiveProcessTarpit: Thread containment terminated and threads released for PID {} ({})",
                pid, proc_name_clone
            );
        });
    }

    #[cfg(not(target_os = "windows"))]
    pub fn trap_pid(&self, pid: u32, interval: Duration, max_duration: Duration) {
        if is_pid_inaccessible_cooldown(pid) {
            return;
        }
        if pid <= 4 || pid == std::process::id() {
            return;
        }
        let proc_name = get_process_name(pid);
        if is_protected_system_or_security_process(pid, &proc_name) {
            warn!(
                "[SECURITY SAFEGUARD] Tarpit refused for PID {} ({}): Protected system or security instrumentation binary.",
                pid, proc_name
            );
            return;
        }

        if let Some(existing) = self.active_traps.get(&pid) {
            if existing.load(Ordering::Relaxed) {
                return;
            }
        }

        let run_flag = Arc::new(AtomicBool::new(true));
        self.active_traps.insert(pid, run_flag.clone());
        let traps = self.active_traps.clone();
        let proc_name_clone = proc_name.clone();

        tokio::spawn(async move {
            info!("ActiveProcessTarpit (non-Windows fallback): Trapping PID {} ({})", pid, proc_name_clone);
            let start = tokio::time::Instant::now();
            while run_flag.load(Ordering::Relaxed) && start.elapsed() < max_duration {
                tokio::time::sleep(interval.min(Duration::from_millis(50))).await;
            }
            traps.remove(&pid);
            info!("ActiveProcessTarpit (non-Windows fallback): Released PID {} ({})", pid, proc_name_clone);
        });
    }
}

pub struct TarpitManager {
    pub active_tarpit: ActiveProcessTarpit,
}

impl Default for TarpitManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TarpitManager {
    pub fn new() -> Self {
        Self {
            active_tarpit: ActiveProcessTarpit::new(),
        }
    }

    pub fn active_tarpit(&self) -> &ActiveProcessTarpit {
        &self.active_tarpit
    }

    /// Enter a "Tarpit" state for a specific process ID.
    /// Combines thread-level asymmetric suspension with process priority throttling.
    /// After `duration_secs`, restores normal priority and releases threads.
    pub async fn apply_tarpit(&self, pid: u32, duration_secs: u64) {
        if is_pid_inaccessible_cooldown(pid) {
            return;
        }
        if pid <= 4 || pid == std::process::id() {
            return;
        }

        let proc_name = get_process_name(pid);
        if is_protected_system_or_security_process(pid, &proc_name) {
            warn!(
                "[SECURITY SAFEGUARD] Tarpit refused for PID {} ({}): Protected system or security instrumentation binary.",
                pid, proc_name
            );
            return;
        }

        warn!(
            "Applying Active Tarpit & Priority Throttling to PID {} ({}) for {}s...",
            pid, proc_name, duration_secs
        );

        // Platform-specific priority throttle
        #[cfg(target_os = "windows")]
        let throttle_applied = Self::windows_throttle(pid, true, &proc_name);

        #[cfg(target_os = "linux")]
        let throttle_applied = Self::linux_throttle(pid, true, &proc_name).await.is_ok();

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        let throttle_applied = false;

        // Active thread-level asymmetric containment
        self.active_tarpit.trap_pid(
            pid,
            Duration::from_millis(500),
            Duration::from_secs(duration_secs),
        );

        // If neither throttle nor thread containment could be applied (e.g. inaccessible/exited), return promptly
        if !throttle_applied && !self.active_tarpit.is_trapped(pid) {
            return;
        }

        sleep(Duration::from_secs(duration_secs)).await;

        // Restore after tarpit window closes
        self.active_tarpit.release_pid(pid);

        #[cfg(target_os = "windows")]
        {
            if throttle_applied {
                Self::windows_throttle(pid, false, &proc_name);
                warn!(
                    "Tarpit duration window closed for PID {} ({}). Priority restored.",
                    pid, proc_name
                );
            }
        }

        #[cfg(target_os = "linux")]
        {
            if throttle_applied {
                let _ = Self::linux_throttle(pid, false, &proc_name).await;
                warn!(
                    "Tarpit duration window closed for PID {} ({}). Priority restored.",
                    pid, proc_name
                );
            }
        }
    }

    /// Windows: Use native Win32 API to set IDLE priority and shrink working set.
    #[cfg(target_os = "windows")]
    fn windows_throttle(pid: u32, throttle: bool, proc_name: &str) -> bool {
        if throttle && is_pid_inaccessible_cooldown(pid) {
            return false;
        }
        if pid <= 4 || pid == std::process::id() {
            return false;
        }
        if is_protected_system_or_security_process(pid, proc_name) {
            warn!(
                "[SECURITY SAFEGUARD] Tarpit refused for PID {} ({}): Protected system or security instrumentation binary.",
                pid, proc_name
            );
            return false;
        }

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
                let mut success = false;

                unsafe {
                    if let Err(e) = SetPriorityClass(h, priority) {
                        warn!("Tarpit: SetPriorityClass({}) failed for PID {} ({}): {}", action, pid, proc_name, e);
                    } else {
                        info!("Tarpit: PID {} ({}) priority set to {}", pid, proc_name, action);
                        success = true;
                    }

                    // Shrink working set to force paging (aggressive throttle)
                    if throttle && success {
                        use windows::Win32::System::Memory::{SetProcessWorkingSetSizeEx, QUOTA_LIMITS_HARDWS_MIN_DISABLE};
                        // SIZE_T(-1) tells Windows to trim the working set
                        let _ = SetProcessWorkingSetSizeEx(h, usize::MAX, usize::MAX, QUOTA_LIMITS_HARDWS_MIN_DISABLE);
                        info!("Tarpit: PID {} ({}) working set trimmed (memory pressure applied)", pid, proc_name);
                    }

                    let _ = CloseHandle(h);
                }
                success
            }
            Err(e) => {
                let err_code = e.code().0 as u32;
                if err_code == 0x80070005 || err_code == 5 {
                    mark_pid_inaccessible(pid);
                }
                warn!(
                    "Tarpit: Cannot open PID {} ({}) for throttle ({}). Process may have exited or requires elevation.",
                    pid, proc_name, e
                );
                false
            }
        }
    }

    /// Linux: Use `renice` to set the process to lowest priority.
    #[cfg(target_os = "linux")]
    async fn linux_throttle(pid: u32, throttle: bool, proc_name: &str) -> anyhow::Result<()> {
        use tokio::process::Command;
        use tokio::time::{timeout, Duration};

        let nice_val = if throttle { "19" } else { "0" };
        let renice_fut = Command::new("renice")
            .args(["-n", nice_val, "-p", &pid.to_string()])
            .status();

        match timeout(Duration::from_secs(10), renice_fut).await {
            Ok(Ok(s)) if s.success() => {
                info!("Tarpit: PID {} ({}) renice set to {}", pid, proc_name, nice_val);
            }
            Ok(Ok(s)) => {
                warn!("Tarpit: renice for PID {} ({}) exited with {:?}", pid, proc_name, s.code());
            }
            _ => {
                warn!("Tarpit: Failed to renice PID {} ({}) (timed out or failed)", pid, proc_name);
            }
        }
        
        // Also apply ionice if available (best-effort)
        if throttle {
            let io_fut = Command::new("ionice")
                .args(["-c", "3", "-p", &pid.to_string()])
                .status();
            let _ = timeout(Duration::from_secs(10), io_fut).await;
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_active_process_tarpit_lifecycle() {
        let tarpit = ActiveProcessTarpit::new();

        #[cfg(target_os = "windows")]
        {
            // Spawn a dummy background process to trap
            let mut child = std::process::Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 30"])
                .spawn()
                .expect("Failed to spawn dummy child process for test");

            let pid = child.id();
            assert!(pid > 0);

            // Give the child process a moment to initialize its primary thread
            tokio::time::sleep(Duration::from_millis(300)).await;

            // Trap PID
            tarpit.trap_pid(pid, Duration::from_millis(50), Duration::from_secs(5));
            assert!(tarpit.is_trapped(pid));

            // Wait a little while containment runs
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(tarpit.is_trapped(pid));

            // Cleanly release
            tarpit.release_pid(pid);
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(!tarpit.is_trapped(pid));

            // Kill child
            let _ = child.kill();
        }

        #[cfg(not(target_os = "windows"))]
        {
            let dummy_pid = 99999;
            tarpit.trap_pid(dummy_pid, Duration::from_millis(50), Duration::from_millis(500));
            assert!(tarpit.is_trapped(dummy_pid));
            tarpit.release_pid(dummy_pid);
            assert!(!tarpit.is_trapped(dummy_pid));
        }
    }

    #[tokio::test]
    async fn test_safeguards_and_inaccessible_cooldown() {
        assert!(is_protected_system_or_security_process(4, "System"));
        assert!(is_protected_system_or_security_process(1234, "sysmon64.exe"));
        assert!(is_protected_system_or_security_process(1235, "Sysmon.exe"));
        assert!(is_protected_system_or_security_process(1236, "msmpeng.exe"));
        assert!(is_protected_system_or_security_process(1237, "osoosi.exe"));
        assert!(is_protected_system_or_security_process(std::process::id(), "anything.exe"));
        assert!(!is_protected_system_or_security_process(9999, "curl.exe"));

        let tarpit = ActiveProcessTarpit::new();
        tarpit.trap_pid(4, Duration::from_millis(50), Duration::from_secs(5));
        assert!(!tarpit.is_trapped(4));

        mark_pid_inaccessible(98765);
        assert!(is_pid_inaccessible_cooldown(98765));
    }
}

