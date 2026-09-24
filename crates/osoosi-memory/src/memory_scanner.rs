//! In-Memory Magic Header Scanning.
//!
//! Scans memory regions for file-type headers (PE/ELF) in non-executable
//! memory segments to detect "fileless" malware.

use goblin;
use magika::Session as MagikaSession;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
pub struct MemoryScanner {
    magika: Option<Arc<Mutex<MagikaSession>>>,
}

impl MemoryScanner {
    pub fn new() -> Self {
        let magika = {
            let prev_hook = std::panic::take_hook();
            std::panic::set_hook(Box::new(|_| {}));
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                MagikaSession::new().ok()
            }));
            std::panic::set_hook(prev_hook);
            res.ok().flatten().map(|s| Arc::new(Mutex::new(s)))
        };

        Self { magika }
    }

    /// Scan a buffer for known file headers.
    pub async fn scan_buffer(&self, buffer: &[u8]) -> Option<String> {
        // 1. Quick check using Goblin for PE/ELF headers
        if let Ok(obj) = goblin::Object::parse(buffer) {
            match obj {
                goblin::Object::PE(_) => return Some("PE Header Detected in Memory".to_string()),
                goblin::Object::Elf(_) => return Some("ELF Header Detected in Memory".to_string()),
                _ => {}
            }
        }

        // 2. Deep identification using Magika if enabled
        if let Some(ref session_mutex) = self.magika {
            if let Ok(mut session) = session_mutex.try_lock() {
                if let Ok(res) = session.identify_content_sync(buffer) {
                    let label = res.info().label;
                    if label == "pe" || label == "exe" || label == "elf" {
                        return Some(format!("Magika Detected: {}", label));
                    }
                }
            }
        }

        None
    }

    /// Scan a process's memory regions (Platform specific).
    #[cfg(target_os = "windows")]
    pub async fn scan_process_memory(&self, pid: u32) -> anyhow::Result<Vec<String>> {
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::memoryapi::VirtualQueryEx;
        use winapi::um::processthreadsapi::OpenProcess;
        use winapi::um::winnt::{
            MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };
        let mut results = Vec::new();
        let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
        if handle.is_null() {
            return Err(anyhow::anyhow!("Failed to open process {}", pid));
        }
        let handle_val = handle as usize;

        let mut base_addr_val = 0usize;
        loop {
            let (is_commited, base_address, region_size) = {
                let mut mem_info: winapi::um::winnt::MEMORY_BASIC_INFORMATION =
                    unsafe { std::mem::zeroed() };
                let res = unsafe {
                    VirtualQueryEx(
                        handle_val as *mut _,
                        base_addr_val as *mut _,
                        &mut mem_info,
                        std::mem::size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>(),
                    )
                };
                if res == 0 {
                    break;
                }
                
                let is_commited = mem_info.State == MEM_COMMIT
                    && (mem_info.Protect & PAGE_NOACCESS) == 0
                    && (mem_info.Protect & PAGE_GUARD) == 0;
                    
                (is_commited, mem_info.BaseAddress as usize, mem_info.RegionSize as usize)
            };

            if is_commited {
                let mut buffer = vec![0u8; region_size];
                let mut bytes_read = 0;
                unsafe {
                    winapi::um::memoryapi::ReadProcessMemory(
                        handle_val as *mut _,
                        base_address as *mut _,
                        buffer.as_mut_ptr() as *mut _,
                        region_size,
                        &mut bytes_read,
                    );
                }
                if bytes_read > 0 {
                    if let Some(detection) = self.scan_buffer(&buffer[..bytes_read]).await {
                        results.push(format!(
                            "Detection at {:#x}: {}",
                            base_address, detection
                        ));
                    }
                }
            }

            base_addr_val = base_address + region_size;
        }

        unsafe { CloseHandle(handle_val as *mut _) };
        Ok(results)
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn scan_process_memory(&self, _pid: u32) -> anyhow::Result<Vec<String>> {
        // Linux/macOS memory scanning would involve /proc/pid/maps or vm_read
        Ok(vec![
            "Memory scanning for this OS is not yet implemented".to_string()
        ])
    }

    /// Scans a process's threads for unbacked execution (threads starting in MEM_PRIVATE/MEM_MAPPED)
    /// or RWX thread stack/execution regions.
    #[cfg(target_os = "windows")]
    pub fn scan_unbacked_threads(&self, pid: u32) -> anyhow::Result<Vec<UnbackedExecutionFinding>> {
        // Protect critical OS PIDs
        if pid <= 4 {
            return Ok(Vec::new());
        }

        use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
        use winapi::um::memoryapi::VirtualQueryEx;
        use winapi::um::processthreadsapi::{OpenProcess, OpenThread};
        use winapi::um::tlhelp32::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };
        use winapi::um::winnt::{
            MEM_COMMIT, MEM_IMAGE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
            PAGE_EXECUTE_WRITECOPY, PROCESS_QUERY_INFORMATION, THREAD_QUERY_INFORMATION,
        };

        let mut findings = Vec::new();

        let mut process_handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid) };
        if process_handle.is_null() {
            process_handle = unsafe { OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, 0, pid) };
        }
        if process_handle.is_null() {
            return Ok(Vec::new());
        }

        // Dynamically resolve NtQueryInformationThread for ThreadQuerySetWin32StartAddress (9)
        type NtQueryInformationThreadFn = unsafe extern "system" fn(
            thread_handle: winapi::um::winnt::HANDLE,
            thread_information_class: u32,
            thread_information: *mut winapi::ctypes::c_void,
            thread_information_length: u32,
            return_length: *mut u32,
        ) -> i32;

        let nt_query_thread: Option<NtQueryInformationThreadFn> = unsafe {
            let ntdll = winapi::um::libloaderapi::GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const _);
            if !ntdll.is_null() {
                let proc = winapi::um::libloaderapi::GetProcAddress(
                    ntdll,
                    b"NtQueryInformationThread\0".as_ptr() as *const _,
                );
                if !proc.is_null() {
                    Some(std::mem::transmute(proc))
                } else {
                    None
                }
            } else {
                None
            }
        };

        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(process_handle) };
            return Ok(Vec::new());
        }

        let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

        if unsafe { Thread32First(snapshot, &mut entry) } != 0 {
            loop {
                if entry.th32OwnerProcessID == pid {
                    let thread_id = entry.th32ThreadID;
                    let mut thread_handle = unsafe {
                        OpenThread(THREAD_QUERY_INFORMATION | 0x0008 /* THREAD_GET_CONTEXT */, 0, thread_id)
                    };
                    if thread_handle.is_null() {
                        thread_handle = unsafe { OpenThread(THREAD_QUERY_INFORMATION, 0, thread_id) };
                    }
                    if thread_handle.is_null() {
                        thread_handle = unsafe { OpenThread(0x0800 /* THREAD_QUERY_LIMITED_INFORMATION */, 0, thread_id) };
                    }

                    if !thread_handle.is_null() {
                        let mut addresses_to_check: Vec<(usize, &'static str)> = Vec::new();

                        // 1. Check thread Win32 Start Address
                        if let Some(query_fn) = nt_query_thread {
                            let mut start_addr: usize = 0;
                            let status = unsafe {
                                query_fn(
                                    thread_handle,
                                    9, // ThreadQuerySetWin32StartAddress
                                    &mut start_addr as *mut usize as *mut _,
                                    std::mem::size_of::<usize>() as u32,
                                    std::ptr::null_mut(),
                                )
                            };
                            if status >= 0 && start_addr != 0 {
                                addresses_to_check.push((start_addr, "Thread Start Address"));
                            }
                        }

                        // 2. Check thread Instruction Pointer (RIP on x86_64, EIP on x86)
                        #[cfg(target_arch = "x86_64")]
                        {
                            use winapi::um::processthreadsapi::GetThreadContext;
                            use winapi::um::winnt::CONTEXT;
                            let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
                            ctx.ContextFlags = winapi::um::winnt::CONTEXT_CONTROL;
                            if unsafe { GetThreadContext(thread_handle, &mut ctx) } != 0 {
                                let rip = ctx.Rip as usize;
                                if rip != 0 && !addresses_to_check.iter().any(|(a, _)| *a == rip) {
                                    addresses_to_check.push((rip, "Instruction Pointer (RIP)"));
                                }
                            }
                        }

                        #[cfg(target_arch = "x86")]
                        {
                            use winapi::um::processthreadsapi::GetThreadContext;
                            use winapi::um::winnt::CONTEXT;
                            let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
                            ctx.ContextFlags = winapi::um::winnt::CONTEXT_CONTROL;
                            if unsafe { GetThreadContext(thread_handle, &mut ctx) } != 0 {
                                let eip = ctx.Eip as usize;
                                if eip != 0 && !addresses_to_check.iter().any(|(a, _)| *a == eip) {
                                    addresses_to_check.push((eip, "Instruction Pointer (EIP)"));
                                }
                            }
                        }

                        for (addr, addr_source) in addresses_to_check {
                            let mut mem_info: winapi::um::winnt::MEMORY_BASIC_INFORMATION =
                                unsafe { std::mem::zeroed() };
                            let res = unsafe {
                                VirtualQueryEx(
                                    process_handle,
                                    addr as *const _,
                                    &mut mem_info,
                                    std::mem::size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>(),
                                )
                            };

                            if res != 0 && mem_info.State == MEM_COMMIT {
                                let exec_mask = PAGE_EXECUTE
                                    | PAGE_EXECUTE_READ
                                    | PAGE_EXECUTE_READWRITE
                                    | PAGE_EXECUTE_WRITECOPY;
                                let is_executable = (mem_info.Protect & exec_mask) != 0;
                                let is_rwx = (mem_info.Protect & PAGE_EXECUTE_READWRITE) != 0;
                                let is_unbacked = is_executable && mem_info.Type != MEM_IMAGE;

                                if is_unbacked || is_rwx {
                                    let type_desc = match mem_info.Type {
                                        winapi::um::winnt::MEM_IMAGE => "MEM_IMAGE",
                                        winapi::um::winnt::MEM_MAPPED => "MEM_MAPPED",
                                        winapi::um::winnt::MEM_PRIVATE => "MEM_PRIVATE",
                                        _ => "MEM_UNKNOWN",
                                    };
                                    let reason = if is_unbacked && is_rwx {
                                        format!("Unbacked memory with RWX protection ({})", addr_source)
                                    } else if is_unbacked {
                                        format!("Executable code in non-image memory ({})", addr_source)
                                    } else {
                                        format!("RWX memory protection on thread execution region ({})", addr_source)
                                    };

                                    findings.push(UnbackedExecutionFinding {
                                        pid,
                                        thread_id,
                                        address: addr,
                                        memory_type: mem_info.Type,
                                        protection: mem_info.Protect,
                                        details: format!(
                                            "{}: address={:#x}, type={}, protect={:#x}",
                                            reason, addr, type_desc, mem_info.Protect
                                        ),
                                    });
                                }
                            }
                        }

                        unsafe { CloseHandle(thread_handle) };
                    }
                }

                if unsafe { Thread32Next(snapshot, &mut entry) } == 0 {
                    break;
                }
            }
        }

        unsafe {
            CloseHandle(snapshot);
            CloseHandle(process_handle);
        }

        Ok(findings)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn scan_unbacked_threads(&self, _pid: u32) -> anyhow::Result<Vec<UnbackedExecutionFinding>> {
        Ok(Vec::new())
    }
}

/// Represents an in-memory execution finding where a thread's execution region
/// is not backed by a valid disk image (MEM_PRIVATE / MEM_MAPPED) or has RWX permissions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnbackedExecutionFinding {
    pub pid: u32,
    pub thread_id: u32,
    pub address: usize,
    pub memory_type: u32,
    pub protection: u32,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unbacked_threads_scanner_self() {
        let scanner = MemoryScanner::new();
        let my_pid = std::process::id();
        let result = scanner.scan_unbacked_threads(my_pid);
        assert!(result.is_ok(), "Scanning self PID must succeed without error");
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_unbacked_thread_detection_with_allocated_executable_memory() {
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::memoryapi::{VirtualAlloc, VirtualFree};
        use winapi::um::processthreadsapi::{CreateThread, TerminateThread};
        use winapi::um::winnt::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE};

        unsafe {
            let mem = VirtualAlloc(
                std::ptr::null_mut(),
                4096,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            assert!(!mem.is_null(), "VirtualAlloc must succeed");

            let code: [u8; 4] = [0x48, 0x31, 0xC0, 0xC3]; // xor rax, rax; ret
            std::ptr::copy_nonoverlapping(code.as_ptr(), mem as *mut u8, code.len());

            // Create suspended thread targeting unbacked RWX memory
            let thread = CreateThread(
                std::ptr::null_mut(),
                0,
                Some(std::mem::transmute(mem)),
                std::ptr::null_mut(),
                0x00000004, // CREATE_SUSPENDED
                std::ptr::null_mut(),
            );
            assert!(!thread.is_null(), "CreateThread must succeed");

            let my_pid = std::process::id();
            let scanner = MemoryScanner::new();
            let findings = scanner.scan_unbacked_threads(my_pid).expect("scan_unbacked_threads should succeed");

            let detected = findings.iter().any(|f| f.address == (mem as usize));

            TerminateThread(thread, 0);
            CloseHandle(thread);
            VirtualFree(mem, 0, MEM_RELEASE);

            assert!(
                detected,
                "Expected scan_unbacked_threads to detect unbacked thread at {:#x}, got: {:?}",
                mem as usize, findings
            );
        }
    }
}
