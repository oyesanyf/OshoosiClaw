//! In-Memory Magic Header Scanning.
//!
//! Scans memory regions for file-type headers (PE/ELF) in non-executable 
//! memory segments to detect "fileless" malware.

use goblin;
use magika::Session as MagikaSession;
use std::sync::Arc;
use tokio::sync::Mutex;
pub struct MemoryScanner {
    magika: Option<Arc<Mutex<MagikaSession>>>,
}

impl MemoryScanner {
    pub fn new() -> Self {
        let magika = MagikaSession::new().ok().map(|s| Arc::new(Mutex::new(s)));
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
        use winapi::um::memoryapi::VirtualQueryEx;
        use winapi::um::processthreadsapi::OpenProcess;
        use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, MEM_COMMIT, PAGE_NOACCESS, PAGE_GUARD};
        use winapi::um::handleapi::CloseHandle;
        use std::ffi::c_void;

        let mut results = Vec::new();
        let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
        if handle.is_null() {
            return Err(anyhow::anyhow!("Failed to open process {}", pid));
        }

        let mut base_addr = 0 as *mut _;
        loop {
            let mut mem_info: winapi::um::winnt::MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            let res = unsafe {
                VirtualQueryEx(handle, base_addr, &mut mem_info, std::mem::size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>())
            };
            if res == 0 { break; }

            // Only scan committed memory that is not protected
            if mem_info.State == MEM_COMMIT && (mem_info.Protect & PAGE_NOACCESS) == 0 && (mem_info.Protect & PAGE_GUARD) == 0 {
                let mut buffer = vec![0u8; mem_info.RegionSize];
                let mut bytes_read = 0;
                unsafe {
                    winapi::um::memoryapi::ReadProcessMemory(handle, mem_info.BaseAddress, buffer.as_mut_ptr() as *mut _, mem_info.RegionSize, &mut bytes_read);
                }
                if bytes_read > 0 {
                    if let Some(detection) = self.scan_buffer(&buffer[..bytes_read]).await {
                        results.push(format!("Detection at {:p}: {}", mem_info.BaseAddress, detection));
                    }
                }
            }

            base_addr = unsafe { (mem_info.BaseAddress as *mut u8).add(mem_info.RegionSize) as *mut _ };
        }

        unsafe { CloseHandle(handle) };
        Ok(results)
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn scan_process_memory(&self, _pid: u32) -> anyhow::Result<Vec<String>> {
        // Linux/macOS memory scanning would involve /proc/pid/maps or vm_read
        Ok(vec!["Memory scanning for this OS is not yet implemented".to_string()])
    }
}
