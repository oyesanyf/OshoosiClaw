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
}
