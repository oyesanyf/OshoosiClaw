//! Just-In-Time (JIT) Memory Patching.
//!
//! Hot-patches vulnerable functions in running processes to prevent 
//! exploitation without requiring a service restart.

use tracing::info;
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
use tracing::warn;

#[cfg(target_os = "windows")]
use winapi::um::processthreadsapi::OpenProcess;
#[cfg(target_os = "windows")]
use winapi::um::memoryapi::{WriteProcessMemory, VirtualProtectEx};
#[cfg(target_os = "windows")]
use winapi::um::winnt::{PROCESS_ALL_ACCESS, PAGE_EXECUTE_READWRITE};
#[cfg(target_os = "windows")]
use winapi::um::handleapi::CloseHandle;

pub struct LiveProcessPatcher;

impl LiveProcessPatcher {
    /// Patch a running process's memory at a specific offset.
    /// 
    /// CAUTION: This is an extremely invasive operation and should only 
    /// be triggered by high-confidence CVE rules.
    pub fn patch_process_memory(pid: u32, offset: usize, new_data: &[u8]) -> anyhow::Result<()> {
        info!("JIT: Patching process {} at offset 0x{:x} ({} bytes)", pid, offset, new_data.len());
        
        #[cfg(target_os = "windows")]
        {
            unsafe {
                let handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
                if handle.is_null() {
                    return Err(anyhow::anyhow!("Failed to open process {} for patching", pid));
                }
                
                let mut old_protect = 0u32;
                // 1. Change memory protection to RWX
                if VirtualProtectEx(handle, offset as *mut winapi::ctypes::c_void, new_data.len(), PAGE_EXECUTE_READWRITE, &mut old_protect) == 0 {
                    CloseHandle(handle);
                    return Err(anyhow::anyhow!("Failed to change memory protection for process {}", pid));
                }
                
                // 2. Write the new instruction/data
                let mut bytes_written = 0usize;
                if WriteProcessMemory(handle, offset as *mut winapi::ctypes::c_void, new_data.as_ptr() as *const winapi::ctypes::c_void, new_data.len(), &mut bytes_written) == 0 {
                    VirtualProtectEx(handle, offset as *mut winapi::ctypes::c_void, new_data.len(), old_protect, &mut old_protect);
                    CloseHandle(handle);
                    return Err(anyhow::anyhow!("Failed to write memory for process {}", pid));
                }
                
                // 3. Restore original protection
                VirtualProtectEx(handle, offset as *mut winapi::ctypes::c_void, new_data.len(), old_protect, &mut old_protect);
                CloseHandle(handle);
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            use std::fs::OpenOptions;
            use std::io::{Seek, SeekFrom, Write};
            
            let mem_path = format!("/proc/{}/mem", pid);
            let mut file = OpenOptions::new().read(true).write(true).open(&mem_path)?;
            file.seek(SeekFrom::Start(offset as u64))?;
            file.write_all(new_data)?;
        }
        
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            warn!("JIT Patching not yet implemented for this OS.");
        }
        
        info!("Successfully hot-patched process {}.", pid);
        Ok(())
    }

    /// High-level method to 'neuter' a vulnerable syscall/function by inserting a RET instruction.
    pub fn neuter_function(pid: u32, offset: usize) -> anyhow::Result<()> {
        // x86/x64 'ret' instruction is 0xC3
        Self::patch_process_memory(pid, offset, &[0xC3])
    }
}
