//! Native DLL/Dylib/SO Injector
//!
//! Ported architectural concept from OpenEDR's `dllinj.cpp` to native Rust.
//! Injects the `osoosi-inject` payload into target processes.
//!
//! Windows: Uses VirtualAllocEx + CreateRemoteThread
//! Linux: Modifies /etc/ld.so.preload or uses ptrace (stub)
//! macOS: Relies on DYLD_INSERT_LIBRARIES or Endpoint Security

use std::path::Path;
use tracing::{info, warn, error};

#[derive(Debug, thiserror::Error)]
pub enum InjectionError {
    #[error("Failed to open target process. PID: {0}. Ensure Oshoosi is running as Admin/root.")]
    OpenProcessFailed(u32),
    #[error("Failed to allocate memory in target process.")]
    VirtualAllocFailed,
    #[error("Failed to write DLL path to target process memory.")]
    WriteMemoryFailed,
    #[error("Failed to find LoadLibraryW in kernel32.dll.")]
    LoadLibraryNotFound,
    #[error("Failed to create remote thread in target process.")]
    CreateRemoteThreadFailed,
    #[error("Payload path is invalid or does not exist: {0}")]
    InvalidDllPath(String),
    #[error("Injection mechanism not fully supported on this OS: {0}")]
    UnsupportedOS(String),
}

#[cfg(target_os = "windows")]
pub fn inject_dll(pid: u32, dll_path: &Path) -> Result<(), InjectionError> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::s;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        CreateRemoteThread, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    };

    if !dll_path.exists() {
        return Err(InjectionError::InvalidDllPath(dll_path.to_string_lossy().to_string()));
    }

    let dll_path_wide: Vec<u16> = dll_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let path_size = dll_path_wide.len() * std::mem::size_of::<u16>();

    unsafe {
        let process_handle = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            false,
            pid,
        ).map_err(|_| InjectionError::OpenProcessFailed(pid))?;

        let remote_mem = VirtualAllocEx(
            process_handle,
            None,
            path_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_mem.is_null() {
            let _ = CloseHandle(process_handle);
            return Err(InjectionError::VirtualAllocFailed);
        }

        let mut bytes_written = 0;
        let write_success = WriteProcessMemory(
            process_handle,
            remote_mem,
            dll_path_wide.as_ptr() as *const std::ffi::c_void,
            path_size,
            Some(&mut bytes_written),
        );

        if write_success.is_err() || bytes_written != path_size {
            let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            let _ = CloseHandle(process_handle);
            return Err(InjectionError::WriteMemoryFailed);
        }

        let kernel32_handle = GetModuleHandleA(s!("kernel32.dll"))
            .map_err(|_| InjectionError::LoadLibraryNotFound)?;
            
        let load_library_addr = GetProcAddress(kernel32_handle, s!("LoadLibraryW"))
            .ok_or(InjectionError::LoadLibraryNotFound)?;

        let mut thread_id = 0;
        let thread_handle = CreateRemoteThread(
            process_handle,
            None,
            0,
            Some(std::mem::transmute(load_library_addr)),
            Some(remote_mem),
            0,
            Some(&mut thread_id),
        ).map_err(|_| {
            let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            let _ = CloseHandle(process_handle);
            InjectionError::CreateRemoteThreadFailed
        })?;

        let _ = CloseHandle(thread_handle);
        let _ = CloseHandle(process_handle);

        info!("Successfully injected payload into PID: {}", pid);
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn inject_dll(pid: u32, dll_path: &Path) -> Result<(), InjectionError> {
    if !dll_path.exists() {
        return Err(InjectionError::InvalidDllPath(dll_path.to_string_lossy().to_string()));
    }

    // Dynamic injection into a running process on Linux/macOS requires ptrace or mach_ports.
    // For now, we simulate the 'deployment' aspect by logging the action.
    // A full production implementation would either write to /etc/ld.so.preload (Linux)
    // or use DYLD_INSERT_LIBRARIES for spawned children.

    #[cfg(target_os = "linux")]
    {
        info!(
            "Linux EDR Injection: To enforce globally, add '{}' to /etc/ld.so.preload",
            dll_path.display()
        );
        // std::fs::write("/etc/ld.so.preload", format!("{}\n", dll_path.display())) ...
    }

    #[cfg(target_os = "macos")]
    {
        warn!(
            "macOS EDR Injection: Cannot dynamically inject into PID {} due to System Integrity Protection (SIP).",
            pid
        );
        info!("macOS requires Endpoint Security Framework (ESF) for execution blocking.");
    }

    Ok(())
}
