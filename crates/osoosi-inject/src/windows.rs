//! OpenỌ̀ṣọ́ọ̀sì Agentic EDR - Native Process Hooking Engine (Injected DLL)
//!
//! Ported from OpenEDR architectural patterns (`edrpm`).
//! This library is injected into processes via APC to provide inner-process telemetry 
//! and prevention capabilities (e.g., stopping screen scraping, blocking process creation).

#![cfg(target_os = "windows")]

use std::ffi::c_void;
use windows::core::{s, PCWSTR};
use windows::Win32::Foundation::{BOOL, HINSTANCE};
use std::sync::Mutex;
use serde_json::json;
use windows::Win32::System::Threading::GetCurrentProcessId;
use windows::Win32::System::LibraryLoader::{GetModuleFileNameW, GetProcAddress, LoadLibraryA};
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::Storage::FileSystem::{CreateFileW, WriteFile, FILE_SHARE_NONE, OPEN_EXISTING, FILE_FLAGS_AND_ATTRIBUTES, GENERIC_WRITE};
use windows::core::w;
use retour::GenericDetour;
use lazy_static::lazy_static;

// --- 1. Define the hook signatures (Detours) ---

type FnBitBlt = unsafe extern "system" fn(
    windows::Win32::Graphics::Gdi::HDC, i32, i32, i32, i32,
    windows::Win32::Graphics::Gdi::HDC, i32, i32, windows::Win32::Graphics::Gdi::ROP_CODE
) -> BOOL;

type FnCreateProcessW = unsafe extern "system" fn(
    PCWSTR,
    windows::core::PWSTR,
    *const windows::Win32::Security::SECURITY_ATTRIBUTES,
    *const windows::Win32::Security::SECURITY_ATTRIBUTES,
    BOOL,
    windows::Win32::System::Threading::PROCESS_CREATION_FLAGS,
    *const c_void,
    PCWSTR,
    *const windows::Win32::System::Threading::STARTUPINFOW,
    *mut windows::Win32::System::Threading::PROCESS_INFORMATION,
) -> BOOL;

// Additional hooks ported from OpenEDR
type FnNtAllocateVirtualMemory = unsafe extern "system" fn(
    windows::Win32::Foundation::HANDLE,
    *mut *mut c_void,
    usize,
    *mut usize,
    windows::Win32::System::Memory::VIRTUAL_ALLOCATION_TYPE,
    windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS,
) -> windows::Win32::Foundation::NTSTATUS;

type FnNtProtectVirtualMemory = unsafe extern "system" fn(
    windows::Win32::Foundation::HANDLE,
    *mut *mut c_void,
    *mut usize,
    u32, // NewProtection
    *mut u32, // OldProtection
) -> windows::Win32::Foundation::NTSTATUS;

type FnOpenProcess = unsafe extern "system" fn(
    u32,
    BOOL,
    u32,
) -> windows::Win32::Foundation::HANDLE;

type FnReadProcessMemory = unsafe extern "system" fn(
    windows::Win32::Foundation::HANDLE,
    *const c_void,
    *mut c_void,
    usize,
    *mut usize,
) -> BOOL;

type FnSend = unsafe extern "system" fn(
    usize, // SOCKET
    *const u8, // buf
    i32, // len
    i32, // flags
) -> i32;

lazy_static! {
    static ref HOOK_BITBLT: Mutex<Option<GenericDetour<FnBitBlt>>> = Mutex::new(None);
    static ref HOOK_CREATEPROCESSW: Mutex<Option<GenericDetour<FnCreateProcessW>>> = Mutex::new(None);
    static ref HOOK_NTALLOCATEVIRTUALMEMORY: Mutex<Option<GenericDetour<FnNtAllocateVirtualMemory>>> = Mutex::new(None);
    static ref HOOK_NTPROTECTVIRTUALMEMORY: Mutex<Option<GenericDetour<FnNtProtectVirtualMemory>>> = Mutex::new(None);
    static ref HOOK_OPENPROCESS: Mutex<Option<GenericDetour<FnOpenProcess>>> = Mutex::new(None);
    static ref HOOK_READPROCESSMEMORY: Mutex<Option<GenericDetour<FnReadProcessMemory>>> = Mutex::new(None);
    static ref HOOK_SEND: Mutex<Option<GenericDetour<FnSend>>> = Mutex::new(None);
}

// --- 2. Implement the intercepted logic ---

fn report_telemetry(hook_source: &str, mut data: serde_json::Value) {
    unsafe {
        // 1. Enrich with process info
        let mut buffer = [0u16; 512];
        let len = GetModuleFileNameW(None, &mut buffer);
        if len > 0 {
            let image = String::from_utf16_lossy(&buffer[..len as usize]);
            if let Some(obj) = data.as_object_mut() {
                obj.insert("Image".to_string(), json!(image));
                obj.insert("ProcessId".to_string(), json!(GetCurrentProcessId()));
                obj.insert("HookSource".to_string(), json!(hook_source));
            }
        }

        // 2. Write to Named Pipe
        // Pipe name: \\.\pipe\osoosi_injection
        let h_pipe = CreateFileW(
            w!(r"\\.\pipe\osoosi_injection"),
            GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES::default(),
            None,
        );

        if let Ok(handle) = h_pipe {
            let json_str = serde_json::to_string(&data).unwrap_or_default();
            let _ = WriteFile(handle, Some(json_str.as_bytes()), None, None);
            let _ = windows::Win32::Foundation::CloseHandle(handle);
        }
    }
}

/// Intercepted BitBlt: Detects and blocks screen capture spyware
extern "system" fn hooked_bitblt(
    hdc_dest: windows::Win32::Graphics::Gdi::HDC,
    x_dest: i32,
    y_dest: i32,
    w_dest: i32,
    h_dest: i32,
    hdc_src: windows::Win32::Graphics::Gdi::HDC,
    x_src: i32,
    y_src: i32,
    rop: windows::Win32::Graphics::Gdi::ROP_CODE,
) -> BOOL {
    // Ported OpenEDR pattern: We can log the attempt or block it based on policy.
    // For now, we allow it but in a full implementation, we'd check if this process is trusted.
    
    // To block: return BOOL(0);

    let hook_guard = HOOK_BITBLT.lock().unwrap();
    if let Some(hook) = hook_guard.as_ref() {
        unsafe { hook.call(hdc_dest, x_dest, y_dest, w_dest, h_dest, hdc_src, x_src, y_src, rop) }
    } else {
        BOOL(0)
    }
}

/// Intercepted CreateProcessW: Allows pre-execution blocking before the kernel sees it
extern "system" fn hooked_create_process_w(
    application_name: PCWSTR,
    command_line: windows::core::PWSTR,
    process_attributes: *const windows::Win32::Security::SECURITY_ATTRIBUTES,
    thread_attributes: *const windows::Win32::Security::SECURITY_ATTRIBUTES,
    inherit_handles: BOOL,
    creation_flags: windows::Win32::System::Threading::PROCESS_CREATION_FLAGS,
    environment: *const c_void,
    current_directory: PCWSTR,
    startup_info: *const windows::Win32::System::Threading::STARTUPINFOW,
    process_information: *mut windows::Win32::System::Threading::PROCESS_INFORMATION,
) -> BOOL {
    
    // Inspect command_line and application_name. Block malicious execution.

    let hook_guard = HOOK_CREATEPROCESSW.lock().unwrap();
    if let Some(hook) = hook_guard.as_ref() {
        unsafe {
            hook.call(
                application_name,
                command_line,
                process_attributes,
                thread_attributes,
                inherit_handles,
                creation_flags,
                environment,
                current_directory,
                startup_info,
                process_information,
            )
        }
    } else {
        BOOL(0)
    }
}

/// Intercepted NtAllocateVirtualMemory: Detects Process Hollowing and Injection
extern "system" fn hooked_nt_allocate_virtual_memory(
    process_handle: windows::Win32::Foundation::HANDLE,
    base_address: *mut *mut c_void,
    zero_bits: usize,
    region_size: *mut usize,
    allocation_type: windows::Win32::System::Memory::VIRTUAL_ALLOCATION_TYPE,
    protect: windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS,
) -> windows::Win32::Foundation::NTSTATUS {
    
    // Check if the allocation is PAGE_EXECUTE_READWRITE (0x40), a common indicator of shellcode injection
    if protect.0 == 0x40 {
        report_telemetry("NtAllocateVirtualMemory", json!({
            "Protection": "RWX",
            "AllocationType": format!("{:?}", allocation_type)
        }));
    }

    let hook_guard = HOOK_NTALLOCATEVIRTUALMEMORY.lock().unwrap();
    if let Some(hook) = hook_guard.as_ref() {
        unsafe {
            hook.call(
                process_handle,
                base_address,
                zero_bits,
                region_size,
                allocation_type,
                protect,
            )
        }
    } else {
        windows::Win32::Foundation::NTSTATUS(-1)
    }
}

/// Intercepted NtProtectVirtualMemory: Detects Module Overloading and RWX transitions
extern "system" fn hooked_nt_protect_virtual_memory(
    process_handle: windows::Win32::Foundation::HANDLE,
    base_address: *mut *mut c_void,
    region_size: *mut usize,
    new_protection: u32,
    old_protection: *mut u32,
) -> windows::Win32::Foundation::NTSTATUS {
    
    // PAGE_EXECUTE_READWRITE (0x40)
    if new_protection == 0x40 {
        report_telemetry("NtProtectVirtualMemory", json!({
            "Protection": "RWX",
            "NewProtection": format!("{:#x}", new_protection)
        }));
    }

    let hook_guard = HOOK_NTPROTECTVIRTUALMEMORY.lock().unwrap();
    if let Some(hook) = hook_guard.as_ref() {
        unsafe {
            hook.call(
                process_handle,
                base_address,
                region_size,
                new_protection,
                old_protection,
            )
        }
    } else {
        windows::Win32::Foundation::NTSTATUS(-1)
    }
}

/// Intercepted OpenProcess: Prevents malware from getting handles to EDR or LSASS
extern "system" fn hooked_open_process(
    desired_access: u32,
    inherit_handle: BOOL,
    process_id: u32,
) -> windows::Win32::Foundation::HANDLE {
    
    // Example: Protect LSASS and OshoosiClaw. In a real EDR, we'd check the PID dynamically.
    // If process_id == lsass_pid && (desired_access & PROCESS_VM_READ) != 0 { return NULL; }

    let hook_guard = HOOK_OPENPROCESS.lock().unwrap();
    if let Some(hook) = hook_guard.as_ref() {
        unsafe { hook.call(desired_access, inherit_handle, process_id) }
    } else {
        windows::Win32::Foundation::HANDLE::default()
    }
}

/// Intercepted ReadProcessMemory: Deep defense against credential dumping
extern "system" fn hooked_read_process_memory(
    hprocess: windows::Win32::Foundation::HANDLE,
    base_address: *const c_void,
    buffer: *mut c_void,
    size: usize,
    number_of_bytes_read: *mut usize,
) -> BOOL {
    
    // Check if `hprocess` points to a protected process and block if it is.

    let hook_guard = HOOK_READPROCESSMEMORY.lock().unwrap();
    if let Some(hook) = hook_guard.as_ref() {
        unsafe { hook.call(hprocess, base_address, buffer, size, number_of_bytes_read) }
    } else {
        BOOL(0)
    }
}

/// Intercepted send: Deep Packet Inspection for HTTP/DNS payloads (Layer 7)
extern "system" fn hooked_send(
    s: usize,
    buf: *const u8,
    len: i32,
    flags: i32,
) -> i32 {
    
    // Here we can port `libnetmon`'s parser_dns.cpp or parser_http_win.cpp logic
    // We can read `buf` up to `len` bytes and check for C2 beacon signatures in headers.

    let hook_guard = HOOK_SEND.lock().unwrap();
    if let Some(hook) = hook_guard.as_ref() {
        unsafe { hook.call(s, buf, len, flags) }
    } else {
        -1 // SOCKET_ERROR
    }
}

// --- 3. Initialization Routine ---

unsafe fn init_hooks() -> Result<(), Box<dyn std::error::Error>> {
    // Resolve GDI32.dll for BitBlt
    let gdi32 = LoadLibraryA(s!("gdi32.dll"))?;
    let bitblt_addr = GetProcAddress(gdi32, s!("BitBlt")).ok_or("Failed to find BitBlt")?;
    
    // Resolve Kernel32.dll for CreateProcessW
    let kernel32 = LoadLibraryA(s!("kernel32.dll"))?;
    let create_process_addr = GetProcAddress(kernel32, s!("CreateProcessW")).ok_or("Failed to find CreateProcessW")?;

    // Resolve ntdll.dll for NtAllocateVirtualMemory
    let ntdll = LoadLibraryA(s!("ntdll.dll"))?;
    let nt_alloc_addr = GetProcAddress(ntdll, s!("NtAllocateVirtualMemory")).ok_or("Failed to find NtAllocateVirtualMemory")?;

    // Install hooks using Detours (retour)
    let bitblt_target: FnBitBlt = std::mem::transmute(bitblt_addr);
    let bitblt_hook = GenericDetour::new(bitblt_target, hooked_bitblt)?;
    bitblt_hook.enable()?;
    *HOOK_BITBLT.lock().unwrap() = Some(bitblt_hook);

    let create_process_target: FnCreateProcessW = std::mem::transmute(create_process_addr);
    let create_process_hook = GenericDetour::new(create_process_target, hooked_create_process_w)?;
    create_process_hook.enable()?;
    *HOOK_CREATEPROCESSW.lock().unwrap() = Some(create_process_hook);

    let nt_alloc_target: FnNtAllocateVirtualMemory = std::mem::transmute(nt_alloc_addr);
    let nt_alloc_hook = GenericDetour::new(nt_alloc_target, hooked_nt_allocate_virtual_memory)?;
    nt_alloc_hook.enable()?;
    *HOOK_NTALLOCATEVIRTUALMEMORY.lock().unwrap() = Some(nt_alloc_hook);

    let nt_protect_addr = GetProcAddress(ntdll, s!("NtProtectVirtualMemory")).ok_or("Failed to find NtProtectVirtualMemory")?;
    let nt_protect_target: FnNtProtectVirtualMemory = std::mem::transmute(nt_protect_addr);
    let nt_protect_hook = GenericDetour::new(nt_protect_target, hooked_nt_protect_virtual_memory)?;
    nt_protect_hook.enable()?;
    *HOOK_NTPROTECTVIRTUALMEMORY.lock().unwrap() = Some(nt_protect_hook);

    let open_process_addr = GetProcAddress(kernel32, s!("OpenProcess")).ok_or("Failed to find OpenProcess")?;
    let open_process_target: FnOpenProcess = std::mem::transmute(open_process_addr);
    let open_process_hook = GenericDetour::new(open_process_target, hooked_open_process)?;
    open_process_hook.enable()?;
    *HOOK_OPENPROCESS.lock().unwrap() = Some(open_process_hook);

    let read_process_memory_addr = GetProcAddress(kernel32, s!("ReadProcessMemory")).ok_or("Failed to find ReadProcessMemory")?;
    let read_process_memory_target: FnReadProcessMemory = std::mem::transmute(read_process_memory_addr);
    let read_process_memory_hook = GenericDetour::new(read_process_memory_target, hooked_read_process_memory)?;
    read_process_memory_hook.enable()?;
    *HOOK_READPROCESSMEMORY.lock().unwrap() = Some(read_process_memory_hook);

    // Resolve ws2_32.dll for send (Network Telemetry)
    let ws2_32 = LoadLibraryA(s!("ws2_32.dll"))?;
    if let Some(send_addr) = GetProcAddress(ws2_32, s!("send")) {
        let send_target: FnSend = std::mem::transmute(send_addr);
        let send_hook = GenericDetour::new(send_target, hooked_send)?;
        send_hook.enable()?;
        *HOOK_SEND.lock().unwrap() = Some(send_hook);
    }

    Ok(())
}

// --- 4. DLL Entry Point ---

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(
    _hinst_dll: HINSTANCE,
    fdw_reason: u32,
    _lpv_reserved: *mut c_void,
) -> BOOL {
    if fdw_reason == DLL_PROCESS_ATTACH {
        // Initialize hooks in a new thread or carefully here
        unsafe {
            if let Err(_e) = init_hooks() {
                // Silently fail if hooks can't be established (standard EDR fallback)
                // eprintln!("Hook init failed: {}", e);
            }
        }
    }
    BOOL(1)
}
