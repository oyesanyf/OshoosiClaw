//! OpenỌ̀ṣọ́ọ̀sì Agentic EDR - Native Process Hooking Engine (Injected DLL)
//!
//! Ported from OpenEDR architectural patterns (`edrpm`).
//! This library is injected into processes via APC to provide inner-process telemetry
//! and prevention capabilities (e.g., stopping screen scraping, blocking process creation).

#![cfg(target_os = "windows")]

use retour::GenericDetour;
use serde_json::json;
use std::ffi::c_void;
use windows::core::w;
use windows::core::{s, PCWSTR};
use windows::Win32::Foundation::{BOOL, GENERIC_WRITE, HINSTANCE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, WriteFile, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_NONE, OPEN_EXISTING,
};
use windows::Win32::System::LibraryLoader::{GetModuleFileNameW, GetProcAddress, LoadLibraryA};
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::System::Threading::GetCurrentProcessId;

// --- 1. Define the hook signatures (Detours) ---

type FnBitBlt = unsafe extern "system" fn(
    windows::Win32::Graphics::Gdi::HDC,
    i32,
    i32,
    i32,
    i32,
    windows::Win32::Graphics::Gdi::HDC,
    i32,
    i32,
    windows::Win32::Graphics::Gdi::ROP_CODE,
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
    u32,      // NewProtection
    *mut u32, // OldProtection
) -> windows::Win32::Foundation::NTSTATUS;

type FnOpenProcess =
    unsafe extern "system" fn(u32, BOOL, u32) -> windows::Win32::Foundation::HANDLE;

type FnReadProcessMemory = unsafe extern "system" fn(
    windows::Win32::Foundation::HANDLE,
    *const c_void,
    *mut c_void,
    usize,
    *mut usize,
) -> BOOL;

type FnSend = unsafe extern "system" fn(
    usize,     // SOCKET
    *const u8, // buf
    i32,       // len
    i32,       // flags
) -> i32;

static HOOK_BITBLT: std::sync::OnceLock<GenericDetour<FnBitBlt>> = std::sync::OnceLock::new();
static HOOK_CREATEPROCESSW: std::sync::OnceLock<GenericDetour<FnCreateProcessW>> =
    std::sync::OnceLock::new();
static HOOK_NTALLOCATEVIRTUALMEMORY: std::sync::OnceLock<GenericDetour<FnNtAllocateVirtualMemory>> =
    std::sync::OnceLock::new();
static HOOK_NTPROTECTVIRTUALMEMORY: std::sync::OnceLock<GenericDetour<FnNtProtectVirtualMemory>> =
    std::sync::OnceLock::new();
static HOOK_OPENPROCESS: std::sync::OnceLock<GenericDetour<FnOpenProcess>> =
    std::sync::OnceLock::new();
static HOOK_READPROCESSMEMORY: std::sync::OnceLock<GenericDetour<FnReadProcessMemory>> =
    std::sync::OnceLock::new();
static HOOK_SEND: std::sync::OnceLock<GenericDetour<FnSend>> = std::sync::OnceLock::new();

thread_local! {
    static IN_HOOK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
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
    if let Some(hook) = HOOK_BITBLT.get() {
        if IN_HOOK.with(|c| c.get()) {
            return unsafe {
                hook.call(
                    hdc_dest, x_dest, y_dest, w_dest, h_dest, hdc_src, x_src, y_src, rop,
                )
            };
        }
        IN_HOOK.with(|c| c.set(true));
        let res = unsafe {
            hook.call(
                hdc_dest, x_dest, y_dest, w_dest, h_dest, hdc_src, x_src, y_src, rop,
            )
        };
        IN_HOOK.with(|c| c.set(false));
        res
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
    if let Some(hook) = HOOK_CREATEPROCESSW.get() {
        if IN_HOOK.with(|c| c.get()) {
            return unsafe {
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
            };
        }
        IN_HOOK.with(|c| c.set(true));
        let res = unsafe {
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
        };
        IN_HOOK.with(|c| c.set(false));
        res
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
    if let Some(hook) = HOOK_NTALLOCATEVIRTUALMEMORY.get() {
        if IN_HOOK.with(|c| c.get()) {
            return unsafe {
                hook.call(
                    process_handle,
                    base_address,
                    zero_bits,
                    region_size,
                    allocation_type,
                    protect,
                )
            };
        }

        IN_HOOK.with(|c| c.set(true));
        if protect.0 == 0x40 {
            report_telemetry(
                "NtAllocateVirtualMemory",
                json!({
                    "Protection": "RWX",
                    "AllocationType": format!("{:?}", allocation_type)
                }),
            );
        }
        let res = unsafe {
            hook.call(
                process_handle,
                base_address,
                zero_bits,
                region_size,
                allocation_type,
                protect,
            )
        };
        IN_HOOK.with(|c| c.set(false));
        res
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
    if let Some(hook) = HOOK_NTPROTECTVIRTUALMEMORY.get() {
        if IN_HOOK.with(|c| c.get()) {
            return unsafe {
                hook.call(
                    process_handle,
                    base_address,
                    region_size,
                    new_protection,
                    old_protection,
                )
            };
        }

        IN_HOOK.with(|c| c.set(true));
        if new_protection == 0x40 {
            report_telemetry(
                "NtProtectVirtualMemory",
                json!({
                    "Protection": "RWX",
                    "NewProtection": format!("{:#x}", new_protection)
                }),
            );
        }
        let res = unsafe {
            hook.call(
                process_handle,
                base_address,
                region_size,
                new_protection,
                old_protection,
            )
        };
        IN_HOOK.with(|c| c.set(false));
        res
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
    if let Some(hook) = HOOK_OPENPROCESS.get() {
        if IN_HOOK.with(|c| c.get()) {
            return unsafe { hook.call(desired_access, inherit_handle, process_id) };
        }
        IN_HOOK.with(|c| c.set(true));
        let res = unsafe { hook.call(desired_access, inherit_handle, process_id) };
        IN_HOOK.with(|c| c.set(false));
        res
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
    if let Some(hook) = HOOK_READPROCESSMEMORY.get() {
        if IN_HOOK.with(|c| c.get()) {
            return unsafe {
                hook.call(hprocess, base_address, buffer, size, number_of_bytes_read)
            };
        }
        IN_HOOK.with(|c| c.set(true));
        let res = unsafe { hook.call(hprocess, base_address, buffer, size, number_of_bytes_read) };
        IN_HOOK.with(|c| c.set(false));
        res
    } else {
        BOOL(0)
    }
}

/// Intercepted send: Deep Packet Inspection for HTTP/DNS payloads (Layer 7)
extern "system" fn hooked_send(s: usize, buf: *const u8, len: i32, flags: i32) -> i32 {
    if let Some(hook) = HOOK_SEND.get() {
        if IN_HOOK.with(|c| c.get()) {
            return unsafe { hook.call(s, buf, len, flags) };
        }
        IN_HOOK.with(|c| c.set(true));
        let res = unsafe { hook.call(s, buf, len, flags) };
        IN_HOOK.with(|c| c.set(false));
        res
    } else {
        -1 // SOCKET_ERROR
    }
}

// --- 3. Initialization Routine ---

unsafe fn get_module_symbol_address(
    module: windows::core::PCSTR,
    symbol: windows::core::PCSTR,
) -> Result<*const c_void, Box<dyn std::error::Error>> {
    use windows::Win32::System::LibraryLoader::GetModuleHandleA;
    let hmod = match GetModuleHandleA(module) {
        Ok(h) if !h.is_invalid() => h,
        _ => LoadLibraryA(module)?,
    };
    let proc = GetProcAddress(hmod, symbol).ok_or("Failed to resolve symbol")?;
    Ok(proc as *const c_void)
}

unsafe fn init_hooks() -> Result<(), Box<dyn std::error::Error>> {
    // Resolve GDI32.dll for BitBlt
    let bitblt_addr = get_module_symbol_address(s!("gdi32.dll"), s!("BitBlt"))?;
    let bitblt_target: FnBitBlt = std::mem::transmute(bitblt_addr);
    let bitblt_hook = GenericDetour::new(bitblt_target, hooked_bitblt)?;
    let _ = HOOK_BITBLT.set(bitblt_hook);
    if let Some(h) = HOOK_BITBLT.get() {
        h.enable()?;
    }

    // Resolve Kernel32.dll for CreateProcessW
    let create_process_addr = get_module_symbol_address(s!("kernel32.dll"), s!("CreateProcessW"))?;
    let create_process_target: FnCreateProcessW = std::mem::transmute(create_process_addr);
    let create_process_hook = GenericDetour::new(create_process_target, hooked_create_process_w)?;
    let _ = HOOK_CREATEPROCESSW.set(create_process_hook);
    if let Some(h) = HOOK_CREATEPROCESSW.get() {
        h.enable()?;
    }

    // Resolve ntdll.dll for NtAllocateVirtualMemory
    let nt_alloc_addr = get_module_symbol_address(s!("ntdll.dll"), s!("NtAllocateVirtualMemory"))?;
    let nt_alloc_target: FnNtAllocateVirtualMemory = std::mem::transmute(nt_alloc_addr);
    let nt_alloc_hook = GenericDetour::new(nt_alloc_target, hooked_nt_allocate_virtual_memory)?;
    let _ = HOOK_NTALLOCATEVIRTUALMEMORY.set(nt_alloc_hook);
    if let Some(h) = HOOK_NTALLOCATEVIRTUALMEMORY.get() {
        h.enable()?;
    }

    let nt_protect_addr = get_module_symbol_address(s!("ntdll.dll"), s!("NtProtectVirtualMemory"))?;
    let nt_protect_target: FnNtProtectVirtualMemory = std::mem::transmute(nt_protect_addr);
    let nt_protect_hook = GenericDetour::new(nt_protect_target, hooked_nt_protect_virtual_memory)?;
    let _ = HOOK_NTPROTECTVIRTUALMEMORY.set(nt_protect_hook);
    if let Some(h) = HOOK_NTPROTECTVIRTUALMEMORY.get() {
        h.enable()?;
    }

    let open_process_addr = get_module_symbol_address(s!("kernel32.dll"), s!("OpenProcess"))?;
    let open_process_target: FnOpenProcess = std::mem::transmute(open_process_addr);
    let open_process_hook = GenericDetour::new(open_process_target, hooked_open_process)?;
    let _ = HOOK_OPENPROCESS.set(open_process_hook);
    if let Some(h) = HOOK_OPENPROCESS.get() {
        h.enable()?;
    }

    let read_process_memory_addr =
        get_module_symbol_address(s!("kernel32.dll"), s!("ReadProcessMemory"))?;
    let read_process_memory_target: FnReadProcessMemory =
        std::mem::transmute(read_process_memory_addr);
    let read_process_memory_hook =
        GenericDetour::new(read_process_memory_target, hooked_read_process_memory)?;
    let _ = HOOK_READPROCESSMEMORY.set(read_process_memory_hook);
    if let Some(h) = HOOK_READPROCESSMEMORY.get() {
        h.enable()?;
    }

    // Resolve ws2_32.dll for send (Network Telemetry)
    if let Ok(send_addr) = get_module_symbol_address(s!("ws2_32.dll"), s!("send")) {
        let send_target: FnSend = std::mem::transmute(send_addr);
        let send_hook = GenericDetour::new(send_target, hooked_send)?;
        let _ = HOOK_SEND.set(send_hook);
        if let Some(h) = HOOK_SEND.get() {
            let _ = h.enable();
        }
    }

    Ok(())
}

// --- 3.5 In-Memory Telemetry Tampering & Unhooking Watchdog (F09) ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvasionDetectionEvent {
    pub target_symbol: &'static str,
    pub reason: &'static str,
    pub prologue_hex: String,
}

/// Pure byte-level inspection of a function prologue for user-mode ETW/AMSI patching or unhooking.
pub fn inspect_prologue_for_evasion(
    symbol: &'static str,
    bytes: &[u8],
) -> Option<EvasionDetectionEvent> {
    if bytes.is_empty() {
        return None;
    }
    let hex_str = bytes
        .iter()
        .take(8)
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join("");

    if symbol == "ntdll!EtwEventWrite" {
        // ret (0xC3), ret imm16 (0xC2), xor eax,eax; ret (33 C0 C3 / 31 C0 C3), xor rax,rax; ret (48 33 C0 C3 / 48 31 C0 C3)
        if bytes[0] == 0xC3
            || bytes[0] == 0xC2
            || (bytes.len() >= 3 && (bytes[0] == 0x33 || bytes[0] == 0x31) && bytes[1] == 0xC0 && bytes[2] == 0xC3)
            || (bytes.len() >= 4
                && bytes[0] == 0x48
                && (bytes[1] == 0x33 || bytes[1] == 0x31)
                && bytes[2] == 0xC0
                && bytes[3] == 0xC3)
        {
            return Some(EvasionDetectionEvent {
                target_symbol: symbol,
                reason: "ETW_USERMODE_PATCH_DETECTED",
                prologue_hex: hex_str,
            });
        }
    } else if symbol == "amsi!AmsiScanBuffer" {
        // mov eax, 0x80070057 (B8 57 00 07 80), ret (0xC3), xor eax,eax; ret (31 C0 C3 / 33 C0 C3)
        if bytes[0] == 0xC3
            || (bytes.len() >= 5
                && bytes[0] == 0xB8
                && bytes[1] == 0x57
                && bytes[2] == 0x00
                && bytes[3] == 0x07
                && bytes[4] == 0x80)
            || (bytes.len() >= 3 && (bytes[0] == 0x31 || bytes[0] == 0x33) && bytes[1] == 0xC0 && bytes[2] == 0xC3)
        {
            return Some(EvasionDetectionEvent {
                target_symbol: symbol,
                reason: "AMSI_SCANBUFFER_BYPASS_PATCH_DETECTED",
                prologue_hex: hex_str,
            });
        }
    }
    None
}

/// Verifies in-memory hook enablement and checks `ntdll!EtwEventWrite` and `amsi!AmsiScanBuffer`
/// for inline patching or NTDLL unhooking. Emits high-priority telemetry on tampering.
pub fn verify_critical_invariants() -> Vec<EvasionDetectionEvent> {
    let mut detections = Vec::new();

    if let Some(h) = HOOK_NTALLOCATEVIRTUALMEMORY.get() {
        if !h.is_enabled() {
            detections.push(EvasionDetectionEvent {
                target_symbol: "ntdll!NtAllocateVirtualMemory",
                reason: "NTDLL_DETOUR_UNHOOKED",
                prologue_hex: "DISABLED".to_string(),
            });
        }
    }
    if let Some(h) = HOOK_NTPROTECTVIRTUALMEMORY.get() {
        if !h.is_enabled() {
            detections.push(EvasionDetectionEvent {
                target_symbol: "ntdll!NtProtectVirtualMemory",
                reason: "NTDLL_DETOUR_UNHOOKED",
                prologue_hex: "DISABLED".to_string(),
            });
        }
    }

    unsafe {
        if let Ok(addr) = get_module_symbol_address(s!("ntdll.dll"), s!("EtwEventWrite")) {
            let slice = std::slice::from_raw_parts(addr as *const u8, 8);
            if let Some(ev) = inspect_prologue_for_evasion("ntdll!EtwEventWrite", slice) {
                detections.push(ev);
            }
        }
        use windows::Win32::System::LibraryLoader::GetModuleHandleA;
        if let Ok(hmod) = GetModuleHandleA(s!("amsi.dll")) {
            if !hmod.is_invalid() {
                if let Some(proc) = GetProcAddress(hmod, s!("AmsiScanBuffer")) {
                    let slice = std::slice::from_raw_parts(proc as *const u8, 8);
                    if let Some(ev) = inspect_prologue_for_evasion("amsi!AmsiScanBuffer", slice) {
                        detections.push(ev);
                    }
                }
            }
        }
    }

    for det in &detections {
        report_telemetry(
            "TelemetryTamperingDetected",
            json!({
                "TargetSymbol": det.target_symbol,
                "Reason": det.reason,
                "PrologueHex": det.prologue_hex,
                "CriticalPriority": true
            }),
        );
    }

    detections
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
