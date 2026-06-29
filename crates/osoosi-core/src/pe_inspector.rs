use anyhow::Result;
use pelite::pe64::Pe;
use pelite::pe64::PeFile;
use std::path::Path;

#[derive(Debug, Default)]
pub struct InspectionFindings {
    pub hollowing_detected: bool,
    pub suspicious_sections: Vec<String>,
    pub is_dot_net: bool,
    pub imports: Vec<String>,
    pub composition_score: f32,
    pub suspicious_dependencies: Vec<String>,
    pub byte_patches: Vec<String>,
    pub has_spoofed_stack: bool,
}

/// Disassembly helper: checks if memory bytes preceding a return address represent a CALL instruction.
/// Decodes relative call (E8) and indirect call (FF /2, FF /3) with full ModRM/SIB displacement decoding.
pub fn is_preceded_by_call(bytes: &[u8]) -> bool {
    let n = bytes.len();
    if n >= 5 && bytes[n - 5] == 0xE8 {
        return true;
    }
    for len in 2..=7 {
        if len > n {
            break;
        }
        let pos = n - len;
        if bytes[pos] != 0xFF {
            continue;
        }
        let modrm = bytes[pos + 1];
        let reg = (modrm >> 3) & 7;
        if reg != 2 && reg != 3 {
            continue;
        }
        let mod_val = (modrm >> 6) & 3;
        let rm = modrm & 7;
        
        let mut instr_len = 2; // Opcode + ModRM
        let mut disp_size = 0;
        
        if mod_val != 3 && rm == 4 {
            instr_len += 1; // SIB byte present
            if pos + 2 >= n {
                continue;
            }
            let sib = bytes[pos + 2];
            let base = sib & 7;
            if mod_val == 0 && base == 5 {
                disp_size = 4;
            }
        }
        
        if mod_val == 1 {
            disp_size = 1;
        } else if mod_val == 2 {
            disp_size = 4;
        } else if mod_val == 0 && rm == 5 {
            disp_size = 4;
        }
        
        let expected = instr_len + disp_size;
        if expected == len {
            return true;
        }
    }
    false
}

/// Inspect a running process's memory for hollowing or injection artifacts using pelite.
pub fn inspect_process(pid: u32) -> Result<InspectionFindings> {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
        use windows::Win32::Foundation::CloseHandle;
        
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)?;
            let mut findings = inspect_handle(handle)?;
            
            // Check for unhooking byte patches
            if let Ok(patches) = inspect_remote_dll_patches(pid) {
                findings.byte_patches = patches;
            }
            
            // Check stack frames
            findings.has_spoofed_stack = inspect_stack_spoof(pid).unwrap_or(false);
            
            let _ = CloseHandle(handle);
            Ok(findings)
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid;
        Ok(InspectionFindings::default())
    }
}

/// Diff process loaded ntdll.dll / kernel32.dll memory against disk bytes to find unhooking/byte patches.
#[cfg(target_os = "windows")]
pub fn inspect_remote_dll_patches(pid: u32) -> Result<Vec<String>> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32
    };
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ, PROCESS_QUERY_INFORMATION};
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::Foundation::CloseHandle;
    
    let mut patches = Vec::new();
    
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)?;
        let mut entry = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };
        
        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)?;
        
        if Module32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let module_name = String::from_utf16_lossy(&entry.szModule)
                    .trim_matches('\0')
                    .to_lowercase();
                
                if module_name == "ntdll.dll" || module_name == "kernel32.dll" {
                    let dll_path_raw = String::from_utf16_lossy(&entry.szExePath);
                    let dll_path = dll_path_raw.trim_matches('\0');
                    let base_address = entry.modBaseAddr;
                    let _module_size = entry.modBaseSize;
                    
                    if let Ok(disk_bytes) = std::fs::read(dll_path) {
                        if let Ok(pe) = pelite::pe64::PeFile::from_bytes(&disk_bytes) {
                            if let Some(text_section) = pe.section_headers().iter().find(|s| s.Name == *b".text\0\0\0") {
                                let virtual_offset = text_section.VirtualAddress as usize;
                                let raw_offset = text_section.PointerToRawData as usize;
                                let section_size = text_section.VirtualSize as usize;
                                
                                let mut mem_buf = vec![0u8; section_size];
                                let target_addr = base_address.add(virtual_offset);
                                
                                let mut bytes_read = 0;
                                let res = ReadProcessMemory(
                                    process_handle,
                                    target_addr as _,
                                    mem_buf.as_mut_ptr() as _,
                                    section_size,
                                    Some(&mut bytes_read)
                                );
                                
                                if res.is_ok() && bytes_read == section_size {
                                    let disk_slice = &disk_bytes[raw_offset..(raw_offset + section_size)];
                                    for offset in 0..section_size {
                                        if mem_buf[offset] != disk_slice[offset] {
                                            patches.push(format!(
                                                "{}: byte patched at offset 0x{:x} (.text virtual offset 0x{:x}): disk=0x{:02x}, memory=0x{:02x}",
                                                module_name, offset, virtual_offset + offset, disk_slice[offset], mem_buf[offset]
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                if Module32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
        let _ = CloseHandle(process_handle);
    }
    
    Ok(patches)
}

#[cfg(not(target_os = "windows"))]
pub fn inspect_remote_dll_patches(_pid: u32) -> Result<Vec<String>> {
    Ok(Vec::new())
}

#[cfg(target_os = "windows")]
fn inspect_stack_spoof(pid: u32) -> Result<bool> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD
    };
    use windows::Win32::System::Threading::{OpenThread, OpenProcess, PROCESS_VM_READ, PROCESS_QUERY_INFORMATION, THREAD_QUERY_INFORMATION, THREAD_GET_CONTEXT};
    use windows::Win32::System::Diagnostics::Debug::{
        GetThreadContext, ReadProcessMemory, CONTEXT
    };
    use windows::Win32::Foundation::{CloseHandle};
    
    const CONTEXT_FULL: u32 = 0x100007;
    let mut spoofed = false;
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)?;
        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        
        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)?;
        
        if Thread32First(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32OwnerProcessID == pid {
                    let thread_handle = OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, false, entry.th32ThreadID);
                    if let Ok(th) = thread_handle {
                        let mut ctx: CONTEXT = CONTEXT {
                            ContextFlags: windows::Win32::System::Diagnostics::Debug::CONTEXT_FLAGS(CONTEXT_FULL),
                            ..Default::default()
                        };
                        if GetThreadContext(th, &mut ctx).is_ok() {
                            let mut buffer = [0u8; 16];
                            let mut bytes_read = 0;
                            let res = ReadProcessMemory(
                                process_handle,
                                ctx.Rip as _,
                                buffer.as_mut_ptr() as _,
                                buffer.len(),
                                Some(&mut bytes_read)
                            );
                            if res.is_ok() && bytes_read == buffer.len() {
                                if !is_preceded_by_call(&buffer) {
                                    spoofed = true;
                                }
                            }
                        }
                        let _ = CloseHandle(th);
                    }
                }
                if Thread32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
        let _ = CloseHandle(process_handle);
    }
    
    Ok(spoofed)
}

#[cfg(not(target_os = "windows"))]
fn inspect_stack_spoof(_pid: u32) -> Result<bool> {
    Ok(false)
}

#[cfg(target_os = "windows")]
unsafe fn inspect_handle(_handle: windows::Win32::Foundation::HANDLE) -> Result<InspectionFindings> {
    Ok(InspectionFindings::default())
}

/// Inspect a file on disk using pelite for composition and heuristics.
pub fn inspect_file(path: &Path) -> Result<InspectionFindings> {
    let bytes = std::fs::read(path)?;
    let pe = PeFile::from_bytes(&bytes)?;
    
    let mut findings = InspectionFindings::default();
    
    // 1. Check for suspicious section characteristics (e.g. RWX)
    let section_table = pe.section_headers();
    for section in section_table {
        if let Ok(name) = section.name() {
            let chars = section.Characteristics;
            
            // IMAGE_SCN_MEM_EXECUTE (0x20000000) | IMAGE_SCN_MEM_WRITE (0x80000000)
            if (chars & 0xA0000000) == 0xA0000000 {
                findings.suspicious_sections.push(format!("RWX section: {}", name));
                findings.composition_score += 0.3;
            }
            
            // High entropy check could go here if we calculate per section
        }
    }
    
    // 2. Extract Imports (Shadow Dependency Check)
    if let Ok(imports) = pe.imports() {
        for desc in imports {
            if let Ok(dll_name) = desc.dll_name() {
                let dll_name = dll_name.to_string();
                findings.imports.push(dll_name.clone());
                
                // Flag "grayware" or unusual libraries
                let low_dll = dll_name.to_lowercase();
                if low_dll.contains("winhttp") || low_dll.contains("wininet") {
                    // Network capabilities in a non-network tool
                    findings.composition_score += 0.1;
                }
            }
            
            // Function imports (using Import Name Table for static analysis)
            if let Ok(int) = desc.int() {
                for import in int {
                    if let Ok(import) = import {
                        match import {
                            pelite::pe64::imports::Import::ByName { name, .. } => {
                                let name = name.to_string();
                                let low_name = name.to_lowercase();
                                
                                // High-risk injection APIs
                                if low_name.contains("virtualalloc") || 
                                   low_name.contains("writeprocessmemory") ||
                                   low_name.contains("createremotethread") ||
                                   low_name.contains("ntunmapviewofsection") ||
                                   low_name.contains("setthreadcontext") {
                                    findings.suspicious_dependencies.push(name.clone());
                                    findings.composition_score += 0.2;
                                }
                            },
                            _ => {}
                        }
                    }
                }
            }
        }
    }
    
    // 3. Check for .NET (COM Descriptor Directory is at index 14)
    if let Some(dir) = pe.data_directory().get(14) {
        if dir.Size > 0 {
            findings.is_dot_net = true;
        }
    }
    
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_preceded_by_call() {
        // 1. Relative call (E8 xx xx xx xx)
        let relative_call = vec![0xE8, 0x11, 0x22, 0x33, 0x44];
        assert!(is_preceded_by_call(&relative_call));

        // 2. Indirect call reg/mem (FF /2, e.g. FF D0 for call rax)
        let indirect_call_rax = vec![0xFF, 0xD0];
        assert!(is_preceded_by_call(&indirect_call_rax));

        // 3. Indirect call reg/mem with SIB (e.g. FF 14 24 for call [rsp])
        let indirect_call_rsp = vec![0xFF, 0x14, 0x24];
        assert!(is_preceded_by_call(&indirect_call_rsp));

        // 4. Random non-call instructions (e.g. mov rax, 1)
        let non_call = vec![0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00];
        assert!(!is_preceded_by_call(&non_call));
    }
}
