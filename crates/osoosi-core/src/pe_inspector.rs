use anyhow::Result;
#[cfg(target_os = "windows")]
use pelite::pe64::Pe;
#[cfg(target_os = "windows")]
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
    pub magika_label: String,
    pub magika_mime_type: String,
    pub is_verified_rust_test_harness: bool,
    pub rdata_only_adversarial_test_vectors: Vec<String>,
}

/// Structural provenance analysis for compiled Rust test binaries (`cargo test` / `target/*/deps/*`).
///
/// Solves the Windows Smart App Control (`os error 4551`) / EDR false-positive dilemma without using
/// lazy directory path exclusions:
/// - Verifies whether a PE/ELF binary has genuine Rust compiler + `libtest` harness markers,
/// - Maps every PE section's raw file range and memory permissions (`IMAGE_SCN_MEM_READ` vs `IMAGE_SCN_MEM_EXECUTE`),
/// - Verifies whether embedded adversarial test strings (`; cat /etc/passwd | calc.exe`, `../../../../windows/system32`,
///   `..\\..\\..\\boot.ini`, `DROP TABLE `) reside **strictly inside read-only data sections (`.rdata` / `.rodata`)**
///   with zero high-risk process-injection / hollowing imports and zero RWX sections.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeTestHarnessProvenance {
    pub has_rust_compiler_provenance: bool,
    pub has_rust_test_harness_symbols: bool,
    pub has_rwx_or_writable_code_section: bool,
    pub has_injection_imports: bool,
    pub rdata_test_vector_hits: Vec<String>,
    pub executable_section_vector_hits: Vec<String>,
    pub is_verified_benign_rust_test_harness: bool,
}

/// Inspect a PE or ELF binary's section table, symbol markers, and read-only `.rdata`/`.rodata` ranges
/// to determine if embedded exploit strings are static unit-test vectors inside a genuine Rust test binary.
pub fn classify_pe_rust_test_harness_provenance(bytes: &[u8]) -> PeTestHarnessProvenance {
    let mut report = PeTestHarnessProvenance::default();
    if bytes.len() < 64 {
        return report;
    }

    let find_subslice = |haystack: &[u8], needle: &[u8]| -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    };

    report.has_rust_compiler_provenance = find_subslice(bytes, b"rustc 1.").is_some()
        || find_subslice(bytes, b".dep-v0").is_some()
        || find_subslice(bytes, b"rust_begin_unwind").is_some()
        || find_subslice(bytes, b"/cargo/registry/src/").is_some()
        || find_subslice(bytes, b"\\cargo\\registry\\src\\").is_some();

    report.has_rust_test_harness_symbols = find_subslice(bytes, b"test::run_test").is_some()
        || find_subslice(bytes, b"run_tests_console").is_some()
        || find_subslice(bytes, b"test_main_static").is_some()
        || find_subslice(bytes, b"__rust_begin_short_backtrace").is_some()
        || find_subslice(bytes, b"running 1 test").is_some()
        || find_subslice(bytes, b"test result: ").is_some();

    let mut rdata_ranges: Vec<(usize, usize)> = Vec::new();
    let mut exec_ranges: Vec<(usize, usize)> = Vec::new();

    if let Ok(pe) = goblin::pe::PE::parse(bytes) {
        for sec in &pe.sections {
            let name = String::from_utf8_lossy(&sec.name)
                .trim_matches('\0')
                .to_ascii_lowercase();
            let raw_start = sec.pointer_to_raw_data as usize;
            let raw_size = sec.size_of_raw_data as usize;
            let raw_end = raw_start.saturating_add(raw_size).min(bytes.len());
            let chars = sec.characteristics;

            let is_exec = (chars & 0x2000_0000) != 0; // IMAGE_SCN_MEM_EXECUTE
            let is_write = (chars & 0x8000_0000) != 0; // IMAGE_SCN_MEM_WRITE
            if is_exec && is_write {
                report.has_rwx_or_writable_code_section = true;
            }
            if raw_start < raw_end {
                if is_exec {
                    exec_ranges.push((raw_start, raw_end));
                } else if !is_write && (name.starts_with(".rdata") || name.starts_with(".rodata")) {
                    rdata_ranges.push((raw_start, raw_end));
                }
            }
        }

        for imp in &pe.imports {
            let low = imp.name.to_ascii_lowercase();
            if low.contains("virtualallocex")
                || low.contains("writeprocessmemory")
                || low.contains("createremotethread")
                || low.contains("ntunmapviewofsection")
                || low.contains("setthreadcontext")
                || low.contains("queueuserapc")
            {
                report.has_injection_imports = true;
            }
        }
    } else if let Ok(goblin::Object::Elf(elf)) = goblin::Object::parse(bytes) {
        for sh in &elf.section_headers {
            let name = elf
                .shdr_strtab
                .get_at(sh.sh_name)
                .unwrap_or("")
                .to_ascii_lowercase();
            let start = sh.sh_offset as usize;
            let end = start.saturating_add(sh.sh_size as usize).min(bytes.len());
            let is_exec = (sh.sh_flags as u32 & goblin::elf::section_header::SHF_EXECINSTR) != 0;
            let is_write = (sh.sh_flags as u32 & goblin::elf::section_header::SHF_WRITE) != 0;
            if is_exec && is_write {
                report.has_rwx_or_writable_code_section = true;
            }
            if start < end {
                if is_exec {
                    exec_ranges.push((start, end));
                } else if !is_write && name.starts_with(".rodata") {
                    rdata_ranges.push((start, end));
                }
            }
        }
    }

    let adversarial_vectors: &[(&[u8], &str)] = &[
        (b"/etc/passwd", "/etc/passwd"),
        (b"calc.exe", "calc.exe"),
        (b"windows/system32", "windows/system32"),
        (b"windows\\system32", "windows\\system32"),
        (b"boot.ini", "boot.ini"),
        (b"DROP TABLE ", "DROP TABLE"),
        (b"echo hacked", "echo hacked"),
    ];

    for &(needle, label) in adversarial_vectors {
        let mut pos = 0usize;
        while pos + needle.len() <= bytes.len() {
            let Some(rel) = find_subslice(&bytes[pos..], needle) else {
                break;
            };
            let abs_off = pos + rel;
            pos = abs_off + needle.len();

            let in_rdata = rdata_ranges
                .iter()
                .any(|&(s, e)| abs_off >= s && abs_off + needle.len() <= e);
            let in_exec = exec_ranges
                .iter()
                .any(|&(s, e)| abs_off >= s && abs_off < e);

            if in_exec {
                if !report
                    .executable_section_vector_hits
                    .contains(&label.to_string())
                {
                    report
                        .executable_section_vector_hits
                        .push(label.to_string());
                }
            } else if in_rdata && !report.rdata_test_vector_hits.contains(&label.to_string()) {
                report.rdata_test_vector_hits.push(label.to_string());
            }
        }
    }

    report.is_verified_benign_rust_test_harness = report.has_rust_compiler_provenance
        && report.has_rust_test_harness_symbols
        && !report.has_rwx_or_writable_code_section
        && !report.has_injection_imports
        && report.executable_section_vector_hits.is_empty();

    report
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
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

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
        let mut findings = InspectionFindings::default();
        let maps_path = format!("/proc/{}/maps", pid);
        if let Ok(content) = std::fs::read_to_string(&maps_path) {
            for line in content.lines() {
                let is_deleted = line.contains("(deleted)");
                let is_rwxp = line.contains("rwxp") || line.contains("rwx");
                let is_libc_or_ld =
                    line.contains("libc.so") || line.contains("ld-linux") || line.contains("libc-");

                if is_deleted && (is_libc_or_ld || line.contains(".so")) {
                    findings.hollowing_detected = true;
                    findings
                        .suspicious_sections
                        .push(format!("Deleted library mapped: {}", line.trim()));
                    findings.composition_score += 0.4;
                }
                if is_rwxp && (is_libc_or_ld || line.contains(".so")) {
                    findings.hollowing_detected = true;
                    findings.suspicious_sections.push(format!(
                        "RWX library segment in {}: {}",
                        pid,
                        line.trim()
                    ));
                    findings.composition_score += 0.3;
                }
            }
        }

        if let Ok(patches) = inspect_remote_dll_patches(pid) {
            findings.byte_patches = patches;
        }

        Ok(findings)
    }
}

/// Diff process loaded ntdll.dll / kernel32.dll memory against disk bytes to find unhooking/byte patches.
#[cfg(target_os = "windows")]
pub fn inspect_remote_dll_patches(pid: u32) -> Result<Vec<String>> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
        TH32CS_SNAPMODULE32,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let mut patches = Vec::new();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)?;
        if snapshot == windows::Win32::Foundation::INVALID_HANDLE_VALUE || snapshot.is_invalid() {
            return Ok(patches);
        }
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
                            if let Some(text_section) = pe
                                .section_headers()
                                .iter()
                                .find(|s| s.Name == *b".text\0\0\0")
                            {
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
                                    Some(&mut bytes_read),
                                );

                                if res.is_ok() && bytes_read == section_size {
                                    let disk_slice =
                                        &disk_bytes[raw_offset..(raw_offset + section_size)];
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
pub fn inspect_remote_dll_patches(pid: u32) -> Result<Vec<String>> {
    let mut patches = Vec::new();
    let maps_path = format!("/proc/{}/maps", pid);
    if let Ok(content) = std::fs::read_to_string(&maps_path) {
        for line in content.lines() {
            let is_deleted = line.contains("(deleted)");
            let is_rwxp = line.contains("rwxp") || line.contains("rwx");
            let is_libc_or_ld =
                line.contains("libc.so") || line.contains("ld-linux") || line.contains("libc-");

            if is_deleted && (is_libc_or_ld || line.contains(".so")) {
                patches.push(format!(
                    "Unlinked/deleted library mapped in pid {}: {}",
                    pid,
                    line.trim()
                ));
            }
            if is_rwxp && (is_libc_or_ld || line.contains(".so")) {
                patches.push(format!(
                    "RWX shared library segment detected in pid {}: {}",
                    pid,
                    line.trim()
                ));
            }
        }
    }
    Ok(patches)
}

#[cfg(target_os = "windows")]
fn inspect_stack_spoof(pid: u32) -> Result<bool> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::{
        GetThreadContext, ReadProcessMemory, CONTEXT,
    };
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, OpenThread, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, THREAD_GET_CONTEXT,
        THREAD_QUERY_INFORMATION,
    };

    const CONTEXT_FULL: u32 = 0x100007;
    let mut spoofed = false;
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)?;
        if snapshot == windows::Win32::Foundation::INVALID_HANDLE_VALUE || snapshot.is_invalid() {
            return Ok(spoofed);
        }
        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)?;

        if Thread32First(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32OwnerProcessID == pid {
                    let thread_handle = OpenThread(
                        THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT,
                        false,
                        entry.th32ThreadID,
                    );
                    if let Ok(th) = thread_handle {
                        let mut ctx: CONTEXT = CONTEXT {
                            ContextFlags: windows::Win32::System::Diagnostics::Debug::CONTEXT_FLAGS(
                                CONTEXT_FULL,
                            ),
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
                                Some(&mut bytes_read),
                            );
                            if res.is_ok()
                                && bytes_read == buffer.len()
                                && !is_preceded_by_call(&buffer)
                            {
                                spoofed = true;
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

#[cfg(target_os = "windows")]
unsafe fn inspect_handle(
    _handle: windows::Win32::Foundation::HANDLE,
) -> Result<InspectionFindings> {
    Ok(InspectionFindings::default())
}

/// Inspect an ELF64 binary for suspicious PT_LOAD RWX segments and injection symbols.
fn inspect_elf64(bytes: &[u8], findings: &mut InspectionFindings) {
    if bytes.len() < 64 || bytes[4] != 2 {
        return;
    }
    let is_le = bytes[5] == 1;

    let read_u16 = |offset: usize| -> Option<u16> {
        let slice: [u8; 2] = bytes.get(offset..offset + 2)?.try_into().ok()?;
        Some(if is_le {
            u16::from_le_bytes(slice)
        } else {
            u16::from_be_bytes(slice)
        })
    };
    let read_u32 = |offset: usize| -> Option<u32> {
        let slice: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
        Some(if is_le {
            u32::from_le_bytes(slice)
        } else {
            u32::from_be_bytes(slice)
        })
    };
    let read_u64 = |offset: usize| -> Option<u64> {
        let slice: [u8; 8] = bytes.get(offset..offset + 8)?.try_into().ok()?;
        Some(if is_le {
            u64::from_le_bytes(slice)
        } else {
            u64::from_be_bytes(slice)
        })
    };

    if let (Some(e_phoff), Some(e_phentsize), Some(e_phnum)) =
        (read_u64(32), read_u16(54), read_u16(56))
    {
        let e_phoff = e_phoff as usize;
        let e_phentsize = e_phentsize as usize;
        let e_phnum = e_phnum as usize;

        if e_phentsize >= 56 {
            for i in 0..e_phnum {
                let ph_offset = e_phoff.saturating_add(i * e_phentsize);
                if ph_offset + 56 > bytes.len() {
                    break;
                }
                let p_type = read_u32(ph_offset).unwrap_or(0);
                let p_flags = read_u32(ph_offset + 4).unwrap_or(0);

                // PT_LOAD = 1, RWX = 0x7 (PF_R | PF_W | PF_X)
                if p_type == 1 && (p_flags & 0x7) == 0x7 {
                    findings
                        .suspicious_sections
                        .push("RWX ELF segment".to_string());
                    findings.composition_score += 0.3;
                }
            }
        }
    }

    let suspicious_symbols = [
        "ptrace",
        "memfd_create",
        "process_vm_writev",
        "dlopen",
        "LD_PRELOAD",
    ];

    for &sym in &suspicious_symbols {
        if bytes.windows(sym.len()).any(|w| w == sym.as_bytes()) {
            findings.suspicious_dependencies.push(sym.to_string());
            findings.composition_score += 0.2;
        }
    }
}

/// Inspect a file on disk (PE on Windows, ELF64, and Google Magika content type on all platforms) for composition and heuristics.
pub fn inspect_file(path: &Path) -> Result<InspectionFindings> {
    let bytes = std::fs::read(path)?;
    let mut findings = InspectionFindings::default();

    let magika_id = crate::rea::identify_with_magika(Some(path), &bytes);
    findings.magika_label = magika_id.label.clone();
    findings.magika_mime_type = magika_id.mime_type.clone();

    // Check for file extension masquerading (e.g., an executable disguised as a benign document/image)
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext_lc = ext.to_ascii_lowercase();
        let claims_benign_doc_or_media = matches!(
            ext_lc.as_str(),
            "pdf"
                | "txt"
                | "jpg"
                | "jpeg"
                | "png"
                | "gif"
                | "bmp"
                | "svg"
                | "doc"
                | "docx"
                | "xls"
                | "xlsx"
                | "ppt"
                | "pptx"
                | "csv"
                | "md"
                | "mp3"
                | "mp4"
                | "wav"
        );
        let is_executable_content = matches!(
            magika_id.label.as_str(),
            "pebin" | "elf" | "macho" | "wasm" | "dex"
        );
        if claims_benign_doc_or_media && is_executable_content {
            findings.suspicious_sections.push(format!(
                "Magika extension masquerading: .{} file contains {} ({})",
                ext_lc, magika_id.label, magika_id.mime_type
            ));
            findings.composition_score += 0.60;
        }
    }

    // Structural RIFF/WAVE inspection (wFormatTag=3 IEEE float without `fact` chunk vs disguised shellcode/heap-spray)
    if let Some(riff_report) = crate::rea::inspect_riff_wave_container(&bytes) {
        if !riff_report.shellcode_or_heapspray_indicators.is_empty() {
            for indicator in &riff_report.shellcode_or_heapspray_indicators {
                findings
                    .suspicious_sections
                    .push(format!("RIFF WAVE Shellcode/Masquerade: {}", indicator));
            }
            findings.composition_score += 0.75;
        }
        return Ok(findings);
    }

    // Structural Rust Test Harness `.rdata` Static-Vector Provenance Check
    let test_prov = classify_pe_rust_test_harness_provenance(&bytes);
    findings.is_verified_rust_test_harness = test_prov.is_verified_benign_rust_test_harness;
    findings.rdata_only_adversarial_test_vectors = test_prov.rdata_test_vector_hits;

    if bytes.starts_with(b"\x7FELF") || magika_id.label == "elf" {
        inspect_elf64(&bytes, &mut findings);
        return Ok(findings);
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(pe) = PeFile::from_bytes(&bytes) {
            // 1. Check for suspicious section characteristics (e.g. RWX)
            let section_table = pe.section_headers();
            for section in section_table {
                if let Ok(name) = section.name() {
                    let chars = section.Characteristics;

                    // IMAGE_SCN_MEM_EXECUTE (0x20000000) | IMAGE_SCN_MEM_WRITE (0x80000000)
                    if (chars & 0xA0000000) == 0xA0000000 {
                        findings
                            .suspicious_sections
                            .push(format!("RWX section: {}", name));
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
                                if let pelite::pe64::imports::Import::ByName { name, .. } = import {
                                    let name = name.to_string();
                                    let low_name = name.to_lowercase();

                                    // High-risk injection APIs
                                    if low_name.contains("virtualalloc")
                                        || low_name.contains("writeprocessmemory")
                                        || low_name.contains("createremotethread")
                                        || low_name.contains("ntunmapviewofsection")
                                        || low_name.contains("setthreadcontext")
                                    {
                                        findings.suspicious_dependencies.push(name.clone());
                                        findings.composition_score += 0.2;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // 3. Check for .NET (COM Descriptor Directory is at index 14)
            if let Some(dir) = pe.data_directory().get(14) {
                if dir.VirtualAddress > 0 && dir.Size >= 48 {
                    findings.is_dot_net = true;
                }
            }
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

    #[test]
    fn test_inspect_elf64_rwx_and_symbols() {
        let mut elf_bytes = vec![0u8; 128];
        // e_ident
        elf_bytes[0..4].copy_from_slice(b"\x7FELF");
        elf_bytes[4] = 2; // ELFCLASS64
        elf_bytes[5] = 1; // ELFDATA2LSB (little endian)
        elf_bytes[6] = 1; // EV_CURRENT

        // e_phoff = 64
        elf_bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        // e_phentsize = 56
        elf_bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        // e_phnum = 1
        elf_bytes[56..58].copy_from_slice(&1u16.to_le_bytes());

        // Program header at offset 64:
        // p_type = 1 (PT_LOAD)
        elf_bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
        // p_flags = 7 (PF_R | PF_W | PF_X = RWX)
        elf_bytes[68..72].copy_from_slice(&7u32.to_le_bytes());

        // Append suspicious symbols
        elf_bytes.extend_from_slice(b"some_code_ptrace_memfd_create_done");

        let mut findings = InspectionFindings::default();
        inspect_elf64(&elf_bytes, &mut findings);

        assert!(findings
            .suspicious_sections
            .contains(&"RWX ELF segment".to_string()));
        assert!(findings
            .suspicious_dependencies
            .contains(&"ptrace".to_string()));
        assert!(findings
            .suspicious_dependencies
            .contains(&"memfd_create".to_string()));
        assert!(findings.composition_score >= 0.7);
    }

    #[test]
    fn test_inspect_file_flags_executable_masquerading_as_document() {
        let tmp =
            std::env::temp_dir().join(format!("osoosi_pe_masquerade_{}.pdf", uuid::Uuid::new_v4()));
        let mut pe_stub = vec![0u8; 256];
        pe_stub[0..2].copy_from_slice(b"MZ");
        std::fs::write(&tmp, &pe_stub).unwrap();

        let findings = inspect_file(&tmp).expect("inspect masqueraded pdf");
        let _ = std::fs::remove_file(&tmp);

        assert_eq!(findings.magika_label, "pebin");
        assert!(
            findings.composition_score >= 0.50,
            "Masquerading executable must exceed StaticAnalyzer 0.50 threshold, got {}",
            findings.composition_score
        );
        assert!(findings
            .suspicious_sections
            .iter()
            .any(|s| s.contains("Magika extension masquerading")));
    }

    #[test]
    fn test_riff_wave_32bit_ieee_float_missing_fact_chunk_and_pcm16_canonicalizer() {
        // Build a bare 44-byte header 32-bit IEEE Float WAV (wFormatTag = 3, 48 kHz, Stereo)
        // without a `fact` chunk — identical to the non-standard float WAVs that trigger SmartScreen/AV heuristics.
        let sample_rate = 48_000u32;
        let channels = 2u16;
        let num_frames = 512usize;
        let total_samples = num_frames * (channels as usize);
        let data_bytes_len = (total_samples * 4) as u32;
        let riff_size = 36u32 + data_bytes_len;

        let mut float_wav = Vec::with_capacity(44 + data_bytes_len as usize);
        float_wav.extend_from_slice(b"RIFF");
        float_wav.extend_from_slice(&riff_size.to_le_bytes());
        float_wav.extend_from_slice(b"WAVE");
        float_wav.extend_from_slice(b"fmt ");
        float_wav.extend_from_slice(&16u32.to_le_bytes());
        float_wav.extend_from_slice(&3u16.to_le_bytes()); // wFormatTag = 3 (IEEE Float)
        float_wav.extend_from_slice(&channels.to_le_bytes());
        float_wav.extend_from_slice(&sample_rate.to_le_bytes());
        float_wav.extend_from_slice(&(sample_rate * 8).to_le_bytes());
        float_wav.extend_from_slice(&8u16.to_le_bytes());
        float_wav.extend_from_slice(&32u16.to_le_bytes()); // bitsPerSample = 32
        float_wav.extend_from_slice(b"data");
        float_wav.extend_from_slice(&data_bytes_len.to_le_bytes());

        for frame in 0..num_frames {
            let t = frame as f32 / sample_rate as f32;
            let left = (2.0 * std::f32::consts::PI * 440.0 * t).sin() * 0.75;
            let right = (2.0 * std::f32::consts::PI * 880.0 * t).cos() * 0.75;
            float_wav.extend_from_slice(&left.to_le_bytes());
            float_wav.extend_from_slice(&right.to_le_bytes());
        }

        let report = crate::rea::inspect_riff_wave_container(&float_wav)
            .expect("Must parse bare 44-byte 32-bit IEEE float WAV");
        assert_eq!(report.format_tag, 3);
        assert!(!report.has_fact_chunk);
        assert!(report.missing_mandatory_fact_chunk);
        assert!(report.valid_ieee_float_waveform);
        assert!(report.shellcode_or_heapspray_indicators.is_empty());
        assert!(report.requires_pcm16_canonicalization);

        // Convert to standard 16-bit PCM WAV (wFormatTag = 1, bitsPerSample = 16)
        let pcm16_wav = crate::rea::canonicalize_ieee_float_wav_to_pcm16(&float_wav)
            .expect("Must canonicalize legitimate IEEE float WAV to 16-bit PCM");
        let pcm_report = crate::rea::inspect_riff_wave_container(&pcm16_wav)
            .expect("Must parse canonicalized 16-bit PCM WAV");
        assert_eq!(pcm_report.format_tag, 1);
        assert_eq!(pcm_report.bits_per_sample, 16);
        assert_eq!(pcm_report.channels, 2);
        assert_eq!(pcm_report.sample_rate, 48_000);
        assert!(!pcm_report.missing_mandatory_fact_chunk);
        assert!(pcm_report.shellcode_or_heapspray_indicators.is_empty());
    }

    #[test]
    fn test_riff_wave_disguised_shellcode_and_heapspray_blocked() {
        let mut malicious_wav = Vec::new();
        malicious_wav.extend_from_slice(b"RIFF");
        malicious_wav.extend_from_slice(&500u32.to_le_bytes());
        malicious_wav.extend_from_slice(b"WAVE");
        malicious_wav.extend_from_slice(b"fmt ");
        malicious_wav.extend_from_slice(&16u32.to_le_bytes());
        malicious_wav.extend_from_slice(&3u16.to_le_bytes()); // Claims wFormatTag = 3
        malicious_wav.extend_from_slice(&2u16.to_le_bytes());
        malicious_wav.extend_from_slice(&48_000u32.to_le_bytes());
        malicious_wav.extend_from_slice(&384_000u32.to_le_bytes());
        malicious_wav.extend_from_slice(&8u16.to_le_bytes());
        malicious_wav.extend_from_slice(&32u16.to_le_bytes());
        malicious_wav.extend_from_slice(b"data");
        malicious_wav.extend_from_slice(&256u32.to_le_bytes());

        // Inject heap-spray sled (0x0c0c0c0c) + x64 CobaltStrike/Metasploit prologue + TEB/PEB walk
        malicious_wav.extend_from_slice(&[0x0cu8; 64]);
        malicious_wav.extend_from_slice(&[0xFC, 0x48, 0x83, 0xE4, 0xF0]);
        malicious_wav.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);
        malicious_wav.resize(44 + 256, 0x90);

        let report = crate::rea::inspect_riff_wave_container(&malicious_wav)
            .expect("Must parse RIFF envelope");
        assert!(!report.valid_ieee_float_waveform);
        assert!(
            report.shellcode_or_heapspray_indicators.len() >= 3,
            "Expected multiple shellcode/heap-spray indicators, got {:?}",
            report.shellcode_or_heapspray_indicators
        );
        assert!(
            crate::rea::canonicalize_ieee_float_wav_to_pcm16(&malicious_wav).is_err(),
            "Canonicalizer must reject WAV containing shellcode/heap-spray payloads"
        );

        let tmp =
            std::env::temp_dir().join(format!("osoosi_malicious_wav_{}.wav", uuid::Uuid::new_v4()));
        std::fs::write(&tmp, &malicious_wav).unwrap();
        let findings = inspect_file(&tmp).expect("inspect malicious wav");
        let _ = std::fs::remove_file(&tmp);
        assert!(
            findings.composition_score >= 0.75,
            "Disguised shellcode WAV must score >= 0.75, got {}",
            findings.composition_score
        );
    }

    #[test]
    fn test_elf_rust_test_harness_rdata_adversarial_vectors_vs_exec_payload() {
        // Construct a minimal ELF64 with:
        // - Section 1: `.text` (SHF_ALLOC | SHF_EXECINSTR = 0x6) at offset 256..384
        // - Section 2: `.rodata` (SHF_ALLOC = 0x2, read-only) at offset 384..768
        // - Section 3: `.shstrtab` at offset 768..832
        let mut buf = vec![0u8; 832];
        buf[0..4].copy_from_slice(b"\x7FELF");
        buf[4] = 2; // 64-bit
        buf[5] = 1; // little-endian
        buf[6] = 1; // EV_CURRENT
        buf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        buf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes()); // x86_64
        buf[20..24].copy_from_slice(&1u32.to_le_bytes());
        buf[40..48].copy_from_slice(&64u64.to_le_bytes()); // e_shoff = 64
        buf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize = 64
        buf[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize = 64
        buf[60..62].copy_from_slice(&4u16.to_le_bytes()); // e_shnum = 4 (null, .text, .rodata, .shstrtab)
        buf[62..64].copy_from_slice(&3u16.to_le_bytes()); // e_shstrndx = 3

        // String table at 768: "\0.text\0.rodata\0.shstrtab\0"
        let shstrtab = b"\0.text\0.rodata\0.shstrtab\0";
        buf[768..768 + shstrtab.len()].copy_from_slice(shstrtab);

        // Section 1 (.text) header at 64 + 64 = 128
        buf[128..132].copy_from_slice(&1u32.to_le_bytes()); // sh_name = 1 (".text")
        buf[132..136].copy_from_slice(&1u32.to_le_bytes()); // SHT_PROGBITS
        buf[136..144].copy_from_slice(&0x6u64.to_le_bytes()); // SHF_ALLOC | SHF_EXECINSTR
        buf[152..160].copy_from_slice(&256u64.to_le_bytes()); // sh_offset = 256
        buf[160..168].copy_from_slice(&128u64.to_le_bytes()); // sh_size = 128

        // Section 2 (.rodata) header at 64 + 128 = 192 (WAIT: 4 sections * 64 = 256 bytes, so headers occupy 64..320!)
        // Let's place .text at 320..448, .rodata at 448..768, .shstrtab at 768..832
        buf[152..160].copy_from_slice(&320u64.to_le_bytes()); // .text offset = 320
        buf[160..168].copy_from_slice(&128u64.to_le_bytes()); // .text size = 128

        // Section 2 (.rodata) header at 192
        buf[192..196].copy_from_slice(&7u32.to_le_bytes()); // sh_name = 7 (".rodata")
        buf[196..200].copy_from_slice(&1u32.to_le_bytes()); // SHT_PROGBITS
        buf[200..208].copy_from_slice(&0x2u64.to_le_bytes()); // SHF_ALLOC (Read-Only!)
        buf[216..224].copy_from_slice(&448u64.to_le_bytes()); // sh_offset = 448
        buf[224..232].copy_from_slice(&320u64.to_le_bytes()); // sh_size = 320

        // Section 3 (.shstrtab) header at 256
        buf[256..260].copy_from_slice(&15u32.to_le_bytes()); // sh_name = 15 (".shstrtab")
        buf[260..264].copy_from_slice(&3u32.to_le_bytes()); // SHT_STRTAB
        buf[280..288].copy_from_slice(&768u64.to_le_bytes()); // sh_offset = 768
        buf[288..296].copy_from_slice(&(shstrtab.len() as u64).to_le_bytes());

        // Populate .rodata (448..768) with Rust compiler + test harness markers + static adversarial test vectors
        let rodata_payload = b"rustc 1.85.0 (4d91de4e4 2025-02-17)\0test::run_test\0; cat /etc/passwd | calc.exe && echo hacked\0../../../../windows/system32\0..\\..\\..\\boot.ini\0DROP TABLE songs\0";
        buf[448..448 + rodata_payload.len()].copy_from_slice(rodata_payload);

        let prov = classify_pe_rust_test_harness_provenance(&buf);
        assert!(prov.has_rust_compiler_provenance);
        assert!(prov.has_rust_test_harness_symbols);
        assert!(!prov.has_rwx_or_writable_code_section);
        assert!(prov.executable_section_vector_hits.is_empty());
        assert!(prov
            .rdata_test_vector_hits
            .contains(&"calc.exe".to_string()));
        assert!(prov
            .rdata_test_vector_hits
            .contains(&"/etc/passwd".to_string()));
        assert!(prov
            .rdata_test_vector_hits
            .contains(&"DROP TABLE".to_string()));
        assert!(prov.is_verified_benign_rust_test_harness);

        // Now inject an exploit vector inside the executable `.text` section (320..448) -> must fail closed!
        let mut trojan_buf = buf.clone();
        trojan_buf[320..328].copy_from_slice(b"calc.exe");
        let trojan_prov = classify_pe_rust_test_harness_provenance(&trojan_buf);
        assert!(!trojan_prov.executable_section_vector_hits.is_empty());
        assert!(!trojan_prov.is_verified_benign_rust_test_harness);
    }

    #[test]
    fn test_webui_media_and_sink_integrity_audit() {
        let temp_dir =
            std::env::temp_dir().join(format!("osoosi_music_songs_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(temp_dir.join("roots_reggae_anthem")).unwrap();
        std::fs::create_dir_all(temp_dir.join("song-one-love-shining-1977")).unwrap();

        let broken_ui_js = r#"
            const url1 = "/api/songs/song_reggae_anthem_001/versions/1/audio/final_master";
            const url2 = "/api/songs/song_afrobeats_002/versions/1/audio/final_master";
            // fallback to silent timer when audio 404s
            setInterval(() => { console.log("silent playback timer"); }, 1000);
        "#;
        let broken_report =
            crate::rea::audit_webui_media_and_sink_integrity(broken_ui_js, Some(&temp_dir));
        assert_eq!(
            broken_report.missing_on_disk_song_ids,
            vec![
                "song_reggae_anthem_001".to_string(),
                "song_afrobeats_002".to_string()
            ]
        );
        assert!(broken_report.has_silent_timer_fallback);
        assert!(!broken_report.supports_set_sink_id);

        let fixed_ui_js = r#"
            const url1 = "/api/songs/roots_reggae_anthem/versions/1/audio/final_master";
            const url2 = "/api/songs/song-one-love-shining-1977/versions/1/audio/final_master";
            async function selectAudioOutput(deviceId) {
                const devices = await navigator.mediaDevices.enumerateDevices();
                const outputs = devices.filter(d => d.kind === "audiooutput");
                await audioEl.setSinkId(deviceId);
            }
        "#;
        let fixed_report =
            crate::rea::audit_webui_media_and_sink_integrity(fixed_ui_js, Some(&temp_dir));
        assert!(fixed_report.missing_on_disk_song_ids.is_empty());
        assert!(!fixed_report.has_silent_timer_fallback);
        assert!(fixed_report.supports_set_sink_id);
        assert!(fixed_report.supports_enumerate_audio_outputs);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
