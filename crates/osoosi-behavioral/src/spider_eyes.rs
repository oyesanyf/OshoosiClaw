use sysinfo::{Pid, System};
use capstone::prelude::*;
use capstone::arch;
use proc_maps::get_process_maps;
use std::path::Path;
use tracing::{info, warn, error};

use crate::llm_engine::Gemma4Analyzer;
use std::sync::Arc;
use dashmap::DashMap;
use blake3::Hasher;

/// THE BRAIN: Local LLM Mechanistic Analyst
#[derive(Clone)]
pub struct GemmaSupervisor {
    pub analyzer: Option<Arc<Gemma4Analyzer>>,
}

impl GemmaSupervisor {
    pub fn new(model_path: &str) -> Self {
        let input_path = Path::new(model_path);
        let model_dir = if input_path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("onnx"))
            .unwrap_or(false)
        {
            input_path.parent().unwrap_or(input_path)
        } else {
            input_path
        };
        
        let analyzer = match Gemma4Analyzer::new(model_dir) {
            Ok(a) => Some(Arc::new(a)),
            Err(e) => {
                warn!(
                    "LLM Cortex failed to initialize from {:?}: {}. Falling back to heuristic analysis.",
                    model_dir, e
                );
                None
            }
        };
        
        Self { analyzer }
    }

    pub async fn analyze_intent(&self, asm: &str) -> String {
        if let Some(ref analyzer) = self.analyzer {
            match analyzer.reason_about_attack(asm).await {
                Ok(report) => format!("AI ANALYSIS: {}", report),
                Err(e) => {
                    error!("LLM inference failed: {}. Using fallback heuristic.", e);
                    self.analyze_heuristic(asm)
                }
            }
        } else {
            self.analyze_heuristic(asm)
        }
    }

    fn analyze_heuristic(&self, asm: &str) -> String {
        let asm_lower = asm.to_lowercase();
        let mut findings: Vec<&str> = Vec::new();

        // --- Process Injection / Hollowing ---
        if asm_lower.contains("syscall") && (asm_lower.contains("0x65") || asm_lower.contains("101")) {
            findings.push("Detected syscall sequence consistent with process hollowing or memory injection (ptrace/process_vm_writev).");
        }

        // --- Network Beaconing ---
        if asm_lower.contains("socket") && asm_lower.contains("connect") {
            findings.push("Detected network beaconing behavior in unexpected code segment.");
        }

        // --- Shellcode / ROP Patterns ---
        if asm_lower.contains("jmp esp") || asm_lower.contains("call esp") || asm_lower.contains("jmp rsp") {
            findings.push("Detected stack-pivot gadget (JMP ESP/RSP). Strong indicator of Return-Oriented Programming (ROP) exploit.");
        }

        // --- Cryptographic / Ransomware Patterns ---
        if asm_lower.contains("aesenc") || asm_lower.contains("aesdec") || asm_lower.contains("pxor") {
            findings.push("Detected AES encryption instructions. Could indicate ransomware payload or encrypted C2 communication.");
        }

        // --- Anti-Debug / Evasion ---
        if asm_lower.contains("int 0x2d") || (asm_lower.contains("rdtsc") && asm_lower.contains("sub")) {
            findings.push("Detected anti-debugging technique (INT 2D / RDTSC timing check). Malware evasion likely.");
        }
        if asm_lower.contains("cpuid") && asm_lower.contains("cmp") {
            findings.push("Detected VM/sandbox detection via CPUID. Malware may refuse to execute in analysis environments.");
        }

        // --- Privilege Escalation ---
        if asm_lower.contains("mov cr0") || asm_lower.contains("wrmsr") || asm_lower.contains("sidt") {
            findings.push("Detected privileged instruction sequence (CR0/MSR/IDT). Kernel-level rootkit or privilege escalation attempt.");
        }

        // --- Credential Harvesting ---
        if asm_lower.contains("lsass") || (asm_lower.contains("samss") && asm_lower.contains("read")) {
            findings.push("Detected reference to LSASS/SAM. Credential harvesting (Mimikatz-style) suspected.");
        }

        // --- Dynamic Import Resolution (GetProcAddress pattern) ---
        if asm_lower.contains("getprocaddress") || asm_lower.contains("loadlibrary") {
            findings.push("Detected dynamic API resolution (GetProcAddress/LoadLibrary). Common in packed/obfuscated malware and shellcode.");
        }

        // --- NOP Sled Detection ---
        let nop_count = asm_lower.matches("nop").count();
        if nop_count > 20 {
            findings.push("Detected large NOP sled (>20 consecutive NOPs). Classic shellcode padding for exploit reliability.");
        }

        if findings.is_empty() {
            "HEURISTIC ANALYSIS: Code segment appears consistent with normal execution.".to_string()
        } else {
            format!("HEURISTIC ANALYSIS: {} finding(s) detected.\n{}", findings.len(), findings.join("\n"))
        }
    }
}

#[derive(Clone)]
pub struct SpiderEyes {
    supervisor: GemmaSupervisor,
    analysis_cache: DashMap<String, String>, // Hash -> Report
}

impl SpiderEyes {
    pub fn new(model_path: &str) -> Self {
        Self {
            supervisor: GemmaSupervisor::new(model_path),
            analysis_cache: DashMap::new(),
        }
    }

    /// ASLR-aware binary analysis of a running process (Non-blocking).
    pub async fn watch_process(&self, target_pid: u32) -> anyhow::Result<String> {
        let spider = Arc::new(self.clone());
        
        tokio::task::spawn_blocking(move || {
            // 1. Locate the process
            let mut s = System::new();
            let pid = Pid::from(target_pid as usize);
            s.refresh_process(pid);
            
            let process = s.process(pid)
                .ok_or_else(|| anyhow::anyhow!("Process {} not found", target_pid))?;
            
            info!("🕸️  [OSHOOSI] Spider attached to: {}", process.name());

            // 2. ASLR BYPASS: Find the primary executable memory segment
            let maps = get_process_maps(target_pid as proc_maps::Pid)?;
            let process_name = process.name().to_lowercase();
            
            // Try to find the segment that matches the process name and is executable
            let exec_segment = maps.iter()
                .find(|m| m.is_exec() && m.filename().map(|f| f.to_string_lossy().to_lowercase().contains(&process_name)).unwrap_or(false))
                // Fallback to first executable segment with a filename if name-match fails
                .or_else(|| maps.iter().find(|m| m.is_exec() && m.filename().is_some()))
                .ok_or_else(|| anyhow::anyhow!("No executable code segment found for PID {}", target_pid))?;

            info!("🕸️  [ASLR] Executable segment found at: 0x{:x}", exec_segment.start());

            // 3. CAPTURE: Read from memory (platform-specific)
            let (buffer, hash) = spider.read_process_memory(target_pid, exec_segment.start(), exec_segment.size())?;

            // Check cache first
            if let Some(cached_report) = spider.analysis_cache.get(&hash) {
                info!("🕸️  [CACHE-HIT] Re-using analysis for binary hash {}", hash);
                return Ok(cached_report.clone());
            }

            // 4. DISASSEMBLE: Translate bytes to assembly
            // Determine mode based on pointer size (simplified heuristic)
            let mode = if std::mem::size_of::<usize>() == 8 {
                arch::x86::ArchMode::Mode64
            } else {
                arch::x86::ArchMode::Mode32
            };

            let cs = Capstone::new()
                .x86()
                .mode(mode)
                .build()
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            let insns = cs.disasm_all(&buffer, exec_segment.start() as u64)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            
            let mut asm_output = String::new();
            for i in insns.iter() {
                asm_output.push_str(&format!("{} {}; ", i.mnemonic().unwrap_or(""), i.op_str().unwrap_or("")));
            }

            // 5. LOCAL INFERENCE: LLM Mechanistic Interpretability
            info!("🕸️  [LOCAL-AI] LLM Cortex analyzing assembly intent for PID {}...", target_pid);
            
            // We are in spawn_blocking, but we need to call an async function.
            // Since we're in a tokio runtime, we can get a handle.
            let rt = tokio::runtime::Handle::current();
            let report = rt.block_on(spider.supervisor.analyze_intent(&asm_output));
            
            let final_report = format!("PID: {}\nNAME: {}\nSEGMENT: 0x{:x}\nDISASSEMBLY: {}\n\nREPORT:\n{}", 
                target_pid, process.name(), exec_segment.start(), asm_output, report);
            
            // Save to cache
            spider.analysis_cache.insert(hash, final_report.clone());
            
            Ok(final_report)
        }).await?
    }

    /// Cross-platform process memory reader
    #[cfg(target_os = "linux")]
    fn read_process_memory(&self, pid: u32, start: usize, _size: usize) -> anyhow::Result<(Vec<u8>, String)> {
        use std::io::{Read, Seek, SeekFrom};
        let mut mem_file = std::fs::File::open(format!("/proc/{}/mem", pid))?;
        let mut buf = vec![0u8; 4096]; // Read more bytes for better analysis coverage
        mem_file.seek(SeekFrom::Start(start as u64))?;
        let bytes_read = mem_file.read(&mut buf)?;
        buf.truncate(bytes_read);
        
        let mut hasher = Hasher::new();
        hasher.update(&buf);
        let hash = hasher.finalize().to_string();
        
        Ok((buf, hash))
    }

    /// macOS: Uses mach_vm_read to read process memory (requires SIP disabled or entitled binary)
    #[cfg(target_os = "macos")]
    fn read_process_memory(&self, pid: u32, start: usize, size: usize) -> anyhow::Result<(Vec<u8>, String)> {
        use std::io::{Read, Seek, SeekFrom};
        // macOS does not have /proc/[pid]/mem, so we use mach VM read via libc.
        // For now, we use the proc-maps crate data and attempt to read via /dev/mem or task_for_pid.
        // A full implementation requires a code-signed binary with the com.apple.security.cs.debugger entitlement.
        
        // Fallback: try reading from the executable file on disk instead of live memory.
        // This is less accurate but works without SIP bypass.
        let maps = proc_maps::get_process_maps(pid as proc_maps::Pid)?;
        let exec_seg = maps.iter()
            .find(|m| m.is_exec() && m.filename().is_some())
            .ok_or_else(|| anyhow::anyhow!("No executable segment found for PID {}", pid))?;
        
        if let Some(path) = exec_seg.filename() {
            let path_str = path.to_string_lossy();
            if std::path::Path::new(&*path_str).exists() {
                let mut f = std::fs::File::open(&*path_str)?;
                let mut buf = vec![0u8; 4096];
                let bytes_read = f.read(&mut buf)?;
                buf.truncate(bytes_read);
                
                let mut hasher = Hasher::new();
                hasher.update(&buf);
                let hash = hasher.finalize().to_string();
                
                info!("🕸️  [macOS] Read {} bytes from on-disk binary: {}", bytes_read, path_str);
                return Ok((buf, hash));
            }
        }
        
        Err(anyhow::anyhow!("macOS: Could not read process memory for PID {}. Code-signing entitlement required.", pid))
    }

    /// Windows: Uses ReadProcessMemory via the windows crate
    #[cfg(target_os = "windows")]
    fn read_process_memory(&self, pid: u32, start: usize, size: usize) -> anyhow::Result<(Vec<u8>, String)> {
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ, PROCESS_QUERY_INFORMATION};
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::Foundation::CloseHandle;

        let read_size = size.min(4096); // Cap read size
        let mut buffer = vec![0u8; read_size];

        unsafe {
            let proc_handle = OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                false,
                pid,
            ).map_err(|e| anyhow::anyhow!("Failed to open process {}: {}", pid, e))?;
            
            let mut bytes_read = 0usize;
            let result = ReadProcessMemory(
                proc_handle,
                start as *const std::ffi::c_void,
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                read_size,
                Some(&mut bytes_read),
            );
            
            let _ = CloseHandle(proc_handle);
            
            if result.is_err() {
                return Err(anyhow::anyhow!("Failed to read memory from PID {}", pid));
            }
            buffer.truncate(bytes_read);
        }

        let mut hasher = Hasher::new();
        hasher.update(&buffer);
        let hash = hasher.finalize().to_string();

        Ok((buffer, hash))
    }
}
