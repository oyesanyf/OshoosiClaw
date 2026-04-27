use sysinfo::{Pid, System};
use capstone::prelude::*;
use capstone::arch;
use proc_maps::get_process_maps;
use std::path::Path;
use tracing::{info, warn, error};

use crate::llm_engine::Gemma4Analyzer;
use std::sync::Arc;

/// THE BRAIN: Local Gemma 4 Mechanistic Analyst
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
        let analyzer = Gemma4Analyzer::new(model_dir).ok().map(Arc::new);
        if analyzer.is_none() {
            warn!(
                "Gemma 4 ONNX analyzer could not be initialized from {:?} (resolved model dir: {:?}). Falling back to heuristic analysis.",
                input_path, model_dir
            );
        }
        Self { analyzer }
    }

    pub fn analyze_intent(&self, asm: &str) -> String {
        if let Some(ref analyzer) = self.analyzer {
            match analyzer.reason_about_attack(asm) {
                Ok(report) => format!("AI ANALYSIS: {}", report),
                Err(e) => {
                    error!("Gemma 4 inference failed: {}. Using fallback heuristic.", e);
                    self.analyze_heuristic(asm)
                }
            }
        } else {
            self.analyze_heuristic(asm)
        }
    }

    fn analyze_heuristic(&self, asm: &str) -> String {
        if asm.contains("syscall") && (asm.contains("0x65") || asm.contains("101")) { // ptrace/process_vm_writev patterns
            "HEURISTIC ANALYSIS: Detected syscall sequence consistent with process hollowing or memory injection.".to_string()
        } else if asm.contains("socket") && asm.contains("connect") {
            "HEURISTIC ANALYSIS: Detected network beaconing behavior in unexpected code segment.".to_string()
        } else {
            "HEURISTIC ANALYSIS: Code segment appears consistent with normal execution.".to_string()
        }
    }
}

pub struct SpiderEyes {
    supervisor: GemmaSupervisor,
}

impl SpiderEyes {
    pub fn new(model_path: &str) -> Self {
        Self {
            supervisor: GemmaSupervisor::new(model_path),
        }
    }

    /// ASLR-aware binary analysis of a running process.
    pub fn watch_process(&self, target_pid: u32) -> anyhow::Result<String> {
        // 1. Locate the process
        let mut s = System::new_all();
        s.refresh_processes();
        
        let process = s.process(Pid::from(target_pid as usize))
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

        // 3. CAPTURE: Read from memory
        // On Linux, we use /proc/[pid]/mem. On Windows, we'd use ReadProcessMemory.
        #[cfg(target_os = "linux")]
        let buffer = {
            use std::io::{Read, Seek, SeekFrom};
            let mut mem_file = std::fs::File::open(format!("/proc/{}/mem", target_pid))?;
            let mut buf = vec![0u8; 1024];
            mem_file.seek(SeekFrom::Start(exec_segment.start() as u64))?;
            let bytes_read = mem_file.read(&mut buf)?;
            buf.truncate(bytes_read);
            buf
        };

        #[cfg(target_os = "windows")]
        let buffer = {
            // Windows-specific memory reading logic
            use winapi::um::processthreadsapi::OpenProcess;
            use winapi::um::memoryapi::ReadProcessMemory;
            use winapi::um::handleapi::CloseHandle;
            use winapi::um::winnt::PROCESS_VM_READ;

            let handle = unsafe { OpenProcess(PROCESS_VM_READ, 0, target_pid) };
            if handle.is_null() {
                return Err(anyhow::anyhow!("Failed to open process for reading"));
            }

            let mut buf = vec![0u8; 1024];
            let mut bytes_read = 0;
            let success = unsafe {
                ReadProcessMemory(
                    handle,
                    exec_segment.start() as *const _,
                    buf.as_mut_ptr() as *mut _,
                    buf.len(),
                    &mut bytes_read
                )
            };
            
            unsafe { CloseHandle(handle); }
            
            if success == 0 {
                return Err(anyhow::anyhow!("ReadProcessMemory failed"));
            }
            buf.truncate(bytes_read);
            buf
        };

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

        // 5. LOCAL INFERENCE: Gemma 4 Mechanistic Interpretability
        info!("🕸️  [LOCAL-AI] Gemma 4 analyzing assembly intent for PID {}...", target_pid);
        let report = self.supervisor.analyze_intent(&asm_output);
        
        Ok(format!("PID: {}\nNAME: {}\nSEGMENT: 0x{:x}\nDISASSEMBLY: {}\n\nREPORT:\n{}", 
            target_pid, process.name(), exec_segment.start(), asm_output, report))
    }
}
