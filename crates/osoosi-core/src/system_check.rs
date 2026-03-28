use sysinfo::System;
use tracing::{info, warn, error};
use anyhow::{Result, anyhow};

pub struct SystemRequirements {
    pub min_ram_mb: u64,
    pub min_cpus: usize,
}

impl Default for SystemRequirements {
    fn default() -> Self {
        Self {
            min_ram_mb: 2048, // 2GB
            min_cpus: 1,

        }
    }
}

pub fn check_system_requirements(reqs: &SystemRequirements) -> Result<()> {
    let mut sys = System::new_all();
    sys.refresh_memory();
    sys.refresh_cpu();

    let total_ram_mb = sys.total_memory() / 1024 / 1024;
    let cpu_count = sys.cpus().len();

    info!("System Health Check: RAM {}MB, CPUs {}", total_ram_mb, cpu_count);

    let mut issues = Vec::new();

    if total_ram_mb < reqs.min_ram_mb {
        issues.push(format!(
            "Insufficient RAM: Found {}MB, requires at least {}MB.",
            total_ram_mb, reqs.min_ram_mb
        ));
    }

    if cpu_count < reqs.min_cpus {
        issues.push(format!(
            "Insufficient CPU Cores: Found {}, requires at least {}.",
            cpu_count, reqs.min_cpus
        ));
    }

    if !issues.is_empty() {
        for issue in &issues {
            error!("Pre-flight Failure: {}", issue);
        }
        return Err(anyhow!("System requirements not met. Please upgrade your hardware to run OpenỌ̀ṣọ́ọ̀sì Agent."));
    }

    info!("System requirements check: PASSED");
    Ok(())
}

pub fn get_os_info() -> (String, String, bool) {
    let name = System::name().unwrap_or_else(|| "unknown".to_string());
    let version = System::os_version().unwrap_or_else(|| "unknown".to_string());
    
    // Simple heuristic for "supported": Recent versions
    let supported = if name.to_lowercase().contains("windows") {
        version.contains("10") || version.contains("11") || version.contains("Server")
    } else if name.to_lowercase().contains("linux") {
        true // Most modern distros are fine
    } else if name.to_lowercase().contains("darwin") || name.to_lowercase().contains("mac") {
        true
    } else {
        false
    };

    (name, version, supported)
}

/// Runs SFC /SCANFILE on Windows to verify if a file is an untampered system file.
/// Returns true if the file is verified clean by Microsoft's store.
pub async fn validate_windows_file_integrity(path: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        use std::path::Path;

        let path_obj = Path::new(path);
        let win_dir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
        
        // Only run SFC for files inside C:\Windows (to save time and avoid erroring on user files)
        if !path_obj.to_string_lossy().to_ascii_lowercase().starts_with(&win_dir.to_ascii_lowercase()) {
            return false;
        }

        info!("SFC Validation: Running 'sfc /scanfile' on {} before remediation...", path);
        
        // SFC /SCANFILE requires full path
        let output = match Command::new("sfc")
            .args(["/scanfile", path])
            .output() {
                Ok(o) => o,
                Err(e) => {
                    error!("SFC Validation: Could not execute sfc: {}", e);
                    return false;
                }
            };
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        // SFC doesn't use exit codes reliably (often 0 even if failure); parse stdout.
        // "Windows Resource Protection did not find any integrity violations." 
        // 0x4B0 represents a success message for many locales in hex, but string matching is safer for 'clean'.
        if stdout.contains("did not find any integrity violations") || stdout.contains("integrity violations and successfully repaired") {
            info!("SFC Validation: File {} is verified CLEAN (original/repaired by Microsoft).", path);
            return true;
        }
        
        warn!("SFC Validation: File {} FAILED integrity check or is not a system file.", path);
    }
    
    #[cfg(not(target_os = "windows"))]
    let _ = path;

    false
}
