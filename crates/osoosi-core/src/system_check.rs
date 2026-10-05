use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sysinfo::System;
use tracing::{error, info, warn};

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

    info!(
        "System Health Check: RAM {}MB, CPUs {}",
        total_ram_mb, cpu_count
    );

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
        return Err(anyhow!(
            "System requirements not met. Please upgrade your hardware to run OpenỌ̀ṣọ́ọ̀sì Agent."
        ));
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

/// Check if a binary path is an administrative CLI tool / Living-off-the-Land Binary (LOLBin).
/// These binaries are signed by Microsoft and valid, but are routinely abused to execute threats
/// (e.g. net.exe creating rogue accounts, powershell.exe downloading beacons, vssadmin deleting shadows).
pub fn is_administrative_lolbin(path: &str) -> bool {
    let path_lc = path.to_ascii_lowercase();
    let filename = std::path::Path::new(&path_lc)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&path_lc);
    matches!(
        filename,
        "net.exe"
            | "net1.exe"
            | "powershell.exe"
            | "pwsh.exe"
            | "cmd.exe"
            | "wmic.exe"
            | "schtasks.exe"
            | "reg.exe"
            | "vssadmin.exe"
            | "wbadmin.exe"
            | "bcdedit.exe"
            | "rundll32.exe"
            | "mshta.exe"
            | "certutil.exe"
            | "bitsadmin.exe"
    )
}

/// Double-veto check: returns true ONLY if the file is genuinely clean and safe to exempt from remediation.
/// If the file is an administrative LOLBin and an active threat is detected (e.g. T1136, T1003),
/// returns false so SFC cannot veto or downgrade the autonomous response.
pub async fn validate_file_safety_with_veto(path: &str, has_active_threat: bool) -> bool {
    if is_administrative_lolbin(path) && has_active_threat {
        warn!(
            "SFC DOUBLE-VETO: Binary {} is an administrative LOLBin executing active threat. SFC safety override disallowed.",
            path
        );
        return false;
    }
    validate_windows_file_integrity(path).await
}

/// Runs SFC /SCANFILE on Windows to verify if a file is an untampered system file.
/// Returns true if the file is verified clean by Microsoft's store.
pub async fn validate_windows_file_integrity(path: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        use std::path::Path;
        use std::process::Command;

        let path_obj = Path::new(path);
        let win_dir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());

        // Only run SFC for files inside C:\Windows (to save time and avoid erroring on user files)
        if !path_obj
            .to_string_lossy()
            .to_ascii_lowercase()
            .starts_with(&win_dir.to_ascii_lowercase())
        {
            return false;
        }

        info!(
            "SFC Validation: Running 'sfc /scanfile' on {} before remediation...",
            path
        );

        // SFC /SCANFILE requires full path
        let output = match Command::new("sfc").args(["/scanfile", path]).output() {
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
        if stdout.contains("did not find any integrity violations")
            || stdout.contains("integrity violations and successfully repaired")
        {
            info!(
                "SFC Validation: File {} is verified CLEAN (original/repaired by Microsoft).",
                path
            );
            return true;
        }

        warn!(
            "SFC Validation: File {} FAILED integrity check or is not a system file.",
            path
        );
    }

    #[cfg(not(target_os = "windows"))]
    let _ = path;

    false
}

/// Detect presence of hardware GPU accelerators (NVIDIA CUDA, Direct3D 12, Vulkan).
pub fn detect_gpu() -> (bool, Option<String>) {
    if let Ok(path) = std::env::var("ORT_DYLIB_PATH") {
        let p_lower = path.to_lowercase();
        if p_lower.contains("cuda") {
            return (true, Some("NVIDIA CUDA (via ORT_DYLIB_PATH)".to_string()));
        } else if p_lower.contains("dml") || p_lower.contains("directml") {
            return (true, Some("DirectML GPU (via ORT_DYLIB_PATH)".to_string()));
        }
    }
    if let Ok(cuda_path) = std::env::var("CUDA_PATH") {
        if !cuda_path.trim().is_empty() {
            return (true, Some(format!("NVIDIA CUDA ({})", cuda_path.trim())));
        }
    }
    if std::env::var("OSOOSI_FORCE_GPU").map(|v| v == "1").unwrap_or(false) {
        return (true, Some("Forced GPU".to_string()));
    }

    #[cfg(target_os = "windows")]
    {
        if std::path::Path::new("C:\\Windows\\System32\\nvcuda.dll").exists() {
            return (true, Some("NVIDIA CUDA Driver".to_string()));
        }
        if std::path::Path::new("C:\\Windows\\System32\\vulkan-1.dll").exists() {
            return (true, Some("Vulkan Graphics / Compute".to_string()));
        }
        if std::path::Path::new("C:\\Windows\\System32\\d3d12.dll").exists() {
            return (true, Some("Direct3D 12 Hardware Acceleration".to_string()));
        }
    }

    #[cfg(target_os = "linux")]
    {
        if std::path::Path::new("/usr/lib/x86_64-linux-gnu/libcuda.so").exists()
            || std::path::Path::new("/usr/local/cuda").exists()
        {
            return (true, Some("NVIDIA CUDA Driver (Linux)".to_string()));
        }
        if std::path::Path::new("/dev/dri/renderD128").exists() {
            return (true, Some("DRI Direct Rendering Manager".to_string()));
        }
    }

    (false, None)
}

/// Comprehensive hardware resource profile of the host endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResourceProfile {
    pub total_ram_mb: u64,
    pub available_ram_mb: u64,
    pub cpu_cores: usize,
    pub os_name: String,
    pub os_version: String,
    pub tier: osoosi_types::config::HardwareTier,
    pub has_gpu: bool,
    pub gpu_name: Option<String>,
}

/// Operational verdict for a given machine learning model or service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelResourceVerdict {
    pub model_name: String,
    pub required_ram_mb: u64,
    pub available_ram_mb: u64,
    pub can_load: bool,
    pub status: String, // "Active", "Skipped (Insufficient RAM)", "Fallback Heuristic Active"
}

impl HostResourceProfile {
    /// Detect live hardware resources and dynamically evaluate hardware tier.
    pub fn detect() -> Self {
        let mut sys = System::new_all();
        sys.refresh_memory();
        sys.refresh_cpu();

        let total_ram_mb = sys.total_memory() / (1024 * 1024);
        let available_ram_mb = sys.available_memory() / (1024 * 1024);
        let cpu_cores = sys.cpus().len();

        let (os_name, os_version, _) = get_os_info();
        let (has_gpu, gpu_name) = detect_gpu();

        let res_cfg = osoosi_types::load_resources_config();
        let tier = Self::resolve_tier(&res_cfg.profile, total_ram_mb, available_ram_mb);

        Self {
            total_ram_mb,
            available_ram_mb,
            cpu_cores,
            os_name,
            os_version,
            tier,
            has_gpu,
            gpu_name,
        }
    }

    /// Resolve hardware tier given configured profile override or raw memory numbers.
    pub fn resolve_tier(profile_str: &str, total_ram_mb: u64, available_ram_mb: u64) -> osoosi_types::config::HardwareTier {
        match profile_str.trim().to_lowercase().as_str() {
            "ultralite" | "ultra_lite" | "ultra-lite" => osoosi_types::config::HardwareTier::UltraLite,
            "lite" => osoosi_types::config::HardwareTier::Lite,
            "standard" => osoosi_types::config::HardwareTier::Standard,
            "enterprise" => osoosi_types::config::HardwareTier::Enterprise,
            _ => {
                if total_ram_mb < 4096 || available_ram_mb < 1500 {
                    osoosi_types::config::HardwareTier::UltraLite
                } else if total_ram_mb < 8192 || available_ram_mb < 3500 {
                    osoosi_types::config::HardwareTier::Lite
                } else if total_ram_mb < 16384 || available_ram_mb < 7000 {
                    osoosi_types::config::HardwareTier::Standard
                } else {
                    osoosi_types::config::HardwareTier::Enterprise
                }
            }
        }
    }

    /// Evaluate operational readiness across all registered models and subsystems.
    pub fn evaluate_model_readiness(&self, cfg: &osoosi_types::config::ResourcesConfig) -> Vec<ModelResourceVerdict> {
        vec![
            ModelResourceVerdict {
                model_name: "Magika (Type Classifier)".to_string(),
                required_ram_mb: 50,
                available_ram_mb: self.available_ram_mb,
                can_load: self.can_load_model("magika", cfg),
                status: if self.can_load_model("magika", cfg) {
                    "Active".to_string()
                } else {
                    "Fallback Heuristic Active".to_string()
                },
            },
            ModelResourceVerdict {
                model_name: "EMBER / MalConv (PE Neural)".to_string(),
                required_ram_mb: cfg.min_free_ram_mb_for_malconv,
                available_ram_mb: self.available_ram_mb,
                can_load: self.can_load_model("malconv", cfg),
                status: if self.can_load_model("malconv", cfg) {
                    "Active".to_string()
                } else {
                    "Skipped (Insufficient RAM)".to_string()
                },
            },
            ModelResourceVerdict {
                model_name: "SOREL-20M (Deep Malware FFNN)".to_string(),
                required_ram_mb: cfg.min_free_ram_mb_for_sorel,
                available_ram_mb: self.available_ram_mb,
                can_load: self.can_load_model("sorel", cfg),
                status: if self.can_load_model("sorel", cfg) {
                    "Active".to_string()
                } else {
                    "Skipped (Insufficient RAM)".to_string()
                },
            },
            ModelResourceVerdict {
                model_name: "SecureBERT (Behavioral Sentence)".to_string(),
                required_ram_mb: cfg.min_free_ram_mb_for_securebert,
                available_ram_mb: self.available_ram_mb,
                can_load: self.can_load_model("securebert", cfg),
                status: if self.can_load_model("securebert", cfg) {
                    "Active".to_string()
                } else {
                    "Skipped (Insufficient RAM)".to_string()
                },
            },
            ModelResourceVerdict {
                model_name: "Clef Flash (Fast Decision Engine)".to_string(),
                required_ram_mb: 100,
                available_ram_mb: self.available_ram_mb,
                can_load: self.can_load_model("clef", cfg),
                status: if self.can_load_model("clef", cfg) {
                    "Active".to_string()
                } else {
                    "Fallback Heuristic Active".to_string()
                },
            },
            ModelResourceVerdict {
                model_name: "Strands Decider 2B (SLM Arbiter)".to_string(),
                required_ram_mb: cfg.min_free_ram_mb_for_strands_decider,
                available_ram_mb: self.available_ram_mb,
                can_load: self.can_load_model("strands", cfg),
                status: if self.can_load_model("strands", cfg) {
                    "Active".to_string()
                } else {
                    "Skipped (Insufficient RAM)".to_string()
                },
            },
            ModelResourceVerdict {
                model_name: "FoundationSec-8B (Cisco / Gemma 4)".to_string(),
                required_ram_mb: cfg.min_free_ram_mb_for_foundation_sec,
                available_ram_mb: self.available_ram_mb,
                can_load: self.can_load_model("foundation_sec", cfg),
                status: if self.can_load_model("foundation_sec", cfg) {
                    "Active".to_string()
                } else {
                    "Skipped (Insufficient RAM)".to_string()
                },
            },
            ModelResourceVerdict {
                model_name: "Web Browser (External Dashboard)".to_string(),
                required_ram_mb: cfg.min_free_ram_mb_for_browser,
                available_ram_mb: self.available_ram_mb,
                can_load: self.can_launch_browser(cfg),
                status: if self.can_launch_browser(cfg) {
                    "Ready".to_string()
                } else {
                    "Suppressed (Low RAM Protection)".to_string()
                },
            },
            ModelResourceVerdict {
                model_name: "NSRL SQLite Hash Cache".to_string(),
                required_ram_mb: match self.tier {
                    osoosi_types::config::HardwareTier::UltraLite => 100,
                    osoosi_types::config::HardwareTier::Lite => 250,
                    osoosi_types::config::HardwareTier::Standard => 500,
                    osoosi_types::config::HardwareTier::Enterprise => 1000,
                },
                available_ram_mb: self.available_ram_mb,
                can_load: true,
                status: format!("Active (Cap: {} records)", self.recommended_nsrl_cache_limit()),
            },
        ]
    }

    /// Check if host has sufficient resources to safely execute/load a specific model.
    pub fn can_load_model(&self, model: &str, cfg: &osoosi_types::config::ResourcesConfig) -> bool {
        if !cfg.auto_throttle_ai_on_low_ram {
            return true;
        }
        let m = model.to_lowercase();
        if m.contains("foundation") || m.contains("gemma") || m.contains("cisco") {
            self.tier >= osoosi_types::config::HardwareTier::Enterprise
                && self.available_ram_mb >= cfg.min_free_ram_mb_for_foundation_sec
        } else if m.contains("strands") || m.contains("decider") {
            self.tier >= osoosi_types::config::HardwareTier::Standard
                && self.available_ram_mb >= cfg.min_free_ram_mb_for_strands_decider
        } else if m.contains("securebert") || m.contains("bert") {
            self.tier >= osoosi_types::config::HardwareTier::Lite
                && self.available_ram_mb >= cfg.min_free_ram_mb_for_securebert
        } else if m.contains("sorel") {
            self.tier >= osoosi_types::config::HardwareTier::Lite
                && self.available_ram_mb >= cfg.min_free_ram_mb_for_sorel
        } else if m.contains("malconv") || m.contains("ember") || m.contains("bodmas") {
            self.available_ram_mb >= cfg.min_free_ram_mb_for_malconv
        } else if m.contains("magika") {
            self.available_ram_mb >= 50
        } else if m.contains("clef") {
            self.available_ram_mb >= 100
        } else {
            self.available_ram_mb >= 500
        }
    }

    /// Check whether external browser process should be launched.
    pub fn can_launch_browser(&self, cfg: &osoosi_types::config::ResourcesConfig) -> bool {
        if !cfg.auto_suppress_browser_on_low_ram {
            return true;
        }
        self.available_ram_mb >= cfg.min_free_ram_mb_for_browser
            && self.tier >= osoosi_types::config::HardwareTier::Standard
    }

    /// Determine safe maximum in-memory cache limit for NSRL hash verification.
    pub fn recommended_nsrl_cache_limit(&self) -> usize {
        let cfg = osoosi_types::load_resources_config();
        if let Some(limit) = cfg.nsrl_cache_limit {
            return limit;
        }
        match self.tier {
            osoosi_types::config::HardwareTier::UltraLite => 25_000,
            osoosi_types::config::HardwareTier::Lite => 100_000,
            osoosi_types::config::HardwareTier::Standard => 500_000,
            osoosi_types::config::HardwareTier::Enterprise => 2_500_000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osoosi_types::config::{HardwareTier, ResourcesConfig};

    #[test]
    fn test_tier_resolution_auto() {
        // UltraLite: total < 4096 or avail < 1500
        assert_eq!(HostResourceProfile::resolve_tier("auto", 2048, 1024), HardwareTier::UltraLite);
        assert_eq!(HostResourceProfile::resolve_tier("auto", 16384, 1000), HardwareTier::UltraLite);

        // Lite: total < 8192 or avail < 3500 (and not UltraLite)
        assert_eq!(HostResourceProfile::resolve_tier("auto", 6144, 2500), HardwareTier::Lite);
        assert_eq!(HostResourceProfile::resolve_tier("auto", 16384, 2500), HardwareTier::Lite);

        // Standard: total < 16384 or avail < 7000 (and not Lite/UltraLite)
        assert_eq!(HostResourceProfile::resolve_tier("auto", 12288, 5000), HardwareTier::Standard);
        assert_eq!(HostResourceProfile::resolve_tier("auto", 32768, 5000), HardwareTier::Standard);

        // Enterprise: total >= 16384 and avail >= 7000
        assert_eq!(HostResourceProfile::resolve_tier("auto", 32768, 16384), HardwareTier::Enterprise);
    }

    #[test]
    fn test_tier_resolution_overrides() {
        assert_eq!(HostResourceProfile::resolve_tier("ultralite", 65536, 32768), HardwareTier::UltraLite);
        assert_eq!(HostResourceProfile::resolve_tier("lite", 65536, 32768), HardwareTier::Lite);
        assert_eq!(HostResourceProfile::resolve_tier("standard", 1024, 512), HardwareTier::Standard);
        assert_eq!(HostResourceProfile::resolve_tier("enterprise", 1024, 512), HardwareTier::Enterprise);
    }

    #[test]
    fn test_ultralite_verdicts() {
        let profile = HostResourceProfile {
            total_ram_mb: 2048,
            available_ram_mb: 1200,
            cpu_cores: 2,
            os_name: "Windows".to_string(),
            os_version: "11".to_string(),
            tier: HardwareTier::UltraLite,
            has_gpu: false,
            gpu_name: None,
        };
        let cfg = ResourcesConfig::default();

        assert!(profile.can_load_model("magika", &cfg));
        assert!(profile.can_load_model("malconv", &cfg));
        assert!(!profile.can_load_model("sorel", &cfg));
        assert!(!profile.can_load_model("securebert", &cfg));
        assert!(!profile.can_load_model("strands", &cfg));
        assert!(!profile.can_load_model("foundation_sec", &cfg));
        assert!(!profile.can_launch_browser(&cfg));
        assert_eq!(profile.recommended_nsrl_cache_limit(), 25_000);

        let verdicts = profile.evaluate_model_readiness(&cfg);
        assert_eq!(verdicts.len(), 9);
        let browser_v = verdicts.iter().find(|v| v.model_name.contains("Browser")).unwrap();
        assert!(!browser_v.can_load);
    }

    #[test]
    fn test_lite_verdicts() {
        let profile = HostResourceProfile {
            total_ram_mb: 6144,
            available_ram_mb: 2800,
            cpu_cores: 4,
            os_name: "Windows".to_string(),
            os_version: "11".to_string(),
            tier: HardwareTier::Lite,
            has_gpu: false,
            gpu_name: None,
        };
        let cfg = ResourcesConfig::default();

        assert!(profile.can_load_model("magika", &cfg));
        assert!(profile.can_load_model("malconv", &cfg));
        assert!(profile.can_load_model("sorel", &cfg));
        assert!(profile.can_load_model("securebert", &cfg));
        assert!(profile.can_load_model("clef", &cfg));
        assert!(!profile.can_load_model("strands", &cfg));
        assert!(!profile.can_load_model("foundation_sec", &cfg));
        assert!(!profile.can_launch_browser(&cfg));
        assert_eq!(profile.recommended_nsrl_cache_limit(), 100_000);
    }

    #[test]
    fn test_standard_verdicts() {
        let profile = HostResourceProfile {
            total_ram_mb: 16384,
            available_ram_mb: 5000,
            cpu_cores: 8,
            os_name: "Windows".to_string(),
            os_version: "11".to_string(),
            tier: HardwareTier::Standard,
            has_gpu: true,
            gpu_name: Some("NVIDIA".to_string()),
        };
        let cfg = ResourcesConfig::default();

        assert!(profile.can_load_model("strands", &cfg));
        assert!(!profile.can_load_model("foundation_sec", &cfg));
        assert!(profile.can_launch_browser(&cfg));
        assert_eq!(profile.recommended_nsrl_cache_limit(), 500_000);
    }

    #[test]
    fn test_enterprise_verdicts() {
        let profile = HostResourceProfile {
            total_ram_mb: 32768,
            available_ram_mb: 16384,
            cpu_cores: 16,
            os_name: "Windows".to_string(),
            os_version: "11".to_string(),
            tier: HardwareTier::Enterprise,
            has_gpu: true,
            gpu_name: Some("NVIDIA".to_string()),
        };
        let cfg = ResourcesConfig::default();

        assert!(profile.can_load_model("foundation_sec", &cfg));
        assert!(profile.can_launch_browser(&cfg));
        assert_eq!(profile.recommended_nsrl_cache_limit(), 2_500_000);
    }
}


