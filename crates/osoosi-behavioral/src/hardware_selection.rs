//! Hardware-Aware AI Model Selection Engine
//!
//! Adapted from ModelFusion architecture for OpenỌ̀ṣọ́ọ̀sì / OshoosiClaw.
//! Performs automated hardware profiling (CPU, RAM, GPU, VRAM, Disks) and selects
//! optimal dual-model pairs (Real-Time Fast Triage + Deep Forensic Graph Synthesis)
//! based on runtime compute tiers without altering or removing existing installed models.

use serde::{Deserialize, Serialize};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;
use sysinfo::{Disks, System};
use tracing::{debug, warn};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Disk partition resource information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskResourceInfo {
    pub mount_point: String,
    pub name: String,
    pub total_gb: f64,
    pub free_gb: f64,
    pub file_system: String,
}

/// Comprehensive hardware telemetry summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemResourceSummary {
    pub cpu_name: String,
    pub logical_cores: usize,
    pub total_ram_gb: f64,
    pub free_ram_gb: f64,
    pub gpu_name: String,
    pub total_vram_mb: u64,
    pub free_vram_mb: u64,
    pub has_gpu: bool,
    pub free_disk_gb: f64,
    pub total_disk_gb: f64,
    pub disks: Vec<DiskResourceInfo>,
}

/// Hardware performance tiers for dynamic model placement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HardwareTier {
    Tier1Constrained, // <12GB RAM, <4GB VRAM (e.g. edge node/laptop)
    Tier2MidRange,    // 12-32GB RAM, 4-8GB VRAM (e.g. dev workstation)
    Tier3HighPerf,    // 32-64GB RAM, 8-16GB VRAM (e.g. high-end workstation)
    Tier4Enterprise,  // >64GB RAM, 16GB+ VRAM or 32+ CPU threads (e.g. multi-socket server)
}

impl HardwareTier {
    pub fn label(&self) -> &'static str {
        match self {
            HardwareTier::Tier1Constrained => "CONSTRAINED / EDGE NODE",
            HardwareTier::Tier2MidRange => "MID-RANGE WORKSTATION",
            HardwareTier::Tier3HighPerf => "HIGH-PERFORMANCE WORKSTATION",
            HardwareTier::Tier4Enterprise => "ENTERPRISE / HIGH-THROUGHPUT",
        }
    }
}

impl SystemResourceSummary {
    /// Determines hardware tier according to available CPU threads, RAM, and GPU VRAM.
    pub fn determine_tier(&self) -> HardwareTier {
        if (self.total_ram_gb >= 64.0 || self.logical_cores >= 32)
            && (self.total_ram_gb >= 48.0 || self.total_vram_mb >= 16_000)
        {
            HardwareTier::Tier4Enterprise
        } else if self.total_ram_gb >= 32.0 || self.total_vram_mb >= 8_000 {
            HardwareTier::Tier3HighPerf
        } else if self.total_ram_gb >= 12.0 || self.total_vram_mb >= 4_000 {
            HardwareTier::Tier2MidRange
        } else {
            HardwareTier::Tier1Constrained
        }
    }
}

/// Optimal fast-path and deep-forensic model selection output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimalModelSelection {
    pub fast_model: String,
    pub deep_model: String,
    pub hardware_tier: HardwareTier,
    pub hardware_tier_label: String,
    pub recommended_device: String,
    pub total_ram_gb: f64,
    pub free_ram_gb: f64,
    pub gpu_vram_mb: u64,
    pub cpu_cores: usize,
    pub rationale: String,
}

static CACHED_SYSTEM_RESOURCES: OnceLock<SystemResourceSummary> = OnceLock::new();

/// Cached query for system resources.
pub fn get_system_resources() -> SystemResourceSummary {
    CACHED_SYSTEM_RESOURCES
        .get_or_init(query_system_resources)
        .clone()
}

/// Uncached live detection of system resources.
pub fn detect_live_resources() -> SystemResourceSummary {
    query_system_resources()
}

/// Probe GPU details via nvidia-smi with hidden window.
fn probe_nvidia_gpu() -> Option<(String, u64, u64)> {
    let mut cmd = Command::new("nvidia-smi");
    cmd.args([
        "--query-gpu=name,memory.total,memory.free",
        "--format=csv,noheader,nounits",
    ]);

    #[cfg(target_os = "windows")]
    cmd.creation_flags(CREATE_NO_WINDOW);

    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
        if parts.len() >= 3 {
            let name = parts[0].to_string();
            let total: u64 = parts[1].parse().unwrap_or(0);
            let free: u64 = parts[2].parse().unwrap_or(0);
            if total > 0 {
                return Some((name, total, free));
            }
        }
    }
    None
}

/// Windows WMIC fallback probe for display adapters.
#[cfg(target_os = "windows")]
fn probe_wmic_gpu() -> Option<(String, u64, u64)> {
    let mut cmd = Command::new("wmic");
    cmd.args([
        "path",
        "win32_VideoController",
        "get",
        "name,adapterram",
        "/format:csv",
    ]);
    cmd.creation_flags(CREATE_NO_WINDOW);

    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
        if parts.len() >= 3 && !parts[1].is_empty() && parts[1] != "AdapterRAM" {
            let bytes: u64 = parts[1].parse().unwrap_or(0);
            let vram_mb = bytes / (1024 * 1024);
            let name = parts[2].trim().to_string();
            if vram_mb > 0 {
                return Some((name, vram_mb, vram_mb));
            }
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
fn probe_wmic_gpu() -> Option<(String, u64, u64)> {
    None
}

/// Query system resources (CPU, RAM, GPU, Disks).
pub fn query_system_resources() -> SystemResourceSummary {
    let mut sys = System::new_all();
    sys.refresh_cpu();
    sys.refresh_memory();

    let cpu_name = sys
        .cpus()
        .first()
        .map(|c| c.brand().trim().to_string())
        .unwrap_or_else(|| "Unknown CPU".to_string());
    let logical_cores = sys.cpus().len().max(1);

    let total_ram_gb = ((sys.total_memory() as f64) / (1024.0 * 1024.0 * 1024.0) * 10.0).round() / 10.0;
    let free_ram_gb = ((sys.available_memory() as f64) / (1024.0 * 1024.0 * 1024.0) * 10.0).round() / 10.0;

    let (gpu_name, total_vram_mb, free_vram_mb, has_gpu) =
        if let Some((name, tot, free)) = probe_nvidia_gpu() {
            (name, tot, free, true)
        } else if let Some((name, tot, free)) = probe_wmic_gpu() {
            (name, tot, free, true)
        } else {
            ("No dedicated GPU detected".to_string(), 0, 0, false)
        };

    let disks_obj = Disks::new_with_refreshed_list();
    let mut disks = Vec::new();
    let mut total_disk_bytes: u64 = 0;
    let mut free_disk_bytes: u64 = 0;

    for d in disks_obj.iter() {
        let total_gb = ((d.total_space() as f64) / (1024.0 * 1024.0 * 1024.0) * 10.0).round() / 10.0;
        let free_gb = ((d.available_space() as f64) / (1024.0 * 1024.0 * 1024.0) * 10.0).round() / 10.0;
        total_disk_bytes = total_disk_bytes.saturating_add(d.total_space());
        free_disk_bytes = free_disk_bytes.saturating_add(d.available_space());

        disks.push(DiskResourceInfo {
            mount_point: d.mount_point().to_string_lossy().to_string(),
            name: d.name().to_string_lossy().to_string(),
            total_gb,
            free_gb,
            file_system: d.file_system().to_string_lossy().to_string(),
        });
    }

    let total_disk_gb = ((total_disk_bytes as f64) / (1024.0 * 1024.0 * 1024.0) * 10.0).round() / 10.0;
    let free_disk_gb = ((free_disk_bytes as f64) / (1024.0 * 1024.0 * 1024.0) * 10.0).round() / 10.0;

    SystemResourceSummary {
        cpu_name,
        logical_cores,
        total_ram_gb,
        free_ram_gb,
        gpu_name,
        total_vram_mb,
        free_vram_mb,
        has_gpu,
        free_disk_gb,
        total_disk_gb,
        disks,
    }
}

/// Case-insensitive model name fuzzy/prefix matching helper.
fn model_matches(candidate: &str, installed: &str) -> bool {
    let cand = candidate.trim().to_lowercase();
    let inst = installed.trim().to_lowercase();
    if cand == inst {
        return true;
    }
    let inst_no_latest = inst.strip_suffix(":latest").unwrap_or(&inst);
    let cand_no_latest = cand.strip_suffix(":latest").unwrap_or(&cand);
    cand_no_latest == inst_no_latest || inst.contains(&cand) || cand.contains(&inst)
}

/// Find first matching model from candidates in the installed list.
fn find_installed_match(candidates: &[&str], installed: &[String]) -> Option<String> {
    for &cand in candidates {
        if let Some(found) = installed.iter().find(|inst| model_matches(cand, inst)) {
            return Some(found.clone());
        }
    }
    None
}

/// Select optimal models adapted from ModelFusion routing rules.
///
/// Ensures zero-disruption: NEVER deletes or overrides existing models,
/// prioritizing currently installed Ollama models and safely falling back
/// to user configured models.
pub fn select_optimal_models(
    res: &SystemResourceSummary,
    installed_ollama_models: &[String],
    configured_fast_model: &str,
    configured_deep_model: &str,
) -> OptimalModelSelection {
    let tier = res.determine_tier();
    let tier_label = tier.label().to_string();

    // 1. Fast Model Selection (Real-Time Event Triage)
    let fast_candidates = [
        "deepseek-r1:1.5b",
        "qwen2.5:1.5b",
        "qwen2.5:7b",
        "gemma3:1b",
        "phi3:mini",
    ];

    let fast_model = if !configured_fast_model.is_empty()
        && installed_ollama_models
            .iter()
            .any(|inst| model_matches(configured_fast_model, inst))
    {
        configured_fast_model.to_string()
    } else if let Some(m) = find_installed_match(&fast_candidates, installed_ollama_models) {
        m
    } else if !configured_fast_model.is_empty() {
        configured_fast_model.to_string()
    } else {
        "deepseek-r1:1.5b".to_string()
    };

    // 2. Deep Model Selection (Causal Attack Graph Forensic Reasoning)
    let deep_candidates: &[&str] = match tier {
        HardwareTier::Tier4Enterprise => &[
            "deepseek-r1:32b",
            "qwen2.5:32b",
            "fenkohq/foundation-sec-8b:latest",
            "fenkohq/foundation-sec-8b",
        ],
        HardwareTier::Tier3HighPerf => &[
            "qwen2.5:14b",
            "fenkohq/foundation-sec-8b",
            "deepseek-r1:7b",
            "qwen2.5:7b",
        ],
        HardwareTier::Tier2MidRange => &[
            "qwen2.5:7b",
            "deepseek-r1:7b",
            "fenkohq/foundation-sec-8b",
        ],
        HardwareTier::Tier1Constrained => &[
            "deepseek-r1:1.5b",
            "qwen2.5:1.5b",
            "qwen2.5:3b",
        ],
    };

    let deep_model = if let Some(m) = find_installed_match(deep_candidates, installed_ollama_models) {
        m
    } else if !configured_deep_model.is_empty() {
        configured_deep_model.to_string()
    } else {
        deep_candidates
            .first()
            .copied()
            .unwrap_or("fenkohq/foundation-sec-8b")
            .to_string()
    };

    // 3. Recommended Device Placement
    let is_large_model = deep_model.contains("32b") || deep_model.contains("70b");
    let recommended_device = if res.has_gpu
        && is_large_model
        && res.logical_cores >= 32
        && res.total_vram_mb <= 12_000
    {
        "Hybrid Offload (VRAM layers + High-Core CPU threads)".to_string()
    } else if res.has_gpu && res.free_vram_mb >= 2000 {
        "GPU (CUDA / Tensor Cores)".to_string()
    } else {
        "CPU (AVX2/AVX-512)".to_string()
    };

    // 4. Diagnostic Rationale
    let rationale = format!(
        "Detected {} profile ({} logical cores, {:.1} GB RAM, GPU: {} [{} MB VRAM]). Selected fast-path '{}' and deep-path '{}' utilizing {}.",
        tier_label,
        res.logical_cores,
        res.total_ram_gb,
        res.gpu_name,
        res.total_vram_mb,
        fast_model,
        deep_model,
        recommended_device
    );

    OptimalModelSelection {
        fast_model,
        deep_model,
        hardware_tier: tier,
        hardware_tier_label: tier_label,
        recommended_device,
        total_ram_gb: res.total_ram_gb,
        free_ram_gb: res.free_ram_gb,
        gpu_vram_mb: res.total_vram_mb,
        cpu_cores: res.logical_cores,
        rationale,
    }
}

#[derive(Deserialize)]
struct OllamaTagsResponse {
    models: Option<Vec<OllamaModelTag>>,
}

#[derive(Deserialize)]
struct OllamaModelTag {
    name: Option<String>,
    model: Option<String>,
}

/// Query currently installed models in local Ollama service.
///
/// Uses a strict 2-second timeout to prevent any blocking of supervisor threads.
/// Returns an empty vector if Ollama is unreachable.
pub async fn query_installed_ollama_models(ollama_endpoint: &str) -> Vec<String> {
    let tags_url = if ollama_endpoint.is_empty() {
        "http://127.0.0.1:11434/api/tags".to_string()
    } else if let Ok(mut parsed) = reqwest::Url::parse(ollama_endpoint) {
        parsed.set_path("/api/tags");
        parsed.set_query(None);
        parsed.to_string()
    } else {
        "http://127.0.0.1:11434/api/tags".to_string()
    };

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to build HTTP client for Ollama tag query: {}", e);
            return Vec::new();
        }
    };

    match client.get(&tags_url).send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                if let Ok(data) = resp.json::<OllamaTagsResponse>().await {
                    if let Some(list) = data.models {
                        let names: Vec<String> = list
                            .into_iter()
                            .filter_map(|m| m.name.or(m.model))
                            .collect();
                        debug!("Discovered {} installed Ollama models.", names.len());
                        return names;
                    }
                }
            }
            Vec::new()
        }
        Err(e) => {
            debug!("Ollama query at {} timed out or unavailable: {}", tags_url, e);
            Vec::new()
        }
    }
}

/// Synchronous query of installed models in local Ollama service.
///
/// Uses a strict 2-second timeout to prevent stalling calling threads.
pub fn query_installed_ollama_models_sync(ollama_endpoint: &str) -> Vec<String> {
    if tokio::runtime::Handle::try_current().is_ok() {
        let ep = ollama_endpoint.to_string();
        std::thread::spawn(move || query_installed_ollama_models_sync_inner(&ep))
            .join()
            .unwrap_or_default()
    } else {
        query_installed_ollama_models_sync_inner(ollama_endpoint)
    }
}

fn query_installed_ollama_models_sync_inner(ollama_endpoint: &str) -> Vec<String> {
    let tags_url = if ollama_endpoint.is_empty() {
        "http://127.0.0.1:11434/api/tags".to_string()
    } else if let Ok(mut parsed) = reqwest::Url::parse(ollama_endpoint) {
        parsed.set_path("/api/tags");
        parsed.set_query(None);
        parsed.to_string()
    } else {
        "http://127.0.0.1:11434/api/tags".to_string()
    };

    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to build sync HTTP client for Ollama tag query: {}", e);
            return Vec::new();
        }
    };

    match client.get(&tags_url).send() {
        Ok(resp) => {
            if resp.status().is_success() {
                if let Ok(data) = resp.json::<OllamaTagsResponse>() {
                    if let Some(list) = data.models {
                        let names: Vec<String> = list
                            .into_iter()
                            .filter_map(|m| m.name.or(m.model))
                            .collect();
                        debug!("Discovered {} installed Ollama models (sync).", names.len());
                        return names;
                    }
                }
            }
            Vec::new()
        }
        Err(e) => {
            debug!("Ollama query at {} timed out or unavailable: {}", tags_url, e);
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_system_resources_non_empty() {
        let res = query_system_resources();
        assert!(res.logical_cores > 0, "Logical cores must be > 0");
        assert!(res.total_ram_gb > 0.0, "Total RAM must be > 0.0 GB");
        assert!(!res.disks.is_empty(), "Disks list must not be empty");
    }

    #[test]
    fn test_determine_hardware_tier() {
        let tier1 = SystemResourceSummary {
            cpu_name: "Intel Core i3".into(),
            logical_cores: 4,
            total_ram_gb: 8.0,
            free_ram_gb: 3.0,
            gpu_name: "None".into(),
            total_vram_mb: 0,
            free_vram_mb: 0,
            has_gpu: false,
            free_disk_gb: 50.0,
            total_disk_gb: 256.0,
            disks: vec![],
        };
        assert_eq!(tier1.determine_tier(), HardwareTier::Tier1Constrained);

        let tier2 = SystemResourceSummary {
            cpu_name: "AMD Ryzen 5".into(),
            logical_cores: 12,
            total_ram_gb: 16.0,
            free_ram_gb: 8.0,
            gpu_name: "GTX 1650".into(),
            total_vram_mb: 4000,
            free_vram_mb: 2500,
            has_gpu: true,
            free_disk_gb: 150.0,
            total_disk_gb: 512.0,
            disks: vec![],
        };
        assert_eq!(tier2.determine_tier(), HardwareTier::Tier2MidRange);

        let tier3 = SystemResourceSummary {
            cpu_name: "AMD Ryzen 9".into(),
            logical_cores: 24,
            total_ram_gb: 32.0,
            free_ram_gb: 18.0,
            gpu_name: "RTX 3070".into(),
            total_vram_mb: 8000,
            free_vram_mb: 6000,
            has_gpu: true,
            free_disk_gb: 500.0,
            total_disk_gb: 1024.0,
            disks: vec![],
        };
        assert_eq!(tier3.determine_tier(), HardwareTier::Tier3HighPerf);

        let tier4 = SystemResourceSummary {
            cpu_name: "Dual Intel Xeon Gold 6154".into(),
            logical_cores: 72,
            total_ram_gb: 224.0,
            free_ram_gb: 180.0,
            gpu_name: "Quadro RTX 4000".into(),
            total_vram_mb: 8192,
            free_vram_mb: 7000,
            has_gpu: true,
            free_disk_gb: 800.0,
            total_disk_gb: 2048.0,
            disks: vec![],
        };
        assert_eq!(tier4.determine_tier(), HardwareTier::Tier4Enterprise);
    }

    #[test]
    fn test_select_optimal_models_preserves_installed() {
        let res = SystemResourceSummary {
            cpu_name: "Dual Intel Xeon Gold 6154".into(),
            logical_cores: 72,
            total_ram_gb: 224.0,
            free_ram_gb: 180.0,
            gpu_name: "Quadro RTX 4000".into(),
            total_vram_mb: 8192,
            free_vram_mb: 7000,
            has_gpu: true,
            free_disk_gb: 800.0,
            total_disk_gb: 2048.0,
            disks: vec![],
        };

        let installed = vec![
            "deepseek-r1:1.5b".to_string(),
            "deepseek-r1:32b".to_string(),
            "qwen2.5:32b".to_string(),
        ];

        let selection = select_optimal_models(
            &res,
            &installed,
            "deepseek-r1:1.5b",
            "fenkohq/foundation-sec-8b",
        );

        assert_eq!(selection.fast_model, "deepseek-r1:1.5b");
        assert_eq!(selection.deep_model, "deepseek-r1:32b");
        assert_eq!(selection.hardware_tier, HardwareTier::Tier4Enterprise);
        assert_eq!(
            selection.recommended_device,
            "Hybrid Offload (VRAM layers + High-Core CPU threads)"
        );
    }

    #[test]
    fn test_select_optimal_models_fallback() {
        let res = SystemResourceSummary {
            cpu_name: "Core i5".into(),
            logical_cores: 8,
            total_ram_gb: 16.0,
            free_ram_gb: 8.0,
            gpu_name: "Intel UHD".into(),
            total_vram_mb: 0,
            free_vram_mb: 0,
            has_gpu: false,
            free_disk_gb: 40.0,
            total_disk_gb: 256.0,
            disks: vec![],
        };

        let installed = vec![];
        let selection = select_optimal_models(
            &res,
            &installed,
            "custom-fast:1b",
            "custom-deep:7b",
        );

        assert_eq!(selection.fast_model, "custom-fast:1b");
        assert_eq!(selection.deep_model, "custom-deep:7b");
        assert_eq!(selection.hardware_tier, HardwareTier::Tier2MidRange);
        assert_eq!(selection.recommended_device, "CPU (AVX2/AVX-512)");
    }
}
