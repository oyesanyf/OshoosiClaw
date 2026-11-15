//! OS Kernel Vulnerability Scanning & Native Patch Orchestration CLI Handler.

use anyhow::Result;
use killswitch_kernel_patcher::{
    is_elevated, HostKernelInfo, KernelPatcher, KernelVulnerability, PatchExecutionResult,
    PatcherError, ScanOptions,
};
use serde::Serialize;

/// Structured JSON output payload for `osoosi patch-kernel --json`.
#[derive(Debug, Serialize)]
struct PatchKernelJsonReport {
    host_kernel: HostKernelInfo,
    target_cpe: String,
    nvd_api_key_configured: bool,
    kev_only: bool,
    min_cvss: Option<f32>,
    timeout_secs: u64,
    execute: bool,
    vulnerability_count: usize,
    cisa_kev_count: usize,
    vulnerabilities: Vec<KernelVulnerability>,
    scan_notice: Option<String>,
    patch_result: PatchExecutionResult,
}

/// Resolves `NVD_API_KEY` solely from the trimmed process environment variable.
/// Never accepts API keys from CLI arguments to avoid leaking secrets in process listings.
fn resolve_trimmed_nvd_api_key() -> Option<String> {
    std::env::var("NVD_API_KEY")
        .ok()
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty())
}

/// Handles the `osoosi patch-kernel` CLI subcommand.
///
/// Discovers the running OS kernel, queries NVD API 2.0 for matching CVEs / CISA KEV entries,
/// and either dry-runs (default) or executes (`--execute`) the OS-native kernel patch workflow.
pub async fn handle_patch_kernel(
    cpe: Option<String>,
    min_cvss: Option<f32>,
    kev_only: bool,
    timeout_secs: u64,
    execute: bool,
    json: bool,
) -> Result<()> {
    let host_info = HostKernelInfo::detect_host_kernel()?;
    let target_cpe = cpe
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| host_info.cpe23.clone());
    let effective_timeout = timeout_secs.max(1);
    let has_env_key = resolve_trimmed_nvd_api_key().is_some();

    if !json {
        println!(
            "\n================================================================================"
        );
        println!("HOST KERNEL DISCOVERY & NVD VULNERABILITY SCANNER");
        println!(
            "================================================================================"
        );
        println!("  OS Family:        {}", host_info.os_family);
        println!("  OS Version:       {}", host_info.os_version);
        println!("  Kernel Release:   {}", host_info.kernel_release);
        println!("  Architecture:     {}", host_info.architecture);
        println!("  Target CPE 2.3:   {}", target_cpe);
        println!(
            "  NVD API Key:      {}",
            if has_env_key {
                "Configured via NVD_API_KEY environment variable"
            } else {
                "None (public rate-limited mode)"
            }
        );
        if kev_only {
            println!("  Filter Mode:      CISA KEV Only");
        }
        if let Some(cvss) = min_cvss {
            println!("  Min CVSS Score:   {:.1}", cvss);
        }
        println!("  Timeout:          {}s", effective_timeout);
        println!(
            "================================================================================\n"
        );
        println!(
            "Querying NVD API 2.0 for kernel vulnerabilities affecting '{}'...",
            target_cpe
        );
    }

    let options = ScanOptions {
        cpe: Some(target_cpe.clone()),
        min_cvss_score: min_cvss,
        kev_only,
        // Keep None so KernelPatcher reads trimmed NVD_API_KEY strictly from runtime env.
        api_key: None,
        timeout_secs: effective_timeout,
    };

    let patcher = KernelPatcher::new();
    let mut vulnerabilities = Vec::new();
    let mut scan_notice: Option<String> = None;

    match patcher.scan_kernel_vulnerabilities(&options).await {
        Ok(vulns) => {
            if !json {
                print_human_vulnerabilities(&vulns);
            }
            vulnerabilities = vulns;
        }
        Err(PatcherError::RateLimited) => {
            let msg = "Rate limited by NIST NVD API 2.0. Set the NVD_API_KEY environment variable to increase NIST rate limits.".to_string();
            if !json {
                eprintln!("Warning: {}", msg);
            }
            scan_notice = Some(msg);
        }
        Err(e) => {
            let msg = format!("NVD vulnerability scan query notice: {}", e);
            if !json {
                eprintln!("Warning: {}", msg);
            }
            scan_notice = Some(msg);
        }
    }

    let dry_run = !execute;
    if !dry_run && !is_elevated() {
        return Err(PatcherError::InsufficientPrivileges.into());
    }

    let exec_result = patcher.apply_os_kernel_patch(dry_run).await?;

    if json {
        let cisa_kev_count = vulnerabilities.iter().filter(|v| v.is_cisa_kev).count();
        let report = PatchKernelJsonReport {
            host_kernel: host_info,
            target_cpe,
            nvd_api_key_configured: has_env_key,
            kev_only,
            min_cvss,
            timeout_secs: effective_timeout,
            execute,
            vulnerability_count: vulnerabilities.len(),
            cisa_kev_count,
            vulnerabilities,
            scan_notice,
            patch_result: exec_result,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Orchestrating native OS kernel patch workflow...");
        if exec_result.dry_run {
            println!("  [DRY-RUN SIMULATION - No kernel or OS changes will be applied]");
        }
        println!(
            "\n================================================================================"
        );
        println!("NATIVE KERNEL PATCH ORCHESTRATION RESULT");
        println!(
            "================================================================================"
        );
        println!("  Target Subsystem: {}", exec_result.os_subsystem);
        println!(
            "  Mode:             {}",
            if exec_result.dry_run {
                "Dry-Run Simulation"
            } else {
                "Live Execution"
            }
        );
        println!(
            "  Command:          {} {}",
            exec_result.command,
            exec_result.args.join(" ")
        );
        println!("  Success:          {}", exec_result.success);
        println!("  Output:\n{}", exec_result.output);
        println!(
            "================================================================================\n"
        );
        if exec_result.dry_run {
            println!("Tip: Re-run with '--execute' under elevated privileges to apply native OS kernel updates.\n");
        }
    }

    Ok(())
}

fn print_human_vulnerabilities(vulns: &[KernelVulnerability]) {
    if vulns.is_empty() {
        println!("Zero vulnerabilities found matching the specified criteria.");
        return;
    }

    let kev_count = vulns.iter().filter(|v| v.is_cisa_kev).count();
    println!(
        "\nFound {} vulnerabilities affecting target kernel ({} CISA KEV):\n",
        vulns.len(),
        kev_count
    );
    for v in vulns {
        println!(
            "--------------------------------------------------------------------------------"
        );
        let score_str = match v.cvss_v31_score {
            Some(score) => format!("{:.1}", score),
            None => "N/A".to_string(),
        };
        let sev_str = v.cvss_v31_severity.as_deref().unwrap_or("UNKNOWN");

        if v.is_cisa_kev {
            println!(
                "[CISA KEV] {} | CVSS v3.1: {} ({})",
                v.cve_id, score_str, sev_str
            );
            if let Some(ref name) = v.cisa_vulnerability_name {
                println!("   Vulnerability Name: {}", name);
            }
            if let Some(ref added) = v.cisa_exploit_add {
                println!("   Added to KEV:       {}", added);
            }
            if let Some(ref due) = v.cisa_action_due {
                println!("   Remediation Due:    {}", due);
            }
            if let Some(ref action) = v.cisa_required_action {
                println!("   Required Action:    {}", action);
            }
        } else {
            println!("{} | CVSS v3.1: {} ({})", v.cve_id, score_str, sev_str);
        }
        if !v.description.is_empty() {
            println!("   Description:        {}", v.description);
        }
    }
    println!(
        "--------------------------------------------------------------------------------\n"
    );
}
