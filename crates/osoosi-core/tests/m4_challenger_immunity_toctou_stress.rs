//! Milestone 4 Empirical Adversarial Challenge Suite (Challenger 1: OshoosiClaw)
//!
//! Vector 2: Process Lineage Immunity, Ancestry Traversal, TOCTOU Stem Checks,
//! and PID Reuse Boundaries in `immunity.rs` & `killchain.rs`.

use osoosi_core::immunity::{
    extract_proc_stem, get_process_ancestry_chain, inspect_process_lineage, LineageImmunityVerdict,
    VetoReason, MAX_ANCESTRY_DEPTH,
};
use osoosi_core::killchain::{
    is_critical_system_pid, is_developer_or_agent_runtime, is_immutable_os_kernel_pid,
};

#[test]
fn test_challenger_kernel_anchor_immunity() {
    // 1. PID <= 4 are immutable OS kernel anchors
    assert!(is_immutable_os_kernel_pid(0, "System Idle"));
    assert!(is_immutable_os_kernel_pid(1, "init"));
    assert!(is_immutable_os_kernel_pid(4, "System"));

    let verdict_0 = inspect_process_lineage(0, Some("System Idle"));
    assert!(verdict_0.is_immune());
    assert_eq!(
        verdict_0.to_veto_reason(),
        Some(VetoReason::CriticalSystemPid)
    );

    let verdict_4 = inspect_process_lineage(4, Some("System"));
    assert!(verdict_4.is_immune());
    assert_eq!(
        verdict_4.to_veto_reason(),
        Some(VetoReason::CriticalSystemPid)
    );

    // 2. Self PID is protected against self-containment
    let self_pid = std::process::id();
    assert!(is_immutable_os_kernel_pid(self_pid, "cargo.exe"));
    let verdict_self = inspect_process_lineage(self_pid, Some("osoosi_test"));
    assert!(verdict_self.is_immune());

    // 3. Core system subsystem anchors
    let core_anchors = [
        "csrss.exe",
        "smss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "lsass.exe",
        "lsm.exe",
        "systemd",
        "systemd-journald",
        "launchd",
        "kernel_task",
    ];
    for anchor in &core_anchors {
        assert!(
            is_immutable_os_kernel_pid(2000, anchor),
            "Core anchor '{}' MUST return true in is_immutable_os_kernel_pid",
            anchor
        );
    }
}

#[test]
fn test_challenger_elevation_tools_immunity_denied() {
    // Only binaries in is_blanket_immunity_denied are actually blocked from target immunity
    let denied_elevation_tools = ["wsl.exe", "wslservice.exe", "wslhost.exe", "sudo", "su"];

    for bin in &denied_elevation_tools {
        // Lineage inspection for direct target must NEVER return ImmuneTarget
        let verdict = inspect_process_lineage(5000, Some(bin));
        assert!(
            !matches!(verdict, LineageImmunityVerdict::ImmuneTarget { .. }),
            "Binary '{}' MUST NOT receive blanket target immunity",
            bin
        );
    }
}

/// EMPIRICAL CHALLENGER VULNERABILITY FINDING 1:
/// Shells (bash, powershell, cmd) and runtimes (python, node, vmmem, docker) leak blanket
/// immunity because `is_critical_system_pid` includes them, while `is_blanket_immunity_denied`
/// omits them instead of delegating to `is_developer_or_agent_runtime`.
#[test]
fn test_challenger_shell_and_runtime_blanket_immunity_leak_empirical_proof() {
    let leaking_binaries = [
        "bash",
        "sh",
        "zsh",
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "python.exe",
        "python",
        "node.exe",
        "node",
        "vmmem",
        "vmmemwsl",
        "docker.exe",
    ];

    for bin in &leaking_binaries {
        // 1. is_developer_or_agent_runtime classifies them as developer/agent runtimes
        assert!(
            is_developer_or_agent_runtime(bin),
            "Binary '{}' is defined as developer runtime in killchain.rs",
            bin
        );

        // 2. Hardened invariant: is_critical_system_pid returns FALSE for non-kernel PIDs
        assert!(
            !is_critical_system_pid(5000, bin),
            "Binary '{}' must NOT be treated as critical system PID",
            bin
        );

        // 3. And inspect_process_lineage does not grant ImmuneTarget
        let verdict = inspect_process_lineage(5000, Some(bin));
        assert!(
            !matches!(verdict, LineageImmunityVerdict::ImmuneTarget { .. }),
            "Hardened invariant: '{}' must NOT receive blanket target immunity",
            bin
        );
    }
}

#[test]
fn test_challenger_toctou_process_stem_mismatch() {
    // Target PID > 4 and != self
    // Find an actual running OS process PID
    let mut sys = sysinfo::System::new();
    sys.refresh_processes();

    // Pick a running process PID != self_pid and > 4
    let self_pid = std::process::id();
    if let Some((&pid, proc_entry)) = sys
        .processes()
        .iter()
        .find(|(&p, _)| p.as_u32() > 4 && p.as_u32() != self_pid)
    {
        let pid_u32 = pid.as_u32();
        let actual_name = proc_entry.name();

        // 1. Pass mismatched name stem -> TOCTOU stem mismatch must trigger NotImmune
        let fake_name = "completely_different_stem.exe";
        let verdict = inspect_process_lineage(pid_u32, Some(fake_name));
        assert_eq!(
            verdict,
            LineageImmunityVerdict::NotImmune,
            "TOCTOU stem mismatch for live PID {} (expected '{}' vs actual '{}') must return NotImmune",
            pid_u32,
            fake_name,
            actual_name
        );
    }
}

#[test]
fn test_challenger_synthetic_pid_allocation_boundary() {
    // Tests must use synthetic non-colliding PIDs strictly >= 4_000_001
    const SYNTHETIC_PID_MIN: u32 = 4_000_001;

    let test_pids = [4_000_001, 4_100_000, 4_999_999, 5_000_000];
    for &pid in &test_pids {
        assert!(
            pid >= SYNTHETIC_PID_MIN,
            "Synthetic test PID {} must be strictly >= 4_000_001",
            pid
        );

        // Unprivileged test process name with synthetic PID must return NotImmune
        let verdict = inspect_process_lineage(pid, Some("worker_agent_task.exe"));
        assert_eq!(
            verdict,
            LineageImmunityVerdict::NotImmune,
            "Synthetic PID {} for unprivileged worker must be NotImmune",
            pid
        );
    }
}

/// EMPIRICAL CHALLENGER VULNERABILITY FINDING 2:
/// `extract_proc_stem` splits on spaces before examining path separators.
/// Any Windows binary located under `C:\Program Files\...` has its stem truncated to `"program"`.
#[test]
fn test_challenger_stem_extraction_quoted_space_truncation_empirical_proof() {
    // Unquoted or single-word paths extract stem correctly
    assert_eq!(extract_proc_stem("'/usr/bin/sudo'"), "sudo");
    assert_eq!(
        extract_proc_stem("  powershell.exe -NoProfile  "),
        "powershell"
    );
    assert_eq!(extract_proc_stem("CSRSS.EXE"), "csrss");
    assert_eq!(extract_proc_stem("C:\\Windows\\System32\\SMSS.EXE"), "smss");
    assert_eq!(extract_proc_stem(""), "");
    // Remediated: Windows executable paths with spaces inside quotes (e.g. Program Files)
    // are tokenized cleanly to the executable stem "wsl".
    let clean_stem = extract_proc_stem("\"C:\\Program Files\\app\\wsl.exe\"");
    assert_eq!(
        clean_stem, "wsl",
        "Hardened extract_proc_stem resolves 'C:\\Program Files\\app\\wsl.exe' to 'wsl'"
    );

    // Also check single-quoted commands and arguments
    assert_eq!(extract_proc_stem("'cmd.exe' /c dir"), "cmd");
    assert_eq!(extract_proc_stem(r#""cmd.exe" /c dir"#), "cmd");
    assert_eq!(
        extract_proc_stem(r#""D:\Program Files\Python310\python.exe" -m http.server"#),
        "python"
    );
}

#[test]
fn test_challenger_elevation_binaries_taxonomy_harmonization() {
    assert!(is_developer_or_agent_runtime("doas"));
    assert!(is_developer_or_agent_runtime("pkexec"));
    assert!(is_developer_or_agent_runtime("runas"));
}

#[test]
fn test_challenger_ancestry_chain_max_depth_and_cycle_bounds() {
    let self_pid = std::process::id();
    let chain = get_process_ancestry_chain(self_pid);

    // Chain length must never exceed MAX_ANCESTRY_DEPTH (5)
    assert!(
        chain.len() <= MAX_ANCESTRY_DEPTH,
        "Ancestry chain length {} exceeds MAX_ANCESTRY_DEPTH ({})",
        chain.len(),
        MAX_ANCESTRY_DEPTH
    );

    // Chain must not contain duplicates (cycle prevention)
    let mut seen = std::collections::HashSet::new();
    seen.insert(self_pid);
    for &(pid, _) in &chain {
        assert!(
            seen.insert(pid),
            "Cycle detected in ancestry chain at PID {}",
            pid
        );
    }
}
