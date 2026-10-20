//! Adversarial empirical challenge test suite for Milestone 1 - Remediation & PID boundaries
//! Tests PID boundary conditions, argument spoofing, and killchain state persistence.

use osoosi_core::remediation::{is_administrative_or_ssh_session, RemediationController};

#[test]
fn test_remediation_pid_boundaries_direct() {
    let controller = RemediationController::new();

    // 1. PID 0 (System Idle)
    let res_pid0 = controller.kill_process_tree(0);
    assert!(res_pid0.is_err(), "kill_process_tree(0) MUST return Err");
    println!("kill_process_tree(0): {:?}", res_pid0);

    // 2. PID 4 (System)
    let res_pid4 = controller.kill_process_tree(4);
    assert!(res_pid4.is_err(), "kill_process_tree(4) MUST return Err");
    println!("kill_process_tree(4): {:?}", res_pid4);

    // 3. Self PID
    let self_pid = std::process::id();
    let res_self = controller.kill_process_tree(self_pid);
    assert!(res_self.is_err(), "kill_process_tree(self_pid) MUST return Err");
    println!("kill_process_tree(self_pid = {}): {:?}", self_pid, res_self);

    // 4. Low PIDs (1, 2, 3)
    assert!(controller.kill_process_tree(1).is_err());
    assert!(controller.kill_process_tree(2).is_err());
    assert!(controller.kill_process_tree(3).is_err());
}

#[test]
fn test_administrative_session_spoofing_via_commandline_arguments() {
    // Attack scenario: Attacker runs a malware process named "c2_beacon.exe" or "backdoor.exe"
    // An attacker passes "--target python" or "python" or "git" in command line arguments.
    let malicious_proc_name = "c2_beacon.exe";
    let spoofed_cmd = vec![
        "c2_beacon.exe".to_string(),
        "--target".to_string(),
        "python".to_string(),
    ];

    let is_shielded = is_administrative_or_ssh_session(malicious_proc_name, &spoofed_cmd);
    println!(
        "c2_beacon.exe with args ['--target', 'python']: is_administrative_or_ssh_session = {}",
        is_shielded
    );

    let spoofed_cmd_git = vec![
        "mimikatz.exe".to_string(),
        "git".to_string(),
    ];
    let mimikatz_shielded = is_administrative_or_ssh_session("mimikatz.exe", &spoofed_cmd_git);
    println!(
        "mimikatz.exe with args ['git']: is_administrative_or_ssh_session = {}",
        mimikatz_shielded
    );

    let spoofed_cmd_code = vec![
        "powershell.exe".to_string(),
        "-c".to_string(),
        "code.exe".to_string(),
    ];
    let ps_shielded = is_administrative_or_ssh_session("powershell.exe", &spoofed_cmd_code);
    println!(
        "powershell.exe with args ['code.exe']: is_administrative_or_ssh_session = {}",
        ps_shielded
    );

    if is_shielded || mimikatz_shielded || ps_shielded {
        println!("CRITICAL VULNERABILITY CONFIRMED: Any malware can evade kill_process_tree by passing 'python', 'git', or 'code' as a CLI argument!");
    }
}
