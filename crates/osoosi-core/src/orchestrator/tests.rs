#![allow(unused_imports)]
#![allow(clippy::field_reassign_with_default)]

use super::types::*;
use super::*;
use crate::causal_graph::*;
use crate::console_defense::*;
use crate::disk_cleanup::*;
use crate::hybrid_runtime::*;
use crate::killchain::*;
use crate::memory_watchdog::*;
use crate::rea::*;
use crate::voters::*;
use osoosi_types::ThreatSignature;
use std::path::Path;

#[test]
fn test_is_developer_tool() {
    assert!(is_developer_tool("git.exe", None));
    assert!(is_developer_tool("git", None));
    assert!(is_developer_tool(r"C:\Program Files\Git\bin\git.exe", None));
    assert!(is_developer_tool("git-remote-https.exe", None));
    assert!(is_developer_tool("git-remote-https", None));
    assert!(is_developer_tool("cargo.exe", None));
    assert!(is_developer_tool("cargo", None));
    assert!(is_developer_tool("rustc.exe", None));
    assert!(is_developer_tool("rust-analyzer.exe", None));
    assert!(is_developer_tool("node.exe", None));
    assert!(is_developer_tool("node", None));
    assert!(is_developer_tool("python.exe", None));
    assert!(is_developer_tool("code.exe", None));
    assert!(is_developer_tool("cargo-watch.exe", None));
    assert!(is_developer_tool("llama-server.exe", None));
    assert!(is_developer_tool("llama-server", None));
    assert!(is_developer_tool("ollama.exe", None));
    assert!(is_developer_tool("ollama_llama_server.exe", None));
    assert!(is_developer_tool("vllm", None));
    assert!(is_developer_tool("text-generation-launcher", None));
    assert!(is_developer_tool("tritonserver.exe", None));
    assert!(is_developer_tool("local-ai", None));
    assert!(is_developer_tool("tabby", None));
    assert!(is_developer_tool("tabby-cpu.exe", None));
    assert!(is_developer_tool("System", None));
    assert!(is_developer_tool("system", None));
    assert!(is_developer_tool("Registry", None));
    assert!(is_developer_tool("registry", None));
    assert!(is_developer_tool("smss.exe", None));
    assert!(is_developer_tool("csrss.exe", None));
    assert!(is_developer_tool("wininit.exe", None));
    assert!(is_developer_tool("services.exe", None));
    assert!(is_developer_tool("lsass.exe", None));
    assert!(!is_developer_tool(
        "custom-runner.exe",
        Some(Path::new(r"D:\project\.vscode\extensions\runner.exe"))
    ));
    assert!(!is_developer_tool(
        "worker.exe",
        Some(Path::new(r"D:\project\target\debug\worker.exe"))
    ));

    assert!(!is_developer_tool(
        "mimikatz.exe",
        Some(Path::new(r"C:\Windows\Temp\mimikatz.exe"))
    ));
    assert!(!is_developer_tool(
        "evil.exe",
        Some(Path::new(r"C:\Users\Public\evil.exe"))
    ));
    assert!(!is_developer_tool("cmd.exe", None));
    assert!(!is_developer_tool("powershell.exe", None));
    assert!(!is_developer_tool("gitminer.exe", None));
    assert!(!is_developer_tool("gitminer", None));
}

#[test]
fn test_should_skip_file_malware_scan() {
    assert!(should_skip_file_malware_scan(Path::new(
        r"D:\dev\my_project\.vscode\settings.json"
    )));
    assert!(should_skip_file_malware_scan(Path::new(
        r"D:\dev\my_project\target\debug\app.pdb"
    )));
    assert!(should_skip_file_malware_scan(Path::new(
        r"D:\dev\my_project\target\debug\incremental\app.rmeta"
    )));
    assert!(should_skip_file_malware_scan(Path::new(
        r"D:\dev\my_project\src\main.rs"
    )));
    assert!(should_skip_file_malware_scan(Path::new(
        r"D:\dev\my_project\.git\index"
    )));
    assert!(should_skip_file_malware_scan(Path::new(
        r"D:\dev\my_project\node_modules\package\index.js"
    )));
    assert!(should_skip_file_malware_scan(Path::new(
        r"C:\Users\dev\.cargo\config.toml"
    )));
    assert!(!should_skip_file_malware_scan(Path::new(
        r"D:\harfile\ModelFusion\IDE\VSCode-win32-x64\vulkan-1.dll"
    )));
    assert!(!should_skip_file_malware_scan(Path::new(
        r"D:\harfile\ModelFusion\IDE\VSCode-win32-x64\7e7950df89\resources\app\extensions\microsoft-authentication\dist\msalruntime.dll"
    )));
    assert!(!should_skip_file_malware_scan(Path::new(
        r"D:\harfile\ModelFusion\IDE\VSCode-win32-x64\7e7950df89\resources\app\extensions\microsoft-authentication\dist\msal-node-runtime.node"
    )));
    assert!(!should_skip_file_malware_scan(Path::new(
        r"D:\harfile\ModelFusion\IDE\VSCode-win32-x64\7e7950df89\resources\app\node_modules\vsda\build\Release\vsda.node"
    )));
    assert!(!should_skip_file_malware_scan(Path::new(
        r"D:\harfile\ModelFusion\IDE\VSCode-win32-x64\7e7950df89\resources\app\extensions\ms-vscode.js-debug\src\win32-app-container-tokens.win32-x64-msvc-VCQE7GJP.node"
    )));

    assert!(!should_skip_file_malware_scan(Path::new(
        r"C:\Windows\System32\unknown_driver.sys"
    )));
    assert!(!should_skip_file_malware_scan(Path::new(
        r"C:\Users\Public\Downloads\installer.exe"
    )));
    assert!(!should_skip_file_malware_scan(Path::new(
        r"C:\Windows\Temp\mimikatz.exe"
    )));
    assert!(!should_skip_file_malware_scan(Path::new(
        r"C:\Windows\Temp\ransomware.exe"
    )));
    assert!(!should_skip_file_malware_scan(Path::new(
        r"C:\Windows\Temp\vulkan-1.dll"
    )));
    assert!(!should_skip_file_malware_scan(Path::new(
        r"C:\Users\victim\Downloads\msalruntime.dll"
    )));
    assert!(!should_skip_file_malware_scan(Path::new(
        r"C:\Users\victim\Downloads\vsda.node"
    )));
    assert!(!should_skip_file_malware_scan(Path::new(
        r"C:\Windows\Temp\win32-app-container-tokens.node"
    )));
}

#[test]
fn test_suppression_key_deduplication() {
    let mut sig1 = ThreatSignature::new("node-1".to_string());
    sig1.hash_blake3 = Some("abc123hash".to_string());
    sig1.process_name = Some("powershell.exe".to_string());
    sig1.add_reason("Intelligent Correlation: Suspicious command line execution".to_string());

    let mut sig2 = ThreatSignature::new("node-1".to_string());
    // Notice sig2 has a different UUID id
    sig2.hash_blake3 = Some("abc123hash".to_string());
    sig2.process_name = Some("powershell.exe".to_string());
    sig2.add_reason("Intelligent Correlation: Repeated suspicious command line".to_string());

    assert_ne!(sig1.id, sig2.id);

    let key1 = EdrOrchestrator::compute_suppression_key(&sig1);
    let key2 = EdrOrchestrator::compute_suppression_key(&sig2);

    assert_eq!(key1, "abc123hash:powershell.exe:Intelligent Correlation");
    assert_eq!(
        key1, key2,
        "Suppression keys must match regardless of random UUID id"
    );

    // Edge case: Empty or whitespace reason gracefully defaults to "generic"
    let mut sig_empty = ThreatSignature::new("node-1".to_string());
    sig_empty.process_name = Some("cmd.exe".to_string());
    sig_empty.reason = Some("   ".to_string());
    assert_eq!(
        EdrOrchestrator::compute_suppression_key(&sig_empty),
        "unknown:cmd.exe:generic"
    );

    // Edge case: Reason starting with colon defaults to "generic"
    let mut sig_colon = ThreatSignature::new("node-1".to_string());
    sig_colon.process_name = Some("cmd.exe".to_string());
    sig_colon.reason = Some(": empty category".to_string());
    assert_eq!(
        EdrOrchestrator::compute_suppression_key(&sig_colon),
        "unknown:cmd.exe:generic"
    );
}

fn make_test_event(data: serde_json::Value) -> osoosi_types::HostSecurityEvent {
    osoosi_types::HostSecurityEvent {
        source: osoosi_types::HostEventSource::WindowsEventLog,
        event_id: 1,
        timestamp: chrono::Utc::now(),
        computer: "TEST-PC".to_string(),
        data,
        causal_parent: None,
    }
}

#[test]
fn test_is_system_critical_lolbin_exclusion() {
    let lolbin_net = make_test_event(serde_json::json!({
        "ProcessId": 1234,
        "Image": r"C:\Windows\System32\net.exe",
    }));
    assert!(
        !is_system_critical(&lolbin_net),
        "net.exe must not be marked system critical"
    );

    let lolbin_ps = make_test_event(serde_json::json!({
        "ProcessId": 1235,
        "Image": r"C:\Windows\System32\powershell.exe",
    }));
    assert!(
        !is_system_critical(&lolbin_ps),
        "powershell.exe must not be marked system critical"
    );

    let lolbin_cmd = make_test_event(serde_json::json!({
        "ProcessId": 1236,
        "Image": r"C:\Windows\System32\cmd.exe",
    }));
    assert!(
        !is_system_critical(&lolbin_cmd),
        "cmd.exe must not be marked system critical"
    );

    // Core system infrastructure must be protected
    let core_pid4 = make_test_event(serde_json::json!({
        "ProcessId": 4,
    }));
    assert!(
        is_system_critical(&core_pid4),
        "PID 4 must be system critical"
    );

    let core_lsass = make_test_event(serde_json::json!({
        "ProcessId": 5678,
        "Image": r"C:\Windows\System32\lsass.exe",
    }));
    assert!(
        is_system_critical(&core_lsass),
        "lsass.exe must be system critical"
    );

    let core_csrss = make_test_event(serde_json::json!({
        "ProcessId": 5679,
        "Image": r"C:\Windows\System32\csrss.exe",
    }));
    assert!(
        is_system_critical(&core_csrss),
        "csrss.exe must be system critical"
    );

    let win_search_host = make_test_event(serde_json::json!({
        "ProcessId": 5680,
        "Image": r"\Device\HarddiskVolume4\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe",
    }));
    assert!(
        is_system_critical(&win_search_host),
        "Windows SearchHost.exe with NT device path must be system critical"
    );

    let win_sihost = make_test_event(serde_json::json!({
        "ProcessId": 5681,
        "Image": r"C:\Windows\System32\sihost.exe",
    }));
    assert!(
        is_system_critical(&win_sihost),
        "Windows sihost.exe must be system critical"
    );

    let linux_gnome_shell = make_test_event(serde_json::json!({
        "ProcessId": 5682,
        "Image": "/usr/bin/gnome-shell",
    }));
    assert!(
        is_system_critical(&linux_gnome_shell),
        "Linux gnome-shell must be system critical"
    );

    let linux_tracker = make_test_event(serde_json::json!({
        "ProcessId": 5683,
        "Image": "/usr/libexec/tracker-miner-fs-3",
    }));
    assert!(
        is_system_critical(&linux_tracker),
        "Linux tracker-miner-fs-3 search indexer must be system critical"
    );

    let macos_finder = make_test_event(serde_json::json!({
        "ProcessId": 5684,
        "Image": "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
    }));
    assert!(
        is_system_critical(&macos_finder),
        "macOS Finder must be system critical"
    );

    let macos_spotlight = make_test_event(serde_json::json!({
        "ProcessId": 5685,
        "Image": "/System/Library/CoreServices/Spotlight.app/Contents/MacOS/Spotlight",
    }));
    assert!(
        is_system_critical(&macos_spotlight),
        "macOS Spotlight must be system critical"
    );
}

#[test]
fn test_is_system_critical_security_providers_and_pid_extraction() {
    // 1. is_system_critical returns true for sysmon64.exe, sysmon.exe, osoosi.exe, msmpeng.exe
    for bin in &["sysmon64.exe", "sysmon.exe", "osoosi.exe", "msmpeng.exe"] {
        let ev = make_test_event(serde_json::json!({
            "ProcessId": 8888,
            "Image": format!(r"C:\Windows\{}", bin),
        }));
        assert!(
            is_system_critical(&ev),
            "{} must be marked system critical / security provider",
            bin
        );

        // Also test without directory path
        let ev_bare = make_test_event(serde_json::json!({
            "ProcessId": 8889,
            "Image": bin,
        }));
        assert!(
            is_system_critical(&ev_bare),
            "bare {} must be marked system critical / security provider",
            bin
        );
    }

    // Also test helper is_security_provider_process directly
    assert!(is_security_provider_process(8888, "sysmon64.exe"));
    assert!(is_security_provider_process(8888, "Sysmon.exe"));
    assert!(is_security_provider_process(8888, "osoosi.exe"));
    assert!(is_security_provider_process(8888, "msmpeng.exe"));
    assert!(is_security_provider_process(std::process::id(), "anything"));
    assert!(!is_security_provider_process(9999, "powershell.exe"));
    assert!(!is_security_provider_process(0, "malware.exe"));
    assert!(!is_security_provider_process(0, ""));

    // Critical guard: Threat events lacking PID must NEVER be shielded as system critical!
    let ev_malware_no_pid = make_test_event(serde_json::json!({
        "Image": r"C:\Windows\Temp\malware.exe",
    }));
    assert!(
        !is_system_critical(&ev_malware_no_pid),
        "Malware without PID must NOT be system critical"
    );

    let ev_empty = make_test_event(serde_json::json!({}));
    assert!(
        !is_system_critical(&ev_empty),
        "Empty event must NOT be system critical"
    );

    // System/Kernel pseudo processes
    let ev_sys_img = make_test_event(serde_json::json!({"Image": "System"}));
    assert!(
        is_system_critical(&ev_sys_img),
        "System pseudo-process must be system critical"
    );

    // 2. extract_event_pid ignores LoggingProcessId and extracts ProcessId from EventData
    let ev_with_logging_pid = make_test_event(serde_json::json!({
        "ProcessId": 4567,
        "LoggingProcessId": 6580,
        "ProviderProcessId": 6580,
        "LoggingThreadId": 1234,
    }));
    assert_eq!(extract_event_pid(&ev_with_logging_pid), Some(4567));

    // When ProcessId is not in EventData but LoggingProcessId is present: extract_event_pid must return None
    let ev_only_logging_pid = make_test_event(serde_json::json!({
        "LoggingProcessId": 6580,
        "ProviderProcessId": 6580,
        "ExecutionProcessId": 6580,
    }));
    assert_eq!(extract_event_pid(&ev_only_logging_pid), None);

    // Kernel PIDs (0, 1, 4) and EDR self PID must return None
    let ev_kernel_0 = make_test_event(serde_json::json!({"ProcessId": 0}));
    let ev_kernel_1 = make_test_event(serde_json::json!({"ProcessId": 1}));
    let ev_kernel_4 = make_test_event(serde_json::json!({"ProcessId": 4}));
    let ev_self = make_test_event(serde_json::json!({"ProcessId": std::process::id()}));
    assert_eq!(extract_event_pid(&ev_kernel_0), None);
    assert_eq!(extract_event_pid(&ev_kernel_1), None);
    assert_eq!(extract_event_pid(&ev_kernel_4), None);
    assert_eq!(extract_event_pid(&ev_self), None);

    // Fallback fields: NewProcessId, SourceProcessId, TargetProcessId, pid
    let ev_new = make_test_event(serde_json::json!({"NewProcessId": 1111}));
    assert_eq!(extract_event_pid(&ev_new), Some(1111));
    let ev_src = make_test_event(serde_json::json!({"SourceProcessId": 2222}));
    assert_eq!(extract_event_pid(&ev_src), Some(2222));
    let ev_tgt = make_test_event(serde_json::json!({"TargetProcessId": 3333}));
    assert_eq!(extract_event_pid(&ev_tgt), Some(3333));
    let ev_pid = make_test_event(serde_json::json!({"pid": "0x1122"}));
    assert_eq!(extract_event_pid(&ev_pid), Some(0x1122));

    // Hex zero edge case
    let ev_hex_zero = make_test_event(serde_json::json!({"ProcessId": "0x0"}));
    assert_eq!(extract_raw_event_pid(&ev_hex_zero), Some(0));
    assert_eq!(extract_event_pid(&ev_hex_zero), None);
}

#[test]
fn test_extract_created_username() {
    assert_eq!(
        extract_created_username("net user rogue_admin P@ssw0rd123 /add"),
        Some("rogue_admin".to_string())
    );
    assert_eq!(
        extract_created_username("net1.exe user \"backdoor_user\" Password! /add"),
        Some("backdoor_user".to_string())
    );
    assert_eq!(
        extract_created_username("net user \"Rogue Admin\" /add"),
        Some("Rogue Admin".to_string())
    );
    assert_eq!(
        extract_created_username("net user \"Rogue Admin\" Pa$$w0rd /add"),
        Some("Rogue Admin".to_string())
    );
    assert_eq!(
        extract_created_username("net user /add attacker"),
        Some("attacker".to_string())
    );
    assert_eq!(
        extract_created_username("net user /add /domain domain_attacker"),
        Some("domain_attacker".to_string())
    );
    assert_eq!(
        extract_created_username("New-LocalUser -Name backdoor -Password $pass"),
        Some("backdoor".to_string())
    );
    assert_eq!(
        extract_created_username("New-LocalUser -Name \"hacker_acc\""),
        Some("hacker_acc".to_string())
    );
    assert_eq!(
        extract_created_username("New-LocalUser -Name 'Backdoor Space' -Password $pass"),
        Some("Backdoor Space".to_string())
    );
    assert_eq!(
        extract_created_username("New-LocalUser -Name:\"Colon Rogue\""),
        Some("Colon Rogue".to_string())
    );
    assert_eq!(
        extract_created_username("net user /delete rogue_admin"),
        None
    );
    assert_eq!(extract_created_username("whoami /all"), None);
}

#[test]
fn test_catalog_attack_and_destructive_detection() {
    let mut sig = ThreatSignature::default();
    sig.mitre_technique = Some("T1136.001".to_string());
    let ev = make_test_event(serde_json::json!({
        "CommandLine": "net user attacker P@ss /add",
    }));

    assert!(is_critical_security_attack(&sig, &ev));
    assert!(is_mitre_catalog_attack(&sig, &ev));
    assert!(is_destructive_mutation(&sig, &ev));

    let mut dump_sig = ThreatSignature::default();
    dump_sig.mitre_technique = Some("T1003.001".to_string());
    assert!(is_critical_security_attack(&dump_sig, &ev));
    assert!(is_mitre_catalog_attack(&dump_sig, &ev));
    assert!(is_destructive_mutation(&dump_sig, &ev));

    // False-positive prevention: low confidence routine execution/discovery must NOT trigger critical attack
    let benign_ev = make_test_event(serde_json::json!({
        "CommandLine": "systeminfo",
    }));
    let mut aml_exec_sig = ThreatSignature::default();
    aml_exec_sig.mitre_technique = Some("AML.T0011".to_string());
    aml_exec_sig.confidence = 0.53;
    assert!(!is_critical_security_attack(&aml_exec_sig, &benign_ev));
    assert!(!is_destructive_mutation(&aml_exec_sig, &benign_ev));

    let mut script_sig = ThreatSignature::default();
    script_sig.mitre_technique = Some("T1059.001".to_string());
    script_sig.confidence = 0.60;
    assert!(!is_critical_security_attack(&script_sig, &benign_ev));

    let mut disc_sig = ThreatSignature::default();
    disc_sig.mitre_technique = Some("T1082".to_string());
    disc_sig.confidence = 0.50;
    assert!(!is_critical_security_attack(&disc_sig, &benign_ev));

    // Critical attacks: subtechnique recognition and confidence boundary
    let mut aml_inj_sig = ThreatSignature::default();
    aml_inj_sig.mitre_technique = Some("AML.T0043.001".to_string());
    aml_inj_sig.confidence = 0.85;
    assert!(is_critical_security_attack(&aml_inj_sig, &benign_ev));

    // Low-confidence critical technique (< 0.75) must NOT escalate
    let mut low_conf_aml = ThreatSignature::default();
    low_conf_aml.mitre_technique = Some("AML.T0043".to_string());
    low_conf_aml.confidence = 0.70;
    assert!(!is_critical_security_attack(&low_conf_aml, &benign_ev));

    // Ransomware recovery inhibition subtechnique
    let mut recov_sig = ThreatSignature::default();
    recov_sig.mitre_technique = Some("T1490.001".to_string());
    recov_sig.confidence = 0.80;
    assert!(is_critical_security_attack(&recov_sig, &benign_ev));
}

#[test]
fn test_is_protected_system_account() {
    assert!(is_protected_system_account("Administrator"));
    assert!(is_protected_system_account("guest"));
    assert!(is_protected_system_account("DefaultAccount"));
    assert!(is_protected_system_account("Owner"));
    assert!(is_protected_system_account("WDAGUtilityAccount"));

    let env_user = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| {
            std::env::set_var("USERNAME", "mock_active_user");
            "mock_active_user".to_string()
        });
    assert!(is_protected_system_account(&env_user));

    assert!(!is_protected_system_account("T1136.001_RogueUser"));
}

#[test]
fn test_non_destructive_account_containment_commands() {
    // Net.exe command generation: must strictly disable account via /active:no, NEVER /delete
    let net_args = get_account_containment_net_args("rogue_admin");
    assert_eq!(net_args, ["user", "rogue_admin", "/active:no"]);
    assert!(
        !net_args.contains(&"/delete"),
        "Containment command must NEVER include /delete"
    );

    // PowerShell command generation: must strictly disable account via Disable-LocalUser, NEVER Remove-LocalUser
    let ps_cmd = get_account_containment_powershell_cmd("rogue_admin");
    assert_eq!(
        ps_cmd,
        "Disable-LocalUser -Name 'rogue_admin' -ErrorAction SilentlyContinue"
    );
    assert!(
        !ps_cmd.contains("Remove-LocalUser"),
        "Containment command must NEVER include Remove-LocalUser"
    );

    // Escaping single quotes in PowerShell commands
    let ps_quote_cmd = get_account_containment_powershell_cmd("rogue'user");
    assert_eq!(
        ps_quote_cmd,
        "Disable-LocalUser -Name 'rogue''user' -ErrorAction SilentlyContinue"
    );
    let ps_injection_cmd = get_account_containment_powershell_cmd("evil'; calc.exe; #");
    assert_eq!(
        ps_injection_cmd,
        "Disable-LocalUser -Name 'evil''; calc.exe; #' -ErrorAction SilentlyContinue"
    );
    assert!(ps_injection_cmd.contains("''"));

    // Audit constants verification
    assert_eq!(
        NON_DESTRUCTIVE_ACCOUNT_CONTAINMENT_EVENT,
        "NON_DESTRUCTIVE_ACCOUNT_CONTAINMENT"
    );
    assert_eq!(
        NON_DESTRUCTIVE_ACCOUNT_CONTAINMENT_STATUS,
        "contained_disabled_non_destructive"
    );
    assert_eq!(
        NON_DESTRUCTIVE_ACCOUNT_CONTAINMENT_METHOD,
        "net user /active:no or Disable-LocalUser"
    );
}

#[test]
fn test_rollback_refuses_protected_and_preexisting() {
    let mut baseline = std::collections::HashSet::new();
    baseline.insert("alice".to_string());
    baseline.insert("bob".to_string());
    baseline.insert("administrator".to_string());

    // Verifies that attempting containment/rollback for "Alice" or "administrator" is rejected and cannot proceed
    assert!(!is_account_rollback_allowed("Alice", &baseline));
    assert!(!is_account_rollback_allowed("alice", &baseline));
    assert!(!is_account_rollback_allowed("administrator", &baseline));
    assert!(!is_account_rollback_allowed("Administrator", &baseline));
    assert!(!is_account_rollback_allowed("bob", &baseline));

    assert!(!is_account_containment_allowed("Alice", &baseline));
    assert!(!is_account_containment_allowed("alice", &baseline));
    assert!(!is_account_containment_allowed("administrator", &baseline));
    assert!(!is_account_containment_allowed("Administrator", &baseline));
    assert!(!is_account_containment_allowed("bob", &baseline));

    // Built-in protected accounts are rejected even if not in explicit baseline map
    assert!(!is_account_rollback_allowed("guest", &baseline));
    assert!(!is_account_rollback_allowed("DefaultAccount", &baseline));
    assert!(!is_account_rollback_allowed("Owner", &baseline));
    assert!(!is_account_rollback_allowed(
        "WDAGUtilityAccount",
        &baseline
    ));

    assert!(!is_account_containment_allowed("guest", &baseline));
    assert!(!is_account_containment_allowed("DefaultAccount", &baseline));
    assert!(!is_account_containment_allowed("Owner", &baseline));
    assert!(!is_account_containment_allowed(
        "WDAGUtilityAccount",
        &baseline
    ));

    // Empty and whitespace strings are rejected
    assert!(!is_account_rollback_allowed("", &baseline));
    assert!(!is_account_rollback_allowed("   ", &baseline));
    assert!(!is_account_containment_allowed("", &baseline));
    assert!(!is_account_containment_allowed("   ", &baseline));

    // CLI switch flags are strictly rejected
    assert!(!is_account_containment_allowed("/delete", &baseline));
    assert!(!is_account_containment_allowed("/add", &baseline));
    assert!(!is_account_containment_allowed("/domain", &baseline));
    assert!(!is_account_containment_allowed("--force", &baseline));
    assert!(!is_account_containment_allowed("-help", &baseline));

    // Control characters and command separators are strictly rejected
    assert!(!is_account_containment_allowed("bad\0user", &baseline));
    assert!(!is_account_containment_allowed("bad\nuser", &baseline));
    assert!(!is_account_containment_allowed("bad\ruser", &baseline));
    assert!(!is_account_containment_allowed(
        "evil'; calc.exe; #",
        &baseline
    ));
    assert!(!is_account_containment_allowed("user&calc", &baseline));
    assert!(!is_account_containment_allowed("user|calc", &baseline));

    // Verifies that rogue accounts are allowed for non-destructive containment disabling if not in the baseline
    assert!(is_account_rollback_allowed("mallory_hacker", &baseline));
    assert!(is_account_rollback_allowed(
        "T1136.001_RogueUser",
        &baseline
    ));
    assert!(is_account_containment_allowed("mallory_hacker", &baseline));
    assert!(is_account_containment_allowed(
        "T1136.001_RogueUser",
        &baseline
    ));
    assert!(is_account_containment_allowed("Rogue Admin", &baseline));
    assert!(is_account_containment_allowed("rogue'name", &baseline));
}

#[test]
fn test_deep_pipeline_autonomy_dispatch_matrix() {
    use osoosi_types::ResponseAction;
    let mut autonomy = osoosi_types::AutonomyConfig::default();
    autonomy.action_confidence_threshold = 0.85;

    let ev = make_test_event(serde_json::json!({
        "CommandLine": "vssadmin delete shadows /all /quiet",
        "ProcessId": 1234,
    }));
    let mut sig = ThreatSignature::default();
    sig.mitre_technique = Some("T1490".to_string());
    sig.confidence = 0.80; // below threshold 0.85
    sig.recommended_action = ResponseAction::Alert;

    // When auto_quarantine_malware is false (Audit mode), catalog attack below threshold MUST downgrade to Alert
    autonomy.auto_quarantine_malware = false;
    let is_catalog_attack = is_mitre_catalog_attack(&sig, &ev);
    let is_destructive = is_destructive_mutation(&sig, &ev);
    assert!(is_catalog_attack);
    assert!(is_destructive);

    let action_audit = if sig.confidence >= autonomy.action_confidence_threshold {
        sig.recommended_action
    } else if is_catalog_attack && autonomy.auto_quarantine_malware {
        if is_destructive || sig.recommended_action == ResponseAction::Isolate {
            ResponseAction::Isolate
        } else if sig.recommended_action == ResponseAction::GhostTarpit {
            ResponseAction::GhostTarpit
        } else {
            ResponseAction::Tarpit
        }
    } else {
        ResponseAction::Alert
    };
    assert_eq!(action_audit, ResponseAction::Alert);

    // When auto_quarantine_malware is true (Active/Lockdown mode), catalog attack below threshold escalates to Isolate (since destructive)
    autonomy.auto_quarantine_malware = true;
    let action_active = if sig.confidence >= autonomy.action_confidence_threshold {
        sig.recommended_action
    } else if is_catalog_attack && autonomy.auto_quarantine_malware {
        if is_destructive || sig.recommended_action == ResponseAction::Isolate {
            ResponseAction::Isolate
        } else if sig.recommended_action == ResponseAction::GhostTarpit {
            ResponseAction::GhostTarpit
        } else {
            ResponseAction::Tarpit
        }
    } else {
        ResponseAction::Alert
    };
    assert_eq!(action_active, ResponseAction::Isolate);

    // Non-destructive catalog attack escalates to Tarpit or GhostTarpit
    let benign_ev = make_test_event(serde_json::json!({
        "CommandLine": "python agent.py --prompt jailbreak",
        "ProcessId": 5678,
    }));
    let mut non_destruct_sig = ThreatSignature::default();
    non_destruct_sig.mitre_technique = Some("AML.T0043".to_string());
    non_destruct_sig.confidence = 0.80;
    non_destruct_sig.recommended_action = ResponseAction::GhostTarpit;

    let is_catalog = is_mitre_catalog_attack(&non_destruct_sig, &benign_ev);
    let is_destruct = is_destructive_mutation(&non_destruct_sig, &benign_ev);
    assert!(is_catalog, "AML.T0043 must be catalog attack");
    assert!(!is_destruct, "AML.T0043 must not be destructive mutation");

    let action_ghost = if non_destruct_sig.confidence >= autonomy.action_confidence_threshold {
        non_destruct_sig.recommended_action
    } else if is_catalog && autonomy.auto_quarantine_malware {
        if is_destruct || non_destruct_sig.recommended_action == ResponseAction::Isolate {
            ResponseAction::Isolate
        } else if non_destruct_sig.recommended_action == ResponseAction::GhostTarpit {
            ResponseAction::GhostTarpit
        } else {
            ResponseAction::Tarpit
        }
    } else {
        ResponseAction::Alert
    };
    assert_eq!(action_ghost, ResponseAction::GhostTarpit);
}

#[test]
fn test_ghost_tarpit_pid_debounce() {
    let pid = 998877;
    let now = std::time::Instant::now();
    RECENT_TARPITTED_PIDS.insert(pid, now);

    // Second call within 120s must be debounced
    let debounced = if let Some(last) = RECENT_TARPITTED_PIDS.get(&pid) {
        now.duration_since(*last) < std::time::Duration::from_secs(120)
    } else {
        false
    };
    assert!(
        debounced,
        "Consecutive event for same PID must be debounced within 120s"
    );

    // Clean up test entry
    RECENT_TARPITTED_PIDS.remove(&pid);
}

#[test]
fn test_is_cloud_storage_service() {
    assert!(is_cloud_storage_service("GoogleDriveFS.exe", None));
    assert!(is_cloud_storage_service("googledrivefs.exe", None));
    assert!(is_cloud_storage_service("OneDrive.exe", None));
    assert!(is_cloud_storage_service("onedrive.exe", None));
    assert!(is_cloud_storage_service("Dropbox.exe", None));
    assert!(is_cloud_storage_service("Nextcloud.exe", None));
    assert!(is_cloud_storage_service("Box.exe", None));
    assert!(is_cloud_storage_service("iCloudServices.exe", None));
    assert!(is_cloud_storage_service("rclone.exe", None));
    assert!(!is_cloud_storage_service(
        "custom_sync.exe",
        Some(std::path::Path::new(
            r"C:\Program Files\Google\DriveFS\custom_sync.exe"
        ))
    ));
    assert!(!is_cloud_storage_service(
        "custom_sync.exe",
        Some(std::path::Path::new(
            "C:/Program Files/Google/DriveFS/custom_sync.exe"
        ))
    ));
    assert!(!is_cloud_storage_service(
        "sync_daemon.exe",
        Some(std::path::Path::new(
            "C:/Users/dev/AppData/Local/Microsoft/OneDrive/sync_daemon.exe"
        ))
    ));
    assert!(is_cloud_storage_service("owncloud.exe", None));
    assert!(is_cloud_storage_service("pcloud.exe", None));

    // Negative cases
    assert!(!is_cloud_storage_service("cmd.exe", None));
    assert!(!is_cloud_storage_service("powershell.exe", None));
    assert!(!is_cloud_storage_service("mimikatz.exe", None));
    assert!(!is_cloud_storage_service(
        "payload.exe",
        Some(std::path::Path::new(r"C:\Windows\Temp\payload.exe"))
    ));
    assert!(!is_cloud_storage_service(
        "payload.exe",
        Some(std::path::Path::new("C:/Windows/Temp/payload.exe"))
    ));
}

#[tokio::test]
async fn test_mesh_skill_knowledge_handling() {
    let temp_dir = std::env::temp_dir().join(format!("osoosi_skill_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);

    let markdown = "# EDR-PAT-TEST\n\nDetect suspicious remote thread creation.";
    let hash = blake3::hash(markdown.trim().as_bytes())
        .to_hex()
        .to_string();

    let broadcast = osoosi_wire::SkillKnowledgeBroadcast {
        node_id: "peer-validator-01".to_string(),
        skill_name: "wikiskill".to_string(),
        version: "1.0.0".to_string(),
        content_hash: hash.clone(),
        pattern_title: "EDR-PAT-TEST: Remote Thread Creation".to_string(),
        markdown_content: markdown.to_string(),
        score: 0.99,
        timestamp: chrono::Utc::now(),
        signature: Some("test-signature-abc".to_string()),
    };

    // 1. Initial valid ingestion into non-existent workspace (tests automatic directory creation)
    let res = EdrOrchestrator::ingest_skill_knowledge_to_workspace(&broadcast, &temp_dir);
    assert!(res.is_ok(), "Valid broadcast must succeed: {:?}", res);
    let (pattern_file, is_duplicate, returned_hash) = res.unwrap();
    assert!(!is_duplicate, "First ingestion must not be duplicate");
    assert_eq!(returned_hash, hash);
    assert!(pattern_file.is_file());

    let saved_content = std::fs::read_to_string(&pattern_file).unwrap();
    assert_eq!(saved_content, markdown);

    let peer_patterns_file = temp_dir.join("wiki").join("peer_patterns.md");
    assert!(peer_patterns_file.is_file());
    let peer_patterns_content = std::fs::read_to_string(&peer_patterns_file).unwrap();
    assert!(peer_patterns_content.contains("EDR-PAT-TEST: Remote Thread Creation"));
    assert!(peer_patterns_content.contains("peer-validator-01"));
    assert!(peer_patterns_content.contains("test-signature-abc"));

    // 2. Duplicate ingestion: must be recognized as duplicate and NOT inflate peer_patterns.md
    let res2 = EdrOrchestrator::ingest_skill_knowledge_to_workspace(&broadcast, &temp_dir);
    assert!(res2.is_ok());
    let (_, is_dup2, _) = res2.unwrap();
    assert!(
        is_dup2,
        "Second ingestion of identical pattern must be duplicate"
    );
    let peer_patterns_content_after = std::fs::read_to_string(&peer_patterns_file).unwrap();
    assert_eq!(
        peer_patterns_content.len(),
        peer_patterns_content_after.len(),
        "Duplicate must not append to peer_patterns.md"
    );

    // 3. Reject empty markdown content
    let mut empty_content = broadcast.clone();
    empty_content.markdown_content = "   \n\t  ".to_string();
    let res_empty = EdrOrchestrator::ingest_skill_knowledge_to_workspace(&empty_content, &temp_dir);
    assert!(res_empty.is_err(), "Empty content must be rejected");

    // 4. Reject empty content_hash (bypassing hash checks)
    let mut empty_hash = broadcast.clone();
    empty_hash.content_hash = "".to_string();
    let res_empty_hash =
        EdrOrchestrator::ingest_skill_knowledge_to_workspace(&empty_hash, &temp_dir);
    assert!(
        res_empty_hash.is_err(),
        "Empty content_hash must be rejected"
    );

    // 5. Reject forged mismatched hash
    let mut forged_hash = broadcast.clone();
    forged_hash.content_hash =
        "deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
    let res_forged = EdrOrchestrator::ingest_skill_knowledge_to_workspace(&forged_hash, &temp_dir);
    assert!(
        res_forged.is_err(),
        "Forged mismatched content_hash must be rejected"
    );

    // 6. Reject forged single-character prefix hash
    let mut forged_prefix = broadcast.clone();
    forged_prefix.content_hash = hash[0..1].to_string();
    let res_forged_prefix =
        EdrOrchestrator::ingest_skill_knowledge_to_workspace(&forged_prefix, &temp_dir);
    assert!(
        res_forged_prefix.is_err(),
        "Short single-character prefix hash must be rejected"
    );

    // 7. Directory traversal in content_hash defense
    let mut traversal = broadcast.clone();
    traversal.content_hash = "../../evil_path".to_string();
    let res_traversal = EdrOrchestrator::ingest_skill_knowledge_to_workspace(&traversal, &temp_dir);
    assert!(
        res_traversal.is_err(),
        "Path traversal in content_hash must be rejected"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_is_internal_or_deception_path_coverage() {
    // Positive cases - relative paths
    assert!(is_internal_or_deception_path("traps\\canary.docx"));
    assert!(is_internal_or_deception_path("traps/canary.docx"));
    assert!(is_internal_or_deception_path("runs\\20261004.log"));
    assert!(is_internal_or_deception_path("runs/20261004.log"));
    assert!(is_internal_or_deception_path("logs\\osoosi.log"));
    assert!(is_internal_or_deception_path(
        "models\\securebert\\model.onnx"
    ));
    assert!(is_internal_or_deception_path("database\\osoosi.db"));
    assert!(is_internal_or_deception_path(
        ".agents\\skills\\security.md"
    ));
    assert!(is_internal_or_deception_path(
        ".gemini\\antigravity\\config"
    ));

    // Positive cases - exact directory/database names
    assert!(is_internal_or_deception_path("traps"));
    assert!(is_internal_or_deception_path("/traps/"));
    assert!(is_internal_or_deception_path("\\traps\\"));
    assert!(is_internal_or_deception_path("database"));
    assert!(is_internal_or_deception_path("runs"));
    assert!(is_internal_or_deception_path("logs"));
    assert!(is_internal_or_deception_path("models"));
    assert!(is_internal_or_deception_path(".agents"));
    assert!(is_internal_or_deception_path(".gemini"));
    assert!(is_internal_or_deception_path("osoosi.db"));
    assert!(is_internal_or_deception_path("osoosi.log"));
    assert!(is_internal_or_deception_path("osoosi_core.log"));

    // Positive cases - absolute Windows paths
    assert!(is_internal_or_deception_path(
        "C:\\Program Files\\OshoosiClaw\\traps\\honey.txt"
    ));
    assert!(is_internal_or_deception_path(
        "D:\\osoosi\\database\\state.db"
    ));
    assert!(is_internal_or_deception_path(
        "C:\\ProgramData\\Oshoosi\\logs\\agent.log"
    ));

    // Negative cases - benign OS paths or substring traps
    assert!(!is_internal_or_deception_path(
        "C:\\Windows\\System32\\cmd.exe"
    ));
    assert!(!is_internal_or_deception_path(
        "C:\\Users\\Bob\\Documents\\report.docx"
    ));
    assert!(!is_internal_or_deception_path("straps\\canary.docx"));
    assert!(!is_internal_or_deception_path("C:\\remodels\\engine.dll"));
    assert!(!is_internal_or_deception_path(""));
    assert!(!is_internal_or_deception_path("   "));
}

#[tokio::test]
async fn test_get_zone_summary_simulated_hosts_and_posture_persistence() {
    let memory = std::sync::Arc::new(osoosi_memory::MemoryStore::new(":memory:").unwrap());

    // Insert 3 simulated hosts (2 hotspot, 1 lan)
    let now = chrono::Utc::now();
    let did_hotspot1 =
        "did:osoosi:31b59725bd7728d80163d4407c0863544ca91604d38374003d7be7285aa61ca9";
    let did_lan = "did:osoosi:4885d3f54d7282b7fa192427d9a7d8b45cced40be66b687c73d43e7df7aac668";
    let did_hotspot2 =
        "did:osoosi:14a974a992b5b95033f1040240820581a81f86d2b96768719c8af0b1ae80cf00";

    for (did, os_ver) in [
        (did_hotspot1, "11 Pro"),
        (did_lan, "11 Enterprise"),
        (did_hotspot2, "11 Pro"),
    ] {
        memory
            .upsert_peer_status(&osoosi_types::PeerAnnounce {
                source_node: did.to_string(),
                is_patched: true,
                os_name: "Windows".to_string(),
                os_version: os_ver.to_string(),
                os_supported: true,
                timestamp: now,
                membership_proof: None,
                attestation: None,
            })
            .unwrap();
        memory
            .upsert_reputation(&osoosi_types::ReputationScore {
                node_id: did.to_string(),
                score: 1.0,
                alerts_verified: 5,
                false_positives: 0,
                last_updated: now,
            })
            .unwrap();
    }

    // Verify query matches our get_zone_summary logic
    let query = "SELECT peer_id as node_id, 1.0 as score FROM peer_status WHERE peer_id != ? AND (datetime(received_at) > datetime('now', '-30 minutes') OR received_at IS NULL) UNION SELECT node_id, score FROM reputation WHERE node_id != ? AND (datetime(last_updated) > datetime('now', '-30 minutes') OR last_updated IS NULL)";
    let peers = memory
        .query_json(
            query,
            &[
                "did:osoosi:local".to_string(),
                "did:osoosi:local".to_string(),
            ],
        )
        .unwrap();
    assert_eq!(peers.len(), 3);

    // Save posture
    memory
        .save_zone_posture(
            "zone-alpha-mesh",
            80,
            true,
            true,
            true,
            "TPM 2.0 Anchored",
            "[]",
        )
        .unwrap();
    let loaded = memory
        .load_zone_posture("zone-alpha-mesh")
        .unwrap()
        .unwrap();
    assert_eq!(loaded["security_score"], 80);
    assert_eq!(loaded["tpm_remediated"], true);
    assert_eq!(loaded["memory_shield_remediated"], true);
    assert_eq!(loaded["egress_remediated"], true);
}

#[tokio::test]
async fn test_evaluate_program_consensus_benign_and_ignore() {
    let temp_dir =
        std::env::temp_dir().join(format!("osoosi_consensus_test_{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let temp_file = temp_dir.join("benign_tool.txt");
    std::fs::write(&temp_file, b"Hello world benign consensus program").unwrap();

    let memory = osoosi_memory::MemoryStore::new(":memory:").unwrap();
    let malware_scanner = osoosi_model::MalwareScanner::new(std::path::Path::new("dummy.onnx"));
    let decision_cfg = osoosi_types::load_decision_model_config();
    let decision_engine = osoosi_behavioral::decision_model::ClefDecisionEngine::new(decision_cfg);
    let executor = std::sync::Arc::new(crate::secured_executor::DirectExecutor::new());
    let provisioner = std::sync::Arc::new(osoosi_telemetry::AgentProvisioner::new(executor));
    let blocking_manager = crate::blocking_manager::BlockingManager::new(provisioner);

    let finding = EdrOrchestrator::evaluate_program_consensus_internal(
        &memory,
        &malware_scanner,
        &decision_engine,
        &blocking_manager,
        &temp_file,
    )
    .await
    .unwrap();

    assert_eq!(finding.verdict, "benign");
    assert_eq!(finding.action_taken, "ignored_and_allowed");
    assert!(memory.is_hash_clean_ignored(&finding.hash_blake3));

    // Subsequent evaluation should return cached from clean-ignored ledger
    let cached = EdrOrchestrator::evaluate_program_consensus_internal(
        &memory,
        &malware_scanner,
        &decision_engine,
        &blocking_manager,
        &temp_file,
    )
    .await
    .unwrap();
    assert_eq!(cached.action_taken, "ignored_and_allowed");
    assert!(cached.id.starts_with("CONS-CACHED-"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cleanup_memory_and_disk_working_set_trim() {
    assert!(crate::memory_watchdog::trim_process_working_set());
}
