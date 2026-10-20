//! Adversarial empirical challenge test suite for Milestone 1
//! Tests command-line parsing, bypasses, edge cases, and spoofing vulnerabilities in immunity enforcement.

use osoosi_types::is_protected_os_shell_or_desktop_binary;

#[test]
fn test_python_inline_c_flag_space_vs_nospace() {
    // Standard command with space
    let standard = is_protected_os_shell_or_desktop_binary("python.exe -c \"import os\"");
    println!("python.exe -c \\\"import os\\\": protected = {}", standard);
    assert!(!standard, "python.exe -c with space should NOT be protected");

    // Adversarial bypass: python accepts -c without space before quotes
    let nospace_double_quote = is_protected_os_shell_or_desktop_binary("python.exe -c\"import os\"");
    println!("python.exe -c\\\"import os\\\": protected = {}", nospace_double_quote);

    // Adversarial bypass: python accepts -c without space before single quotes
    let nospace_single_quote = is_protected_os_shell_or_desktop_binary("python.exe -c'import os'");
    println!("python.exe -c'import os': protected = {}", nospace_single_quote);

    // Adversarial bypass: tab separator instead of space
    let tab_sep = is_protected_os_shell_or_desktop_binary("python.exe\t-c\t\"import os\"");
    println!("python.exe\\t-c\\t\\\"import os\\\": protected = {}", tab_sep);

    assert!(!nospace_double_quote, "python.exe -c\"...\" without space MUST NOT be protected");
    assert!(!nospace_single_quote, "python.exe -c'...' without space MUST NOT be protected");
    assert!(!tab_sep, "python.exe\\t-c\\t... with tab separator MUST NOT be protected");
}

#[test]
fn test_node_inline_eval_variations() {
    // Node with space
    let node_space = is_protected_os_shell_or_desktop_binary("node.exe -e \"process.exit(1)\"");
    println!("node.exe -e with space: protected = {}", node_space);
    assert!(!node_space, "node.exe -e with space should NOT be protected");

    // Node without space: node -e"code"
    let node_nospace = is_protected_os_shell_or_desktop_binary("node.exe -e\"process.exit(1)\"");
    println!("node.exe -e\\\"code\\\": protected = {}", node_nospace);

    // Node with --eval="code"
    let node_eval_eq = is_protected_os_shell_or_desktop_binary("node.exe --eval=\"process.exit(1)\"");
    println!("node.exe --eval=\\\"code\\\": protected = {}", node_eval_eq);

    assert!(!node_nospace, "node.exe -e\"...\" without space MUST NOT be protected");
    assert!(!node_eval_eq, "node.exe --eval=\"...\" with '=' MUST NOT be protected");
}

#[test]
fn test_case_insensitivity_windows() {
    assert!(is_protected_os_shell_or_desktop_binary("PYTHON.EXE"));
    assert!(is_protected_os_shell_or_desktop_binary("Cargo.Exe"));
    assert!(is_protected_os_shell_or_desktop_binary(r"C:\Windows\System32\SIHOST.EXE"));
    assert!(is_protected_os_shell_or_desktop_binary(r"C:\Program Files\Rust\CARGO.EXE"));

    // Case insensitive with inline flag
    assert!(!is_protected_os_shell_or_desktop_binary("PYTHON.EXE -C \"IMPORT OS\""));
}

#[test]
fn test_commandline_arguments_on_non_interpreter_tools() {
    // Plain binary name
    assert!(is_protected_os_shell_or_desktop_binary("cargo.exe"));
    assert!(is_protected_os_shell_or_desktop_binary("git.exe"));
    assert!(is_protected_os_shell_or_desktop_binary("explorer.exe"));

    // Command line with arguments
    let cargo_with_args = is_protected_os_shell_or_desktop_binary("cargo.exe build");
    println!("cargo.exe build: protected = {}", cargo_with_args);

    let git_with_args = is_protected_os_shell_or_desktop_binary("git.exe status");
    println!("git.exe status: protected = {}", git_with_args);

    let explorer_with_args = is_protected_os_shell_or_desktop_binary(r"C:\Windows\explorer.exe /n");
    println!("explorer.exe /n: protected = {}", explorer_with_args);

    let svchost_with_args = is_protected_os_shell_or_desktop_binary(r"C:\Windows\System32\svchost.exe -k netsvcs");
    println!("svchost.exe -k netsvcs: protected = {}", svchost_with_args);

    assert!(cargo_with_args, "cargo.exe build with args MUST retain immunity");
    assert!(git_with_args, "git.exe status with args MUST retain immunity");
    assert!(explorer_with_args, "explorer.exe /n with args MUST retain immunity");
    assert!(svchost_with_args, "svchost.exe -k netsvcs with args MUST retain immunity");
}

#[test]
fn test_temporary_and_untrusted_folder_paths() {
    // Windows Temp
    assert!(!is_protected_os_shell_or_desktop_binary(r"C:\Windows\Temp\python.exe"));
    assert!(!is_protected_os_shell_or_desktop_binary(r"C:\Users\user\AppData\Local\Temp\python.exe"));
    assert!(!is_protected_os_shell_or_desktop_binary(r"C:\Temp\python.exe"));

    // Linux tmp
    assert!(!is_protected_os_shell_or_desktop_binary("/tmp/python3"));
    assert!(!is_protected_os_shell_or_desktop_binary("/var/tmp/python3"));

    // Untrusted writable directories commonly used by malware:
    // 1. C:\Users\Public\
    let public_dir = is_protected_os_shell_or_desktop_binary(r"C:\Users\Public\python.exe");
    println!(r"C:\Users\Public\python.exe: protected = {}", public_dir);
    assert!(!public_dir, "C:\\Users\\Public\\python.exe in untrusted directory MUST NOT be protected");

    // 2. /dev/shm/
    let shm_dir = is_protected_os_shell_or_desktop_binary("/dev/shm/python3");
    println!("/dev/shm/python3: protected = {}", shm_dir);
    assert!(!shm_dir, "/dev/shm/python3 in untrusted directory MUST NOT be protected");

    // 3. C:\ProgramData\
    let programdata_dir = is_protected_os_shell_or_desktop_binary(r"C:\ProgramData\python.exe");
    println!(r"C:\ProgramData\python.exe: protected = {}", programdata_dir);
    assert!(!programdata_dir, "C:\\ProgramData\\python.exe in untrusted directory MUST NOT be protected");
}

#[test]
fn test_legitimate_developer_argument_false_positives() {
    // Legitimate developer running pytest or python script with -c for config file
    let dev_config_flag = is_protected_os_shell_or_desktop_binary("python.exe run_tests.py -c config.yaml");
    println!("python.exe run_tests.py -c config.yaml: protected = {}", dev_config_flag);
    assert!(dev_config_flag, "python.exe run_tests.py -c config.yaml MUST retain immunity");

    // Legitimate security analysis script named beacon_analysis.py
    let dev_beacon_script = is_protected_os_shell_or_desktop_binary(r"C:\Dev\beacon_analysis.py");
    println!("C:\\Dev\\beacon_analysis.py: protected = {}", dev_beacon_script);
    assert!(dev_beacon_script, "C:\\Dev\\beacon_analysis.py MUST retain immunity");

    // Legitimate security tool detecting evil
    let dev_evil_scanner = is_protected_os_shell_or_desktop_binary(r"C:\Dev\detect_evil.py");
    println!("C:\\Dev\\detect_evil.py: protected = {}", dev_evil_scanner);
    assert!(dev_evil_scanner, "C:\\Dev\\detect_evil.py MUST retain immunity");
}

