//! Integration test for `osoosi` CLI stop command and status

#[test]
fn test_cli_stop_help_output() {
    let osoosi_bin = env!("CARGO_BIN_EXE_osoosi");
    let output = std::process::Command::new(osoosi_bin)
        .args(["stop", "--help"])
        .output()
        .expect("execute osoosi stop --help");

    assert!(output.status.success(), "stop --help must succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Stop the OpenỌ̀ṣọ́ọ̀sì security agent daemon"));
    assert!(stdout.contains("--force") || stdout.contains("-f"));
}

#[test]
fn test_cli_down_alias_help_output() {
    let osoosi_bin = env!("CARGO_BIN_EXE_osoosi");
    let output = std::process::Command::new(osoosi_bin)
        .args(["down", "--help"])
        .output()
        .expect("execute osoosi down --help");

    assert!(output.status.success(), "down --help must succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Stop the OpenỌ̀ṣọ́ọ̀sì security agent daemon"));
}
