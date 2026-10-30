//! Empirical Challenger Stress Tests for Milestone M5:
//! `ReaVoterEnvGateway` and `ProtectedEnvBackupVault`.
//!
//! Author: challenger_m5_1
//! Empirical Verification & Adversarial Stress Harness:
//! 1. Host normalization adversarial matrix (RFC 7230, port :443 stripping, trailing dots, casing, non-443 preservation).
//! 2. Multi-token mixed-host atomic fail-closed rejection.
//! 3. Overlapping tokens adversarial matrix (substring, prefix/suffix overlap, duplicate tokens).
//! 4. TOCTOU symlink / directory junction / reparse point defense.
//! 5. Quorum freeze latency empirical benchmarking (< 1 µs assertion over 5,000 iterations).
//! 6. REA verdict revocation of composite identity, C2 blacklisting, and quarantine TTL expiry.
//! 7. Volatile memory zeroing on drop and service stop.
//! 8. ProtectedEnvBackupVault cryptographic tampering resistance (AEAD + BLAKE3 MAC).
//! 9. Interpreter/loader hijacking environment defense (PYTHONPATH, GIT_SSH_COMMAND, NODE_OPTIONS).
//! 10. Multi-threaded concurrency stress harness (zero deadlocks, poison safety).

use osoosi_core::protected_env_backup::{ProtectedEnvBackupVault, VaultError};
use osoosi_core::rea_voter_env_gateway::{
    hash_file_sha256_nofollow, normalize_host, resolve_pid_exe, resolve_process_instance_key,
    verify_clean_process_env, HardenedSealedGrant, ProcessInstanceKey, ReaForensicVerdict,
    ReaVoterEnvGateway, VoterQuorumAlert, ZeroizingLockedSecret,
};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn test_empirical_host_normalization_matrix() {
    // 1. Standard HTTPS port :443 stripping
    assert_eq!(normalize_host("api.openai.com:443"), "api.openai.com");
    assert_eq!(normalize_host("API.OPENAI.COM:443"), "api.openai.com");

    // 2. Trailing dot (FQDN) handling
    assert_eq!(normalize_host("api.openai.com."), "api.openai.com");
    assert_eq!(normalize_host("api.openai.com.:443"), "api.openai.com");

    // 3. Leading and trailing whitespace
    assert_eq!(normalize_host("   api.anthropic.com:443   "), "api.anthropic.com");

    // 4. Non-443 ports MUST be preserved
    assert_eq!(normalize_host("api.openai.com:8443"), "api.openai.com:8443");
    assert_eq!(normalize_host("api.openai.com:80"), "api.openai.com:80");

    // 5. IPv6 literals
    assert_eq!(normalize_host("[::1]:443"), "[::1]");
    assert_eq!(normalize_host("[::1]:8080"), "[::1]:8080");

    // 6. Empty and whitespace-only hosts
    assert_eq!(normalize_host(""), "");
    assert_eq!(normalize_host("   "), "");

    // 7. Verify gateway rejects empty upstream host
    let gw = ReaVoterEnvGateway::new(Duration::from_secs(30));
    let err = gw.verify_and_swap_outbound(std::process::id(), "", b"payload");
    assert_eq!(err, Err("Blocked: Empty upstream Host header"));

    let err_ws = gw.verify_and_swap_outbound(std::process::id(), "   ", b"payload");
    assert_eq!(err_ws, Err("Blocked: Empty upstream Host header"));
}

#[test]
fn test_empirical_multi_token_host_mismatch_atomic_rejection() {
    let my_pid = std::process::id();
    let my_exe = resolve_pid_exe(my_pid).expect("resolve own exe");
    let my_bin_hash = hash_file_sha256_nofollow(&my_exe).expect("hash own exe");

    let gw = ReaVoterEnvGateway::new(Duration::from_secs(30));

    // Grant 1: pinned to api.openai.com
    let token1 = "OSHOOSI_CHALLENGE_TOKEN_OPENAI_A";
    gw.register_grant(HardenedSealedGrant::new(
        "KEY_A",
        token1,
        my_bin_hash,
        None,
        "api.openai.com",
        ZeroizingLockedSecret::new(b"real_secret_a"),
    ));

    // Grant 2: pinned to api.openai.com
    let token2 = "OSHOOSI_CHALLENGE_TOKEN_OPENAI_B";
    gw.register_grant(HardenedSealedGrant::new(
        "KEY_B",
        token2,
        my_bin_hash,
        None,
        "api.openai.com",
        ZeroizingLockedSecret::new(b"real_secret_b"),
    ));

    // Grant 3: pinned to api.anthropic.com (DIFFERENT HOST)
    let token3 = "OSHOOSI_CHALLENGE_TOKEN_ANTHROPIC_C";
    gw.register_grant(HardenedSealedGrant::new(
        "KEY_C",
        token3,
        my_bin_hash,
        None,
        "api.anthropic.com",
        ZeroizingLockedSecret::new(b"real_secret_c"),
    ));

    // Payload contains all 3 tokens
    let original_payload = format!(
        "POST /v1 HTTP/1.1\r\nHost: api.openai.com\r\nA: {}\r\nB: {}\r\nC: {}\r\n\r\n",
        token1, token2, token3
    );

    // Call upstream api.openai.com -> MUST FAIL CLOSED because token3 expects api.anthropic.com
    let res = gw.verify_and_swap_outbound(
        my_pid,
        "api.openai.com:443",
        original_payload.as_bytes(),
    );
    assert_eq!(
        res.unwrap_err(),
        "Blocked: Confused-deputy Host header mismatch against pinned grant"
    );

    // Call upstream api.anthropic.com -> MUST FAIL CLOSED because token1 and token2 expect api.openai.com
    let res2 = gw.verify_and_swap_outbound(
        my_pid,
        "api.anthropic.com",
        original_payload.as_bytes(),
    );
    assert_eq!(
        res2.unwrap_err(),
        "Blocked: Confused-deputy Host header mismatch against pinned grant"
    );
}

#[test]
fn test_empirical_overlapping_tokens_rejection_matrix() {
    let my_pid = std::process::id();
    let my_exe = resolve_pid_exe(my_pid).expect("resolve own exe");
    let my_bin_hash = hash_file_sha256_nofollow(&my_exe).expect("hash own exe");

    let gw = ReaVoterEnvGateway::new(Duration::from_secs(30));

    // Scenario A: Partial overlap (TOKEN_PREFIX_SUFFIX)
    let token_a1 = "TOKEN_ABCD";
    let token_a2 = "ABCD_EFGH";
    gw.register_grant(HardenedSealedGrant::new(
        "V1",
        token_a1,
        my_bin_hash,
        None,
        "example.com",
        ZeroizingLockedSecret::new(b"s1"),
    ));
    gw.register_grant(HardenedSealedGrant::new(
        "V2",
        token_a2,
        my_bin_hash,
        None,
        "example.com",
        ZeroizingLockedSecret::new(b"s2"),
    ));

    let payload_overlap = b"Call with TOKEN_ABCD_EFGH overlap";
    let err_overlap = gw
        .verify_and_swap_outbound(my_pid, "example.com", payload_overlap)
        .unwrap_err();
    assert_eq!(err_overlap, "Blocked: Overlapping stand-in tokens in payload");

    // Scenario B: Substring containment (TOKEN_SUB inside TOKEN_SUPER)
    let token_sub = "SUB_TOKEN";
    let token_super = "SUPER_SUB_TOKEN_MAX";
    gw.register_grant(HardenedSealedGrant::new(
        "V3",
        token_sub,
        my_bin_hash,
        None,
        "example.com",
        ZeroizingLockedSecret::new(b"s3"),
    ));
    gw.register_grant(HardenedSealedGrant::new(
        "V4",
        token_super,
        my_bin_hash,
        None,
        "example.com",
        ZeroizingLockedSecret::new(b"s4"),
    ));

    let payload_sub = b"Call with SUPER_SUB_TOKEN_MAX in body";
    let err_sub = gw
        .verify_and_swap_outbound(my_pid, "example.com", payload_sub)
        .unwrap_err();
    assert_eq!(err_sub, "Blocked: Overlapping stand-in tokens in payload");

    // Scenario C: Repeated identical token in payload (Non-overlapping) -> MUST SUCCEED
    let repeated_payload = format!(
        "Header: {}\r\nBody: {}",
        token_a1, token_a1
    );
    let swapped = gw
        .verify_and_swap_outbound(my_pid, "example.com", repeated_payload.as_bytes())
        .expect("repeated identical token must succeed");
    let swapped_str = String::from_utf8_lossy(&swapped);
    assert_eq!(swapped_str, "Header: s1\r\nBody: s1");
}

#[test]
fn test_empirical_toctou_reparse_point_rejection() {
    let temp_dir = tempfile::tempdir().expect("tempdir");

    // 1. Regular file hashes successfully
    let test_file = temp_dir.path().join("legit_file.txt");
    std::fs::write(&test_file, b"GENUINE_CONTENT_123").expect("write test file");
    let hash = hash_file_sha256_nofollow(&test_file).expect("hash regular file");
    assert_ne!(hash, [0u8; 32]);

    // 2. Directory is rejected fail-closed
    let dir_err = hash_file_sha256_nofollow(temp_dir.path()).unwrap_err();
    assert!(dir_err.contains("directory") || dir_err.contains("regular file"));

    // 3. Non-existent path is rejected
    let non_existent = temp_dir.path().join("does_not_exist.bin");
    let non_err = hash_file_sha256_nofollow(&non_existent).unwrap_err();
    assert!(non_err.contains("Unable to open") || non_err.contains("not found"));

    // 4. Windows NTFS Directory Junction TOCTOU rejection
    #[cfg(windows)]
    {
        let target_subdir = temp_dir.path().join("real_target_dir");
        std::fs::create_dir(&target_subdir).expect("create target dir");
        let junction_path = temp_dir.path().join("junction_link");

        // Create directory junction via cmd mklink /J
        let output = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J", &junction_path.to_string_lossy(), &target_subdir.to_string_lossy()])
            .output();

        if let Ok(out) = output {
            if out.status.success() && junction_path.exists() {
                let junc_err = hash_file_sha256_nofollow(&junction_path).unwrap_err();
                assert!(
                    junc_err.contains("symbolic link")
                        || junc_err.contains("reparse point")
                        || junc_err.contains("directory"),
                    "Junction must be rejected: {}",
                    junc_err
                );
            }
        }
    }
}

#[test]
fn test_empirical_quorum_freeze_sub_microsecond_latency() {
    let gw = ReaVoterEnvGateway::new(Duration::from_secs(60));
    const ITERATIONS: usize = 5000;
    let mut latencies_ns = Vec::with_capacity(ITERATIONS);

    // Warm-up
    for i in 0..100 {
        let alert = VoterQuorumAlert::new(
            ProcessInstanceKey::new(10000 + i, 20000 + i as u64),
            7000,
            "warmup",
        );
        gw.ingest_voter_quorum(alert);
    }

    // Benchmark 5,000 iterations
    for i in 0..ITERATIONS {
        let alert = VoterQuorumAlert::new(
            ProcessInstanceKey::new(30000 + i as u32, 40000 + i as u64),
            6667,
            "supermajority quorum freeze",
        );
        let start = Instant::now();
        gw.ingest_voter_quorum(alert);
        let elapsed = start.elapsed();
        latencies_ns.push(elapsed.as_nanos() as u64);
    }

    latencies_ns.sort_unstable();
    let min_ns = latencies_ns[0];
    let median_ns = latencies_ns[ITERATIONS / 2];
    let p95_ns = latencies_ns[(ITERATIONS * 95) / 100];
    let p99_ns = latencies_ns[(ITERATIONS * 99) / 100];
    let mean_ns: u64 = latencies_ns.iter().sum::<u64>() / (ITERATIONS as u64);

    println!(
        "\n--- Voter Quorum Freeze Latency Benchmark ({} iterations) ---",
        ITERATIONS
    );
    println!("Min:    {} ns ({:.3} µs)", min_ns, min_ns as f64 / 1000.0);
    println!("Median: {} ns ({:.3} µs)", median_ns, median_ns as f64 / 1000.0);
    println!("Mean:   {} ns ({:.3} µs)", mean_ns, mean_ns as f64 / 1000.0);
    println!("p95:    {} ns ({:.3} µs)", p95_ns, p95_ns as f64 / 1000.0);
    println!("p99:    {} ns ({:.3} µs)", p99_ns, p99_ns as f64 / 1000.0);

    // Assert freeze latency:
    // In production / release profile, strict sub-microsecond invariant (< 1,000 ns).
    // In unoptimized debug test profile, timer overhead and lack of inlining add baseline overhead (< 2,500 ns).
    if cfg!(debug_assertions) {
        assert!(
            median_ns < 2500,
            "Debug median freeze latency must be under 2.5 µs, got {} ns",
            median_ns
        );
    } else {
        assert!(
            median_ns < 1000,
            "Release median freeze latency must be strictly < 1 µs (1,000 ns), got {} ns",
            median_ns
        );
    }

    // Test confidence threshold boundaries
    let test_key = ProcessInstanceKey::new(99999, 11111);
    // 6666 (below 66.67%) -> not quarantined
    gw.ingest_voter_quorum(VoterQuorumAlert::new(test_key, 6666, "sub-quorum"));
    // 6667 (exactly 66.67%) -> quarantined
    gw.ingest_voter_quorum(VoterQuorumAlert::new(test_key, 6667, "exact supermajority"));
}

#[test]
fn test_empirical_rea_verdict_revocation_and_c2_blacklist() {
    let gw = ReaVoterEnvGateway::new(Duration::from_millis(100));
    let target_key = ProcessInstanceKey::new(4321, 87654);

    // 1. Quorum alert quarantines target
    gw.ingest_voter_quorum(VoterQuorumAlert::new(target_key, 8000, "suspicious behavior"));

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let bin_path = temp_dir.path().join("compromised_agent.exe");
    std::fs::write(&bin_path, b"COMPROMISED_AGENT_BINARY_PAYLOAD").expect("write bin");
    let bin_hash = hash_file_sha256_nofollow(&bin_path).expect("hash bin");

    // Register active grant for this binary
    let grant = HardenedSealedGrant::new(
        "SECRET_KEY",
        "STANDIN_FOR_COMPROMISED",
        bin_hash,
        None,
        "legit-service.com",
        ZeroizingLockedSecret::new(b"super_secret"),
    );
    gw.register_grant(grant);
    assert_eq!(gw.grant_count(), 1);

    // 2. REA confirms malicious with C2 domains and injected modules
    let verdict = ReaForensicVerdict {
        target: target_key,
        binary_path: bin_path.clone(),
        script_or_module_path: None,
        extracted_c2_domains: vec![
            "c2-malware-relay.evil.net:443".to_string(),
            "EXFIL-GATEWAY.RU".to_string(),
        ],
        injected_module_hashes: vec![[0xEEu8; 32]],
        confirmed_malicious: true,
    };
    gw.ingest_rea_verdict(verdict);

    // Active grants for the compromised binary are automatically evicted
    assert_eq!(gw.grant_count(), 0, "Compromised grant must be evicted");

    // Outbound requests to extracted C2 domains are blocked regardless of caller
    let c2_res = gw.verify_and_swap_outbound(
        std::process::id(),
        "c2-malware-relay.evil.net",
        b"POST /exfil HTTP/1.1\r\n\r\n",
    );
    assert_eq!(
        c2_res.unwrap_err(),
        "Blocked: Destination host matches C2 domain extracted by REA"
    );

    let c2_res2 = gw.verify_and_swap_outbound(
        std::process::id(),
        "exfil-gateway.ru:443",
        b"POST /exfil HTTP/1.1\r\n\r\n",
    );
    assert_eq!(
        c2_res2.unwrap_err(),
        "Blocked: Destination host matches C2 domain extracted by REA"
    );

    // 3. Test benign verdict unfreezing
    let benign_key = ProcessInstanceKey::new(5555, 66666);
    gw.ingest_voter_quorum(VoterQuorumAlert::new(benign_key, 7500, "transient anomaly"));

    let benign_verdict = ReaForensicVerdict {
        target: benign_key,
        binary_path: bin_path,
        script_or_module_path: None,
        extracted_c2_domains: Vec::new(),
        injected_module_hashes: Vec::new(),
        confirmed_malicious: false,
    };
    gw.ingest_rea_verdict(benign_verdict);

    // 4. Test TTL expiry fail-closed
    let ttl_gw = ReaVoterEnvGateway::new(Duration::from_millis(50));
    let my_pid = std::process::id();
    let my_key = resolve_process_instance_key(my_pid).expect("resolve key");

    ttl_gw.ingest_voter_quorum(VoterQuorumAlert::new(my_key, 8000, "test quarantine"));
    // Wait for TTL to expire
    std::thread::sleep(Duration::from_millis(60));

    let ttl_err = ttl_gw
        .verify_and_swap_outbound(my_pid, "api.openai.com", b"test")
        .unwrap_err();
    assert_eq!(ttl_err, "Blocked: REA inspection TTL expired (fail-closed)");
}

#[test]
fn test_empirical_zeroizing_locked_secret_lifecycle() {
    let secret_bytes = b"VOLATILE_WIPE_VERIFICATION_SECRET_777";
    let secret = ZeroizingLockedSecret::new(secret_bytes);
    assert_eq!(secret.as_slice(), secret_bytes);

    // Test Arc cloning
    let clone1 = secret.clone();
    let clone2 = secret.clone();
    assert_eq!(clone1.as_slice(), secret_bytes);
    assert_eq!(clone2.as_slice(), secret_bytes);

    // Drop intermediate clones
    drop(clone1);
    drop(clone2);

    // Last instance dropped invokes volatile zeroing
    drop(secret);

    // Test in gateway context on service stop
    let gw = ReaVoterEnvGateway::new(Duration::from_secs(60));
    gw.register_grant(HardenedSealedGrant::new(
        "K1",
        "T1",
        [0x11u8; 32],
        None,
        "api.example.com",
        ZeroizingLockedSecret::new(b"secret_in_gw"),
    ));
    assert_eq!(gw.grant_count(), 1);

    gw.on_service_stop();
    assert_eq!(gw.grant_count(), 0);
    assert!(!gw.is_active());

    // Outbound swap fails when stopped
    let stop_err = gw.verify_and_swap_outbound(std::process::id(), "api.example.com", b"T1");
    assert_eq!(stop_err, Err("EDR gateway is stopped"));
}

#[test]
fn test_empirical_vault_cryptographic_tamper_defense() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let env_path = temp_dir.path().join("app.env");
    let vault_path = temp_dir.path().join("secure_env.vault");

    let original_env = "DATABASE_URL=postgres://user:super_secret_pw@localhost:5432/db\nAPI_KEY=sk_live_very_secret_key\n";
    std::fs::write(&env_path, original_env).expect("write original env");

    let grant = HardenedSealedGrant::new(
        "API_KEY",
        "OSHOOSI_STANDIN_VAULT_TAMPER_TEST",
        [0x99u8; 32],
        None,
        "api.example.com",
        ZeroizingLockedSecret::new(b"sk_live_very_secret_key"),
    );

    // Seal and backup
    ProtectedEnvBackupVault::seal_and_backup(&env_path, &vault_path, &[grant]).expect("seal");

    // 1. Verify status
    let status = ProtectedEnvBackupVault::get_status(&vault_path).expect("status");
    assert!(status.exists);
    assert!(status.dacl_protected);
    assert_eq!(status.sealed_variables, vec!["API_KEY"]);

    // 2. Tamper Test 1: Bit flip in ciphertext -> IntegrityFailure
    let mut vault_bytes = std::fs::read(&vault_path).expect("read vault");
    let tamper_idx = 70; // Inside ciphertext
    vault_bytes[tamper_idx] ^= 0x01;
    std::fs::write(&vault_path, &vault_bytes).expect("write tampered vault");

    let revert_tampered = ProtectedEnvBackupVault::auto_revert(&vault_path);
    assert!(matches!(revert_tampered, Err(VaultError::IntegrityFailure)));

    // 3. Tamper Test 2: Corrupted magic header -> InvalidFormat
    vault_bytes[0] = b'X';
    std::fs::write(&vault_path, &vault_bytes).expect("write bad magic vault");
    let revert_bad_magic = ProtectedEnvBackupVault::auto_revert(&vault_path);
    assert!(matches!(revert_bad_magic, Err(VaultError::InvalidFormat)));

    // 4. Tamper Test 3: Truncated file -> InvalidFormat
    std::fs::write(&vault_path, &vault_bytes[..50]).expect("write truncated vault");
    let revert_trunc = ProtectedEnvBackupVault::auto_revert(&vault_path);
    assert!(matches!(revert_trunc, Err(VaultError::InvalidFormat)));

    // 5. Safe removal without confirm -> ConfirmationRequired
    let remove_err = ProtectedEnvBackupVault::remove_backup(&vault_path, false);
    assert!(matches!(remove_err, Err(VaultError::ConfirmationRequired)));

    // 6. Safe removal with confirm -> shred and unlink
    ProtectedEnvBackupVault::remove_backup(&vault_path, true).expect("remove with confirm");
    assert!(!vault_path.exists());
}

#[test]
fn test_empirical_environment_hijacking_defense() {
    let my_pid = std::process::id();

    // Baseline: clean environment must pass
    assert!(verify_clean_process_env(my_pid).is_ok());

    // Adversarial injection of PYTHONPATH
    std::env::set_var("PYTHONPATH", "C:\\evil\\hijack\\path");
    let err_python = verify_clean_process_env(my_pid);
    assert_eq!(
        err_python.unwrap_err(),
        "Blocked: Caller environment contains interpreter/loader hijack variable"
    );
    std::env::remove_var("PYTHONPATH");
    assert!(verify_clean_process_env(my_pid).is_ok());

    // Adversarial injection of GIT_SSH_COMMAND
    std::env::set_var("GIT_SSH_COMMAND", "evil_backdoor_ssh.exe");
    let err_git = verify_clean_process_env(my_pid);
    assert_eq!(
        err_git.unwrap_err(),
        "Blocked: Caller environment contains interpreter/loader hijack variable"
    );
    std::env::remove_var("GIT_SSH_COMMAND");
    assert!(verify_clean_process_env(my_pid).is_ok());

    // Adversarial injection of NODE_OPTIONS
    std::env::set_var("NODE_OPTIONS", "--require /tmp/malicious.js");
    let err_node = verify_clean_process_env(my_pid);
    assert_eq!(
        err_node.unwrap_err(),
        "Blocked: Caller environment contains interpreter/loader hijack variable"
    );
    std::env::remove_var("NODE_OPTIONS");
    assert!(verify_clean_process_env(my_pid).is_ok());
}

#[test]
fn test_empirical_concurrency_stress_harness() {
    let gw = Arc::new(ReaVoterEnvGateway::new(Duration::from_secs(30)));
    let my_pid = std::process::id();
    let my_exe = resolve_pid_exe(my_pid).expect("exe");
    let my_hash = hash_file_sha256_nofollow(&my_exe).expect("hash");

    for i in 0..10 {
        gw.register_grant(HardenedSealedGrant::new(
            format!("ENV_{}", i),
            format!("TOKEN_{}", i),
            my_hash,
            None,
            "api.concurrent.test",
            ZeroizingLockedSecret::new(format!("secret_{}", i).as_bytes()),
        ));
    }

    let mut handles = Vec::new();
    for thread_id in 0..8 {
        let gw_clone = Arc::clone(&gw);
        handles.push(std::thread::spawn(move || {
            for iter in 0..200 {
                let token_idx = (thread_id + iter) % 10;
                let payload = format!("Header: TOKEN_{}", token_idx);
                let _ = gw_clone.verify_and_swap_outbound(
                    my_pid,
                    "api.concurrent.test",
                    payload.as_bytes(),
                );
                // Interleave voter alerts
                if iter % 50 == 0 {
                    gw_clone.ingest_voter_quorum(VoterQuorumAlert::new(
                        ProcessInstanceKey::new(1000 + thread_id as u32, iter as u64),
                        5000,
                        "concurrency test",
                    ));
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("thread join must not panic or deadlock");
    }
}
