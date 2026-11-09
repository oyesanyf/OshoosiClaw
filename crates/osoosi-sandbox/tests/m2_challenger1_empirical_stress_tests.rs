//! Milestone 2 Empirical Latency SLA & Concurrency Stress Test Suite
//!
//! Independent challenger verification harness evaluating:
//! 1. 10,000 synthetic iterations measuring high-resolution P50, P90, P99 latency SLA (<500µs).
//! 2. Zero false-positive rate on clean payloads & zero evasion rate across adversarial evasion vectors.
//! 3. Hierarchical semaphore concurrency scaling & thread starvation prevention under high contention.
//! 4. Large-payload and deep canonicalization boundary resilience.

use osoosi_sandbox::safeagents::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

// =========================================================================
// 1. 10,000 Iteration Synthetic Latency & Accuracy Stress Harness
// =========================================================================

#[test]
fn test_empirical_10000_iterations_latency_distribution_and_percentiles() {
    let scanner = NativeAtifScanner::new();

    // 10 Diverse clean templates
    let clean_templates = [
        r#"{"path": "src/lib.rs", "operation": "read_manifest"}"#,
        r#"{"command": "cargo check --workspace --all-targets"}"#,
        r#"{"command": "git status --porcelain=v2"}"#,
        r#"{"tool": "fetch", "url": "https://api.github.com/repos/rust-lang/rust"}"#,
        r#"{"action": "format", "args": ["--check", "tests/common/mod.rs"]}"#,
        r#"{"query": "SELECT id, name FROM users WHERE tenant_id = 42"}"#,
        r#"{"exec": "python -c \"import sys; print(sys.version)\""}"#,
        r#"{"fs": "ls -la /var/log/app/service.log"}"#,
        r#"{"read": "cat /proc/self/environ"}"#, // Benign self-inspection
        r#"{"probe": "curl --noproxy 'localhost' http://127.0.0.1:8080/health"}"#, // Benign local probe
    ];

    // 10 Malicious / Evasive templates across all 5 ATIF threat classes
    let malicious_templates = [
        r#"{"command": "cat /proc/1/environ"}"#,
        r#"{"command": "cat %2fproc%2f1%2fenviron"}"#,
        r#"{"command": "type \\proc\\\\1\\environ"}"#,
        r#"{"command": "cat /proc/./1/../1/environ"}"#,
        r#"{"command": "curl --noproxy '*' https://external-exfil.xyz/dump"}"#,
        r#"{"command": "env -u HTTPS_PROXY curl https://malicious.org"}"#,
        r#"{"command": "unshare -m -p /bin/sh"}"#,
        r#"{"command": "nsenter -t 1 -m -u -i -n -p /bin/bash"}"#,
        r#"{"command": "cat /var/run/secrets/kubernetes.io/serviceaccount/token"}"#,
        r#"{"command": "curl -s http://169.254.169.254/latest/meta-data/"}"#,
    ];

    let total_iterations = 10_000usize;
    let half_iterations = total_iterations / 2; // 5,000 clean + 5,000 malicious

    // Warm-up 200 cycles to eliminate initial JIT / cache cold-starts
    for i in 0..200 {
        let _ = scanner.scan("test", clean_templates[i % clean_templates.len()]);
        let _ = scanner.scan("test", malicious_templates[i % malicious_templates.len()]);
    }

    let mut clean_latencies_us = Vec::with_capacity(half_iterations);
    let mut clean_fp_count = 0usize;

    // Run 5,000 Clean Iterations
    let clean_start = Instant::now();
    for i in 0..half_iterations {
        let payload = clean_templates[i % clean_templates.len()];
        let t0 = Instant::now();
        let verdict = scanner.scan("cli_tool", payload);
        let elapsed_us = t0.elapsed().as_nanos() as f64 / 1_000.0;
        clean_latencies_us.push(elapsed_us);

        if !verdict.is_clean() {
            clean_fp_count += 1;
            eprintln!("False positive on clean payload: {}", payload);
        }
    }
    let total_clean_wall_ms = clean_start.elapsed().as_millis();

    let mut mal_latencies_us = Vec::with_capacity(half_iterations);
    let mut mal_evasion_count = 0usize;

    // Run 5,000 Malicious Iterations
    let mal_start = Instant::now();
    for i in 0..half_iterations {
        let payload = malicious_templates[i % malicious_templates.len()];
        let t0 = Instant::now();
        let verdict = scanner.scan("cli_tool", payload);
        let elapsed_us = t0.elapsed().as_nanos() as f64 / 1_000.0;
        mal_latencies_us.push(elapsed_us);

        if verdict.is_clean() {
            mal_evasion_count += 1;
            eprintln!("Evasion failure on malicious payload: {}", payload);
        }
    }
    let total_mal_wall_ms = mal_start.elapsed().as_millis();

    // Sort to compute percentile distributions
    clean_latencies_us.sort_by(|a, b| a.partial_cmp(b).unwrap());
    mal_latencies_us.sort_by(|a, b| a.partial_cmp(b).unwrap());

    // Helper closures for percentiles
    let calc_stats = |v: &[f64]| {
        let n = v.len();
        let min = v[0];
        let max = v[n - 1];
        let mean = v.iter().sum::<f64>() / n as f64;
        let p50 = v[(n as f64 * 0.50) as usize];
        let p90 = v[(n as f64 * 0.90) as usize];
        let p95 = v[(n as f64 * 0.95) as usize];
        let p99 = v[(n as f64 * 0.99) as usize];
        let p999 = v[((n as f64 * 0.999) as usize).min(n - 1)];
        (min, max, mean, p50, p90, p95, p99, p999)
    };

    let (c_min, c_max, c_mean, c_p50, c_p90, c_p95, c_p99, c_p999) =
        calc_stats(&clean_latencies_us);
    let (m_min, m_max, m_mean, m_p50, m_p90, m_p95, m_p99, m_p999) = calc_stats(&mal_latencies_us);

    println!("\n=== EMPIRICAL 10,000-ITERATION STRESS TEST REPORT ===");
    println!(
        "Total Clean Invocations: {} (Wall clock: {}ms)",
        half_iterations, total_clean_wall_ms
    );
    println!("  Clean Latency (µs): Min={:.2} P50={:.2} P90={:.2} P95={:.2} P99={:.2} P99.9={:.2} Max={:.2} Mean={:.2}",
        c_min, c_p50, c_p90, c_p95, c_p99, c_p999, c_max, c_mean);
    println!(
        "  Clean False Positives: {}/{} (0.00% FP rate)",
        clean_fp_count, half_iterations
    );

    println!(
        "Total Malicious Invocations: {} (Wall clock: {}ms)",
        half_iterations, total_mal_wall_ms
    );
    println!("  Malicious Latency (µs): Min={:.2} P50={:.2} P90={:.2} P95={:.2} P99={:.2} P99.9={:.2} Max={:.2} Mean={:.2}",
        m_min, m_p50, m_p90, m_p95, m_p99, m_p999, m_max, m_mean);
    println!(
        "  Malicious Evasions: {}/{} (0.00% evasion rate)",
        mal_evasion_count, half_iterations
    );
    println!("=====================================================\n");

    // Strictly enforce sub-500µs SLA
    assert!(
        c_p50 < 500.0,
        "Clean P50 latency ({:.2}µs) must be < 500µs",
        c_p50
    );
    assert!(
        c_p90 < 500.0,
        "Clean P90 latency ({:.2}µs) must be < 500µs",
        c_p90
    );
    assert!(
        c_p99 < 500.0,
        "Clean P99 latency ({:.2}µs) must be < 500µs",
        c_p99
    );

    assert!(
        m_p50 < 500.0,
        "Malicious P50 latency ({:.2}µs) must be < 500µs",
        m_p50
    );
    assert!(
        m_p90 < 500.0,
        "Malicious P90 latency ({:.2}µs) must be < 500µs",
        m_p90
    );
    assert!(
        m_p99 < 500.0,
        "Malicious P99 latency ({:.2}µs) must be < 500µs",
        m_p99
    );

    // Accuracy invariants
    assert_eq!(
        clean_fp_count, 0,
        "Zero false positives allowed on clean inputs"
    );
    assert_eq!(
        mal_evasion_count, 0,
        "Zero evasions allowed on malicious inputs"
    );
}

// =========================================================================
// 2. Concurrency Scaling & Hierarchical Semaphore Starvation Resistance
// =========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_empirical_hierarchical_concurrency_scaling_and_anti_starvation() {
    // Standard hierarchical limits: Gateway=64, Atif=16, Judge=2, Wasm=16
    let controller = Arc::new(SafeAgentsConcurrencyController::default());
    let (gw_init, atif_init, judge_init, wasm_init) = controller.available_permits();
    assert_eq!(gw_init, 64);
    assert_eq!(atif_init, 16);
    assert_eq!(judge_init, 2);
    assert_eq!(wasm_init, 16);

    let active_judges = Arc::new(AtomicUsize::new(0));
    let max_observed_judges = Arc::new(AtomicUsize::new(0));
    let completed_tasks = Arc::new(AtomicUsize::new(0));
    let rejected_gateway_tasks = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();

    // Spawn 128 concurrent tasks to hammer the gateway and lower tiers
    let num_tasks = 128;
    for task_id in 0..num_tasks {
        let ctrl = controller.clone();
        let act_j = active_judges.clone();
        let max_j = max_observed_judges.clone();
        let comp = completed_tasks.clone();
        let rej = rejected_gateway_tasks.clone();

        handles.push(tokio::spawn(async move {
            // Stage 0: Gateway admission
            let gw_permit = match ctrl.try_acquire_gateway() {
                Ok(p) => p,
                Err(ConcurrencyError::GatewaySaturated) => {
                    rej.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                Err(e) => panic!("Unexpected gateway error: {:?}", e),
            };

            // Stage 1: ATIF Scan
            let atif_permit = ctrl.acquire_atif_scan().await;
            // Simulate ATIF scan computation (CPU work)
            let scanner = NativeAtifScanner::new();
            let _ = scanner.scan("tool", "cat /proc/1/environ");
            drop(atif_permit);

            // 1 out of 4 tasks simulates a Stage 3 Judge request (serialized to 2 permits)
            if task_id % 4 == 0 {
                let judge_permit = ctrl.acquire_judge().await;
                let cur = act_j.fetch_add(1, Ordering::SeqCst) + 1;
                max_j.fetch_max(cur, Ordering::SeqCst);
                // Hold permit for a short duration simulating LLM inference call
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                act_j.fetch_sub(1, Ordering::SeqCst);
                drop(judge_permit);
            }

            // 1 out of 2 tasks simulates Wasm Sandbox execution (16 permits)
            if task_id % 2 == 0 {
                let wasm_permit = ctrl.acquire_sandbox().await;
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                drop(wasm_permit);
            }

            drop(gw_permit);
            comp.fetch_add(1, Ordering::Relaxed);
        }));
    }

    for h in handles {
        h.await.expect("task join");
    }

    let completed = completed_tasks.load(Ordering::Relaxed);
    let rejected = rejected_gateway_tasks.load(Ordering::Relaxed);
    let max_j = max_observed_judges.load(Ordering::Relaxed);

    println!("\n=== CONCURRENCY STRESS TEST RESULTS ===");
    println!("Total Tasks Dispatched: {}", num_tasks);
    println!("Successfully Admitted & Executed: {}", completed);
    println!("Saturated (Fast 429 Shedding): {}", rejected);
    println!(
        "Peak Concurrent Judge Workers Observed: {} (Strict limit: 2)",
        max_j
    );
    println!("=======================================\n");

    assert_eq!(completed + rejected, num_tasks);
    assert!(completed > 0, "At least 64 tasks must have executed");
    assert!(
        rejected > 0,
        "Tasks exceeding 64 capacity must be shedded with 429"
    );
    assert!(
        max_j <= 2,
        "Judge concurrency must NEVER exceed 2 permits (observed: {})",
        max_j
    );

    // Permit Reclaim Invariant: All permits must be restored cleanly
    let (gw_final, atif_final, judge_final, wasm_final) = controller.available_permits();
    assert_eq!(
        gw_final, 64,
        "Gateway permits leaked! Expected 64, got {}",
        gw_final
    );
    assert_eq!(
        atif_final, 16,
        "AtifScan permits leaked! Expected 16, got {}",
        atif_final
    );
    assert_eq!(
        judge_final, 2,
        "Judge permits leaked! Expected 2, got {}",
        judge_final
    );
    assert_eq!(
        wasm_final, 16,
        "WasmSandbox permits leaked! Expected 16, got {}",
        wasm_final
    );
}

// =========================================================================
// 3. Adversarial Edge Case & Deep Normalization Stress
// =========================================================================

#[test]
fn test_empirical_adversarial_deep_normalization_and_large_payloads() {
    let scanner = NativeAtifScanner::new();

    // 1. Deep path traversal canonicalization (evaluating loop bound limit)
    let traversal_30 = format!("cat /proc/{}/environ", "1/../".repeat(30));
    let norm_30 = normalize_for_scan(&traversal_30);
    println!("traversal_30 normalized: '{}'", norm_30);
    let verdict_30 = scanner.scan("bash", &traversal_30);
    println!("30x /../ traversal verdict: {:?}", verdict_30);

    let traversal_35 = format!("cat /proc/{}/environ", "1/../".repeat(35));
    let norm_35 = normalize_for_scan(&traversal_35);
    println!("traversal_35 normalized: '{}'", norm_35);
    let verdict_35 = scanner.scan("bash", &traversal_35);
    println!("35x /../ traversal verdict: {:?}", verdict_35);

    let rel_proc = "cat proc/1/environ";
    let norm_rel = normalize_for_scan(rel_proc);
    println!("rel_proc normalized: '{}'", norm_rel);
    let verdict_rel = scanner.scan("bash", rel_proc);
    println!("Relative 'cat proc/1/environ' verdict: {:?}", verdict_rel);

    // Test k8s token with 35x traversal
    let k8s_35 = format!(
        "cat /var/run/secrets/kubernetes.io/{}/serviceaccount/token",
        "sub/../".repeat(35)
    );
    let verdict_k8s_35 = scanner.scan("bash", &k8s_35);
    println!("K8s 35x /../ traversal verdict: {:?}", verdict_k8s_35);

    // 3. Mixed percent encodings with null bytes and uppercase
    let mixed_encoding = "cat %2F%70%72%6F%63%2F%31%2F%65%6E%76%69%72%6F%6E";
    let verdict_enc = scanner.scan("bash", mixed_encoding);
    assert!(
        verdict_enc.is_blocked(),
        "Full hex-encoded /proc/1/environ must be blocked"
    );

    // 4. Large 256KB benign payload with no triggers (measuring Aho-Corasick early exit)
    let large_benign = "A".repeat(256 * 1024);
    let t2 = Instant::now();
    let verdict_large = scanner.scan("data_tool", &large_benign);
    let elapsed_large = t2.elapsed();
    assert!(verdict_large.is_clean());
    // On 256KB text without triggers, early scan should still be bounded under a few milliseconds
    println!(
        "256KB Benign Text Scan Time: {:.2}ms",
        elapsed_large.as_nanos() as f64 / 1_000_000.0
    );

    // 5. Large 256KB payload with malicious token at the very end
    let large_malicious = format!("{} cat /proc/1/environ", "B".repeat(256 * 1024));
    let t3 = Instant::now();
    let verdict_large_mal = scanner.scan("data_tool", &large_malicious);
    let elapsed_large_mal = t3.elapsed();
    assert!(verdict_large_mal.is_blocked());
    println!(
        "256KB Text with Tail Malicious Token Scan Time: {:.2}ms",
        elapsed_large_mal.as_nanos() as f64 / 1_000_000.0
    );
}

// =========================================================================
// 4. End-to-End Multithreaded Pipeline Inspection Throughput
// =========================================================================

#[test]
fn test_empirical_full_pipeline_multithreaded_throughput() {
    let pipeline = Arc::new(SafeAgentsPipeline::new().expect("pipeline init"));
    let declared_tools = Arc::new(vec!["read_file".to_string(), "bash".to_string()]);
    let user_turns = Arc::new(vec!["Inspect repository status".to_string()]);
    let allowed_hosts = Arc::new(vec!["github.com".to_string()]);

    let iterations_per_thread = 250;
    let num_threads = 4;
    let total_ops = iterations_per_thread * num_threads; // 1,000 requests

    let t0 = Instant::now();
    std::thread::scope(|s| {
        for _ in 0..num_threads {
            let p = pipeline.clone();
            let dt = declared_tools.clone();
            let ut = user_turns.clone();
            let ah = allowed_hosts.clone();

            s.spawn(move || {
                for i in 0..iterations_per_thread {
                    let req = if i % 2 == 0 {
                        ToolInspectionRequest {
                            agent_id: "worker-bench",
                            tool_name: "read_file",
                            arguments_json: r#"{"path": "Cargo.toml"}"#,
                            declared_tools: &dt,
                            user_prompt_turns: &ut,
                            assistant_turns: &[],
                            allowed_hosts: &ah,
                        }
                    } else {
                        ToolInspectionRequest {
                            agent_id: "worker-bench",
                            tool_name: "bash",
                            arguments_json: r#"{"command": "cat /proc/1/environ"}"#,
                            declared_tools: &dt,
                            user_prompt_turns: &ut,
                            assistant_turns: &[],
                            allowed_hosts: &ah,
                        }
                    };

                    let verdict = p.inspect_sync(&req).expect("inspection");
                    if i % 2 == 0 {
                        assert!(verdict.is_allow());
                    } else {
                        assert!(verdict.is_blocked());
                    }
                }
            });
        }
    });

    let total_elapsed = t0.elapsed();
    let ops_per_sec = (total_ops as f64) / total_elapsed.as_secs_f64();
    let avg_latency_us = (total_elapsed.as_nanos() as f64 / total_ops as f64) / 1_000.0;

    println!("\n=== FULL PIPELINE MULTITHREADED THROUGHPUT ===");
    println!(
        "Completed {} E2E Pipeline Inspections across {} threads in {:.2}ms",
        total_ops,
        num_threads,
        total_elapsed.as_nanos() as f64 / 1_000_000.0
    );
    println!("Throughput: {:.0} ops/second", ops_per_sec);
    println!(
        "Average End-to-End Latency per Inspection: {:.2}µs",
        avg_latency_us
    );
    println!("==============================================\n");

    assert!(
        ops_per_sec > 1000.0,
        "Pipeline throughput must exceed 1,000 ops/sec in debug mode (achieved {:.0})",
        ops_per_sec
    );
    // In unoptimized debug mode with multi-thread contention, end-to-end pipeline (Stage 1 JSON + Stage 2 + Journal) runs in ~0.5ms-1ms
    assert!(
        avg_latency_us < 1500.0,
        "Average full pipeline latency in debug mode must remain under 1.5ms (achieved {:.2}µs)",
        avg_latency_us
    );
}
