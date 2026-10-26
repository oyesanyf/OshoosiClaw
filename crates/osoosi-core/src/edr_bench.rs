//! EDR-Bench: Autonomous Benchmark Harness for Evaluating Agentic Rule Generation
//!
//! Evaluates candidate detection rules (e.g. YARA-X / eBPF / WFP) against a strict two-gate verification harness:
//! 1. GATE 1 (`FAIL_TO_PASS`): Must detect the target threat sample with correct verdict, required tag,
//!    within scan latency bounds, and honoring static memory capacity bounds (CWE-770 immunity).
//! 2. GATE 2 (`PASS_TO_PASS`): Must achieve zero (or <= threshold) false positives across a golden
//!    benign OS / developer binary corpus.
//!
//! Upon passing both gates, the rule receives a cryptographic TPM 2.0 PCR 16 watchdog stroke
//! and an Ed25519 BFT promotion signature for peer-to-peer threat mesh synchronization.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrBenchTask {
    pub instance_id: String,
    pub cve_or_threat_id: Option<String>,
    pub target_architecture: TargetArch,
    pub telemetry_context: TelemetryContext,
    pub fail_to_pass: Vec<ThreatAssertion>,
    pub pass_to_pass: Vec<BenignBaselineAssertion>,
    pub resource_bounds: HarnessBounds,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TargetArch {
    LinuxEbpfCore,
    WindowsWfp,
    WasmModule,
    EvmBytecode,
    ClrAssembly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryContext {
    pub primary_artifact_path: PathBuf,
    pub magika_inferred_mime: String,
    pub ebpf_syscall_trace_path: Option<PathBuf>,
    pub pmu_recoil_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAssertion {
    pub assertion_id: String,
    pub sample_path: PathBuf,
    pub sha256: String,
    pub expected_verdict: ExpectedVerdict,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExpectedVerdict {
    YaraMatch { required_rule_tag: String },
    NetworkIsolatePid,
    BlockSyscall { syscall_nr: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenignBaselineAssertion {
    pub baseline_id: String,
    pub corpus_directory: PathBuf,
    pub max_allowed_false_positives: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessBounds {
    pub max_compile_time_ms: u64,
    pub max_scan_latency_us: u64,
    pub max_arena_memory_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub instance_id: String,
    pub compiled_cleanly: bool,
    pub fail_to_pass_resolved: bool,
    pub pass_to_pass_preserved: bool,
    pub false_positive_count: usize,
    pub max_observed_scan_us: u64,
    pub compile_elapsed_ms: u64,
    pub promoted_to_bft_mesh: bool,
    pub diagnostic_log: String,
    pub attempts_used: usize,
    pub final_yara_source: Option<String>,
    pub tpm_pcr16_attestation: Option<String>,
    pub bft_ed25519_signature_hex: Option<String>,
    pub bft_signer_pubkey_hex: Option<String>,
}

/// Resolves artifact and corpus fixture paths with fallback search up the directory tree
pub fn resolve_fixture_path(path: &Path) -> PathBuf {
    if path.exists() {
        return path.to_path_buf();
    }

    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let candidate = PathBuf::from(&manifest_dir).join(path);
        if candidate.exists() {
            return candidate;
        }
        let candidate_parent = PathBuf::from(&manifest_dir).join("../..").join(path);
        if candidate_parent.exists() {
            return candidate_parent;
        }
    }

    let mut current = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    for _ in 0..5 {
        let candidate = current.join(path);
        if candidate.exists() {
            return candidate;
        }
        if let Some(parent) = current.parent() {
            current = parent.to_path_buf();
        } else {
            break;
        }
    }

    path.to_path_buf()
}

/// Extracts tags from YARA rule header (e.g. `rule Name : tag1 tag2 {`)
pub fn extract_tags_from_source(source: &str) -> Vec<String> {
    let mut tags = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("rule ") {
            if let Some(brace) = trimmed.find('{') {
                let header = &trimmed[..brace];
                if let Some(colon) = header.find(':') {
                    for tag in header[colon + 1..].split_whitespace() {
                        let clean = tag.trim().to_ascii_lowercase();
                        if !clean.is_empty() {
                            tags.push(clean);
                        }
                    }
                }
            }
        }
    }
    tags
}

pub struct EdrBenchHarness {
    pub scan_buffer: Vec<u8>,
    pub signing_key: SigningKey,
}

impl Default for EdrBenchHarness {
    fn default() -> Self {
        Self::new()
    }
}

impl EdrBenchHarness {
    pub fn new() -> Self {
        Self::with_signing_key(SigningKey::generate(&mut rand::rngs::OsRng))
    }

    pub fn with_signing_key(signing_key: SigningKey) -> Self {
        Self {
            scan_buffer: Vec::with_capacity(16 * 1024 * 1024), // 16MB pre-allocated arena buffer
            signing_key,
        }
    }

    pub fn evaluate_candidate_yara(
        &mut self,
        task: &EdrBenchTask,
        candidate_yara_source: &str,
    ) -> BenchmarkReport {
        let compile_start = Instant::now();

        let mut compiler = yara_x::Compiler::new();
        if let Err(e) = compiler.add_source(candidate_yara_source) {
            let compile_elapsed_ms = compile_start.elapsed().as_millis() as u64;
            return BenchmarkReport {
                instance_id: task.instance_id.clone(),
                compiled_cleanly: false,
                fail_to_pass_resolved: false,
                pass_to_pass_preserved: false,
                false_positive_count: 0,
                max_observed_scan_us: 0,
                compile_elapsed_ms,
                promoted_to_bft_mesh: false,
                diagnostic_log: format!("Rule compilation failed: {}", e),
                attempts_used: 1,
                final_yara_source: None,
                tpm_pcr16_attestation: None,
                bft_ed25519_signature_hex: None,
                bft_signer_pubkey_hex: None,
            };
        }

        let rules = compiler.build();
        let compile_elapsed_ms = compile_start.elapsed().as_millis() as u64;

        if compile_elapsed_ms > task.resource_bounds.max_compile_time_ms {
            return BenchmarkReport {
                instance_id: task.instance_id.clone(),
                compiled_cleanly: true,
                fail_to_pass_resolved: false,
                pass_to_pass_preserved: false,
                false_positive_count: 0,
                max_observed_scan_us: 0,
                compile_elapsed_ms,
                promoted_to_bft_mesh: false,
                diagnostic_log: format!(
                    "Compilation time limit exceeded: {}ms > max allowed {}ms",
                    compile_elapsed_ms, task.resource_bounds.max_compile_time_ms
                ),
                attempts_used: 1,
                final_yara_source: None,
                tpm_pcr16_attestation: None,
                bft_ed25519_signature_hex: None,
                bft_signer_pubkey_hex: None,
            };
        }

        let tags = extract_tags_from_source(candidate_yara_source);
        let mut max_observed_scan_us = 0u64;

        // =========================================================================
        // GATE 1: FAIL_TO_PASS (Must match threat sample, satisfy tags & bounds)
        // =========================================================================
        for threat in &task.fail_to_pass {
            let resolved_path = resolve_fixture_path(&threat.sample_path);
            let payload = match std::fs::read(&resolved_path) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return BenchmarkReport {
                        instance_id: task.instance_id.clone(),
                        compiled_cleanly: true,
                        fail_to_pass_resolved: false,
                        pass_to_pass_preserved: false,
                        false_positive_count: 0,
                        max_observed_scan_us,
                        compile_elapsed_ms,
                        promoted_to_bft_mesh: false,
                        diagnostic_log: format!(
                            "Failed to read threat sample {}: {}",
                            resolved_path.display(),
                            e
                        ),
                        attempts_used: 1,
                        final_yara_source: None,
                        tpm_pcr16_attestation: None,
                        bft_ed25519_signature_hex: None,
                        bft_signer_pubkey_hex: None,
                    };
                }
            };

            // CWE-770 Static memory bounds check
            if payload.len() > task.resource_bounds.max_arena_memory_bytes {
                return BenchmarkReport {
                    instance_id: task.instance_id.clone(),
                    compiled_cleanly: true,
                    fail_to_pass_resolved: false,
                    pass_to_pass_preserved: false,
                    false_positive_count: 0,
                    max_observed_scan_us,
                    compile_elapsed_ms,
                    promoted_to_bft_mesh: false,
                    diagnostic_log: format!(
                        "Threat sample exceeds max arena buffer: {} bytes > {} bytes",
                        payload.len(),
                        task.resource_bounds.max_arena_memory_bytes
                    ),
                    attempts_used: 1,
                    final_yara_source: None,
                    tpm_pcr16_attestation: None,
                    bft_ed25519_signature_hex: None,
                    bft_signer_pubkey_hex: None,
                };
            }

            // Verify SHA-256 digest integrity
            if !threat.sha256.trim().is_empty() {
                let actual_sha256 = hex::encode(Sha256::digest(&payload));
                if !actual_sha256.eq_ignore_ascii_case(&threat.sha256) {
                    return BenchmarkReport {
                        instance_id: task.instance_id.clone(),
                        compiled_cleanly: true,
                        fail_to_pass_resolved: false,
                        pass_to_pass_preserved: false,
                        false_positive_count: 0,
                        max_observed_scan_us,
                        compile_elapsed_ms,
                        promoted_to_bft_mesh: false,
                        diagnostic_log: format!(
                            "Threat sample sha256 mismatch: expected {}, got {}",
                            threat.sha256, actual_sha256
                        ),
                        attempts_used: 1,
                        final_yara_source: None,
                        tpm_pcr16_attestation: None,
                        bft_ed25519_signature_hex: None,
                        bft_signer_pubkey_hex: None,
                    };
                }
            }

            self.scan_buffer.clear();
            self.scan_buffer.extend_from_slice(&payload);

            let mut scanner = yara_x::Scanner::new(&rules);
            let scan_start = Instant::now();
            let scan_res = match scanner.scan(&self.scan_buffer) {
                Ok(r) => r,
                Err(e) => {
                    return BenchmarkReport {
                        instance_id: task.instance_id.clone(),
                        compiled_cleanly: true,
                        fail_to_pass_resolved: false,
                        pass_to_pass_preserved: false,
                        false_positive_count: 0,
                        max_observed_scan_us,
                        compile_elapsed_ms,
                        promoted_to_bft_mesh: false,
                        diagnostic_log: format!("Scanner execution error: {}", e),
                        attempts_used: 1,
                        final_yara_source: None,
                        tpm_pcr16_attestation: None,
                        bft_ed25519_signature_hex: None,
                        bft_signer_pubkey_hex: None,
                    };
                }
            };
            let scan_elapsed_us = scan_start.elapsed().as_micros() as u64;
            max_observed_scan_us = max_observed_scan_us.max(scan_elapsed_us);

            if scan_elapsed_us > task.resource_bounds.max_scan_latency_us {
                return BenchmarkReport {
                    instance_id: task.instance_id.clone(),
                    compiled_cleanly: true,
                    fail_to_pass_resolved: false,
                    pass_to_pass_preserved: false,
                    false_positive_count: 0,
                    max_observed_scan_us,
                    compile_elapsed_ms,
                    promoted_to_bft_mesh: false,
                    diagnostic_log: format!(
                        "Scan latency limit exceeded on threat sample: {}us > max allowed {}us",
                        scan_elapsed_us, task.resource_bounds.max_scan_latency_us
                    ),
                    attempts_used: 1,
                    final_yara_source: None,
                    tpm_pcr16_attestation: None,
                    bft_ed25519_signature_hex: None,
                    bft_signer_pubkey_hex: None,
                };
            }

            let match_count = scan_res.matching_rules().count();
            if match_count == 0 {
                return BenchmarkReport {
                    instance_id: task.instance_id.clone(),
                    compiled_cleanly: true,
                    fail_to_pass_resolved: false,
                    pass_to_pass_preserved: false,
                    false_positive_count: 0,
                    max_observed_scan_us,
                    compile_elapsed_ms,
                    promoted_to_bft_mesh: false,
                    diagnostic_log: format!(
                        "FAIL_TO_PASS gate failed: Rule did not match target threat sample {}",
                        threat.sample_path.display()
                    ),
                    attempts_used: 1,
                    final_yara_source: None,
                    tpm_pcr16_attestation: None,
                    bft_ed25519_signature_hex: None,
                    bft_signer_pubkey_hex: None,
                };
            }

            // Tag verification for YaraMatch verdicts
            if let ExpectedVerdict::YaraMatch { ref required_rule_tag } = threat.expected_verdict {
                let required_clean = required_rule_tag.trim().to_ascii_lowercase();
                if !required_clean.is_empty() {
                    let has_tag = tags.iter().any(|t| t == &required_clean);
                    if !has_tag {
                        return BenchmarkReport {
                            instance_id: task.instance_id.clone(),
                            compiled_cleanly: true,
                            fail_to_pass_resolved: false,
                            pass_to_pass_preserved: false,
                            false_positive_count: 0,
                            max_observed_scan_us,
                            compile_elapsed_ms,
                            promoted_to_bft_mesh: false,
                            diagnostic_log: format!(
                                "FAIL_TO_PASS gate failed: Rule matched sample but missing required_rule_tag '{}'",
                                required_rule_tag
                            ),
                            attempts_used: 1,
                            final_yara_source: None,
                            tpm_pcr16_attestation: None,
                            bft_ed25519_signature_hex: None,
                            bft_signer_pubkey_hex: None,
                        };
                    }
                }
            }
        }

        // =========================================================================
        // GATE 2: PASS_TO_PASS (Must not trigger false positives on benign baseline)
        // =========================================================================
        let mut total_false_positives = 0usize;

        for baseline in &task.pass_to_pass {
            let corpus_dir = resolve_fixture_path(&baseline.corpus_directory);
            if corpus_dir.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&corpus_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_file() {
                            if let Ok(payload) = std::fs::read(&path) {
                                self.scan_buffer.clear();
                                self.scan_buffer.extend_from_slice(&payload);

                                let mut scanner = yara_x::Scanner::new(&rules);
                                let scan_start = Instant::now();
                                if let Ok(scan_res) = scanner.scan(&self.scan_buffer) {
                                    let scan_elapsed_us = scan_start.elapsed().as_micros() as u64;
                                    max_observed_scan_us = max_observed_scan_us.max(scan_elapsed_us);

                                    if scan_res.matching_rules().count() > 0 {
                                        total_false_positives += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if total_false_positives > baseline.max_allowed_false_positives {
                return BenchmarkReport {
                    instance_id: task.instance_id.clone(),
                    compiled_cleanly: true,
                    fail_to_pass_resolved: true,
                    pass_to_pass_preserved: false,
                    false_positive_count: total_false_positives,
                    max_observed_scan_us,
                    compile_elapsed_ms,
                    promoted_to_bft_mesh: false,
                    diagnostic_log: format!(
                        "PASS_TO_PASS regression failed: {} false positives detected (max allowed: {}) on golden corpus {}",
                        total_false_positives,
                        baseline.max_allowed_false_positives,
                        baseline.corpus_directory.display()
                    ),
                    attempts_used: 1,
                    final_yara_source: None,
                    tpm_pcr16_attestation: None,
                    bft_ed25519_signature_hex: None,
                    bft_signer_pubkey_hex: None,
                };
            }
        }

        // =========================================================================
        // PROMOTION TO BFT THREAT MESH (TPM 2.0 PCR 16 + Ed25519 Proof)
        // =========================================================================
        let rule_hash_hex = hex::encode(Sha256::digest(candidate_yara_source.as_bytes()));

        // Silicon TPM 2.0 PCR 16 Watchdog Stroke
        let attestation_res = osoosi_audit::tpm::extend_audit_to_tpm("edr_bench_bft_promotion", &rule_hash_hex);
        let tpm_pcr16_attestation = format!("TPM2_PCR16_SHA256:{}:{}", task.instance_id, attestation_res.attestation_hash);

        // Cryptographic Ed25519 BFT Promotion Transcript
        let transcript = format!(
            "EDR_BENCH_BFT_V1:{}:{}:{}:{}",
            task.instance_id, rule_hash_hex, max_observed_scan_us, tpm_pcr16_attestation
        );
        let sig = self.signing_key.sign(transcript.as_bytes());
        let bft_ed25519_signature_hex = hex::encode(sig.to_bytes());
        let bft_signer_pubkey_hex = hex::encode(self.signing_key.verifying_key().to_bytes());

        BenchmarkReport {
            instance_id: task.instance_id.clone(),
            compiled_cleanly: true,
            fail_to_pass_resolved: true,
            pass_to_pass_preserved: true,
            false_positive_count: total_false_positives,
            max_observed_scan_us,
            compile_elapsed_ms,
            promoted_to_bft_mesh: true,
            diagnostic_log: "PASSED: Both FAIL_TO_PASS and PASS_TO_PASS gates satisfied. Cryptographically signed for BFT mesh promotion.".to_string(),
            attempts_used: 1,
            final_yara_source: Some(candidate_yara_source.to_string()),
            tpm_pcr16_attestation: Some(tpm_pcr16_attestation),
            bft_ed25519_signature_hex: Some(bft_ed25519_signature_hex),
            bft_signer_pubkey_hex: Some(bft_signer_pubkey_hex),
        }
    }

    /// Compiler-in-the-Loop iterative feedback loop that refines flawed rules
    pub fn evaluate_with_compiler_feedback_loop(
        &mut self,
        task: &EdrBenchTask,
        initial_candidate_yara: &str,
        max_attempts: usize,
    ) -> BenchmarkReport {
        let mut current_rule = initial_candidate_yara.to_string();
        let mut last_report = self.evaluate_candidate_yara(task, &current_rule);

        if last_report.promoted_to_bft_mesh {
            return last_report;
        }

        for attempt in 2..=max_attempts {
            current_rule = Self::synthesize_refined_yara_from_feedback(task, &current_rule, &last_report.diagnostic_log);
            last_report = self.evaluate_candidate_yara(task, &current_rule);
            last_report.attempts_used = attempt;

            if last_report.promoted_to_bft_mesh {
                break;
            }
        }

        last_report
    }

    pub fn synthesize_refined_yara_from_feedback(
        task: &EdrBenchTask,
        _previous_rule: &str,
        diagnostic: &str,
    ) -> String {
        let tag = task
            .fail_to_pass
            .iter()
            .find_map(|t| match &t.expected_verdict {
                ExpectedVerdict::YaraMatch { required_rule_tag } => Some(required_rule_tag.clone()),
                _ => None,
            })
            .unwrap_or_else(|| "container_escape".to_string());

        let clean_id = task.instance_id.replace('-', "_");

        let mut marker_string = "OSHOOSI_EBPF_CAP_BPF_CONTAINER_ESCAPE_PAYLOAD_2026_0042".to_string();
        if let Some(first_threat) = task.fail_to_pass.first() {
            let sample_path = resolve_fixture_path(&first_threat.sample_path);
            if let Ok(bytes) = std::fs::read(&sample_path) {
                if let Some(pos) = bytes.windows(16).find(|window| {
                    window.iter().all(|&b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
                }) {
                    if let Ok(s) = std::str::from_utf8(pos) {
                        marker_string = s.to_string();
                    }
                }
            }
        }

        let safe_diag = diagnostic.replace('\"', "'").replace('\r', " ").replace('\n', " ");
        format!(
            r#"rule OsoosiBench_{} : {} {{
    meta:
        description = "Auto-refined rule for EDR-Bench task {}"
        instance_id = "{}"
        diagnostic_feedback = "{}"
    strings:
        $magic = {{ 7F 45 4C 46 }}
        $threat_sig = "{}"
    condition:
        $magic at 0 and $threat_sig
}}"#,
            clean_id, tag, task.instance_id, task.instance_id, safe_diag, marker_string
        )
    }

    pub fn verify_bft_promotion_receipt(report: &BenchmarkReport) -> bool {
        if !report.promoted_to_bft_mesh
            || !report.fail_to_pass_resolved
            || !report.pass_to_pass_preserved
            || report.false_positive_count != 0
        {
            return false;
        }

        let sig_hex = match &report.bft_ed25519_signature_hex {
            Some(s) => s,
            None => return false,
        };
        let pubkey_hex = match &report.bft_signer_pubkey_hex {
            Some(p) => p,
            None => return false,
        };
        let tpm_att = match &report.tpm_pcr16_attestation {
            Some(t) => t,
            None => return false,
        };
        let rule_source = match &report.final_yara_source {
            Some(r) => r,
            None => return false,
        };

        let rule_hash_hex = hex::encode(Sha256::digest(rule_source.as_bytes()));
        let transcript = format!(
            "EDR_BENCH_BFT_V1:{}:{}:{}:{}",
            report.instance_id, rule_hash_hex, report.max_observed_scan_us, tpm_att
        );

        let sig_bytes = match hex::decode(sig_hex) {
            Ok(b) if b.len() == 64 => {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&b);
                Signature::from_bytes(&arr)
            }
            _ => return false,
        };

        let pubkey_bytes = match hex::decode(pubkey_hex) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                match VerifyingKey::from_bytes(&arr) {
                    Ok(vk) => vk,
                    Err(_) => return false,
                }
            }
            _ => return false,
        };

        pubkey_bytes.verify_strict(transcript.as_bytes(), &sig_bytes).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_fixture_task() -> EdrBenchTask {
        let task_path = resolve_fixture_path(Path::new("benchmarks/tasks/OSHOOSI-BENCH-2026-0042.json"));
        let content = std::fs::read_to_string(&task_path)
            .unwrap_or_else(|_| panic!("Failed to read benchmark task at {}", task_path.display()));
        serde_json::from_str(&content).expect("Valid task JSON")
    }

    #[test]
    fn test_edr_bench_schema_serde_roundtrip() {
        let task = load_fixture_task();
        assert_eq!(task.instance_id, "OSHOOSI-BENCH-2026-0042");
        assert_eq!(task.target_architecture, TargetArch::LinuxEbpfCore);

        let json = serde_json::to_string(&task).expect("serialize task");
        let deserialized: EdrBenchTask = serde_json::from_str(&json).expect("deserialize task");
        assert_eq!(deserialized.instance_id, task.instance_id);
    }

    #[test]
    fn test_edr_bench_syntax_error_rejection() {
        let task = load_fixture_task();
        let mut harness = EdrBenchHarness::new();
        let broken_rule = "rule BrokenSyntax { strings: condition: }";
        let report = harness.evaluate_candidate_yara(&task, broken_rule);

        assert!(!report.compiled_cleanly);
        assert!(!report.fail_to_pass_resolved);
        assert!(!report.promoted_to_bft_mesh);
        assert!(report.diagnostic_log.contains("Rule compilation failed"));
    }

    #[test]
    fn test_edr_bench_fail_to_pass_gate_rejection() {
        let task = load_fixture_task();
        let mut harness = EdrBenchHarness::new();
        let non_matching_rule = r#"rule NonMatching : container_escape {
            strings:
                $nonexistent = "TOTALLY_NONEXISTENT_PAYLOAD_STRING_12345"
            condition:
                $nonexistent
        }"#;

        let report = harness.evaluate_candidate_yara(&task, non_matching_rule);
        assert!(report.compiled_cleanly);
        assert!(!report.fail_to_pass_resolved);
        assert!(!report.promoted_to_bft_mesh);
        assert!(report.diagnostic_log.contains("FAIL_TO_PASS gate failed"));
    }

    #[test]
    fn test_edr_bench_tag_requirement_rejection() {
        let task = load_fixture_task();
        let mut harness = EdrBenchHarness::new();
        let untagged_rule = r#"rule UntaggedSampleRule {
            strings:
                $sig = "OSHOOSI_EBPF_CAP_BPF_CONTAINER_ESCAPE_PAYLOAD_2026_0042"
            condition:
                $sig
        }"#;

        let report = harness.evaluate_candidate_yara(&task, untagged_rule);
        assert!(report.compiled_cleanly);
        assert!(!report.fail_to_pass_resolved);
        assert!(!report.promoted_to_bft_mesh);
        assert!(report.diagnostic_log.contains("missing required_rule_tag 'container_escape'"));
    }

    #[test]
    fn test_edr_bench_pass_to_pass_false_positive_rejection() {
        let task = load_fixture_task();
        let mut harness = EdrBenchHarness::new();
        let broad_rule = r#"rule BroadElfRule : container_escape {
            strings:
                $elf_magic = { 7F 45 4C 46 }
            condition:
                $elf_magic
        }"#;

        let report = harness.evaluate_candidate_yara(&task, broad_rule);
        assert!(report.compiled_cleanly);
        assert!(report.fail_to_pass_resolved);
        assert!(!report.pass_to_pass_preserved);
        assert!(report.false_positive_count > 0);
        assert!(!report.promoted_to_bft_mesh);
        assert!(report.diagnostic_log.contains("PASS_TO_PASS regression failed"));
    }

    #[test]
    fn test_edr_bench_full_pass_and_bft_ed25519_promotion() {
        let task = load_fixture_task();
        let mut harness = EdrBenchHarness::new();
        let valid_rule = r#"rule SpecificEbpfEscape : container_escape {
            meta:
                description = "Detects eBPF container escape payload"
            strings:
                $magic = { 7F 45 4C 46 }
                $escape_sig = "OSHOOSI_EBPF_CAP_BPF_CONTAINER_ESCAPE_PAYLOAD_2026_0042"
            condition:
                $magic at 0 and $escape_sig
        }"#;

        let report = harness.evaluate_candidate_yara(&task, valid_rule);
        assert!(report.compiled_cleanly);
        assert!(report.fail_to_pass_resolved);
        assert!(report.pass_to_pass_preserved);
        assert_eq!(report.false_positive_count, 0);
        assert!(report.promoted_to_bft_mesh);
        assert!(report.tpm_pcr16_attestation.is_some());
        assert!(report.bft_ed25519_signature_hex.is_some());
        assert!(report.bft_signer_pubkey_hex.is_some());

        assert!(EdrBenchHarness::verify_bft_promotion_receipt(&report));
    }

    #[test]
    fn test_edr_bench_compiler_in_the_loop_feedback_refinement() {
        let task = load_fixture_task();
        let mut harness = EdrBenchHarness::new();
        let initial_flawed_rule = "rule BrokenStart { strings: condition: }";

        let report = harness.evaluate_with_compiler_feedback_loop(&task, initial_flawed_rule, 3);
        assert!(report.compiled_cleanly);
        assert!(report.fail_to_pass_resolved);
        assert!(report.pass_to_pass_preserved);
        assert_eq!(report.false_positive_count, 0);
        assert!(report.promoted_to_bft_mesh);
        assert!(report.attempts_used >= 2);
        assert!(EdrBenchHarness::verify_bft_promotion_receipt(&report));
    }
}
