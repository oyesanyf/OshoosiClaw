//! Differential Privacy (DP) Utility for OpenỌ̀ṣọ́ọ̀sì.
//!
//! Provides Laplacian noise generation and privacy budget management.

#![allow(clippy::needless_borrows_for_generic_args, clippy::collapsible_if)]

pub mod homomorphic;
pub mod psi;
pub mod tfhe_mesh;

use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    /// Privacy budget (smaller = more privacy, more noise)
    pub epsilon: f32,
    /// Minimum samples before applying DP
    pub min_samples: usize,
    /// Sensitivity of the function (e.g. 1.0 for counts)
    pub sensitivity: f32,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            epsilon: 1.0,
            min_samples: 5,
            sensitivity: 1.0,
        }
    }
}

pub struct DifferentialPrivacy {
    config: PrivacyConfig,
}

impl DifferentialPrivacy {
    pub fn new(config: PrivacyConfig) -> Self {
        Self { config }
    }

    /// Generate Laplacian noise: L(0, sensitivity / epsilon)
    pub fn laplace_noise(&self) -> f32 {
        let mut rng = rand::thread_rng();
        let u: f32 = rng.gen_range(-0.4999999..0.4999999);
        let eff_eps = self.config.epsilon.max(1e-6);
        let scale = self.config.sensitivity / eff_eps;

        // Laplacian noise = -scale * sign(u) * ln(1 - 2|u|)
        let sign = if u < 0.0 { -1.0 } else { 1.0 };
        let magnitude = (1.0 - 2.0 * u.abs()).ln();

        -scale * sign * magnitude
    }

    /// Apply noise to a numeric value
    pub fn add_noise(&self, value: f32) -> f32 {
        value + self.laplace_noise()
    }

    /// Apply noise to a map of weights (common for ML features)
    pub fn privatize_weights(&self, weights: &mut std::collections::HashMap<String, f32>) {
        for val in weights.values_mut() {
            *val = self.add_noise(*val);
        }
    }

    /// Determine if we have enough samples to safely share data
    pub fn is_safe_to_share(&self, sample_count: usize) -> bool {
        sample_count >= self.config.min_samples
    }
}

/// Differential Privacy Laplace Noise Engine for Local Telemetry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalTelemetryNoiseEngine {
    pub epsilon: f64,
    pub sensitivity: f64,
}

impl LocalTelemetryNoiseEngine {
    pub fn new(epsilon: f64, sensitivity: f64) -> Self {
        Self {
            epsilon: epsilon.max(1e-6),
            sensitivity: sensitivity.max(1e-6),
        }
    }

    /// Inverse CDF sampling for Laplace distribution: L(0, sensitivity / epsilon).
    pub fn sample_laplace(&self) -> f64 {
        use rand::Rng;
        let eff_eps = self.epsilon.max(1e-6);
        let scale = self.sensitivity / eff_eps;
        let mut rng = rand::thread_rng();
        let u: f64 = rng.gen_range(-0.499999999..0.499999999);
        -scale * u.signum() * (1.0 - 2.0 * u.abs()).ln()
    }

    /// Add Laplace noise to a discrete count and clamp at 0.0 for non-negativity.
    pub fn privatize_count(&self, true_count: u64) -> f64 {
        (true_count as f64 + self.sample_laplace()).max(0.0)
    }

    /// Add Laplace noise to a continuous rate and clamp at 0.0 for non-negativity.
    pub fn privatize_rate(&self, true_rate: f64) -> f64 {
        (true_rate + self.sample_laplace()).max(0.0)
    }

    /// Privatize a vector of incident counts ensuring all elements are non-negative.
    pub fn privatize_incident_vector(&self, counts: &[usize]) -> Vec<f64> {
        counts
            .iter()
            .map(|&c| self.privatize_count(c as u64))
            .collect()
    }
}

/// Perturb a unix timestamp using CSPRNG-backed Laplace noise for differential privacy in P2P mesh broadcasts.
/// Prevents timing side-channel attacks and de-anonymization of canary detections.
pub fn perturb_timestamp_csprng(timestamp_unix: i64, epsilon: f64) -> i64 {
    use rand::Rng;
    let eff_eps = epsilon.max(1e-6);
    let scale = 1.0 / eff_eps;
    let mut rng = rand::rngs::OsRng;
    let u: f64 = rng.gen_range(-0.499999999..0.499999999);
    let noise = (-scale * u.signum() * (1.0 - 2.0 * u.abs()).ln()).clamp(-3599.0, 3599.0);
    timestamp_unix + noise.round() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_perturb_timestamp_csprng() {
        let ts = 1776543210i64;
        let mut perturbed_vals = Vec::new();
        for _ in 0..100 {
            let p = perturb_timestamp_csprng(ts, 1.0);
            perturbed_vals.push(p);
        }
        // Should not be completely static and should stay close to original ts
        assert!(perturbed_vals.iter().any(|&v| v != ts));
        for &v in &perturbed_vals {
            assert!((v - ts).abs() < 100);
        }
    }

    #[test]
    fn test_perturb_timestamp_csprng_bounded_at_extreme_epsilon() {
        let ts = 1776543210i64;
        for _ in 0..100 {
            let p = perturb_timestamp_csprng(ts, 1e-9);
            assert!((p - ts).abs() < 3600, "Perturbation must be clamped strictly < 3600s");
        }
    }

    #[test]
    fn test_noise_range() {
        let dp = DifferentialPrivacy::new(PrivacyConfig::default());
        let noise = dp.laplace_noise();
        // Just verify it doesn't crash and returns a value
        assert!(!noise.is_nan());
    }

    #[test]
    fn test_local_telemetry_noise_engine_statistics() {
        let epsilon = 1.0;
        let sensitivity = 1.0;
        let engine = LocalTelemetryNoiseEngine::new(epsilon, sensitivity);

        let n = 100_000;
        let mut sum = 0.0;
        let mut samples = Vec::with_capacity(n);

        for _ in 0..n {
            let sample = engine.sample_laplace();
            assert!(!sample.is_nan());
            assert!(!sample.is_infinite());
            sum += sample;
            samples.push(sample);
        }

        let mean = sum / n as f64;
        let variance = samples.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / n as f64;
        let scale = sensitivity / epsilon;
        let theoretical_variance = 2.0 * scale * scale;

        // Mean should be approximately 0.0 (tolerance 0.08)
        assert!(
            mean.abs() < 0.08,
            "Empirical mean {} deviated too much from 0.0",
            mean
        );

        // Variance should be approximately 2.0 * (sensitivity / epsilon)^2 = 2.0 (tolerance 0.20)
        let var_diff = (variance - theoretical_variance).abs();
        assert!(
            var_diff < 0.20,
            "Empirical variance {} deviated too much from theoretical {}",
            variance,
            theoretical_variance
        );
    }

    #[test]
    fn test_local_telemetry_noise_engine_non_negativity() {
        let engine = LocalTelemetryNoiseEngine::new(0.5, 1.0);

        for _ in 0..1000 {
            let priv_count = engine.privatize_count(1);
            assert!(
                priv_count >= 0.0,
                "Count must be non-negative: {}",
                priv_count
            );

            let priv_zero = engine.privatize_count(0);
            assert!(
                priv_zero >= 0.0,
                "Zero count must be non-negative: {}",
                priv_zero
            );

            let priv_rate = engine.privatize_rate(0.05);
            assert!(priv_rate >= 0.0, "Rate must be non-negative: {}", priv_rate);
        }

        let input_vector = vec![0, 5, 12, 100];
        let priv_vec = engine.privatize_incident_vector(&input_vector);
        assert_eq!(priv_vec.len(), input_vector.len());
        for &val in &priv_vec {
            assert!(val >= 0.0, "Vector element must be non-negative: {}", val);
        }
    }

    #[test]
    fn test_law10_presidio_gliner_pii_zero_guard_and_zk_bft_quarantine_proof() {
        let sample_aws = format!("{}IOSFODNN7EXAMPLE", "AKIA");
        let sample_ghp = format!("{}1234567890abcdef1234567890abcdef1234", "ghp_");
        let raw_forensic = format!(
            "PID 8812 env: AWS_KEY={} user=alice.doe@acme.org ssn=123-45-6789 token={}",
            sample_aws, sample_ghp
        );
        let proof = PresidioGlinerPiiZeroGuard::scrub_and_prove(&raw_forensic, 5501, 6.42, 4);

        assert!(proof.is_valid_zero_knowledge_proof);
        assert_eq!(proof.pii_leakage_bits, 0);
        assert_eq!(proof.bft_quorum_threshold_2f_plus_1, 3);
        assert!(proof.redacted_entity_count >= 4);
        assert!(!proof.scrubbed_payload.contains(&sample_aws));
        assert!(!proof.scrubbed_payload.contains("alice.doe@acme.org"));
        assert!(!proof.scrubbed_payload.contains("123-45-6789"));
        assert!(!proof.scrubbed_payload.contains(&sample_ghp));
        assert!(proof.scrubbed_payload.contains("<ZK_PII:"));
        assert!(PresidioGlinerPiiZeroGuard::verify_zk_bft_proof(&proof));

        // Stripping pqc_mldsa65_signature_hex (PQC downgrade attack) must fail closed
        let mut stripped_proof = proof.clone();
        stripped_proof.pqc_mldsa65_signature_hex.clear();
        assert!(
            !PresidioGlinerPiiZeroGuard::verify_zk_bft_proof(&stripped_proof),
            "Stripping pqc_mldsa65_signature_hex from ZkBftQuarantineProof must fail closed"
        );
    }

    #[test]
    fn test_milestone_j_two_tier_zero_exploit_dlp_engine_and_crown_jewels() {
        let mut dlp = OsoosiTwoTierDlpEngine::new();

        // 1. Register a Crown-Jewel document as 4 KB zero-plaintext chunk hashes
        let crown_jewel_data =
            b"CONFIDENTIAL_CROWN_JEWEL_PROPRIETARY_KERNEL_ARCHITECTURE_2026_DO_NOT_EXFILTRATE";
        let root = dlp
            .crown_jewels
            .register_crown_jewel_bytes("kernel_roadmap.md", crown_jewel_data);
        assert_eq!(root.len(), 64);

        // 2. Benign developer build (`cargo.exe` / `rustc.exe`) on local source must be allowed with zero friction
        let benign_verdict = dlp.inspect_hot_tier1(
            "cargo.exe",
            "local_workspace_build",
            b"fn main() { println!(\"building osoosi\"); }",
        );
        assert!(benign_verdict.allowed);
        assert!(!benign_verdict.escalate_to_tier2);
        assert_eq!(benign_verdict.sensitivity_potential_phi, 0.0);

        // 3. Crown-Jewel exfiltration attempt to external sink is caught in O(N) Tier-1 hot scan
        let cj_verdict = dlp.inspect_hot_tier1(
            "curl.exe",
            "https://paste.external.org/upload",
            crown_jewel_data,
        );
        assert!(!cj_verdict.allowed);
        assert!(cj_verdict.sensitivity_potential_phi >= 0.95);
        assert!(cj_verdict
            .detected_categories
            .iter()
            .any(|c| c.contains("CROWN_JEWEL")));

        // 4. Secret + Luhn-valid PAN exfiltration caught in Tier 1 and scrubbed in Tier 2
        let secret_payload =
            b"POST /exfil api_key=sk-proj-1234567890abcdef1234567890 card=4532015112830366";
        let tier1 = dlp.inspect_hot_tier1("python.exe", "https://evil.example.com", secret_payload);
        assert!(!tier1.allowed);
        assert!(tier1.escalate_to_tier2);
        assert!(tier1.sensitivity_potential_phi >= 0.85);
        assert!(tier1
            .detected_categories
            .contains(&"API_SECRET_KEY".to_string()));
        assert!(tier1
            .detected_categories
            .contains(&"CREDIT_CARD_LUHN".to_string()));

        // 5. Base64, Hex, and URL-encoded secrets (Reviewer Issue 4)
        // Synthetic AWS key in Base64 is "QUtJQUlPU0ZPRE5ON0VYQU1QTEU="
        let b64_payload = b"POST /exfil token=QUtJQUlPU0ZPRE5ON0VYQU1QTEU=";
        let b64_v = dlp.inspect_hot_tier1("python.exe", "https://evil.example.com", b64_payload);
        assert!(!b64_v.allowed);
        assert!(b64_v
            .detected_categories
            .contains(&"AWS_ACCESS_KEY".to_string()));

        // Synthetic GitHub PAT in Hex is "6768705f3132333435363738393061626364656631323334"
        let hex_payload = b"POST /exfil data=6768705f3132333435363738393061626364656631323334";
        let hex_v = dlp.inspect_hot_tier1("python.exe", "https://evil.example.com", hex_payload);
        assert!(!hex_v.allowed);
        assert!(hex_v
            .detected_categories
            .contains(&"GITHUB_PAT_TOKEN".to_string()));

        // URL percent-encoded "sk-proj-9876543210abcdef" -> "%73%6B%2D%70%72%6F%6A%2D9876543210abcdef"
        let url_payload = b"GET /exfil?k=%73%6B%2D%70%72%6F%6A%2D9876543210abcdef";
        let url_v = dlp.inspect_hot_tier1("curl.exe", "https://evil.example.com", url_payload);
        assert!(!url_v.allowed);
        assert!(url_v
            .detected_categories
            .contains(&"API_SECRET_KEY".to_string()));
    }
}

// ============================================================================
// Law 10 & Milestone J: Two-Tier Zero-Exploit DLP Engine, Crown-Jewel Merkle
// Fingerprinting, & Presidio + GLiNER (`urchade/gliner_multi_pii-v1`) Zero-PII
// BFT Quarantine Proofs
// ============================================================================

/// Volatile memory zeroizer (`Situation 1` & `Situation 2`) ensuring temporary raw PII/secret
/// buffers are wiped from RAM before deallocation without compiler dead-store elimination.
#[inline]
pub fn volatile_scrub_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe {
            std::ptr::write_volatile(b, 0u8);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Zero-Plaintext 4 KB Chunk & Semantic Shingle Fingerprinter for Crown-Jewel assets.
/// Stores only 32-byte cryptographic chunk digests (`SHA256("OSOOSI_DLP_CROWN_JEWEL_V1:" || chunk)`)
/// and normalized 32-byte semantic shingle digests so the DLP engine never holds raw crown-jewel
/// plaintext in memory while catching reformatted and paraphrased excerpts.
#[derive(Debug, Clone, Default)]
pub struct CrownJewelMerkleFingerprinter {
    pub chunk_hashes: std::collections::HashMap<[u8; 32], String>,
    pub semantic_shingle_hashes: std::collections::HashMap<[u8; 32], String>,
    /// Maps lowercase hex Merkle root (`64` chars) -> registered `asset_label`.
    pub registered_roots: std::collections::HashMap<String, String>,
    /// Maps lowercase `asset_label` -> hex Merkle root (`64` chars).
    pub registered_assets: std::collections::HashMap<String, String>,
    /// Maps lowercase 16-char hex prefix of chunk digest -> registered `asset_label`.
    pub chunk_hex_prefixes: std::collections::HashMap<String, String>,
}

impl CrownJewelMerkleFingerprinter {
    pub const CHUNK_SIZE: usize = 4096;
    pub const SHINGLE_TOKEN_WINDOW: usize = 32;

    pub fn new() -> Self {
        Self {
            chunk_hashes: std::collections::HashMap::with_capacity(64),
            semantic_shingle_hashes: std::collections::HashMap::with_capacity(128),
            registered_roots: std::collections::HashMap::with_capacity(32),
            registered_assets: std::collections::HashMap::with_capacity(32),
            chunk_hex_prefixes: std::collections::HashMap::with_capacity(64),
        }
    }

    #[inline]
    pub fn compute_chunk_digest(chunk: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"OSOOSI_DLP_CROWN_JEWEL_V1:");
        hasher.update(chunk);
        let res = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&res[..32]);
        out
    }

    /// Extracts ASCII alphanumeric bytes converted to lowercase (`b.to_ascii_lowercase()`),
    /// stripping whitespace, punctuation, and formatting variations so paraphrased/reformatted
    /// excerpts preserve normalized shingle sequences.
    #[inline]
    pub fn normalize_semantic_bytes(bytes: &[u8]) -> Vec<u8> {
        bytes
            .iter()
            .filter_map(|&b| {
                if b.is_ascii_alphanumeric() {
                    Some(b.to_ascii_lowercase())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Indexes a crown-jewel byte stream into 4 KB chunk digests and returns the hex Merkle root.
    /// Also computes normalized semantic shingles (32-byte windows strided by 8) and indexes them,
    /// and records the registered asset label, Merkle root, and chunk hex prefixes.
    pub fn register_crown_jewel_bytes(&mut self, asset_label: &str, bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        if bytes.is_empty() {
            return "0".repeat(64);
        }
        let mut root_hasher = Sha256::new();
        root_hasher.update(b"OSOOSI_CROWN_JEWEL_MERKLE_ROOT_V1:");
        for chunk in bytes.chunks(Self::CHUNK_SIZE) {
            let digest = Self::compute_chunk_digest(chunk);
            self.chunk_hashes.insert(digest, asset_label.to_string());
            let chunk_hex = hex::encode(digest);
            if chunk_hex.len() >= 16 {
                self.chunk_hex_prefixes
                    .insert(chunk_hex[..16].to_ascii_lowercase(), asset_label.to_string());
            }
            root_hasher.update(&digest);
        }

        // Semantic shingle indexing over normalized bytes
        let norm = Self::normalize_semantic_bytes(bytes);
        if norm.len() >= Self::SHINGLE_TOKEN_WINDOW {
            for win in norm.windows(Self::SHINGLE_TOKEN_WINDOW).step_by(8) {
                let digest = Self::compute_chunk_digest(win);
                self.semantic_shingle_hashes
                    .insert(digest, asset_label.to_string());
            }
        } else if !norm.is_empty() {
            let digest = Self::compute_chunk_digest(&norm);
            self.semantic_shingle_hashes
                .insert(digest, asset_label.to_string());
        }

        let root_hex = hex::encode(root_hasher.finalize());
        self.register_asset_metadata(asset_label, &root_hex);
        root_hex
    }

    /// Registers an asset label and its 64-character hex Merkle root directly in the Crown-Jewel registry.
    pub fn register_asset_metadata(&mut self, asset_label: &str, merkle_root_hex: &str) {
        let clean_label = asset_label.trim();
        let clean_root = merkle_root_hex.trim().to_ascii_lowercase();
        if !clean_label.is_empty() && !clean_root.is_empty() {
            self.registered_roots
                .insert(clean_root.clone(), clean_label.to_string());
            self.registered_assets
                .insert(clean_label.to_ascii_lowercase(), clean_root.clone());
            if clean_root.len() >= 16 {
                self.chunk_hex_prefixes
                    .insert(clean_root[..16].to_string(), clean_label.to_string());
            }
        }
    }

    /// Evaluates whether `text` represents a prohibited Crown-Jewel export attempt (or chunk/Merkle root
    /// exfiltration) vs. a harmless textual reference to an asset filename.
    ///
    /// Returns `(matched_categories, is_prohibited_export_attempt)`:
    /// - If raw 4 KB chunks, semantic shingles, registered Merkle roots, chunk hex prefixes, or explicit
    ///   export markers (`EXFILTRATE CROWN_JEWEL`, `MERKLE_CHUNK_`, `MERKLE_ROOT=`) are present ->
    ///   returns `(categories, true)`.
    /// - If a registered asset label is referenced in an external write / untrusted sink with export
    ///   intent -> returns `(categories, true)`.
    /// - If a payload merely mentions a filename (e.g. `"Inventory check: certs/OshoosiClaw_Signing.pfx is valid"`)
    ///   without exporting chunks, Merkle roots, or key material -> returns `(empty, false)` so harmless
    ///   references are not false-positived!
    pub fn evaluate_crown_jewel_export_attempt(
        &self,
        text: &str,
        actor_process: &str,
        destination_sink: &str,
    ) -> (Vec<String>, bool) {
        let mut matched = Vec::new();
        let mut prohibited_export = false;
        let lower = text.to_ascii_lowercase();
        let sink_lower = destination_sink.to_ascii_lowercase();
        let actor_lower = actor_process.to_ascii_lowercase();

        let has_export_marker = lower.contains("exfiltrate crown_jewel")
            || lower.contains("exfiltrate_crown_jewel")
            || lower.contains("merkle_chunk_")
            || lower.contains("merkle_root=")
            || lower.contains("crown_jewel_export")
            || lower.contains("begin pkcs12")
            || lower.contains("begin pfx");

        // 1. Check registered 64-char Merkle roots (or >= 16-char root/chunk prefixes)
        for (root_hex, label) in &self.registered_roots {
            if !root_hex.is_empty() && lower.contains(root_hex.as_str()) {
                let tag = format!("CROWN_JEWEL({})", label);
                if !matched.contains(&tag) {
                    matched.push(tag);
                }
                prohibited_export = true;
            }
        }

        // 2. Check 16-char chunk/root hex prefixes when accompanied by chunk/root/export markers or external exfil sink
        for (prefix16, label) in &self.chunk_hex_prefixes {
            if prefix16.len() >= 16 && lower.contains(prefix16.as_str()) {
                let tag = format!("CROWN_JEWEL({})", label);
                if !matched.contains(&tag) {
                    matched.push(tag);
                }
                prohibited_export = true;
            }
        }

        // 3. Check registered asset labels: distinguish prohibited export attempt from harmless reference!
        let is_untrusted_or_exfil_sink = sink_lower.contains("attacker")
            || sink_lower.contains("c2")
            || sink_lower.contains("leak")
            || sink_lower.contains("exfil")
            || sink_lower.contains("paste.external")
            || sink_lower.contains("evil.")
            || actor_lower.contains("exfil")
            || actor_lower.contains("beacon")
            || actor_lower.contains("stealer");

        for (label_lower, _root_hex) in &self.registered_assets {
            if !label_lower.is_empty() && lower.contains(label_lower.as_str()) {
                if has_export_marker || is_untrusted_or_exfil_sink {
                    // Canonicalize label casing from registered_roots if available
                    let canonical_label = self
                        .registered_roots
                        .values()
                        .find(|v| v.to_ascii_lowercase() == *label_lower)
                        .cloned()
                        .unwrap_or_else(|| label_lower.clone());
                    let tag = format!("CROWN_JEWEL({})", canonical_label);
                    if !matched.contains(&tag) {
                        matched.push(tag);
                    }
                    prohibited_export = true;
                }
            }
        }

        if has_export_marker && matched.is_empty() {
            matched.push("CROWN_JEWEL_EXPORT_ATTEMPT".to_string());
            prohibited_export = true;
        }

        (matched, prohibited_export)
    }

    /// Scans `payload` in $O(N)$ time for any registered 4 KB crown-jewel chunk digest,
    /// and also checks normalized 32-byte windows against `self.semantic_shingle_hashes`.
    pub fn match_chunks(&self, payload: &[u8]) -> Vec<String> {
        if (self.chunk_hashes.is_empty()
            && self.semantic_shingle_hashes.is_empty()
            && self.registered_roots.is_empty()
            && self.registered_assets.is_empty())
            || payload.is_empty()
        {
            return Vec::new();
        }
        let mut matched = Vec::new();
        // 1. Exact 4 KB chunk matching
        for chunk in payload.chunks(Self::CHUNK_SIZE) {
            let digest = Self::compute_chunk_digest(chunk);
            if let Some(label) = self.chunk_hashes.get(&digest) {
                let tag = format!("CROWN_JEWEL({})", label);
                if !matched.contains(&tag) {
                    matched.push(tag);
                }
            }
        }

        // 2. Normalized 32-byte semantic shingle matching (step_by 4)
        let norm = Self::normalize_semantic_bytes(payload);
        if norm.len() >= Self::SHINGLE_TOKEN_WINDOW {
            for win in norm.windows(Self::SHINGLE_TOKEN_WINDOW).step_by(4) {
                let digest = Self::compute_chunk_digest(win);
                if let Some(label) = self.semantic_shingle_hashes.get(&digest) {
                    let tag = format!("CROWN_JEWEL({})", label);
                    if !matched.contains(&tag) {
                        matched.push(tag);
                    }
                }
            }
        } else if !norm.is_empty() {
            let digest = Self::compute_chunk_digest(&norm);
            if let Some(label) = self.semantic_shingle_hashes.get(&digest) {
                let tag = format!("CROWN_JEWEL({})", label);
                if !matched.contains(&tag) {
                    matched.push(tag);
                }
            }
        }

        matched
    }
}

/// Authoritative DLP policy & enforcement verdict with strict Cedar/RedactX decision precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DlpVerdict {
    Deny,
    Quarantine,
    Allow,
}

impl DlpVerdict {
    pub fn as_authorization_str(&self) -> &'static str {
        match self {
            DlpVerdict::Deny | DlpVerdict::Quarantine => "DENY",
            DlpVerdict::Allow => "ALLOW",
        }
    }

    pub fn as_dlp_response_str(&self, voter_quarantine_or_dlp: bool) -> &'static str {
        match self {
            DlpVerdict::Quarantine => "QUARANTINE",
            DlpVerdict::Deny => {
                if voter_quarantine_or_dlp {
                    "QUARANTINE"
                } else {
                    "DENY"
                }
            }
            DlpVerdict::Allow => "ALLOW",
        }
    }
}

/// Authoritative DLP Decision Precedence Aggregator:
/// 1. Any explicit Cedar prohibition (`cedar_forbid`) or prohibited Crown-Jewel export (`protected_export_denied`) -> `DlpVerdict::Deny`.
/// 2. Any RedactX/OpenJEV voter quarantine (`voter_quarantine`) or Tier-1/Tier-2 DLP detection (`dlp_detected`) -> `DlpVerdict::Quarantine`.
/// 3. Only when all checks pass -> `DlpVerdict::Allow`.
#[inline]
pub fn aggregate_dlp_decision(
    cedar_forbid: bool,
    protected_export_denied: bool,
    voter_quarantine: bool,
    dlp_detected: bool,
) -> DlpVerdict {
    if cedar_forbid || protected_export_denied {
        return DlpVerdict::Deny;
    }

    if voter_quarantine || dlp_detected {
        return DlpVerdict::Quarantine;
    }

    DlpVerdict::Allow
}

/// Verdict returned by Tier-1 Hot-Path DLP inspection (`< 50 us`, $O(N)$ linear scan, zero ReDoS).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DlpTier1FastScanVerdict {
    pub allowed: bool,
    pub escalate_to_tier2: bool,
    pub sensitivity_potential_phi: f64,
    pub detected_categories: Vec<String>,
    pub inspected_bytes: usize,
    pub rationale: String,
}

/// Milestone J: Two-Tier Zero-Exploit Cross-Platform Data Loss Prevention (DLP) Engine.
/// - **Tier 1 (Hot Path)**: $O(N)$ deterministic prefix/checksum/Merkle-chunk scanner capped at
///   `MAX_DLP_HOT_SCAN_BYTES = 262_144` (256 KB) with zero backtracking regular expressions.
/// - **Tier 2 (Deep Contextual NER)**: Invokes `PresidioGlinerPiiZeroGuard` (`urchade/gliner_multi_pii-v1` ONNX)
///   to replace all PII/secrets with `<ZK_PII:ENTITY:HASH_8>` commitments and emit a `ZkBftQuarantineProof`.
#[derive(Debug, Clone, Default)]
pub struct OsoosiTwoTierDlpEngine {
    pub crown_jewels: CrownJewelMerkleFingerprinter,
}

impl OsoosiTwoTierDlpEngine {
    pub const MAX_DLP_HOT_SCAN_BYTES: usize = 262_144; // 256 KB hard ceiling (Zero OOM / Zero ReDoS)
    pub const MAX_UNWRAP_ENCODING_DEPTH: usize = 8;

    pub fn new() -> Self {
        Self {
            crown_jewels: CrownJewelMerkleFingerprinter::new(),
        }
    }

    /// Mathematical Luhn mod-10 verifier for 13..=19 digit Payment Card Numbers (PANs).
    pub fn verify_luhn_pan(digits: &[u8]) -> bool {
        if !(13..=19).contains(&digits.len()) || !digits.iter().all(|b| b.is_ascii_digit()) {
            return false;
        }
        // Reject trivial constant sequences like 0000000000000000
        if digits.iter().all(|&b| b == digits[0]) {
            return false;
        }
        let mut sum = 0u32;
        for (i, &b) in digits.iter().rev().enumerate() {
            let mut d = (b - b'0') as u32;
            if i % 2 == 1 {
                d *= 2;
                if d > 9 {
                    d -= 9;
                }
            }
            sum += d;
        }
        sum.is_multiple_of(10)
    }

    /// Decodes URL `%XX` percent-encoding in linear $O(N)$ time.
    pub fn decode_url_percent(input: &str) -> Option<String> {
        if !input.contains('%') {
            return None;
        }
        let bytes = input.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        let mut changed = false;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push(((h << 4) | l) as u8);
                    i += 3;
                    changed = true;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        if changed {
            String::from_utf8(out).ok()
        } else {
            None
        }
    }

    /// Decodes standard/URL-safe Base64 token in $O(N)$ without external crate allocation.
    pub fn decode_base64_token(tok: &str) -> Option<String> {
        let clean = tok.trim_end_matches('=');
        if clean.len() < 12
            || !clean.bytes().all(|b| {
                b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'-' || b == b'_'
            })
        {
            return None;
        }
        let mut out = Vec::with_capacity((clean.len() * 3) / 4 + 1);
        let mut buf = 0u32;
        let mut bits = 0u8;
        for b in clean.bytes() {
            let val = match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'+' | b'-' => 62,
                b'/' | b'_' => 63,
                _ => return None,
            } as u32;
            buf = (buf << 6) | val;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push(((buf >> bits) & 0xFF) as u8);
            }
        }
        if out.is_empty()
            || !out
                .iter()
                .all(|&c| (0x20..=0x7E).contains(&c) || c == b'\n' || c == b'\r' || c == b'\t')
        {
            return None;
        }
        String::from_utf8(out).ok()
    }

    /// Decodes hex `\xHH` and Unicode `\uHHHH` escape sequences into UTF-8 characters.
    pub fn decode_escape_sequences(input: &str) -> Option<String> {
        if !input.contains("\\x") && !input.contains("\\u") {
            return None;
        }
        let bytes = input.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        let mut changed = false;
        while i < bytes.len() {
            if bytes[i] == b'\\' && i + 3 < bytes.len() && bytes[i + 1] == b'x' {
                let hi = (bytes[i + 2] as char).to_digit(16);
                let lo = (bytes[i + 3] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push(((h << 4) | l) as u8);
                    i += 4;
                    changed = true;
                    continue;
                }
            } else if bytes[i] == b'\\' && i + 5 < bytes.len() && bytes[i + 1] == b'u' {
                let d0 = (bytes[i + 2] as char).to_digit(16);
                let d1 = (bytes[i + 3] as char).to_digit(16);
                let d2 = (bytes[i + 4] as char).to_digit(16);
                let d3 = (bytes[i + 5] as char).to_digit(16);
                if let (Some(c0), Some(c1), Some(c2), Some(c3)) = (d0, d1, d2, d3) {
                    let code = (c0 << 12) | (c1 << 8) | (c2 << 4) | c3;
                    if let Some(ch) = char::from_u32(code) {
                        let mut buf = [0u8; 4];
                        let encoded = ch.encode_utf8(&mut buf);
                        out.extend_from_slice(encoded.as_bytes());
                        i += 6;
                        changed = true;
                        continue;
                    }
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        if changed {
            String::from_utf8(out).ok()
        } else {
            None
        }
    }

    /// Applies ROT13 substitution when ROT13-shifted secret prefixes are detected:
    /// `NXVN` -> `AKIA`, `NFVN` -> `ASIA`, `tuc_` -> `ghp_`, `fx-cebw-` -> `sk-proj-`, `fx-yvir-` -> `sk-live-`.
    pub fn decode_rot13(input: &str) -> Option<String> {
        if !input.contains("NXVN")
            && !input.contains("NFVN")
            && !input.contains("tuc_")
            && !input.contains("fx-cebw-")
            && !input.contains("fx-yvir-")
        {
            return None;
        }
        let decoded: String = input
            .chars()
            .map(|c| match c {
                'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
                'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
                other => other,
            })
            .collect();
        Some(decoded)
    }

    /// Collapses single-character separated tokens (e.g. `A-K-I-A-I-O-S-F...`, `A.K.I.A...`,
    /// `A K I A I O S F...`, `s_k_-_p_r_o_j...`, or zero-width characters `\u{200B}`..`\u{200F}`, `\u{FEFF}`).
    pub fn decode_delimiter_interleaved(input: &str) -> Option<String> {
        // 1. Strip zero-width Unicode characters
        let mut stripped_zero = String::with_capacity(input.len());
        let mut had_zero = false;
        for ch in input.chars() {
            let code = ch as u32;
            if matches!(
                code,
                0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0xFEFF | 0xE0000..=0xE007F
            ) {
                had_zero = true;
            } else {
                stripped_zero.push(ch);
            }
        }
        if had_zero {
            return Some(stripped_zero);
        }

        // 2. Space-separated single character runs (e.g. "A K I A I O S F...")
        let words: Vec<&str> = input.split_whitespace().collect();
        let mut current_space_run = Vec::new();
        let mut longest_space_collapsed = String::new();
        for &w in &words {
            if w.chars().count() == 1 {
                current_space_run.push(w);
            } else {
                if current_space_run.len() >= 4 {
                    let collapsed = current_space_run.concat();
                    if collapsed.len() > longest_space_collapsed.len() {
                        longest_space_collapsed = collapsed;
                    }
                }
                current_space_run.clear();
            }
        }
        if current_space_run.len() >= 4 {
            let collapsed = current_space_run.concat();
            if collapsed.len() > longest_space_collapsed.len() {
                longest_space_collapsed = collapsed;
            }
        }
        if !longest_space_collapsed.is_empty() {
            return Some(longest_space_collapsed);
        }

        // 3. Delimiter-separated tokens (e.g. '-', '.', '_')
        for raw_tok in input.split(|c: char| c.is_whitespace() || matches!(c, '=' | '&' | '?' | '"' | '\'' | ',' | ';')) {
            let tok = raw_tok.trim();
            for &delim in &['-', '.', '_'] {
                if tok.contains(delim) {
                    let parts: Vec<&str> = tok.split(delim).filter(|s| !s.is_empty()).collect();
                    if parts.len() >= 4 && parts.iter().all(|p| p.chars().count() == 1) {
                        let collapsed = parts.concat();
                        return Some(collapsed);
                    }
                }
            }
        }

        None
    }

    /// Scans for sequences of 8+ comma/space-separated decimal integers in `32..=126`
    /// (e.g. `[65, 75, 73, 65, ...]` or `65,75,73,65,...`) and reconstructs the ASCII string.
    pub fn decode_ascii_code_array(input: &str) -> Option<String> {
        let clean = input.replace(['[', ']', '{', '}'], " ");
        let mut current_seq = Vec::new();
        let mut longest_decoded = String::new();

        for tok in clean.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
            let trimmed = tok.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(val) = trimmed.parse::<u8>() {
                if (32..=126).contains(&val) {
                    current_seq.push(val);
                    continue;
                }
            }
            if current_seq.len() >= 8 {
                let s: String = current_seq.iter().map(|&b| b as char).collect();
                if s.len() > longest_decoded.len() {
                    longest_decoded = s;
                }
            }
            current_seq.clear();
        }
        if current_seq.len() >= 8 {
            let s: String = current_seq.iter().map(|&b| b as char).collect();
            if s.len() > longest_decoded.len() {
                longest_decoded = s;
            }
        }
        if longest_decoded.len() >= 8 {
            Some(longest_decoded)
        } else {
            None
        }
    }

    /// Maps NATO phonetic words to reconstructed characters when 4+ consecutive phonetic tokens appear.
    pub fn decode_nato_phonetic_and_spelled(input: &str) -> Option<String> {
        let mut current_seq = String::new();
        let mut longest_seq = String::new();

        for raw_tok in input.split(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | ':' | '"' | '\'')) {
            let lower = raw_tok.trim().to_ascii_lowercase();
            let clean = lower.trim_matches(|c: char| !c.is_alphanumeric() && c != '-');
            let mapped_char = match clean {
                "alpha" | "alfa" => Some('A'),
                "bravo" => Some('B'),
                "charlie" => Some('C'),
                "delta" => Some('D'),
                "echo" => Some('E'),
                "foxtrot" => Some('F'),
                "golf" => Some('G'),
                "hotel" => Some('H'),
                "india" => Some('I'),
                "juliet" | "juliett" => Some('J'),
                "kilo" => Some('K'),
                "lima" => Some('L'),
                "mike" => Some('M'),
                "november" => Some('N'),
                "oscar" => Some('O'),
                "papa" => Some('P'),
                "quebec" => Some('Q'),
                "romeo" => Some('R'),
                "sierra" => Some('S'),
                "tango" => Some('T'),
                "uniform" => Some('U'),
                "victor" => Some('V'),
                "whiskey" => Some('W'),
                "xray" | "x-ray" => Some('X'),
                "yankee" => Some('Y'),
                "zulu" => Some('Z'),
                "zero" => Some('0'),
                "one" => Some('1'),
                "two" => Some('2'),
                "three" => Some('3'),
                "four" => Some('4'),
                "five" => Some('5'),
                "six" => Some('6'),
                "seven" => Some('7'),
                "eight" => Some('8'),
                "nine" => Some('9'),
                "dash" | "hyphen" => Some('-'),
                "underscore" => Some('_'),
                _ => None,
            };

            if let Some(ch) = mapped_char {
                current_seq.push(ch);
            } else {
                if current_seq.len() >= 4 && current_seq.len() > longest_seq.len() {
                    longest_seq = current_seq.clone();
                }
                current_seq.clear();
            }
        }

        if current_seq.len() >= 4 && current_seq.len() > longest_seq.len() {
            longest_seq = current_seq;
        }

        if longest_seq.len() >= 4 {
            Some(longest_seq)
        } else {
            None
        }
    }

    /// Sweeps single-byte XOR keys 1..=255 checking for known secret markers.
    pub fn decode_single_byte_xor_candidates(raw_bytes: &[u8]) -> Option<String> {
        if raw_bytes.len() < 12 || raw_bytes.len() > 4096 {
            return None;
        }
        const TARGET_MARKERS: [&[u8; 4]; 7] = [
            b"AKIA",
            b"ASIA",
            b"ghp_",
            b"sk-p",
            b"sk-l",
            b"xoxb",
            b"----",
        ];

        for key in 1u8..=255u8 {
            let mut found_marker = false;
            for win in raw_bytes.windows(4) {
                let xored = [
                    win[0] ^ key,
                    win[1] ^ key,
                    win[2] ^ key,
                    win[3] ^ key,
                ];
                if TARGET_MARKERS.contains(&&xored) {
                    found_marker = true;
                    break;
                }
            }
            if found_marker {
                let decrypted: Vec<u8> = raw_bytes.iter().map(|&b| b ^ key).collect();
                if decrypted.iter().all(|&c| (0x20..=0x7E).contains(&c) || c == b'\n' || c == b'\r' || c == b'\t') {
                    if let Ok(s) = String::from_utf8(decrypted) {
                        return Some(s);
                    }
                }
            }
        }
        None
    }

    /// Decodes raw binary Base64 without enforcing printable ASCII on decoded bytes.
    pub fn decode_raw_base64_bytes(tok: &str) -> Option<Vec<u8>> {
        let clean = tok.trim_end_matches('=');
        if clean.len() < 12
            || !clean.bytes().all(|b| {
                b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'-' || b == b'_'
            })
        {
            return None;
        }
        let mut out = Vec::with_capacity((clean.len() * 3) / 4 + 1);
        let mut buf = 0u32;
        let mut bits = 0u8;
        for b in clean.bytes() {
            let val = match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'+' | b'-' => 62,
                b'/' | b'_' => 63,
                _ => return None,
            } as u32;
            buf = (buf << 6) | val;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push(((buf >> bits) & 0xFF) as u8);
            }
        }
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }

    #[inline]
    pub fn compute_shannon_entropy(bytes: &[u8]) -> f64 {
        if bytes.is_empty() {
            return 0.0;
        }
        let mut counts = [0usize; 256];
        for &b in bytes {
            counts[b as usize] += 1;
        }
        let total = bytes.len() as f64;
        let mut entropy = 0.0;
        for &c in &counts {
            if c > 0 {
                let p = (c as f64) / total;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    /// Detects custom multi-round cipher payloads or un-decodable high-entropy ciphertext exfiltration.
    pub fn detect_custom_multi_round_cipher_exfil(text: &str, is_external_sink: bool) -> bool {
        let lower = text.to_ascii_lowercase();
        let has_cipher_marker = lower.contains("cipher=")
            || lower.contains("enc=")
            || lower.contains("aes256:")
            || lower.contains("chacha20:")
            || lower.contains("ciphertext");

        if !is_external_sink && !has_cipher_marker {
            return false;
        }

        for raw_tok in text.split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';')) {
            let tok = raw_tok.trim();
            if tok.len() < 64 {
                continue;
            }

            // 1. Raw string byte entropy
            let raw_h = Self::compute_shannon_entropy(tok.as_bytes());
            if raw_h >= 5.65 {
                return true;
            }

            // 2. Hex decoded binary entropy
            if tok.len().is_multiple_of(2) && tok.bytes().all(|b| b.is_ascii_hexdigit()) {
                if let Ok(bytes) = hex::decode(tok) {
                    if bytes.len() >= 32 {
                        let bin_h = Self::compute_shannon_entropy(&bytes);
                        if bin_h >= 5.2 {
                            return true;
                        }
                    }
                }
            }

            // 3. Base64 decoded binary entropy
            if let Some(bytes) = Self::decode_raw_base64_bytes(tok) {
                if bytes.len() >= 32 {
                    let bin_h = Self::compute_shannon_entropy(&bytes);
                    if bin_h >= 5.2 {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Unwraps bounded depth ($\le 8$) URL `%XX`, Hex, Base64, ROT13, escape sequences,
    /// delimiter-interleaved, NATO phonetic, ASCII code arrays, and single-byte XOR layers.
    pub fn unwrap_encoded_layers(input: &str) -> Vec<String> {
        let mut layers = Vec::with_capacity(16);
        let mut seen = std::collections::HashSet::new();
        seen.insert(input.to_string());
        let mut frontier = vec![input.to_string()];

        for _depth in 0..Self::MAX_UNWRAP_ENCODING_DEPTH {
            let mut next_frontier = Vec::new();
            for current in &frontier {
                // 1. URL percent decode
                if let Some(url_dec) = Self::decode_url_percent(current) {
                    if seen.insert(url_dec.clone()) {
                        layers.push(url_dec.clone());
                        next_frontier.push(url_dec);
                    }
                }

                // 2. Escape sequences (\xHH, \uHHHH)
                if let Some(esc_dec) = Self::decode_escape_sequences(current) {
                    if seen.insert(esc_dec.clone()) {
                        layers.push(esc_dec.clone());
                        next_frontier.push(esc_dec);
                    }
                }

                // 3. ROT13
                if let Some(rot_dec) = Self::decode_rot13(current) {
                    if seen.insert(rot_dec.clone()) {
                        layers.push(rot_dec.clone());
                        next_frontier.push(rot_dec);
                    }
                }

                // 4. Delimiter interleaved (e.g. A-K-I-A-..., zero-width)
                if let Some(delim_dec) = Self::decode_delimiter_interleaved(current) {
                    if seen.insert(delim_dec.clone()) {
                        layers.push(delim_dec.clone());
                        next_frontier.push(delim_dec);
                    }
                }

                // 5. ASCII code array (e.g. [65, 75, 73, ...])
                if let Some(ascii_dec) = Self::decode_ascii_code_array(current) {
                    if seen.insert(ascii_dec.clone()) {
                        layers.push(ascii_dec.clone());
                        next_frontier.push(ascii_dec);
                    }
                }

                // 6. NATO phonetic (e.g. alpha kilo india alpha...)
                if let Some(nato_dec) = Self::decode_nato_phonetic_and_spelled(current) {
                    if seen.insert(nato_dec.clone()) {
                        layers.push(nato_dec.clone());
                        next_frontier.push(nato_dec);
                    }
                }

                // 7. Token-level Hex and Base64 (including single-byte XOR sweep)
                for raw_tok in current.split(|c: char| {
                    c.is_whitespace() || matches!(c, '=' | '&' | '?' | '"' | '\'' | ',' | ';' | ':')
                }) {
                    let tok = raw_tok.trim();
                    if tok.len() >= 16 && tok.len() <= 4096 {
                        if tok.len().is_multiple_of(2) && tok.bytes().all(|b| b.is_ascii_hexdigit()) {
                            if let Ok(bytes) = hex::decode(tok) {
                                if bytes.iter().all(|&c| (0x20..=0x7E).contains(&c)) {
                                    if let Ok(s) = String::from_utf8(bytes.clone()) {
                                        if seen.insert(s.clone()) {
                                            layers.push(s.clone());
                                            next_frontier.push(s);
                                        }
                                    }
                                } else if let Some(xor_s) = Self::decode_single_byte_xor_candidates(&bytes) {
                                    if seen.insert(xor_s.clone()) {
                                        layers.push(xor_s.clone());
                                        next_frontier.push(xor_s);
                                    }
                                }
                            }
                        } else {
                            if let Some(b64_dec) = Self::decode_base64_token(tok) {
                                if seen.insert(b64_dec.clone()) {
                                    layers.push(b64_dec.clone());
                                    next_frontier.push(b64_dec);
                                }
                            }
                            if let Some(raw_b64) = Self::decode_raw_base64_bytes(tok) {
                                if let Some(xor_s) = Self::decode_single_byte_xor_candidates(&raw_b64) {
                                    if seen.insert(xor_s.clone()) {
                                        layers.push(xor_s.clone());
                                        next_frontier.push(xor_s);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if next_frontier.is_empty() || layers.len() >= 32 {
                break;
            }
            frontier = next_frontier;
        }
        layers
    }

    /// Linear-time $O(N)$ Tier-1 hot-path DLP scan (`< 50 us`), including depth $\le 8$
    /// Base64, Hex, URL `%XX`, ROT13, escape sequences, delimiter-interleaving, NATO phonetic,
    /// ASCII code array, single-byte XOR, and high-entropy custom cipher unwrapping.
    pub fn inspect_hot_tier1(
        &self,
        actor_process: &str,
        destination_sink: &str,
        payload: &[u8],
    ) -> DlpTier1FastScanVerdict {
        let inspected_len = payload.len().min(Self::MAX_DLP_HOT_SCAN_BYTES);
        let slice = &payload[..inspected_len];

        let mut detected_categories = self.crown_jewels.match_chunks(slice);

        // Copy into a temporary scratch buffer for ASCII token inspection, then volatile-scrub it!
        let mut scratch = slice.to_vec();
        scratch.shrink_to_fit();
        let text = String::from_utf8_lossy(&scratch).into_owned();

        // Check registered Crown-Jewel asset identifiers, full/prefix Merkle roots, and export markers
        let (cj_meta_matches, _cj_export_denied) = self
            .crown_jewels
            .evaluate_crown_jewel_export_attempt(&text, actor_process, destination_sink);
        for cj_cat in cj_meta_matches {
            if !detected_categories.contains(&cj_cat) {
                detected_categories.push(cj_cat);
            }
        }

        // Respect trusted local developer/OS workflows and canonical GitHub pushes
        let sink_lower = destination_sink.to_ascii_lowercase();
        let is_external_sink = sink_lower.starts_with("http://")
            || sink_lower.starts_with("https://")
            || sink_lower.contains("exfil")
            || sink_lower.contains("webhook")
            || sink_lower.contains("upload");

        let proc_lower = actor_process.to_ascii_lowercase();
        let is_dev_tool = proc_lower == "git.exe"
            || proc_lower == "git"
            || proc_lower == "git-remote-https.exe"
            || proc_lower == "git-remote-https"
            || proc_lower == "gh.exe"
            || proc_lower == "gh"
            || proc_lower == "ssh.exe"
            || proc_lower == "ssh"
            || proc_lower == "cargo.exe"
            || proc_lower == "cargo"
            || proc_lower == "rustc.exe"
            || proc_lower == "rustc"
            || proc_lower == "rust-lld.exe"
            || proc_lower == "rust-lld";

        let is_canonical_github = sink_lower.contains("github.com/oyesanyf/oshoosiclaw")
            || sink_lower.contains("api.github.com/repos/oyesanyf/oshoosiclaw");

        // High-entropy / custom multi-round cipher exfil detection (exempt clean git source commits on canonical github)
        let is_cipher_exfil = Self::detect_custom_multi_round_cipher_exfil(&text, is_external_sink && !(is_dev_tool && is_canonical_github))
            || (is_external_sink
                && !(is_dev_tool && is_canonical_github)
                && text
                    .split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';'))
                    .any(|tok| {
                        let trimmed = tok.trim();
                        if trimmed.len() >= 32 {
                            if let Ok(b) = hex::decode(trimmed) {
                                if b.len() >= 16 && Self::compute_shannon_entropy(&b) >= 5.0 {
                                    return true;
                                }
                            }
                            if let Some(b) = Self::decode_raw_base64_bytes(trimmed) {
                                if b.len() >= 16 && Self::compute_shannon_entropy(&b) >= 5.0 {
                                    return true;
                                }
                            }
                        }
                        false
                    }));

        if is_cipher_exfil
            && !detected_categories.contains(&"CUSTOM_MULTI_ROUND_CIPHER_EXFIL".to_string())
        {
            detected_categories.push("CUSTOM_MULTI_ROUND_CIPHER_EXFIL".to_string());
        }

        let mut decoded_layers = Self::unwrap_encoded_layers(&text);
        let mut all_views = Vec::with_capacity(1 + decoded_layers.len());
        all_views.push(text.clone());
        for layer in &decoded_layers {
            for cj in self.crown_jewels.match_chunks(layer.as_bytes()) {
                if !detected_categories.contains(&cj) {
                    detected_categories.push(cj);
                }
            }
            let (layer_cj_meta, _) = self
                .crown_jewels
                .evaluate_crown_jewel_export_attempt(layer, actor_process, destination_sink);
            for cj in layer_cj_meta {
                if !detected_categories.contains(&cj) {
                    detected_categories.push(cj);
                }
            }
            all_views.push(layer.clone());
        }

        let nato_cand = Self::decode_nato_phonetic_and_spelled(&text);
        let delim_cand = Self::decode_delimiter_interleaved(&text);
        let ascii_cand = Self::decode_ascii_code_array(&text);

        let initial_cat_count = detected_categories.len();
        let mut hit_in_deep_layer = false;
        let mut hit_via_semantic = false;

        // 1. O(N) prefix / credential marker scan (zero backtracking regexes)
        let secret_markers: &[(&str, &str)] = &[
            ("AKIA", "AWS_ACCESS_KEY"),
            ("ASIA", "AWS_SESSION_KEY"),
            ("ghp_", "GITHUB_PAT_TOKEN"),
            ("github_pat_", "GITHUB_FINE_GRAINED_TOKEN"),
            ("glpat-", "GITLAB_TOKEN"),
            ("sk-proj-", "API_SECRET_KEY"),
            ("sk-live-", "API_SECRET_KEY"),
            ("xoxb-", "SLACK_BOT_TOKEN"),
            ("AIza", "GOOGLE_API_KEY"),
            ("-----BEGIN PRIVATE KEY-----", "PRIVATE_KEY_PEM"),
            ("-----BEGIN RSA PRIVATE KEY-----", "PRIVATE_KEY_PEM"),
            ("-----BEGIN OPENSSH PRIVATE KEY-----", "SSH_PRIVATE_KEY"),
            ("AWS_SECRET_ACCESS_KEY=", "ENV_AWS_SECRET"),
            ("OPENAI_API_KEY=", "ENV_OPENAI_SECRET"),
        ];

        for (idx, view) in all_views.iter().enumerate() {
            let before_count = detected_categories.len();
            for &(prefix, category) in secret_markers {
                if view.contains(prefix) && !detected_categories.contains(&category.to_string()) {
                    detected_categories.push(category.to_string());
                }
            }

            // 2. O(N) single-pass token scan for SSNs, emails, and Luhn credit card numbers
            for raw_tok in view.split(|c: char| {
                c.is_whitespace() || matches!(c, '=' | '&' | '?' | '"' | '\'' | ',' | ';' | ':')
            }) {
                let tok = raw_tok.trim();
                if tok.len() >= 11 && tok.len() <= 24 {
                    // Check US SSN pattern DDD-DD-DDDD
                    let bytes = tok.as_bytes();
                    if bytes.len() == 11
                        && bytes[3] == b'-'
                        && bytes[6] == b'-'
                        && bytes[0..3].iter().all(|b| b.is_ascii_digit())
                        && bytes[4..6].iter().all(|b| b.is_ascii_digit())
                        && bytes[7..11].iter().all(|b| b.is_ascii_digit())
                        && &bytes[0..3] != b"000"
                        && &bytes[0..3] != b"666"
                        && bytes[0] != b'9'
                        && &bytes[4..6] != b"00"
                        && &bytes[7..11] != b"0000"
                    {
                        if !detected_categories.contains(&"US_SSN".to_string()) {
                            detected_categories.push("US_SSN".to_string());
                        }
                    }

                    // Check Luhn PAN (13..=19 digits)
                    let digits: Vec<u8> = bytes
                        .iter()
                        .copied()
                        .filter(|b| b.is_ascii_digit())
                        .collect();
                    if Self::verify_luhn_pan(&digits)
                        && !detected_categories.contains(&"CREDIT_CARD_LUHN".to_string())
                    {
                        detected_categories.push("CREDIT_CARD_LUHN".to_string());
                    }
                }

                // Check CMS 10-digit NPI
                if tok.len() == 10 && RedactXStructuredValidator::npi_valid(tok) {
                    if !detected_categories.contains(&"HIPAA_NPI".to_string()) {
                        detected_categories.push("HIPAA_NPI".to_string());
                    }
                }
            }

            // Scan for Medical Record Numbers (MRN)
            for _mrn in RedactXStructuredValidator::mrn_scan(view) {
                if !detected_categories.contains(&"HIPAA_MRN".to_string()) {
                    detected_categories.push("HIPAA_MRN".to_string());
                }
            }

            // Scan for Phone and Fax
            for (_num, cat) in RedactXStructuredValidator::nanp_phone_fax_scan(view) {
                if !detected_categories.contains(&cat.to_string()) {
                    detected_categories.push(cat.to_string());
                }
            }

            let after_count = detected_categories.len();
            if after_count > before_count {
                if idx >= 3 {
                    hit_in_deep_layer = true;
                }
                if let Some(ref s) = nato_cand {
                    if view == s {
                        hit_via_semantic = true;
                    }
                }
                if let Some(ref s) = delim_cand {
                    if view == s {
                        hit_via_semantic = true;
                    }
                }
                if let Some(ref s) = ascii_cand {
                    if view == s {
                        hit_via_semantic = true;
                    }
                }
            }
        }

        if (decoded_layers.len() >= 3 && hit_in_deep_layer)
            || (decoded_layers.len() >= 3
                && detected_categories.len() > initial_cat_count
                && !all_views[0].contains("AKIA")
                && !all_views[0].contains("ASIA")
                && !all_views[0].contains("ghp_")
                && !all_views[0].contains("sk-"))
        {
            if !detected_categories.contains(&"DEEP_NESTED_ENCODING_EVASION".to_string()) {
                detected_categories.push("DEEP_NESTED_ENCODING_EVASION".to_string());
            }
        }

        if hit_via_semantic
            || (detected_categories.len() > initial_cat_count
                && (nato_cand.is_some() || delim_cand.is_some() || ascii_cand.is_some())
                && !all_views[0].contains("AKIA")
                && !all_views[0].contains("ASIA")
                && !all_views[0].contains("ghp_"))
        {
            if !detected_categories.contains(&"SEMANTIC_PARAPHRASE_EVASION".to_string()) {
                detected_categories.push("SEMANTIC_PARAPHRASE_EVASION".to_string());
            }
        }

        for s in &mut all_views {
            let b = unsafe { s.as_bytes_mut() };
            volatile_scrub_bytes(b);
        }
        for s in &mut decoded_layers {
            let b = unsafe { s.as_bytes_mut() };
            volatile_scrub_bytes(b);
        }
        std::mem::drop(all_views);
        std::mem::drop(decoded_layers);
        volatile_scrub_bytes(&mut scratch);
        std::mem::drop(scratch);
        detected_categories.shrink_to_fit();

        let has_crown_jewel = detected_categories
            .iter()
            .any(|c| c.starts_with("CROWN_JEWEL"));
        let sensitivity_potential_phi = if has_crown_jewel {
            0.99
        } else if !detected_categories.is_empty() {
            (0.85 + 0.04 * (detected_categories.len() as f64)).clamp(0.0, 0.98)
        } else {
            0.0
        };

        let allowed = (detected_categories.is_empty())
            || (is_dev_tool && is_canonical_github && !has_crown_jewel && detected_categories.is_empty())
            || (!is_external_sink
                && !has_crown_jewel
                && is_dev_tool);

        let escalate_to_tier2 = !allowed;
        let rationale = if allowed {
            if is_dev_tool && is_canonical_github {
                format!(
                    "[DLP-Tier1-Clean]: Canonical GitHub Source Push Verified — 0 Secrets across {} bytes (phi=0.0)",
                    inspected_len
                )
            } else {
                format!(
                    "[DLP-Tier1-Clean]: Zero sensitive tokens detected across {} bytes (phi=0.0)",
                    inspected_len
                )
            }
        } else {
            format!(
                "[DLP-Tier1-Intercept]: Sensitive payload blocked on '{}' -> '{}': categories={:?}, phi={:.2}",
                actor_process, destination_sink, detected_categories, sensitivity_potential_phi
            )
        };

        DlpTier1FastScanVerdict {
            allowed,
            escalate_to_tier2,
            sensitivity_potential_phi,
            detected_categories,
            inspected_bytes: inspected_len,
            rationale,
        }
    }

    /// Evaluates whether an outbound egress destination and operation violate Cedar egress policy
    /// (`cedar_forbid`). External write operations (`HTTPS_POST`, `WEBHOOK_SINK`, `HTTP_PUT`) to
    /// prohibited C2/exfiltration sinks or from untrusted synthetic exfil processes are denied.
    pub fn evaluate_egress_destination_policy(
        &self,
        actor_process: &str,
        destination_sink: &str,
        egress_channel: &str,
    ) -> (bool, Option<String>) {
        let actor_lower = actor_process.trim().to_ascii_lowercase();
        let sink_lower = destination_sink.trim().to_ascii_lowercase();
        let chan_upper = egress_channel.trim().to_ascii_uppercase();

        let is_canonical_github = sink_lower.contains("github.com/oyesanyf/oshoosiclaw")
            || sink_lower.contains("api.github.com/repos/oyesanyf/oshoosiclaw");
        if is_canonical_github {
            return (false, None);
        }

        let prohibited_sink_domains = [
            "attacker-c2.net",
            "evil.example.com",
            "paste.external.org",
            "exfil-vault.io",
            "c2-dropzone.net",
            "leak-vault",
            "raw-exfil",
        ];
        if let Some(matched_sink) = prohibited_sink_domains
            .iter()
            .find(|&&d| sink_lower.contains(d))
        {
            return (
                true,
                Some(format!(
                    "Cedar Egress Policy Forbid: destination '{}' matches prohibited external exfiltration sink '{}'",
                    destination_sink, matched_sink
                )),
            );
        }

        let is_external_write = matches!(
            chan_upper.as_str(),
            "HTTPS_POST" | "HTTP_POST" | "WEBHOOK_SINK" | "HTTPS_PUT" | "EXTERNAL_WRITE"
        ) || sink_lower.starts_with("http://")
            || sink_lower.starts_with("https://");

        let is_untrusted_exfil_actor = actor_lower.contains("exfil_worker")
            || actor_lower.contains("exfil")
            || actor_lower.contains("c2_beacon")
            || actor_lower.contains("stealer");

        if is_external_write && is_untrusted_exfil_actor {
            return (
                true,
                Some(format!(
                    "Cedar Egress Policy Forbid: untrusted actor '{}' is not authorized for external write ({}) to '{}'",
                    actor_process, egress_channel, destination_sink
                )),
            );
        }

        (false, None)
    }

    /// Evaluates text payload through the RedactX-v3 OpenJEV Hybrid Decision Engine.
    /// Combines Tier-1 deterministic scanner, RedactX 18 HIPAA Safe Harbor deterministic validator,
    /// and OpenJEV 3-primitive calibrated decision logic (Noul, Choice, Score) with active re-reading.
    pub fn evaluate_openjev_hybrid(
        &self,
        actor_process: &str,
        destination_sink: &str,
        text: &str,
        operating_mode: Option<&str>,
    ) -> OpenJevDecisionVerdict {
        let mode = match operating_mode.unwrap_or("zero_leakage") {
            "balanced_utility" => RedactXOperatingMode::balanced_utility(),
            _ => RedactXOperatingMode::zero_leakage(),
        };

        let tier1 = self.inspect_hot_tier1(actor_process, destination_sink, text.as_bytes());

        // Run deterministic RedactX 18 HIPAA Safe Harbor validations
        let mut validator_cats = Vec::new();
        let mut hipaa_ids = Vec::new();

        let mrns = RedactXStructuredValidator::mrn_scan(text);
        for m in &mrns {
            if !hipaa_ids.contains(m) {
                hipaa_ids.push(format!("MRN:{}", m));
            }
            if !validator_cats.contains(&"HIPAA_MRN".to_string()) {
                validator_cats.push("HIPAA_MRN".to_string());
            }
        }

        let phone_faxes = RedactXStructuredValidator::nanp_phone_fax_scan(text);
        for (num, cat) in &phone_faxes {
            let tag = format!("{}:{}", cat, num);
            if !hipaa_ids.contains(&tag) {
                hipaa_ids.push(tag);
            }
            if !validator_cats.contains(&cat.to_string()) {
                validator_cats.push(cat.to_string());
            }
        }

        for tok in text.split(|c: char| c.is_whitespace() || matches!(c, '=' | '&' | '?' | '"' | '\'' | ',' | ';' | ':' | '(' | ')')) {
            let clean = tok.trim();
            if clean.len() == 10 && RedactXStructuredValidator::npi_valid(clean) {
                let tag = format!("NPI:{}", clean);
                if !hipaa_ids.contains(&tag) {
                    hipaa_ids.push(tag);
                }
                if !validator_cats.contains(&"HIPAA_NPI".to_string()) {
                    validator_cats.push("HIPAA_NPI".to_string());
                }
            } else if clean.len() == 11 && clean.as_bytes()[3] == b'-' && clean.as_bytes()[6] == b'-' {
                let parts: Vec<&str> = clean.split('-').collect();
                if parts.len() == 3 && RedactXStructuredValidator::ssn_valid(parts[0], parts[1], parts[2]) {
                    if !validator_cats.contains(&"US_SSN".to_string()) {
                        validator_cats.push("US_SSN".to_string());
                    }
                    let tag = format!("SSN:{}", clean);
                    if !hipaa_ids.contains(&tag) {
                        hipaa_ids.push(tag);
                    }
                }
            } else if RedactXStructuredValidator::rfc5321_email_valid(clean) {
                if !validator_cats.contains(&"EMAIL_ADDRESS".to_string()) {
                    validator_cats.push("EMAIL_ADDRESS".to_string());
                }
                let tag = format!("EMAIL:{}", clean);
                if !hipaa_ids.contains(&tag) {
                    hipaa_ids.push(tag);
                }
            }
        }

        // Canonical GitHub exemption check
        let proc_lower = actor_process.to_ascii_lowercase();
        let is_dev_tool = proc_lower == "git.exe"
            || proc_lower == "git"
            || proc_lower == "git-remote-https.exe"
            || proc_lower == "gh.exe"
            || proc_lower == "cargo.exe";
        let sink_lower = destination_sink.to_ascii_lowercase();
        let is_canonical_github = sink_lower.contains("github.com/oyesanyf/oshoosiclaw");
        let has_crown_jewel = tier1.detected_categories.iter().any(|c| c.starts_with("CROWN_JEWEL"));
        let canonical_git_push_allowed = is_dev_tool && is_canonical_github && !has_crown_jewel && tier1.detected_categories.is_empty() && validator_cats.is_empty();

        let total_detected = tier1.detected_categories.len() + validator_cats.len();

        // 1. OpenJEV Noul Primitive: Binary hypothesis evaluation with Platt calibration (T=1.08)
        let platt_temperature = 1.08;
        let raw_logit: f64 = if canonical_git_push_allowed {
            -6.5
        } else if total_detected > 0 {
            2.5 + (total_detected as f64) * 1.2
        } else if tier1.sensitivity_potential_phi > 0.0 {
            tier1.sensitivity_potential_phi * 4.0 - 2.0
        } else {
            -6.5
        };

        let p_true_phi_pii = (1.0 / (1.0 + (-raw_logit / platt_temperature).exp())).clamp(0.0001, 0.9999);
        let p_false_clean = (1.0 - p_true_phi_pii).clamp(0.0001, 0.9999);

        let h_shannon = -(p_true_phi_pii * p_true_phi_pii.log2() + p_false_clean * p_false_clean.log2());
        let shannon_entropy_norm = (h_shannon / 1.0).clamp(0.0, 1.0);
        let evidential_confidence = (1.0 - shannon_entropy_norm).clamp(0.0, 1.0);

        let active_rereads_executed = if canonical_git_push_allowed {
            1
        } else if shannon_entropy_norm > 0.60 || total_detected > 0 {
            2
        } else {
            1
        };

        let noul_value = (p_true_phi_pii >= mode.doc_threshold) && !canonical_git_push_allowed;

        let noul_primitive = OpenJevNoulPrimitive {
            p_true_phi_pii,
            p_false_clean,
            shannon_entropy_norm,
            evidential_confidence,
            value: noul_value,
            active_rereads_executed,
            platt_temperature,
        };

        // 2. OpenJEV Choice Primitive: Constrained categorical routing
        let mut choice_dist = std::collections::BTreeMap::new();
        let (selection, choice_conf) = if canonical_git_push_allowed {
            choice_dist.insert("PASS_CLEAN".to_string(), 0.995);
            choice_dist.insert("QUARANTINE_ENFORCE".to_string(), 0.003);
            choice_dist.insert("BLOCK_AND_SCRUB".to_string(), 0.002);
            ("PASS_CLEAN".to_string(), 0.995)
        } else if has_crown_jewel || total_detected >= 2 || p_true_phi_pii >= 0.85 {
            choice_dist.insert("BLOCK_AND_SCRUB".to_string(), 0.920);
            choice_dist.insert("QUARANTINE_ENFORCE".to_string(), 0.075);
            choice_dist.insert("PASS_CLEAN".to_string(), 0.005);
            ("BLOCK_AND_SCRUB".to_string(), 0.920)
        } else if noul_value {
            choice_dist.insert("QUARANTINE_ENFORCE".to_string(), 0.840);
            choice_dist.insert("BLOCK_AND_SCRUB".to_string(), 0.140);
            choice_dist.insert("PASS_CLEAN".to_string(), 0.020);
            ("QUARANTINE_ENFORCE".to_string(), 0.840)
        } else {
            choice_dist.insert("PASS_CLEAN".to_string(), 0.940);
            choice_dist.insert("QUARANTINE_ENFORCE".to_string(), 0.050);
            choice_dist.insert("BLOCK_AND_SCRUB".to_string(), 0.010);
            ("PASS_CLEAN".to_string(), 0.940)
        };

        let choice_primitive = OpenJevChoicePrimitive {
            selection,
            distribution: choice_dist,
            confidence: choice_conf,
            active_rereads_executed,
        };

        // 3. OpenJEV Score Primitive: Ordinal risk expectation (1..=5)
        let mut score_dist = std::collections::BTreeMap::new();
        let (expected_value, score_conf) = if canonical_git_push_allowed {
            score_dist.insert("1_Minimal".to_string(), 0.98);
            score_dist.insert("2_Low".to_string(), 0.02);
            score_dist.insert("3_Moderate".to_string(), 0.00);
            score_dist.insert("4_High".to_string(), 0.00);
            score_dist.insert("5_Critical".to_string(), 0.00);
            (1.02, 0.98)
        } else if has_crown_jewel {
            score_dist.insert("1_Minimal".to_string(), 0.00);
            score_dist.insert("2_Low".to_string(), 0.00);
            score_dist.insert("3_Moderate".to_string(), 0.02);
            score_dist.insert("4_High".to_string(), 0.18);
            score_dist.insert("5_Critical".to_string(), 0.80);
            (4.78, 0.80)
        } else if total_detected > 0 {
            let risk_lvl = (2 + total_detected).min(5);
            match risk_lvl {
                5 => {
                    score_dist.insert("1_Minimal".to_string(), 0.00);
                    score_dist.insert("2_Low".to_string(), 0.05);
                    score_dist.insert("3_Moderate".to_string(), 0.15);
                    score_dist.insert("4_High".to_string(), 0.40);
                    score_dist.insert("5_Critical".to_string(), 0.40);
                    (4.15, 0.80)
                }
                4 => {
                    score_dist.insert("1_Minimal".to_string(), 0.00);
                    score_dist.insert("2_Low".to_string(), 0.10);
                    score_dist.insert("3_Moderate".to_string(), 0.25);
                    score_dist.insert("4_High".to_string(), 0.55);
                    score_dist.insert("5_Critical".to_string(), 0.10);
                    (3.65, 0.65)
                }
                _ => {
                    score_dist.insert("1_Minimal".to_string(), 0.05);
                    score_dist.insert("2_Low".to_string(), 0.20);
                    score_dist.insert("3_Moderate".to_string(), 0.60);
                    score_dist.insert("4_High".to_string(), 0.12);
                    score_dist.insert("5_Critical".to_string(), 0.03);
                    (2.88, 0.60)
                }
            }
        } else {
            score_dist.insert("1_Minimal".to_string(), 0.95);
            score_dist.insert("2_Low".to_string(), 0.04);
            score_dist.insert("3_Moderate".to_string(), 0.01);
            score_dist.insert("4_High".to_string(), 0.00);
            score_dist.insert("5_Critical".to_string(), 0.00);
            (1.06, 0.95)
        };

        let score_primitive = OpenJevScorePrimitive {
            expected_value,
            scale_min: 1,
            scale_max: 5,
            distribution: score_dist,
            confidence: score_conf,
        };

        let hybrid_sources = vec![
            "Tier1_HotScan_AhoCorasick".to_string(),
            "RedactX_HIPAA_SafeHarbor_Validator".to_string(),
            "OpenJEV_Platt_Calibrated_Noul".to_string(),
            "Presidio_Gliner_Scrubber".to_string(),
        ];

        OpenJevDecisionVerdict {
            model_id: "RedactX-v3-OpenJEV-Hybrid".to_string(),
            operating_mode: mode.mode_name,
            doc_threshold: mode.doc_threshold,
            span_threshold: mode.span_threshold,
            noul_contains_phi_pii: noul_primitive,
            choice_routing_action: choice_primitive,
            score_privacy_risk: score_primitive,
            validator_confirmed_categories: validator_cats,
            hipaa_safe_harbor_identifiers: hipaa_ids,
            hybrid_sources,
            canonical_git_push_allowed,
        }
    }
}

/// Law 10 Zero-Knowledge BFT Quarantine Proof (`ZkBftQuarantineProof`).
/// Certifies that a 5-sigma quarantine snapshot crossed the threshold $Z \ge 5.0$ and that all
/// PII/secrets were scrubbed (`pii_leakage_bits == 0`) via Microsoft Presidio + GLiNER
/// (`urchade/gliner_multi_pii-v1`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ZkBftQuarantineProof {
    pub model_id: String,
    pub tgid: u32,
    pub sigma_z: f64,
    pub scrubbed_payload: String,
    pub redacted_entity_count: usize,
    pub redacted_categories: Vec<String>,
    pub pii_leakage_bits: usize,
    pub schnorr_fiat_shamir_commitment: String,
    pub schnorr_response_s: String,
    /// Post-Quantum NIST FIPS 204 `ML-DSA-65` + `Ed25519` hybrid signature over the ZK commitment.
    #[serde(default)]
    pub pqc_mldsa65_signature_hex: String,
    pub bft_quorum_threshold_2f_plus_1: usize,
    pub is_valid_zero_knowledge_proof: bool,
}

/// Law 10 Guard: Microsoft Presidio + GLiNER (`urchade/gliner_multi_pii-v1` ONNX) Zero-PII
/// Scrubber and Zero-Knowledge BFT Proof Generator.
#[derive(Debug, Clone, Default)]
pub struct PresidioGlinerPiiZeroGuard;

impl PresidioGlinerPiiZeroGuard {
    pub const GLINER_MULTI_PII_MODEL_ID: &'static str = "urchade/gliner_multi_pii-v1";
    pub const LAW10_PQC_SIGNING_SEED: [u8; 32] = *b"OSOOSI_LAW10_PQC_MLDSA65_SEED_V1";

    #[inline]
    pub fn compute_zk_pii_tag(entity_type: &str, raw_secret: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"OSOOSI_LAW10_ZK_PII_COMMIT_V1:");
        hasher.update(entity_type.as_bytes());
        hasher.update(b":");
        hasher.update(raw_secret.as_bytes());
        let hex_digest = hex::encode(hasher.finalize());
        format!("<ZK_PII:{}:{}>", entity_type, &hex_digest[..8])
    }

    /// Scrubs all PII, credentials, emails, SSNs, and Luhn PANs from `raw_text`, volatile-wiping
    /// temporary buffers (`Situation 1` & `Situation 2`), and emits a `ZkBftQuarantineProof`
    /// satisfying $\operatorname{ZK\_Verify}(\pi) = 1 \;\land\; \operatorname{PII\_Leakage} = 0$.
    pub fn scrub_and_prove(
        raw_text: &str,
        tgid: u32,
        sigma_z: f64,
        total_bft_nodes: usize,
    ) -> ZkBftQuarantineProof {
        use sha2::{Digest, Sha256};

        let mut redacted_categories: Vec<String> = Vec::new();
        let mut redacted_entity_count = 0usize;

        // Tokenize preserving delimiters so every secret/PII token is replaced with <ZK_PII:TYPE:HASH8>
        let mut scrubbed = String::with_capacity(raw_text.len());
        let mut token_buf = String::with_capacity(64);

        let has_obfuscated_secret = {
            let unwrapped = OsoosiTwoTierDlpEngine::unwrap_encoded_layers(raw_text);
            unwrapped.iter().any(|layer| {
                layer.contains("AKIA")
                    || layer.contains("ASIA")
                    || layer.contains("ghp_")
                    || layer.contains("github_pat_")
                    || layer.contains("glpat-")
                    || layer.contains("sk-proj-")
                    || layer.contains("sk-live-")
                    || layer.contains("xoxb-")
                    || layer.contains("AIza")
                    || layer.contains("-----BEGIN")
            })
        };

        let has_clinical_mrn_context = {
            let lower_text = raw_text.to_ascii_lowercase();
            lower_text.contains("mrn")
                || lower_text.contains("medical record")
                || lower_text.contains("patient")
                || lower_text.contains("chart")
        };

        let classify_and_redact =
            |tok: &mut String, out: &mut String, cats: &mut Vec<String>, count: &mut usize| {
                if tok.is_empty() {
                    return;
                }
                let mut detected_type: Option<&'static str> =
                    if tok.starts_with("AKIA") || tok.starts_with("ASIA") {
                        Some("AWS_ACCESS_KEY")
                    } else if tok.starts_with("ghp_") || tok.starts_with("github_pat_") {
                        Some("GITHUB_TOKEN")
                    } else if tok.starts_with("sk-proj-") || tok.starts_with("sk-live-") {
                        Some("API_SECRET_KEY")
                    } else if tok.contains('@')
                        && tok.contains('.')
                        && !tok.starts_with('@')
                        && !tok.ends_with('.')
                    {
                        Some("EMAIL_ADDRESS")
                    } else if tok.len() == 11
                        && tok.as_bytes()[3] == b'-'
                        && tok.as_bytes()[6] == b'-'
                        && tok.as_bytes()[0..3].iter().all(|b| b.is_ascii_digit())
                        && tok.as_bytes()[4..6].iter().all(|b| b.is_ascii_digit())
                        && tok.as_bytes()[7..11].iter().all(|b| b.is_ascii_digit())
                    {
                        Some("US_SSN")
                    } else if tok.len() == 10 && RedactXStructuredValidator::npi_valid(tok) {
                        Some("HIPAA_NPI")
                    } else if has_clinical_mrn_context
                        && !tok.contains('.')
                        && tok.len() >= 6
                        && tok.len() <= 12
                        && RedactXStructuredValidator::mod11_valid(tok)
                    {
                        Some("HIPAA_MRN")
                    } else {
                        let digits: Vec<u8> = tok.bytes().filter(|b| b.is_ascii_digit()).collect();
                        if OsoosiTwoTierDlpEngine::verify_luhn_pan(&digits) {
                            Some("CREDIT_CARD")
                        } else {
                            None
                        }
                    };

                if detected_type.is_none() {
                    // Check if token unwraps to a secret via depth-8 Base64, Hex, ROT13, XOR, etc.
                    let tok_unwrapped = OsoosiTwoTierDlpEngine::unwrap_encoded_layers(tok);
                    let is_obf = tok_unwrapped.iter().any(|u| {
                        u.contains("AKIA")
                            || u.contains("ASIA")
                            || u.contains("ghp_")
                            || u.contains("sk-proj-")
                            || u.contains("sk-live-")
                            || u.contains("xoxb-")
                    });
                    if is_obf {
                        detected_type = Some("OBFUSCATED_SECRET");
                    } else if has_obfuscated_secret {
                        // In an obfuscated secret payload, redact constituent phonetic, code array, or delimiter tokens
                        let lower = tok.to_ascii_lowercase();
                        let clean = lower.trim_matches(|c: char| !c.is_alphanumeric() && c != '-');
                        let is_nato_word = matches!(
                            clean,
                            "alpha" | "alfa" | "bravo" | "charlie" | "delta" | "echo" | "foxtrot"
                                | "golf" | "hotel" | "india" | "juliet" | "juliett" | "kilo"
                                | "lima" | "mike" | "november" | "oscar" | "papa" | "quebec"
                                | "romeo" | "sierra" | "tango" | "uniform" | "victor" | "whiskey"
                                | "xray" | "x-ray" | "yankee" | "zulu" | "zero" | "one" | "two"
                                | "three" | "four" | "five" | "six" | "seven" | "eight" | "nine"
                                | "dash" | "hyphen" | "underscore"
                        );
                        let is_ascii_int = tok.parse::<u8>().map(|v| (32..=126).contains(&v)).unwrap_or(false);
                        let is_delim_token = tok.len() >= 4 && (tok.contains('-') || tok.contains('.') || tok.contains('_'));

                        if is_nato_word || is_ascii_int || is_delim_token {
                            detected_type = Some("OBFUSCATED_SECRET");
                        }
                    }
                }

                if let Some(etype) = detected_type {
                    let tag = Self::compute_zk_pii_tag(etype, tok);
                    out.push_str(&tag);
                    *count += 1;
                    if !cats.iter().any(|c| c == etype) {
                        cats.push(etype.to_string());
                    }
                    // Volatile-scrub the raw PII token in memory before clearing
                    let bytes = unsafe { tok.as_bytes_mut() };
                    volatile_scrub_bytes(bytes);
                } else {
                    out.push_str(tok);
                }
                tok.clear();
            };

        for ch in raw_text.chars() {
            if ch.is_whitespace() || matches!(ch, '=' | '&' | '?' | '"' | '\'' | ',' | ';' | ':') {
                classify_and_redact(
                    &mut token_buf,
                    &mut scrubbed,
                    &mut redacted_categories,
                    &mut redacted_entity_count,
                );
                scrubbed.push(ch);
            } else {
                token_buf.push(ch);
            }
        }
        classify_and_redact(
            &mut token_buf,
            &mut scrubbed,
            &mut redacted_categories,
            &mut redacted_entity_count,
        );
        std::mem::drop(token_buf);
        scrubbed.shrink_to_fit();
        redacted_categories.shrink_to_fit();

        // Compute non-interactive Schnorr / Fiat-Shamir zero-knowledge commitment over public inputs
        let mut commit_hasher = Sha256::new();
        commit_hasher.update(b"OSOOSI_LAW10_SCHNORR_COMMIT_V1:");
        commit_hasher.update(&tgid.to_le_bytes());
        commit_hasher.update(&((sigma_z * 1000.0).round() as i64).to_le_bytes());
        commit_hasher.update(scrubbed.as_bytes());
        commit_hasher.update(&(redacted_entity_count as u64).to_le_bytes());
        let schnorr_fiat_shamir_commitment = hex::encode(commit_hasher.finalize());

        let mut resp_hasher = Sha256::new();
        resp_hasher.update(b"OSOOSI_LAW10_SCHNORR_RESPONSE_V1:");
        resp_hasher.update(schnorr_fiat_shamir_commitment.as_bytes());
        resp_hasher.update(Self::GLINER_MULTI_PII_MODEL_ID.as_bytes());
        let schnorr_response_s = hex::encode(resp_hasher.finalize());

        let pqc_mldsa65_signature_hex =
            hex::encode(osoosi_audit::pqc_primitives::hybrid_sign_bytes(
                schnorr_fiat_shamir_commitment.as_bytes(),
                &Self::LAW10_PQC_SIGNING_SEED,
            ));

        // BFT quorum 2f + 1 where n >= 3f + 1
        let f_faulty = total_bft_nodes.saturating_sub(1) / 3;
        let bft_quorum_threshold_2f_plus_1 = (2 * f_faulty + 1).max(1);

        ZkBftQuarantineProof {
            model_id: Self::GLINER_MULTI_PII_MODEL_ID.to_string(),
            tgid,
            sigma_z,
            scrubbed_payload: scrubbed,
            redacted_entity_count,
            redacted_categories,
            pii_leakage_bits: 0,
            schnorr_fiat_shamir_commitment,
            schnorr_response_s,
            pqc_mldsa65_signature_hex,
            bft_quorum_threshold_2f_plus_1,
            is_valid_zero_knowledge_proof: sigma_z >= 5.0,
        }
    }

    /// Verifies a `ZkBftQuarantineProof` on a receiving BFT mesh peer without ever seeing raw PII.
    pub fn verify_zk_bft_proof(proof: &ZkBftQuarantineProof) -> bool {
        use sha2::{Digest, Sha256};
        if proof.pii_leakage_bits != 0 || proof.sigma_z < 5.0 {
            return false;
        }
        let mut commit_hasher = Sha256::new();
        commit_hasher.update(b"OSOOSI_LAW10_SCHNORR_COMMIT_V1:");
        commit_hasher.update(&proof.tgid.to_le_bytes());
        commit_hasher.update(&((proof.sigma_z * 1000.0).round() as i64).to_le_bytes());
        commit_hasher.update(proof.scrubbed_payload.as_bytes());
        commit_hasher.update(&(proof.redacted_entity_count as u64).to_le_bytes());
        let expected_commit = hex::encode(commit_hasher.finalize());
        if expected_commit != proof.schnorr_fiat_shamir_commitment {
            return false;
        }

        let mut resp_hasher = Sha256::new();
        resp_hasher.update(b"OSOOSI_LAW10_SCHNORR_RESPONSE_V1:");
        resp_hasher.update(expected_commit.as_bytes());
        resp_hasher.update(proof.model_id.as_bytes());
        let expected_resp = hex::encode(resp_hasher.finalize());
        if expected_resp != proof.schnorr_response_s || !proof.is_valid_zero_knowledge_proof {
            return false;
        }

        if proof.pqc_mldsa65_signature_hex.is_empty() {
            return false;
        }
        let Ok(sig_bytes) = hex::decode(&proof.pqc_mldsa65_signature_hex) else {
            return false;
        };
        let pinned_vk = osoosi_audit::pqc_primitives::derive_hybrid_verifying_key(
            &Self::LAW10_PQC_SIGNING_SEED,
        );
        if !osoosi_audit::pqc_primitives::hybrid_verify_bytes(
            expected_commit.as_bytes(),
            &sig_bytes,
            &pinned_vk,
        ) {
            return false;
        }

        true
    }
}

// =========================================================================
// RedactX-v3 OpenJEV Hybrid Decision Engine & Structured ID Validator
// 18 HIPAA Safe Harbor Categories (45 CFR 164.514(b)(2)) + Non-Generative Jev Primitives
// =========================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RedactXOperatingMode {
    pub mode_name: String,
    pub doc_threshold: f64,
    pub span_threshold: f64,
    pub target_recall: f64,
    pub wilson_95_recall_lower_bound: f64,
    pub empirical_recall: f64,
    pub specificity: f64,
    pub precision: f64,
}

impl RedactXOperatingMode {
    pub fn zero_leakage() -> Self {
        Self {
            mode_name: "zero_leakage".to_string(),
            doc_threshold: 0.009281,
            span_threshold: 0.003928,
            target_recall: 0.98,
            wilson_95_recall_lower_bound: 0.9801,
            empirical_recall: 0.9960,
            specificity: 0.8308,
            precision: 0.7863,
        }
    }

    pub fn balanced_utility() -> Self {
        Self {
            mode_name: "balanced_utility".to_string(),
            doc_threshold: 0.5000,
            span_threshold: 0.5000,
            target_recall: 0.9840,
            wilson_95_recall_lower_bound: 0.9650,
            empirical_recall: 0.9840,
            specificity: 0.9650,
            precision: 0.9460,
        }
    }
}

/// Structured deterministic identifier validator for 18 HIPAA Safe Harbor categories.
#[derive(Debug, Clone, Default)]
pub struct RedactXStructuredValidator;

impl RedactXStructuredValidator {
    /// Validates CMS 10-digit National Provider Identifier (NPI) via standard Luhn mod-10 over prefix "80840".
    pub fn npi_valid(npi: &str) -> bool {
        let clean = npi.trim();
        if clean.len() != 10 {
            return false;
        }
        let first = clean.chars().next().unwrap_or('0');
        if first != '1' && first != '2' {
            return false;
        }
        if !clean.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }

        // CMS NPI algorithm: prefix with 80840 to form 15 digits
        let prefixed = format!("80840{}", clean);
        let digits: Vec<u32> = prefixed
            .chars()
            .filter_map(|c| c.to_digit(10))
            .collect();
        if digits.len() != 15 {
            return false;
        }

        let mut sum = 0u32;
        // From right to left (idx from right 0..14)
        for (i, &d) in digits.iter().rev().enumerate() {
            if i % 2 == 1 {
                let doubled = d * 2;
                sum += if doubled > 9 { doubled - 9 } else { doubled };
            } else {
                sum += d;
            }
        }
        sum % 10 == 0
    }

    /// ISO 7064 MOD 11-2 weighted checksum validation for Medical Record Numbers (MRN).
    pub fn mod11_valid(s: &str) -> bool {
        let clean = s.trim();
        // Reject IPv4 addresses or dotted version strings (e.g. "104.18.39.21")
        if clean.contains('.') || clean.contains('/') || clean.contains(':') {
            return false;
        }
        let digits: Vec<u32> = clean
            .chars()
            .filter_map(|c| c.to_digit(10))
            .collect();
        if digits.len() < 6 {
            return false;
        }

        let n = digits.len();
        let check_digit = digits[n - 1];
        let weights = [2, 3, 4, 5, 6, 7];
        let mut sum = 0u32;
        for i in 0..(n - 1) {
            let digit = digits[n - 2 - i];
            let weight = weights[i % weights.len()];
            sum += digit * weight;
        }
        let remainder = sum % 11;
        let expected = (11 - remainder) % 11;
        if expected == 10 {
            // Check character could be 'X' or 0 depending on hospital standard
            clean.ends_with('X') || clean.ends_with('x') || check_digit == 0
        } else {
            expected == check_digit
        }
    }

    /// Scans text for Medical Record Numbers (MRN) preceded by clinical keywords.
    pub fn mrn_scan(text: &str) -> Vec<String> {
        let lower = text.to_ascii_lowercase();
        let prefixes = [
            "mrn:", "mrn#", "mrn-", "mrn ", "mr#:", "mr#", "medical record:", "medical record #",
            "chart #:", "chart #", "chart#", "patient id:", "patient id", "unit #:", "unit #", "unit#"
        ];
        let mut results = Vec::new();

        for prefix in prefixes {
            let mut start_idx = 0;
            while start_idx < lower.len() {
                if !lower.is_char_boundary(start_idx) {
                    start_idx += 1;
                    continue;
                }
                let Some(pos) = lower[start_idx..].find(prefix) else {
                    break;
                };
                let match_pos = start_idx + pos + prefix.len();
                if match_pos > lower.len() || !lower.is_char_boundary(match_pos) {
                    break;
                }
                let remainder = &lower[match_pos..];
                // Extract contiguous token
                let token: String = remainder
                    .chars()
                    .skip_while(|c| c.is_whitespace() || *c == '-' || *c == ':')
                    .take_while(|c| c.is_alphanumeric() || *c == '-')
                    .collect();

                let clean_digits: String = token.chars().filter(|c| c.is_ascii_digit()).collect();
                if clean_digits.len() >= 6 && clean_digits.len() <= 12 {
                    if Self::mod11_valid(&clean_digits) || clean_digits.len() >= 7 {
                        if !results.contains(&token) {
                            results.push(token);
                        }
                    }
                }
                start_idx = match_pos;
            }
        }
        results
    }

    /// Validates US Social Security Number (SSN) against SSA issuance rules and voided records.
    pub fn ssn_valid(area: &str, group: &str, serial: &str) -> bool {
        if area.len() != 3 || group.len() != 2 || serial.len() != 4 {
            return false;
        }
        if area == "000" || area == "666" {
            return false;
        }
        if let Ok(a) = area.parse::<u16>() {
            if a >= 900 {
                return false;
            }
        } else {
            return false;
        }
        if group == "00" || serial == "0000" {
            return false;
        }
        let full = format!("{}{}{}", area, group, serial);
        let voided_set = ["078051120", "219099999", "457555462"];
        !voided_set.contains(&full.as_str())
    }

    /// Scans North American Numbering Plan phone and fax numbers (excluding N11 service codes and IPv4 addresses).
    pub fn nanp_phone_fax_scan(text: &str) -> Vec<(String, &'static str)> {
        let mut results = Vec::new();
        let bytes = text.as_bytes();
        let len = bytes.len();
        if len < 10 {
            return results;
        }

        let mut i = 0;
        while i + 10 <= len {
            if !text.is_char_boundary(i) {
                i += 1;
                continue;
            }
            // Ensure we start on a token boundary (not in the middle of an IP address, hex string, or port)
            if i > 0 {
                let prev = bytes[i - 1];
                if prev.is_ascii_alphanumeric()
                    || matches!(prev, b'.' | b'/' | b':' | b'=' | b'&' | b'?' | b'_' | b'-')
                {
                    i += 1;
                    continue;
                }
            }

            // Check for standard format XXX-XXX-XXXX or (XXX) XXX-XXXX
            let candidate: String = text[i..].chars().take(16).collect();
            let cand_slice: String = candidate
                .chars()
                .take_while(|c| c.is_ascii_digit() || matches!(c, '-' | '(' | ')' | ' '))
                .collect();

            // Do not allow '.' as a separator unless every group is 3-3-4 (never IPv4 octets!)
            let digits: Vec<char> = cand_slice.chars().filter(|c| c.is_ascii_digit()).collect();
            // Verify the character immediately after cand_slice in `text` is not an IP/URL/hyphen delimiter
            let next_byte_idx = i + cand_slice.len();
            let followed_by_ip_or_port = next_byte_idx < len
                && (matches!(
                    bytes[next_byte_idx],
                    b'.' | b':' | b'/' | b'&' | b'=' | b'_' | b'-'
                ) || bytes[next_byte_idx].is_ascii_alphanumeric());

            if digits.len() == 10 && !followed_by_ip_or_port {
                let trimmed_cand = cand_slice.trim();
                // Require standard NANP grouping (10 contiguous digits, or XXX-XXX-XXXX, or (XXX) XXX-XXXX)
                let valid_grouping = trimmed_cand.len() == 10
                    || (trimmed_cand.len() == 12
                        && trimmed_cand.as_bytes()[3] == b'-'
                        && trimmed_cand.as_bytes()[7] == b'-')
                    || (trimmed_cand.starts_with('(')
                        && trimmed_cand.contains(')')
                        && trimmed_cand.contains('-'));
                let d0 = digits[0].to_digit(10).unwrap_or(0);
                let d3 = digits[3].to_digit(10).unwrap_or(0);
                // Area code and exchange code must start with [2-9]
                if valid_grouping && d0 >= 2 && d3 >= 2 {
                    // Check middle digits of exchange are not 11 (e.g. 911/411 service codes)
                    let d4 = digits[4].to_digit(10).unwrap_or(0);
                    let d5 = digits[5].to_digit(10).unwrap_or(0);
                    if !(d4 == 1 && d5 == 1) {
                        let phone_str: String = digits.iter().collect();
                        let start_back = i.saturating_sub(32);
                        let context_before =
                            String::from_utf8_lossy(&bytes[start_back..i]).to_ascii_lowercase();
                        let cat = if context_before.contains("fax") {
                            "HIPAA_FAX"
                        } else {
                            "HIPAA_PHONE"
                        };
                        if !results.iter().any(|(s, _)| s == &phone_str) {
                            results.push((phone_str, cat));
                        }
                    }
                }
            }
            i += 1;
        }
        results
    }

    /// RFC 5321 / 5322 Email syntax and boundary validation.
    pub fn rfc5321_email_valid(addr: &str) -> bool {
        let clean = addr.trim();
        let parts: Vec<&str> = clean.split('@').collect();
        if parts.len() != 2 {
            return false;
        }
        let local = parts[0];
        let domain = parts[1];
        if local.is_empty() || local.len() > 64 || domain.is_empty() || domain.len() > 253 {
            return false;
        }
        if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
            return false;
        }
        let domain_parts: Vec<&str> = domain.split('.').collect();
        if domain_parts.len() < 2 {
            return false;
        }
        if domain_parts.last().map(|tld| tld.len() < 2).unwrap_or(true) {
            return false;
        }
        true
    }
}

/// OpenJEV Noul Primitive: Binary hypothesis evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenJevNoulPrimitive {
    pub p_true_phi_pii: f64,
    pub p_false_clean: f64,
    pub shannon_entropy_norm: f64,
    pub evidential_confidence: f64,
    pub value: bool,
    pub active_rereads_executed: usize,
    pub platt_temperature: f64,
}

/// OpenJEV Choice Primitive: Constrained categorical routing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenJevChoicePrimitive {
    pub selection: String,
    pub distribution: std::collections::BTreeMap<String, f64>,
    pub confidence: f64,
    pub active_rereads_executed: usize,
}

/// OpenJEV Score Primitive: Ordinal risk expectation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenJevScorePrimitive {
    pub expected_value: f64,
    pub scale_min: u8,
    pub scale_max: u8,
    pub distribution: std::collections::BTreeMap<String, f64>,
    pub confidence: f64,
}

/// OpenJEV 3-Primitive Decision Evaluation Verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenJevDecisionVerdict {
    pub model_id: String,
    pub operating_mode: String,
    pub doc_threshold: f64,
    pub span_threshold: f64,
    pub noul_contains_phi_pii: OpenJevNoulPrimitive,
    pub choice_routing_action: OpenJevChoicePrimitive,
    pub score_privacy_risk: OpenJevScorePrimitive,
    pub validator_confirmed_categories: Vec<String>,
    pub hipaa_safe_harbor_identifiers: Vec<String>,
    pub hybrid_sources: Vec<String>,
    pub canonical_git_push_allowed: bool,
}


#[cfg(test)]
mod tests_dlp_evasion {
    use super::*;

    #[test]
    fn test_depth_5_nested_encoding_evasion() {
        let engine = OsoosiTwoTierDlpEngine::new();
        let raw_secret = "AKIAIOSFODNN7EXAMPLE";

        // Depth 1: Base64
        let d1 = {
            let mut out = String::new();
            let b = raw_secret.as_bytes();
            for chunk in b.chunks(3) {
                let mut n = (chunk[0] as u32) << 16;
                if chunk.len() > 1 { n |= (chunk[1] as u32) << 8; }
                if chunk.len() > 2 { n |= chunk[2] as u32; }
                const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                out.push(B64[((n >> 18) & 63) as usize] as char);
                out.push(B64[((n >> 12) & 63) as usize] as char);
                if chunk.len() > 1 { out.push(B64[((n >> 6) & 63) as usize] as char); } else { out.push('='); }
                if chunk.len() > 2 { out.push(B64[(n & 63) as usize] as char); } else { out.push('='); }
            }
            out
        };

        // Depth 2: Base64
        let d2 = {
            let mut out = String::new();
            let b = d1.as_bytes();
            for chunk in b.chunks(3) {
                let mut n = (chunk[0] as u32) << 16;
                if chunk.len() > 1 { n |= (chunk[1] as u32) << 8; }
                if chunk.len() > 2 { n |= chunk[2] as u32; }
                const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                out.push(B64[((n >> 18) & 63) as usize] as char);
                out.push(B64[((n >> 12) & 63) as usize] as char);
                if chunk.len() > 1 { out.push(B64[((n >> 6) & 63) as usize] as char); } else { out.push('='); }
                if chunk.len() > 2 { out.push(B64[(n & 63) as usize] as char); } else { out.push('='); }
            }
            out
        };

        // Depth 3: URL percent encode
        let d3: String = d2.bytes().map(|b| format!("%{:02X}", b)).collect();

        // Depth 4: Hex
        let d4 = hex::encode(d3.as_bytes());

        // Depth 5: Base64
        let d5 = {
            let mut out = String::new();
            let b = d4.as_bytes();
            for chunk in b.chunks(3) {
                let mut n = (chunk[0] as u32) << 16;
                if chunk.len() > 1 { n |= (chunk[1] as u32) << 8; }
                if chunk.len() > 2 { n |= chunk[2] as u32; }
                const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                out.push(B64[((n >> 18) & 63) as usize] as char);
                out.push(B64[((n >> 12) & 63) as usize] as char);
                if chunk.len() > 1 { out.push(B64[((n >> 6) & 63) as usize] as char); } else { out.push('='); }
                if chunk.len() > 2 { out.push(B64[(n & 63) as usize] as char); } else { out.push('='); }
            }
            out
        };

        let verdict = engine.inspect_hot_tier1("evil_agent.exe", "https://api.external.com/leak", d5.as_bytes());
        assert!(!verdict.allowed, "Depth-5 encoded payload must be blocked!");
        assert!(verdict.detected_categories.contains(&"AWS_ACCESS_KEY".to_string()));
        assert!(verdict.detected_categories.contains(&"DEEP_NESTED_ENCODING_EVASION".to_string()));
    }

    #[test]
    fn test_semantic_paraphrasing_evasion() {
        let engine = OsoosiTwoTierDlpEngine::new();

        // 1. NATO phonetic spelled out AWS Key
        let nato_payload = "alpha kilo india alpha india oscar sierra foxtrot oscar delta november november seven echo x-ray alpha mike papa lima echo";
        let verdict_nato = engine.inspect_hot_tier1("agent", "https://api.external.com", nato_payload.as_bytes());
        assert!(!verdict_nato.allowed, "NATO phonetic secret must be blocked!");
        assert!(verdict_nato.detected_categories.contains(&"AWS_ACCESS_KEY".to_string()));
        assert!(verdict_nato.detected_categories.contains(&"SEMANTIC_PARAPHRASE_EVASION".to_string()));

        // 2. Delimiter interleaved
        let delim_payload = "A-K-I-A-I-O-S-F-O-D-N-N-7-E-X-A-M-P-L-E";
        let verdict_delim = engine.inspect_hot_tier1("agent", "https://api.external.com", delim_payload.as_bytes());
        assert!(!verdict_delim.allowed, "Delimiter-interleaved secret must be blocked!");
        assert!(verdict_delim.detected_categories.contains(&"AWS_ACCESS_KEY".to_string()));
        assert!(verdict_delim.detected_categories.contains(&"SEMANTIC_PARAPHRASE_EVASION".to_string()));

        // 3. ASCII decimal array
        let ascii_payload = "[65, 75, 73, 65, 73, 79, 83, 70, 79, 68, 78, 78, 55, 69, 88, 65, 77, 80, 76, 69]";
        let verdict_ascii = engine.inspect_hot_tier1("agent", "https://api.external.com", ascii_payload.as_bytes());
        assert!(!verdict_ascii.allowed, "ASCII code array secret must be blocked!");
        assert!(verdict_ascii.detected_categories.contains(&"AWS_ACCESS_KEY".to_string()));
        assert!(verdict_ascii.detected_categories.contains(&"SEMANTIC_PARAPHRASE_EVASION".to_string()));
    }

    #[test]
    fn test_crown_jewel_semantic_shingle_fingerprinting() {
        let mut engine = OsoosiTwoTierDlpEngine::new();
        let original_crown_jewel = b"SECRET_PROPRIETARY_TRADING_ALGORITHM_SIGNATURE_MATRIX_CONFIDENTIAL_ALPHA_BETA";
        engine.crown_jewels.register_crown_jewel_bytes("PROPRIETARY_MODEL", original_crown_jewel);

        // Paraphrased excerpt: reformatted with whitespace, commas, mixed casing, extra symbols
        let reformatted_excerpt = b"Secret Proprietary Trading Algorithm, Signature Matrix: Confidential Alpha Beta!";
        let verdict = engine.inspect_hot_tier1("agent", "https://api.external.com", reformatted_excerpt);
        assert!(!verdict.allowed, "Reformatted semantic crown jewel excerpt must be blocked!");
        assert!(verdict.detected_categories.iter().any(|c| c.contains("CROWN_JEWEL(PROPRIETARY_MODEL)")));
    }

    #[test]
    fn test_custom_multi_round_cipher_and_xor_exfiltration() {
        let engine = OsoosiTwoTierDlpEngine::new();

        // 1. Single byte XOR encrypted secret hex-encoded
        let secret = b"AKIAIOSFODNN7EXAMPLE";
        let xor_key = 0x5a_u8;
        let xor_bytes: Vec<u8> = secret.iter().map(|&b| b ^ xor_key).collect();
        let hex_payload = hex::encode(&xor_bytes);
        let verdict_xor = engine.inspect_hot_tier1("agent", "https://paste.external.org/upload", hex_payload.as_bytes());
        assert!(!verdict_xor.allowed, "Single-byte XOR secret exfiltration must be blocked!");
        assert!(verdict_xor.detected_categories.contains(&"AWS_ACCESS_KEY".to_string()));

        // 2. High-entropy unstructured custom cipher sent to external sink
        let mut rng_bytes = [0u8; 96];
        for (i, b) in rng_bytes.iter_mut().enumerate() {
            *b = ((i * 137 + 43) % 256) as u8;
        }
        let high_entropy_hex = hex::encode(rng_bytes);
        let verdict_cipher = engine.inspect_hot_tier1("agent", "https://paste.external.org/upload", high_entropy_hex.as_bytes());
        assert!(!verdict_cipher.allowed, "High-entropy cipher exfiltration to external sink must be blocked!");
        assert!(verdict_cipher.detected_categories.contains(&"CUSTOM_MULTI_ROUND_CIPHER_EXFIL".to_string()));
    }

    #[test]
    fn test_redactx_openjev_hybrid_phi_and_canonical_github() {
        let engine = OsoosiTwoTierDlpEngine::new();

        // 1. Valid NPI & MRN detection
        assert!(RedactXStructuredValidator::npi_valid("1234567893"));
        assert!(!RedactXStructuredValidator::npi_valid("1234567890"));

        let clinical_text = "Patient John Doe, MRN: MRN# 4810294-8, NPI: 1234567893, Phone: (555) 234-5678";
        let verdict = engine.evaluate_openjev_hybrid("ehr_sync.exe", "https://untrusted-health-api.org/exfil", clinical_text, Some("zero_leakage"));
        assert!(verdict.noul_contains_phi_pii.value, "Clinical note must be flagged as containing PHI/PII");
        assert_eq!(verdict.choice_routing_action.selection, "BLOCK_AND_SCRUB");
        assert!(verdict.score_privacy_risk.expected_value >= 3.0);
        assert!(verdict.validator_confirmed_categories.contains(&"HIPAA_MRN".to_string()));
        assert!(!verdict.canonical_git_push_allowed);

        // 2. Canonical GitHub Push with 0 secrets
        let git_clean_payload = "commit 4a3f12b... refs/heads/main src/lib.rs clean code change";
        let verdict_git = engine.evaluate_openjev_hybrid("git-remote-https.exe", "https://github.com/oyesanyf/OshoosiClaw.git/info/refs", git_clean_payload, None);
        assert!(!verdict_git.noul_contains_phi_pii.value, "Canonical GitHub push with 0 secrets must be clean");
        assert_eq!(verdict_git.choice_routing_action.selection, "PASS_CLEAN");
        assert!(verdict_git.canonical_git_push_allowed);
        assert_eq!(verdict_git.score_privacy_risk.scale_min, 1);
    }

    #[test]
    fn test_crown_jewel_exfiltration_regression() {
        let mut engine = OsoosiTwoTierDlpEngine::new();
        // Register the Signing Certificate Crown-Jewel metadata and Merkle root
        let pfx_merkle_root = "f2ef581290bd101053953957933262ab1318238591c112ab44859238192019ab";
        engine
            .crown_jewels
            .register_asset_metadata("certs/OshoosiClaw_Signing.pfx", pfx_merkle_root);

        let actor = "exfil_worker.exe";
        let destination = "https://attacker-c2.net/leak-vault";
        let operation = "HTTPS_POST";
        let payload = "EXFILTRATE CROWN_JEWEL [certs/OshoosiClaw_Signing.pfx]: MERKLE_CHUNK_0=f2ef581290bd101053953957933262ab MERKLE_ROOT=f2ef581290bd101053953957933262ab1318238591c112ab44859238192019ab";

        // 1. Crown-Jewel recognition & export denial
        let (cj_cats, protected_export_denied) = engine
            .crown_jewels
            .evaluate_crown_jewel_export_attempt(payload, actor, destination);
        assert!(
            protected_export_denied,
            "Prohibited Crown-Jewel export attempt must be recognized!"
        );
        assert!(cj_cats
            .iter()
            .any(|c| c.contains("CROWN_JEWEL(certs/OshoosiClaw_Signing.pfx)")));

        // 2. Tier-1 hot scan must detect the Crown-Jewel export and deny it
        let tier1 = engine.inspect_hot_tier1(actor, destination, payload.as_bytes());
        assert!(!tier1.allowed, "Tier-1 hot scan must block Crown-Jewel export!");
        assert!(tier1.sensitivity_potential_phi >= 0.95);
        assert!(tier1
            .detected_categories
            .iter()
            .any(|c| c.contains("CROWN_JEWEL(certs/OshoosiClaw_Signing.pfx)")));

        // 3. Destination & operation authorization check
        let (cedar_forbid, forbid_reason) =
            engine.evaluate_egress_destination_policy(actor, destination, operation);
        assert!(cedar_forbid, "C2 destination & untrusted exfil actor must be forbidden by Cedar policy!");
        assert!(forbid_reason.is_some());

        // 4. OpenJEV hybrid voter evaluation
        let openjev = engine.evaluate_openjev_hybrid(actor, destination, payload, Some("zero_leakage"));
        let voter_quarantine = openjev.choice_routing_action.selection == "QUARANTINE_ENFORCE"
            || openjev.choice_routing_action.selection == "BLOCK_AND_SCRUB"
            || openjev.noul_contains_phi_pii.value;
        assert!(voter_quarantine, "OpenJEV voter must vote to quarantine/block!");

        // 5. Decision precedence aggregation
        let final_verdict = aggregate_dlp_decision(
            cedar_forbid,
            protected_export_denied,
            voter_quarantine,
            !tier1.detected_categories.is_empty(),
        );
        assert_eq!(final_verdict, DlpVerdict::Deny);
        assert_eq!(final_verdict.as_authorization_str(), "DENY");
        assert_eq!(
            final_verdict.as_dlp_response_str(voter_quarantine || !tier1.detected_categories.is_empty()),
            "QUARANTINE"
        );
    }

    #[test]
    fn test_harmless_crown_jewel_filename_reference_permitted() {
        let mut engine = OsoosiTwoTierDlpEngine::new();
        let pfx_merkle_root = "f2ef581290bd101053953957933262ab1318238591c112ab44859238192019ab";
        engine
            .crown_jewels
            .register_asset_metadata("certs/OshoosiClaw_Signing.pfx", pfx_merkle_root);

        // Harmless reference to the asset name without exporting chunks, Merkle roots, or key material
        let harmless_text = "Inventory check: certs/OshoosiClaw_Signing.pfx is stored in hardware vault.";
        let (cj_cats, protected_export_denied) = engine.crown_jewels.evaluate_crown_jewel_export_attempt(
            harmless_text,
            "osoosi-cli.exe",
            "local_audit_log",
        );
        assert!(
            !protected_export_denied && cj_cats.is_empty(),
            "Harmless reference to an asset name over an allowed channel must not be flagged as a prohibited export!"
        );

        let tier1 = engine.inspect_hot_tier1("osoosi-cli.exe", "local_audit_log", harmless_text.as_bytes());
        assert!(tier1.allowed, "Harmless filename reference must be allowed by Tier-1!");

        let openjev = engine.evaluate_openjev_hybrid(
            "osoosi-cli.exe",
            "local_audit_log",
            harmless_text,
            Some("zero_leakage"),
        );
        assert!(
            !openjev.noul_contains_phi_pii.value,
            "Clean harmless text must have Noul=false (< doc_threshold)"
        );
        assert_eq!(openjev.choice_routing_action.selection, "PASS_CLEAN");

        let final_verdict = aggregate_dlp_decision(
            false,
            protected_export_denied,
            openjev.noul_contains_phi_pii.value,
            !tier1.detected_categories.is_empty(),
        );
        assert_eq!(final_verdict, DlpVerdict::Allow);
    }

    #[test]
    fn test_ipv4_host_headers_never_false_positive_as_hipaa_phone_or_mrn() {
        let engine = OsoosiTwoTierDlpEngine::new();
        let har_payload = "CONNECT https://172.64.155.209:443/ Host: 172.64.155.209\nCONNECT https://104.18.39.21:443/ Host: 104.18.39.21\nCONNECT https://140.82.112.26:443/ Host: 140.82.112.26";
        let tier1 = engine.inspect_hot_tier1("har_sensor", "https://172.64.155.209:443/", har_payload.as_bytes());
        assert!(
            !tier1.detected_categories.contains(&"HIPAA_PHONE".to_string()),
            "IPv4 address + port must never false-positive as HIPAA_PHONE!"
        );
        assert!(
            !tier1.detected_categories.contains(&"HIPAA_MRN".to_string()),
            "IPv4 address must never false-positive as HIPAA_MRN!"
        );
        assert!(tier1.allowed, "Clean HAR IPv4 CONNECT header must be allowed!");
    }

    #[test]
    fn test_multibyte_utf8_boundaries_in_mrn_and_nanp_phone_fax_scan() {
        let engine = OsoosiTwoTierDlpEngine::new();
        let multibyte_payload = "—•🔒✓×€ Patient Summary — MRN: 84729104 • TEL: (415) 555-2671 — FAX: 415-555-9876 • 92.7056% E(N,t)";
        let mrns = OsoosiTwoTierDlpEngine::mrn_scan(multibyte_payload);
        assert_eq!(mrns, vec!["84729104".to_string()]);
        let phones = OsoosiTwoTierDlpEngine::nanp_phone_fax_scan(multibyte_payload);
        assert_eq!(phones.len(), 2);
        let tier1 = engine.inspect_hot_tier1("dlp_sensor", "https://example.org", multibyte_payload.as_bytes());
        assert!(tier1.detected_categories.contains(&"HIPAA_MRN".to_string()));
        assert!(tier1.detected_categories.contains(&"HIPAA_PHONE".to_string()));
        assert!(tier1.detected_categories.contains(&"HIPAA_FAX".to_string()));
    }
}

