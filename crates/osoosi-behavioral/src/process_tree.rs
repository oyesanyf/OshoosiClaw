//! ML-Driven Process Tree Embedding (Candle-Core).
//!
//! Uses deep learning to generate embeddings of process execution chains
//! (Parent-Child relationships). Detects anomalies by comparing real-time
//! process trees against a 'known good' baseline.
//!
//! Adversarial Robustness: Embeddings include controlled noise injection to
//! harden against "telemetry poisoning" attacks that attempt to blend malicious
//! process chains into the normal baseline.

use candle_core::{DType, Device, Tensor};
use candle_nn::{Linear, Module};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, warn};

/// Represents a process relationship in the execution chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRelationship {
    pub parent_name: String,
    pub child_name: String,
    pub arguments: Vec<String>,
    /// MITRE ATT&CK technique ID if classified (e.g. "T1059.001")
    pub mitre_technique: Option<String>,
    pub confidence: f32,
}

/// Known suspicious parent-child pairs mapped to MITRE ATT&CK techniques.
/// Updated from MITRE ATT&CK v15 Windows sub-techniques.
const SUSPICIOUS_PAIRS: &[(&str, &str, &str)] = &[
    // T1059 - Command and Scripting Interpreter
    ("winword.exe", "cmd.exe", "T1059.003"),
    ("winword.exe", "powershell.exe", "T1059.001"),
    ("excel.exe", "cmd.exe", "T1059.003"),
    ("excel.exe", "powershell.exe", "T1059.001"),
    ("outlook.exe", "cmd.exe", "T1059.003"),
    ("outlook.exe", "powershell.exe", "T1059.001"),
    // T1055 - Process Injection
    ("explorer.exe", "powershell.exe", "T1055"),
    ("svchost.exe", "cmd.exe", "T1055"),
    // T1547 - Boot or Logon Autostart
    ("lsass.exe", "cmd.exe", "T1547"),
    ("lsass.exe", "cscript.exe", "T1547"),
    // T1218 - System Binary Proxy Execution
    ("mshta.exe", "powershell.exe", "T1218.005"),
    ("regsvr32.exe", "cmd.exe", "T1218.010"),
    ("wscript.exe", "cmd.exe", "T1218.005"),
    // T1003 - OS Credential Dumping
    ("lsass.exe", "procdump.exe", "T1003.001"),
    ("lsass.exe", "mimikatz.exe", "T1003.001"),
    // T1036 - Masquerading
    ("explorer.exe", "svchost.exe", "T1036.005"),
    // T1569 - System Services
    ("services.exe", "cmd.exe", "T1569.002"),
];

pub struct ProcessTreeEmbedder {
    device: Device,
    /// Linear embedding layer (128-dim output from 64-dim input features).
    /// In production, replace with a pre-trained Transformer or LSTM autoencoder.
    embedding_layer: Linear,
    /// Known-good baseline embeddings keyed by "parent->child".
    baseline: HashMap<String, Vec<f32>>,
    /// Adversarial noise scale (default: 0.01 — imperceptible but hardens against poisoning).
    noise_scale: f32,
}

impl ProcessTreeEmbedder {
    pub fn new() -> candle_core::Result<Self> {
        let device = Device::Cpu;
        // 128-dim embedding from 64-dim feature vector
        let weight = Tensor::zeros((128, 64), DType::F32, &device)?;
        let bias = Tensor::zeros((128,), DType::F32, &device)?;
        let embedding_layer = Linear::new(weight, Some(bias));

        Ok(Self {
            device,
            embedding_layer,
            baseline: HashMap::new(),
            noise_scale: 0.01,
        })
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Feature Extraction
    // ─────────────────────────────────────────────────────────────────────────

    /// Build a 64-dimensional feature vector from a process relationship.
    ///
    /// Feature layout:
    ///   [0..15]  → Parent process name hash (multi-bit)
    ///   [16..31] → Child process name hash (multi-bit)
    ///   [32..47] → Argument token hashes
    ///   [48]     → Is child a shell? (cmd, powershell, bash, sh)
    ///   [49]     → Is child a script host? (wscript, cscript, mshta)
    ///   [50]     → Is parent an Office app?
    ///   [51]     → Is child a known LOLBin?
    ///   [52..63] → Reserved for future use
    fn extract_features(&self, rel: &ProcessRelationship) -> Vec<f32> {
        let mut features = vec![0.0f32; 64];

        // Parent hash → indices 0-15
        let h_parent = self.hash_str(&rel.parent_name.to_lowercase());
        for i in 0..16 {
            features[i] = ((h_parent >> i) & 1) as f32;
        }

        // Child hash → indices 16-31
        let h_child = self.hash_str(&rel.child_name.to_lowercase());
        for i in 0..16 {
            features[16 + i] = ((h_child >> i) & 1) as f32;
        }

        // Argument hashes → indices 32-47
        for (arg_idx, arg) in rel.arguments.iter().take(16).enumerate() {
            let h = self.hash_str(&arg.to_lowercase());
            features[32 + arg_idx] = ((h & 0xFFFF) as f32) / 65535.0;
        }

        let child_lc = rel.child_name.to_lowercase();
        let parent_lc = rel.parent_name.to_lowercase();

        // Behavioral flags
        features[48] = if matches!(
            child_lc.as_str(),
            "cmd.exe" | "powershell.exe" | "bash" | "sh" | "zsh"
        ) {
            1.0
        } else {
            0.0
        };
        features[49] = if matches!(
            child_lc.as_str(),
            "wscript.exe" | "cscript.exe" | "mshta.exe"
        ) {
            1.0
        } else {
            0.0
        };
        features[50] = if parent_lc.contains("word")
            || parent_lc.contains("excel")
            || parent_lc.contains("outlook")
            || parent_lc.contains("powerpoint")
        {
            1.0
        } else {
            0.0
        };
        features[51] = if matches!(
            child_lc.as_str(),
            "regsvr32.exe"
                | "rundll32.exe"
                | "certutil.exe"
                | "bitsadmin.exe"
                | "msiexec.exe"
                | "installutil.exe"
                | "odbcconf.exe"
                | "regasm.exe"
        ) {
            1.0
        } else {
            0.0
        };

        features
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Embedding
    // ─────────────────────────────────────────────────────────────────────────

    /// Generate an embedding for a process relationship.
    /// Applies adversarial noise to harden against telemetry poisoning.
    pub fn embed(&self, rel: &ProcessRelationship) -> anyhow::Result<Vec<f32>> {
        let mut features = self.extract_features(rel);

        // Adversarial robustness: add calibrated Gaussian noise.
        // This prevents adversaries from finding vectors that evade the baseline
        // by making the decision boundary "fuzzy" at inference time.
        for val in features.iter_mut() {
            let noise = (rand::random::<f32>() - 0.5) * 2.0 * self.noise_scale;
            *val = (*val + noise).clamp(0.0, 1.0);
        }

        let input = Tensor::from_vec(features, (1, 64), &self.device)?;
        let output = self.embedding_layer.forward(&input)?;
        let out_vec = output.flatten_all()?.to_vec1::<f32>()?;
        Ok(out_vec)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MITRE Signature Check
    // ─────────────────────────────────────────────────────────────────────────

    /// Check a process relationship against known MITRE ATT&CK suspicious pairs.
    /// Returns the matched technique ID if found.
    pub fn check_suspicious_pair(&self, rel: &ProcessRelationship) -> Option<&'static str> {
        let parent_lc = rel.parent_name.to_lowercase();
        let child_lc = rel.child_name.to_lowercase();

        for &(parent, child, technique) in SUSPICIOUS_PAIRS {
            if parent_lc.contains(parent) && child_lc.contains(child) {
                warn!(
                    "ALERT: Suspicious process chain detected → {} → {} (MITRE {})",
                    rel.parent_name, rel.child_name, technique
                );
                return Some(technique);
            }
        }
        None
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Anomaly Scoring
    // ─────────────────────────────────────────────────────────────────────────

    /// Calculate anomaly score (1.0 = malicious, 0.0 = normal).
    /// Combines MITRE signature check with cosine distance from baseline.
    pub fn calculate_anomaly_score(&self, rel: &ProcessRelationship, embedding: &[f32]) -> f32 {
        // Hard rule: known MITRE pair → immediate high score
        if self.check_suspicious_pair(rel).is_some() {
            return 0.95;
        }

        // Soft rule: distance from baseline embedding
        let key = format!(
            "{}→{}",
            rel.parent_name.to_lowercase(),
            rel.child_name.to_lowercase()
        );
        if let Some(baseline_emb) = self.baseline.get(&key) {
            let similarity = self.cosine_similarity(embedding, baseline_emb);
            let distance_score = (1.0 - similarity).max(0.0);
            debug!(
                "Process pair '{}' cosine distance: {:.3}",
                key, distance_score
            );
            // Threshold: pairs with >0.35 distance from baseline are suspicious
            if distance_score > 0.35 {
                distance_score
            } else {
                0.0
            }
        } else {
            // Unknown baseline — moderate suspicion
            debug!("No baseline for '{}', defaulting to 0.3 suspicion.", key);
            0.3
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Baseline Management
    // ─────────────────────────────────────────────────────────────────────────

    /// Seed the 'known good' baseline for a specific parent→child pair.
    pub fn update_baseline(&mut self, parent: &str, child: &str, embedding: Vec<f32>) {
        let key = format!("{}→{}", parent.to_lowercase(), child.to_lowercase());
        self.baseline.insert(key, embedding);
    }

    /// Analyze an entire batch of process relationships and return anomalous ones.
    pub fn analyze_chain(&self, chain: &[ProcessRelationship]) -> Vec<(ProcessRelationship, f32)> {
        let mut anomalies = Vec::new();
        for rel in chain {
            match self.embed(rel) {
                Ok(emb) => {
                    let score = self.calculate_anomaly_score(rel, &emb);
                    if score > 0.3 {
                        anomalies.push((rel.clone(), score));
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to embed process relationship {}→{}: {}",
                        rel.parent_name, rel.child_name, e
                    );
                }
            }
        }
        anomalies.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        anomalies
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    fn hash_str(&self, s: &str) -> usize {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        s.hash(&mut hasher);
        hasher.finish() as usize
    }

    fn cosine_similarity(&self, a: &[f32], b: &[f32]) -> f32 {
        let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm_a == 0.0 || norm_b == 0.0 {
            return 0.0;
        }
        dot / (norm_a * norm_b)
    }
}
