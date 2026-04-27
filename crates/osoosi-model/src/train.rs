//! Model training and inference using self + peer data.

use osoosi_types::ThreatSignature;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::{info, warn};

/// Configuration for model storage and training.
#[derive(Debug, Clone)]
pub struct ModelConfig {
    /// Directory to store models (default: ./models)
    pub models_dir: String,
    /// Minimum samples before training
    pub min_samples: usize,
    /// Model filename
    pub model_file: String,
    /// Differential Privacy configuration
    pub dp_config: Option<osoosi_dp::PrivacyConfig>,
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            models_dir: "models".to_string(),
            min_samples: 10,
            model_file: "threat_model.json".to_string(),
            dp_config: Some(osoosi_dp::PrivacyConfig {
                epsilon: 1.0,
                min_samples: 5,
                sensitivity: 1.0,
            }),
        }
    }
}

/// Serializable model format (feature -> weight).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModelWeights {
    pub features: HashMap<String, f32>,
    pub trained_at: Option<String>,
    pub sample_count: usize,
}

/// Local threat model trained on self + peer data.
pub struct ThreatModel {
    config: ModelConfig,
    weights: ModelWeights,
}

impl ThreatModel {
    pub fn new(config: ModelConfig) -> Self {
        let weights = Self::load_weights(&config).unwrap_or_default();
        Self { config, weights }
    }

    fn model_path(&self) -> std::path::PathBuf {
        Path::new(&self.config.models_dir).join(&self.config.model_file)
    }

    /// Load weights from models/ folder.
    fn load_weights(config: &ModelConfig) -> anyhow::Result<ModelWeights> {
        let path = Path::new(&config.models_dir).join(&config.model_file);
        if path.exists() {
            let data = std::fs::read_to_string(&path)?;
            let w: ModelWeights = serde_json::from_str(&data)?;
            info!(
                "Loaded threat model from {} ({} features)",
                path.display(),
                w.features.len()
            );
            Ok(w)
        } else {
            Err(anyhow::anyhow!("Model file not found"))
        }
    }

    /// Save weights to models/ folder.
    pub fn save(&self) -> anyhow::Result<()> {
        let path = self.model_path();
        std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")))?;
        let data = serde_json::to_string_pretty(&self.weights)?;
        std::fs::write(&path, data)?;
        info!("Saved threat model to {}", path.display());
        Ok(())
    }

    /// Extract features from a threat signature (for training).
    fn features_from_signature(sig: &ThreatSignature) -> Vec<String> {
        let mut f = Vec::new();
        if let Some(ref p) = sig.process_name {
            f.push(format!("proc:{}", p.to_lowercase()));
        }
        if let Some(ref c) = sig.cve_id {
            f.push(format!("cve:{}", c.to_lowercase()));
        }
        f.push(format!("source:{}", sig.source_node.to_lowercase()));
        f
    }

    /// Add a threat signature to training data and optionally retrain.
    pub fn add_training_sample(&mut self, sig: &ThreatSignature) {
        // Avoid model poisoning: don't learn from detections of trusted operational tools (git, node, etc.)
        // as these are likely noise or previous false positives that entered the gossip mesh.
        if let Some(ref p) = sig.process_name {
            let p = p.to_lowercase();
            if p == "git.exe" || p == "node.exe" || p == "python.exe" || p == "net.exe" || p == "osoosi.exe" {
                return;
            }
        }

        let features = Self::features_from_signature(sig);
        for feat in &features {
            *self.weights.features.entry(feat.clone()).or_insert(0.0) += sig.confidence;
        }
        self.weights.sample_count += 1;
    }

    /// Train from a batch of threat signatures (self + peer data).
    pub fn train(&mut self, samples: &[ThreatSignature]) -> anyhow::Result<()> {
        if samples.len() < self.config.min_samples {
            warn!(
                "Not enough samples to train ({} < {}). For development, lower the threshold with OSOOSI_MODEL_MIN_SAMPLES.",
                samples.len(),
                self.config.min_samples
            );
            return Ok(());
        }

        let mut feature_counts: HashMap<String, f32> = HashMap::new();
        for sig in samples {
            let features = Self::features_from_signature(sig);
            for feat in features {
                *feature_counts.entry(feat).or_insert(0.0) += sig.confidence;
            }
        }

        // Normalize: weight = count / total
        let total: f32 = feature_counts.values().sum();
        if total > 0.0 {
            for (_k, v) in feature_counts.iter_mut() {
                *v /= total;
            }
        }

        // Apply Differential Privacy if configured
        if let Some(ref dp_conf) = self.config.dp_config {
            let dp = osoosi_dp::DifferentialPrivacy::new(dp_conf.clone());
            dp.privatize_weights(&mut feature_counts);
            info!(
                "Applied Differential Privacy (epsilon={}) to model weights",
                dp_conf.epsilon
            );
        }

        self.weights.features = feature_counts;
        self.weights.sample_count = samples.len();
        self.weights.trained_at = Some(chrono::Utc::now().to_rfc3339());
        self.save()?;
        info!(
            "Trained model on {} samples, {} features",
            samples.len(),
            self.weights.features.len()
        );
        Ok(())
    }

    /// Infer threat score for given features (process_name, cve_id, etc).
    pub fn infer(&self, process_name: Option<&str>, cve_id: Option<&str>) -> f32 {
        let mut score = 0.0f32;
        if let Some(p) = process_name {
            let key = format!("proc:{}", p.to_lowercase());
            score += self.weights.features.get(&key).copied().unwrap_or(0.0);
        }
        if let Some(c) = cve_id {
            let key = format!("cve:{}", c.to_lowercase());
            score += self.weights.features.get(&key).copied().unwrap_or(0.0);
        }
        score.min(1.0)
    }

    /// Get current weights (for inspection).
    pub fn weights(&self) -> &ModelWeights {
        &self.weights
    }

    /// Reload model from disk.
    pub fn reload(&mut self) -> anyhow::Result<()> {
        self.weights = Self::load_weights(&self.config)?;
        Ok(())
    }

    /// Federated Learning: Merge a delta from a peer node.
    pub fn merge_delta(&mut self, delta: &osoosi_types::FederatedModelDelta) {
        info!(
            "Merging federated model delta from Node {} ({} features)",
            delta.source_node,
            delta.features.len()
        );

        for (feat, weight) in &delta.features {
            let entry = self.weights.features.entry(feat.clone()).or_insert(0.0);
            // Average the weights (simplistic Federated Averaging)
            *entry = (*entry + *weight) / 2.0;
        }

        self.weights.sample_count += 1;
        let _ = self.save();
    }
}
