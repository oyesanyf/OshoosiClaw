//! Model training and inference using self + peer data.

use osoosi_types::ThreatSignature;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::{info, debug};

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
        let mut model = Self { 
            config, 
            weights: ModelWeights::default() 
        };
        let _ = model.load();
        model
    }

    /// Load and merge all available threat intelligence models.
    pub fn load(&mut self) -> anyhow::Result<()> {
        // 1. Load manual threat model
        let manual_path = Path::new(&self.config.models_dir).join("threat_model.json");
        if manual_path.exists() {
            if let Ok(data) = std::fs::read_to_string(&manual_path) {
                if let Ok(w) = serde_json::from_str::<ModelWeights>(&data) {
                    self.weights = w;
                    debug!("Loaded manual threat model weights.");
                }
            }
        }

        // 2. Load and merge bulk threat model (The 100k Brain)
        let bulk_path = Path::new(&self.config.models_dir).join("bulk_threat_model.json");
        if bulk_path.exists() {
            if let Ok(data) = std::fs::read_to_string(&bulk_path) {
                if let Ok(bulk_w) = serde_json::from_str::<ModelWeights>(&data) {
                    debug!("Integrating {} bulk-trained CVE features into threat model.", bulk_w.features.len());
                    for (feat, &weight) in &bulk_w.features {
                        // Merge logic: Average or Insert
                        // Merge logic: Weighted Blend if exists, otherwise Insert
                        let entry = self.weights.features.entry(feat.clone()).or_insert(weight);
                        if *entry != weight {
                            *entry = (*entry + weight) / 2.0;
                        }
                    }
                    self.weights.sample_count += bulk_w.sample_count;
                }
            }
        }

        Ok(())
    }

    fn model_path(&self) -> std::path::PathBuf {
        Path::new(&self.config.models_dir).join(&self.config.model_file)
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
        if let Some(ref parent) = sig.parent_process {
            f.push(format!("parent:{}", parent.to_lowercase()));
        }
        if let Some(ref v) = sig.version {
            if let Some(ref p) = sig.process_name {
                f.push(format!("ver:{}:{}", p.to_lowercase(), v.to_lowercase()));
            }
        }
        if let Some(ref c) = sig.cve_id {
            f.push(format!("cve:{}", c.to_lowercase()));
        }
        f.push(format!("source:{}", sig.source_node.to_lowercase()));
        f
    }

    /// Train model on provided labeled samples.
    pub fn train(&mut self, samples: Vec<ThreatSignature>) -> anyhow::Result<()> {
        if samples.len() < self.config.min_samples {
            return Ok(());
        }
        for sig in &samples {
            let features = Self::features_from_signature(sig);
            for feat in features {
                let entry = self.weights.features.entry(feat).or_insert(0.0);
                // Simple online learning: increase weight for confirmed threats
                if sig.confidence > 0.7 {
                    *entry = (*entry + sig.confidence) / 2.0;
                }
            }
        }
        self.weights.sample_count = samples.len();
        self.weights.trained_at = Some(chrono::Utc::now().to_rfc3339());
        self.save()?;
        debug!(
            "Trained model on {} samples, {} features",
            samples.len(),
            self.weights.features.len()
        );
        Ok(())
    }

    /// Add a single training sample (online learning).
    pub fn add_training_sample(&mut self, sig: &ThreatSignature) {
        let features = Self::features_from_signature(sig);
        for feat in features {
            let entry = self.weights.features.entry(feat).or_insert(0.0);
            if sig.confidence > 0.7 {
                // Online learning update rule
                *entry = (*entry + sig.confidence) / 2.0;
            }
        }
        self.weights.sample_count += 1;
    }

    /// Infer threat score for given features (process_name, cve_id, version, lineage).
    pub fn infer(&self, process_name: Option<&str>, cve_id: Option<&str>, version: Option<&str>, lineage: Vec<String>) -> f32 {
        let mut score = 0.0f32;

        if let Some(p) = process_name {
            let p_low = p.to_lowercase();
            
            // 1. Version-Specific Risk
            if let Some(v) = version {
                let ver_key = format!("ver:{}:{}", p_low, v.to_lowercase());
                if let Some(&ver_score) = self.weights.features.get(&ver_key) {
                    score += ver_score;
                }
            }

            // 2. General Process-Level Risk
            let proc_key = format!("proc:{}", p_low);
            score += self.weights.features.get(&proc_key).copied().unwrap_or(0.0);
        }

        // 3. Lineage/Parent Process Risk (Examine the entire tree)
        for parent in lineage {
            let parent_key = format!("parent:{}", parent.to_lowercase());
            if let Some(&p_score) = self.weights.features.get(&parent_key) {
                // Compound risk: multiple suspicious parents increase total score
                score += p_score;
            }
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
        self.load()
    }

    /// Federated Learning: Merge a delta from a peer node.
    pub fn merge_delta(&mut self, delta: &osoosi_types::FederatedModelDelta) {
        debug!(
            "Merging federated model delta from Node {} ({} features)",
            delta.source_node,
            delta.features.len()
        );
        for (feat, &weight) in &delta.features {
            let entry = self.weights.features.entry(feat.clone()).or_insert(0.0);
            // Influence blending: Give peer data significant weight
            *entry = (*entry + weight) / 2.0;
        }
    }

    /// Generate a delta of the current model for broadcast.
    pub fn delta(&self, node_id: &str) -> osoosi_types::FederatedModelDelta {
        osoosi_types::FederatedModelDelta {
            source_node: node_id.to_string(),
            features: self.weights.features.clone(),
            epsilon: self.config.dp_config.as_ref().map(|c| c.epsilon).unwrap_or(0.0),
            timestamp: chrono::Utc::now(),
        }
    }
}
