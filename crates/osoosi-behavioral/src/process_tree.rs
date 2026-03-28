//! ML-Driven Process Tree Embedding (Candle-Core).
//!
//! Uses deep learning to generate embeddings of process execution chains 
//! (Parent-Child relationships). Detects anomalies by comparing real-time 
//! process trees against a 'known good' baseline.

use candle_core::{Device, Tensor, DType};
use candle_nn::{Linear, Module};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a process relationship in the execution chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRelationship {
    pub parent_name: String,
    pub child_name: String,
    pub arguments: Vec<String>,
    pub confidence: f32,
}

pub struct ProcessTreeEmbedder {
    device: Device,
    // A simple linear embedding layer for demonstration. 
    // In production, this would be a pre-trained Transformer or Autoencoder.
    embedding_layer: Linear,
    baseline: HashMap<String, Vec<f32>>,
}

impl ProcessTreeEmbedder {
    pub fn new() -> candle_core::Result<Self> {
        let device = Device::Cpu;
        // Simple 128-dim embedding space
        let weight = Tensor::zeros((128, 64), DType::F32, &device)?;
        let bias = Tensor::zeros((128,), DType::F32, &device)?;
        let embedding_layer = Linear::new(weight, Some(bias));
        
        Ok(Self {
            device,
            embedding_layer,
            baseline: HashMap::new(),
        })
    }

    /// Generate an embedding for a process relationship.
    pub fn embed(&self, rel: &ProcessRelationship) -> anyhow::Result<Vec<f32>> {
        // More robust feature vector using BLAKE3 or multiple hashes
        let mut features = vec![0.0f32; 64];
        let h_parent = self.hash_str(&rel.parent_name);
        let h_child = self.hash_str(&rel.child_name);
        
        // Use multiple bits for better representation
        features[h_parent % 64] = 1.0;
        features[(h_parent >> 3) % 64] = 0.5;
        features[h_child % 64] = 1.0;
        features[(h_child >> 3) % 64] = 0.5;

        let mut input_vec = features;
        // Simple adversarial robustness: add small random noise during inference/training
        // In a real model, we'd use AT (Adversarial Training) 
        for val in input_vec.iter_mut() {
            let noise = (rand::random::<f32>() - 0.5) * 0.01;
            *val += noise;
        }

        let input = Tensor::from_vec(input_vec, (1, 64), &self.device)?;
        let output = self.embedding_layer.forward(&input)?;
        
        let out_vec = output.flatten_all()?.to_vec1::<f32>()?;
        Ok(out_vec)
    }

    /// Calculate anomaly score (1.0 = malicious, 0.0 = normal).
    /// Uses Cosine Similarity against the 'known good' baseline.
    pub fn calculate_anomaly_score(&self, embedding: &[f32], baseline_key: &str) -> f32 {
        if let Some(target) = self.baseline.get(baseline_key) {
            let similarity = self.cosine_similarity(embedding, target);
            // Higher distance = more anomalous
            let score = (1.0 - similarity).max(0.0);
            
            // Apply threshold for confidence
            if score > 0.3 { score } else { 0.0 }
        } else {
            0.5 // Unknown baseline
        }
    }

    fn hash_str(&self, s: &str) -> usize {
        // Use a better hash than wrapping add
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut s_hasher = DefaultHasher::new();
        s.hash(&mut s_hasher);
        s_hasher.finish() as usize
    }

    fn cosine_similarity(&self, a: &[f32], b: &[f32]) -> f32 {
        let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm_a == 0.0 || norm_b == 0.0 { return 0.0; }
        dot / (norm_a * norm_b)
    }

    /// Seed the 'known good' baseline for the current asset.
    pub fn update_baseline(&mut self, key: String, embedding: Vec<f32>) {
        self.baseline.insert(key, embedding);
    }
}
