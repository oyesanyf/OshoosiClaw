//! Differential Privacy (DP) Utility for OpenỌ̀ṣọ́ọ̀sì.
//!
//! Provides Laplacian noise generation and privacy budget management.

pub mod homomorphic;
pub mod psi;

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
        let u: f32 = rng.gen_range(-0.5..0.5);
        let scale = self.config.sensitivity / self.config.epsilon;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noise_range() {
        let dp = DifferentialPrivacy::new(PrivacyConfig::default());
        let noise = dp.laplace_noise();
        // Just verify it doesn't crash and returns a value
        assert!(!noise.is_nan());
    }
}
