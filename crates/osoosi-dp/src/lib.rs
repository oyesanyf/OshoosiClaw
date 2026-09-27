//! Differential Privacy (DP) Utility for OpenỌ̀ṣọ́ọ̀sì.
//!
//! Provides Laplacian noise generation and privacy budget management.

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

/// Differential Privacy Laplace Noise Engine for Local Telemetry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalTelemetryNoiseEngine {
    pub epsilon: f64,
    pub sensitivity: f64,
}

impl LocalTelemetryNoiseEngine {
    pub fn new(epsilon: f64, sensitivity: f64) -> Self {
        Self {
            epsilon,
            sensitivity,
        }
    }

    /// Inverse CDF sampling for Laplace distribution: L(0, sensitivity / epsilon).
    pub fn sample_laplace(&self) -> f64 {
        let scale = self.sensitivity / self.epsilon;
        let mut u: f64 = fastrand::f64() - 0.5;
        // Guard against boundary values +/-0.5 to prevent ln(0)
        if u.abs() >= 0.5 {
            u = u.signum() * 0.4999999999999999;
        }
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
        counts.iter().map(|&c| self.privatize_count(c as u64)).collect()
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
            assert!(priv_count >= 0.0, "Count must be non-negative: {}", priv_count);

            let priv_zero = engine.privatize_count(0);
            assert!(priv_zero >= 0.0, "Zero count must be non-negative: {}", priv_zero);

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
}

