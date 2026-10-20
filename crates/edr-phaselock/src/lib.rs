//! # Crate 1: Nonlinear Dynamics for EDR Telemetry (`edr-phaselock`)
//!
//! Defeats spaced-out malicious system calls and Living-off-the-Land (LOLBin) pacing by applying
//! **Takens' Delay Embedding Theorem** and **Rosenstein's Maximal Lyapunov Exponent ($\lambda_{\max}$)**
//! estimation to kernel/ETW/eBPF event streams.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PhaseSpaceError {
    #[error("Insufficient telemetry history to reconstruct phase space manifold")]
    InsufficientHistory,
    #[error("Invalid embedding configuration: dimension must be >= 2 and delay >= 1")]
    InvalidConfiguration,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TelemetryVerdict {
    pub lyapunov_exponent: f64,
    pub mahalanobis_drift: f64,
    pub is_chaotic_breakout: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseSpaceMonitor {
    embedding_dim: usize,
    tau_delay: usize,
    window_capacity: usize,
    chaos_threshold: f64,
    scalar_series: VecDeque<f64>,
    attractor_centroid: Vec<f64>,
    attractor_variance: Vec<f64>,
}

impl PhaseSpaceMonitor {
    pub fn new(
        embedding_dim: usize,
        tau_delay: usize,
        window_capacity: usize,
        chaos_threshold: f64,
    ) -> Result<Self, PhaseSpaceError> {
        let min_required = (embedding_dim.saturating_sub(1)) * tau_delay + 2;
        if embedding_dim < 2 || tau_delay < 1 || window_capacity < min_required {
            return Err(PhaseSpaceError::InvalidConfiguration);
        }

        Ok(Self {
            embedding_dim,
            tau_delay,
            window_capacity,
            chaos_threshold,
            scalar_series: VecDeque::with_capacity(window_capacity),
            attractor_centroid: vec![0.0; embedding_dim],
            attractor_variance: vec![1.0; embedding_dim],
        })
    }

    /// Creates a pre-calibrated 4D Takens attractor monitor for per-PID EDR telemetry streams.
    pub fn default_edr_monitor() -> Self {
        Self::new(4, 2, 32, 0.85).expect("valid default PhaseSpaceMonitor configuration")
    }

    /// Maps an event ID, inter-arrival delta (ms), and command-line/payload entropy into a scalar phase metric.
    pub fn compute_syscall_phase_metric(event_id: u32, delta_ms: f64, cmdline_entropy: f64) -> f64 {
        let event_weight = match event_id {
            1 => 1.25,       // ProcessCreate / execve
            3 => 1.40,       // NetworkConnect
            8 => 3.80,       // CreateRemoteThread
            10 => 4.20,      // ProcessAccess (LSASS / cross-process memory)
            11 => 1.15,      // FileCreate
            12 | 13 => 1.60, // Registry modification
            17 | 18 => 1.75, // Named Pipe create/connect
            22 => 1.35,      // DNS Query
            _ => 1.0,
        };
        let pacing_factor = (1000.0 / (delta_ms.max(1.0) + 10.0)).ln_1p();
        event_weight * (1.0 + 0.35 * cmdline_entropy.max(0.0)) + 0.25 * pacing_factor
    }

    /// Ingests a scalar telemetry metric (e.g., syscall entropy weighted by inter-arrival delta-t)
    /// and reconstructs the delay-coordinate vector v(t) = [x(t), x(t-tau), ..., x(t-(d-1)tau)].
    pub fn observe_event(&mut self, metric: f64) -> Result<TelemetryVerdict, PhaseSpaceError> {
        if self.scalar_series.len() == self.window_capacity {
            self.scalar_series.pop_front();
        }
        self.scalar_series.push_back(metric);

        let min_len = (self.embedding_dim - 1) * self.tau_delay + 2;
        if self.scalar_series.len() < min_len {
            return Err(PhaseSpaceError::InsufficientHistory);
        }

        let current_vec = self.reconstruct_latest_vector();
        let lyapunov = self.compute_local_divergence(&current_vec);
        let drift = self.update_and_measure_drift(&current_vec);

        let is_chaotic_breakout = lyapunov > self.chaos_threshold && drift > 2.5;

        Ok(TelemetryVerdict {
            lyapunov_exponent: lyapunov,
            mahalanobis_drift: drift,
            is_chaotic_breakout,
        })
    }

    fn reconstruct_latest_vector(&self) -> Vec<f64> {
        let n = self.scalar_series.len();
        (0..self.embedding_dim)
            .map(|i| self.scalar_series[n - 1 - i * self.tau_delay])
            .collect()
    }

    fn reconstruct_previous_vector(&self, offset_from_end: usize) -> Vec<f64> {
        let n = self.scalar_series.len();
        (0..self.embedding_dim)
            .map(|i| self.scalar_series[n - 1 - offset_from_end - i * self.tau_delay])
            .collect()
    }

    /// Rosenstein's algorithm approximation for local trajectory divergence in phase space.
    fn compute_local_divergence(&self, current: &[f64]) -> f64 {
        let max_offset = self.scalar_series.len() - 1 - (self.embedding_dim - 1) * self.tau_delay;
        let mut min_dist = f64::MAX;

        for offset in 1..=max_offset {
            let candidate = self.reconstruct_previous_vector(offset);
            let dist = euclidean_distance(current, &candidate);
            if dist > 1e-9 && dist < min_dist {
                min_dist = dist;
            }
        }

        if min_dist == f64::MAX {
            return 0.0;
        }

        // Logarithmic divergence rate relative to unit phase-space cell
        (min_dist / 0.1_f64).ln()
    }

    fn update_and_measure_drift(&mut self, current: &[f64]) -> f64 {
        let alpha = 0.05; // Exponential moving average decay for attractor manifold
        let mut squared_mahalanobis = 0.0;

        for (i, &cur_val) in current.iter().enumerate().take(self.embedding_dim) {
            let diff = cur_val - self.attractor_centroid[i];
            let safe_var = self.attractor_variance[i].max(1e-6);
            squared_mahalanobis += (diff * diff) / safe_var;

            self.attractor_centroid[i] += alpha * diff;
            self.attractor_variance[i] =
                (1.0 - alpha) * self.attractor_variance[i] + alpha * (diff * diff);
        }

        squared_mahalanobis.sqrt()
    }
}

fn euclidean_distance(a: &[f64], b: &[f64]) -> f64 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x - y).powi(2))
        .sum::<f64>()
        .sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stable_attractor_vs_chaotic_injection_breakout() {
        let mut monitor = PhaseSpaceMonitor::default_edr_monitor();
        // Feed stable baseline telemetry
        for i in 0..12 {
            let metric = 1.2 + ((i % 2) as f64) * 0.05;
            let _ = monitor.observe_event(metric);
        }
        let baseline_verdict = monitor.observe_event(1.22).expect("sufficient history");
        assert!(!baseline_verdict.is_chaotic_breakout);

        // Sudden process injection / shellcode control-flow hijack spike
        let spike_verdict = monitor.observe_event(28.5).expect("sufficient history");
        assert!(spike_verdict.lyapunov_exponent > 0.85);
        assert!(spike_verdict.mahalanobis_drift > 2.5);
        assert!(spike_verdict.is_chaotic_breakout);
    }
}
