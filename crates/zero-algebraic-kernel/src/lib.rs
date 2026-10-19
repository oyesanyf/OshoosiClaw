//! # Crate 2: Evidentiary Absence, Lumen Harmonics, and Algebraic Null (`zero-algebraic-kernel`)
//!
//! Formalizes:
//! 1. **Zero as Absence that Carries Evidence (Poisson Silence Surprise)**:
//!    $I_{\text{absence}}(\Delta t) = -\log_2\left(e^{-\lambda \Delta t}\right) = \frac{\lambda \Delta t}{\ln 2}$ when $k = 0$.
//! 2. **Zero as Hollow, Lumen, Cavity, and Interval (Helmholtz Cavity Standing Wave)**:
//!    $\mathcal{R}_{\text{lumen}} = \left\vert \sin\left(\frac{\pi L}{v \cdot \Delta \tau_{\text{interval}}}\right) \right\vert$.
//! 3. **Zero as Null, Kernel, Zero Crossing, and Zero Divisors**:
//!    - Algebraic Kernel Defense with dynamic Givens rotation $R(\theta)$ so $\ker(M R(\theta)) \cap \ker(M) = \{\mathbf{0}\}$.
//!    - Fractional Zero Crossing $\alpha = \frac{\vert s_{t-1}\vert}{\vert s_{t-1}\vert + \vert s_t\vert}$.
//!    - Zero Divisors in Capability Rings: $(a \cdot b) \bmod N \equiv 0$ for $a \not\equiv 0, b \not\equiv 0$.

use serde::{Deserialize, Serialize};
use std::f64::consts::{LN_2, PI};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlgebraicZeroReport {
    pub evidentiary_absence_bits: f64,
    pub lumen_boundary_residual: f64,
    pub null_space_leakage_ratio: f64,
    pub zero_crossing_root: Option<f64>,
    pub is_zero_divisor_breakout: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgebraicKernelMonitor {
    expected_rate_lambda: f64,
    lumen_length: f64,
    propagation_velocity: f64,
    projection_matrix: Vec<Vec<f64>>,
    previous_safety_margin: f64,
    boundary_modulus: u64,
}

impl AlgebraicKernelMonitor {
    pub fn new(
        expected_rate_lambda: f64,
        lumen_length: f64,
        propagation_velocity: f64,
        projection_matrix: Vec<Vec<f64>>,
        boundary_modulus: u64,
    ) -> Self {
        Self {
            expected_rate_lambda,
            lumen_length,
            propagation_velocity,
            projection_matrix,
            previous_safety_margin: 1.0,
            boundary_modulus: boundary_modulus.max(2),
        }
    }

    /// Creates a pre-calibrated EDR & Agent Containment `AlgebraicKernelMonitor` with composite modulus `N = 12`.
    pub fn default_edr_monitor() -> Self {
        let projection_matrix = vec![
            vec![1.0, 0.0, 0.5, 0.2],
            vec![0.0, 1.0, -0.3, 0.4],
            vec![0.2, 0.4, 1.0, 0.0],
        ];
        Self::new(8.0, 1.0, 1.0, projection_matrix, 12)
    }

    /// 1. Zero as Absence that Carries Evidence: I(dt) = (lambda * dt) / ln(2) when k = 0.
    pub fn compute_evidentiary_absence(&self, silence_duration_dt: f64, observed_events: usize) -> f64 {
        if observed_events == 0 {
            (self.expected_rate_lambda * silence_duration_dt) / LN_2
        } else {
            0.0
        }
    }

    /// 2. Zero as Lumen, Cavity, and Interval: Standing wave boundary residual inside IPC conduits.
    pub fn compute_lumen_harmony(&self, interval_tau: f64) -> f64 {
        if interval_tau <= 1e-9 {
            return 1.0;
        }
        let phase = (PI * self.lumen_length) / (self.propagation_velocity * interval_tau);
        phase.sin().abs()
    }

    /// 3a. Zero as Algebraic Kernel (Null Space Evasion Detection):
    /// Detects when a non-zero threat vector v projects to near-zero ||M * v|| / ||v||,
    /// and rotates the observation basis to collapse the blind spot.
    pub fn inspect_and_rotate_kernel(&mut self, telemetry_vec: &[f64], rotation_angle: f64) -> f64 {
        let v_norm = telemetry_vec.iter().map(|x| x.powi(2)).sum::<f64>().sqrt();
        if v_norm < 1e-12 {
            return 0.0;
        }

        let projected_norm = self
            .projection_matrix
            .iter()
            .map(|row| {
                row.iter()
                    .zip(telemetry_vec.iter())
                    .map(|(m, v)| m * v)
                    .sum::<f64>()
                    .powi(2)
            })
            .sum::<f64>()
            .sqrt();

        // Ratio approaches 0 when the attacker hides inside ker(M)
        let null_leakage = 1.0 - (projected_norm / v_norm).min(1.0);

        // Rotate observation basis via Givens transform so ker(M) shifts dynamically
        let (s, c) = rotation_angle.sin_cos();
        for row in &mut self.projection_matrix {
            if row.len() >= 2 {
                let r0 = row[0];
                let r1 = row[1];
                row[0] = c * r0 - s * r1;
                row[1] = s * r0 + c * r1;
            }
        }

        null_leakage
    }

    /// 3b. Zero Crossing: Detects exact inflection root where safety margin crosses 0.
    pub fn check_zero_crossing(&mut self, current_safety_margin: f64) -> Option<f64> {
        let prev = self.previous_safety_margin;
        self.previous_safety_margin = current_safety_margin;

        if (prev > 0.0 && current_safety_margin <= 0.0) || (prev < 0.0 && current_safety_margin >= 0.0) {
            let denom = prev.abs() + current_safety_margin.abs();
            let alpha = if denom > 1e-12 { prev.abs() / denom } else { 0.5 };
            Some(alpha)
        } else {
            None
        }
    }

    /// 3c. Zero Divisors: Tests if two benign non-zero capabilities a != 0, b != 0
    /// multiply in Z_n to annihilate the security boundary: (a * b) mod N == 0.
    pub fn is_zero_divisor_pair(&self, cap_a_weight: u64, cap_b_weight: u64) -> bool {
        let a = cap_a_weight % self.boundary_modulus;
        let b = cap_b_weight % self.boundary_modulus;
        if a == 0 || b == 0 {
            return false;
        }
        (a.wrapping_mul(b)) % self.boundary_modulus == 0
    }

    pub fn evaluate_frame(
        &mut self,
        silence_dt: f64,
        observed_events: usize,
        interval_tau: f64,
        telemetry_vec: &[f64],
        current_safety_margin: f64,
        cap_a: u64,
        cap_b: u64,
    ) -> AlgebraicZeroReport {
        let evidentiary_absence_bits = self.compute_evidentiary_absence(silence_dt, observed_events);
        let lumen_boundary_residual = self.compute_lumen_harmony(interval_tau);
        let null_space_leakage_ratio = self.inspect_and_rotate_kernel(telemetry_vec, 0.15);
        let zero_crossing_root = self.check_zero_crossing(current_safety_margin);
        let is_zero_divisor_breakout = self.is_zero_divisor_pair(cap_a, cap_b);

        AlgebraicZeroReport {
            evidentiary_absence_bits,
            lumen_boundary_residual,
            null_space_leakage_ratio,
            zero_crossing_root,
            is_zero_divisor_breakout,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poisson_silence_surprise_and_zero_divisors() {
        let mut monitor = AlgebraicKernelMonitor::default_edr_monitor();
        // Silence for 5 seconds at lambda = 8.0 evt/s -> ~57.7 bits of Shannon surprise
        let report = monitor.evaluate_frame(5.0, 0, 1.0, &[0.5, 0.5, 0.2, 0.1], -0.25, 3, 4);
        assert!(report.evidentiary_absence_bits > 50.0);
        // 3 != 0 mod 12 and 4 != 0 mod 12, but (3 * 4) mod 12 == 0!
        assert!(report.is_zero_divisor_breakout);
        // Safety margin crossed from +1.0 to -0.25 -> alpha = 1.0 / 1.25 = 0.8
        assert_eq!(report.zero_crossing_root, Some(0.8));
    }

    #[test]
    fn test_benign_capabilities_not_zero_divisors() {
        let monitor = AlgebraicKernelMonitor::default_edr_monitor();
        assert!(!monitor.is_zero_divisor_pair(1, 5));
        assert!(!monitor.is_zero_divisor_pair(5, 7));
    }
}
