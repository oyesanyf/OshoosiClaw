//! # Crate 3: Quantum Vacuum Fluctuations and Cosmological Lensing (`zero-vacuum-lensing`)
//!
//! Implements:
//! 1. **Zero as Vacuum that is Not Simple Nothingness (Zero-Point Energy & Casimir Pressure)**:
//!    $E_{\text{ZPE}} = \frac{1}{2} \sum_k \hbar_{\text{sys}} \omega_k$ and
//!    $P_{\text{Casimir}}(a) = -\frac{\pi^2 \hbar_{\text{sys}} c_{\text{bus}}}{240 \, a^4}$.
//! 2. **Zero as the Unseen in Cosmology (Gravitational Lensing & Dark Mass Triangulation)**:
//!    $M_{\text{dark}} = \frac{b \cdot c_{\text{bus}}^2 \cdot \Delta \phi}{4 G_{\text{sys}}}$.

use serde::{Deserialize, Serialize};
use std::f64::consts::PI;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VacuumCosmologyMetrics {
    pub zero_point_energy_deviation: f64,
    pub casimir_pressure_anomaly: f64,
    pub inferred_dark_mass: f64,
    pub unseen_entity_detected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VacuumCosmologySensor {
    hbar_sys: f64,
    c_bus: f64,
    g_sys: f64,
    baseline_zpe: f64,
}

impl VacuumCosmologySensor {
    pub fn new(hbar_sys: f64, c_bus: f64, g_sys: f64, baseline_frequencies: &[f64]) -> Self {
        // E_ZPE = 1/2 * sum(hbar * omega_k)
        let baseline_zpe = 0.5 * hbar_sys * baseline_frequencies.iter().sum::<f64>();

        Self {
            hbar_sys,
            c_bus,
            g_sys,
            baseline_zpe,
        }
    }

    /// Creates a pre-calibrated EDR `VacuumCosmologySensor` for host & P2P mesh monitoring.
    pub fn default_edr_sensor() -> Self {
        Self::new(1.0, 10.0, 1.0, &[2.0, 4.0, 6.0, 8.0])
    }

    /// 1. Zero as Vacuum (Not Simple Nothingness):
    /// Measures Zero-Point Energy deviation and Casimir pressure anomaly between sandboxes.
    pub fn measure_vacuum_plenum(
        &self,
        observed_idle_frequencies: &[f64],
        sandbox_separation_a: f64,
        observed_boundary_pressure: f64,
    ) -> (f64, f64) {
        let current_zpe = 0.5 * self.hbar_sys * observed_idle_frequencies.iter().sum::<f64>();
        let zpe_deviation = (current_zpe - self.baseline_zpe).abs();

        let safe_a = sandbox_separation_a.max(1e-6);
        let expected_casimir =
            -(PI.powi(2) * self.hbar_sys * self.c_bus) / (240.0 * safe_a.powi(4));
        let casimir_anomaly = (observed_boundary_pressure - expected_casimir).abs();

        (zpe_deviation, casimir_anomaly)
    }

    /// 2. Zero as the Unseen in Cosmology:
    /// Infers the hidden mass M_dark of an unmonitored rootkit or external agent via gravitational lensing
    /// deflection (latency/cache distortion delta_phi) at impact distance b.
    pub fn infer_unseen_dark_mass(&self, impact_parameter_b: f64, deflection_angle_phi: f64) -> f64 {
        if self.g_sys <= 1e-12 {
            return 0.0;
        }
        (impact_parameter_b * self.c_bus.powi(2) * deflection_angle_phi.abs()) / (4.0 * self.g_sys)
    }

    pub fn scan_horizon(
        &self,
        observed_idle_frequencies: &[f64],
        sandbox_separation_a: f64,
        observed_boundary_pressure: f64,
        impact_parameter_b: f64,
        deflection_angle_phi: f64,
        dark_mass_threshold: f64,
    ) -> VacuumCosmologyMetrics {
        let (zpe_dev, casimir_anom) = self.measure_vacuum_plenum(
            observed_idle_frequencies,
            sandbox_separation_a,
            observed_boundary_pressure,
        );
        let dark_mass = self.infer_unseen_dark_mass(impact_parameter_b, deflection_angle_phi);

        let unseen_entity_detected =
            dark_mass > dark_mass_threshold || zpe_dev > self.baseline_zpe * 0.25;

        VacuumCosmologyMetrics {
            zero_point_energy_deviation: zpe_dev,
            casimir_pressure_anomaly: casimir_anom,
            inferred_dark_mass: dark_mass,
            unseen_entity_detected,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vacuum_equilibrium_vs_unseen_rootkit_lensing() {
        let sensor = VacuumCosmologySensor::default_edr_sensor();
        let expected_casimir = -(PI.powi(2) * 1.0 * 10.0) / 240.0;
        let calm = sensor.scan_horizon(
            &[2.0, 4.0, 6.0, 8.0],
            1.0,
            expected_casimir,
            1.0,
            0.001,
            5.0,
        );
        assert!(!calm.unseen_entity_detected);
        assert!(calm.zero_point_energy_deviation < 1e-9);
        assert!(calm.casimir_pressure_anomaly < 1e-9);

        // Unmonitored rootkit bends syscall trajectory (deflection_angle_phi = 0.45)
        let lensed = sensor.scan_horizon(
            &[2.0, 4.0, 6.0, 8.0],
            1.0,
            expected_casimir,
            2.0,
            0.45,
            5.0,
        );
        assert!(lensed.unseen_entity_detected);
        assert!(lensed.inferred_dark_mass > 20.0);
    }
}
