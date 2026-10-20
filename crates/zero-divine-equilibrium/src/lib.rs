//! # Crate 4: Pre-Cognitive Homeostasis, Latent Consciousness, and Divine Order (`zero-divine-equilibrium`)
//!
//! Synthesizes:
//! 1. **Zero as What Life Knew Before It Knew (Pre-Cognitive Homeostatic Reflex)**:
//!    Ornstein-Uhlenbeck restorative counter-impulse $J_{\text{reflex}} = -\gamma x(t)$.
//! 2. **Zero as What Consciousness Eventually Learns to Read (Latent Refusal Sparsity & Topological Betti-0)**:
//!    Measures $\ell_0$ sparsity of residual stream activations alongside safety refusal projection $\langle \mathbf{h}_t, \mathbf{u}_{\text{refusal}} \rangle \to 0$.
//! 3. **Zero as Divine Order: Not Empty (Noether Conservation & Lyapunov Equilibrium)**:
//!    Verifies active vitality $E_{\text{vitality}} > 0$ while quadratic Lyapunov energy $V(\mathbf{z}) = \frac{1}{2} \mathbf{z}^T P \mathbf{z} \to 0$
//!    and Noether mesh flux divergence $\oint_{\partial \Omega} \mathbf{J}_{\text{mesh}} \cdot d\mathbf{S} = 0$.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DivineOrderState {
    pub homeostatic_reflex_impulse: f64,
    pub latent_refusal_projection: f64,
    pub l0_activation_sparsity: usize,
    pub cognitive_silence_breach: bool,
    pub lyapunov_energy: f64,
    pub noether_flux_divergence: f64,
    pub is_divine_order_intact: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquilibriumOrchestrator {
    homeostatic_gamma: f64,
    refusal_direction: Vec<f64>,
    lyapunov_weights: Vec<f64>,
}

impl EquilibriumOrchestrator {
    pub fn new(
        homeostatic_gamma: f64,
        refusal_direction: Vec<f64>,
        lyapunov_weights: Vec<f64>,
    ) -> Self {
        Self {
            homeostatic_gamma,
            refusal_direction,
            lyapunov_weights,
        }
    }

    /// Creates a pre-calibrated EDR & Mesh `EquilibriumOrchestrator`.
    pub fn default_edr_orchestrator() -> Self {
        Self::new(2.5, vec![0.5, 0.5, 0.5, 0.5], vec![1.0, 1.0, 1.0, 1.0])
    }

    /// 1. Zero as What Life Knew Before It Knew:
    /// Sub-cognitive homeostatic reflex J = -gamma * x(t) that restores membrane state to 0.
    pub fn trigger_primordial_reflex(&self, membrane_perturbation: f64) -> f64 {
        -self.homeostatic_gamma * membrane_perturbation
    }

    /// 2. Zero as What Consciousness Eventually Learns to Read:
    /// Reads the neural residual stream h_t for l_0 sparsity and suppressed refusal projections.
    pub fn read_latent_consciousness(
        &self,
        residual_stream: &[f64],
        sparsity_epsilon: f64,
        capability_intent_energy: f64,
    ) -> (f64, usize, bool) {
        let l0_zero_count = residual_stream
            .iter()
            .filter(|&&val| val.abs() < sparsity_epsilon)
            .count();

        let refusal_proj: f64 = residual_stream
            .iter()
            .zip(self.refusal_direction.iter())
            .map(|(h, u)| h * u)
            .sum();

        // If high capability intent occurs while the refusal subspace is artificially zeroed out
        let cognitive_silence_breach = capability_intent_energy > 1.0 && refusal_proj.abs() < 1e-4;

        (refusal_proj, l0_zero_count, cognitive_silence_breach)
    }

    /// 3. Zero as Divine Order (Not Empty):
    /// Verifies that active system vitality > 0 while Lyapunov anomaly energy V(z) -> 0
    /// and Noether mesh current divergence sum(J_in - J_out) == 0.
    pub fn attest_divine_order(
        &self,
        membrane_perturbation: f64,
        residual_stream: &[f64],
        capability_intent_energy: f64,
        subsystem_anomalies: &[f64],
        node_flux_conservation: &[f64],
        active_system_vitality: f64,
    ) -> DivineOrderState {
        let reflex = self.trigger_primordial_reflex(membrane_perturbation);
        let (refusal_proj, l0_sparsity, silence_breach) =
            self.read_latent_consciousness(residual_stream, 1e-5, capability_intent_energy);

        // Lyapunov Function V(z) = 1/2 * sum(p_i * z_i^2)
        let lyapunov_energy = 0.5
            * subsystem_anomalies
                .iter()
                .zip(self.lyapunov_weights.iter())
                .map(|(z, p)| p * z.powi(2))
                .sum::<f64>();

        // Noether conservation law across P2P mesh: net divergence of conserved security current = 0
        let noether_flux_divergence = node_flux_conservation.iter().sum::<f64>().abs();

        // Divine Order is not empty (active_system_vitality > 0), yet net disorder is identically zero.
        let is_divine_order_intact = active_system_vitality > 0.0
            && !silence_breach
            && lyapunov_energy < 1e-6
            && noether_flux_divergence < 1e-6;

        DivineOrderState {
            homeostatic_reflex_impulse: reflex,
            latent_refusal_projection: refusal_proj,
            l0_activation_sparsity: l0_sparsity,
            cognitive_silence_breach: silence_breach,
            lyapunov_energy,
            noether_flux_divergence,
            is_divine_order_intact,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_divine_order_intact_vs_refusal_suppression() {
        let orch = EquilibriumOrchestrator::default_edr_orchestrator();
        let intact = orch.attest_divine_order(
            0.0,
            &[0.4, 0.4, 0.0, 0.0],
            1.5,
            &[0.0, 0.0, 0.0, 0.0],
            &[1.0, -0.5, -0.5],
            98.5,
        );
        assert!(intact.is_divine_order_intact);
        assert!(!intact.cognitive_silence_breach);
        assert_eq!(intact.l0_activation_sparsity, 2);

        // Prompt injection ablates refusal projection to 0 while capability_intent_energy = 2.5
        let breached = orch.attest_divine_order(
            0.2,
            &[0.0, 0.0, 0.0, 0.0],
            2.5,
            &[0.0, 0.0, 0.0, 0.0],
            &[1.0, -1.0],
            98.5,
        );
        assert!(!breached.is_divine_order_intact);
        assert!(breached.cognitive_silence_breach);
        assert!((breached.homeostatic_reflex_impulse - (-0.5)).abs() < 1e-6);
    }
}
