//! #Crate 1: Ontological Origin, Capacity, and Hidden Structure (`zero-genesis-capacity`)
//!
//! Unifies:
//! 1. **Zero Before Visible Form (Pre-Execution Wavefunction)**:
//!    $\langle \psi_{\text{embryo}} \mid \hat{H}_{\text{threat}} \mid \psi_{\text{embryo}} \rangle = 0$ prior to binary mapping.
//! 2. **Zero as Capacity (Euler-Lagrange Boundary Saturation)**:
//!    $\Omega(t) = C_{\max} - \int_0^t r(\tau)\,d\tau$ and barrier potential $U(\Omega) = \frac{1}{\Omega(t)} \to \infty$ as $\Omega(t) \to 0^+$.
//! 3. **Zero as Mathematical Origin and Placeholder (Radix-Weighted Mahalanobis Displacement)**:
//!    $D_0(\mathbf{x}) = \sqrt{\sum_{k=0}^{n-1} b^{2k} \frac{x_k^2}{\sigma_k^2}}$ relative to boot-time cryptographic attestation $\mathbf{0} \in \mathbb{R}^n$.
//! 4. **Zero as Hidden Structure (Adjacency Annihilation)**:
//!    Complement $\bar{A}_{ij} = 1 - A_{ij}$ of allowed control-flow/tool transitions, requiring $\Vert T \circ \bar{A} \Vert_F = 0$.

use serde::{Deserialize, Serialize};

/// Encodes Zero Before Visible Form, Zero as Capacity, Mathematical Origin, and Hidden Structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisVessel {
    origin_hash: [u8; 32],
    max_capacity: f64,
    consumed_volume: f64,
    positional_variance: Vec<f64>,
    radix_base: f64,
    allowed_adjacency: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GenesisAssessment {
    pub pre_form_energy: f64,
    pub remaining_void_capacity: f64,
    pub barrier_potential: f64,
    pub origin_displacement: f64,
    pub hidden_structure_violation: f64,
    pub is_lawful: bool,
}

impl GenesisVessel {
    pub fn new(
        boot_attestation_seed: &[u8],
        max_capacity: f64,
        positional_variance: Vec<f64>,
        radix_base: f64,
        allowed_adjacency: Vec<Vec<u8>>,
    ) -> Self {
        let origin_hash = *blake3::hash(boot_attestation_seed).as_bytes();
        Self {
            origin_hash,
            max_capacity,
            consumed_volume: 0.0,
            positional_variance,
            radix_base,
            allowed_adjacency,
        }
    }

    /// Creates a pre-calibrated EDR & Agent Containment `GenesisVessel` with a 5-stage capability adjacency matrix:
    /// - Node 0: `EmbryoFork`
    /// - Node 1: `ReadWorkspace`
    /// - Node 2: `WriteWorkspace`
    /// - Node 3: `NetworkAllowlisted`
    /// - Node 4: `PrivilegeOrKernelSink` (restricted from untrusted nodes)
    pub fn default_edr_vessel(boot_seed: &[u8]) -> Self {
        let allowed_adjacency = vec![
            vec![1, 1, 1, 1, 0], // 0: EmbryoFork -> can read/write/net, cannot jump straight to kernel sink
            vec![0, 1, 1, 1, 0], // 1: ReadWorkspace -> cannot jump to kernel sink
            vec![0, 1, 1, 1, 0], // 2: WriteWorkspace -> cannot jump to kernel sink
            vec![0, 1, 1, 1, 0], // 3: NetworkAllowlisted -> cannot jump to kernel sink
            vec![0, 0, 0, 0, 1], // 4: PrivilegeOrKernelSink -> isolated self-loop only
        ];
        Self::new(
            boot_seed,
            1000.0,
            vec![1.0, 1.0, 1.0, 1.0],
            2.0,
            allowed_adjacency,
        )
    }

    /// Zero Before Visible Form (1): Evaluates kernel task allocation prior to userspace mapping.
    /// Computes `<psi | H_threat | psi> == 0`.
    pub fn evaluate_embryonic_state(embryo_state: &[f64], threat_operator_diag: &[f64]) -> f64 {
        embryo_state
            .iter()
            .zip(threat_operator_diag.iter())
            .map(|(&psi, &h)| psi * h * psi)
            .sum()
    }

    /// Evaluates runtime execution against Capacity, Origin Placeholder, and Hidden Structure.
    pub fn observe_transition(
        &mut self,
        embryo_state: &[f64],
        threat_operator_diag: &[f64],
        resource_delta: f64,
        positional_state_vector: &[f64],
        from_node: usize,
        to_node: usize,
    ) -> GenesisAssessment {
        // 1. Pre-visible form check
        let pre_form_energy = Self::evaluate_embryonic_state(embryo_state, threat_operator_diag);

        // 2. Zero as Capacity: Omega(t) = C_max - Integral(r(t) dt)
        self.consumed_volume += resource_delta.max(0.0);
        let remaining_void = (self.max_capacity - self.consumed_volume).max(0.0);
        let barrier_potential = if remaining_void > 1e-9 {
            1.0 / remaining_void
        } else {
            f64::INFINITY
        };

        // 3. Zero as Origin and Positional Placeholder: Radix-weighted displacement from 0
        let mut weighted_sq_sum = 0.0;
        for (k, (&x_k, &var_k)) in positional_state_vector
            .iter()
            .zip(self.positional_variance.iter())
            .enumerate()
        {
            let radix_weight = self.radix_base.powi((2 * k) as i32);
            let safe_var = var_k.max(1e-9);
            weighted_sq_sum += radix_weight * (x_k.powi(2) / safe_var);
        }
        let origin_displacement = weighted_sq_sum.sqrt();

        // 4. Zero as Hidden Structure: Frobenius norm over forbidden adjacency complement
        let allowed = self
            .allowed_adjacency
            .get(from_node)
            .and_then(|row| row.get(to_node))
            .copied()
            .unwrap_or(0);
        let complement = 1.0 - (allowed as f64);
        let hidden_structure_violation = complement; // Non-zero if transition hits a zero-entry

        let is_lawful = pre_form_energy < 1e-6
            && remaining_void > 0.0
            && hidden_structure_violation == 0.0
            && origin_displacement < 100.0;

        GenesisAssessment {
            pre_form_energy,
            remaining_void_capacity: remaining_void,
            barrier_potential,
            origin_displacement,
            hidden_structure_violation,
            is_lawful,
        }
    }

    pub fn invariant_origin(&self) -> &[u8; 32] {
        &self.origin_hash
    }

    pub fn remaining_void(&self) -> f64 {
        (self.max_capacity - self.consumed_volume).max(0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_lawful_transition_and_origin() {
        let mut vessel = GenesisVessel::default_edr_vessel(b"osoosi-boot-attestation-v1");
        assert_ne!(vessel.invariant_origin(), &[0u8; 32]);

        let assessment = vessel.observe_transition(
            &[0.0, 0.0, 0.0],
            &[10.0, 20.0, 30.0],
            5.0,
            &[0.5, 0.2, 0.1, 0.0],
            1,
            2,
        );
        assert!(assessment.is_lawful);
        assert_eq!(assessment.pre_form_energy, 0.0);
        assert_eq!(assessment.hidden_structure_violation, 0.0);
        assert!((assessment.remaining_void_capacity - 995.0).abs() < 1e-6);
    }

    #[test]
    fn test_genesis_hidden_structure_and_capacity_exhaustion() {
        let mut vessel = GenesisVessel::default_edr_vessel(b"osoosi-boot-attestation-v1");
        // Forbidden transition 1 -> 4 (ReadWorkspace -> PrivilegeOrKernelSink)
        let forbidden =
            vessel.observe_transition(&[0.0, 0.0], &[1.0, 1.0], 10.0, &[0.1, 0.1, 0.0, 0.0], 1, 4);
        assert!(!forbidden.is_lawful);
        assert_eq!(forbidden.hidden_structure_violation, 1.0);

        // Exhaust remaining void capacity
        let exhausted = vessel.observe_transition(
            &[0.0, 0.0],
            &[1.0, 1.0],
            2000.0,
            &[0.1, 0.1, 0.0, 0.0],
            1,
            2,
        );
        assert!(!exhausted.is_lawful);
        assert_eq!(exhausted.remaining_void_capacity, 0.0);
        assert!(exhausted.barrier_potential.is_infinite());
    }
}
