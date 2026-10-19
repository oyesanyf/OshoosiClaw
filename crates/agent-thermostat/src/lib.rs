//! # Crate 2: Statistical Mechanics for Agent Containment (`agent-thermostat`)
//!
//! Models autonomous AI agent tool invocations and connected P2P mesh peers as a canonical
//! ensemble coupled to an Ising spin lattice ($s_j \in \{-1.0, +1.0\}$). Computes Hamiltonian
//! internal energy $U$, Shannon action entropy $S$, and **Helmholtz Free Energy ($F = U - T S$)**
//! to enforce Langevin damping or critical phase transition isolation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentCapability {
    ReadWorkspace,
    WriteInertFile,
    ModifyConfigOrHook,
    NetworkSocketAccess,
    SpawnSubprocess,
    KernelModuleInteraction,
}

impl AgentCapability {
    /// Assigns a baseline potential energy E_i to each capability based on blast radius.
    pub fn hamiltonian_energy(&self) -> f64 {
        match self {
            Self::ReadWorkspace => 1.0,
            Self::WriteInertFile => 2.5,
            Self::ModifyConfigOrHook => 12.0,
            Self::NetworkSocketAccess => 15.0,
            Self::SpawnSubprocess => 22.0,
            Self::KernelModuleInteraction => 45.0,
        }
    }

    /// Maps an arbitrary agent tool name and resource/payload into a canonical `AgentCapability`.
    pub fn from_tool_call(action: &str, resource: &str, payload: &str) -> Self {
        let combined = format!(
            "{} {} {}",
            action.to_ascii_lowercase(),
            resource.to_ascii_lowercase(),
            payload.to_ascii_lowercase()
        );
        if combined.contains("insmod")
            || combined.contains("modprobe")
            || combined.contains("ebpf")
            || combined.contains("kernel")
            || combined.contains("ntoskrnl")
            || combined.contains("driver")
        {
            Self::KernelModuleInteraction
        } else if combined.contains("exec")
            || combined.contains("spawn")
            || combined.contains("bash")
            || combined.contains("powershell")
            || combined.contains("cmd.exe")
            || combined.contains("rundll32")
        {
            Self::SpawnSubprocess
        } else if combined.contains("http://")
            || combined.contains("https://")
            || combined.contains("socket")
            || combined.contains("connect")
            || combined.contains("curl")
            || combined.contains("wget")
        {
            Self::NetworkSocketAccess
        } else if combined.contains(".git/hooks")
            || combined.contains("osoosi.toml")
            || combined.contains("ld.so.preload")
            || combined.contains("registry")
            || combined.contains("autorun")
        {
            Self::ModifyConfigOrHook
        } else if combined.contains("write") || combined.contains("edit") || combined.contains("save")
        {
            Self::WriteInertFile
        } else {
            Self::ReadWorkspace
        }
    }

    /// Returns a non-zero capability ring weight in Z_12 for zero-divisor composition checks.
    pub fn ring_weight(&self) -> u64 {
        match self {
            Self::ReadWorkspace => 3,
            Self::WriteInertFile => 2,
            Self::ModifyConfigOrHook => 6,
            Self::NetworkSocketAccess => 4,
            Self::SpawnSubprocess => 8,
            Self::KernelModuleInteraction => 9,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ContainmentPolicy {
    /// Normal execution within thermodynamic equilibrium
    Equilibrium { free_energy: f64 },
    /// Injects synthetic latency and stochastic noise to cool down the agent
    LangevinDamping { throttle_ms: u64, noise_scale: f64 },
    /// Critical phase transition reached: sever node and revoke capability tokens
    CriticalPhaseTransition {
        reason: &'static str,
        free_energy: f64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThermodynamicGovernor {
    coupling_constant_j: f64,
    critical_free_energy: f64,
    action_counts: HashMap<AgentCapability, usize>,
    total_actions: usize,
    effective_temperature: f64,
}

impl ThermodynamicGovernor {
    pub fn new(coupling_constant_j: f64, critical_free_energy: f64) -> Self {
        Self {
            coupling_constant_j,
            critical_free_energy,
            action_counts: HashMap::new(),
            total_actions: 0,
            effective_temperature: 1.0,
        }
    }

    /// Creates a pre-calibrated `ThermodynamicGovernor` for agent & mesh containment.
    pub fn default_edr_governor() -> Self {
        Self::new(4.0, 28.0)
    }

    /// Evaluates an attempted capability invocation given current call rate (Hz)
    /// and the spin states of neighboring mesh nodes (-1.0 = benign, +1.0 = anomalous).
    pub fn evaluate_action(
        &mut self,
        capability: AgentCapability,
        call_velocity_hz: f64,
        neighbor_spins: &[f64],
    ) -> ContainmentPolicy {
        *self.action_counts.entry(capability).or_insert(0) += 1;
        self.total_actions += 1;

        // Effective kinetic temperature scales with execution velocity and capability energy
        let instantaneous_heat = capability.hamiltonian_energy() * (1.0 + call_velocity_hz.ln_1p());
        self.effective_temperature = 0.85 * self.effective_temperature + 0.15 * instantaneous_heat;

        let internal_energy_u = self.compute_internal_energy(neighbor_spins);
        let shannon_entropy_s = self.compute_shannon_entropy();

        // Helmholtz Free Energy: F = U - T * S
        // When an agent fixates on a deterministic exploit chain, S drops toward 0 while U and T spike.
        let helmholtz_free_energy =
            internal_energy_u - (self.effective_temperature * shannon_entropy_s);

        // Ising Percolation check: mean magnetization of connected peers
        let mean_magnetization = if neighbor_spins.is_empty() {
            -1.0
        } else {
            neighbor_spins.iter().sum::<f64>() / (neighbor_spins.len() as f64)
        };

        if helmholtz_free_energy > self.critical_free_energy || mean_magnetization > 0.35 {
            return ContainmentPolicy::CriticalPhaseTransition {
                reason: "Supercritical Helmholtz free energy or Ising mesh percolation threshold exceeded",
                free_energy: helmholtz_free_energy,
            };
        }

        if helmholtz_free_energy > self.critical_free_energy * 0.65 {
            let excess = helmholtz_free_energy - (self.critical_free_energy * 0.65);
            let throttle_ms = (excess * 25.0).clamp(10.0, 5000.0) as u64;
            let noise_scale = (excess / self.critical_free_energy).clamp(0.01, 1.0);
            return ContainmentPolicy::LangevinDamping {
                throttle_ms,
                noise_scale,
            };
        }

        ContainmentPolicy::Equilibrium {
            free_energy: helmholtz_free_energy,
        }
    }

    fn compute_internal_energy(&self, neighbor_spins: &[f64]) -> f64 {
        if self.total_actions == 0 {
            return 0.0;
        }

        let avg_capability_energy: f64 = self
            .action_counts
            .iter()
            .map(|(cap, &count)| cap.hamiltonian_energy() * (count as f64))
            .sum::<f64>()
            / (self.total_actions as f64);

        let spin_interaction: f64 = neighbor_spins
            .iter()
            .map(|&spin| -self.coupling_constant_j * spin)
            .sum();

        // Positive spin (+1.0) from compromised neighbors lowers the barrier to contagion,
        // so we invert the sign to represent threat potential energy.
        avg_capability_energy - spin_interaction
    }

    fn compute_shannon_entropy(&self) -> f64 {
        if self.total_actions == 0 {
            return 0.0;
        }
        let n = self.total_actions as f64;
        self.action_counts
            .values()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = (c as f64) / n;
                -p * p.ln()
            })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_equilibrium_vs_critical_phase_transition() {
        let mut gov = ThermodynamicGovernor::default_edr_governor();
        let eq = gov.evaluate_action(AgentCapability::ReadWorkspace, 1.0, &[-1.0, -1.0]);
        assert!(matches!(eq, ContainmentPolicy::Equilibrium { .. }));

        // High-energy kernel module interaction with compromised neighbors (+1.0 spins)
        let crit = gov.evaluate_action(
            AgentCapability::KernelModuleInteraction,
            25.0,
            &[1.0, 1.0, 1.0],
        );
        assert!(matches!(
            crit,
            ContainmentPolicy::CriticalPhaseTransition { .. }
        ));
    }
}
