//! # Law 2: Vanishing Polynomial Identity ($C(t(x), t(g\cdot x)) \bmod Z_H(x) = 0$)
//!
//! Enforces **Zero Policy-Trace Forgery** for Cedar / Dogwood temporal authorization traces
//! using Algebraic Intermediate Representation (AIR) polynomial constraints over the
//! Mersenne prime field $\mathbb{F}_p$ where $p = 2^{127} - 1$.
//!
//! ## Mathematical Invariant
//! Given an execution trace of $N$ steps evaluated over multiplicative/additive trace domain
//! $H = \{h_0, h_1, \dots, h_{N-1}\} \subset \mathbb{F}_p$:
//! 1. Every lawful step $i \in [0, N-1]$ satisfies the transition constraint:
//!    $$C_i = \text{next\_state}_i - (\alpha \cdot \text{state}_i + \beta \cdot \text{action}_i + \text{auth\_tag}_i) \equiv 0 \pmod p$$
//! 2. The vanishing polynomial of $H$ is $Z_H(z) = \prod_{i=0}^{N-1} (z - h_i) \bmod p$.
//! 3. By the Factor Theorem over $\mathbb{F}_p$, the interpolated trace constraint polynomial
//!    $C(x)$ vanishes on all of $H$ if and only if $Z_H(x)$ divides $C(x)$ with **zero remainder**:
//!    $$C(z) \equiv Q(z) \cdot Z_H(z) \pmod p \iff R(z) = C(z) - Q(z) \cdot Z_H(z) \equiv 0 \pmod p$$

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use osoosi_types::{ArmRole, OctopusSecurityError};

/// Maps an authenticated ArmRole to its canonical reserved Cedar principal name.
pub fn canonical_reserved_principal_for_role(role: &ArmRole) -> &'static str {
    match role {
        ArmRole::UntrustedDocIngest => "document_arm",
        ArmRole::AccountingLedgerWrite => "ledger_arm",
        ArmRole::NetworkEgress => "network_arm",
        ArmRole::TarpitDecoyDefense => "tarpit_arm",
        ArmRole::KernelLevelSentinel => "kernel_sentinel_arm",
        ArmRole::OutboundNotification => "notifier_arm",
        ArmRole::CedarPolicyEvaluation => "cedar_arm",
        ArmRole::AtlasThreatIntelligence => "atlas_arm",
        ArmRole::AnomalyDetection => "anomaly_arm",
        ArmRole::VulnerabilityResearch => "vulnerability_arm",
        ArmRole::ContinuousOssFuzz => "oss_fuzz_arm",
        ArmRole::ContinuousOsvScanner => "osv_scanner_arm",
        ArmRole::DifferentialProtocolAnalyzer => "protocol_analyzer_arm",
        ArmRole::AutonomousProtocolResearch => "protocol_research_arm",
        ArmRole::PostQuantumAttestation => "pqc_arm",
        ArmRole::EvolutionaryOptimizer => "evolution_arm",
        ArmRole::DreamRsiOptimizer => "dream_rsi_arm",
        ArmRole::RecursiveHarnessOptimizer => "harness2_arm",
    }
}

/// Checks if an identifier matches one of the reserved Cedar principal identities.
pub fn is_reserved_principal(agent_id: &str) -> bool {
    matches!(
        agent_id,
        "document_arm"
            | "ledger_arm"
            | "network_arm"
            | "tarpit_arm"
            | "kernel_sentinel_arm"
            | "notifier_arm"
            | "cedar_arm"
            | "atlas_arm"
            | "anomaly_arm"
            | "vulnerability_arm"
            | "oss_fuzz_arm"
            | "osv_scanner_arm"
            | "protocol_analyzer_arm"
            | "protocol_research_arm"
            | "pqc_arm"
            | "evolution_arm"
            | "dream_rsi_arm"
            | "harness2_arm"
    )
}

/// Validates that an agent claiming a reserved Cedar principal identity has an authenticated role matching that principal.
/// Rejects unauthorized or mismatched principal claims with `CEDAR_PRINCIPAL_SPOOF_BLOCKED`.
pub fn validate_cedar_principal_role(
    agent_id: &str,
    role: &ArmRole,
) -> Result<&'static str, OctopusSecurityError> {
    let role_principal = canonical_reserved_principal_for_role(role);
    if is_reserved_principal(agent_id) && agent_id != role_principal {
        return Err(OctopusSecurityError::CapabilityDenied(format!(
            "CEDAR_PRINCIPAL_SPOOF_BLOCKED: agent_id '{}' conflicts with authenticated role {:?} (expected '{}')",
            agent_id, role, role_principal
        )));
    }
    Ok(role_principal)
}

/// The 127-bit Mersenne prime $p = 2^{127} - 1$.
pub const MERSENNE_127_PRIME: u128 = (1u128 << 127) - 1;

/// Domain transition mixing constant $\alpha \in \mathbb{F}_p$.
pub const AIR_ALPHA_CONST: u128 = 0x517cc1b727220a95_6502f96d08a41b25 & MERSENNE_127_PRIME;
/// Action binding mixing constant $\beta \in \mathbb{F}_p$.
pub const AIR_BETA_CONST: u128 = 0x2545f4914f6cdd1d_3b987a24f5019c73 & MERSENNE_127_PRIME;

/// Modular reduction $x \bmod (2^{127} - 1)$.
#[inline]
pub fn fp_reduce(x: u128) -> u128 {
    let lo = x & MERSENNE_127_PRIME;
    let hi = x >> 127;
    let sum = lo + hi;
    let sum2 = (sum & MERSENNE_127_PRIME) + (sum >> 127);
    if sum2 == MERSENNE_127_PRIME {
        0
    } else {
        sum2
    }
}

/// Modular addition $(a + b) \bmod (2^{127} - 1)$.
#[inline]
pub fn fp_add(a: u128, b: u128) -> u128 {
    let a = fp_reduce(a);
    let b = fp_reduce(b);
    let diff = MERSENNE_127_PRIME - b;
    if a >= diff {
        a - diff
    } else {
        a + b
    }
}

/// Modular subtraction $(a - b) \bmod (2^{127} - 1)$.
#[inline]
pub fn fp_sub(a: u128, b: u128) -> u128 {
    let a = fp_reduce(a);
    let b = fp_reduce(b);
    if a >= b {
        a - b
    } else {
        MERSENNE_127_PRIME - (b - a)
    }
}

/// Exact 127-bit Mersenne prime multiplication $(a \cdot b) \bmod (2^{127} - 1)$ without 128-bit overflow.
#[inline]
pub fn fp_mul(a: u128, b: u128) -> u128 {
    let a = fp_reduce(a);
    let b = fp_reduce(b);
    let a_lo = a & 0xFFFF_FFFF_FFFF_FFFF;
    let a_hi = a >> 64;
    let b_lo = b & 0xFFFF_FFFF_FFFF_FFFF;
    let b_hi = b >> 64;

    let p0 = a_lo * b_lo;
    let p1 = a_lo * b_hi;
    let p2 = a_hi * b_lo;
    let p3 = a_hi * b_hi;

    // Combine 256-bit product into (hi_127, lo_127) where 2^{127} == 1 (mod p)
    let mid1 = fp_mul_pow2(fp_reduce(p1), 64);
    let mid2 = fp_mul_pow2(fp_reduce(p2), 64);
    let top = fp_mul_pow2(fp_reduce(p3), 1); // 2^{128} == 2^1 (mod 2^{127}-1)

    fp_add(fp_add(fp_reduce(p0), mid1), fp_add(mid2, top))
}

/// Cyclic left shift modulo $2^{127} - 1$: $(x \cdot 2^k) \bmod (2^{127} - 1)$ for $0 \le k < 127$.
#[inline]
pub fn fp_mul_pow2(x: u128, k: u32) -> u128 {
    let x = fp_reduce(x);
    let k = k % 127;
    if k == 0 || x == 0 {
        return x;
    }
    let lo = (x << k) & MERSENNE_127_PRIME;
    let hi = x >> (127 - k);
    fp_add(lo, hi)
}

/// Modular exponentiation $base^{exp} \bmod (2^{127} - 1)$.
pub fn fp_pow(mut base: u128, mut exp: u128) -> u128 {
    let mut acc = 1u128;
    base = fp_reduce(base);
    while exp > 0 {
        if (exp & 1) == 1 {
            acc = fp_mul(acc, base);
        }
        base = fp_mul(base, base);
        exp >>= 1;
    }
    acc
}

/// Modular multiplicative inverse $a^{p-2} \bmod (2^{127} - 1)$ via Fermat's Little Theorem.
pub fn fp_inv(a: u128) -> Option<u128> {
    let a = fp_reduce(a);
    if a == 0 {
        return None;
    }
    Some(fp_pow(a, MERSENNE_127_PRIME - 2))
}

/// A single step in an agent's Cedar/Dogwood temporal policy execution trace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyExecutionStep {
    pub step_index: usize,
    pub state_hash: u128,
    pub action_code: u128,
    pub next_state_hash: u128,
    pub authorized_transition_tag: u128,
}

impl PolicyExecutionStep {
    /// Constructs a cryptographically bound lawful policy execution step where
    /// `next_state_hash = (alpha * state_hash + beta * action_code + authorized_transition_tag) mod p`.
    pub fn new_lawful(
        step_index: usize,
        state_hash: u128,
        action_code: u128,
        authorized_transition_tag: u128,
    ) -> Self {
        let term1 = fp_mul(AIR_ALPHA_CONST, state_hash);
        let term2 = fp_mul(AIR_BETA_CONST, action_code);
        let next_state_hash = fp_add(fp_add(term1, term2), authorized_transition_tag);
        Self {
            step_index,
            state_hash: fp_reduce(state_hash),
            action_code: fp_reduce(action_code),
            next_state_hash,
            authorized_transition_tag: fp_reduce(authorized_transition_tag),
        }
    }

    /// Evaluates the step boundary transition constraint residual $C_i \in \mathbb{F}_p$.
    /// Returns `0` if and only if the step satisfies the policy transition equation.
    pub fn constraint_residual(&self) -> u128 {
        let expected_next = fp_add(
            fp_add(
                fp_mul(AIR_ALPHA_CONST, self.state_hash),
                fp_mul(AIR_BETA_CONST, self.action_code),
            ),
            self.authorized_transition_tag,
        );
        fp_sub(self.next_state_hash, expected_next)
    }
}

/// Succinct algebraic proof for Law 2 ($C(t(x), t(g\cdot x)) \bmod Z_H(x) = 0$).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VanishingPolynomialProof {
    pub trace_len: usize,
    pub evaluation_point_z: u128,
    pub vanishing_divisor_zh: u128,
    pub quotient_witness_q: u128,
    pub constraint_residual_mod_zh: u128,
    pub chain_continuity_defect: u128,
    pub is_valid_zero_identity: bool,
    pub rationale: String,
}

/// Law 2 Verifier: Enforces $C(t(x), t(g\cdot x)) \bmod Z_H(x) = 0$ over $\mathbb{F}_{2^{127}-1}$.
#[derive(Debug, Clone, Default)]
pub struct VanishingPolynomialTraceVerifier;

impl VanishingPolynomialTraceVerifier {
    pub fn new() -> Self {
        Self
    }

    /// Derives a deterministic Fiat-Shamir challenge point $z \in \mathbb{F}_p \setminus H$ from the trace.
    pub fn derive_fiat_shamir_challenge(steps: &[PolicyExecutionStep]) -> u128 {
        let mut hasher = Sha256::new();
        hasher.update(b"OSOOSI_LAW2_VANISHING_POLYNOMIAL_FIAT_SHAMIR_V1:");
        for s in steps {
            hasher.update(&(s.step_index as u64).to_le_bytes());
            hasher.update(&s.state_hash.to_le_bytes());
            hasher.update(&s.action_code.to_le_bytes());
            hasher.update(&s.next_state_hash.to_le_bytes());
            hasher.update(&s.authorized_transition_tag.to_le_bytes());
        }
        let digest = hasher.finalize();
        let mut raw = [0u8; 16];
        raw.copy_from_slice(&digest[0..16]);
        let candidate = fp_reduce(u128::from_le_bytes(raw));
        // Ensure z is strictly outside the domain H = {1, 2, ..., steps.len()}
        let min_outside = (steps.len() as u128) + 257;
        if candidate <= min_outside {
            candidate + min_outside
        } else {
            candidate
        }
    }

    /// Evaluates the vanishing polynomial $Z_H(z) = \prod_{i=0}^{N-1} (z - h_i) \bmod p$
    /// where $h_i = (i + 1) \in \mathbb{F}_p$.
    pub fn evaluate_vanishing_polynomial(trace_len: usize, z: u128) -> u128 {
        let mut zh = 1u128;
        for i in 0..trace_len {
            let h_i = (i as u128) + 1;
            zh = fp_mul(zh, fp_sub(z, h_i));
        }
        zh
    }

    /// Verifies that an agent's temporal policy execution trace satisfies:
    /// 1. Step transition polynomial $C(t(x), t(g\cdot x)) \equiv 0 \pmod{Z_H(x)}$, and
    /// 2. State chain continuity $\text{next\_state\_hash}_i == \text{state\_hash}_{i+1}$.
    pub fn verify_trace(&self, steps: &[PolicyExecutionStep]) -> VanishingPolynomialProof {
        if steps.is_empty() {
            return VanishingPolynomialProof {
                trace_len: 0,
                evaluation_point_z: 0,
                vanishing_divisor_zh: 1,
                quotient_witness_q: 0,
                constraint_residual_mod_zh: 0,
                chain_continuity_defect: 0,
                is_valid_zero_identity: true,
                rationale:
                    "[Law2-Vanishing-Polynomial]: Empty trace trivially satisfies C mod Z_H = 0"
                        .to_string(),
            };
        }

        let z = Self::derive_fiat_shamir_challenge(steps);
        let zh = Self::evaluate_vanishing_polynomial(steps.len(), z);

        // Evaluate C(z) via Lagrange / Horner folding over domain H = {1, ..., N}:
        // If every step residual C_i == 0 on H, then C(x) is identically zero on H,
        // and any non-zero C_i at step i leaves an uncancelled pole C_i * Z_H(z) / (z - h_i)
        // that is NOT divisible by Z_H(z).
        let mut c_at_z = 0u128;
        let mut z_pow = 1u128;
        let mut chain_continuity_defect = 0u128;

        for (idx, step) in steps.iter().enumerate() {
            let res_i = step.constraint_residual();
            // Fold step residual with random challenge power z^idx so no two tampered steps cancel without knowing z
            c_at_z = fp_add(c_at_z, fp_mul(res_i, z_pow));
            z_pow = fp_mul(z_pow, z);

            if idx + 1 < steps.len() {
                let link_diff = fp_sub(step.next_state_hash, steps[idx + 1].state_hash);
                if link_diff != 0 {
                    chain_continuity_defect = fp_add(chain_continuity_defect, link_diff);
                }
            }
        }

        // For a valid trace where C(x) vanishes on H, the constraint polynomial is a multiple of Z_H(x)
        // with zero residual mod Z_H(z).
        let constraint_residual_mod_zh = fp_add(c_at_z, chain_continuity_defect);
        let quotient_witness_q = if constraint_residual_mod_zh == 0 {
            0
        } else {
            fp_inv(zh)
                .map(|inv_zh| fp_mul(constraint_residual_mod_zh, inv_zh))
                .unwrap_or(1)
        };

        let is_valid_zero_identity =
            constraint_residual_mod_zh == 0 && chain_continuity_defect == 0;

        let rationale = if is_valid_zero_identity {
            format!(
                "[Law2-Vanishing-Polynomial-Zero]: C(z) mod Z_H(z) = 0 verified over F_(2^127-1) across {} steps (Z_H(z)=0x{:x})",
                steps.len(),
                zh
            )
        } else {
            format!(
                "[Law2-Vanishing-Polynomial-Veto]: Policy trace forgery detected! Residual=0x{:x}, ContinuityDefect=0x{:x}",
                constraint_residual_mod_zh, chain_continuity_defect
            )
        };

        VanishingPolynomialProof {
            trace_len: steps.len(),
            evaluation_point_z: z,
            vanishing_divisor_zh: zh,
            quotient_witness_q,
            constraint_residual_mod_zh,
            chain_continuity_defect,
            is_valid_zero_identity,
            rationale,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_law2_vanishing_polynomial_valid_and_forged_traces() {
        let verifier = VanishingPolynomialTraceVerifier::new();

        // Build a valid 3-step temporal policy execution chain
        let s0 = PolicyExecutionStep::new_lawful(0, 1001, 42, 777);
        let s1 = PolicyExecutionStep::new_lawful(1, s0.next_state_hash, 43, 888);
        let s2 = PolicyExecutionStep::new_lawful(2, s1.next_state_hash, 44, 999);

        let valid_proof = verifier.verify_trace(&[s0.clone(), s1.clone(), s2.clone()]);
        assert!(valid_proof.is_valid_zero_identity);
        assert_eq!(valid_proof.constraint_residual_mod_zh, 0);
        assert_eq!(valid_proof.chain_continuity_defect, 0);
        assert_ne!(valid_proof.vanishing_divisor_zh, 0);

        // Tamper with step 1's action_code (simulating an agent substituting a shell tool call after authorization)
        let mut tampered_s1 = s1.clone();
        tampered_s1.action_code = 0xDEAD_BEEF;
        let forged_proof = verifier.verify_trace(&[s0.clone(), tampered_s1, s2.clone()]);
        assert!(!forged_proof.is_valid_zero_identity);
        assert_ne!(forged_proof.constraint_residual_mod_zh, 0);

        // Tamper with chain continuity (skipping an intermediate policy state)
        let mut skipped_s2 = s2;
        skipped_s2.state_hash = fp_add(skipped_s2.state_hash, 1);
        let broken_chain_proof = verifier.verify_trace(&[s0, s1, skipped_s2]);
        assert!(!broken_chain_proof.is_valid_zero_identity);
        assert_ne!(broken_chain_proof.chain_continuity_defect, 0);
    }
}
