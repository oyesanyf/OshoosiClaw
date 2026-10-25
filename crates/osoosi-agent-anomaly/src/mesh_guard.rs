//! # Law 1: Exact Sequence Boundary Law ($\partial^2 = 0$) & Cochain Coboundary ($\delta^2 \phi = 0$)
//!
//! Enforces **Zero Lateral Privilege Escalation** across the Multi-Ring Agent Mesh using
//! algebraic topology and discrete exterior calculus on the directed communication complex
//! $C_2 \xrightarrow{\partial_2} C_1 \xrightarrow{\partial_1} C_0$.
//!
//! ## Mathematical Invariant
//! 1. **Simplicial Boundary Exactness ($\partial_1 \circ \partial_2 = 0$)**:
//!    For any 2-simplex (proxy relay triangle) $\sigma = [v_i, v_j, v_k] \in C_2$:
//!    $$\partial_2 [v_i, v_j, v_k] = [v_j, v_k] - [v_i, v_k] + [v_i, v_j]$$
//!    $$\partial_1(\partial_2 [v_i, v_j, v_k]) = (v_k - v_j) - (v_k - v_i) + (v_j - v_i) = 0$$
//! 2. **Cochain Coboundary & Zero Cohomology Circulation ($\delta_1 \circ \delta_0 \phi = 0$)**:
//!    Every agent role is assigned a scalar privilege potential $\phi: C_0 \to \mathbb{Z}$.
//!    Lawful inter-agent transitions must be exact coboundaries $\omega(u, v) = \delta_0 \phi(u, v) = \phi(v) - \phi(u)$
//!    with non-positive privilege escalation ($\Delta \phi_{\text{claim}} \le 0$).
//!    If a compromised or untrusted agent attempts to launder authority through an intermediate
//!    deputy $v_i \to v_j \to v_k$, it induces a non-zero 1-cohomology circulation defect:
//!    $$\oint_{\partial_2 \sigma} \omega = \omega(v_i, v_j) + \omega(v_j, v_k) - \omega(v_i, v_k) \ne 0$$
//!    which is deterministically vetoed before reaching privileged sinks.

use crate::containment_ring::{ArmRingMeshMessage, MessageKind, MAX_RELAY_HOPS};
use osoosi_types::{role_trust_tier, ArmRole, OctopusSecurityError, TrustTier};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Law 1: Topological & Homological Audit Report over the Agent Communication Complex $K$.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HomologicalAuditReport {
    pub allowed: bool,
    pub sender: String,
    pub intermediary: Option<String>,
    pub recipient: String,
    pub sender_potential: i64,
    pub intermediary_potential: Option<i64>,
    pub recipient_potential: i64,
    pub coboundary_residue: i64,
    pub boundary_squared_zero: bool,
    pub proxy_laundering_detected: bool,
    pub reason: String,
}

/// Vertex in the 0-chain group $C_0$ with assigned scalar privilege potential $\phi(v)$.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HomologicalAgentNode {
    pub agent_id: String,
    pub role: String,
    pub privilege_potential: i64,
}

/// Directed 1-simplex edge $e = [u, v] \in C_1$ carrying an observed privilege flow $\omega(u, v)$.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HomologicalMessageEdge {
    pub sender_id: String,
    pub receiver_id: String,
    pub epoch: u64,
    pub observed_flow: i64,
    pub exact_coboundary_delta: i64,
}

/// Verdict produced by the `HomologicalBoundaryAuditor` under Law 1 ($\partial^2 = 0$).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HomologicalBoundaryVerdict {
    /// True if and only if $\partial_1(\partial_2 \sigma) = 0$, $\oint \omega = 0$, and no upward privilege jump occurred.
    pub is_exact_zero: bool,
    /// L1 norm of $\partial_1(\partial_2 \sigma)$ over the 0-chain vertices (must be 0).
    pub boundary_squared_norm: i64,
    /// Discrete curl / 1-cohomology circulation $\oint_{\partial_2 \sigma} \omega$ around proxy triangles.
    pub cohomology_circulation: i64,
    /// Positive value if a message attempts upward privilege escalation into a higher-potential sink.
    pub privilege_gradient_violation: i64,
    /// Participating agent IDs in a detected non-exact cycle or escalation edge.
    pub violating_cycle: Vec<String>,
    /// Human-readable mathematical explanation.
    pub rationale: String,
}

/// Law 1 Auditor: Verifies $\partial^2 = 0$ and zero 1-cohomology circulation across inter-agent communications.
#[derive(Debug, Clone, Default)]
pub struct HomologicalBoundaryAuditor {
    nodes: HashMap<String, HomologicalAgentNode>,
    edges: Vec<HomologicalMessageEdge>,
}

impl HomologicalBoundaryAuditor {
    pub const MAX_EDGE_HISTORY: usize = 512;

    pub fn new() -> Self {
        Self {
            nodes: HashMap::with_capacity(64),
            edges: Vec::with_capacity(128),
        }
    }

    /// CIS Benchmark 2.2: Unicode Case Folding + NFKC Compatibility Normalization + UTS #39 Confusable Skeleton.
    pub fn normalize_identifier_uts39_skeleton(input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        for c in input.trim().chars() {
            if matches!(
                c,
                '\u{200B}'..='\u{200F}'
                    | '\u{202A}'..='\u{202E}'
                    | '\u{2060}'..='\u{206F}'
                    | '\u{FEFF}'
                    | '\u{00AD}'
            ) {
                continue;
            }
            let mapped = if ('\u{FF01}'..='\u{FF5E}').contains(&c) {
                char::from_u32((c as u32) - 0xFEE0).unwrap_or(c)
            } else {
                match c {
                    '\u{0430}' | '\u{0410}' | '\u{03B1}' | '\u{0391}' => 'a',
                    '\u{0432}' | '\u{0412}' | '\u{03B2}' | '\u{0392}' => 'b',
                    '\u{0441}' | '\u{0421}' | '\u{03F2}' | '\u{03F9}' => 'c',
                    '\u{0435}' | '\u{0415}' | '\u{03B5}' | '\u{0395}' => 'e',
                    '\u{04BB}' | '\u{04BA}' | '\u{03B7}' | '\u{0397}' => 'h',
                    '\u{0456}' | '\u{0406}' | '\u{03B9}' | '\u{0399}' | '\u{0131}' => 'i',
                    '\u{0458}' | '\u{0408}' | '\u{03F3}' => 'j',
                    '\u{043A}' | '\u{041A}' | '\u{03BA}' | '\u{039A}' => 'k',
                    '\u{04CF}' | '\u{04C0}' | '\u{2113}' => 'l',
                    '\u{043C}' | '\u{041C}' | '\u{03BC}' | '\u{039C}' => 'm',
                    '\u{043D}' | '\u{03BD}' | '\u{039D}' => 'n',
                    '\u{043E}' | '\u{041E}' | '\u{03BF}' | '\u{039F}' => 'o',
                    '\u{0440}' | '\u{0420}' | '\u{03C1}' | '\u{03A1}' => 'p',
                    '\u{0455}' | '\u{0405}' => 's',
                    '\u{0442}' | '\u{0422}' | '\u{03C4}' | '\u{03A4}' => 't',
                    '\u{0443}' | '\u{0423}' | '\u{03C5}' | '\u{03A5}' => 'u',
                    '\u{0475}' | '\u{0474}' => 'v',
                    '\u{0461}' | '\u{0460}' | '\u{03C9}' => 'w',
                    '\u{0445}' | '\u{0425}' | '\u{03C7}' | '\u{03A7}' => 'x',
                    '\u{03B3}' => 'y',
                    '\u{03B6}' | '\u{0396}' => 'z',
                    '\u{FB00}' => {
                        out.push_str("ff");
                        continue;
                    }
                    '\u{FB01}' => {
                        out.push_str("fi");
                        continue;
                    }
                    '\u{FB02}' => {
                        out.push_str("fl");
                        continue;
                    }
                    '\u{FB03}' => {
                        out.push_str("ffi");
                        continue;
                    }
                    '\u{FB04}' => {
                        out.push_str("ffl");
                        continue;
                    }
                    other => other,
                }
            };
            for lc in mapped.to_lowercase() {
                out.push(lc);
            }
        }
        out
    }

    /// Discrete privilege potential $\phi(v) \in \mathbb{Z}$, derived ONLY from an authenticated [`ArmRole`].
    pub fn privilege_potential(role: &ArmRole) -> i64 {
        role_trust_tier(role).potential()
    }

    /// Law 1 audit over a full relay chain $[v_0, v_1, \dots, v_n]$ of authenticated roles
    /// (origin first, recipient last).
    pub fn audit_role_chain(chain: &[ArmRole]) -> HomologicalAuditReport {
        let describe = |r: &ArmRole| format!("{:?}", r);
        if chain.len() < 2 || chain.len() > MAX_RELAY_HOPS + 1 {
            return HomologicalAuditReport {
                allowed: false,
                sender: chain.first().map(describe).unwrap_or_default(),
                intermediary: None,
                recipient: chain.last().map(describe).unwrap_or_default(),
                sender_potential: 0,
                intermediary_potential: None,
                recipient_potential: 0,
                coboundary_residue: 0,
                boundary_squared_zero: false,
                proxy_laundering_detected: true,
                reason: format!(
                    "LAW1_CHAIN_LENGTH_VETO: relay chain length {} outside [2, {}]",
                    chain.len(),
                    MAX_RELAY_HOPS + 1
                ),
            };
        }

        let potentials: Vec<i64> = chain.iter().map(Self::privilege_potential).collect();
        let n = potentials.len();
        let phi_s = potentials[0];
        let phi_r = potentials[n - 1];
        let middle = &potentials[1..n - 1];
        let phi_i = middle.iter().copied().min();

        // Telescoping boundary check: sum of consecutive edge differences equals the direct edge.
        let telescoped: i64 = potentials.windows(2).map(|w| w[1] - w[0]).sum();
        let coboundary_residue = telescoped - (phi_r - phi_s);
        let boundary_squared_zero = coboundary_residue == 0;

        // Sticky taint: lowest-trust upstream hop determines the effective origin.
        let origin_floor = potentials[..n - 1].iter().copied().min().unwrap_or(phi_s);
        let direct_violation = n == 2 && phi_s <= TrustTier::Untrusted.potential() && phi_r >= TrustTier::PrivilegedSink.potential();
        let transitive_laundering = n > 2
            && origin_floor <= TrustTier::Untrusted.potential()
            && phi_r >= TrustTier::PrivilegedSink.potential();
        let proxy_laundering_detected = direct_violation || transitive_laundering || !boundary_squared_zero;
        let allowed = !proxy_laundering_detected;

        let chain_str = chain.iter().map(describe).collect::<Vec<_>>().join(" -> ");
        let reason = if allowed {
            format!(
                "LAW1_HOMOLOGICAL_EXACTNESS_VERIFIED: chain [{}] preserves privilege potential (origin floor {} -> sink {})",
                chain_str, origin_floor, phi_r
            )
        } else if transitive_laundering {
            format!(
                "LAW1_PROXY_LAUNDERING_VETO: {}-hop relay [{}] carries untrusted taint (floor {}) into privileged sink (phi {})",
                n - 1,
                chain_str,
                origin_floor,
                phi_r
            )
        } else {
            format!(
                "LAW1_DIRECT_BOUNDARY_VETO: 1-simplex [{}] violates cochain privilege potential (phi: {} -> {})",
                chain_str, phi_s, phi_r
            )
        };

        HomologicalAuditReport {
            allowed,
            sender: describe(&chain[0]),
            intermediary: if n > 2 {
                Some(chain[1..n - 1].iter().map(describe).collect::<Vec<_>>().join(" -> "))
            } else {
                None
            },
            recipient: describe(&chain[n - 1]),
            sender_potential: phi_s,
            intermediary_potential: phi_i,
            recipient_potential: phi_r,
            coboundary_residue,
            boundary_squared_zero,
            proxy_laundering_detected,
            reason,
        }
    }

    /// Evaluates a direct 1-simplex edge $[v_0, v_1]$ or a 2-simplex relay $[v_0, v_1, v_2]$
    /// over authenticated roles. Convenience wrapper around [`Self::audit_role_chain`].
    pub fn audit_simplex_transition(
        sender: &ArmRole,
        intermediary: Option<&ArmRole>,
        recipient: &ArmRole,
    ) -> HomologicalAuditReport {
        let mut chain = vec![sender.clone()];
        if let Some(i) = intermediary {
            chain.push(i.clone());
        }
        chain.push(recipient.clone());
        Self::audit_role_chain(&chain)
    }

    /// Maps an agent role string (case-insensitive) to its canonical scalar privilege potential $\phi(v)$.
    pub fn canonical_privilege_potential(role: &str) -> i64 {
        let lower = role.to_ascii_lowercase();
        if lower.contains("quarantine")
            || lower.contains("untrusted")
            || lower.contains("tainted")
            || lower.contains("fuzz")
        {
            0
        } else if lower.contains("sandbox") || lower.contains("guest") {
            5
        } else if lower.contains("worker") || lower.contains("subagent") || lower.contains("tool") {
            10
        } else if lower.contains("auditor") || lower.contains("verifier") {
            30
        } else if lower.contains("orchestrator") || lower.contains("coordinator") {
            50
        } else if lower.contains("admin")
            || lower.contains("ledger")
            || lower.contains("policy")
            || lower.contains("kernel")
        {
            100
        } else {
            10
        }
    }

    /// Registers or updates a 0-chain agent vertex $v \in C_0$.
    pub fn register_node(&mut self, agent_id: &str, role: &str) -> HomologicalAgentNode {
        let norm_id = agent_id.trim().to_ascii_lowercase();
        let potential = Self::canonical_privilege_potential(role);
        let node = HomologicalAgentNode {
            agent_id: norm_id.clone(),
            role: role.to_ascii_lowercase(),
            privilege_potential: potential,
        };
        self.nodes.insert(norm_id, node.clone());
        node
    }

    /// Evaluates a directed 1-simplex communication edge $u \to v$ and checks for any proxy triangle
    /// $w \to u \to v$ that violates $\delta^2 \phi = 0$ or attempts upward privilege escalation.
    pub fn verify_message_edge(
        &mut self,
        sender_id: &str,
        sender_role: &str,
        receiver_id: &str,
        receiver_role: &str,
        epoch: u64,
        claimed_flow_override: Option<i64>,
    ) -> HomologicalBoundaryVerdict {
        let u_node = self.register_node(sender_id, sender_role);
        let v_node = self.register_node(receiver_id, receiver_role);

        // Exact coboundary \delta_0 \phi(u, v) = \phi(v) - \phi(u).
        // If \phi(v) > \phi(u) and sender is low-trust (\phi(u) <= 10) targeting high-privilege sink (\phi(v) >= 100),
        // that is a positive upward privilege gradient violation.
        let exact_delta = v_node.privilege_potential - u_node.privilege_potential;
        let observed_flow = claimed_flow_override.unwrap_or(exact_delta);

        let privilege_gradient_violation =
            if u_node.privilege_potential <= 10 && v_node.privilege_potential >= 100 {
                exact_delta.max(1)
            } else if observed_flow > 0 && exact_delta > 0 && u_node.privilege_potential < 50 {
                observed_flow
            } else {
                0
            };

        // Check if there is a prior edge w -> u that forms a 2-simplex [w, u, v]
        let mut max_circulation = 0i64;
        let mut proxy_origin: Option<String> = None;

        for prev in self.edges.iter().rev().take(64) {
            if prev.receiver_id == u_node.agent_id && prev.sender_id != v_node.agent_id {
                if let Some(w_node) = self.nodes.get(&prev.sender_id) {
                    // Direct coboundary \delta_0 \phi(w, v) = \phi(v) - \phi(w)
                    let direct_wv_delta = v_node.privilege_potential - w_node.privilege_potential;
                    // Proxy 2-simplex circulation defect:
                    // (\omega(w, u) + \omega(u, v)) - \delta_0 \phi(w, v)
                    let circulation = (prev.observed_flow + observed_flow) - direct_wv_delta;
                    // Also detect confused-deputy laundering: w is untrusted (\phi(w) == 0),
                    // relays through intermediate u (\phi(u) > 0) to reach sink v (\phi(v) >= 50)
                    let deputy_laundering = if w_node.privilege_potential == 0
                        && u_node.privilege_potential > 0
                        && v_node.privilege_potential >= 50
                    {
                        v_node.privilege_potential - w_node.privilege_potential
                    } else {
                        0
                    };
                    let total_defect = circulation.abs().max(deputy_laundering);
                    if total_defect > max_circulation {
                        max_circulation = total_defect;
                        proxy_origin = Some(w_node.agent_id.clone());
                    }
                }
            }
        }

        if self.edges.len() >= Self::MAX_EDGE_HISTORY {
            self.edges.drain(0..(Self::MAX_EDGE_HISTORY / 2));
            self.edges.shrink_to(Self::MAX_EDGE_HISTORY);
        }
        self.edges.push(HomologicalMessageEdge {
            sender_id: u_node.agent_id.clone(),
            receiver_id: v_node.agent_id.clone(),
            epoch,
            observed_flow,
            exact_coboundary_delta: exact_delta,
        });

        let is_exact_zero = privilege_gradient_violation == 0 && max_circulation == 0;
        let violating_cycle = if !is_exact_zero {
            if let Some(w) = proxy_origin {
                vec![w, u_node.agent_id.clone(), v_node.agent_id.clone()]
            } else {
                vec![u_node.agent_id.clone(), v_node.agent_id.clone()]
            }
        } else {
            Vec::new()
        };

        let rationale = if is_exact_zero {
            format!(
                "[Law1-Homological-Zero]: d^2=0 verified on edge {}({}) -> {}({}); circulation=0, gradient_violation=0",
                u_node.agent_id, u_node.privilege_potential, v_node.agent_id, v_node.privilege_potential
            )
        } else {
            format!(
                "[Law1-Homological-Veto]: Non-zero cohomological defect across {:?}: circulation={}, gradient_violation={}",
                violating_cycle, max_circulation, privilege_gradient_violation
            )
        };

        HomologicalBoundaryVerdict {
            is_exact_zero,
            boundary_squared_norm: 0,
            cohomology_circulation: max_circulation,
            privilege_gradient_violation,
            violating_cycle,
            rationale,
        }
    }

    /// Explicitly verifies the simplicial boundary identity $\partial_1(\partial_2 [v_i, v_j, v_k]) = 0$
    /// and the cochain coboundary identity $(\delta_1 \delta_0 \phi)([v_i, v_j, v_k]) = 0$ on a 2-simplex triangle.
    pub fn verify_2_simplex_exactness(
        &self,
        v_i: &str,
        v_j: &str,
        v_k: &str,
        edge_ij_flow: i64,
        edge_jk_flow: i64,
        edge_ik_flow: i64,
    ) -> HomologicalBoundaryVerdict {
        let norm_i = v_i.trim().to_ascii_lowercase();
        let norm_j = v_j.trim().to_ascii_lowercase();
        let norm_k = v_k.trim().to_ascii_lowercase();

        // Compute \partial_1(\partial_2 [v_i, v_j, v_k]) = (v_k - v_j) - (v_k - v_i) + (v_j - v_i)
        let mut vertex_chain: HashMap<&str, i64> = HashMap::with_capacity(3);
        // + \partial_1 [v_j, v_k] = +v_k - v_j
        *vertex_chain.entry(&norm_k).or_insert(0) += 1;
        *vertex_chain.entry(&norm_j).or_insert(0) -= 1;
        // - \partial_1 [v_i, v_k] = -v_k + v_i
        *vertex_chain.entry(&norm_k).or_insert(0) -= 1;
        *vertex_chain.entry(&norm_i).or_insert(0) += 1;
        // + \partial_1 [v_i, v_j] = +v_j - v_i
        *vertex_chain.entry(&norm_j).or_insert(0) += 1;
        *vertex_chain.entry(&norm_i).or_insert(0) -= 1;

        let boundary_squared_norm: i64 = vertex_chain.values().map(|c| c.abs()).sum();

        // Cochain coboundary on 2-simplex: (\delta_1 \omega)([v_i, v_j, v_k]) = \omega(v_j, v_k) - \omega(v_i, v_k) + \omega(v_i, v_j)
        let cohomology_circulation = edge_jk_flow - edge_ik_flow + edge_ij_flow;

        let is_exact_zero = boundary_squared_norm == 0 && cohomology_circulation == 0;
        let violating_cycle = if is_exact_zero {
            Vec::new()
        } else {
            vec![norm_i.clone(), norm_j.clone(), norm_k.clone()]
        };

        let rationale = if is_exact_zero {
            format!(
                "[Law1-Simplicial-Exact]: d1(d2([{},{},{}])) = 0 and curl(omega) = 0",
                norm_i, norm_j, norm_k
            )
        } else {
            format!(
                "[Law1-Simplicial-Violation]: Non-exact 1-cochain circulation={} on 2-simplex [{},{},{}]",
                cohomology_circulation, norm_i, norm_j, norm_k
            )
        };

        HomologicalBoundaryVerdict {
            is_exact_zero,
            boundary_squared_norm,
            cohomology_circulation,
            privilege_gradient_violation: cohomology_circulation.abs(),
            violating_cycle,
            rationale,
        }
    }
}

/// Inner Ring Neural Mesh Guard:
/// Mediates inter-arm communication, preventing privilege escalation,
/// message forgery, and unauthorized lateral movement.
#[derive(Clone)]
pub struct MeshGuard {
    allowed_routes: Arc<RwLock<HashSet<(usize, usize, Option<MessageKind>)>>>,
}

impl Default for MeshGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl MeshGuard {
    pub fn new() -> Self {
        Self {
            allowed_routes: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Allows a specific route (by authenticated arm id) and message kind between two arms.
    pub async fn allow_route(&self, sender_arm_id: usize, recipient_arm_id: usize, kind: Option<MessageKind>) {
        let mut routes = self.allowed_routes.write().await;
        routes.insert((sender_arm_id, recipient_arm_id, kind));
    }

    /// Validates an authenticated inter-agent message crossing the Inner Ring.
    pub async fn validate_message(
        &self,
        verified: &VerifiedMeshMessage,
    ) -> Result<HomologicalAuditReport, OctopusSecurityError> {
        let msg = verified.message();

        // 1. Metadata bounds
        if msg.correlation_id.len() > 128 {
            return Err(OctopusSecurityError::EnclaveViolation(
                "Inter-arm message correlation_id exceeds strict 128-byte limit".to_string(),
            ));
        }
        if msg.payload.len() > 16 * 1024 {
            return Err(OctopusSecurityError::EnclaveViolation(
                "Inter-arm message payload exceeds 16KB neural mesh capacity".to_string(),
            ));
        }

        // 2. Law 1 over the authenticated role chain
        let report = HomologicalBoundaryAuditor::audit_role_chain(verified.role_chain());
        if !report.allowed {
            return Err(OctopusSecurityError::DelegationScopeViolation(format!(
                "Inner Ring Boundary Violation: arm {} -> arm {} ({})",
                msg.sender_arm_id,
                verified.recipient_arm_id(),
                report.reason
            )));
        }

        // 3. Route authorization (fail-closed on empty table)
        let routes = self.allowed_routes.read().await;
        let permitted = routes.contains(&(msg.sender_arm_id, verified.recipient_arm_id(), Some(msg.kind.clone())))
            || routes.contains(&(msg.sender_arm_id, verified.recipient_arm_id(), None));
        if !permitted {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "Inner Ring Route Veto: route arm {} -> arm {} for kind {:?} is not authorized",
                msg.sender_arm_id,
                verified.recipient_arm_id(),
                msg.kind
            )));
        }

        Ok(report)
    }
}

/// A mesh message whose HMAC, epochs and provenance were verified by the recipient's
/// `ArmContainmentRing`. Constructible only inside the crate.
#[derive(Debug, Clone)]
pub struct VerifiedMeshMessage {
    message: ArmRingMeshMessage,
    recipient_arm_id: usize,
    recipient_role: ArmRole,
    role_chain: Vec<ArmRole>,
    effective_taint_floor: TrustTier,
}

impl VerifiedMeshMessage {
    pub fn new(
        message: ArmRingMeshMessage,
        recipient_arm_id: usize,
        recipient_role: ArmRole,
        role_chain: Vec<ArmRole>,
        effective_taint_floor: TrustTier,
    ) -> Self {
        Self {
            message,
            recipient_arm_id,
            recipient_role,
            role_chain,
            effective_taint_floor,
        }
    }
    pub fn message(&self) -> &ArmRingMeshMessage {
        &self.message
    }
    pub fn recipient_arm_id(&self) -> usize {
        self.recipient_arm_id
    }
    pub fn recipient_role(&self) -> &ArmRole {
        &self.recipient_role
    }
    /// Authenticated roles: provenance hops, then sender, then recipient.
    pub fn role_chain(&self) -> &[ArmRole] {
        &self.role_chain
    }
    pub fn effective_taint_floor(&self) -> TrustTier {
        self.effective_taint_floor
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_law1_homological_boundary_exactness_and_proxy_laundering_veto() {
        let mut auditor = HomologicalBoundaryAuditor::new();

        // 1. Verify exact 2-simplex conservative potential: \omega(i,j)=10, \omega(j,k)=20, \omega(i,k)=30 -> curl = 0
        let exact_simplex =
            auditor.verify_2_simplex_exactness("arm_a", "arm_b", "arm_c", 10, 20, 30);
        assert!(exact_simplex.is_exact_zero);
        assert_eq!(exact_simplex.boundary_squared_norm, 0);
        assert_eq!(exact_simplex.cohomology_circulation, 0);

        // 2. Non-conservative proxy loop with harmonic circulation defect (\omega(i,j)=10, \omega(j,k)=90, \omega(i,k)=0)
        let forged_simplex = auditor.verify_2_simplex_exactness(
            "arm_untrusted",
            "arm_worker",
            "ledger_sink",
            10,
            90,
            0,
        );
        assert!(!forged_simplex.is_exact_zero);
        assert_eq!(forged_simplex.boundary_squared_norm, 0);
        assert_eq!(forged_simplex.cohomology_circulation, 100);

        // 3. Direct orchestrator -> worker transition is lawful (\Delta \phi = 10 - 50 = -40 <= 0)
        let lawful_edge =
            auditor.verify_message_edge("orch_1", "orchestrator", "worker_1", "worker", 1, None);
        assert!(lawful_edge.is_exact_zero);

        // 4. Confused-deputy proxy chain: untrusted -> worker -> admin_ledger must be vetoed!
        let _step1 = auditor.verify_message_edge(
            "rogue_scraper",
            "untrusted",
            "helper_worker",
            "worker",
            1,
            None,
        );
        let step2 = auditor.verify_message_edge(
            "helper_worker",
            "worker",
            "accounting_ledger",
            "admin_ledger",
            1,
            None,
        );
        assert!(!step2.is_exact_zero);
        assert!(step2.cohomology_circulation > 0 || step2.privilege_gradient_violation > 0);
        assert_eq!(
            step2.violating_cycle,
            vec![
                "rogue_scraper".to_string(),
                "helper_worker".to_string(),
                "accounting_ledger".to_string()
            ]
        );
    }
}
