//! Byzantine-fault-aware policy consensus + Sybil-resistant weighting for the mesh.
//!
//! Layers (configurable via env):
//! - **BFT quorum** (pBFT-style among *participating* voters): ⌈2/3⌉ `Optimal`, or weighted stake share.
//! - **Nakamoto-style majority on stake** (optional): `OSOOSI_BFT_WEIGHT_THRESHOLD=0.51` for “>50% stake” on optimals.
//! - **Proof-of-stake analogue**: reputation is **stake**; `OSOOSI_POS_STAKE_EXPONENT` skews weight toward high-rep nodes.
//! - **Proof-of-work on votes** (optional): `OSOOSI_POW_VOTE_BITS` — each vote may carry `work_nonce` (hex); hash must have enough leading zero bits (hardware cost to Sybil IDs).
//! - **Permissioned / PoA**: `OSOOSI_MESH_VOTER_WHITELIST` — comma-separated `voter_id`s; others’ votes are ignored.
//! - **pBFT context**: optional `mesh_peer_hint` records max tolerable faults `f = ⌊(n−1)/3⌋` for ops logging.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use osoosi_types::{PolicyConsensusMessage, PolicyHealthStatus, PolicyHealthVote, WitnessVote};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// Tunable thresholds; see module docs for env vars.
#[derive(Clone, Debug)]
pub struct BftConsensusParams {
    pub high_trust_reputation: f32,
    pub low_trust_reputation: f32,
    pub min_mean_optimal_reputation: f32,
    pub small_mesh_participating_max: usize,
    /// Leading zero bits required on SHA256(voter|policy|nonce) when > 0 (PoW gate).
    pub pow_vote_leading_zero_bits: u8,
    /// If set, only these `voter_id`s count toward quorum (permissioned / PKI-style allowlist).
    pub voter_whitelist: Option<HashSet<String>>,
    /// Weighted stake fraction to declare optimals winning (default 2/3; use 0.51 for Nakamoto-style majority).
    pub weighted_vote_threshold: f64,
    /// Exponent on reputation when summing stake (PoS skew; 1.0 = linear).
    pub pos_stake_exponent: f64,
    /// Observed mesh size (e.g. from `mesh_peer_count`) for pBFT `f` diagnostics.
    pub mesh_peer_hint: Option<u32>,
    /// Minimum reputation required for both nodes in a 2-host mesh to establish quorum of 2 (default 0.80).
    pub two_host_reputation_threshold: f32,
    /// Designated arbiter / witness ID for breaking 2-host stalemates.
    pub designated_witness_id: Option<String>,
    /// Designated witness Ed25519 public key (hex) for verifying witness signature.
    pub witness_public_key: Option<String>,
    /// Enable weighted reputation tie-breaker when no witness vote is received.
    pub enable_reputation_tie_breaker: bool,
    /// Minimum reputation delta required to break a tie via reputation (e.g. 0.05).
    pub tie_breaker_reputation_margin: f32,
}

impl Default for BftConsensusParams {
    fn default() -> Self {
        let whitelist = std::env::var("OSOOSI_MESH_VOTER_WHITELIST").ok().map(|s| {
            s.split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect::<HashSet<_>>()
        });
        let whitelist = if whitelist.as_ref().is_some_and(|w| w.is_empty()) {
            None
        } else {
            whitelist
        };

        Self {
            high_trust_reputation: std::env::var("OSOOSI_BFT_HIGH_TRUST")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0.85),
            low_trust_reputation: std::env::var("OSOOSI_BFT_LOW_TRUST")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0.45),
            min_mean_optimal_reputation: std::env::var("OSOOSI_BFT_MIN_MEAN_OPT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0.55),
            small_mesh_participating_max: std::env::var("OSOOSI_BFT_SMALL_MESH")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8),
            pow_vote_leading_zero_bits: std::env::var("OSOOSI_POW_VOTE_BITS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            voter_whitelist: whitelist,
            weighted_vote_threshold: std::env::var("OSOOSI_BFT_WEIGHT_THRESHOLD")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(2.0 / 3.0),
            pos_stake_exponent: std::env::var("OSOOSI_POS_STAKE_EXPONENT")
                .ok()
                .and_then(|s| s.parse::<f64>().ok())
                .unwrap_or(1.0)
                .clamp(0.5_f64, 4.0_f64),
            mesh_peer_hint: None,
            two_host_reputation_threshold: std::env::var("OSOOSI_BFT_TWO_HOST_TRUST")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0.80),
            designated_witness_id: std::env::var("OSOOSI_BFT_WITNESS_ID").ok(),
            witness_public_key: std::env::var("OSOOSI_BFT_WITNESS_PUBKEY").ok(),
            enable_reputation_tie_breaker: std::env::var("OSOOSI_BFT_REP_TIE_BREAKER")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(true),
            tie_breaker_reputation_margin: std::env::var("OSOOSI_BFT_TIE_MARGIN")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0.05),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct PolicyBftOutcome {
    pub mesh_validated: bool,
    pub quorum: usize,
    pub participating_voters: usize,
    pub optimal_count: usize,
    pub critical_count: usize,
    pub degraded_count: usize,
    pub weighted_optimal_share: f64,
    pub high_trust_endorsement: bool,
    pub mean_optimal_reputation: f64,
    pub penalize_critical_voters: Vec<String>,
    pub stalemate_conflict: bool,
    /// pBFT: max Byzantine faults tolerated for hinted mesh size `n`: `f = ⌊(n−1)/3⌋`.
    pub pbft_max_faults: Option<u32>,
    /// Whether consensus was resolved via witness/arbiter tie-breaker.
    pub witness_resolved: bool,
    /// The winning health status if consensus succeeded or was resolved by witness/tie-breaker.
    pub winning_status: Option<PolicyHealthStatus>,
}

/// Count leading zero bits (MSB-first) of SHA-256 output.
pub fn sha256_leading_zero_bits(data: &[u8]) -> u32 {
    let mut count = 0u32;
    for byte in data {
        for i in 0..8 {
            let mask = 0x80u8 >> i;
            if byte & mask == 0 {
                count += 1;
            } else {
                return count;
            }
        }
    }
    count
}

/// Verify vote PoW: `SHA256(voter_id | policy_id | work_nonce_hex)` has ≥ `required_bits` leading zero bits.
pub fn vote_work_proof_valid(
    voter_id: &str,
    policy_id: &str,
    work_nonce: Option<&str>,
    required_bits: u8,
) -> bool {
    if required_bits == 0 {
        return true;
    }
    let Some(nonce) = work_nonce else {
        return false;
    };
    if nonce.len() < 8 {
        return false;
    }
    let mut hasher = Sha256::new();
    hasher.update(voter_id.as_bytes());
    hasher.update(b"|");
    hasher.update(policy_id.as_bytes());
    hasher.update(b"|");
    hasher.update(nonce.as_bytes());
    let out = hasher.finalize();
    sha256_leading_zero_bits(&out) >= u32::from(required_bits)
}

/// Brute-force a minimal hex nonce (for tests / ops tooling). May take time if `bits` is large.
pub fn mine_vote_work_nonce(voter_id: &str, policy_id: &str, required_bits: u8) -> Option<String> {
    if required_bits == 0 {
        return Some(String::new());
    }
    if required_bits > 24 {
        return None;
    }
    for i in 0u64..10_000_000 {
        let nonce = format!("{:016x}", i);
        if vote_work_proof_valid(voter_id, policy_id, Some(&nonce), required_bits) {
            return Some(nonce);
        }
    }
    None
}

fn latest_votes_per_peer(messages: &[PolicyConsensusMessage]) -> HashMap<String, PolicyHealthVote> {
    let mut m: HashMap<String, PolicyHealthVote> = HashMap::new();
    let now = chrono::Utc::now();
    for msg in messages {
        if let PolicyConsensusMessage::Vote(v) = msg {
            // Drop future-dated votes (> 120s into the future) to prevent timeline poisoning
            if (v.timestamp - now).num_seconds() > 120 {
                continue;
            }
            match m.get_mut(&v.voter_id) {
                Some(existing) => {
                    // Retain only the freshest vote; replayed older votes cannot overwrite newer votes
                    if v.timestamp > existing.timestamp {
                        *existing = v.clone();
                    }
                }
                None => {
                    m.insert(v.voter_id.clone(), v.clone());
                }
            }
        }
    }
    m
}

fn apply_sybil_filters(
    mut latest: HashMap<String, PolicyHealthVote>,
    params: &BftConsensusParams,
) -> HashMap<String, PolicyHealthVote> {
    if let Some(ref wl) = params.voter_whitelist {
        latest.retain(|id, _| wl.contains(id));
    }
    if params.pow_vote_leading_zero_bits > 0 {
        latest.retain(|_, v| {
            vote_work_proof_valid(
                &v.voter_id,
                &v.policy_id,
                v.work_nonce.as_deref(),
                params.pow_vote_leading_zero_bits,
            )
        });
    }
    latest
}

fn stake_weight(rep: f32, exp: f64) -> f64 {
    f64::from(rep.max(0.01)).powf(exp)
}

/// Analyze one policy’s message history (announcements ignored for quorum; votes dedupe by peer).
pub fn analyze_policy_consensus(
    messages: &[PolicyConsensusMessage],
    reputation: impl Fn(&str) -> f32,
    params: &BftConsensusParams,
) -> PolicyBftOutcome {
    let latest = apply_sybil_filters(latest_votes_per_peer(messages), params);
    let participating = latest.len();
    if participating == 0 {
        return PolicyBftOutcome::default();
    }

    let both_high_trust = participating == 2
        && latest
            .values()
            .all(|v| reputation(&v.voter_id) >= params.two_host_reputation_threshold);

    let quorum = if both_high_trust {
        2usize
    } else {
        std::cmp::max(3usize, (2 * participating + 2) / 3)
    };

    let mut optimal_ids = Vec::new();
    let mut critical_ids = Vec::new();
    let mut degraded_ids = Vec::new();
    for (id, v) in &latest {
        match v.status {
            PolicyHealthStatus::Optimal => optimal_ids.push(id.clone()),
            PolicyHealthStatus::CriticalFailure => critical_ids.push(id.clone()),
            PolicyHealthStatus::Degraded => degraded_ids.push(id.clone()),
        }
    }

    let optimal_count = optimal_ids.len();
    let critical_count = critical_ids.len();
    let degraded_count = degraded_ids.len();

    let exp = params.pos_stake_exponent;

    let mut w_opt = 0.0f64;
    let mut sum_rep_opt = 0.0f64;
    for id in &optimal_ids {
        let r = reputation(id);
        w_opt += stake_weight(r, exp);
        sum_rep_opt += f64::from(r);
    }

    let mut w_tot = 0.0f64;
    for v in latest.values() {
        let r = reputation(&v.voter_id);
        w_tot += stake_weight(r, exp);
    }

    let weighted_optimal_share = if w_tot > 0.0 { w_opt / w_tot } else { 0.0 };

    let bft_unweighted = optimal_count >= quorum;
    let thr = params.weighted_vote_threshold.clamp(0.5, 0.99);
    let bft_weighted = weighted_optimal_share >= thr;

    let high_trust_endorsement = optimal_ids
        .iter()
        .any(|id| reputation(id) >= params.high_trust_reputation);

    let mean_optimal_reputation = if optimal_count > 0 {
        sum_rep_opt / optimal_count as f64
    } else {
        0.0
    };

    let all_optimal_low_trust = !optimal_ids.is_empty()
        && optimal_ids
            .iter()
            .all(|id| reputation(id) < params.low_trust_reputation);
    let sybil_optimal_cluster = participating > params.small_mesh_participating_max
        && all_optimal_low_trust
        && optimal_count >= quorum;

    let trust_gate = participating <= params.small_mesh_participating_max
        || high_trust_endorsement
        || mean_optimal_reputation >= f64::from(params.min_mean_optimal_reputation);

    // Permissioned allowlist: need enough distinct voters for a meaningful quorum (two-node
    // weighted-only paths remain allowed when no whitelist is configured; see tests).
    let whitelist_min_participants = match &params.voter_whitelist {
        None => true,
        Some(w) if w.is_empty() => true,
        Some(_) => participating >= 3,
    };

    let mut mesh_validated = (bft_unweighted || bft_weighted)
        && trust_gate
        && optimal_count > 0
        && !sybil_optimal_cluster
        && whitelist_min_participants;

    let mut stalemate_conflict = (participating >= 6
        && optimal_count >= 2
        && critical_count >= 2
        && (optimal_count as isize - critical_count as isize).unsigned_abs() <= 1)
        || (participating == 2 && optimal_count == 1 && critical_count == 1);

    let mut witness_resolved = false;
    let mut winning_status = if mesh_validated {
        Some(PolicyHealthStatus::Optimal)
    } else {
        None
    };

    // Stalemate resolution: Designated witness signature or weighted reputation tie-breaker
    if stalemate_conflict && participating == 2 {
        let now = chrono::Utc::now();
        let target_policy_id = latest.values().next().map(|v| v.policy_id.as_str());
        let mut freshest_witness_vote: Option<&WitnessVote> = None;

        // Witness resolution is only permitted when a designated witness or public key is configured
        let witness_configured = params.designated_witness_id.is_some() || params.witness_public_key.is_some();
        if witness_configured {
            for msg in messages {
                if let PolicyConsensusMessage::Witness(w) = msg {
                    // Match policy ID
                    if let Some(target_pid) = target_policy_id {
                        if w.policy_id != target_pid {
                            continue;
                        }
                    }
                    // Validate designated witness ID
                    if let Some(ref designated) = params.designated_witness_id {
                        if &w.witness_id != designated {
                            continue;
                        }
                    }
                    // Reject future-dated witness votes (>120s into the future) to prevent timeline poisoning
                    if (w.timestamp - now).num_seconds() > 120 {
                        continue;
                    }
                    // Reject excessively stale witness votes (>3600s old)
                    if (now - w.timestamp).num_seconds() > 3600 {
                        continue;
                    }
                    // Cryptographic Ed25519 signature verification: mandatory when witness is configured
                    let Some(ref pk_hex) = params.witness_public_key else {
                        // Reject unauthenticated witness votes if no verifying key is configured
                        continue;
                    };
                    let Ok(pk_bytes) = hex::decode(pk_hex) else { continue };
                    let Ok(verifying_key) = VerifyingKey::try_from(pk_bytes.as_slice()) else { continue };
                    let Ok(sig_bytes) = hex::decode(&w.signature) else { continue };
                    let Ok(sig) = Signature::try_from(sig_bytes.as_slice()) else { continue };
                    let digest = osoosi_types::compute_witness_digest(
                        &w.policy_id,
                        &w.witness_id,
                        &w.favored_status,
                        w.timestamp.timestamp(),
                    );
                    if verifying_key.verify(&digest, &sig).is_err() {
                        continue;
                    }

                    // Select the freshest valid witness vote
                    match freshest_witness_vote {
                        Some(current) if w.timestamp > current.timestamp => {
                            freshest_witness_vote = Some(w);
                        }
                        None => {
                            freshest_witness_vote = Some(w);
                        }
                        _ => {}
                    }
                }
            }
        }

        if let Some(w) = freshest_witness_vote {
            witness_resolved = true;
            stalemate_conflict = false;
            winning_status = Some(w.favored_status.clone());
            if w.favored_status == PolicyHealthStatus::Optimal {
                mesh_validated = true;
            } else {
                mesh_validated = false;
            }
        } else if params.enable_reputation_tie_breaker {
            let opt_rep = optimal_ids.first().map(|id| reputation(id)).unwrap_or(0.0);
            let crit_rep = critical_ids.first().map(|id| reputation(id)).unwrap_or(0.0);
            let margin = params.tie_breaker_reputation_margin;

            if opt_rep - crit_rep >= margin {
                witness_resolved = true;
                stalemate_conflict = false;
                mesh_validated = true;
                winning_status = Some(PolicyHealthStatus::Optimal);
            } else if crit_rep - opt_rep >= margin {
                witness_resolved = true;
                stalemate_conflict = false;
                mesh_validated = false;
                winning_status = Some(PolicyHealthStatus::CriticalFailure);
            }
        }
    }

    let penalize_critical_voters = if mesh_validated && !witness_resolved {
        critical_ids.clone()
    } else {
        Vec::new()
    };

    let pbft_max_faults = params.mesh_peer_hint.map(|n| n.saturating_sub(1) / 3);

    PolicyBftOutcome {
        mesh_validated,
        quorum,
        participating_voters: participating,
        optimal_count,
        critical_count,
        degraded_count,
        weighted_optimal_share,
        high_trust_endorsement,
        mean_optimal_reputation,
        penalize_critical_voters,
        stalemate_conflict,
        pbft_max_faults,
        witness_resolved,
        winning_status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn vote_full(
        id: &str,
        st: PolicyHealthStatus,
        policy: &str,
        nonce: Option<&str>,
    ) -> PolicyConsensusMessage {
        PolicyConsensusMessage::Vote(PolicyHealthVote {
            policy_id: policy.into(),
            voter_id: id.into(),
            status: st,
            uptime_seconds: 0,
            timestamp: Utc::now(),
            work_nonce: nonce.map(String::from),
        })
    }

    fn vote(id: &str, st: PolicyHealthStatus) -> PolicyConsensusMessage {
        vote_full(id, st, "KB1", None)
    }

    #[test]
    fn three_optimal_unweighted_passes() {
        let msgs = vec![
            vote("a", PolicyHealthStatus::Optimal),
            vote("b", PolicyHealthStatus::Optimal),
            vote("c", PolicyHealthStatus::Optimal),
        ];
        let p = BftConsensusParams {
            small_mesh_participating_max: 10,
            weighted_vote_threshold: 2.0 / 3.0,
            ..Default::default()
        };
        let o = analyze_policy_consensus(&msgs, |_| 0.5, &p);
        assert!(o.mesh_validated);
        assert!(o.penalize_critical_voters.is_empty());
    }

    #[test]
    fn whitelist_drops_unknown() {
        let msgs = vec![
            vote("a", PolicyHealthStatus::Optimal),
            vote("b", PolicyHealthStatus::Optimal),
            vote("c", PolicyHealthStatus::Optimal),
        ];
        let mut p = BftConsensusParams {
            small_mesh_participating_max: 10,
            weighted_vote_threshold: 2.0 / 3.0,
            ..Default::default()
        };
        p.voter_whitelist = Some(["a".into(), "b".into()].into_iter().collect());
        let o = analyze_policy_consensus(&msgs, |_| 0.9, &p);
        assert!(!o.mesh_validated);
    }

    #[test]
    fn pow_required_without_nonce_fails() {
        let msgs = vec![
            vote("a", PolicyHealthStatus::Optimal),
            vote("b", PolicyHealthStatus::Optimal),
            vote("c", PolicyHealthStatus::Optimal),
        ];
        let mut p = BftConsensusParams {
            small_mesh_participating_max: 10,
            weighted_vote_threshold: 2.0 / 3.0,
            ..Default::default()
        };
        p.pow_vote_leading_zero_bits = 8;
        let o = analyze_policy_consensus(&msgs, |_| 0.9, &p);
        assert!(!o.mesh_validated);
    }

    #[test]
    fn pow_with_mined_nonce_passes() {
        let bits = 8u8;
        let mut msgs = Vec::new();
        for id in ["x", "y", "z"] {
            let n = mine_vote_work_nonce(id, "KB9", bits).expect("mine");
            msgs.push(vote_full(id, PolicyHealthStatus::Optimal, "KB9", Some(&n)));
        }
        let mut p = BftConsensusParams {
            small_mesh_participating_max: 10,
            weighted_vote_threshold: 2.0 / 3.0,
            ..Default::default()
        };
        p.pow_vote_leading_zero_bits = bits;
        let o = analyze_policy_consensus(&msgs, |_| 0.9, &p);
        assert!(o.mesh_validated);
    }

    #[test]
    fn nakamoto_half_threshold() {
        let msgs = vec![
            vote("a", PolicyHealthStatus::Optimal),
            vote("b", PolicyHealthStatus::Optimal),
        ];
        let mut p = BftConsensusParams {
            small_mesh_participating_max: 10,
            ..Default::default()
        };
        p.weighted_vote_threshold = 0.51;
        // 2 participants: quorum 3 from formula uses max(3,2) -> (4+2)/3=2, need 2 optimal — have 2
        let o = analyze_policy_consensus(&msgs, |_| 0.5, &p);
        assert!(o.mesh_validated);
    }

    #[test]
    fn low_trust_only_blocked_without_high_or_mean() {
        let msgs = vec![
            vote("a", PolicyHealthStatus::Optimal),
            vote("b", PolicyHealthStatus::Optimal),
            vote("c", PolicyHealthStatus::Optimal),
        ];
        let p = BftConsensusParams {
            small_mesh_participating_max: 2,
            min_mean_optimal_reputation: 0.99,
            high_trust_reputation: 0.99,
            weighted_vote_threshold: 2.0 / 3.0,
            ..Default::default()
        };
        let o = analyze_policy_consensus(&msgs, |_| 0.2, &p);
        assert!(!o.mesh_validated);
    }

    #[test]
    fn critical_penalized_when_bft_optimal() {
        let msgs = vec![
            vote("a", PolicyHealthStatus::Optimal),
            vote("b", PolicyHealthStatus::Optimal),
            vote("c", PolicyHealthStatus::Optimal),
            vote("liar", PolicyHealthStatus::CriticalFailure),
        ];
        let p = BftConsensusParams {
            small_mesh_participating_max: 10,
            weighted_vote_threshold: 2.0 / 3.0,
            ..Default::default()
        };
        let o = analyze_policy_consensus(&msgs, |_| 0.7, &p);
        assert!(o.mesh_validated);
        assert!(o.penalize_critical_voters.contains(&"liar".to_string()));
    }

    #[test]
    fn two_host_quorum_both_high_trust_passes() {
        let msgs = vec![
            vote("host1", PolicyHealthStatus::Optimal),
            vote("host2", PolicyHealthStatus::Optimal),
        ];
        let p = BftConsensusParams {
            two_host_reputation_threshold: 0.80,
            ..Default::default()
        };
        // Both nodes have high reputation >= 0.80 -> quorum adapts to 2
        let o = analyze_policy_consensus(&msgs, |_| 0.85, &p);
        assert!(o.mesh_validated);
        assert_eq!(o.quorum, 2);
        assert_eq!(o.participating_voters, 2);
        assert_eq!(o.optimal_count, 2);
        assert!(!o.stalemate_conflict);
    }

    #[test]
    fn two_host_quorum_low_trust_reverts_to_three() {
        let msgs = vec![
            vote("host1", PolicyHealthStatus::Optimal),
            vote("host2", PolicyHealthStatus::Optimal),
        ];
        let p = BftConsensusParams {
            two_host_reputation_threshold: 0.80,
            ..Default::default()
        };
        // Nodes have reputation 0.70 < 0.80 -> quorum remains 3
        let o = analyze_policy_consensus(&msgs, |_| 0.70, &p);
        assert_eq!(o.quorum, 3);
        assert_eq!(o.participating_voters, 2);
    }

    #[test]
    fn two_host_quorum_split_optimal_degraded_fails() {
        let msgs = vec![
            vote("host1", PolicyHealthStatus::Optimal),
            vote("host2", PolicyHealthStatus::Degraded),
        ];
        let p = BftConsensusParams {
            two_host_reputation_threshold: 0.80,
            ..Default::default()
        };
        let o = analyze_policy_consensus(&msgs, |_| 0.85, &p);
        assert!(!o.mesh_validated);
        assert_eq!(o.quorum, 2);
        assert_eq!(o.optimal_count, 1);
        assert_eq!(o.degraded_count, 1);
        assert!(!o.stalemate_conflict);
    }

    #[test]
    fn two_host_stalemate_detected_one_vs_one() {
        let msgs = vec![
            vote("host1", PolicyHealthStatus::Optimal),
            vote("host2", PolicyHealthStatus::CriticalFailure),
        ];
        let p = BftConsensusParams {
            enable_reputation_tie_breaker: false,
            ..Default::default()
        };
        let o = analyze_policy_consensus(&msgs, |_| 0.85, &p);
        assert!(!o.mesh_validated);
        assert!(o.stalemate_conflict, "1-vs-1 split vote must trigger stalemate_conflict");
    }

    #[test]
    fn two_host_witness_resolves_stalemate() {
        use ed25519_dalek::Signer;
        let mut csprng = rand::thread_rng();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let pubkey_hex = hex::encode(verifying_key.to_bytes());

        let timestamp = chrono::Utc::now();
        let digest = osoosi_types::compute_witness_digest(
            "KB1",
            "arbiter_node",
            &PolicyHealthStatus::Optimal,
            timestamp.timestamp(),
        );
        let signature = signing_key.sign(&digest);
        let sig_hex = hex::encode(signature.to_bytes());

        let msgs = vec![
            vote("host1", PolicyHealthStatus::Optimal),
            vote("host2", PolicyHealthStatus::CriticalFailure),
            PolicyConsensusMessage::Witness(WitnessVote {
                policy_id: "KB1".to_string(),
                witness_id: "arbiter_node".to_string(),
                favored_status: PolicyHealthStatus::Optimal,
                signature: sig_hex,
                timestamp,
            }),
        ];

        let p = BftConsensusParams {
            designated_witness_id: Some("arbiter_node".to_string()),
            witness_public_key: Some(pubkey_hex),
            ..Default::default()
        };

        let o = analyze_policy_consensus(&msgs, |_| 0.85, &p);
        assert!(o.mesh_validated);
        assert!(o.witness_resolved);
        assert!(!o.stalemate_conflict);
        assert_eq!(o.winning_status, Some(PolicyHealthStatus::Optimal));
    }

    #[test]
    fn two_host_weighted_reputation_tie_breaker() {
        let msgs = vec![
            vote("high_trust_node", PolicyHealthStatus::Optimal),
            vote("low_trust_node", PolicyHealthStatus::CriticalFailure),
        ];
        let p = BftConsensusParams {
            enable_reputation_tie_breaker: true,
            tie_breaker_reputation_margin: 0.10,
            ..Default::default()
        };

        let rep_fn = |id: &str| {
            if id == "high_trust_node" {
                0.90
            } else {
                0.50
            }
        };

        let o = analyze_policy_consensus(&msgs, rep_fn, &p);
        assert!(o.mesh_validated);
        assert!(o.witness_resolved);
        assert!(!o.stalemate_conflict);
        assert_eq!(o.winning_status, Some(PolicyHealthStatus::Optimal));
    }

    #[test]
    fn two_host_unauthenticated_witness_ignored() {
        let msgs = vec![
            vote("host1", PolicyHealthStatus::Optimal),
            vote("host2", PolicyHealthStatus::CriticalFailure),
            PolicyConsensusMessage::Witness(WitnessVote {
                policy_id: "KB1".to_string(),
                witness_id: "attacker_arbiter".to_string(),
                favored_status: PolicyHealthStatus::Optimal,
                signature: "deadbeef".to_string(),
                timestamp: chrono::Utc::now(),
            }),
        ];
        // Witness credentials are NOT configured -> injected witness vote must NOT resolve stalemate
        let p = BftConsensusParams {
            enable_reputation_tie_breaker: false,
            designated_witness_id: None,
            witness_public_key: None,
            ..Default::default()
        };

        let o = analyze_policy_consensus(&msgs, |_| 0.85, &p);
        assert!(!o.mesh_validated);
        assert!(!o.witness_resolved);
        assert!(o.stalemate_conflict);
    }

    #[test]
    fn two_host_tampered_witness_sig_ignored() {
        use ed25519_dalek::Signer;
        let mut csprng = rand::thread_rng();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let pubkey_hex = hex::encode(verifying_key.to_bytes());

        let timestamp = chrono::Utc::now();
        let digest = osoosi_types::compute_witness_digest(
            "KB1",
            "arbiter_node",
            &PolicyHealthStatus::Optimal,
            timestamp.timestamp(),
        );
        let signature = signing_key.sign(&digest);
        let mut sig_bytes = signature.to_bytes();
        sig_bytes[0] ^= 0xff; // Tamper signature
        let tampered_sig_hex = hex::encode(sig_bytes);

        let msgs = vec![
            vote("host1", PolicyHealthStatus::Optimal),
            vote("host2", PolicyHealthStatus::CriticalFailure),
            PolicyConsensusMessage::Witness(WitnessVote {
                policy_id: "KB1".to_string(),
                witness_id: "arbiter_node".to_string(),
                favored_status: PolicyHealthStatus::Optimal,
                signature: tampered_sig_hex,
                timestamp,
            }),
        ];

        let p = BftConsensusParams {
            designated_witness_id: Some("arbiter_node".to_string()),
            witness_public_key: Some(pubkey_hex),
            enable_reputation_tie_breaker: false,
            ..Default::default()
        };

        let o = analyze_policy_consensus(&msgs, |_| 0.85, &p);
        assert!(!o.mesh_validated);
        assert!(!o.witness_resolved);
        assert!(o.stalemate_conflict);
    }

    #[test]
    fn two_host_mismatched_policy_witness_ignored() {
        use ed25519_dalek::Signer;
        let mut csprng = rand::thread_rng();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let pubkey_hex = hex::encode(verifying_key.to_bytes());

        let timestamp = chrono::Utc::now();
        // Witness was signed for KB2, but votes are for KB1
        let digest = osoosi_types::compute_witness_digest(
            "KB2",
            "arbiter_node",
            &PolicyHealthStatus::Optimal,
            timestamp.timestamp(),
        );
        let signature = signing_key.sign(&digest);
        let sig_hex = hex::encode(signature.to_bytes());

        let msgs = vec![
            vote("host1", PolicyHealthStatus::Optimal),
            vote("host2", PolicyHealthStatus::CriticalFailure),
            PolicyConsensusMessage::Witness(WitnessVote {
                policy_id: "KB2".to_string(),
                witness_id: "arbiter_node".to_string(),
                favored_status: PolicyHealthStatus::Optimal,
                signature: sig_hex,
                timestamp,
            }),
        ];

        let p = BftConsensusParams {
            designated_witness_id: Some("arbiter_node".to_string()),
            witness_public_key: Some(pubkey_hex),
            enable_reputation_tie_breaker: false,
            ..Default::default()
        };

        let o = analyze_policy_consensus(&msgs, |_| 0.85, &p);
        assert!(!o.mesh_validated);
        assert!(!o.witness_resolved);
        assert!(o.stalemate_conflict);
    }

    #[test]
    fn two_host_future_dated_witness_ignored() {
        use ed25519_dalek::Signer;
        let mut csprng = rand::thread_rng();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let pubkey_hex = hex::encode(verifying_key.to_bytes());

        // Future-dated timestamp (>120s into the future)
        let future_timestamp = chrono::Utc::now() + chrono::Duration::seconds(300);
        let digest = osoosi_types::compute_witness_digest(
            "KB1",
            "arbiter_node",
            &PolicyHealthStatus::Optimal,
            future_timestamp.timestamp(),
        );
        let signature = signing_key.sign(&digest);
        let sig_hex = hex::encode(signature.to_bytes());

        let msgs = vec![
            vote("host1", PolicyHealthStatus::Optimal),
            vote("host2", PolicyHealthStatus::CriticalFailure),
            PolicyConsensusMessage::Witness(WitnessVote {
                policy_id: "KB1".to_string(),
                witness_id: "arbiter_node".to_string(),
                favored_status: PolicyHealthStatus::Optimal,
                signature: sig_hex,
                timestamp: future_timestamp,
            }),
        ];

        let p = BftConsensusParams {
            designated_witness_id: Some("arbiter_node".to_string()),
            witness_public_key: Some(pubkey_hex),
            enable_reputation_tie_breaker: false,
            ..Default::default()
        };

        let o = analyze_policy_consensus(&msgs, |_| 0.85, &p);
        assert!(!o.mesh_validated);
        assert!(!o.witness_resolved);
        assert!(o.stalemate_conflict);
    }

    #[test]
    fn two_host_freshest_witness_vote_precedence() {
        use ed25519_dalek::Signer;
        let mut csprng = rand::thread_rng();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let pubkey_hex = hex::encode(verifying_key.to_bytes());

        let older_timestamp = chrono::Utc::now() - chrono::Duration::seconds(50);
        let newer_timestamp = chrono::Utc::now() - chrono::Duration::seconds(10);

        let digest_older = osoosi_types::compute_witness_digest(
            "KB1",
            "arbiter_node",
            &PolicyHealthStatus::Optimal,
            older_timestamp.timestamp(),
        );
        let sig_older = hex::encode(signing_key.sign(&digest_older).to_bytes());

        let digest_newer = osoosi_types::compute_witness_digest(
            "KB1",
            "arbiter_node",
            &PolicyHealthStatus::CriticalFailure,
            newer_timestamp.timestamp(),
        );
        let sig_newer = hex::encode(signing_key.sign(&digest_newer).to_bytes());

        // Put the older vote first in the messages list
        let msgs = vec![
            vote("host1", PolicyHealthStatus::Optimal),
            vote("host2", PolicyHealthStatus::CriticalFailure),
            PolicyConsensusMessage::Witness(WitnessVote {
                policy_id: "KB1".to_string(),
                witness_id: "arbiter_node".to_string(),
                favored_status: PolicyHealthStatus::Optimal,
                signature: sig_older,
                timestamp: older_timestamp,
            }),
            PolicyConsensusMessage::Witness(WitnessVote {
                policy_id: "KB1".to_string(),
                witness_id: "arbiter_node".to_string(),
                favored_status: PolicyHealthStatus::CriticalFailure,
                signature: sig_newer,
                timestamp: newer_timestamp,
            }),
        ];

        let p = BftConsensusParams {
            designated_witness_id: Some("arbiter_node".to_string()),
            witness_public_key: Some(pubkey_hex),
            enable_reputation_tie_breaker: false,
            ..Default::default()
        };

        let o = analyze_policy_consensus(&msgs, |_| 0.85, &p);
        assert!(!o.mesh_validated);
        assert!(o.witness_resolved);
        assert_eq!(o.winning_status, Some(PolicyHealthStatus::CriticalFailure));
    }
}


