use super::context::{AgentSecuritySubject, AgentTrustTier, RaspDecision, RaspThreatCategory, TaintLevel};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

/// Progressive mitigation levels in the RT-ASP dynamic mitigation ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AdaptiveMitigationTier {
    Level0Monitor = 0,
    Level1Sanitize = 1,
    Level2SyntheticDecoy = 2,
    Level3TarpitStall = 3,
    Level4HardRevoke = 4,
}

impl Default for AdaptiveMitigationTier {
    fn default() -> Self {
        AdaptiveMitigationTier::Level1Sanitize
    }
}

/// Configuration settings for the Real-Time Agentic Self-Protection Policy Engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaspPolicyConfig {
    pub active_mitigation_tier: AdaptiveMitigationTier,
    pub max_memory_bytes_per_agent: usize,
    pub max_ledger_disbursement_unattested: i64,
    pub tarpit_delay_default_ms: u64,
    pub enable_dynamic_honeypots: bool,
    pub enable_canary_tripwires: bool,
    pub enable_multilingual_semantic_pass: bool,
}

impl Default for RaspPolicyConfig {
    fn default() -> Self {
        Self {
            active_mitigation_tier: AdaptiveMitigationTier::Level1Sanitize,
            max_memory_bytes_per_agent: 64 * 1024 * 1024, // 64 MB Windows Job Object invariant
            max_ledger_disbursement_unattested: 10_000,   // $10,000 threshold
            tarpit_delay_default_ms: 1_200,
            enable_dynamic_honeypots: true,
            enable_canary_tripwires: true,
            enable_multilingual_semantic_pass: true,
        }
    }
}

/// Dynamic Honeytoken & Canary tripwire manager for the RT-ASP engine.
pub struct RaspCanaryManager {
    active_canaries: RwLock<HashMap<String, String>>, // token -> label
    compromised_canaries: RwLock<HashSet<String>>,
}

impl Default for RaspCanaryManager {
    fn default() -> Self {
        let mut initial = HashMap::new();
        initial.insert(
            "CANARY_OCTOPUS_SEC_ROOT_78F9A".to_string(),
            "kernel_master_credential".to_string(),
        );
        initial.insert(
            "CANARY_OCTOPUS_LEDGER_KEY_442B".to_string(),
            "ledger_signer_key".to_string(),
        );

        Self {
            active_canaries: RwLock::new(initial),
            compromised_canaries: RwLock::new(HashSet::new()),
        }
    }
}

impl RaspCanaryManager {
    pub fn register_canary(&self, label: &str) -> String {
        let token = format!("CANARY_OCTOPUS_{}_{:08x}", label.to_uppercase(), rand::random::<u32>());
        let mut canaries = self.active_canaries.write().unwrap_or_else(|e| e.into_inner());
        canaries.insert(token.clone(), label.to_string());
        token
    }

    pub fn check_and_trip(&self, text: &str) -> Option<(String, String)> {
        let canaries = self.active_canaries.read().unwrap_or_else(|e| e.into_inner());
        for (token, label) in canaries.iter() {
            if text.contains(token) {
                let mut compromised = self.compromised_canaries.write().unwrap_or_else(|e| e.into_inner());
                compromised.insert(token.clone());
                return Some((token.clone(), label.clone()));
            }
        }
        None
    }

    pub fn is_compromised(&self, token: &str) -> bool {
        self.compromised_canaries.read().unwrap_or_else(|e| e.into_inner()).contains(token)
    }

    pub fn compromised_count(&self) -> usize {
        self.compromised_canaries.read().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// RT-ASP Policy Engine coordinating deterministic and adaptive security rules.
pub struct RaspPolicyEngine {
    config: RwLock<RaspPolicyConfig>,
    canary_mgr: RaspCanaryManager,
}

impl Default for RaspPolicyEngine {
    fn default() -> Self {
        Self {
            config: RwLock::new(RaspPolicyConfig::default()),
            canary_mgr: RaspCanaryManager::default(),
        }
    }
}

impl RaspPolicyEngine {
    pub fn new(config: RaspPolicyConfig) -> Self {
        Self {
            config: RwLock::new(config),
            canary_mgr: RaspCanaryManager::default(),
        }
    }

    pub fn config(&self) -> RaspPolicyConfig {
        self.config.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set_mitigation_tier(&self, tier: AdaptiveMitigationTier) {
        let mut cfg = self.config.write().unwrap_or_else(|e| e.into_inner());
        cfg.active_mitigation_tier = tier;
    }

    pub fn canary_mgr(&self) -> &RaspCanaryManager {
        &self.canary_mgr
    }

    /// Evaluates subject and action against the active mitigation ladder.
    pub fn evaluate_mitigation_action(
        &self,
        category: RaspThreatCategory,
        reason: &str,
        subject: &AgentSecuritySubject,
        policy_id: &str,
    ) -> RaspDecision {
        let cfg = self.config();

        // System kernel subjects are never tarpitted or quarantined
        if subject.trust_tier == AgentTrustTier::SystemKernel {
            return RaspDecision::Allow {
                taint_level: TaintLevel::Clean,
            };
        }

        match cfg.active_mitigation_tier {
            AdaptiveMitigationTier::Level0Monitor => {
                // Monitor only: log threat but allow
                RaspDecision::Allow {
                    taint_level: TaintLevel::Suspect,
                }
            }
            AdaptiveMitigationTier::Level1Sanitize => {
                // Return sanitized or denied based on category
                match category {
                    RaspThreatCategory::CredentialLeakage | RaspThreatCategory::ToolParameterTampering => {
                        RaspDecision::Sanitize {
                            modified_payload: serde_json::json!({
                                "status": "sanitized_by_rt_asp",
                                "original_reason": reason,
                            }),
                            redaction_count: 1,
                            warnings: vec![reason.to_string()],
                            threat_category: category,
                        }
                    }
                    _ => RaspDecision::Deny {
                        reason: reason.to_string(),
                        policy_id: policy_id.to_string(),
                        threat_category: category,
                    },
                }
            }
            AdaptiveMitigationTier::Level2SyntheticDecoy => {
                let decoy = self.generate_synthetic_honey_payload(category, reason);
                RaspDecision::Tarpit {
                    delay_ms: 100, // Minimal decoy delay
                    decoy_payload: decoy,
                    reason: format!("Synthetic decoy deployed: {}", reason),
                    threat_category: category,
                }
            }
            AdaptiveMitigationTier::Level3TarpitStall => {
                let decoy = self.generate_synthetic_honey_payload(category, reason);
                RaspDecision::Tarpit {
                    delay_ms: cfg.tarpit_delay_default_ms,
                    decoy_payload: decoy,
                    reason: format!("Adversary session tarpitted: {}", reason),
                    threat_category: category,
                }
            }
            AdaptiveMitigationTier::Level4HardRevoke => {
                RaspDecision::Quarantine {
                    agent_id: subject.agent_id.clone(),
                    reason: format!("Hard revocation triggered: {}", reason),
                    threat_category: category,
                }
            }
        }
    }

    /// Synthesizes authentic-looking honeytoken responses to misdirect attackers.
    pub fn generate_synthetic_honey_payload(
        &self,
        category: RaspThreatCategory,
        reason: &str,
    ) -> serde_json::Value {
        match category {
            RaspThreatCategory::CredentialLeakage => serde_json::json!({
                "token_type": "Bearer",
                "access_token": format!("honey_tok_{:016x}", rand::random::<u64>()),
                "expires_in": 3600,
                "scope": "read_telemetry_isolated",
                "note": "Synthetic decoy generated by RT-ASP"
            }),
            RaspThreatCategory::LateralCollusion | RaspThreatCategory::PrivilegeEscalation => serde_json::json!({
                "transaction_status": "PENDING_HONEYPOT_VERIFICATION",
                "decoy_ledger_id": format!("LEDGER_HONEY_{:08x}", rand::random::<u32>()),
                "amount": 0,
                "balance": 1000000,
                "memo": "Decoy response. Action contained."
            }),
            _ => serde_json::json!({
                "status": "ok",
                "result": "Operation simulated within sandbox boundary",
                "canary_reference": format!("REF_{:08x}", rand::random::<u32>()),
                "synthetic": true,
                "reason": reason
            }),
        }
    }
}
