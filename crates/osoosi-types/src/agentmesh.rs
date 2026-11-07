//! Google AgentMesh Types & Telemetry Models (`crates/osoosi-types/src/agentmesh.rs`)
//!
//! Provides the canonical data contracts for:
//! - Workload OIDC JWT Claims & RFC 7517 JWKS
//! - Ed25519-signed Attenuated Mandates
//! - Outbound Tier 1 Wasm Sandbox Pore Telemetry Receipts
//! - Inbound Published Wasm Tool Actuation Telemetry Receipts
//! - Serving Node Configuration & Role Bindings

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Configuration for initializing the AgentMesh Production Engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMeshConfig {
    pub base_issuer_url: String,
    pub policy: AgentMeshPolicyConfig,
    pub external_mesh_node_url: Option<String>,
    pub enable_loopback_node: bool,
    pub loopback_port: u16,
}

impl Default for AgentMeshConfig {
    fn default() -> Self {
        let external_url = std::env::var("AGENTMESH_UPSTREAM_URL").ok();
        Self {
            base_issuer_url: "http://127.0.0.1:5005".to_string(),
            policy: AgentMeshPolicyConfig::default_serving_policy(),
            external_mesh_node_url: external_url,
            enable_loopback_node: true,
            loopback_port: 0, // dynamic ephemeral binding
        }
    }
}

/// Status telemetry exported to the WebUI dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMeshStatus {
    pub engine_state: String,
    pub serving_node_active: bool,
    pub serving_node_port: Option<u16>,
    pub killswitch_tripped: bool,
    pub generation_epoch: u64,
    pub total_outbound_calls: u64,
    pub successful_outbound_calls: u64,
    pub denied_outbound_calls: u64,
    pub total_inbound_calls: u64,
    pub last_revocation_latency_ns: u64,
    pub cached_credentials_count: usize,
    pub active_jwks_kid: String,
    #[serde(default)]
    pub tier2_confinement_posture: String,
    #[serde(default)]
    pub published_wasm_tools: Vec<String>,
}

/// Telemetry receipt returned by a real Tier 1 Wasm sandbox outbound mesh invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxMeshCallReport {
    pub arm_id: String,
    pub generation_epoch: u64,
    pub target_uri: String,
    pub allowed: bool,
    pub wasm_exit_code: i32,
    pub fuel_consumed: u64,
    pub fuel_budget: u64,
    pub execution_us: u64,
    pub peak_linear_memory_bytes: usize,
    pub linear_memory_zero_secret_verified: bool,
    pub mesh_calls_attempted: u64,
    pub mesh_calls_succeeded: u64,
    pub mesh_bytes_exchanged: u64,
    pub blocked_escape_attempts: Vec<String>,
    pub sanitized_response: String,
}

/// Telemetry receipt returned by an inbound published Wasm tool actuation (`Mesh -> Sandbox`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundMeshCallReport {
    pub http_status: u16,
    pub tool_uri: String,
    pub wasm_tool_name: String,
    pub seal_id: String,
    pub wasm_exit_code: i32,
    pub fuel_consumed: u64,
    pub peak_linear_memory_bytes: usize,
    pub linear_memory_zero_secret_verified: bool,
    pub sanitized_output: String,
}

/// RFC 7519 Workload JWT Claims for OIDC workload identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkloadClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: u64,
    pub nbf: u64,
    pub iat: u64,
    pub jti: String,
    pub arm_id: String,
    pub epoch: u64,
    pub role: String,
}

/// A cryptographic delegation hop inside an `AttenuatedMandate`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationLink {
    pub parent_pubkey_hex: String,
    pub child_pubkey_hex: String,
    pub allowed_services: BTreeSet<String>,
    pub published_tools: BTreeSet<String>,
    pub delegated_at: u64,
    pub signature_hex: String,
}

/// Monotonically attenuated Ed25519-signed capability mandate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttenuatedMandate {
    pub mandate_id: String,
    pub root_issuer_pubkey_hex: String,
    pub current_holder_pubkey_hex: String,
    pub allowed_services: BTreeSet<String>,
    pub published_tools: BTreeSet<String>,
    pub depth: u32,
    pub issued_at: u64,
    pub expires_at: u64,
    pub delegation_chain: Vec<DelegationLink>,
}

/// Role definition for Google AgentMesh serving node.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentMeshRoleDef {
    pub name: String,
    #[serde(default)]
    pub allowed_services: Vec<String>,
    #[serde(default)]
    pub published_tools: Vec<String>,
}

/// Role binding definition for Google AgentMesh serving node.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentMeshBindingDef {
    pub subject: String,
    pub role: String,
}

/// Serving node policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentMeshPolicyConfig {
    #[serde(default)]
    pub roles: Vec<AgentMeshRoleDef>,
    #[serde(default)]
    pub bindings: Vec<AgentMeshBindingDef>,
}

impl AgentMeshPolicyConfig {
    pub fn default_serving_policy() -> Self {
        Self {
            roles: vec![
                AgentMeshRoleDef {
                    name: "default_executor".to_string(),
                    allowed_services: vec![
                        "mcp://calc".to_string(),
                        "mcp://echo_headers".to_string(),
                        "mesh://service/discover".to_string(),
                    ],
                    published_tools: vec![
                        "mcp://calc".to_string(),
                        "mcp://echo_headers".to_string(),
                    ],
                },
                AgentMeshRoleDef {
                    name: "restricted_eval".to_string(),
                    allowed_services: vec!["mcp://calc".to_string()],
                    published_tools: vec![],
                },
            ],
            bindings: vec![
                AgentMeshBindingDef {
                    subject: "user:arm_calc".to_string(),
                    role: "default_executor".to_string(),
                },
                AgentMeshBindingDef {
                    subject: "user:arm_eval".to_string(),
                    role: "restricted_eval".to_string(),
                },
            ],
        }
    }
}

/// Root policy wrapper for AgentMesh conformance.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentMeshPolicyRoot {
    #[serde(default)]
    pub policy_config: Option<AgentMeshPolicyConfig>,
    #[serde(default)]
    pub roles: Option<Vec<AgentMeshRoleDef>>,
    #[serde(default)]
    pub bindings: Option<Vec<AgentMeshBindingDef>>,
}
