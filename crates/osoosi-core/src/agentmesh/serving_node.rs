//! Embedded AgentMesh Serving Node (`src/security/agentmesh/serving_node.rs`)
//!
//! Provides a fully self-contained loopback HTTP server implementing Google AgentMesh
//! control-plane and data-plane primitives:
//! - RFC 8693 OAuth 2.0 Token Exchange (`POST /oauth/token`)
//! - AgentMesh `policy.json` evaluation (`roles`, `allowed_services`, `allowed_publish`, `bindings`)
//! - Strict RFC 7515 `ES256` JWS verification with <= 5s clock skew tolerance
//! - Dual-Side #734 Defense: Active Revocation List & Epoch Watermark enforcement
//! - Mock mesh tool endpoints (`/mesh/mcp/calc`, `/mesh/mcp/payroll`)
//! - Header-echo verification (`/mesh/echo_headers`)

use super::oidc_actor_issuer::JwksDocument;

fn base64url_decode_no_pad(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
}

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, RwLock};

/// Wire format helper accepting both `{"policy_config": {"roles": ..., "bindings": ...}}`
/// and upstream `google/agentmesh` protojson `{"roles": ..., "bindings": ...}`.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum AgentMeshPolicyConfigWire {
    Wrapped { policy_config: AgentMeshPolicyRoot },
    Direct(AgentMeshPolicyRoot),
}

impl From<AgentMeshPolicyConfigWire> for AgentMeshPolicyConfig {
    fn from(wire: AgentMeshPolicyConfigWire) -> Self {
        match wire {
            AgentMeshPolicyConfigWire::Wrapped { policy_config } => Self { policy_config },
            AgentMeshPolicyConfigWire::Direct(policy_config) => Self { policy_config },
        }
    }
}

/// Root wrapper for Google AgentMesh policy configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "AgentMeshPolicyConfigWire")]
pub struct AgentMeshPolicyConfig {
    pub policy_config: AgentMeshPolicyRoot,
}

/// Core policy root containing role definitions and subject bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentMeshPolicyRoot {
    pub roles: Vec<AgentMeshRoleDef>,
    pub bindings: Vec<AgentMeshBindingDef>,
}

/// An AgentMesh role definition specifying capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentMeshRoleDef {
    pub name: String,
    #[serde(default)]
    pub allowed_services: Vec<String>,
    #[serde(default)]
    pub allowed_publish: Vec<String>,
    #[serde(default)]
    pub allowed_targets: Vec<String>,
}

/// A binding between an AgentMesh role and subject identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentMeshBindingDef {
    pub role: String,
    pub members: Vec<String>,
}

impl AgentMeshPolicyConfig {
    /// Creates the standard policy for AgentOctopus serving.
    pub fn default_serving_policy() -> Self {
        Self {
            policy_config: AgentMeshPolicyRoot {
                roles: vec![
                    AgentMeshRoleDef {
                        name: "calc_worker".to_string(),
                        allowed_services: vec![
                            "system://mesh.catalog".to_string(),
                            "mcp://calc".to_string(),
                            "mcp://echo".to_string(),
                            "mcp://echo_headers".to_string(),
                            "mcp://echo-headers".to_string(),
                            "mcp://octopus/doc_extractor".to_string(),
                            "mcp://octopus-doc-extractor".to_string(),
                        ],
                        allowed_publish: vec![],
                        allowed_targets: vec!["mcp://calc".to_string()],
                    },
                    AgentMeshRoleDef {
                        name: "payroll_admin".to_string(),
                        allowed_services: vec![
                            "system://mesh.catalog".to_string(),
                            "mcp://calc".to_string(),
                            "mcp://payroll".to_string(),
                            "mcp://echo_headers".to_string(),
                            "mcp://echo-headers".to_string(),
                        ],
                        allowed_publish: vec![],
                        allowed_targets: vec!["mcp://*".to_string()],
                    },
                    AgentMeshRoleDef {
                        name: "octopus_publisher".to_string(),
                        allowed_services: vec![
                            "system://mesh.catalog".to_string(),
                            "mcp://*".to_string(),
                        ],
                        allowed_publish: vec![
                            "mcp://octopus/doc_extractor".to_string(),
                            "mcp://octopus/ledger_validator".to_string(),
                            "mcp://octopus-doc-extractor".to_string(),
                            "mcp://octopus-ledger-validator".to_string(),
                        ],
                        allowed_targets: vec!["mcp://*".to_string()],
                    },
                ],
                bindings: vec![
                    AgentMeshBindingDef {
                        role: "calc_worker".to_string(),
                        members: vec![
                            "user:spiffe://oshoosiclaw.local/arm/arm_calc/epoch/*".to_string(),
                            "spiffe://oshoosiclaw.local/arm/arm_calc/epoch/*".to_string(),
                            "http://127.0.0.1:5005/arm/arm_calc/epoch/*".to_string(),
                            "http://127.0.0.1:5006/arm/arm_calc/epoch/*".to_string(),
                            "user:spiffe://oshoosiclaw.local/arm/1/epoch/*".to_string(),
                            "spiffe://oshoosiclaw.local/arm/1/epoch/*".to_string(),
                            "http://127.0.0.1:5005/arm/1/epoch/*".to_string(),
                            "user:spiffe://oshoosiclaw.local/arm/arm-UntrustedDocIngest-0/epoch/*"
                                .to_string(),
                            "spiffe://oshoosiclaw.local/arm/arm-UntrustedDocIngest-0/epoch/*"
                                .to_string(),
                            "http://127.0.0.1:5005/arm/arm-UntrustedDocIngest-0/epoch/*"
                                .to_string(),
                        ],
                    },
                    AgentMeshBindingDef {
                        role: "payroll_admin".to_string(),
                        members: vec![
                            "user:spiffe://oshoosiclaw.local/arm/arm_payroll/epoch/*".to_string(),
                            "spiffe://oshoosiclaw.local/arm/arm_payroll/epoch/*".to_string(),
                            "http://127.0.0.1:5005/arm/arm_payroll/epoch/*".to_string(),
                        ],
                    },
                    AgentMeshBindingDef {
                        role: "octopus_publisher".to_string(),
                        members: vec![
                            "user:spiffe://oshoosiclaw.local/arm/arm_publisher/epoch/*"
                                .to_string(),
                            "spiffe://oshoosiclaw.local/arm/arm_publisher/epoch/*".to_string(),
                            "http://127.0.0.1:5005/arm/arm_publisher/epoch/*".to_string(),
                        ],
                    },
                ],
            },
        }
    }

    /// Convenience alias for the default serving policy.
    pub fn default_policy() -> Self {
        Self::default_serving_policy()
    }

    /// Evaluates whether a subject SPIFFE ID is bound to a role authorized for `service_uri`.
    pub fn is_service_allowed(&self, spiffe_id: &str, service_uri: &str) -> bool {
        let bound_roles = self.resolve_roles_for_subject(spiffe_id);
        for role in bound_roles {
            for pattern in &role.allowed_services {
                if matches_pattern(pattern, service_uri) {
                    return true;
                }
            }
        }
        false
    }

    /// Resolves all role definitions bound to the given SPIFFE ID or `user:<sub_value>`.
    pub fn resolve_roles_for_subject(&self, spiffe_id: &str) -> Vec<&AgentMeshRoleDef> {
        let bare = spiffe_id.strip_prefix("user:").unwrap_or(spiffe_id);
        let user_prefixed = format!("user:{}", bare);
        let mut matching_roles = Vec::new();
        for binding in &self.policy_config.bindings {
            for member_pattern in &binding.members {
                if matches_pattern(member_pattern, bare)
                    || matches_pattern(member_pattern, &user_prefixed)
                {
                    if let Some(role) = self.policy_config.roles.iter().find(|r| r.name == binding.role) {
                        matching_roles.push(role);
                    }
                    break;
                }
            }
        }
        matching_roles
    }
}

/// Matches a string against a wildcard pattern (`*` or prefix with trailing `*`).
pub fn matches_pattern(pattern: &str, target: &str) -> bool {
    if pattern == "*" || pattern == target {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return target.starts_with(prefix);
    }
    false
}

/// Metadata stored for an exchanged access token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangedTokenMetadata {
    pub token_id: String,
    pub subject: String,
    pub arm_id: String,
    pub epoch: u64,
    pub roles: Vec<String>,
    pub allowed_services: Vec<String>,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Telemetry metrics for the serving node.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ServingNodeStats {
    pub total_requests: u64,
    pub sts_exchanges_requested: u64,
    pub sts_exchanges_succeeded: u64,
    pub sts_exchanges_denied: u64,
    pub mcp_calc_calls: u64,
    pub mcp_payroll_calls: u64,
    pub mcp_payroll_denials: u64,
    pub header_echo_inspections: u64,
    #[serde(default)]
    pub published_wasm_calls: u64,
    #[serde(default)]
    pub published_seal_replays_blocked: u64,
}

pub type ConformanceNodeStats = ServingNodeStats;

/// RFC 8693 Token Exchange Request payload.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenExchangeRequest {
    pub grant_type: String,
    pub subject_token: String,
    pub subject_token_type: String,
    #[serde(default)]
    pub requested_token_type: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

/// RFC 8693 Token Exchange Successful Response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenExchangeResponse {
    pub access_token: String,
    pub issued_token_type: String,
    pub token_type: String,
    pub expires_in: u64,
}

/// RFC 6749 Section 5.2 Error Response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenExchangeErrorResponse {
    pub error: String,
    pub error_description: String,
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: HashMap<String, String>, // normalized to lowercase
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status_code: u16,
    pub status_text: &'static str,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn json<T: Serialize>(status: u16, text: &'static str, val: &T) -> Self {
        let body = serde_json::to_vec(val).unwrap_or_default();
        Self {
            status_code: status,
            status_text: text,
            headers: vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Content-Length".to_string(), body.len().to_string()),
                ("Connection".to_string(), "close".to_string()),
            ],
            body,
        }
    }

    pub fn error(status: u16, text: &'static str, code: &str, description: &str) -> Self {
        Self::json(
            status,
            text,
            &TokenExchangeErrorResponse {
                error: code.to_string(),
                error_description: description.to_string(),
            },
        )
    }
}

/// Cryptographically signed revocation signal for Weakness 1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEpochRevocationSignal {
    pub arm_id: String,
    pub revocation_epoch: u64,
    pub timestamp: u64,
    pub signature: String, // hex-encoded ES256 signature
}

/// Bounded store for exchanged access tokens preventing memory leaks.
#[derive(Debug, Clone)]
pub struct BoundedActiveTokenStore {
    tokens: HashMap<String, ExchangedTokenMetadata>,
    revoked_tokens: HashSet<String>,
    insertion_order: VecDeque<String>,
    capacity: usize,
}

impl BoundedActiveTokenStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            tokens: HashMap::new(),
            revoked_tokens: HashSet::new(),
            insertion_order: VecDeque::new(),
            capacity: capacity.max(100),
        }
    }

    pub fn insert(&mut self, token_id: String, meta: ExchangedTokenMetadata) {
        if self.tokens.len() >= self.capacity {
            while let Some(oldest) = self.insertion_order.pop_front() {
                if self.tokens.remove(&oldest).is_some() {
                    break;
                }
            }
        }
        self.revoked_tokens.remove(&token_id);
        self.tokens.insert(token_id.clone(), meta);
        self.insertion_order.push_back(token_id);
    }

    pub fn get(&self, token_id: &str) -> Option<&ExchangedTokenMetadata> {
        self.tokens.get(token_id)
    }

    pub fn revoke_token(&mut self, token_id: &str) -> bool {
        let existed = self.tokens.remove(token_id).is_some();
        self.insertion_order.retain(|k| k != token_id);
        if self.revoked_tokens.len() >= self.capacity {
            self.revoked_tokens.clear();
        }
        self.revoked_tokens.insert(token_id.to_string());
        existed
    }

    pub fn is_token_revoked(&self, token_id: &str) -> bool {
        self.revoked_tokens.contains(token_id)
    }

    pub fn revoke_arm(&mut self, arm_id: &str) {
        self.tokens.retain(|_, m| m.arm_id != arm_id);
        self.insertion_order.retain(|k| self.tokens.contains_key(k));
    }

    pub fn advance_arm_epoch(&mut self, arm_id: &str, min_valid_epoch: u64) {
        self.tokens.retain(|_, m| !(m.arm_id == arm_id && m.epoch < min_valid_epoch));
        self.insertion_order.retain(|k| self.tokens.contains_key(k));
    }

    pub fn prune_expired(&mut self, now: u64) {
        self.tokens.retain(|_, m| m.expires_at > now);
        self.insertion_order.retain(|k| self.tokens.contains_key(k));
    }

    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

/// Bounded FIFO nonce store preventing replay attacks.
#[derive(Debug)]
pub struct BoundedNonceStore {
    nonces: HashSet<String>,
    fifo: VecDeque<String>,
    capacity: usize,
}

impl BoundedNonceStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            nonces: HashSet::new(),
            fifo: VecDeque::new(),
            capacity: capacity.max(100),
        }
    }

    pub fn check_and_insert(&mut self, nonce: &str) -> bool {
        if self.nonces.contains(nonce) {
            return false;
        }
        if self.fifo.len() >= self.capacity {
            if let Some(old) = self.fifo.pop_front() {
                self.nonces.remove(&old);
            }
        }
        self.nonces.insert(nonce.to_string());
        self.fifo.push_back(nonce.to_string());
        true
    }
}

pub const HEADER_PEP_CHANNEL_PROOF: &str = "x-octopus-pep-channel-proof";
pub const HEADER_PEP_NONCE: &str = "x-octopus-pep-nonce";
pub const HEADER_PEP_TIMESTAMP: &str = "x-octopus-pep-timestamp";
pub const HEADER_PEP_CAGE_SEAL: &str = "x-octopus-cage-seal";
pub const HEADER_NODE_PROOF: &str = "x-octopus-node-proof";

pub const PEP_CHANNEL_MAX_SKEW_MS: u64 = 5_000; // Strict <= 5s drift tolerance

fn compute_hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let hash = Sha256::digest(key);
        k[..32].copy_from_slice(&hash);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    let outer_hash = outer.finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(&outer_hash);
    result
}

/// Computes PEP request channel proof
pub fn compute_pep_channel_proof(
    channel_secret: &[u8; 32],
    method: &str,
    path: &str,
    timestamp_ms: u64,
    nonce: &str,
    body: &[u8],
    cage_seal: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let body_hash_hex = hex::encode(hasher.finalize());
    let seal_str = cage_seal.unwrap_or("");

    let canonical = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.to_uppercase(),
        path,
        timestamp_ms,
        nonce,
        body_hash_hex,
        seal_str
    );

    let hmac = compute_hmac_sha256(channel_secret, canonical.as_bytes());
    hex::encode(hmac)
}

/// Computes Node response mutual proof
pub fn compute_node_response_proof(
    channel_secret: &[u8; 32],
    status_code: u16,
    nonce: &str,
    body: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let body_hash_hex = hex::encode(hasher.finalize());

    let canonical = format!("{}\n{}\n{}", status_code, nonce, body_hash_hex);
    let hmac = compute_hmac_sha256(channel_secret, canonical.as_bytes());
    hex::encode(hmac)
}

#[derive(Debug, Error)]
pub enum TokenVerificationError {
    #[error("Token not found or expired")]
    NotFoundOrExpired,
    #[error("Arm is actively revoked")]
    ArmRevoked,
    #[error("Epoch superseded")]
    EpochSuperseded,
    #[error("Service '{0}' not allowed for token")]
    ServiceDenied(String),
}

/// Internal shared state for the serving node.
pub struct ServingNodeInner {
    pub policy: RwLock<AgentMeshPolicyConfig>,
    pub jwks: RwLock<Option<JwksDocument>>,
    pub active_tokens: RwLock<BoundedActiveTokenStore>,
    pub stats: RwLock<ServingNodeStats>,
    pub revoked_arms: RwLock<HashSet<String>>,
    pub arm_epoch_watermarks: RwLock<HashMap<String, u64>>,
    pub node_id: String,
    pub channel_secret: Option<[u8; 32]>,
    pub seen_pep_nonces: RwLock<BoundedNonceStore>,
    pub cage_engine: RwLock<Arc<crate::security::cage_governance::CageGovernanceEngine>>,
    pub wasm_executor: RwLock<Option<Arc<crate::security::wasm_tier1::WasmTier1Executor>>>,
}

/// Handle to the active embedded loopback HTTP serving node.
pub struct AgentMeshServingNode {
    inner: Arc<ServingNodeInner>,
    server_task: Option<tokio::task::JoinHandle<()>>,
    shutdown_tx: Option<watch::Sender<bool>>,
    bound_port: u16,
}

impl AgentMeshServingNode {
    /// Starts the loopback HTTP server listening on `127.0.0.1:preferred_port` (or ephemeral port if 0).
    pub async fn start(
        policy: AgentMeshPolicyConfig,
        jwks: Option<JwksDocument>,
        preferred_port: u16,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::start_with_channel(policy, jwks, preferred_port, None).await
    }

    /// Starts the loopback HTTP server with optional mutual PEP channel secret.
    pub async fn start_with_channel(
        policy: AgentMeshPolicyConfig,
        jwks: Option<JwksDocument>,
        preferred_port: u16,
        channel_secret: Option<[u8; 32]>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(("127.0.0.1", preferred_port)).await?;
        let bound_port = listener.local_addr()?.port();

        let inner = Arc::new(ServingNodeInner {
            policy: RwLock::new(policy),
            jwks: RwLock::new(jwks),
            active_tokens: RwLock::new(BoundedActiveTokenStore::new(10_000)),
            stats: RwLock::new(ServingNodeStats::default()),
            revoked_arms: RwLock::new(HashSet::new()),
            arm_epoch_watermarks: RwLock::new(HashMap::new()),
            node_id: format!("agentmesh_serving_node_{}", bound_port),
            channel_secret,
            seen_pep_nonces: RwLock::new(BoundedNonceStore::new(10_000)),
            cage_engine: RwLock::new(Arc::new(
                crate::security::cage_governance::CageGovernanceEngine::default(),
            )),
            wasm_executor: RwLock::new(
                crate::security::wasm_tier1::WasmTier1Executor::try_new()
                    .ok()
                    .map(Arc::new),
            ),
        });

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let inner_clone = Arc::clone(&inner);

        let server_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((stream, _)) => {
                                let inner_req = Arc::clone(&inner_clone);
                                tokio::spawn(async move {
                                    let _ = handle_connection(stream, inner_req).await;
                                });
                            }
                            Err(_) => break,
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });

        Ok(Self {
            inner,
            server_task: Some(server_task),
            shutdown_tx: Some(shutdown_tx),
            bound_port,
        })
    }

    pub fn port(&self) -> u16 {
        self.bound_port
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.bound_port)
    }

    pub fn token_endpoint(&self) -> String {
        format!("{}/oauth/token", self.url())
    }

    pub async fn stats(&self) -> ServingNodeStats {
        self.inner.stats.read().await.clone()
    }

    pub async fn update_jwks(&self, jwks: JwksDocument) {
        *self.inner.jwks.write().await = Some(jwks);
    }

    pub async fn update_policy(&self, policy: AgentMeshPolicyConfig) {
        *self.inner.policy.write().await = policy;
    }

    /// Dual-side #734 defense: Active Revocation List
    pub async fn revoke_arm(&self, arm_id: &str) {
        let mut rev = self.inner.revoked_arms.write().await;
        rev.insert(arm_id.to_string());
    }

    /// Clears all active arm revocations on the serving node (used on explicit supervisor reset).
    pub async fn clear_revoked_arms(&self) {
        self.inner.revoked_arms.write().await.clear();
    }

    /// Attaches shared CAGE governance and Tier 1 Wasm executors for inbound published tools.
    pub async fn attach_cage_and_wasm(
        &self,
        cage_engine: Arc<crate::security::cage_governance::CageGovernanceEngine>,
        wasm_executor: Arc<crate::security::wasm_tier1::WasmTier1Executor>,
    ) {
        *self.inner.cage_engine.write().await = cage_engine;
        *self.inner.wasm_executor.write().await = Some(wasm_executor);
    }

    /// Checks if an arm has been marked revoked.
    pub async fn is_arm_revoked(&self, arm_id: &str) -> bool {
        self.inner.revoked_arms.read().await.contains(arm_id)
    }

    /// Dual-side #734 defense: Advance Arm Epoch Watermark
    pub async fn advance_arm_epoch(&self, arm_id: &str, min_valid_epoch: u64) {
        let mut wm = self.inner.arm_epoch_watermarks.write().await;
        wm.insert(arm_id.to_string(), min_valid_epoch);
    }

    /// Verifies an exchanged token against active store, revocation lists, and capabilities.
    pub async fn verify_access_token(
        &self,
        token: &str,
        resource: &str,
    ) -> Result<ExchangedTokenMetadata, TokenVerificationError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut tokens = self.inner.active_tokens.write().await;
        tokens.prune_expired(now);

        if tokens.is_token_revoked(token) {
            return Err(TokenVerificationError::ArmRevoked);
        }

        let meta = match tokens.get(token) {
            Some(m) => m.clone(),
            None => return Err(TokenVerificationError::NotFoundOrExpired),
        };

        if now > meta.expires_at {
            return Err(TokenVerificationError::NotFoundOrExpired);
        }

        // Check active revocation
        let rev = self.inner.revoked_arms.read().await;
        if rev.contains(&meta.arm_id) {
            return Err(TokenVerificationError::ArmRevoked);
        }

        // Check epoch watermark
        let wm = self.inner.arm_epoch_watermarks.read().await;
        if let Some(&min_epoch) = wm.get(&meta.arm_id) {
            if meta.epoch < min_epoch {
                return Err(TokenVerificationError::EpochSuperseded);
            }
        }

        // Check allowed services
        if !meta.allowed_services.iter().any(|s| matches_pattern(s, resource)) {
            return Err(TokenVerificationError::ServiceDenied(resource.to_string()));
        }

        Ok(meta)
    }

    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(handle) = self.server_task.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for AgentMeshServingNode {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
    }
}

pub type AgentMeshReferenceNode = AgentMeshServingNode;
pub type ConformanceNodeInner = ServingNodeInner;

async fn handle_connection(
    mut stream: TcpStream,
    state: Arc<ServingNodeInner>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 1024];
    let mut header_end = None;

    // Read header block up to 64 KiB with 5s timeout
    while buf.len() < 65536 {
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk)).await??;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = Some(pos);
            break;
        }
    }

    let pos = match header_end {
        Some(p) => p,
        None => return Ok(()),
    };

    let header_bytes = &buf[..pos];
    let header_str = std::str::from_utf8(header_bytes)?;
    let mut lines = header_str.lines();
    let req_line = match lines.next() {
        Some(l) => l,
        None => return Ok(()),
    };

    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_uppercase();
    let full_uri = parts.next().unwrap_or("/");

    let (path, query) = match full_uri.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (full_uri.to_string(), None),
    };

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let content_len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    const MAX_HTTP_BODY_BYTES: usize = 10 * 1024 * 1024; // 10 MiB limit
    if content_len > MAX_HTTP_BODY_BYTES {
        let resp = HttpResponse::error(
            413,
            "Payload Too Large",
            "payload_too_large",
            "Request body exceeds 10 MiB limit",
        );
        let mut resp_str = format!("HTTP/1.1 {} {}\r\n", resp.status_code, resp.status_text);
        for (k, v) in &resp.headers {
            resp_str.push_str(&format!("{}: {}\r\n", k, v));
        }
        resp_str.push_str("\r\n");
        let _ = stream.write_all(resp_str.as_bytes()).await;
        if !resp.body.is_empty() {
            let _ = stream.write_all(&resp.body).await;
        }
        let _ = stream.flush().await;
        let _ = stream.shutdown().await;
        return Ok(());
    }

    let mut body = buf[pos + 4..].to_vec();
    while body.len() < content_len {
        let to_read = (content_len - body.len()).min(chunk.len());
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk[..to_read])).await??;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }

    let req = HttpRequest {
        method,
        path,
        query,
        headers,
        body,
    };

    state.stats.write().await.total_requests += 1;
    let resp = route_request(req, &state).await;

    let mut resp_str = format!("HTTP/1.1 {} {}\r\n", resp.status_code, resp.status_text);
    for (k, v) in &resp.headers {
        resp_str.push_str(&format!("{}: {}\r\n", k, v));
    }
    resp_str.push_str("\r\n");

    stream.write_all(resp_str.as_bytes()).await?;
    if !resp.body.is_empty() {
        stream.write_all(&resp.body).await?;
    }
    stream.flush().await?;
    let _ = stream.shutdown().await;

    Ok(())
}

async fn route_request(req: HttpRequest, state: &Arc<ConformanceNodeInner>) -> HttpResponse {
    // 1. Weakness 4: Mutual PEP-to-Node channel verification
    let pep_nonce = req.headers.get(HEADER_PEP_NONCE).cloned();
    if let Some(secret) = &state.channel_secret {
        let proof = match req.headers.get(HEADER_PEP_CHANNEL_PROOF) {
            Some(p) => p,
            None => {
                return HttpResponse::error(
                    403,
                    "Forbidden",
                    "PEP_CHANNEL_AUTH_REQUIRED",
                    "Channel proof header missing",
                );
            }
        };
        let nonce = match &pep_nonce {
            Some(n) => n,
            None => {
                return HttpResponse::error(
                    403,
                    "Forbidden",
                    "PEP_CHANNEL_AUTH_REQUIRED",
                    "Nonce header missing",
                );
            }
        };
        let ts_str = match req.headers.get(HEADER_PEP_TIMESTAMP) {
            Some(t) => t,
            None => {
                return HttpResponse::error(
                    403,
                    "Forbidden",
                    "PEP_CHANNEL_AUTH_REQUIRED",
                    "Timestamp header missing",
                );
            }
        };

        let ts_ms = match ts_str.parse::<u64>() {
            Ok(t) => t,
            Err(_) => {
                return HttpResponse::error(
                    403,
                    "Forbidden",
                    "PEP_CHANNEL_AUTH_INVALID",
                    "Invalid timestamp",
                );
            }
        };
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        if now_ms.abs_diff(ts_ms) > PEP_CHANNEL_MAX_SKEW_MS {
            return HttpResponse::error(
                403,
                "Forbidden",
                "PEP_CHANNEL_TIMESTAMP_SKEW",
                "Timestamp skew exceeded 5s limit",
            );
        }

        if !state.seen_pep_nonces.write().await.check_and_insert(nonce) {
            return HttpResponse::error(
                403,
                "Forbidden",
                "PEP_CHANNEL_NONCE_REPLAY",
                "Nonce replay detected",
            );
        }

        let cage_seal = req.headers.get(HEADER_PEP_CAGE_SEAL).map(|s| s.as_str());
        let expected_proof = compute_pep_channel_proof(
            secret,
            &req.method,
            &req.path,
            ts_ms,
            nonce,
            &req.body,
            cage_seal,
        );
        if !crate::security::constant_time_eq_hex(proof, &expected_proof) {
            return HttpResponse::error(
                403,
                "Forbidden",
                "PEP_CHANNEL_PROOF_INVALID",
                "Constant-time HMAC verification failed",
            );
        }
    }

    // 2. Normalize peer-scoped `/mesh/<peer-id>/<type>/<rest>` paths to `/mesh/<type>/<rest>`
    let normalized_path = if let Some(after_mesh) = req.path.strip_prefix("/mesh/") {
        if let Some((first_seg, rest)) = after_mesh.split_once('/') {
            if !matches!(
                first_seg,
                "mcp" | "a2a" | "inference" | "egress" | "echo_headers" | "revoke" | "service"
            ) && (rest.starts_with("mcp/")
                || rest.starts_with("a2a/")
                || rest.starts_with("inference/")
                || rest.starts_with("egress/"))
            {
                format!("/mesh/{}", rest)
            } else {
                req.path.clone()
            }
        } else {
            req.path.clone()
        }
    } else {
        req.path.clone()
    };

    // 3. Dispatch routes
    let mut resp = match (req.method.as_str(), normalized_path.as_str()) {
        ("POST", "/oauth/token") => handle_token_exchange(req, state).await,
        ("POST", "/oauth/revoke") => handle_oauth_revoke(req, state).await,
        ("POST", "/mesh/revoke") => handle_signed_revocation(req, state).await,
        ("GET", "/mesh/service/discover") => handle_service_discover(req, state).await,
        ("POST", "/mesh/mcp/calc") => handle_mcp_calc(req, state).await,
        ("POST", "/mesh/mcp/payroll") => handle_mcp_payroll(req, state).await,
        ("POST", "/mesh/mcp/echo_headers")
        | ("POST", "/mesh/mcp/echo-headers")
        | ("GET", "/mesh/mcp/echo_headers")
        | ("GET", "/mesh/mcp/echo-headers") => handle_mcp_echo_headers(req, state).await,
        ("POST", "/mesh/mcp/octopus/doc_extractor")
        | ("POST", "/mesh/mcp/octopus-doc-extractor") => {
            let tool_uri = if normalized_path.ends_with("octopus-doc-extractor") {
                "mcp://octopus-doc-extractor"
            } else {
                "mcp://octopus/doc_extractor"
            };
            handle_published_wasm_tool(req, state, tool_uri, "wasm_doc_extractor").await
        }
        ("POST", "/mesh/mcp/octopus/ledger_validator")
        | ("POST", "/mesh/mcp/octopus-ledger-validator") => {
            let tool_uri = if normalized_path.ends_with("octopus-ledger-validator") {
                "mcp://octopus-ledger-validator"
            } else {
                "mcp://octopus/ledger_validator"
            };
            handle_published_wasm_tool(req, state, tool_uri, "wasm_ledger_validator").await
        }
        ("GET", "/mesh/echo_headers") | ("POST", "/mesh/echo_headers") => {
            handle_echo_headers(req, state).await
        }
        ("GET", "/.well-known/jwks.json") | ("GET", "/jwks.json") | ("GET", "/jwks") => {
            handle_jwks(state).await
        }
        ("GET", "/.well-known/openid-configuration") => handle_openid_config(state).await,
        ("GET", "/health")
        | ("POST", "/health")
        | ("GET", "/status")
        | ("GET", "/readyz")
        | ("GET", "/info") => HttpResponse::json(
            200,
            "OK",
            &serde_json::json!({
                "status": "healthy",
                "node_id": state.node_id,
                "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            }),
        ),
        _ => HttpResponse::error(404, "Not Found", "not_found", "The requested path does not exist"),
    };

    // 3. Inject mutual node response proof header if channel secret is active
    if let (Some(secret), Some(nonce)) = (&state.channel_secret, pep_nonce) {
        let node_proof = compute_node_response_proof(secret, resp.status_code, &nonce, &resp.body);
        resp.headers.push((HEADER_NODE_PROOF.to_string(), node_proof));
    }

    resp
}

async fn handle_oauth_revoke(req: HttpRequest, state: &Arc<ConformanceNodeInner>) -> HttpResponse {
    let token_to_revoke = if req
        .headers
        .get("content-type")
        .map(|ct| ct.starts_with("application/json"))
        .unwrap_or(false)
    {
        serde_json::from_slice::<serde_json::Value>(&req.body)
            .ok()
            .and_then(|v| v.get("token").and_then(|t| t.as_str()).map(str::to_string))
    } else {
        let body_str = String::from_utf8_lossy(&req.body);
        body_str.split('&').find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            if k == "token" {
                Some(percent_decode(v))
            } else {
                None
            }
        })
    };

    let Some(token) = token_to_revoke.filter(|t| !t.trim().is_empty()) else {
        return HttpResponse::error(400, "Bad Request", "invalid_request", "token parameter is required");
    };

    state.active_tokens.write().await.revoke_token(&token);
    HttpResponse::json(
        200,
        "OK",
        &serde_json::json!({
            "status": "revoked"
        }),
    )
}

async fn handle_service_discover(req: HttpRequest, state: &Arc<ConformanceNodeInner>) -> HttpResponse {
    let mut filter_type = None;
    let mut filter_name = None;
    if let Some(q) = &req.query {
        for pair in q.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                match k {
                    "type" => filter_type = Some(percent_decode(v)),
                    "name" => filter_name = Some(percent_decode(v)),
                    _ => {}
                }
            }
        }
    }

    if filter_type.as_deref().map(|t| t != "mcp" && !t.is_empty()).unwrap_or(false) {
        return HttpResponse::json(200, "OK", &Vec::<serde_json::Value>::new());
    }

    let caller_allowed: Option<Vec<String>> = if let Some(auth) = extract_bearer_token(&req) {
        state
            .active_tokens
            .read()
            .await
            .get(&auth)
            .map(|m| m.allowed_services.clone())
    } else {
        None
    };

    let port = state.node_id.rsplit('_').next().unwrap_or("0");
    let catalog = [
        ("calc", "mcp://calc", "Calculator MCP service"),
        ("payroll", "mcp://payroll", "Sensitive payroll MCP service"),
        ("echo-headers", "mcp://echo-headers", "Header hygiene inspection MCP service"),
        ("octopus-doc-extractor", "mcp://octopus-doc-extractor", "Wasmtime v49 document extractor"),
        ("octopus-ledger-validator", "mcp://octopus-ledger-validator", "Wasmtime v49 ledger validator"),
    ];

    let mut entries = Vec::new();
    for (srv_name, uri, desc) in catalog {
        if let Some(ref want_name) = filter_name {
            if !want_name.is_empty() && want_name != srv_name {
                continue;
            }
        }
        if let Some(ref allowed) = caller_allowed {
            if !allowed.iter().any(|pat| matches_pattern(pat, uri)) {
                continue;
            }
        }
        entries.push(serde_json::json!({
            "peer_id": state.node_id,
            "srv_name": srv_name,
            "srv_description": desc,
            "local_proxy_url": format!("http://127.0.0.1:{}/mesh/{}/mcp/{}", port, state.node_id, srv_name),
        }));
    }

    HttpResponse::json(200, "OK", &entries)
}

async fn handle_signed_revocation(req: HttpRequest, state: &Arc<ConformanceNodeInner>) -> HttpResponse {
    let signal: SignedEpochRevocationSignal = match serde_json::from_slice(&req.body) {
        Ok(s) => s,
        Err(e) => {
            return HttpResponse::error(
                400,
                "Bad Request",
                "invalid_signal",
                &format!("Failed to parse SignedEpochRevocationSignal: {e}"),
            );
        }
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Verify timestamp skew <= 30 seconds
    if now.abs_diff(signal.timestamp) > 30 {
        return HttpResponse::error(
            400,
            "Bad Request",
            "revocation_timestamp_skew",
            "Revocation signal timestamp skew exceeded 30s",
        );
    }

    let sig_input = format!("{}:{}:{}", signal.arm_id, signal.revocation_epoch, signal.timestamp);
    let sig_bytes = match hex::decode(&signal.signature) {
        Ok(b) => b,
        Err(_) => {
            return HttpResponse::error(
                401,
                "Unauthorized",
                "invalid_signature_hex",
                "Revocation signature is not valid hex",
            );
        }
    };

    let jwks_guard = state.jwks.read().await;
    let jwks = match jwks_guard.as_ref() {
        Some(j) => j,
        None => {
            return HttpResponse::error(
                500,
                "Internal Server Error",
                "server_error",
                "No JWKS configured to verify revocation signal",
            );
        }
    };

    let verified = jwks.keys.iter().any(|k| {
        verify_es256_p256(sig_input.as_bytes(), &sig_bytes, &k.x, &k.y)
    });

    if !verified {
        return HttpResponse::error(
            401,
            "Unauthorized",
            "invalid_revocation_signature",
            "Revocation digital signature verification failed",
        );
    }

    // Apply revocation and epoch advance
    {
        let mut rev = state.revoked_arms.write().await;
        rev.insert(signal.arm_id.clone());
    }
    {
        let mut wm = state.arm_epoch_watermarks.write().await;
        let current_wm = wm.get(&signal.arm_id).copied().unwrap_or(0);
        if signal.revocation_epoch >= current_wm {
            wm.insert(signal.arm_id.clone(), signal.revocation_epoch);
        }
    }

    HttpResponse::json(
        200,
        "OK",
        &serde_json::json!({
            "status": "revoked",
            "arm_id": signal.arm_id,
            "revocation_epoch": signal.revocation_epoch,
        }),
    )
}

async fn handle_token_exchange(req: HttpRequest, state: &Arc<ConformanceNodeInner>) -> HttpResponse {
    let mut stats = state.stats.write().await;
    stats.sts_exchanges_requested += 1;
    drop(stats);

    // Parse form-urlencoded or JSON body
    let parsed_req: TokenExchangeRequest = if req
        .headers
        .get("content-type")
        .map(|ct| ct.starts_with("application/json"))
        .unwrap_or(false)
    {
        match serde_json::from_slice(&req.body) {
            Ok(r) => r,
            Err(_) => {
                state.stats.write().await.sts_exchanges_denied += 1;
                return HttpResponse::error(400, "Bad Request", "invalid_request", "Malformed JSON body");
            }
        }
    } else {
        // Form urlencoded fallback
        let body_str = String::from_utf8_lossy(&req.body);
        let mut r = TokenExchangeRequest::default();
        for pair in body_str.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                let decoded_val = percent_decode(v);
                match k {
                    "grant_type" => r.grant_type = decoded_val,
                    "subject_token" => r.subject_token = decoded_val,
                    "subject_token_type" => r.subject_token_type = decoded_val,
                    "requested_token_type" => r.requested_token_type = Some(decoded_val),
                    "resource" => r.resource = Some(decoded_val),
                    "audience" => r.audience = Some(decoded_val),
                    "scope" => r.scope = Some(decoded_val),
                    _ => {}
                }
            }
        }
        r
    };

    // 1. Validate grant_type
    if parsed_req.grant_type != "urn:ietf:params:oauth:grant-type:token-exchange" {
        state.stats.write().await.sts_exchanges_denied += 1;
        return HttpResponse::error(
            400,
            "Bad Request",
            "invalid_request",
            "grant_type must be urn:ietf:params:oauth:grant-type:token-exchange",
        );
    }

    // 2. Validate subject_token_type
    if parsed_req.subject_token_type != "urn:ietf:params:oauth:token-type:jwt" {
        state.stats.write().await.sts_exchanges_denied += 1;
        return HttpResponse::error(
            400,
            "Bad Request",
            "invalid_request",
            "subject_token_type must be urn:ietf:params:oauth:token-type:jwt",
        );
    }

    if parsed_req.subject_token.is_empty() {
        state.stats.write().await.sts_exchanges_denied += 1;
        return HttpResponse::error(400, "Bad Request", "invalid_request", "subject_token is required");
    }

    // 3. Verify JWS ES256 Signature and Claims
    let jws_parts: Vec<&str> = parsed_req.subject_token.split('.').collect();
    if jws_parts.len() != 3 {
        state.stats.write().await.sts_exchanges_denied += 1;
        return HttpResponse::error(
            400,
            "Bad Request",
            "invalid_request",
            "Malformed JWS compact token serialization",
        );
    }

    let header_bytes = match base64url_decode_no_pad(jws_parts[0]) {
        Ok(b) => b,
        Err(_) => {
            state.stats.write().await.sts_exchanges_denied += 1;
            return HttpResponse::error(400, "Bad Request", "invalid_request", "Invalid header base64url");
        }
    };
    let header_val: serde_json::Value = match serde_json::from_slice(&header_bytes) {
        Ok(v) => v,
        Err(_) => {
            state.stats.write().await.sts_exchanges_denied += 1;
            return HttpResponse::error(400, "Bad Request", "invalid_request", "Invalid header JSON");
        }
    };

    if header_val.get("alg").and_then(|a| a.as_str()) != Some("ES256") {
        state.stats.write().await.sts_exchanges_denied += 1;
        return HttpResponse::error(400, "Bad Request", "invalid_request", "Algorithm must be ES256");
    }

    let payload_bytes = match base64url_decode_no_pad(jws_parts[1]) {
        Ok(b) => b,
        Err(_) => {
            state.stats.write().await.sts_exchanges_denied += 1;
            return HttpResponse::error(400, "Bad Request", "invalid_request", "Invalid payload base64url");
        }
    };
    let payload_val: serde_json::Value = match serde_json::from_slice(&payload_bytes) {
        Ok(v) => v,
        Err(_) => {
            state.stats.write().await.sts_exchanges_denied += 1;
            return HttpResponse::error(400, "Bad Request", "invalid_request", "Invalid payload JSON");
        }
    };

    let subject = match payload_val.get("sub").and_then(|s| s.as_str()) {
        Some(s) => s.to_string(),
        None => {
            state.stats.write().await.sts_exchanges_denied += 1;
            return HttpResponse::error(400, "Bad Request", "invalid_request", "Missing sub claim");
        }
    };

    let arm_id = payload_val.get("arm_id").and_then(|a| a.as_str()).unwrap_or("").to_string();
    let epoch = payload_val.get("epoch").and_then(|e| e.as_u64()).unwrap_or(0);

    // Dual-side #734 defense: Check active revocation and minimum epoch watermark
    {
        let rev = state.revoked_arms.read().await;
        if rev.contains(&arm_id) {
            state.stats.write().await.sts_exchanges_denied += 1;
            return HttpResponse::error(
                403,
                "Forbidden",
                "invalid_grant",
                &format!("Arm '{}' is present in active revocation list", arm_id),
            );
        }
    }
    {
        let wm = state.arm_epoch_watermarks.read().await;
        if let Some(&min_epoch) = wm.get(&arm_id) {
            if epoch < min_epoch {
                state.stats.write().await.sts_exchanges_denied += 1;
                return HttpResponse::error(
                    403,
                    "Forbidden",
                    "invalid_grant",
                    &format!("Arm '{}' epoch {} is superseded by epoch watermark {}", arm_id, epoch, min_epoch),
                );
            }
        }
    }

    // 4. Timestamp & Skew Verification (<= 5s window)
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if let Some(exp) = payload_val.get("exp").and_then(|e| e.as_u64()) {
        if now > exp + 5 {
            state.stats.write().await.sts_exchanges_denied += 1;
            return HttpResponse::error(
                401,
                "Unauthorized",
                "invalid_grant",
                "Token expired (exceeded 5s clock skew limit)",
            );
        }
    }
    if let Some(nbf) = payload_val.get("nbf").and_then(|n| n.as_u64()) {
        if now + 5 < nbf {
            state.stats.write().await.sts_exchanges_denied += 1;
            return HttpResponse::error(
                401,
                "Unauthorized",
                "invalid_grant",
                "Token not yet valid (nbf in future)",
            );
        }
    }

    // 5. Digital Signature Verification
    let kid = header_val.get("kid").and_then(|k| k.as_str()).unwrap_or("");
    let sig_bytes = match base64url_decode_no_pad(jws_parts[2]) {
        Ok(b) => b,
        Err(_) => {
            state.stats.write().await.sts_exchanges_denied += 1;
            return HttpResponse::error(401, "Unauthorized", "invalid_grant", "Malformed signature encoding");
        }
    };

    if sig_bytes.len() != 64 {
        state.stats.write().await.sts_exchanges_denied += 1;
        return HttpResponse::error(
            401,
            "Unauthorized",
            "invalid_grant",
            "Signature length must be exactly 64 bytes (IEEE P1363 R || S)",
        );
    }

    let jwks_guard = state.jwks.read().await;
    let jwks = match jwks_guard.as_ref() {
        Some(j) => j,
        None => {
            state.stats.write().await.sts_exchanges_denied += 1;
            return HttpResponse::error(
                500,
                "Internal Server Error",
                "server_error",
                "No active JWKS configured for token verification",
            );
        }
    };

    let matching_key = jwks.keys.iter().find(|k| k.kid == kid || kid.is_empty());
    match matching_key {
        Some(key_dto) => {
            let signing_input = format!("{}.{}", jws_parts[0], jws_parts[1]);
            if !verify_es256_p256(signing_input.as_bytes(), &sig_bytes, &key_dto.x, &key_dto.y) {
                state.stats.write().await.sts_exchanges_denied += 1;
                return HttpResponse::error(
                    401,
                    "Unauthorized",
                    "invalid_grant",
                    "Digital signature verification failed",
                );
            }
        }
        None => {
            state.stats.write().await.sts_exchanges_denied += 1;
            return HttpResponse::error(
                401,
                "Unauthorized",
                "invalid_grant",
                &format!("Unknown key ID '{}' in active JWKS", kid),
            );
        }
    }

    // 6. Policy Evaluation
    let policy = state.policy.read().await;
    let bound_roles = policy.resolve_roles_for_subject(&subject);
    if bound_roles.is_empty() {
        state.stats.write().await.sts_exchanges_denied += 1;
        return HttpResponse::error(
            403,
            "Forbidden",
            "invalid_target",
            &format!("Subject '{}' is not bound to any policy role", subject),
        );
    }

    if let Some(target_resource) = &parsed_req.resource {
        if !policy.is_service_allowed(&subject, target_resource) {
            state.stats.write().await.sts_exchanges_denied += 1;
            return HttpResponse::error(
                403,
                "Forbidden",
                "invalid_target",
                &format!("Subject '{}' role denies access to resource '{}'", subject, target_resource),
            );
        }
    }

    // 7. Mint Exchanged Mesh Credential (with optional RFC 8693 `resource` / `scope` narrowing)
    let token_nonce: [u8; 16] = rand::random();
    let access_token = format!("mesh_tok_{}", hex::encode(token_nonce));
    let mut allowed_services = Vec::new();
    let mut role_names = Vec::new();
    for r in &bound_roles {
        role_names.push(r.name.clone());
        allowed_services.extend(r.allowed_services.clone());
    }

    let mut requested_narrowing: Vec<String> = Vec::new();
    if let Some(ref res_uri) = parsed_req.resource {
        if !res_uri.trim().is_empty() {
            requested_narrowing.push(res_uri.trim().to_string());
        }
    }
    if let Some(ref scope_str) = parsed_req.scope {
        for s in scope_str.split_whitespace() {
            if !s.trim().is_empty() {
                requested_narrowing.push(s.trim().to_string());
            }
        }
    }
    if !requested_narrowing.is_empty() {
        allowed_services = requested_narrowing
            .into_iter()
            .filter(|req_svc| {
                allowed_services
                    .iter()
                    .any(|grant| matches_pattern(grant, req_svc))
            })
            .collect();
    }

    let token_meta = ExchangedTokenMetadata {
        token_id: access_token.clone(),
        subject,
        arm_id,
        epoch,
        roles: role_names,
        allowed_services,
        issued_at: now,
        expires_at: now + 300,
    };

    state
        .active_tokens
        .write()
        .await
        .insert(access_token.clone(), token_meta);

    state.stats.write().await.sts_exchanges_succeeded += 1;

    HttpResponse::json(
        200,
        "OK",
        &TokenExchangeResponse {
            access_token,
            issued_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 300,
        },
    )
}

async fn handle_mcp_calc(req: HttpRequest, state: &Arc<ConformanceNodeInner>) -> HttpResponse {
    let auth = match extract_bearer_token(&req) {
        Some(t) => t,
        None => return HttpResponse::error(401, "Unauthorized", "unauthorized", "Missing Bearer token"),
    };

    let tokens = state.active_tokens.read().await;
    if tokens.is_token_revoked(&auth) {
        return HttpResponse::error(403, "Forbidden", "access_denied", "Token was revoked via RFC 7009");
    }
    let meta = match tokens.get(&auth) {
        Some(m) => m,
        None => return HttpResponse::error(401, "Unauthorized", "invalid_token", "Exchanged token not found or expired"),
    };

    // Check active revocation
    {
        let rev = state.revoked_arms.read().await;
        if rev.contains(&meta.arm_id) {
            return HttpResponse::error(403, "Forbidden", "access_denied", "Arm is in active revocation list");
        }
    }

    if !meta.allowed_services.iter().any(|s| matches_pattern(s, "mcp://calc")) {
        return HttpResponse::error(403, "Forbidden", "access_denied", "Token lacks mcp://calc authority");
    }

    state.stats.write().await.mcp_calc_calls += 1;

    // Parse simple calculation request: {"op": "add", "a": 10, "b": 20}
    let req_json: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
    let op = req_json.get("op").and_then(|v| v.as_str()).unwrap_or("echo");
    let a = req_json.get("a").and_then(|v| v.as_i64()).unwrap_or(0);
    let b = req_json.get("b").and_then(|v| v.as_i64()).unwrap_or(0);

    let result = match op {
        "add" => a + b,
        "mul" => a * b,
        "sub" => a - b,
        _ => a,
    };

    HttpResponse::json(
        200,
        "OK",
        &serde_json::json!({
            "status": "ok",
            "service": "mcp://calc",
            "caller": meta.subject,
            "operation": op,
            "result": result,
        }),
    )
}

async fn handle_mcp_payroll(req: HttpRequest, state: &Arc<ConformanceNodeInner>) -> HttpResponse {
    state.stats.write().await.mcp_payroll_calls += 1;

    let auth = match extract_bearer_token(&req) {
        Some(t) => t,
        None => return HttpResponse::error(401, "Unauthorized", "unauthorized", "Missing Bearer token"),
    };

    let tokens = state.active_tokens.read().await;
    if tokens.is_token_revoked(&auth) {
        state.stats.write().await.mcp_payroll_denials += 1;
        return HttpResponse::error(403, "Forbidden", "access_denied", "Token was revoked via RFC 7009");
    }
    let meta = match tokens.get(&auth) {
        Some(m) => m,
        None => return HttpResponse::error(401, "Unauthorized", "invalid_token", "Token invalid"),
    };

    // Check active revocation
    {
        let rev = state.revoked_arms.read().await;
        if rev.contains(&meta.arm_id) {
            state.stats.write().await.mcp_payroll_denials += 1;
            return HttpResponse::error(403, "Forbidden", "access_denied", "Arm is in active revocation list");
        }
    }

    if !meta.allowed_services.iter().any(|s| matches_pattern(s, "mcp://payroll")) {
        state.stats.write().await.mcp_payroll_denials += 1;
        return HttpResponse::error(
            403,
            "Forbidden",
            "access_denied",
            &format!("Role '{:?}' is denied access to sensitive payroll ledger", meta.roles),
        );
    }

    HttpResponse::json(
        200,
        "OK",
        &serde_json::json!({
            "status": "ok",
            "service": "mcp://payroll",
            "caller": meta.subject,
            "disbursement_status": "CONFIRMED",
            "payroll_records_accessed": 42,
        }),
    )
}

async fn handle_mcp_echo_headers(req: HttpRequest, state: &Arc<ConformanceNodeInner>) -> HttpResponse {
    state.stats.write().await.header_echo_inspections += 1;

    let auth = match extract_bearer_token(&req) {
        Some(t) => t,
        None => {
            return HttpResponse::error(
                401,
                "Unauthorized",
                "unauthorized",
                "Missing Bearer token",
            )
        }
    };

    let tokens = state.active_tokens.read().await;
    if tokens.is_token_revoked(&auth) {
        return HttpResponse::error(
            403,
            "Forbidden",
            "access_denied",
            "Token was revoked via RFC 7009",
        );
    }
    let meta = match tokens.get(&auth) {
        Some(m) => m.clone(),
        None => {
            return HttpResponse::error(
                401,
                "Unauthorized",
                "invalid_token",
                "Exchanged token not found or expired",
            )
        }
    };
    drop(tokens);

    if state.revoked_arms.read().await.contains(&meta.arm_id) {
        return HttpResponse::error(
            403,
            "Forbidden",
            "access_denied",
            "Arm is in active revocation list",
        );
    }

    if !meta.allowed_services.iter().any(|s| {
        matches_pattern(s, "mcp://echo_headers") || matches_pattern(s, "mcp://echo-headers")
    }) {
        return HttpResponse::error(
            403,
            "Forbidden",
            "access_denied",
            "Token lacks mcp://echo_headers authority",
        );
    }

    let auth_header_present = req.headers.contains_key("authorization");
    let cookie_header_present = req.headers.contains_key("cookie");
    let mesh_auth_present = req.headers.contains_key("x-mesh-authentication");
    let mut redacted_header_names: Vec<String> = req.headers.keys().cloned().collect();
    redacted_header_names.sort();

    // Never echo raw X-Mesh-Authentication bearer bytes back into Wasm guest memory.
    HttpResponse::json(
        200,
        "OK",
        &serde_json::json!({
            "status": "ok",
            "service": "mcp://echo_headers",
            "caller": meta.subject,
            "authorization_header_present": auth_header_present,
            "cookie_header_present": cookie_header_present,
            "authorization_stripped": !auth_header_present,
            "cookie_stripped": !cookie_header_present,
            "x_mesh_authentication_present": mesh_auth_present,
            "observed_header_names": redacted_header_names,
        }),
    )
}

async fn handle_published_wasm_tool(
    req: HttpRequest,
    state: &Arc<ConformanceNodeInner>,
    tool_uri: &str,
    wasm_tool_name: &str,
) -> HttpResponse {
    use crate::security::cage_governance::{CageRoutingSeal, SealRejection};
    use crate::security::wasm_tier1::WasmSandboxLimits;

    let auth = match extract_bearer_token(&req) {
        Some(t) => t,
        None => {
            return HttpResponse::error(
                401,
                "Unauthorized",
                "unauthorized",
                "Missing Bearer X-Mesh-Authentication header",
            )
        }
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // 1. Verify exchanged token or ES256 workload JWT
    let caller_subject: String;
    if auth.starts_with("mesh_tok_") {
        let mut tokens = state.active_tokens.write().await;
        tokens.prune_expired(now);
        let meta = match tokens.get(&auth) {
            Some(m) => m.clone(),
            None => {
                return HttpResponse::error(
                    401,
                    "Unauthorized",
                    "invalid_token",
                    "Exchanged token not found or expired",
                )
            }
        };
        drop(tokens);
        if state.revoked_arms.read().await.contains(&meta.arm_id) {
            return HttpResponse::error(
                403,
                "Forbidden",
                "access_denied",
                "Caller arm is in active revocation list",
            );
        }
        if !meta
            .allowed_services
            .iter()
            .any(|s| matches_pattern(s, tool_uri))
        {
            return HttpResponse::error(
                403,
                "Forbidden",
                "access_denied",
                &format!("Token lacks permission for {}", tool_uri),
            );
        }
        caller_subject = meta.subject;
    } else {
        // Verify ES256 JWS against configured JWKS
        let parts: Vec<&str> = auth.split('.').collect();
        if parts.len() != 3 {
            return HttpResponse::error(
                401,
                "Unauthorized",
                "invalid_token",
                "Malformed bearer token",
            );
        }
        let payload_bytes = match base64url_decode_no_pad(parts[1]) {
            Ok(b) => b,
            Err(_) => {
                return HttpResponse::error(
                    401,
                    "Unauthorized",
                    "invalid_token",
                    "Invalid JWT payload encoding",
                )
            }
        };
        let sig_bytes = match base64url_decode_no_pad(parts[2]) {
            Ok(b) => b,
            Err(_) => {
                return HttpResponse::error(
                    401,
                    "Unauthorized",
                    "invalid_token",
                    "Invalid JWT signature encoding",
                )
            }
        };
        let payload_val: serde_json::Value = match serde_json::from_slice(&payload_bytes) {
            Ok(v) => v,
            Err(_) => {
                return HttpResponse::error(
                    401,
                    "Unauthorized",
                    "invalid_token",
                    "Invalid JWT payload JSON",
                )
            }
        };
        if let Some(exp) = payload_val.get("exp").and_then(|v| v.as_u64()) {
            if now > exp + 5 {
                return HttpResponse::error(
                    401,
                    "Unauthorized",
                    "token_expired",
                    "Bearer JWT expired beyond 5s skew window",
                );
            }
        }
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let jwks_guard = state.jwks.read().await;
        let verified = match jwks_guard.as_ref() {
            Some(jwks) => jwks
                .keys
                .iter()
                .any(|k| verify_es256_p256(signing_input.as_bytes(), &sig_bytes, &k.x, &k.y)),
            None => false,
        };
        drop(jwks_guard);
        if !verified {
            return HttpResponse::error(
                401,
                "Unauthorized",
                "invalid_signature",
                "ES256 JWT signature verification failed",
            );
        }
        let sub = payload_val
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let arm_id = payload_val
            .get("arm_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if state.revoked_arms.read().await.contains(arm_id) {
            return HttpResponse::error(
                403,
                "Forbidden",
                "access_denied",
                "Caller arm is revoked",
            );
        }
        if !state.policy.read().await.is_service_allowed(&sub, tool_uri) {
            return HttpResponse::error(
                403,
                "Forbidden",
                "access_denied",
                &format!("Subject '{}' is not authorized for {}", sub, tool_uri),
            );
        }
        caller_subject = sub;
    }

    // 2. Verify and atomically consume single-use CAGE RoutingSeal
    let raw_seal = match req.headers.get(HEADER_PEP_CAGE_SEAL) {
        Some(s) if !s.trim().is_empty() => s.trim(),
        _ => {
            return HttpResponse::error(
                403,
                "Forbidden",
                "missing_cage_seal",
                "Inbound published Wasm actuation requires X-Octopus-Cage-Seal",
            )
        }
    };

    let seal: CageRoutingSeal = if raw_seal.starts_with('{') {
        match serde_json::from_str(raw_seal) {
            Ok(s) => s,
            Err(e) => {
                return HttpResponse::error(
                    400,
                    "Bad Request",
                    "malformed_cage_seal",
                    &format!("Invalid CAGE seal JSON: {e}"),
                )
            }
        }
    } else {
        match base64url_decode_no_pad(raw_seal)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
        {
            Some(s) => s,
            None => {
                return HttpResponse::error(
                    400,
                    "Bad Request",
                    "malformed_cage_seal",
                    "Invalid base64url-encoded CAGE seal",
                )
            }
        }
    };

    let cage_engine = state.cage_engine.read().await.clone();
    let params_val = serde_json::json!({
        "tool_uri": tool_uri,
        "payload_sha256": hex::encode(Sha256::digest(&req.body)),
        "payload_len": req.body.len(),
    });
    let expected_digest = cage_engine.compute_action_digest(wasm_tool_name, &params_val);

    if let Err(rej) = cage_engine.verify_and_consume_seal(&seal, wasm_tool_name, &expected_digest) {
        return match rej {
            SealRejection::AlreadyConsumed(seal_id) => {
                state.stats.write().await.published_seal_replays_blocked += 1;
                HttpResponse::error(
                    409,
                    "Conflict",
                    "SEAL_ALREADY_CONSUMED",
                    &format!("Single-use CAGE RoutingSeal '{}' was already consumed", seal_id),
                )
            }
            other => HttpResponse::error(
                403,
                "Forbidden",
                "INVALID_CAGE_SEAL",
                &format!("CAGE RoutingSeal rejected: {}", other),
            ),
        };
    }

    // 3. Execute real Tier 1 Wasmtime sandbox module
    let wasm_opt = state.wasm_executor.read().await.clone();
    let Some(wasm) = wasm_opt else {
        return HttpResponse::error(
            500,
            "Internal Server Error",
            "wasm_unavailable",
            "WasmTier1Executor not initialized on serving node",
        );
    };

    let limits = WasmSandboxLimits::default();
    let receipt_res = if wasm_tool_name == "wasm_ledger_validator" {
        wasm.execute_ledger_validator(&req.body, limits)
    } else {
        wasm.execute_doc_extractor(&req.body, limits)
    };

    match receipt_res {
        Ok(receipt) => {
            state.stats.write().await.published_wasm_calls += 1;
            HttpResponse::json(
                200,
                "OK",
                &serde_json::json!({
                    "status": "ok",
                    "tool": wasm_tool_name,
                    "uri": tool_uri,
                    "caller": caller_subject,
                    "seal_id": seal.seal_id,
                    "wasm_exit_code": receipt.exit_code,
                    "fuel_consumed": receipt.fuel_consumed,
                    "peak_linear_memory_bytes": receipt.peak_linear_memory_bytes,
                    "linear_memory_zero_secret_verified": receipt.linear_memory_zero_secret_verified,
                    "sanitized_output": receipt.zero_mi_projection.canonical_output,
                    "raw_output": receipt.raw_output,
                }),
            )
        }
        Err(e) => HttpResponse::error(
            422,
            "Unprocessable Entity",
            "wasm_execution_failed",
            &e.to_string(),
        ),
    }
}

async fn handle_echo_headers(req: HttpRequest, state: &Arc<ConformanceNodeInner>) -> HttpResponse {
    state.stats.write().await.header_echo_inspections += 1;

    let auth_header_present = req.headers.contains_key("authorization");
    let mesh_auth_present = req.headers.contains_key("x-mesh-authentication");
    let mesh_auth_val = req.headers.get("x-mesh-authentication").cloned().unwrap_or_default();

    HttpResponse::json(
        200,
        "OK",
        &serde_json::json!({
            "status": "ok",
            "received_headers": req.headers,
            "authorization_header_present": auth_header_present,
            "authorization_stripped": !auth_header_present,
            "x_mesh_authentication_present": mesh_auth_present,
            "x_mesh_auth_value": mesh_auth_val,
        }),
    )
}

async fn handle_jwks(state: &Arc<ConformanceNodeInner>) -> HttpResponse {
    let jwks = state.jwks.read().await;
    match jwks.as_ref() {
        Some(j) => HttpResponse::json(200, "OK", j),
        None => HttpResponse::error(404, "Not Found", "not_found", "JWKS not configured"),
    }
}

async fn handle_openid_config(state: &Arc<ConformanceNodeInner>) -> HttpResponse {
    let port = state.node_id.rsplit('_').next().unwrap_or("0");
    HttpResponse::json(
        200,
        "OK",
        &serde_json::json!({
            "issuer": format!("http://127.0.0.1:{}", port),
            "token_endpoint": format!("http://127.0.0.1:{}/oauth/token", port),
            "jwks_uri": format!("http://127.0.0.1:{}/.well-known/jwks.json", port),
            "response_types_supported": ["token"],
            "grant_types_supported": ["urn:ietf:params:oauth:grant-type:token-exchange"],
            "id_token_signing_alg_values_supported": ["ES256"],
        }),
    )
}

fn extract_bearer_token(req: &HttpRequest) -> Option<String> {
    if let Some(auth) = req.headers.get("x-mesh-authentication") {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            return Some(token.trim().to_string());
        }
    }
    if let Some(auth) = req.headers.get("authorization") {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            return Some(token.trim().to_string());
        }
    }
    None
}

/// Simple percent-decoding implementation without external dependencies
pub fn percent_decode(input: &str) -> String {
    let mut bytes = Vec::with_capacity(input.len());
    let mut chars = input.bytes().peekable();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let h1 = chars.next();
            let h2 = chars.next();
            if let (Some(c1), Some(c2)) = (h1, h2) {
                let hex_str = [c1, c2];
                if let Ok(s) = std::str::from_utf8(&hex_str) {
                    if let Ok(byte) = u8::from_str_radix(s, 16) {
                        bytes.push(byte);
                        continue;
                    }
                }
                bytes.push(b'%');
                bytes.push(c1);
                bytes.push(c2);
            } else {
                bytes.push(b'%');
            }
        } else if b == b'+' {
            bytes.push(b' ');
        } else {
            bytes.push(b);
        }
    }
    String::from_utf8_lossy(&bytes).to_string()
}

/// Verifies an ES256 (ECDSA P-256 with SHA-256) signature against base64url coordinates X and Y.
pub fn verify_es256_p256(data: &[u8], sig_bytes: &[u8], x_b64: &str, y_b64: &str) -> bool {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    if sig_bytes.len() != 64 {
        return false;
    }

    let x = match base64url_decode_no_pad(x_b64) {
        Ok(b) if b.len() == 32 => b,
        _ => return false,
    };
    let y = match base64url_decode_no_pad(y_b64) {
        Ok(b) if b.len() == 32 => b,
        _ => return false,
    };

    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(&x);
    uncompressed.extend_from_slice(&y);

    let verifying_key = match VerifyingKey::from_sec1_bytes(&uncompressed) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let signature = match Signature::from_slice(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    verifying_key.verify(data, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::pep_bridge::AsyncHttpWireClient;
    use base64::Engine;

    #[tokio::test]
    async fn test_policy_json_resolution_and_matching() {
        let policy = AgentMeshPolicyConfig::default_serving_policy();
        assert!(policy.is_service_allowed("spiffe://oshoosiclaw.local/arm/arm_calc/epoch/0", "mcp://calc"));
        assert!(!policy.is_service_allowed("spiffe://oshoosiclaw.local/arm/arm_calc/epoch/0", "mcp://payroll"));
        assert!(policy.is_service_allowed("spiffe://oshoosiclaw.local/arm/arm_payroll/epoch/1", "mcp://payroll"));
        assert!(!policy.is_service_allowed("spiffe://oshoosiclaw.local/arm/arm_rogue/epoch/0", "mcp://calc"));
    }

    #[tokio::test]
    async fn test_conformance_node_ephemeral_port_lifecycle() {
        let policy = AgentMeshPolicyConfig::default_serving_policy();
        let mut node = AgentMeshServingNode::start(policy, None, 0).await.expect("Bind failed");
        assert!(node.port() > 0);
        assert!(node.url().starts_with("http://127.0.0.1:"));

        let stats = node.stats().await;
        assert_eq!(stats.total_requests, 0);

        node.stop().await;
    }

    #[tokio::test]
    async fn test_rfc8693_token_exchange_invalid_grant_type() {
        let policy = AgentMeshPolicyConfig::default_serving_policy();
        let mut node = AgentMeshServingNode::start(policy, None, 0).await.unwrap();

        let payload = serde_json::to_vec(&serde_json::json!({
            "grant_type": "client_credentials",
            "subject_token": "dummy",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt"
        })).unwrap();

        let (status, _headers, resp_bytes) = AsyncHttpWireClient::post(
            &format!("{}/oauth/token", node.url()),
            &[("Content-Type".to_string(), "application/json".to_string())],
            &payload,
        ).await.unwrap();

        assert_eq!(status, 400);
        let body: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
        assert_eq!(body["error"], "invalid_request");

        node.stop().await;
    }

    #[tokio::test]
    async fn test_header_echo_verifies_authorization_stripped() {
        let policy = AgentMeshPolicyConfig::default_serving_policy();
        let mut node = AgentMeshServingNode::start(policy, None, 0).await.unwrap();

        let (status, _headers, resp_bytes) = AsyncHttpWireClient::post(
            &format!("{}/mesh/echo_headers", node.url()),
            &[("X-Mesh-Authentication".to_string(), "Bearer mesh_tok_valid123".to_string())],
            b"",
        ).await.unwrap();

        assert_eq!(status, 200);
        let body: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
        assert_eq!(body["authorization_header_present"], false);
        assert_eq!(body["authorization_stripped"], true);
        assert_eq!(body["x_mesh_authentication_present"], true);

        node.stop().await;
    }

    #[tokio::test]
    async fn test_active_revocation_list_dual_side_734() {
        let policy = AgentMeshPolicyConfig::default_serving_policy();
        let mut node = AgentMeshServingNode::start(policy, None, 0).await.unwrap();

        // Revoke arm_rogue on serving node
        node.revoke_arm("arm_rogue").await;

        // Attempt token exchange with arm_rogue (synthetic JWS)
        let header = "{\"alg\":\"ES256\",\"typ\":\"JWT\",\"kid\":\"k1\"}";
        let payload = "{\"sub\":\"spiffe://oshoosiclaw.local/arm/arm_rogue/epoch/0\",\"arm_id\":\"arm_rogue\",\"epoch\":0,\"exp\":9999999999,\"nbf\":1000,\"iat\":1000}";
        let sig = vec![0u8; 64];

        let jws = format!(
            "{}.{}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig)
        );

        let req_body = serde_json::to_vec(&serde_json::json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": jws,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt"
        })).unwrap();

        let (status, _headers, resp_bytes) = AsyncHttpWireClient::post(
            &format!("{}/oauth/token", node.url()),
            &[("Content-Type".to_string(), "application/json".to_string())],
            &req_body,
        ).await.unwrap();

        // Must reject with 403 Forbidden due to active revocation
        assert_eq!(status, 403);
        let resp_str = String::from_utf8_lossy(&resp_bytes);
        assert!(resp_str.contains("active revocation list"));

        node.stop().await;
    }
}
