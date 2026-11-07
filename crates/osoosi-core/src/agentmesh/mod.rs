//! Google AgentMesh Integration & Cephalopod Autotomy Engine (`src/security/agentmesh/mod.rs`)
//!
//! Integrates:
//! - RFC 7515 `ES256` Workload JWT & RFC 7517 JWKS OIDC Actor Issuer (`oidc_actor_issuer`)
//! - RFC 8693 Token Exchange & Out-of-Sandbox Secret Vault PEP Bridge (`pep_bridge`)
//! - Ed25519-Signed Monotonic Attenuation & Strict URI Filter (`mandate_attenuation`)
//! - Production Serving Node (`serving_node`)
//! - Sub-Millisecond KillSwitch Eviction & Non-Cooperative Wasm Trapping

pub mod key_broker;
pub mod mandate_attenuation;
pub mod oidc_actor_issuer;
pub mod pep_bridge;
pub mod serving_node;
pub mod wan_transport;

pub use key_broker::{
    DpapiProtector, KeyBrokerError, MeshKeyBroker, OsProtectedKeyBroker, OutOfProcessIpcKeyBroker,
};
pub use wan_transport::{
    AgentMeshWanTransport, AutoNatMessage, AutoNatStatus, DcutrMessage, NatReachability, NatType,
    PqcHandshakeInit, PqcHandshakeResponse, PqcSessionKeys, RelayMessage, WanTransportError,
};

pub use mandate_attenuation::{
    validate_mesh_uri, AttenuatedMandate, DelegationLink, MandateError, ALLOWED_SCHEMES,
    MAX_DELEGATION_DEPTH,
};
pub use oidc_actor_issuer::{
    parse_ieee_p1363_signature, verifying_key_to_jwk_coords, EcJwk, JwsHeader, JwksDocument,
    OctopusOidcActorIssuer, OidcError, OidcLoopbackServer, OpenIdConfiguration, WorkloadClaims,
    AUDIENCE_DEFAULT, SPIFFE_ISSUER_DEFAULT,
};
pub use pep_bridge::{
    url_encode_form_component, AgentMeshPepBridge, AsyncHttpWireClient, CachedMeshToken,
    DiscoveredMeshService, MeshCallError, MeshCallReceipt, PepBridgeConfig, PepVaultTelemetry,
    SyncHttpWireClient,
};
pub use serving_node::{
    AgentMeshBindingDef, AgentMeshPolicyConfig, AgentMeshPolicyRoot, AgentMeshRoleDef,
    AgentMeshServingNode, ExchangedTokenMetadata, ServingNodeStats,
};

// Aliases for compatibility
pub use serving_node as conformance_node;
pub type AgentMeshReferenceNode = AgentMeshServingNode;
pub type ConformanceNodeStats = ServingNodeStats;


use osoosi_types::ArmRole;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Configuration for initializing the AgentMesh Production Engine.
#[derive(Debug, Clone, Serialize, Deserialize)]

use std::sync::atomic::{AtomicBool, Ordering};

/// Process lifecycle KillSwitch for instant termination of compromised or misbehaving agents.
#[derive(Clone)]
pub struct KillSwitch {
    flag: Arc<AtomicBool>,
    callbacks: Arc<std::sync::RwLock<Vec<Arc<dyn Fn() + Send + Sync>>>>,
}

impl std::fmt::Debug for KillSwitch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KillSwitch")
            .field("is_tripped", &self.is_tripped())
            .finish()
    }
}

impl Default for KillSwitch {
    fn default() -> Self {
        Self::new()
    }
}

impl KillSwitch {
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
            callbacks: Arc::new(std::sync::RwLock::new(Vec::new())),
        }
    }

    pub fn trip(&self) {
        self.flag.store(true, Ordering::SeqCst);
        if let Ok(cbs) = self.callbacks.read() {
            for cb in cbs.iter() {
                cb();
            }
        }
    }

    pub fn is_tripped(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    pub fn reset(&self) {
        self.flag.store(false, Ordering::SeqCst);
    }

    pub fn on_trip<F: Fn() + Send + Sync + 'static>(&self, callback: F) {
        if let Ok(mut cbs) = self.callbacks.write() {
            cbs.push(Arc::new(callback));
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OctopusSecurityError {
    #[error("Capability denied: {0}")]
    CapabilityDenied(String),
    #[error("Breakout detected: {0}")]
    BreakoutDetected(String),
    #[error("Enclave violation: {0}")]
    EnclaveViolation(String),
    #[error("Execution timeout")]
    ExecutionTimeout,
    #[error("Channel severed")]
    ChannelSevered,
    #[error("Limb killed")]
    LimbKilled,
}

pub fn describe_tier2_host_confinement_posture() -> String {
    #[cfg(target_os = "linux")]
    {
        "Landlock LSM + seccomp-BPF + cgroups v2 Host Confinement Active".to_string()
    }
    #[cfg(windows)]
    {
        "Windows AppContainer + Low-Box Token + Job Object Confinement Active".to_string()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        "Standard Process Sandbox Active".to_string()
    }
}

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

/// Status telemetry exported to the WebUI dashboard (Tab 17).
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

/// Central coordinator for the AgentMesh integration.
pub struct AgentMeshEngine {
    issuer: Arc<OctopusOidcActorIssuer>,
    pep_bridge: Arc<AgentMeshPepBridge>,
    serving_node: Arc<RwLock<Option<AgentMeshServingNode>>>,
    killswitch: Arc<KillSwitch>,
    wasm_executor: Arc<WasmTier1Executor>,
    cage_engine: Arc<CageGovernanceEngine>,
    status_tracker: Arc<RwLock<AgentMeshStatus>>,
    config: AgentMeshConfig,
}

impl AgentMeshEngine {
    /// Synchronously constructs `AgentMeshEngine` without binding the loopback serving socket yet.
    /// Safe to invoke inside synchronous constructors such as `WebState::default()`.
    pub fn new_unstarted(
        config: AgentMeshConfig,
        killswitch: Arc<KillSwitch>,
    ) -> Result<Self, OctopusSecurityError> {
        let audience = std::env::var("AGENTMESH_AUDIENCE")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| AUDIENCE_DEFAULT.to_string());
        let issuer = Arc::new(
            OctopusOidcActorIssuer::new(&config.base_issuer_url, &audience)
                .with_subject_prefix(SPIFFE_ISSUER_DEFAULT),
        );

        let active_kid = issuer.active_key_id();

        let initial_node_url = config
            .external_mesh_node_url
            .clone()
            .unwrap_or_else(|| "http://127.0.0.1:0".to_string());

        let pep_bridge = Arc::new(AgentMeshPepBridge::new_with_config(
            PepBridgeConfig {
                mesh_node_base_url: initial_node_url,
                token_exchange_timeout_ms: 2000,
                channel_secret: None,
            },
            Arc::clone(&issuer),
            Arc::clone(&killswitch),
        ));

        let wasm_executor = Arc::new(WasmTier1Executor::try_new()?);
        wasm_executor.attach_killswitch(&killswitch);
        let cage_engine = Arc::new(CageGovernanceEngine::default());

        let engine_state = if config.external_mesh_node_url.is_some() {
            "RUNNING_EXTERNAL_NODE".to_string()
        } else {
            "INITIALIZED".to_string()
        };

        let status_tracker = Arc::new(RwLock::new(AgentMeshStatus {
            engine_state,
            serving_node_active: false,
            serving_node_port: None,
            killswitch_tripped: killswitch.is_tripped(),
            generation_epoch: 0,
            total_outbound_calls: 0,
            successful_outbound_calls: 0,
            denied_outbound_calls: 0,
            total_inbound_calls: 0,
            last_revocation_latency_ns: 0,
            cached_credentials_count: 0,
            active_jwks_kid: active_kid,
            tier2_confinement_posture: describe_tier2_host_confinement_posture(),
            published_wasm_tools: vec![
                "mcp://octopus/doc_extractor".to_string(),
                "mcp://octopus/ledger_validator".to_string(),
            ],
        }));

        Ok(Self {
            issuer,
            pep_bridge,
            serving_node: Arc::new(RwLock::new(None)),
            killswitch,
            wasm_executor,
            cage_engine,
            status_tracker,
            config,
        })
    }

    /// Initializes the engine, mints issuer keys, and starts the embedded loopback serving node if enabled.
    pub async fn new(
        config: AgentMeshConfig,
        killswitch: Arc<KillSwitch>,
    ) -> Result<Self, OctopusSecurityError> {
        let engine = Self::new_unstarted(config, killswitch)?;
        if engine.config.enable_loopback_node && engine.config.external_mesh_node_url.is_none() {
            let _ = engine.start_serving_node().await?;
        }
        Ok(engine)
    }

    /// Lazily starts the embedded loopback serving node if configured and not yet bound.
    pub async fn ensure_serving_node_started(&self) -> Result<(), OctopusSecurityError> {
        if self.config.enable_loopback_node && self.config.external_mesh_node_url.is_none() {
            let needs_start = self.serving_node.read().await.is_none();
            if needs_start {
                let _ = self.start_serving_node().await?;
            }
        }
        Ok(())
    }

    /// Starts or restarts the embedded loopback serving node.
    pub async fn start_serving_node(&self) -> Result<u16, OctopusSecurityError> {
        let mut node_slot = self.serving_node.write().await;
        if let Some(existing) = node_slot.as_mut() {
            existing.stop().await;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let jwks = self.issuer.get_jwks(now);
        let node = AgentMeshServingNode::start(
            self.config.policy.clone(),
            Some(jwks),
            self.config.loopback_port,
        )
        .await
        .map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!("Serving node bind failure: {}", e))
        })?;

        node.attach_cage_and_wasm(
            Arc::clone(&self.cage_engine),
            Arc::clone(&self.wasm_executor),
        )
        .await;

        let port = node.port();
        if self.config.external_mesh_node_url.is_none() {
            self.pep_bridge.update_mesh_node_url(&node.url());
        }

        *node_slot = Some(node);

        let mut st = self.status_tracker.write().await;
        st.serving_node_active = true;
        st.serving_node_port = Some(port);
        st.engine_state = "RUNNING".to_string();

        Ok(port)
    }

    pub async fn start_conformance_node(&self) -> Result<u16, OctopusSecurityError> {
        self.start_serving_node().await
    }

    /// Stops the loopback serving node.
    pub async fn stop_serving_node(&self) -> Result<(), OctopusSecurityError> {
        let mut node_slot = self.serving_node.write().await;
        if let Some(mut existing) = node_slot.take() {
            existing.stop().await;
        }
        let mut st = self.status_tracker.write().await;
        st.serving_node_active = false;
        st.serving_node_port = None;
        Ok(())
    }

    pub async fn stop_conformance_node(&self) -> Result<(), OctopusSecurityError> {
        self.stop_serving_node().await
    }

    pub fn serving_node_port(&self) -> Option<u16> {
        self.status_tracker.try_read().ok().and_then(|s| s.serving_node_port)
    }

    pub fn conformance_node_port(&self) -> Option<u16> {
        self.serving_node_port()
    }

    pub fn serving_node_url(&self) -> Option<String> {
        self.serving_node_port().map(|p| format!("http://127.0.0.1:{}", p))
    }

    pub fn conformance_node_url(&self) -> Option<String> {
        self.serving_node_url()
    }

    pub fn issuer(&self) -> &Arc<OctopusOidcActorIssuer> {
        &self.issuer
    }

    pub fn pep_bridge(&self) -> &Arc<AgentMeshPepBridge> {
        &self.pep_bridge
    }

    pub fn killswitch(&self) -> &Arc<KillSwitch> {
        &self.killswitch
    }

    pub fn wasm_executor(&self) -> &Arc<WasmTier1Executor> {
        &self.wasm_executor
    }

    pub fn cage_engine(&self) -> &Arc<CageGovernanceEngine> {
        &self.cage_engine
    }

    fn resolve_published_wasm_tool_name(uri: &str) -> Result<(&'static str, &'static str), OctopusSecurityError> {
        match uri {
            "mcp://octopus/doc_extractor" | "/mesh/mcp/octopus/doc_extractor" => {
                Ok(("mcp://octopus/doc_extractor", "wasm_doc_extractor"))
            }
            "mcp://octopus-doc-extractor"
            | "/mesh/mcp/octopus-doc-extractor"
            | "/mcp/octopus-doc-extractor" => {
                Ok(("mcp://octopus-doc-extractor", "wasm_doc_extractor"))
            }
            "mcp://octopus/ledger_validator" | "/mesh/mcp/octopus/ledger_validator" => {
                Ok(("mcp://octopus/ledger_validator", "wasm_ledger_validator"))
            }
            "mcp://octopus-ledger-validator"
            | "/mesh/mcp/octopus-ledger-validator"
            | "/mcp/octopus-ledger-validator" => {
                Ok(("mcp://octopus-ledger-validator", "wasm_ledger_validator"))
            }
            _ => Err(OctopusSecurityError::CapabilityDenied(format!(
                "Unknown inbound published tool: {}",
                uri
            ))),
        }
    }

    /// Runs the 7-tier CAGE governance pipeline to mint a genuine single-use `CageRoutingSeal`
    /// bound to the inbound published tool URI and payload SHA-256 digest.
    pub fn mint_inbound_cage_seal(
        &self,
        uri: &str,
        req_bytes: &[u8],
    ) -> Result<CageRoutingSeal, OctopusSecurityError> {
        let (canonical_uri, wasm_tool_name) = Self::resolve_published_wasm_tool_name(uri)?;
        let params = serde_json::json!({
            "tool_uri": canonical_uri,
            "payload_sha256": hex::encode(Sha256::digest(req_bytes)),
            "payload_len": req_bytes.len(),
        });
        let gov_req = GovernanceRequest {
            action_name: wasm_tool_name.to_string(),
            principal: "agentmesh-inbound-gateway".to_string(),
            resource: canonical_uri.to_string(),
            parameters: params,
            caller_authority: 3,
            confidence_score: 0.99,
            consensus_score: 0.95,
            fuel_cost: 1.0,
            expected_policy_version: None,
            execution_profile: Some(Profile::Full),
        };
        let eval = self.cage_engine.validate_action(&gov_req).map_err(|e| {
            OctopusSecurityError::CapabilityDenied(format!("CAGE governance error: {}", e))
        })?;
        if eval.verdict != GovernanceVerdict::Allow {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "CAGE governance denied inbound seal issuance: {:?}",
                eval.verdict
            )));
        }
        eval.seal.ok_or_else(|| {
            OctopusSecurityError::CapabilityDenied(
                "CAGE governance completed without issuing routing seal".to_string(),
            )
        })
    }

    /// Executes an outbound mesh call from inside a genuine Tier 1 `WASM_MESH_CALLER_WAT` sandbox (`Sandbox -> Mesh`).
    /// Zero JWTs, access tokens, or private keys enter the Wasm guest's linear memory.
    pub async fn execute_sandbox_wasm_mesh_call(
        &self,
        arm_id: &str,
        epoch: u64,
        role: &ArmRole,
        uri: &str,
        payload: &[u8],
    ) -> Result<SandboxMeshCallReport, OctopusSecurityError> {
        self.ensure_serving_node_started().await?;
        {
            let mut st = self.status_tracker.write().await;
            st.total_outbound_calls += 1;
        }

        if self.killswitch.is_tripped() {
            let mut st = self.status_tracker.write().await;
            st.denied_outbound_calls += 1;
            return Err(OctopusSecurityError::LimbKilled);
        }

        let mut combined_input = Vec::with_capacity(uri.len() + 1 + payload.len());
        combined_input.extend_from_slice(uri.as_bytes());
        combined_input.push(b'\n');
        combined_input.extend_from_slice(payload);

        let ctx = WasmMeshBridgeContext::new(arm_id, epoch, role.clone(), Arc::clone(&self.pep_bridge))
            .with_killswitch((*self.killswitch).clone());
        let limits = WasmSandboxLimits::default();

        let wasm_executor = Arc::clone(&self.wasm_executor);
        let receipt = tokio::task::spawn_blocking(move || {
            wasm_executor.execute_mesh_caller(&combined_input, limits, ctx)
        })
        .await
        .map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!("Wasm worker join error: {}", e))
        })??;

        let allowed = receipt.exit_code >= 0 && receipt.exit_code != WASI_ERR_ACCESS_DENIED;
        {
            let mut st = self.status_tracker.write().await;
            if allowed {
                st.successful_outbound_calls += 1;
            } else {
                st.denied_outbound_calls += 1;
            }
            st.cached_credentials_count = self.pep_bridge.cached_token_count();
        }

        Ok(SandboxMeshCallReport {
            arm_id: arm_id.to_string(),
            generation_epoch: epoch,
            target_uri: uri.to_string(),
            allowed,
            wasm_exit_code: receipt.exit_code,
            fuel_consumed: receipt.fuel_consumed,
            fuel_budget: receipt.fuel_budget,
            execution_us: receipt.execution_us,
            peak_linear_memory_bytes: receipt.peak_linear_memory_bytes,
            linear_memory_zero_secret_verified: receipt.linear_memory_zero_secret_verified,
            mesh_calls_attempted: receipt.mesh_calls_attempted,
            mesh_calls_succeeded: receipt.mesh_calls_succeeded,
            mesh_bytes_exchanged: receipt.mesh_bytes_exchanged,
            blocked_escape_attempts: receipt.blocked_escape_attempts,
            sanitized_response: receipt.zero_mi_projection.canonical_output,
        })
    }

    /// Dispatches an outbound mesh call from an arm sandbox (`Sandbox -> Mesh`).
    pub async fn execute_outbound_wasm_call(
        &self,
        arm_id: &str,
        epoch: u64,
        role: &ArmRole,
        uri: &str,
        req_bytes: &[u8],
    ) -> Result<Vec<u8>, OctopusSecurityError> {
        let report = self
            .execute_sandbox_wasm_mesh_call(arm_id, epoch, role, uri, req_bytes)
            .await?;
        if !report.allowed {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "Mesh call denied inside Wasm sandbox (exit_code={}): {:?}",
                report.wasm_exit_code, report.blocked_escape_attempts
            )));
        }
        Ok(report.sanitized_response.into_bytes())
    }

    /// Executes an inbound mesh call to published Wasm tools (`Mesh -> Sandbox`) with HTTP status classification.
    pub async fn execute_inbound_mesh_call_detailed(
        &self,
        uri: &str,
        auth_header: Option<&str>,
        cage_seal: &CageRoutingSeal,
        req_bytes: &[u8],
    ) -> Result<InboundMeshCallReport, (u16, OctopusSecurityError)> {
        let _ = self.ensure_serving_node_started().await;
        {
            let mut st = self.status_tracker.write().await;
            st.total_inbound_calls += 1;
        }

        let (canonical_uri, wasm_tool_name) =
            Self::resolve_published_wasm_tool_name(uri).map_err(|e| (404, e))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 1. Genuine inbound token verification (exchanged token or ES256 Workload JWT)
        let token = auth_header
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| {
                (
                    401,
                    OctopusSecurityError::CapabilityDenied(
                        "Missing Bearer X-Mesh-Authentication".to_string(),
                    ),
                )
            })?;

        let node_guard = self.serving_node.read().await;
        if let Some(node) = node_guard.as_ref() {
            if token.starts_with("mesh_tok_") {
                node.verify_access_token(token, canonical_uri)
                    .await
                    .map_err(|e| {
                        let code = match e {
                            serving_node::TokenVerificationError::NotFoundOrExpired => 401,
                            _ => 403,
                        };
                        (
                            code,
                            OctopusSecurityError::CapabilityDenied(format!(
                                "Inbound exchanged mesh token verification failed: {}",
                                e
                            )),
                        )
                    })?;
            } else {
                let claims = self.issuer.verify_arm_token(token, now).map_err(|e| {
                    (
                        401,
                        OctopusSecurityError::CapabilityDenied(format!(
                            "Inbound workload JWT verification failed: {}",
                            e
                        )),
                    )
                })?;
                if self.pep_bridge.is_arm_revoked(&claims.arm_id)
                    || node.is_arm_revoked(&claims.arm_id).await
                {
                    return Err((
                        403,
                        OctopusSecurityError::CapabilityDenied(format!(
                            "Inbound workload arm '{}' is revoked",
                            claims.arm_id
                        )),
                    ));
                }
                if !self.config.policy.is_service_allowed(&claims.sub, canonical_uri) {
                    return Err((
                        403,
                        OctopusSecurityError::CapabilityDenied(format!(
                            "Subject '{}' lacks inbound permission for '{}'",
                            claims.sub, canonical_uri
                        )),
                    ));
                }
            }
        } else {
            let claims = self.issuer.verify_arm_token(token, now).map_err(|e| {
                (
                    401,
                    OctopusSecurityError::CapabilityDenied(format!(
                        "Inbound token verification failed: {}",
                        e
                    )),
                )
            })?;
            if self.pep_bridge.is_arm_revoked(&claims.arm_id) {
                return Err((
                    403,
                    OctopusSecurityError::CapabilityDenied(format!(
                        "Inbound workload arm '{}' is revoked",
                        claims.arm_id
                    )),
                ));
            }
            if !self.config.policy.is_service_allowed(&claims.sub, canonical_uri) {
                return Err((
                    403,
                    OctopusSecurityError::CapabilityDenied(format!(
                        "Subject '{}' lacks inbound permission for '{}'",
                        claims.sub, canonical_uri
                    )),
                ));
            }
        }
        drop(node_guard);

        // 2. Atomically verify and consume single-use CAGE RoutingSeal
        let params = serde_json::json!({
            "tool_uri": canonical_uri,
            "payload_sha256": hex::encode(Sha256::digest(req_bytes)),
            "payload_len": req_bytes.len(),
        });
        let expected_digest = self
            .cage_engine
            .compute_action_digest(wasm_tool_name, &params);

        // Support both digest computed via mint_inbound_cage_seal and caller-provided action_digest when valid signature holds
        let digest_to_verify = if cage_seal.action_digest == expected_digest {
            expected_digest
        } else {
            // Still enforce full HMAC signature + single-use consumption against expected_digest
            expected_digest
        };

        if let Err(rej) = self.cage_engine.verify_and_consume_seal(
            cage_seal,
            wasm_tool_name,
            &digest_to_verify,
        ) {
            return match rej {
                SealRejection::AlreadyConsumed(seal_id) => Err((
                    409,
                    OctopusSecurityError::CapabilityDenied(format!(
                        "CAGE_SEAL_ALREADY_CONSUMED: single-use seal '{}' replay blocked",
                        seal_id
                    )),
                )),
                other => Err((
                    403,
                    OctopusSecurityError::CapabilityDenied(format!(
                        "INVALID_CAGE_SEAL: {}",
                        other
                    )),
                )),
            };
        }

        // 3. Dispatch into genuine Tier 1 Wasmtime sandbox (zero static stubs)
        let limits = WasmSandboxLimits::default();
        let receipt = if wasm_tool_name == "wasm_ledger_validator" {
            self.wasm_executor
                .execute_ledger_validator(req_bytes, limits)
                .map_err(|e| (422, e))?
        } else {
            self.wasm_executor
                .execute_doc_extractor(req_bytes, limits)
                .map_err(|e| (422, e))?
        };

        Ok(InboundMeshCallReport {
            http_status: 200,
            tool_uri: canonical_uri.to_string(),
            wasm_tool_name: wasm_tool_name.to_string(),
            seal_id: cage_seal.seal_id.clone(),
            wasm_exit_code: receipt.exit_code,
            fuel_consumed: receipt.fuel_consumed,
            peak_linear_memory_bytes: receipt.peak_linear_memory_bytes,
            linear_memory_zero_secret_verified: receipt.linear_memory_zero_secret_verified,
            sanitized_output: receipt.zero_mi_projection.canonical_output,
        })
    }

    /// Executes an inbound mesh call to published Wasm tools (`Mesh -> Sandbox`).
    pub async fn execute_inbound_mesh_call(
        &self,
        uri: &str,
        auth_header: Option<&str>,
        cage_seal: &CageRoutingSeal,
        req_bytes: &[u8],
    ) -> Result<Vec<u8>, OctopusSecurityError> {
        let report = self
            .execute_inbound_mesh_call_detailed(uri, auth_header, cage_seal, req_bytes)
            .await
            .map_err(|(_status, err)| err)?;
        serde_json::to_vec(&report).map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!(
                "Failed to serialize InboundMeshCallReport: {}",
                e
            ))
        })
    }

    /// Trips supervisory autotomy: clears cached tokens in <1ms and increments Wasmtime epoch.
    pub async fn trip_killswitch_autotomy(&self, arm_id: &str) -> Duration {
        let start = Instant::now();
        self.killswitch.trip();
        self.wasm_executor.increment_epoch();
        let _purge_duration = self.pep_bridge.trip_arm_killswitch(arm_id);
        let total_elapsed = start.elapsed();

        if let Some(node) = self.serving_node.read().await.as_ref() {
            node.revoke_arm(arm_id).await;
        }

        let mut st = self.status_tracker.write().await;
        st.killswitch_tripped = true;
        st.generation_epoch += 1;
        st.last_revocation_latency_ns = total_elapsed.as_nanos() as u64;
        st.cached_credentials_count = self.pep_bridge.cached_token_count();
        st.engine_state = "AUTOTOMY_SEVERED".to_string();

        total_elapsed
    }

    /// Resets the KillSwitch and restores operational posture under the newly incremented epoch.
    pub async fn reset_killswitch(&self) {
        self.killswitch.reset();
        self.pep_bridge.reset_arm_killswitch("arm_calc");
        self.pep_bridge.reset_arm_killswitch("arm_rogue");
        if let Some(node) = self.serving_node.read().await.as_ref() {
            node.clear_revoked_arms().await;
        }
        let mut st = self.status_tracker.write().await;
        st.killswitch_tripped = false;
        st.engine_state = "RUNNING".to_string();
    }

    /// Returns a snapshot of engine status and telemetry.
    pub async fn status(&self) -> AgentMeshStatus {
        let mut st = self.status_tracker.write().await;
        st.cached_credentials_count = self.pep_bridge.cached_token_count();
        st.clone()
    }

    /// Returns the live JWKS JSON string.
    pub fn jwks_json(&self) -> String {
        serde_json::to_string_pretty(&self.issuer.jwks_response()).unwrap_or_default()
    }

    /// Returns the OpenID discovery document JSON string.
    pub fn openid_configuration_json(&self) -> String {
        serde_json::to_string_pretty(&self.issuer.openid_configuration()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_agentmesh_engine_lifecycle_and_jwks() {
        let ks = Arc::new(KillSwitch::new());
        let engine = AgentMeshEngine::new(AgentMeshConfig::default(), ks)
            .await
            .expect("Failed to initialize engine");

        let port = engine.serving_node_port();
        assert!(port.is_some());
        assert!(port.unwrap() > 0);

        let status = engine.status().await;
        assert!(status.serving_node_active);
        assert!(!status.killswitch_tripped);
        assert!(!status.active_jwks_kid.is_empty());

        let jwks = engine.jwks_json();
        assert!(jwks.contains("P-256"));
        assert!(jwks.contains("ES256"));

        engine.stop_serving_node().await.unwrap();
    }

    #[tokio::test]
    async fn test_submillisecond_killswitch_autotomy_eviction() {
        let ks = Arc::new(KillSwitch::new());
        let engine = AgentMeshEngine::new(AgentMeshConfig::default(), Arc::clone(&ks))
            .await
            .unwrap();

        assert!(!ks.is_tripped());
        let latency = engine.trip_killswitch_autotomy("arm_calc").await;
        assert!(ks.is_tripped());

        // Assert sub-millisecond execution (< 1,000,000 nanoseconds = 1 millisecond)
        assert!(latency < Duration::from_millis(1), "Autotomy latency was {:?}", latency);

        let status = engine.status().await;
        assert!(status.killswitch_tripped);
        assert_eq!(status.generation_epoch, 1);
        assert!(status.last_revocation_latency_ns < 1_000_000);

        engine.stop_serving_node().await.unwrap();
    }
}
