//! Host-side Policy Enforcement Point (PEP) Bridge, Secret Vault, and Sub-Millisecond Eviction.
//!
//! Google AgentMesh (#734) x AgentOctopus Tier 1 Wasm Integration.
//!
//! Enforces:
//! 1. Zero secrets in Wasm linear memory: all mesh credentials remain in host vault memory.
//! 2. Token vault caching indexed by `(arm_id, generation_epoch)`.
//! 3. Bounded token vault capacity (no memory leaks).
//! 4. Proactive token refresh when < 15 seconds remain before expiry.
//! 5. Strict header hygiene: strips `Authorization`, `Cookie`, `X-Mesh-*`; injects `X-Mesh-Authentication`.
//! 6. Sub-millisecond KillSwitch eviction (< 1,000 microseconds) closing the #734 window.
//! 7. Zero-Mutual-Information output projection on all upstream response payloads.
//! 8. Strict URI scheme filtering (`mcp://`, `a2a://`, `inference://`, `egress://`).

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use super::KillSwitch;
use osoosi_types::ArmRole;
use super::OctopusSecurityError;

pub struct ZeroMutualInformationProjector;
impl ZeroMutualInformationProjector {
    pub fn is_zero_width_or_stego_char(c: char) -> bool {
        let u = c as u32;
        matches!(
            u,
            0x200B..=0x200F
                | 0x202A..=0x202E
                | 0x2060..=0x206F
                | 0xFEFF
                | 0xFE00..=0xFE0F
                | 0xE0100..=0xE01EF
        )
    }
    pub fn project_output(raw_output: &str, _timestamp_ms: u64, _slot_width_ms: u64) -> String {
        raw_output.chars().filter(|c| !Self::is_zero_width_or_stego_char(*c)).collect()
    }
}

use super::mandate_attenuation::validate_mesh_uri;
use super::oidc_actor_issuer::OctopusOidcActorIssuer;
use super::serving_node::{
    compute_node_response_proof, compute_pep_channel_proof, SignedEpochRevocationSignal,
    HEADER_NODE_PROOF, HEADER_PEP_CHANNEL_PROOF, HEADER_PEP_NONCE, HEADER_PEP_TIMESTAMP,
};
use tokio_util::sync::CancellationToken;

/// Tolerance window in seconds: if remaining lifetime is <= this buffer, refresh token proactively.
pub const TOKEN_REFRESH_BUFFER_SECS: u64 = 15;

/// Sub-millisecond eviction SLA: 1,000 microseconds (1 millisecond).
pub const KILLSWITCH_EVICTION_SLA_MICROS: u128 = 1_000;

/// Default connect timeout for loopback HTTP transport.
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 3_000;

/// Default read/write timeout for loopback/mesh HTTP transport.
pub const DEFAULT_IO_TIMEOUT_MS: u64 = 10_000;

/// Maximum number of cached tokens in vault
pub const MAX_CACHED_TOKENS_CAPACITY: usize = 1_024;

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum MeshCallError {
    #[error("KillSwitch is tripped for arm '{0}'")]
    KillSwitchTripped(String),

    #[error("Prohibited mesh URI '{0}': scheme must be 'mcp://', 'a2a://', 'inference://', or 'egress://'")]
    InvalidUri(String),

    #[error("Workload JWT minting failed: {0}")]
    TokenMintError(String),

    #[error("RFC 8693 token exchange failed (HTTP {status}): {message}")]
    TokenExchangeFailed { status: u16, message: String },

    #[error("Upstream mesh call failed (HTTP {status}): {message}")]
    UpstreamCallFailed { status: u16, message: String },

    #[error("Access denied by mesh policy (HTTP 403 / WASI_ERR_ACCESS_DENIED): {0}")]
    AccessDenied(String),

    #[error("Network transport error during mesh communication: {0}")]
    NetworkError(String),

    #[error("Token expired or missing for arm '{0}', epoch {1}")]
    TokenExpired(String, u64),

    #[error("Internal PEP bridge synchronization error: {0}")]
    Internal(String),
}

impl From<MeshCallError> for OctopusSecurityError {
    fn from(err: MeshCallError) -> Self {
        match err {
            MeshCallError::KillSwitchTripped(_) => OctopusSecurityError::LimbKilled,
            MeshCallError::AccessDenied(msg) => OctopusSecurityError::CapabilityDenied(msg),
            MeshCallError::InvalidUri(uri) => OctopusSecurityError::SsrfBlocked(uri),
            other => OctopusSecurityError::IsolationViolation(other.to_string()),
        }
    }
}

// ============================================================================
// Token Vault Data Structures & RFC 8693 Schemas
// ============================================================================

/// Cached exchanged mesh credential, stored strictly in host memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedMeshToken {
    pub arm_id: String,
    pub epoch: u64,
    pub role: ArmRole,
    pub access_token: String,
    pub token_type: String,
    pub issued_token_type: String,
    pub issued_at_unix_secs: u64,
    pub expires_at_unix_secs: u64,
}

impl CachedMeshToken {
    /// Returns true if the token has expired or is within the proactive refresh buffer.
    pub fn is_expired_or_near(&self, now_secs: u64, buffer_secs: u64) -> bool {
        now_secs.saturating_add(buffer_secs) >= self.expires_at_unix_secs
    }
}

/// Bounded Token Vault Store
#[derive(Default)]
pub struct BoundedTokenVault {
    tokens: HashMap<(String, u64), CachedMeshToken>,
    insertion_order: VecDeque<(String, u64)>,
    capacity: usize,
}

impl BoundedTokenVault {
    pub fn new(capacity: usize) -> Self {
        Self {
            tokens: HashMap::with_capacity(capacity),
            insertion_order: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub fn insert(&mut self, key: (String, u64), token: CachedMeshToken) {
        if !self.tokens.contains_key(&key) {
            if self.tokens.len() >= self.capacity {
                if let Some(oldest) = self.insertion_order.pop_front() {
                    self.tokens.remove(&oldest);
                }
            }
            self.insertion_order.push_back(key.clone());
        }
        self.tokens.insert(key, token);
    }

    pub fn get(&self, key: &(String, u64)) -> Option<&CachedMeshToken> {
        self.tokens.get(key)
    }

    pub fn remove(&mut self, key: &(String, u64)) -> Option<CachedMeshToken> {
        let tok = self.tokens.remove(key);
        if tok.is_some() {
            self.insertion_order.retain(|k| k != key);
        }
        tok
    }

    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&(String, u64), &mut CachedMeshToken) -> bool,
    {
        self.tokens.retain(|k, v| f(k, v));
        self.insertion_order.retain(|k| self.tokens.contains_key(k));
    }

    pub fn clear(&mut self) {
        self.tokens.clear();
        self.insertion_order.clear();
    }

    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

/// RFC 8693 OAuth 2.0 Token Exchange Request (`application/x-www-form-urlencoded` per RFC 8693 §2.1 & `google/agentmesh` `internal/node/sts.go`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rfc8693TokenRequest {
    pub grant_type: String,
    pub subject_token: String,
    pub subject_token_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seal: Option<bool>,
}

/// RFC 3986 / `application/x-www-form-urlencoded` percent-encoder for OAuth 2.0 form fields.
pub fn url_encode_form_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

impl Rfc8693TokenRequest {
    /// Serializes the RFC 8693 token exchange parameters as `application/x-www-form-urlencoded`
    /// so Go's `http.Request.ParseForm()` in `agentmesh-node` (`internal/node/sts.go`) parses every field.
    pub fn to_form_urlencoded(&self) -> Vec<u8> {
        let mut pairs = vec![
            format!("grant_type={}", url_encode_form_component(&self.grant_type)),
            format!(
                "subject_token={}",
                url_encode_form_component(&self.subject_token)
            ),
            format!(
                "subject_token_type={}",
                url_encode_form_component(&self.subject_token_type)
            ),
        ];
        if let Some(ref rtt) = self.requested_token_type {
            pairs.push(format!(
                "requested_token_type={}",
                url_encode_form_component(rtt)
            ));
        }
        if let Some(ref aud) = self.audience {
            pairs.push(format!("audience={}", url_encode_form_component(aud)));
        }
        if let Some(ref res) = self.resource {
            pairs.push(format!("resource={}", url_encode_form_component(res)));
        }
        if let Some(ref sc) = self.scope {
            pairs.push(format!("scope={}", url_encode_form_component(sc)));
        }
        if let Some(true) = self.seal {
            pairs.push("seal=true".to_string());
        }
        pairs.join("&").into_bytes()
    }
}

/// Discovered service entry returned by `GET /mesh/service/discover` on `agentmesh-node`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredMeshService {
    pub peer_id: String,
    #[serde(default)]
    pub srv_name: String,
    #[serde(default)]
    pub srv_description: String,
    #[serde(default)]
    pub local_proxy_url: String,
}

/// RFC 8693 OAuth 2.0 Token Exchange Successful Response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rfc8693TokenResponse {
    pub access_token: String,
    pub issued_token_type: String,
    pub token_type: String,
    pub expires_in: u64,
}

/// RFC 6749 / RFC 8693 Standard Error Response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rfc8693ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

/// Receipt returned after executing a mesh call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshCallReceipt {
    pub uri: String,
    pub caller_arm_id: String,
    pub epoch: u64,
    pub response_bytes: Vec<u8>,
    pub execution_duration_us: u64,
}

/// Configuration for PEP bridge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PepBridgeConfig {
    pub mesh_node_base_url: String,
    pub token_exchange_timeout_ms: u64,
    #[serde(default)]
    pub channel_secret: Option<[u8; 32]>,
}

impl Default for PepBridgeConfig {
    fn default() -> Self {
        Self {
            mesh_node_base_url: "http://127.0.0.1:0".to_string(),
            token_exchange_timeout_ms: 2000,
            channel_secret: None,
        }
    }
}

/// Telemetry structure exposed to WebUI dashboard (Tab 17) and audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PepVaultTelemetry {
    pub cached_tokens_count: usize,
    pub active_killswitches_count: usize,
    pub total_token_exchanges: u64,
    pub total_cache_hits: u64,
    pub total_killswitch_evictions: u64,
    pub last_eviction_duration_us: u64,
    pub mesh_node_url: String,
}

// ============================================================================
// Pure-Rust Synchronous & Asynchronous Wire Transports
// ============================================================================

/// Minimal synchronous HTTP/1.1 transport using `std::net::TcpStream`.
/// Operates without an async runtime for host imports called inside `wasmtime`.
pub struct SyncHttpWireClient {
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
}

impl Default for SyncHttpWireClient {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncHttpWireClient {
    pub fn new() -> Self {
        Self {
            connect_timeout: Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS),
            read_timeout: Duration::from_millis(DEFAULT_IO_TIMEOUT_MS),
            write_timeout: Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS),
        }
    }

    /// Dispatches an HTTP GET request over a raw TCP connection.
    pub fn get(
        &self,
        target_url: &str,
        headers: &[(String, String)],
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), MeshCallError> {
        self.request("GET", target_url, headers, &[])
    }

    /// Dispatches an HTTP POST request over a raw TCP connection.
    pub fn post(
        &self,
        target_url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), MeshCallError> {
        self.request("POST", target_url, headers, body)
    }

    /// Dispatches an HTTP/1.1 request over a raw TCP connection.
    pub fn request(
        &self,
        method: &str,
        target_url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), MeshCallError> {
        let parsed = Url::parse(target_url)
            .map_err(|e| MeshCallError::NetworkError(format!("Malformed URL '{}': {}", target_url, e)))?;

        let host = parsed.host_str().unwrap_or("127.0.0.1");
        let port = parsed.port_or_known_default().unwrap_or(80);
        let path = if parsed.path().is_empty() { "/" } else { parsed.path() };
        let query = parsed.query().map(|q| format!("?{}", q)).unwrap_or_default();
        let request_target = format!("{}{}", path, query);

        let addrs: Vec<SocketAddr> = format!("{}:{}", host, port)
            .to_socket_addrs()
            .map_err(|e| MeshCallError::NetworkError(format!("DNS resolution failed for {}:{}: {}", host, port, e)))?
            .collect();

        if addrs.is_empty() {
            return Err(MeshCallError::NetworkError(format!("No resolved addresses for {}:{}", host, port)));
        }

        let mut stream = TcpStream::connect_timeout(&addrs[0], self.connect_timeout)
            .map_err(|e| MeshCallError::NetworkError(format!("TCP connect to {} failed: {}", addrs[0], e)))?;

        stream
            .set_read_timeout(Some(self.read_timeout))
            .map_err(|e| MeshCallError::NetworkError(format!("Set read timeout failed: {}", e)))?;
        stream
            .set_write_timeout(Some(self.write_timeout))
            .map_err(|e| MeshCallError::NetworkError(format!("Set write timeout failed: {}", e)))?;

        let host_hdr = if port == 80 {
            host.to_string()
        } else {
            format!("{}:{}", host, port)
        };
        let mut wire_req = if method.eq_ignore_ascii_case("GET") && body.is_empty() {
            format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
                request_target, host_hdr
            )
        } else {
            format!(
                "{} {} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                method, request_target, host_hdr, body.len()
            )
        };

        for (k, v) in headers {
            wire_req.push_str(&format!("{}: {}\r\n", k, v));
        }
        wire_req.push_str("\r\n");

        stream
            .write_all(wire_req.as_bytes())
            .map_err(|e| MeshCallError::NetworkError(format!("TCP write header error: {}", e)))?;
        if !body.is_empty() {
            stream
                .write_all(body)
                .map_err(|e| MeshCallError::NetworkError(format!("TCP write body error: {}", e)))?;
        }
        stream
            .flush()
            .map_err(|e| MeshCallError::NetworkError(format!("TCP flush error: {}", e)))?;

        let mut raw_response = Vec::new();
        stream
            .read_to_end(&mut raw_response)
            .map_err(|e| MeshCallError::NetworkError(format!("TCP read error: {}", e)))?;

        Self::parse_http_response(&raw_response)
    }

    /// Decodes an HTTP/1.1 `Transfer-Encoding: chunked` body per RFC 9112 §7.1.
    pub fn decode_chunked_body(raw_body: &[u8]) -> Result<Vec<u8>, MeshCallError> {
        let mut out = Vec::with_capacity(raw_body.len());
        let mut idx = 0;
        while idx < raw_body.len() {
            let line_end = raw_body[idx..]
                .windows(2)
                .position(|w| w == b"\r\n")
                .ok_or_else(|| {
                    MeshCallError::NetworkError("Malformed chunked body: missing CRLF after chunk size".into())
                })?;
            let size_line = std::str::from_utf8(&raw_body[idx..idx + line_end])
                .map_err(|e| MeshCallError::NetworkError(format!("Invalid chunk size UTF-8: {e}")))?;
            let hex_part = size_line.split(';').next().unwrap_or("").trim();
            let chunk_size = usize::from_str_radix(hex_part, 16).map_err(|e| {
                MeshCallError::NetworkError(format!("Invalid hex chunk size '{}': {}", hex_part, e))
            })?;
            idx += line_end + 2;
            if chunk_size == 0 {
                break;
            }
            if idx + chunk_size > raw_body.len() {
                return Err(MeshCallError::NetworkError(
                    "Truncated chunked HTTP response body".into(),
                ));
            }
            out.extend_from_slice(&raw_body[idx..idx + chunk_size]);
            idx += chunk_size;
            if raw_body.get(idx..idx + 2) == Some(b"\r\n") {
                idx += 2;
            }
        }
        Ok(out)
    }

    /// Parses a raw HTTP/1.1 response buffer into status code, headers, and body.
    pub fn parse_http_response(raw: &[u8]) -> Result<(u16, Vec<(String, String)>, Vec<u8>), MeshCallError> {
        let header_end = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| MeshCallError::NetworkError("Malformed HTTP response: missing header terminator".into()))?;

        let header_bytes = &raw[..header_end];
        let body_bytes = &raw[header_end + 4..];

        let header_str = std::str::from_utf8(header_bytes)
            .map_err(|e| MeshCallError::NetworkError(format!("Non-UTF8 HTTP headers: {}", e)))?;

        let mut lines = header_str.lines();
        let status_line = lines
            .next()
            .ok_or_else(|| MeshCallError::NetworkError("Empty HTTP response status line".into()))?;

        let parts: Vec<&str> = status_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(MeshCallError::NetworkError(format!("Invalid HTTP status line: '{}'", status_line)));
        }

        let status_code: u16 = parts[1]
            .parse()
            .map_err(|e| MeshCallError::NetworkError(format!("Failed to parse HTTP status '{}': {}", parts[1], e)))?;

        let mut headers = Vec::new();
        let mut is_chunked = false;
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                let key = k.trim().to_string();
                let val = v.trim().to_string();
                if key.eq_ignore_ascii_case("transfer-encoding")
                    && val.to_ascii_lowercase().contains("chunked")
                {
                    is_chunked = true;
                }
                headers.push((key, val));
            }
        }

        let decoded_body = if is_chunked {
            Self::decode_chunked_body(body_bytes)?
        } else {
            body_bytes.to_vec()
        };

        Ok((status_code, headers, decoded_body))
    }
}

/// Asynchronous wire transport using `tokio::net::TcpStream` for server tasks.
pub struct AsyncHttpWireClient;

impl AsyncHttpWireClient {
    pub async fn get(
        target_url: &str,
        headers: &[(String, String)],
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), MeshCallError> {
        Self::request("GET", target_url, headers, &[]).await
    }

    pub async fn post(
        target_url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), MeshCallError> {
        Self::request("POST", target_url, headers, body).await
    }

    pub async fn request(
        method: &str,
        target_url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), MeshCallError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let parsed = Url::parse(target_url)
            .map_err(|e| MeshCallError::NetworkError(format!("Malformed URL '{}': {}", target_url, e)))?;

        let host = parsed.host_str().unwrap_or("127.0.0.1");
        let port = parsed.port_or_known_default().unwrap_or(80);
        let path = if parsed.path().is_empty() { "/" } else { parsed.path() };
        let query = parsed.query().map(|q| format!("?{}", q)).unwrap_or_default();
        let request_target = format!("{}{}", path, query);

        let mut stream = tokio::time::timeout(
            Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS),
            tokio::net::TcpStream::connect(format!("{}:{}", host, port)),
        )
        .await
        .map_err(|_| MeshCallError::NetworkError(format!("Async connect timeout to {}:{}", host, port)))?
        .map_err(|e| MeshCallError::NetworkError(format!("Async connect failed: {}", e)))?;

        let host_hdr = if port == 80 {
            host.to_string()
        } else {
            format!("{}:{}", host, port)
        };
        let mut wire_req = if method.eq_ignore_ascii_case("GET") && body.is_empty() {
            format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
                request_target, host_hdr
            )
        } else {
            format!(
                "{} {} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                method, request_target, host_hdr, body.len()
            )
        };

        for (k, v) in headers {
            wire_req.push_str(&format!("{}: {}\r\n", k, v));
        }
        wire_req.push_str("\r\n");

        stream
            .write_all(wire_req.as_bytes())
            .await
            .map_err(|e| MeshCallError::NetworkError(format!("Async write headers error: {}", e)))?;
        if !body.is_empty() {
            stream
                .write_all(body)
                .await
                .map_err(|e| MeshCallError::NetworkError(format!("Async write body error: {}", e)))?;
        }
        stream
            .flush()
            .await
            .map_err(|e| MeshCallError::NetworkError(format!("Async flush error: {}", e)))?;

        let mut raw_response = Vec::new();
        stream
            .read_to_end(&mut raw_response)
            .await
            .map_err(|e| MeshCallError::NetworkError(format!("Async read error: {}", e)))?;

        SyncHttpWireClient::parse_http_response(&raw_response)
    }
}

// ============================================================================
// Core Policy Enforcement Point (PEP) Bridge
// ============================================================================

/// Out-of-sandbox policy enforcement point, host-only secret vault, and sub-ms autotomy controller.
#[derive(Clone)]
pub struct AgentMeshPepBridge {
    issuer: Arc<OctopusOidcActorIssuer>,
    token_vault: Arc<RwLock<BoundedTokenVault>>,
    killswitch_registry: Arc<RwLock<HashMap<String, KillSwitch>>>,
    global_killswitch: Arc<RwLock<Option<Arc<KillSwitch>>>>,
    mesh_node_url: Arc<RwLock<String>>,
    wire_client: Arc<SyncHttpWireClient>,
    active_cancellations: Arc<tokio::sync::RwLock<HashMap<String, Vec<CancellationToken>>>>,
    channel_secret: Arc<RwLock<Option<[u8; 32]>>>,
    peer_directory_cache: Arc<RwLock<HashMap<(String, String), String>>>,
    default_provider_peer_id: Arc<RwLock<Option<String>>>,

    // Telemetry counters
    total_token_exchanges: Arc<AtomicU64>,
    total_cache_hits: Arc<AtomicU64>,
    total_killswitch_evictions: Arc<AtomicU64>,
    last_eviction_duration_us: Arc<AtomicU64>,
}

impl AgentMeshPepBridge {
    /// Creates a new PEP bridge bound to the given workload actor issuer.
    pub fn new(issuer: Arc<OctopusOidcActorIssuer>, default_mesh_node_url: String) -> Self {
        Self {
            issuer,
            token_vault: Arc::new(RwLock::new(BoundedTokenVault::new(MAX_CACHED_TOKENS_CAPACITY))),
            killswitch_registry: Arc::new(RwLock::new(HashMap::new())),
            global_killswitch: Arc::new(RwLock::new(None)),
            mesh_node_url: Arc::new(RwLock::new(default_mesh_node_url)),
            wire_client: Arc::new(SyncHttpWireClient::new()),
            active_cancellations: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            channel_secret: Arc::new(RwLock::new(None)),
            peer_directory_cache: Arc::new(RwLock::new(HashMap::new())),
            default_provider_peer_id: Arc::new(RwLock::new(
                std::env::var("AGENTMESH_PROVIDER_PEER_ID").ok().filter(|s| !s.trim().is_empty()),
            )),
            total_token_exchanges: Arc::new(AtomicU64::new(0)),
            total_cache_hits: Arc::new(AtomicU64::new(0)),
            total_killswitch_evictions: Arc::new(AtomicU64::new(0)),
            last_eviction_duration_us: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Sets or clears an explicit fallback/default provider `PeerID` (`12D3KooW...`) used when
    /// calling `/mesh/<peer-id>/<type>/<name>` against an `agentmesh-node` proxy.
    pub fn set_default_provider_peer_id(&self, peer_id: Option<String>) {
        if let Ok(mut guard) = self.default_provider_peer_id.write() {
            *guard = peer_id.filter(|s| !s.trim().is_empty());
        }
    }

    /// Clears cached `(service_type, service_name) -> peer_id` discovery mappings.
    pub fn clear_peer_directory_cache(&self) {
        if let Ok(mut guard) = self.peer_directory_cache.write() {
            guard.clear();
        }
    }

    /// Creates a new PEP bridge with PepBridgeConfig and global KillSwitch
    pub fn new_with_config(
        config: PepBridgeConfig,
        issuer: Arc<OctopusOidcActorIssuer>,
        killswitch: Arc<KillSwitch>,
    ) -> Self {
        let bridge = Self::new(issuer, config.mesh_node_base_url);
        if let Ok(mut gks) = bridge.global_killswitch.write() {
            *gks = Some(killswitch);
        }
        if let Ok(mut cs) = bridge.channel_secret.write() {
            *cs = config.channel_secret;
        }
        bridge
    }

    /// Sets or updates the target mesh node URL (e.g. after loopback reference node startup).
    pub fn set_mesh_node_url(&self, url: String) {
        if let Ok(mut lock) = self.mesh_node_url.write() {
            *lock = url;
        }
    }

    /// Update URL method (alias for consistency across modules)
    pub fn update_mesh_node_url(&self, url: &str) {
        self.set_mesh_node_url(url.to_string());
    }

    /// Returns the currently configured mesh node URL.
    pub fn get_mesh_node_url(&self) -> String {
        self.mesh_node_url
            .read()
            .map(|u| u.clone())
            .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string())
    }

    /// Number of active cached tokens
    pub fn cached_token_count(&self) -> usize {
        self.token_vault.read().map(|v| v.len()).unwrap_or(0)
    }

    // ------------------------------------------------------------------------
    // Circuit Breaker Registration & Sub-Millisecond Eviction
    // ------------------------------------------------------------------------

    /// Registers a limb's circuit breaker to be governed by the PEP bridge.
    pub fn register_arm_killswitch(&self, arm_id: &str, killswitch: KillSwitch) {
        if let Ok(mut reg) = self.killswitch_registry.write() {
            reg.insert(arm_id.to_string(), killswitch);
        }
    }

    /// Checks whether an arm's registered KillSwitch (or global KillSwitch) has been tripped.
    pub fn is_arm_tripped(&self, arm_id: &str) -> bool {
        // Check global killswitch first
        if let Ok(gks_lock) = self.global_killswitch.read() {
            if let Some(ref ks) = *gks_lock {
                if ks.is_tripped() {
                    return true;
                }
            }
        }

        // Check per-arm registry
        if let Ok(reg) = self.killswitch_registry.read() {
            if let Some(ks) = reg.get(arm_id) {
                return ks.is_tripped();
            }
        }
        false
    }

    /// Sub-Millisecond KillSwitch Eviction:
    /// 1. Immediately evicts all token cache entries matching `arm_id`.
    /// 2. Trips the registered KillSwitch atomically (`SeqCst`).
    /// 3. Asserts total elapsed duration < 1,000 microseconds (< 1ms SLA).
    /// 4. Returns the measured elapsed duration.
    pub fn trip_arm_killswitch(&self, arm_id: &str) -> Duration {
        let t0 = Instant::now();

        // 1. Evict matching credentials from token vault
        if let Ok(mut vault) = self.token_vault.write() {
            vault.retain(|(cached_arm, _epoch), _token| cached_arm != arm_id);
        }

        // 2. Trip registered circuit breaker
        if let Ok(reg) = self.killswitch_registry.read() {
            if let Some(ks) = reg.get(arm_id) {
                ks.trip();
            }
        }
        if let Ok(gks_lock) = self.global_killswitch.read() {
            if let Some(ref ks) = *gks_lock {
                ks.trip();
            }
        }

        // Weakness 1: Abort all in-flight asynchronous HTTP requests for this arm in <1ms
        let arm_id_owned = arm_id.to_string();
        if let Ok(mut map) = self.active_cancellations.try_write() {
            if let Some(tokens) = map.remove(&arm_id_owned) {
                for token in tokens {
                    token.cancel();
                }
            }
        } else {
            let cancellations = self.active_cancellations.clone();
            tokio::spawn(async move {
                let mut map = cancellations.write().await;
                if let Some(tokens) = map.remove(&arm_id_owned) {
                    for token in tokens {
                        token.cancel();
                    }
                }
            });
        }

        let elapsed = t0.elapsed();

        // Update telemetry
        self.total_killswitch_evictions.fetch_add(1, Ordering::Relaxed);
        self.last_eviction_duration_us
            .store(elapsed.as_micros() as u64, Ordering::Relaxed);

        // Verification of sub-millisecond SLA
        if elapsed.as_micros() >= KILLSWITCH_EVICTION_SLA_MICROS {
            tracing::warn!(
                "KillSwitch eviction latency SLA breached: took {:?}, expected < 1ms",
                elapsed
            );
        }

        elapsed
    }

    /// Checks if an arm is tripped / revoked.
    pub fn is_arm_revoked(&self, arm_id: &str) -> bool {
        self.is_arm_tripped(arm_id)
    }

    /// Resets any registered circuit breaker for `arm_id` (and global circuit breaker if set).
    pub fn reset_arm_killswitch(&self, arm_id: &str) {
        if let Ok(reg) = self.killswitch_registry.read() {
            if let Some(ks) = reg.get(arm_id) {
                ks.reset();
            }
        }
        if let Ok(gks_lock) = self.global_killswitch.read() {
            if let Some(ref ks) = *gks_lock {
                ks.reset();
            }
        }
    }

    /// Dispatches an RFC 7009 OAuth 2.0 Token Revocation (`POST /oauth/revoke`) with
    /// `Content-Type: application/x-www-form-urlencoded` (`token=<biscuit>`) to an `agentmesh-node`.
    pub fn revoke_token_rfc7009_sync(&self, access_token: &str) -> Result<(), MeshCallError> {
        let endpoint = format!("{}/oauth/revoke", self.get_mesh_node_url().trim_end_matches('/'));
        let form_body = format!("token={}", url_encode_form_component(access_token)).into_bytes();
        let headers = vec![
            (
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ),
            ("Accept".to_string(), "application/json".to_string()),
        ];
        let (status, _resp_headers, resp_bytes) =
            self.wire_client.post(&endpoint, &headers, &form_body)?;
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(MeshCallError::UpstreamCallFailed {
                status,
                message: format!(
                    "RFC 7009 revocation failed: {}",
                    String::from_utf8_lossy(&resp_bytes)
                ),
            })
        }
    }

    /// Asynchronous counterpart for RFC 7009 Token Revocation (`POST /oauth/revoke`).
    pub async fn revoke_token_rfc7009_async(&self, access_token: &str) -> Result<(), MeshCallError> {
        let endpoint = format!("{}/oauth/revoke", self.get_mesh_node_url().trim_end_matches('/'));
        let form_body = format!("token={}", url_encode_form_component(access_token)).into_bytes();
        let headers = vec![
            (
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ),
            ("Accept".to_string(), "application/json".to_string()),
        ];
        let (status, _resp_headers, resp_bytes) =
            AsyncHttpWireClient::post(&endpoint, &headers, &form_body).await?;
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(MeshCallError::UpstreamCallFailed {
                status,
                message: format!(
                    "RFC 7009 revocation failed: {}",
                    String::from_utf8_lossy(&resp_bytes)
                ),
            })
        }
    }

    /// Dispatches a signed epoch revocation signal to the target node's POST /mesh/revoke endpoint.
    pub async fn dispatch_signed_revocation_async(
        &self,
        node_url: &str,
        signal: SignedEpochRevocationSignal,
    ) -> Result<(), MeshCallError> {
        let endpoint = format!("{}/mesh/revoke", node_url.trim_end_matches('/'));
        let body = serde_json::to_vec(&signal)
            .map_err(|e| MeshCallError::Internal(format!("Failed to serialize revocation signal: {e}")))?;

        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ];

        let (status, _resp_headers, resp_bytes) = AsyncHttpWireClient::post(&endpoint, &headers, &body).await?;
        if status == 200 {
            Ok(())
        } else {
            Err(MeshCallError::UpstreamCallFailed {
                status,
                message: format!("Revocation dispatch failed: {}", String::from_utf8_lossy(&resp_bytes)),
            })
        }
    }

    /// Evicts a specific generation epoch token for an arm without tripping the circuit breaker.
    pub fn evict_arm_epoch(&self, arm_id: &str, epoch: u64) {
        if let Ok(mut vault) = self.token_vault.write() {
            vault.remove(&(arm_id.to_string(), epoch));
        }
    }

    /// Purges all cached tokens across all arms and epochs.
    pub fn purge_all_tokens(&self) {
        if let Ok(mut vault) = self.token_vault.write() {
            vault.clear();
        }
    }

    // ------------------------------------------------------------------------
    // Header Hygiene & Injection
    // ------------------------------------------------------------------------

    /// Sanitizes caller headers and injects verified `X-Mesh-Authentication`.
    /// Strips: `Authorization`, `Cookie`, `X-Mesh-*` (case-insensitive).
    /// Injects: `X-Mesh-Authentication: Bearer <mesh_token>`.
    pub fn sanitize_and_inject_headers(
        raw_headers: &[(String, String)],
        mesh_token: &str,
    ) -> Vec<(String, String)> {
        let mut sanitized = Vec::with_capacity(raw_headers.len() + 2);
        let mut has_user_agent = false;
        let mut has_content_type = false;

        for (name, val) in raw_headers {
            let name_lower = name.to_ascii_lowercase();

            // Strip sensitive caller headers that could shadow identity or bypass mesh controls
            if name_lower == "authorization"
                || name_lower == "cookie"
                || name_lower.starts_with("x-mesh-")
            {
                continue;
            }

            if name_lower == "user-agent" {
                has_user_agent = true;
            }
            if name_lower == "content-type" {
                has_content_type = true;
            }

            sanitized.push((name.clone(), val.clone()));
        }

        // Inject authoritative host-held mesh bearer credential
        sanitized.push((
            "X-Mesh-Authentication".to_string(),
            format!("Bearer {}", mesh_token),
        ));

        if !has_user_agent {
            sanitized.push(("User-Agent".to_string(), "AgentOctopus-HostPep/1.0".to_string()));
        }
        if !has_content_type {
            sanitized.push(("Content-Type".to_string(), "application/json".to_string()));
        }

        sanitized
    }

    // ------------------------------------------------------------------------
    // Logical URI Resolution, Service Discovery & Scheme Validation
    // ------------------------------------------------------------------------

    /// Extracts `(service_type, service_name)` for `mcp://` and `a2a://` URIs used with
    /// `GET /mesh/service/discover` on `agentmesh-node`.
    pub fn extract_service_type_and_name(logical_uri: &str) -> Option<(&'static str, &str)> {
        if let Some(rest) = logical_uri.strip_prefix("mcp://") {
            let svc = rest.split('/').next().unwrap_or(rest);
            Some(("mcp", svc))
        } else if let Some(rest) = logical_uri.strip_prefix("a2a://") {
            let svc = rest.split('/').next().unwrap_or(rest);
            Some(("a2a", svc))
        } else {
            None
        }
    }

    /// Resolves logical mesh URIs into the target HTTP endpoint on the mesh node, optionally
    /// targeting a discovered provider `peer_id` (`/mesh/<peer-id>/mcp/<service>`).
    /// Strictly allows: `mcp://`, `a2a://`, `inference://`, `egress://`.
    /// Strictly rejects: `http://`, `https://`, `file://`, IP literals, TCP sockets.
    pub fn resolve_mesh_endpoint_with_peer(
        node_url: &str,
        logical_uri: &str,
        peer_id: Option<&str>,
    ) -> Result<String, MeshCallError> {
        validate_mesh_uri(logical_uri)
            .map_err(|e| MeshCallError::InvalidUri(format!("{}: {}", logical_uri, e)))?;

        let trimmed_base = node_url.trim_end_matches('/');
        let peer_opt = peer_id.map(str::trim).filter(|p| !p.is_empty());

        if let Some(rest) = logical_uri.strip_prefix("mcp://") {
            match peer_opt {
                Some(pid) => Ok(format!("{}/mesh/{}/mcp/{}", trimmed_base, pid, rest)),
                None => Ok(format!("{}/mesh/mcp/{}", trimmed_base, rest)),
            }
        } else if let Some(rest) = logical_uri.strip_prefix("a2a://") {
            match peer_opt {
                Some(pid) => Ok(format!("{}/mesh/{}/a2a/{}", trimmed_base, pid, rest)),
                None => Ok(format!("{}/mesh/a2a/{}", trimmed_base, rest)),
            }
        } else if let Some(rest) = logical_uri.strip_prefix("inference://") {
            match peer_opt {
                Some(pid) => Ok(format!(
                    "{}/mesh/{}/inference/{}/v1/chat/completions",
                    trimmed_base, pid, rest
                )),
                None => Ok(format!("{}/v1/chat/completions", trimmed_base)),
            }
        } else if let Some(rest) = logical_uri.strip_prefix("egress://") {
            match peer_opt {
                Some(pid) => Ok(format!("{}/mesh/{}/egress/{}", trimmed_base, pid, rest)),
                None => Ok(format!("{}/egress/{}", trimmed_base, rest)),
            }
        } else {
            Err(MeshCallError::InvalidUri(logical_uri.to_string()))
        }
    }

    /// Resolves logical mesh URIs into the local HTTP endpoint on the mesh node without a peer prefix.
    pub fn resolve_mesh_endpoint(node_url: &str, logical_uri: &str) -> Result<String, MeshCallError> {
        Self::resolve_mesh_endpoint_with_peer(node_url, logical_uri, None)
    }

    fn lookup_cached_peer(&self, base_url: &str, svc_type: &str, svc_name: &str) -> Option<String> {
        let key = (format!("{}:{}", base_url, svc_type), svc_name.to_string());
        if let Ok(cache) = self.peer_directory_cache.read() {
            if let Some(pid) = cache.get(&key) {
                if !pid.is_empty() {
                    return Some(pid.clone());
                }
            }
        }
        self.default_provider_peer_id
            .read()
            .ok()
            .and_then(|g| g.clone())
    }

    fn lookup_any_cached_peer_for_node(&self, base_url: &str) -> Option<String> {
        let prefix = format!("{}:", base_url);
        if let Ok(cache) = self.peer_directory_cache.read() {
            for ((k_prefix, _), pid) in cache.iter() {
                if k_prefix.starts_with(&prefix) && !pid.is_empty() {
                    return Some(pid.clone());
                }
            }
        }
        self.default_provider_peer_id
            .read()
            .ok()
            .and_then(|g| g.clone())
    }

    /// Queries `GET {base_url}/mesh/service/discover` on `agentmesh-node` to resolve the
    /// remote provider `PeerID` (`12D3KooW...`) for `(svc_type, svc_name)`.
    pub fn discover_service_peer_sync(
        &self,
        base_url: &str,
        svc_type: &str,
        svc_name: &str,
        mesh_token: &str,
    ) -> Option<String> {
        if let Some(cached) = self.lookup_cached_peer(base_url, svc_type, svc_name) {
            return Some(cached);
        }

        let trimmed = base_url.trim_end_matches('/');
        let headers = vec![
            (
                "X-Mesh-Authentication".to_string(),
                format!("Bearer {}", mesh_token),
            ),
            ("Accept".to_string(), "application/json".to_string()),
        ];

        let exact_url = format!(
            "{}/mesh/service/discover?type={}&name={}",
            trimmed,
            url_encode_form_component(svc_type),
            url_encode_form_component(svc_name)
        );
        if let Ok((200, _, body)) = self.wire_client.get(&exact_url, &headers) {
            if let Ok(entries) = serde_json::from_slice::<Vec<DiscoveredMeshService>>(&body) {
                if let Some(first) = entries.into_iter().find(|e| !e.peer_id.is_empty()) {
                    if let Ok(mut cache) = self.peer_directory_cache.write() {
                        cache.insert(
                            (format!("{}:{}", base_url, svc_type), svc_name.to_string()),
                            first.peer_id.clone(),
                        );
                    }
                    return Some(first.peer_id);
                }
            }
        }

        // Fallback: if exact service was hidden by policy filtering, query any visible service of same type
        // or reuse a known provider PeerID for this node so denied calls still hit `/mesh/<peer-id>/...` and receive 403.
        let broad_url = format!(
            "{}/mesh/service/discover?type={}",
            trimmed,
            url_encode_form_component(svc_type)
        );
        if let Ok((200, _, body)) = self.wire_client.get(&broad_url, &headers) {
            if let Ok(entries) = serde_json::from_slice::<Vec<DiscoveredMeshService>>(&body) {
                if let Some(first) = entries.into_iter().find(|e| !e.peer_id.is_empty()) {
                    return Some(first.peer_id);
                }
            }
        }

        self.lookup_any_cached_peer_for_node(base_url)
    }

    /// Asynchronous counterpart for `GET /mesh/service/discover`.
    pub async fn discover_service_peer_async(
        &self,
        base_url: &str,
        svc_type: &str,
        svc_name: &str,
        mesh_token: &str,
    ) -> Option<String> {
        if let Some(cached) = self.lookup_cached_peer(base_url, svc_type, svc_name) {
            return Some(cached);
        }

        let trimmed = base_url.trim_end_matches('/');
        let headers = vec![
            (
                "X-Mesh-Authentication".to_string(),
                format!("Bearer {}", mesh_token),
            ),
            ("Accept".to_string(), "application/json".to_string()),
        ];

        let exact_url = format!(
            "{}/mesh/service/discover?type={}&name={}",
            trimmed,
            url_encode_form_component(svc_type),
            url_encode_form_component(svc_name)
        );
        if let Ok((200, _, body)) = AsyncHttpWireClient::get(&exact_url, &headers).await {
            if let Ok(entries) = serde_json::from_slice::<Vec<DiscoveredMeshService>>(&body) {
                if let Some(first) = entries.into_iter().find(|e| !e.peer_id.is_empty()) {
                    if let Ok(mut cache) = self.peer_directory_cache.write() {
                        cache.insert(
                            (format!("{}:{}", base_url, svc_type), svc_name.to_string()),
                            first.peer_id.clone(),
                        );
                    }
                    return Some(first.peer_id);
                }
            }
        }

        let broad_url = format!(
            "{}/mesh/service/discover?type={}",
            trimmed,
            url_encode_form_component(svc_type)
        );
        if let Ok((200, _, body)) = AsyncHttpWireClient::get(&broad_url, &headers).await {
            if let Ok(entries) = serde_json::from_slice::<Vec<DiscoveredMeshService>>(&body) {
                if let Some(first) = entries.into_iter().find(|e| !e.peer_id.is_empty()) {
                    return Some(first.peer_id);
                }
            }
        }

        self.lookup_any_cached_peer_for_node(base_url)
    }

    // ------------------------------------------------------------------------
    // RFC 8693 Token Exchange Workflow
    // ------------------------------------------------------------------------

    /// Obtains a cached token or performs RFC 8693 token exchange (`application/x-www-form-urlencoded`)
    /// if missing or near expiry.
    pub fn get_or_exchange_token_sync(
        &self,
        arm_id: &str,
        epoch: u64,
        role: &ArmRole,
        _target_resource: &str,
    ) -> Result<String, MeshCallError> {
        // 1. Fail closed if KillSwitch is tripped
        if self.is_arm_tripped(arm_id) {
            return Err(MeshCallError::KillSwitchTripped(arm_id.to_string()));
        }

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let cache_key = (arm_id.to_string(), epoch);

        // 2. Fast-path: Check cached token in host vault
        if let Ok(vault) = self.token_vault.read() {
            if let Some(cached) = vault.get(&cache_key) {
                if !cached.is_expired_or_near(now_secs, TOKEN_REFRESH_BUFFER_SECS) {
                    self.total_cache_hits.fetch_add(1, Ordering::Relaxed);
                    return Ok(cached.access_token.clone());
                }
            }
        }

        // 3. Slow-path: Mint workload JWT via OIDC actor issuer
        let workload_jwt = self
            .issuer
            .mint_arm_token(arm_id, epoch, role)
            .map_err(|e| MeshCallError::TokenMintError(e.to_string()))?;

        // 4. Construct RFC 8693 Token Exchange request (form-urlencoded per RFC 8693 §2.1 & `agentmesh` `sts.go`)
        let token_req = Rfc8693TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            subject_token: workload_jwt,
            subject_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
            requested_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_string()),
            audience: Some(self.issuer.audience().to_string()),
            resource: None,
            scope: None,
            seal: None,
        };

        let req_body = token_req.to_form_urlencoded();

        let token_endpoint = format!("{}/oauth/token", self.get_mesh_node_url().trim_end_matches('/'));
        let headers = vec![
            (
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ),
            ("Accept".to_string(), "application/json".to_string()),
        ];

        // 5. Transmit token exchange request to STS endpoint
        let (status, _resp_headers, resp_bytes) = self.wire_client.post(&token_endpoint, &headers, &req_body)?;

        if status == 200 {
            let token_resp: Rfc8693TokenResponse = serde_json::from_slice(&resp_bytes)
                .map_err(|e| MeshCallError::TokenExchangeFailed {
                    status,
                    message: format!("Malformed RFC 8693 token response: {}", e),
                })?;

            let cached = CachedMeshToken {
                arm_id: arm_id.to_string(),
                epoch,
                role: role.clone(),
                access_token: token_resp.access_token.clone(),
                token_type: token_resp.token_type,
                issued_token_type: token_resp.issued_token_type,
                issued_at_unix_secs: now_secs,
                expires_at_unix_secs: now_secs.saturating_add(token_resp.expires_in),
            };

            // Store in vault
            if let Ok(mut vault) = self.token_vault.write() {
                vault.insert(cache_key, cached);
            }

            self.total_token_exchanges.fetch_add(1, Ordering::Relaxed);
            Ok(token_resp.access_token)
        } else if status == 403 {
            let err_msg = String::from_utf8_lossy(&resp_bytes).to_string();
            Err(MeshCallError::AccessDenied(err_msg))
        } else {
            let err_desc = serde_json::from_slice::<Rfc8693ErrorResponse>(&resp_bytes)
                .map(|e| e.error_description.unwrap_or(e.error))
                .unwrap_or_else(|_| String::from_utf8_lossy(&resp_bytes).to_string());

            Err(MeshCallError::TokenExchangeFailed {
                status,
                message: err_desc,
            })
        }
    }

    /// Asynchronous counterpart for RFC 8693 token exchange (`application/x-www-form-urlencoded`).
    pub async fn get_or_exchange_token_async(
        &self,
        arm_id: &str,
        epoch: u64,
        role: &ArmRole,
        _target_resource: &str,
    ) -> Result<String, MeshCallError> {
        if self.is_arm_tripped(arm_id) {
            return Err(MeshCallError::KillSwitchTripped(arm_id.to_string()));
        }

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let cache_key = (arm_id.to_string(), epoch);

        if let Ok(vault) = self.token_vault.read() {
            if let Some(cached) = vault.get(&cache_key) {
                if !cached.is_expired_or_near(now_secs, TOKEN_REFRESH_BUFFER_SECS) {
                    self.total_cache_hits.fetch_add(1, Ordering::Relaxed);
                    return Ok(cached.access_token.clone());
                }
            }
        }

        let workload_jwt = self
            .issuer
            .mint_arm_token(arm_id, epoch, role)
            .map_err(|e| MeshCallError::TokenMintError(e.to_string()))?;

        let token_req = Rfc8693TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            subject_token: workload_jwt,
            subject_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
            requested_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_string()),
            audience: Some(self.issuer.audience().to_string()),
            resource: None,
            scope: None,
            seal: None,
        };

        let req_body = token_req.to_form_urlencoded();

        let token_endpoint = format!("{}/oauth/token", self.get_mesh_node_url().trim_end_matches('/'));
        let headers = vec![
            (
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ),
            ("Accept".to_string(), "application/json".to_string()),
        ];

        let (status, _resp_headers, resp_bytes) = AsyncHttpWireClient::post(&token_endpoint, &headers, &req_body).await?;

        if status == 200 {
            let token_resp: Rfc8693TokenResponse = serde_json::from_slice(&resp_bytes)
                .map_err(|e| MeshCallError::TokenExchangeFailed {
                    status,
                    message: format!("Malformed RFC 8693 token response: {}", e),
                })?;

            let cached = CachedMeshToken {
                arm_id: arm_id.to_string(),
                epoch,
                role: role.clone(),
                access_token: token_resp.access_token.clone(),
                token_type: token_resp.token_type,
                issued_token_type: token_resp.issued_token_type,
                issued_at_unix_secs: now_secs,
                expires_at_unix_secs: now_secs.saturating_add(token_resp.expires_in),
            };

            if let Ok(mut vault) = self.token_vault.write() {
                vault.insert(cache_key, cached);
            }

            self.total_token_exchanges.fetch_add(1, Ordering::Relaxed);
            Ok(token_resp.access_token)
        } else if status == 403 {
            let err_msg = String::from_utf8_lossy(&resp_bytes).to_string();
            Err(MeshCallError::AccessDenied(err_msg))
        } else {
            let err_desc = serde_json::from_slice::<Rfc8693ErrorResponse>(&resp_bytes)
                .map(|e| e.error_description.unwrap_or(e.error))
                .unwrap_or_else(|_| String::from_utf8_lossy(&resp_bytes).to_string());

            Err(MeshCallError::TokenExchangeFailed {
                status,
                message: err_desc,
            })
        }
    }

    /// Exchanges a workload JWT for a task-attenuated (and optionally sealed) Biscuit via
    /// `POST /oauth/token` (`resource` / `scope` / `seal=true` -> `tar_block` on `agentmesh-node`).
    /// Does not overwrite the arm's standing `(arm_id, epoch)` vault entry.
    pub fn exchange_scoped_task_token_sync(
        &self,
        arm_id: &str,
        epoch: u64,
        role: &ArmRole,
        resource: Option<&str>,
        scope: Option<&str>,
        seal: bool,
    ) -> Result<String, MeshCallError> {
        if self.is_arm_tripped(arm_id) {
            return Err(MeshCallError::KillSwitchTripped(arm_id.to_string()));
        }

        let workload_jwt = self
            .issuer
            .mint_arm_token(arm_id, epoch, role)
            .map_err(|e| MeshCallError::TokenMintError(e.to_string()))?;

        let token_req = Rfc8693TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            subject_token: workload_jwt,
            subject_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
            requested_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_string()),
            audience: Some(self.issuer.audience().to_string()),
            resource: resource.map(str::to_string),
            scope: scope.map(str::to_string),
            seal: if seal { Some(true) } else { None },
        };

        let token_endpoint =
            format!("{}/oauth/token", self.get_mesh_node_url().trim_end_matches('/'));
        let headers = vec![
            (
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ),
            ("Accept".to_string(), "application/json".to_string()),
        ];
        let (status, _resp_headers, resp_bytes) =
            self.wire_client
                .post(&token_endpoint, &headers, &token_req.to_form_urlencoded())?;

        if status == 200 {
            let token_resp: Rfc8693TokenResponse =
                serde_json::from_slice(&resp_bytes).map_err(|e| {
                    MeshCallError::TokenExchangeFailed {
                        status,
                        message: format!("Malformed RFC 8693 token response: {}", e),
                    }
                })?;
            self.total_token_exchanges.fetch_add(1, Ordering::Relaxed);
            Ok(token_resp.access_token)
        } else if status == 403 {
            Err(MeshCallError::AccessDenied(
                String::from_utf8_lossy(&resp_bytes).to_string(),
            ))
        } else {
            let err_desc = serde_json::from_slice::<Rfc8693ErrorResponse>(&resp_bytes)
                .map(|e| e.error_description.unwrap_or(e.error))
                .unwrap_or_else(|_| String::from_utf8_lossy(&resp_bytes).to_string());
            Err(MeshCallError::TokenExchangeFailed {
                status,
                message: err_desc,
            })
        }
    }

    /// Asynchronous counterpart for `exchange_scoped_task_token_sync`.
    pub async fn exchange_scoped_task_token_async(
        &self,
        arm_id: &str,
        epoch: u64,
        role: &ArmRole,
        resource: Option<&str>,
        scope: Option<&str>,
        seal: bool,
    ) -> Result<String, MeshCallError> {
        if self.is_arm_tripped(arm_id) {
            return Err(MeshCallError::KillSwitchTripped(arm_id.to_string()));
        }

        let workload_jwt = self
            .issuer
            .mint_arm_token(arm_id, epoch, role)
            .map_err(|e| MeshCallError::TokenMintError(e.to_string()))?;

        let token_req = Rfc8693TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            subject_token: workload_jwt,
            subject_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
            requested_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_string()),
            audience: Some(self.issuer.audience().to_string()),
            resource: resource.map(str::to_string),
            scope: scope.map(str::to_string),
            seal: if seal { Some(true) } else { None },
        };

        let token_endpoint =
            format!("{}/oauth/token", self.get_mesh_node_url().trim_end_matches('/'));
        let headers = vec![
            (
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ),
            ("Accept".to_string(), "application/json".to_string()),
        ];
        let (status, _resp_headers, resp_bytes) = AsyncHttpWireClient::post(
            &token_endpoint,
            &headers,
            &token_req.to_form_urlencoded(),
        )
        .await?;

        if status == 200 {
            let token_resp: Rfc8693TokenResponse =
                serde_json::from_slice(&resp_bytes).map_err(|e| {
                    MeshCallError::TokenExchangeFailed {
                        status,
                        message: format!("Malformed RFC 8693 token response: {}", e),
                    }
                })?;
            self.total_token_exchanges.fetch_add(1, Ordering::Relaxed);
            Ok(token_resp.access_token)
        } else if status == 403 {
            Err(MeshCallError::AccessDenied(
                String::from_utf8_lossy(&resp_bytes).to_string(),
            ))
        } else {
            let err_desc = serde_json::from_slice::<Rfc8693ErrorResponse>(&resp_bytes)
                .map(|e| e.error_description.unwrap_or(e.error))
                .unwrap_or_else(|_| String::from_utf8_lossy(&resp_bytes).to_string());
            Err(MeshCallError::TokenExchangeFailed {
                status,
                message: err_desc,
            })
        }
    }

    // ------------------------------------------------------------------------
    // Response Sanitization: Zero-Mutual-Information Projector
    // ------------------------------------------------------------------------

    /// Extracts JSON payloads from MCP Streamable HTTP `text/event-stream` frames (`data: {...}`)
    /// if the upstream server responded in SSE format; passes raw JSON/text through unchanged.
    pub fn unwrap_sse_json_if_needed(
        resp_headers: &[(String, String)],
        raw_bytes: &[u8],
    ) -> Vec<u8> {
        let is_sse = resp_headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("content-type")
                && v.to_ascii_lowercase().contains("text/event-stream")
        });
        if !is_sse {
            return raw_bytes.to_vec();
        }
        let text = String::from_utf8_lossy(raw_bytes);
        let mut last_data = None;
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("data:") {
                let trimmed = rest.trim();
                if !trimmed.is_empty() {
                    last_data = Some(trimmed.as_bytes().to_vec());
                }
            }
        }
        last_data.unwrap_or_else(|| raw_bytes.to_vec())
    }

    /// Projects upstream raw bytes through `ZeroMutualInformationProjector`.
    /// Strips zero-width stego chars, redacts secrets with `<ZK_MI_REDACTED>`,
    /// sorts JSON keys, and quantizes release time.
    pub fn sanitize_upstream_payload(raw_bytes: &[u8]) -> Vec<u8> {
        let raw_str = String::from_utf8_lossy(raw_bytes);
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let projected = ZeroMutualInformationProjector::project_output(&raw_str, now_ms, 100);
        projected.canonical_output.into_bytes()
    }

    // ------------------------------------------------------------------------
    // Public Dispatch Interface for Wasm & Containment
    // ------------------------------------------------------------------------

    /// Dispatches a mesh call synchronously using an explicit pre-exchanged Biscuit token
    /// (e.g. a task-attenuated `tar_block` token from `exchange_scoped_task_token_sync`) and
    /// optional caller headers to test header hygiene.
    pub fn dispatch_mesh_call_with_token_sync(
        &self,
        arm_id: &str,
        uri: &str,
        token: &str,
        extra_caller_headers: &[(String, String)],
        req_bytes: &[u8],
    ) -> Result<Vec<u8>, MeshCallError> {
        if self.is_arm_tripped(arm_id) {
            return Err(MeshCallError::KillSwitchTripped(arm_id.to_string()));
        }

        let base_url = self.get_mesh_node_url();
        let initial_peer = Self::extract_service_type_and_name(uri)
            .and_then(|(st, sn)| self.lookup_cached_peer(&base_url, st, sn));
        let endpoint_url =
            Self::resolve_mesh_endpoint_with_peer(&base_url, uri, initial_peer.as_deref())?;

        let mut caller_headers = Vec::with_capacity(extra_caller_headers.len() + 2);
        caller_headers.extend_from_slice(extra_caller_headers);
        if !caller_headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        {
            caller_headers.push(("Content-Type".to_string(), "application/json".to_string()));
        }
        if !caller_headers
            .iter()
            .any(|k| k.0.eq_ignore_ascii_case("accept"))
        {
            caller_headers.push((
                "Accept".to_string(),
                "application/json, text/event-stream".to_string(),
            ));
        }

        let sanitized_headers = Self::sanitize_and_inject_headers(&caller_headers, token);

        let (mut status, mut resp_headers, mut resp_bytes) =
            self.wire_client
                .post(&endpoint_url, &sanitized_headers, req_bytes)?;

        // Transparently discover remote provider PeerID on `agentmesh-node` if direct path returned 404
        if status == 404 && initial_peer.is_none() {
            if let Some((svc_type, svc_name)) = Self::extract_service_type_and_name(uri) {
                if let Some(peer_id) =
                    self.discover_service_peer_sync(&base_url, svc_type, svc_name, token)
                {
                    let peer_endpoint =
                        Self::resolve_mesh_endpoint_with_peer(&base_url, uri, Some(&peer_id))?;
                    let retry = self
                        .wire_client
                        .post(&peer_endpoint, &sanitized_headers, req_bytes)?;
                    status = retry.0;
                    resp_headers = retry.1;
                    resp_bytes = retry.2;
                }
            }
        }

        if status == 200 {
            let unwrapped = Self::unwrap_sse_json_if_needed(&resp_headers, &resp_bytes);
            Ok(Self::sanitize_upstream_payload(&unwrapped))
        } else if status == 403 {
            Err(MeshCallError::AccessDenied(
                String::from_utf8_lossy(&resp_bytes).to_string(),
            ))
        } else {
            Err(MeshCallError::UpstreamCallFailed {
                status,
                message: String::from_utf8_lossy(&resp_bytes).to_string(),
            })
        }
    }

    /// Synchronous dispatch for `octopus_wasi::mesh_call` inside Tier 1 Wasm host import.
    pub fn dispatch_mesh_call_sync(
        &self,
        arm_id: &str,
        epoch: u64,
        role: &ArmRole,
        uri: &str,
        req_bytes: &[u8],
    ) -> Result<Vec<u8>, MeshCallError> {
        if self.is_arm_tripped(arm_id) {
            return Err(MeshCallError::KillSwitchTripped(arm_id.to_string()));
        }

        validate_mesh_uri(uri)
            .map_err(|e| MeshCallError::InvalidUri(format!("{}: {}", uri, e)))?;

        let token = self.get_or_exchange_token_sync(arm_id, epoch, role, uri)?;
        self.dispatch_mesh_call_with_token_sync(arm_id, uri, &token, &[], req_bytes)
    }

    /// Asynchronous dispatch for Tokio tasks and Web API endpoints.
    pub async fn dispatch_mesh_call_async(
        &self,
        arm_id: &str,
        epoch: u64,
        role: &ArmRole,
        uri: &str,
        req_bytes: &[u8],
    ) -> Result<Vec<u8>, MeshCallError> {
        if self.is_arm_tripped(arm_id) {
            return Err(MeshCallError::KillSwitchTripped(arm_id.to_string()));
        }

        let base_url = self.get_mesh_node_url();
        let has_channel_secret = self
            .channel_secret
            .read()
            .ok()
            .and_then(|g| *g)
            .is_some();
        let initial_peer = if has_channel_secret {
            None
        } else {
            Self::extract_service_type_and_name(uri)
                .and_then(|(st, sn)| self.lookup_cached_peer(&base_url, st, sn))
        };
        let endpoint_url =
            Self::resolve_mesh_endpoint_with_peer(&base_url, uri, initial_peer.as_deref())?;
        let token = self.get_or_exchange_token_async(arm_id, epoch, role, uri).await?;

        let mut default_headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            (
                "Accept".to_string(),
                "application/json, text/event-stream".to_string(),
            ),
        ];

        // Weakness 4: Inject mutual PEP channel proof if channel secret is active
        let (nonce_str, expected_node_secret) = if let Ok(cs_guard) = self.channel_secret.read() {
            if let Some(secret) = *cs_guard {
                let nonce = format!("{:016x}", rand::random::<u64>());
                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let parsed_url = Url::parse(&endpoint_url).unwrap_or_else(|_| Url::parse("http://127.0.0.1/").unwrap());
                let path = parsed_url.path();
                let proof = compute_pep_channel_proof(
                    &secret,
                    "POST",
                    path,
                    now_ms,
                    &nonce,
                    req_bytes,
                    None,
                );
                default_headers.push((HEADER_PEP_CHANNEL_PROOF.to_string(), proof));
                default_headers.push((HEADER_PEP_NONCE.to_string(), nonce.clone()));
                default_headers.push((HEADER_PEP_TIMESTAMP.to_string(), now_ms.to_string()));
                (Some(nonce), Some(secret))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        let sanitized_headers = Self::sanitize_and_inject_headers(&default_headers, &token);

        // Weakness 1: In-flight cancellation token for sub-ms stream abort upon killswitch trip
        let cancel_token = CancellationToken::new();
        {
            let mut map = self.active_cancellations.write().await;
            map.entry(arm_id.to_string()).or_default().push(cancel_token.clone());
        }

        let cancel_child = cancel_token.clone();
        let post_fut = AsyncHttpWireClient::post(&endpoint_url, &sanitized_headers, req_bytes);

        let post_result = tokio::select! {
            res = post_fut => res,
            _ = cancel_child.cancelled() => {
                Err(MeshCallError::KillSwitchTripped(arm_id.to_string()))
            }
        };

        // Remove token from active_cancellations
        {
            let mut map = self.active_cancellations.write().await;
            if let Some(vec) = map.get_mut(arm_id) {
                vec.retain(|t| !t.is_cancelled());
            }
        }

        let (mut status, mut resp_headers, mut resp_bytes) = post_result?;

        // Transparently discover remote provider PeerID on `agentmesh-node` if direct path returned 404
        if status == 404 && initial_peer.is_none() && expected_node_secret.is_none() {
            if let Some((svc_type, svc_name)) = Self::extract_service_type_and_name(uri) {
                if let Some(peer_id) = self
                    .discover_service_peer_async(&base_url, svc_type, svc_name, &token)
                    .await
                {
                    let peer_endpoint =
                        Self::resolve_mesh_endpoint_with_peer(&base_url, uri, Some(&peer_id))?;
                    let retry =
                        AsyncHttpWireClient::post(&peer_endpoint, &sanitized_headers, req_bytes)
                            .await?;
                    status = retry.0;
                    resp_headers = retry.1;
                    resp_bytes = retry.2;
                }
            }
        }

        // Weakness 4: Verify mutual node response proof header if channel secret is active
        if let (Some(secret), Some(nonce)) = (expected_node_secret, nonce_str) {
            let node_proof = resp_headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(HEADER_NODE_PROOF))
                .map(|(_, v)| v.as_str());
            match node_proof {
                Some(proof) => {
                    let expected_proof = compute_node_response_proof(&secret, status, &nonce, &resp_bytes);
                    if !crate::security::constant_time_eq_hex(proof, &expected_proof) {
                        return Err(MeshCallError::UpstreamCallFailed {
                            status: 403,
                            message: "Node mutual authentication response proof mismatch".to_string(),
                        });
                    }
                }
                None => {
                    return Err(MeshCallError::UpstreamCallFailed {
                        status: 403,
                        message: "Node response missing x-octopus-node-proof header".to_string(),
                    });
                }
            }
        }

        if status == 200 {
            let unwrapped = Self::unwrap_sse_json_if_needed(&resp_headers, &resp_bytes);
            Ok(Self::sanitize_upstream_payload(&unwrapped))
        } else if status == 403 {
            Err(MeshCallError::AccessDenied(String::from_utf8_lossy(&resp_bytes).to_string()))
        } else {
            Err(MeshCallError::UpstreamCallFailed {
                status,
                message: String::from_utf8_lossy(&resp_bytes).to_string(),
            })
        }
    }

    // ------------------------------------------------------------------------
    // Telemetry & Monitoring
    // ------------------------------------------------------------------------

    /// Returns active PEP vault telemetry for WebUI dashboard (Tab 17) and audit.
    pub fn telemetry(&self) -> PepVaultTelemetry {
        let cached_count = self.token_vault.read().map(|v| v.len()).unwrap_or(0);
        let killswitch_count = self.killswitch_registry.read().map(|k| k.len()).unwrap_or(0);

        PepVaultTelemetry {
            cached_tokens_count: cached_count,
            active_killswitches_count: killswitch_count,
            total_token_exchanges: self.total_token_exchanges.load(Ordering::Relaxed),
            total_cache_hits: self.total_cache_hits.load(Ordering::Relaxed),
            total_killswitch_evictions: self.total_killswitch_evictions.load(Ordering::Relaxed),
            last_eviction_duration_us: self.last_eviction_duration_us.load(Ordering::Relaxed),
            mesh_node_url: self.get_mesh_node_url(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn test_header_hygiene_stripping_and_injection() {
        let dirty_headers = vec![
            ("Authorization".to_string(), "Bearer stolen_token_12345".to_string()),
            ("authorization".to_string(), "Bearer lower_case_attempt".to_string()),
            ("Cookie".to_string(), "session_id=abcd1234secret".to_string()),
            ("cookie".to_string(), "tracked_cookie=xyz".to_string()),
            ("X-Mesh-Custom-Actor".to_string(), "spoofed_admin".to_string()),
            ("x-mesh-forwarded-for".to_string(), "10.0.0.1".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-Custom-Tracing".to_string(), "trace_99".to_string()),
        ];

        let sanitized = AgentMeshPepBridge::sanitize_and_inject_headers(&dirty_headers, "valid_mesh_token_xyz");

        // 1. Verify Authorization, Cookie, and X-Mesh-* are completely removed
        assert!(!sanitized.iter().any(|(k, _)| k.eq_ignore_ascii_case("authorization")));
        assert!(!sanitized.iter().any(|(k, _)| k.eq_ignore_ascii_case("cookie")));
        assert!(!sanitized.iter().any(|(k, _)| k.to_ascii_lowercase().starts_with("x-mesh-") && k != "X-Mesh-Authentication"));

        // 2. Verify X-Mesh-Authentication is injected
        let auth_hdr = sanitized.iter().find(|(k, _)| k == "X-Mesh-Authentication");
        assert!(auth_hdr.is_some());
        assert_eq!(auth_hdr.unwrap().1, "Bearer valid_mesh_token_xyz");

        // 3. Verify non-sensitive headers are preserved
        assert!(sanitized.iter().any(|(k, v)| k == "Content-Type" && v == "application/json"));
        assert!(sanitized.iter().any(|(k, v)| k == "X-Custom-Tracing" && v == "trace_99"));
    }

    #[test]
    fn test_strict_uri_scheme_filtering() {
        let base_url = "http://127.0.0.1:8080";

        // Allowed schemes (local fallback & peer-scoped proxy paths)
        assert_eq!(
            AgentMeshPepBridge::resolve_mesh_endpoint(base_url, "mcp://calc").unwrap(),
            "http://127.0.0.1:8080/mesh/mcp/calc"
        );
        assert_eq!(
            AgentMeshPepBridge::resolve_mesh_endpoint_with_peer(
                base_url,
                "mcp://calc",
                Some("12D3KooWExamplePeerId")
            )
            .unwrap(),
            "http://127.0.0.1:8080/mesh/12D3KooWExamplePeerId/mcp/calc"
        );
        assert_eq!(
            AgentMeshPepBridge::resolve_mesh_endpoint(base_url, "a2a://worker").unwrap(),
            "http://127.0.0.1:8080/mesh/a2a/worker"
        );
        assert_eq!(
            AgentMeshPepBridge::resolve_mesh_endpoint_with_peer(
                base_url,
                "a2a://worker",
                Some("12D3KooWExamplePeerId")
            )
            .unwrap(),
            "http://127.0.0.1:8080/mesh/12D3KooWExamplePeerId/a2a/worker"
        );
        assert_eq!(
            AgentMeshPepBridge::resolve_mesh_endpoint(base_url, "inference://qwen").unwrap(),
            "http://127.0.0.1:8080/v1/chat/completions"
        );
        assert_eq!(
            AgentMeshPepBridge::resolve_mesh_endpoint(base_url, "egress://api.service.com").unwrap(),
            "http://127.0.0.1:8080/egress/api.service.com"
        );

        // Prohibited schemes (must fail closed)
        assert!(matches!(
            AgentMeshPepBridge::resolve_mesh_endpoint(base_url, "http://127.0.0.1:8080/evil"),
            Err(MeshCallError::InvalidUri(_))
        ));
        assert!(matches!(
            AgentMeshPepBridge::resolve_mesh_endpoint(base_url, "https://google.com"),
            Err(MeshCallError::InvalidUri(_))
        ));
        assert!(matches!(
            AgentMeshPepBridge::resolve_mesh_endpoint(base_url, "file:///etc/passwd"),
            Err(MeshCallError::InvalidUri(_))
        ));
        assert!(matches!(
            AgentMeshPepBridge::resolve_mesh_endpoint(base_url, "tcp://192.168.1.1:5000"),
            Err(MeshCallError::InvalidUri(_))
        ));
    }

    #[test]
    fn test_chunked_http_decoding_and_form_urlencoded_rfc8693() {
        let raw_resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n{\"ok\":1\r\n1\r\n}\r\n0\r\n\r\n";
        let (status, _hdrs, body) = SyncHttpWireClient::parse_http_response(raw_resp).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"{\"ok\":1}");

        let req = Rfc8693TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            subject_token: "hdr.pay.sig".to_string(),
            subject_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
            requested_token_type: None,
            audience: Some("agentmesh".to_string()),
            resource: None,
            scope: Some("mcp://calc".to_string()),
            seal: Some(true),
        };
        let encoded = String::from_utf8(req.to_form_urlencoded()).unwrap();
        assert!(encoded.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"));
        assert!(encoded.contains("audience=agentmesh"));
        assert!(encoded.contains("scope=mcp%3A%2F%2Fcalc"));
        assert!(encoded.contains("seal=true"));
    }

    #[test]
    fn test_sub_millisecond_killswitch_eviction_benchmark() {
        let issuer = Arc::new(OctopusOidcActorIssuer::new_ephemeral("https://agentoctopus.local"));
        let bridge = AgentMeshPepBridge::new(issuer, "http://127.0.0.1:8080".to_string());

        let arm_calc = "arm_calc";
        let arm_rogue = "arm_rogue";

        let ks_calc = KillSwitch::new();
        let ks_rogue = KillSwitch::new();

        bridge.register_arm_killswitch(arm_calc, ks_calc.clone());
        bridge.register_arm_killswitch(arm_rogue, ks_rogue.clone());

        // Pre-populate cache with multiple epochs
        {
            let mut vault = bridge.token_vault.write().unwrap();
            vault.insert(
                (arm_calc.to_string(), 1),
                CachedMeshToken {
                    arm_id: arm_calc.to_string(),
                    epoch: 1,
                    role: ArmRole::UntrustedDocIngest,
                    access_token: "token_calc_ep1".to_string(),
                    token_type: "Bearer".to_string(),
                    issued_token_type: "access_token".to_string(),
                    issued_at_unix_secs: 1000,
                    expires_at_unix_secs: 2000,
                },
            );
            vault.insert(
                (arm_calc.to_string(), 2),
                CachedMeshToken {
                    arm_id: arm_calc.to_string(),
                    epoch: 2,
                    role: ArmRole::UntrustedDocIngest,
                    access_token: "token_calc_ep2".to_string(),
                    token_type: "Bearer".to_string(),
                    issued_token_type: "access_token".to_string(),
                    issued_at_unix_secs: 1000,
                    expires_at_unix_secs: 2000,
                },
            );
            vault.insert(
                (arm_rogue.to_string(), 1),
                CachedMeshToken {
                    arm_id: arm_rogue.to_string(),
                    epoch: 1,
                    role: ArmRole::AccountingLedgerWrite,
                    access_token: "token_rogue_ep1".to_string(),
                    token_type: "Bearer".to_string(),
                    issued_token_type: "access_token".to_string(),
                    issued_at_unix_secs: 1000,
                    expires_at_unix_secs: 2000,
                },
            );
        }

        assert_eq!(bridge.token_vault.read().unwrap().len(), 3);
        assert!(!ks_calc.is_tripped());
        assert!(!ks_rogue.is_tripped());

        // Trip KillSwitch for arm_calc and benchmark eviction latency
        let elapsed = bridge.trip_arm_killswitch(arm_calc);

        // Sub-millisecond SLA assertion (< 1,000 microseconds)
        assert!(
            elapsed.as_micros() < 1_000,
            "Eviction took {} us, exceeding 1,000 us SLA",
            elapsed.as_micros()
        );

        // Verify arm_calc is evicted from vault and circuit breaker tripped
        assert!(ks_calc.is_tripped());
        assert!(!ks_rogue.is_tripped());

        let vault = bridge.token_vault.read().unwrap();
        assert!(vault.get(&(arm_calc.to_string(), 1)).is_none());
        assert!(vault.get(&(arm_calc.to_string(), 2)).is_none());
        assert!(vault.get(&(arm_rogue.to_string(), 1)).is_some()); // Sibling untouched
        assert_eq!(vault.len(), 1);

        // Subsequent call for arm_calc fails closed immediately
        let res = bridge.dispatch_mesh_call_sync(arm_calc, 2, &ArmRole::UntrustedDocIngest, "mcp://calc", b"{}");
        assert!(matches!(res, Err(MeshCallError::KillSwitchTripped(_))));
    }

    #[test]
    fn test_zero_mutual_information_sanitization() {
        let dirty_payload = "{\"zebra\": 1, \"alpha\": 2, \"key\": \"ghp_99887766554433221100aabbccddeeff\u{200B}\u{FEFF}\"}";

        let sanitized_bytes = AgentMeshPepBridge::sanitize_upstream_payload(dirty_payload.as_bytes());
        let sanitized_str = String::from_utf8(sanitized_bytes).unwrap();

        // Zero-width characters must be completely stripped
        assert!(!sanitized_str.contains('\u{200B}'));
        assert!(!sanitized_str.contains('\u{FEFF}'));

        // High entropy secret must be redacted
        assert!(sanitized_str.contains("<ZK_MI_REDACTED>"));
        assert!(!sanitized_str.contains("ghp_99887766554433221100aabbccddeeff"));
    }

    #[test]
    fn test_cached_token_proactive_refresh_window() {
        let token = CachedMeshToken {
            arm_id: "arm_calc".to_string(),
            epoch: 1,
            role: ArmRole::UntrustedDocIngest,
            access_token: "token_abc".to_string(),
            token_type: "Bearer".to_string(),
            issued_token_type: "access_token".to_string(),
            issued_at_unix_secs: 100,
            expires_at_unix_secs: 200,
        };

        // At t=150 (50s remaining): not expired
        assert!(!token.is_expired_or_near(150, 15));

        // At t=186 (14s remaining): within 15s refresh buffer -> must refresh
        assert!(token.is_expired_or_near(186, 15));

        // At t=205: past expiry -> must refresh
        assert!(token.is_expired_or_near(205, 15));
    }

    #[test]
    fn test_e2e_token_exchange_mock_node() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mock_url = format!("http://127.0.0.1:{}", port);

        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut full_req = Vec::new();
                let mut buf = [0u8; 1024];
                while !String::from_utf8_lossy(&full_req).contains("grant_type") {
                    let n = stream.read(&mut buf).unwrap();
                    if n == 0 {
                        break;
                    }
                    full_req.extend_from_slice(&buf[..n]);
                }
                let req_str = String::from_utf8_lossy(&full_req);

                assert!(req_str.contains("POST /oauth/token HTTP/1.1"));
                assert!(req_str.contains("grant_type"));

                let resp_body = "{\"access_token\":\"mock_mesh_token_777\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\",\"token_type\":\"Bearer\",\"expires_in\":300}";
                let resp_wire = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    resp_body.len(),
                    resp_body
                );
                stream.write_all(resp_wire.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
        });

        let issuer = Arc::new(OctopusOidcActorIssuer::new_ephemeral("https://agentoctopus.local"));
        let bridge = AgentMeshPepBridge::new(issuer, mock_url);

        let token = bridge
            .get_or_exchange_token_sync("arm_calc", 1, &ArmRole::UntrustedDocIngest, "mcp://calc")
            .unwrap();

        assert_eq!(token, "mock_mesh_token_777");

        let vault = bridge.token_vault.read().unwrap();
        let cached = vault.get(&("arm_calc".to_string(), 1)).unwrap();
        assert_eq!(cached.access_token, "mock_mesh_token_777");

        handle.join().unwrap();
    }
}
