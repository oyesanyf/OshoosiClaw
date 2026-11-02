//! Host-Mediated Capability Gate (`crates/osoosi-sandbox/src/host_capability_gate.rs`).
//!
//! Enforces:
//! 1. Strict Domain Allowlisting (`export.arxiv.org`, `arxiv.org`, `api.github.com`, and conditional `127.0.0.1:11434`).
//! 2. Mathematical IPv4/IPv6 SSRF & DNS Rebinding Protection via `SocketAddr` pinning.
//! 3. Boundary Secret Injection outside guest linear memory.

use crate::native_host::build_ssrf_safe_http_client;
use dashmap::DashSet;
use hmac::{Hmac, Mac};
use osoosi_types::cage::RoutingSeal;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{compiler_fence, Ordering};
use std::sync::{Arc, RwLock};
use subtle::ConstantTimeEq;
use tracing::info;

type HmacSha256 = Hmac<Sha256>;

/// Default substrate HMAC-SHA256 secret key for CAGE routing seals.
pub const DEFAULT_CAGE_SUBSTRATE_SECRET: &[u8] =
    b"oshoosiclaw_cage_governance_secret_2026_test_key";

/// In-memory secret buffer that zeroes its backing heap allocation via volatile writes
/// whenever a grant is revoked or dropped (`Drop`).
#[derive(Clone)]
pub struct ZeroizingLockedSecret {
    bytes: Arc<Vec<u8>>,
}

impl ZeroizingLockedSecret {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            bytes: Arc::new(secret.to_vec()),
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for ZeroizingLockedSecret {
    fn drop(&mut self) {
        if let Some(vec_mut) = Arc::get_mut(&mut self.bytes) {
            for b in vec_mut.iter_mut() {
                unsafe { std::ptr::write_volatile(b, 0) };
            }
            compiler_fence(Ordering::SeqCst);
        }
    }
}

/// Hardened sealed grant binding an OS environment variable stand-in token
/// to allowed binary hash, optional entrypoint script hash, pinned upstream host,
/// and volatile zeroizing secret.
#[derive(Clone)]
pub struct HardenedSealedGrant {
    pub env_var_name: String,
    pub standin_token: String,
    pub allowed_binary_sha256: [u8; 32],
    pub allowed_script_sha256: Option<[u8; 32]>,
    pub pinned_upstream_host: String,
    pub secret: ZeroizingLockedSecret,
}

impl HardenedSealedGrant {
    pub fn new(
        env_var_name: impl Into<String>,
        standin_token: impl Into<String>,
        allowed_binary_sha256: [u8; 32],
        allowed_script_sha256: Option<[u8; 32]>,
        pinned_upstream_host: impl Into<String>,
        secret: ZeroizingLockedSecret,
    ) -> Self {
        Self {
            env_var_name: env_var_name.into(),
            standin_token: standin_token.into(),
            allowed_binary_sha256,
            allowed_script_sha256,
            pinned_upstream_host: pinned_upstream_host.into(),
            secret,
        }
    }
}

/// Provider trait for swapping synthetic stand-in tokens with actual secrets on the host.
pub trait SecretSwapProvider: Send + Sync {
    fn verify_and_swap_outbound(
        &self,
        caller_pid: u32,
        upstream_host: &str,
        http_payload: &[u8],
    ) -> Result<Vec<u8>, String>;
}

/// Execution receipt issued upon successful validation and atomic single-use consumption of a routing seal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealConsumptionReceipt {
    pub status: String,
    pub seal_id: String,
    pub action_name: String,
    pub consumed_at_utc: u64,
    pub ttl_remaining_seconds: u64,
}

/// Errors returned by the host capability gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateError {
    DomainDenied(String),
    SsrfBlocked(String),
    DnsRebindingBlocked(String),
    CredentialDenied(String),
    NetworkError(String),
    Timeout,
    SealRequired(String),
    SealRejection(String),
}

impl std::fmt::Display for GateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateError::DomainDenied(msg) => write!(f, "Domain Denied: {}", msg),
            GateError::SsrfBlocked(msg) => write!(f, "SSRF Blocked: {}", msg),
            GateError::DnsRebindingBlocked(msg) => write!(f, "DNS Rebinding Blocked: {}", msg),
            GateError::CredentialDenied(msg) => write!(f, "Credential Denied: {}", msg),
            GateError::NetworkError(msg) => write!(f, "Network Error: {}", msg),
            GateError::Timeout => write!(f, "Request Timed Out"),
            GateError::SealRequired(msg) => {
                write!(f, "Routing Seal Required (NoDirectBind): {}", msg)
            }
            GateError::SealRejection(msg) => write!(f, "Routing Seal Rejected: {}", msg),
        }
    }
}

impl std::error::Error for GateError {}

/// Host-mediated capability gate controlling network access and secret boundaries for Wasm guests.
#[derive(Clone)]
pub struct HostCapabilityGate {
    grants: Arc<RwLock<HashMap<String, HardenedSealedGrant>>>,
    custom_swap_provider: Option<Arc<dyn SecretSwapProvider>>,
    ollama_bridge_enabled: bool,
    caller_pid: u32,
    consumed_seals: Arc<DashSet<String>>,
    substrate_secret: Vec<u8>,
}

impl Default for HostCapabilityGate {
    fn default() -> Self {
        Self::new(false, std::process::id())
    }
}

impl HostCapabilityGate {
    pub fn new(ollama_bridge_enabled: bool, caller_pid: u32) -> Self {
        Self {
            grants: Arc::new(RwLock::new(HashMap::new())),
            custom_swap_provider: None,
            ollama_bridge_enabled,
            caller_pid,
            consumed_seals: Arc::new(DashSet::new()),
            substrate_secret: DEFAULT_CAGE_SUBSTRATE_SECRET.to_vec(),
        }
    }

    /// Attaches an external secret swap provider (such as ReaVoterEnvGateway).
    pub fn with_secret_provider(mut self, provider: Arc<dyn SecretSwapProvider>) -> Self {
        self.custom_swap_provider = Some(provider);
        self
    }

    /// Configures the substrate secret key used to verify HMAC-SHA256 routing seal signatures.
    pub fn with_substrate_secret(mut self, secret: &[u8]) -> Self {
        self.substrate_secret = secret.to_vec();
        self
    }

    /// Checks whether a routing seal with the specified ID has already been consumed.
    pub fn is_seal_consumed(&self, seal_id: &str) -> bool {
        self.consumed_seals.contains(seal_id)
    }

    /// Returns the total count of consumed routing seals.
    pub fn consumed_seals_count(&self) -> usize {
        self.consumed_seals.len()
    }

    /// Validates format, single-use nonce, TTL expiration, action digest binding, and HMAC signature,
    /// then atomically consumes the routing seal in the thread-safe nonce set.
    ///
    /// Implements CAGE `NoDirectBind`: execution fails closed immediately if the seal is invalid or replayed.
    pub fn validate_and_consume_seal(
        &self,
        seal: &RoutingSeal,
        expected_action_name: &str,
        expected_params: &serde_json::Value,
        current_time_utc: Option<u64>,
    ) -> Result<SealConsumptionReceipt, GateError> {
        let seal_id = &seal.seal_id;
        if seal_id.is_empty() {
            return Err(GateError::SealRejection("Missing seal_id".to_string()));
        }

        // 1. Single-use replay check (preliminary check)
        if self.consumed_seals.contains(seal_id) {
            return Err(GateError::SealRejection(format!(
                "Replay detected: routing seal '{}' has already been consumed",
                seal_id
            )));
        }

        // 2. TTL Expiration check
        let now = current_time_utc.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });
        if now > seal.expires_at {
            return Err(GateError::SealRejection(format!(
                "Routing seal expired: current {} > expires {}",
                now, seal.expires_at
            )));
        }

        // 3. Action Digest Match (canonical RFC 8785 JSON digest)
        let expected_digest = compute_action_digest(expected_action_name, expected_params);
        if seal.action_digest != expected_digest {
            return Err(GateError::SealRejection(format!(
                "Action digest mismatch: seal bound to {}, expected {}",
                seal.action_digest, expected_digest
            )));
        }

        // 4. Cryptographic HMAC-SHA256 Signature Verification (constant-time)
        let expected_sig = sign_routing_seal(
            &self.substrate_secret,
            seal_id,
            &seal.action_digest,
            &seal.policy_version_id,
            seal.issued_at,
        );

        let is_valid = if seal.signature.len() == expected_sig.len() {
            seal.signature
                .as_bytes()
                .ct_eq(expected_sig.as_bytes())
                .into()
        } else {
            false
        };

        if !is_valid {
            return Err(GateError::SealRejection(
                "Cryptographic HMAC signature invalid".to_string(),
            ));
        }

        // 5. Atomic single-use consumption registration (prevents concurrent double-spend race condition)
        if !self.consumed_seals.insert(seal_id.clone()) {
            return Err(GateError::SealRejection(format!(
                "Replay detected: routing seal '{}' has already been consumed",
                seal_id
            )));
        }

        Ok(SealConsumptionReceipt {
            status: "CONSUMED".to_string(),
            seal_id: seal_id.clone(),
            action_name: expected_action_name.to_string(),
            consumed_at_utc: now,
            ttl_remaining_seconds: seal.expires_at.saturating_sub(now),
        })
    }

    /// Registers a sealed grant directly with the capability gate.
    pub fn register_grant(&self, grant: HardenedSealedGrant) {
        let mut lock = self.grants.write().unwrap_or_else(|p| p.into_inner());
        lock.insert(grant.standin_token.clone(), grant);
    }

    /// Canonical Domain Allowlist Verification.
    /// Strictly permits:
    /// - `export.arxiv.org`
    /// - `arxiv.org`
    /// - `api.github.com`
    /// - `127.0.0.1:11434` (ONLY IF `ollama_bridge_enabled == true`)
    pub fn verify_domain_allowlist(&self, host: &str, port: u16) -> Result<(), GateError> {
        let normalized_host = host.trim().to_ascii_lowercase();
        let stripped_host = normalized_host.trim_end_matches('.');

        // Special handling for local Ollama bridge
        if (stripped_host == "127.0.0.1" || stripped_host == "localhost") && port == 11434 {
            if self.ollama_bridge_enabled {
                return Ok(());
            } else {
                return Err(GateError::DomainDenied(
                    "Local Ollama inference bridge is disabled".to_string(),
                ));
            }
        }

        match stripped_host {
            "export.arxiv.org" | "arxiv.org" | "api.github.com" => Ok(()),
            other => Err(GateError::DomainDenied(format!(
                "Host '{}' is not in the authoritative research allowlist",
                other
            ))),
        }
    }

    /// Internal helper to swap standin tokens with real secrets.
    fn swap_secret(&self, host: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
        if let Some(ref provider) = self.custom_swap_provider {
            return provider.verify_and_swap_outbound(self.caller_pid, host, payload);
        }

        let grants = self.grants.read().unwrap_or_else(|p| p.into_inner());
        for (standin, grant) in grants.iter() {
            let token_bytes = standin.as_bytes();
            if let Some(pos) = find_subslice(payload, token_bytes) {
                let normalized_host = normalize_host_gate(host);
                let pinned_host = normalize_host_gate(&grant.pinned_upstream_host);
                if normalized_host != pinned_host {
                    return Err(format!(
                        "Confused-deputy host mismatch: target '{}' vs pinned grant '{}'",
                        normalized_host, pinned_host
                    ));
                }

                let mut out = Vec::with_capacity(
                    payload.len() - token_bytes.len() + grant.secret.as_slice().len(),
                );
                out.extend_from_slice(&payload[..pos]);
                out.extend_from_slice(grant.secret.as_slice());
                out.extend_from_slice(&payload[pos + token_bytes.len()..]);
                return Ok(out);
            }
        }

        Err("No registered stand-in token matched".to_string())
    }

    /// Dispatches an outbound HTTP request through the host-mediated capability gate.
    ///
    /// Sequence:
    /// 1. Parse and validate URL scheme (https only, except http for local Ollama).
    /// 2. Enforce strict domain allowlist.
    /// 3. Verify DNS resolution and enforce mathematical SSRF blocking with SocketAddr pinning.
    /// 4. Boundary secret injection: swap `OSHOOSI_STANDIN_*` tokens strictly inside host memory.
    /// 5. Scrub sensitive response headers before returning bytes to the caller.
    pub async fn dispatch_request(
        &self,
        method: &str,
        url_str: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), GateError> {
        let parsed_url = reqwest::Url::parse(url_str)
            .map_err(|e| GateError::DomainDenied(format!("Malformed URL '{}': {}", url_str, e)))?;

        let host = parsed_url
            .host_str()
            .ok_or_else(|| GateError::DomainDenied("Missing host in URL".to_string()))?;
        let port = parsed_url.port_or_known_default().unwrap_or(443);

        // 1. Strict Domain Allowlist
        self.verify_domain_allowlist(host, port)?;

        // 2. Scheme check
        let is_local_ollama = (host == "127.0.0.1" || host == "localhost") && port == 11434;
        if parsed_url.scheme() == "http" && !is_local_ollama {
            return Err(GateError::DomainDenied(
                "Insecure HTTP scheme rejected for external hosts (HTTPS required)".to_string(),
            ));
        }

        // 3. Client initialization
        let client = if is_local_ollama {
            if !self.ollama_bridge_enabled {
                return Err(GateError::DomainDenied(
                    "Local Ollama inference bridge is disabled".to_string(),
                ));
            }
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|e| GateError::NetworkError(e.to_string()))?
        } else {
            // SSRF & DNS Pinning via build_ssrf_safe_http_client
            let (c, pinned_socket) =
                build_ssrf_safe_http_client(url_str)
                    .await
                    .map_err(|e| match e {
                        osoosi_types::OctopusSecurityError::SsrfBlocked(msg) => {
                            if msg.contains("DNS REBINDING") {
                                GateError::DnsRebindingBlocked(msg)
                            } else {
                                GateError::SsrfBlocked(msg)
                            }
                        }
                        other => GateError::NetworkError(other.to_string()),
                    })?;

            info!(
                "HostCapabilityGate: outbound fetch '{}' pinned to '{}'",
                url_str, pinned_socket
            );
            c
        };

        // 4. Boundary Secret Injection
        let mut request_builder = match method.to_ascii_uppercase().as_str() {
            "GET" => client.get(url_str),
            "POST" => client.post(url_str),
            "HEAD" => client.head(url_str),
            other => {
                return Err(GateError::NetworkError(format!(
                    "Unsupported HTTP method '{}'",
                    other
                )))
            }
        };

        for (k, v) in headers {
            if v.contains("OSHOOSI_STANDIN_") {
                let swapped = self.swap_secret(host, v.as_bytes()).map_err(|e| {
                    GateError::CredentialDenied(format!(
                        "Boundary secret swap failed for header '{}': {}",
                        k, e
                    ))
                })?;
                let swapped_str = String::from_utf8(swapped).map_err(|_| {
                    GateError::CredentialDenied("Non-UTF8 secret byte representation".to_string())
                })?;
                request_builder = request_builder.header(k, swapped_str);
            } else {
                request_builder = request_builder.header(k, v);
            }
        }

        if let Some(payload) = body {
            if payload.windows(16).any(|w| w == b"OSHOOSI_STANDIN_") {
                let swapped_body = self.swap_secret(host, payload).map_err(|e| {
                    GateError::CredentialDenied(format!(
                        "Boundary secret swap failed in payload: {}",
                        e
                    ))
                })?;
                request_builder = request_builder.body(swapped_body);
            } else {
                request_builder = request_builder.body(payload.to_vec());
            }
        }

        // 5. Execute Request
        let resp = request_builder
            .send()
            .await
            .map_err(|e| GateError::NetworkError(e.to_string()))?;

        let status = resp.status().as_u16();
        let mut resp_headers = Vec::new();
        for (k, v) in resp.headers() {
            let key = k.as_str().to_string();
            // Scrub sensitive response headers to prevent echo back into guest
            if key.eq_ignore_ascii_case("set-cookie")
                || key.eq_ignore_ascii_case("authorization")
                || key.eq_ignore_ascii_case("proxy-authorization")
            {
                continue;
            }
            if let Ok(val) = v.to_str() {
                resp_headers.push((key, val.to_string()));
            }
        }

        let resp_body = resp
            .bytes()
            .await
            .map_err(|e| GateError::NetworkError(e.to_string()))?
            .to_vec();

        Ok((status, resp_headers, resp_body))
    }

    /// Dispatches an outbound request mediated by a mandatory CAGE cryptographic routing seal.
    ///
    /// Enforces the foundational CAGE `NoDirectBind` invariant:
    /// - If `seal` is None, fails closed immediately with [`GateError::SealRequired`].
    /// - Validates and atomically consumes the single-use routing seal.
    /// - Proceeds with host-mediated capability dispatch only after authentic receipt issuance.
    #[allow(clippy::too_many_arguments)]
    pub async fn dispatch_request_with_seal(
        &self,
        method: &str,
        url_str: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
        seal: Option<&RoutingSeal>,
        expected_action: &str,
        expected_params: &serde_json::Value,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), GateError> {
        let seal = seal.ok_or_else(|| {
            GateError::SealRequired(
                "NoDirectBind violation: unsealed execution rejected".to_string(),
            )
        })?;

        self.validate_and_consume_seal(seal, expected_action, expected_params, None)?;
        self.dispatch_request(method, url_str, headers, body).await
    }
}

/// Canonicalizes a JSON value into RFC 8785 JSON Canonicalization Scheme (JCS) representation.
///
/// Invariants enforced:
/// 1. Object keys sorted lexicographically by UTF-16 code units (RFC 8785 §3.2.3).
/// 2. Minimal string escaping (only `"`, `\`, and control characters `\u0000`..`\u001f`, `/` is unescaped).
/// 3. ECMAScript-compliant canonical number serialization.
/// 4. No whitespace between structural tokens.
pub fn canonicalize_jcs(val: &serde_json::Value) -> Result<String, String> {
    let mut out = String::with_capacity(128);
    write_jcs_value(val, &mut out)?;
    Ok(out)
}

fn write_jcs_value(val: &serde_json::Value, out: &mut String) -> Result<(), String> {
    match val {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        serde_json::Value::Number(n) => {
            write_jcs_number(n, out);
        }
        serde_json::Value::String(s) => {
            write_jcs_string(s, out);
        }
        serde_json::Value::Array(arr) => {
            out.push('[');
            for (i, elem) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_jcs_value(elem, out)?;
            }
            out.push(']');
        }
        serde_json::Value::Object(map) => {
            out.push('{');
            let mut entries: Vec<(&String, &serde_json::Value)> = map.iter().collect();
            // RFC 8785 §3.2.3: Object keys MUST be sorted lexicographically by UTF-16 code units.
            entries.sort_by(|(k1, _), (k2, _)| {
                let u1 = k1.encode_utf16();
                let u2 = k2.encode_utf16();
                u1.cmp(u2)
            });
            for (i, (key, value)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_jcs_string(key, out);
                out.push(':');
                write_jcs_value(value, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_jcs_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{000c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) <= 0x1F => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_jcs_number(n: &serde_json::Number, out: &mut String) {
    if let Some(i) = n.as_i64() {
        out.push_str(&i.to_string());
    } else if let Some(u) = n.as_u64() {
        out.push_str(&u.to_string());
    } else if let Some(f) = n.as_f64() {
        if f == 0.0 {
            out.push('0');
        } else if f.is_finite() {
            if f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0 {
                out.push_str(&(f as i64).to_string());
            } else {
                let s = f.to_string();
                let s_clean = if let Some(idx) = s.find("e+") {
                    let mut res = s[..idx].to_string();
                    res.push('e');
                    res.push_str(&s[idx + 2..]);
                    res
                } else {
                    s
                };
                out.push_str(&s_clean);
            }
        } else {
            out.push_str("null");
        }
    }
}

/// Computes the deterministic 64-character lowercase hex SHA-256 action digest binding action name and canonical parameters.
pub fn compute_action_digest(action_name: &str, params: &serde_json::Value) -> String {
    let canonical_params = canonicalize_jcs(params).unwrap_or_else(|_| params.to_string());
    let mut hasher = Sha256::new();
    hasher.update(action_name.as_bytes());
    hasher.update(b":");
    hasher.update(canonical_params.as_bytes());
    hex::encode(hasher.finalize())
}

/// Computes HMAC-SHA256 signature binding seal attributes against the substrate secret key.
pub fn sign_routing_seal(
    secret_key: &[u8],
    seal_id: &str,
    action_digest: &str,
    policy_version_id: &str,
    issued_at: u64,
) -> String {
    let payload = format!(
        "{}|{}|{}|{}",
        seal_id, action_digest, policy_version_id, issued_at
    );
    let mut mac = HmacSha256::new_from_slice(secret_key)
        .expect("HMAC initialization must succeed with any key length");
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn normalize_host_gate(host: &str) -> String {
    let trimmed = host.trim().to_ascii_lowercase();
    trimmed
        .strip_suffix(":443")
        .unwrap_or(&trimmed)
        .trim_end_matches('.')
        .to_string()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}
