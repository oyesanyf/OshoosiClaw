//! Mathematical IPv4/IPv6 SSRF Normalization, CIS 3.3 Range Checks, and DNS Pinning (Finding 6).
//!
//! Provides defense-in-depth against DNS rebinding and SSRF bypasses:
//! 1. [`is_non_standard_ip_host_encoding`]: Detects decimal integer, hex, octal, and shortened quad encodings.
//! 2. [`is_restricted_rebinding_ip`]: Complete mathematical classification of restricted IPv4/IPv6 ranges (CIS 3.3).
//! 3. [`validate_agent_egress_url`]: HTTPS-only transport, credential stripping, trailing-dot normalization, and domain allowlists.
//! 4. [`resolve_and_pin`]: OS DNS resolution pinning returning [`PinnedEgress`] with `--resolve` formatting.

use std::collections::BTreeMap;
use std::net::{IpAddr, ToSocketAddrs};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use url::Url;

/// Information returned when outbound egress is blocked by the DLP Lineage Tracker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressLineageBlockInfo {
    pub policy: String,
    pub classification: String,
    pub reason: String,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
}

impl std::fmt::Display for EgressLineageBlockInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "policy={}, classification={}, reason={}",
            self.policy, self.classification, self.reason
        )
    }
}

/// Synthetic child span emitted when outbound egress is blocked (Finding: zero-PII OpenTelemetry attributes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyntheticBlockedSpan {
    pub name: String,
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub status: String, // "ERROR"
    pub action: String, // "BLOCKED"
    pub policy: String,
    pub classification: String,
    pub timestamp_utc: String,
    pub attributes: BTreeMap<String, String>,
}

pub type LineageEgressHook = Box<
    dyn Fn(Option<&str>, Option<&str>, Option<&str>) -> Result<(), EgressLineageBlockInfo>
        + Send
        + Sync,
>;

pub static LINEAGE_EGRESS_HOOK: parking_lot::RwLock<Option<LineageEgressHook>> =
    parking_lot::RwLock::new(None);

pub static RECENT_BLOCKED_SPANS: parking_lot::RwLock<Vec<SyntheticBlockedSpan>> =
    parking_lot::RwLock::new(Vec::new());

/// Registers the callback providing synchronous inline egress blocking from `DlpLineageTracker`.
pub fn register_lineage_egress_hook<F>(hook: F)
where
    F: Fn(Option<&str>, Option<&str>, Option<&str>) -> Result<(), EgressLineageBlockInfo>
        + Send
        + Sync
        + 'static,
{
    *LINEAGE_EGRESS_HOOK.write() = Some(Box::new(hook));
}

/// Helper: returns all recorded synthetic blocked spans (for tests and forensics).
pub fn get_recent_blocked_spans() -> Vec<SyntheticBlockedSpan> {
    RECENT_BLOCKED_SPANS.read().clone()
}

/// Helper: clears recent blocked spans.
pub fn clear_recent_blocked_spans() {
    RECENT_BLOCKED_SPANS.write().clear();
}

/// Records and logs a synthetic blocked child span with status ERROR and zero-PII attributes.
pub fn emit_synthetic_blocked_span(
    url: Option<&str>,
    file_path: Option<&str>,
    hash: Option<&str>,
    block_info: &EgressLineageBlockInfo,
) -> SyntheticBlockedSpan {
    let now = Utc::now().to_rfc3339();
    let trace_id = block_info
        .trace_id
        .clone()
        .unwrap_or_else(|| format!("{:032x}", rand::random::<u128>()));
    let span_id = format!("{:016x}", rand::random::<u64>());
    let parent_span_id = block_info.span_id.clone();

    let mut attrs = BTreeMap::new();
    attrs.insert("dlp.action".to_string(), "BLOCKED".to_string());
    attrs.insert("dlp.policy".to_string(), block_info.policy.clone());
    attrs.insert("dlp.classification".to_string(), block_info.classification.clone());
    attrs.insert("otel.status_code".to_string(), "ERROR".to_string());
    attrs.insert("otel.status_description".to_string(), block_info.reason.clone());
    attrs.insert("error.type".to_string(), "DLP_EGRESS_BLOCKED".to_string());

    if let Some(u) = url {
        // Strip any credentials to preserve zero-PII invariant
        let sanitized = sanitize_url_zero_pii_egress(u);
        attrs.insert("url.full".to_string(), sanitized);
    }
    if let Some(fp) = file_path {
        attrs.insert("file.path".to_string(), fp.to_string());
    }
    if let Some(h) = hash {
        attrs.insert("file.hash.sha256".to_string(), h.to_string());
    }

    let span = SyntheticBlockedSpan {
        name: "dlp.inline_egress_block".to_string(),
        trace_id,
        span_id,
        parent_span_id,
        status: "ERROR".to_string(),
        action: "BLOCKED".to_string(),
        policy: block_info.policy.clone(),
        classification: block_info.classification.clone(),
        timestamp_utc: now,
        attributes: attrs,
    };

    tracing::error!(
        status = "ERROR",
        dlp_action = "BLOCKED",
        policy = %span.policy,
        classification = %span.classification,
        trace_id = %span.trace_id,
        span_id = %span.span_id,
        "Synchronous inline egress blocked by DLP Lineage"
    );

    let mut lock = RECENT_BLOCKED_SPANS.write();
    if lock.len() >= 1000 {
        lock.remove(0);
    }
    lock.push(span.clone());

    span
}

fn sanitize_url_zero_pii_egress(u: &str) -> String {
    if let Some(idx) = u.find("://") {
        let scheme = &u[..idx + 3];
        let rest = &u[idx + 3..];
        if let Some(at_idx) = rest.find('@') {
            if let Some(slash_idx) = rest.find('/') {
                if at_idx < slash_idx {
                    return format!("{}{}", scheme, &rest[at_idx + 1..]);
                }
            } else {
                return format!("{}{}", scheme, &rest[at_idx + 1..]);
            }
        }
    }
    u.to_string()
}

/// Flexible conversion trait allowing `&url`, `&str`, `Option<&str>`, `String`, etc.
pub trait IntoEgressTarget {
    fn as_target_str(&self) -> Option<&str>;
}

impl IntoEgressTarget for &str {
    fn as_target_str(&self) -> Option<&str> {
        if self.is_empty() { None } else { Some(self) }
    }
}

impl IntoEgressTarget for &&str {
    fn as_target_str(&self) -> Option<&str> {
        if self.is_empty() { None } else { Some(*self) }
    }
}

impl IntoEgressTarget for String {
    fn as_target_str(&self) -> Option<&str> {
        if self.is_empty() { None } else { Some(self.as_str()) }
    }
}

impl IntoEgressTarget for &String {
    fn as_target_str(&self) -> Option<&str> {
        if self.is_empty() { None } else { Some(self.as_str()) }
    }
}

impl IntoEgressTarget for Option<&str> {
    fn as_target_str(&self) -> Option<&str> {
        *self
    }
}

impl IntoEgressTarget for &Option<&str> {
    fn as_target_str(&self) -> Option<&str> {
        **self
    }
}

impl IntoEgressTarget for Option<String> {
    fn as_target_str(&self) -> Option<&str> {
        self.as_deref()
    }
}

impl IntoEgressTarget for &Option<String> {
    fn as_target_str(&self) -> Option<&str> {
        self.as_deref()
    }
}

impl IntoEgressTarget for () {
    fn as_target_str(&self) -> Option<&str> {
        None
    }
}

/// Global lineage tracker proxy executing synchronous in-memory egress evaluation in nanoseconds.
#[derive(Debug, Clone, Copy, Default)]
pub struct EgressLineageTrackerProxy;

impl EgressLineageTrackerProxy {
    /// Queries the global lineage tracker in nanoseconds for URL, file path, and content hash taint.
    /// If tainted with `Quarantine` or `CrownJewel`, blocks immediately.
    #[inline]
    pub fn check_egress_allowed_full<U, F, H>(
        &self,
        url: U,
        file_path: F,
        hash: H,
    ) -> Result<(), EgressLineageBlockInfo>
    where
        U: IntoEgressTarget,
        F: IntoEgressTarget,
        H: IntoEgressTarget,
    {
        let u = url.as_target_str();
        let fp = file_path.as_target_str();
        let h = hash.as_target_str();

        if let Some(ref hook) = *LINEAGE_EGRESS_HOOK.read() {
            hook(u, fp, h)
        } else {
            Ok(())
        }
    }
}

/// Returns the global lineage tracker accessor for egress proxy checks.
#[inline]
pub fn global_lineage_tracker() -> EgressLineageTrackerProxy {
    EgressLineageTrackerProxy
}

/// Convenience standalone function checking outbound egress against the DLP Lineage Tracker.
pub fn check_egress_allowed_inline<U, F, H>(
    url: U,
    file_path: F,
    hash: H,
) -> Result<(), String>
where
    U: IntoEgressTarget,
    F: IntoEgressTarget,
    H: IntoEgressTarget,
{
    let u_str = url.as_target_str();
    let fp_str = file_path.as_target_str();
    let h_str = hash.as_target_str();

    let check_res = global_lineage_tracker().check_egress_allowed_full(u_str, fp_str, h_str);
    if let Err(block_info) = check_res {
        let is_blocked = block_info.policy.eq_ignore_ascii_case("QUARANTINE")
            || block_info.policy.eq_ignore_ascii_case("BLOCK")
            || block_info.classification.eq_ignore_ascii_case("CROWN_JEWEL");
        if is_blocked {
            emit_synthetic_blocked_span(u_str, fp_str, h_str, &block_info);
            return Err(format!(
                "DLP_EGRESS_BLOCKED: Egress blocked by DLP Lineage (policy={}, classification={}): {}",
                block_info.policy, block_info.classification, block_info.reason
            ));
        }
    }
    Ok(())
}

/// Mathematical IPv4/IPv6 SSRF & DNS Rebinding Range Classifier.
///
/// CIS Benchmark 3.3: Detects non-standard IP host encodings (decimal integer `2130706433`,
/// hex `0x7f000001`, octal `0177.0.0.1`, shortened dotted-quad `127.1`) before URL canonicalization.
pub fn is_non_standard_ip_host_encoding(host: &str) -> bool {
    if host.is_empty() || host.starts_with('[') {
        return false;
    }
    if !host.contains('.') {
        if host.chars().all(|c| c.is_ascii_digit()) {
            return true;
        }
        if let Some(hex_part) = host.strip_prefix("0x") {
            if !hex_part.is_empty() && hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
                return true;
            }
        }
        return false;
    }
    let parts: Vec<&str> = host.split('.').collect();
    let all_numeric_or_hex = parts.iter().all(|part| {
        if part.is_empty() {
            return false;
        }
        if let Some(hex_part) = part.strip_prefix("0x") {
            !hex_part.is_empty() && hex_part.chars().all(|c| c.is_ascii_hexdigit())
        } else {
            part.chars().all(|c| c.is_ascii_digit())
        }
    });
    if !all_numeric_or_hex {
        return false;
    }
    if parts.len() != 4 {
        return true;
    }
    for part in parts {
        if part.starts_with("0x") || (part.len() > 1 && part.starts_with('0')) {
            return true;
        }
    }
    false
}

/// Evaluates parsed `IpAddr` literals to block:
/// - RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
/// - Loopback (`127.0.0.0/8`, `::1`)
/// - Link-local / Cloud Metadata (`169.254.0.0/16`, `fe80::/10`)
/// - CGNAT (`100.64.0.0/10`)
/// - Unique Local IPv6 (`fc00::/7`)
/// - Unspecified (`0.0.0.0`, `::`), Broadcast, Multicast, Documentation
/// - Benchmarking (`198.18.0.0/15`), Class E (`240.0.0.0/4`), IETF protocol (`192.0.0.0/24`)
/// - IPv4-mapped IPv6 (`::ffff:0:0/96`), IPv4-compatible (`::0:0/96`)
/// - NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`), 6to4 (`2002::/16`), Teredo (`2001::`)
pub fn is_restricted_rebinding_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            let is_this_net = o[0] == 0; // 0.0.0.0/8
            let is_cgnat = o[0] == 100 && (o[1] & 0b1100_0000) == 64; // 100.64.0.0/10
            let is_metadata = o[0] == 169 && o[1] == 254; // 169.254.0.0/16
            let is_benchmarking = o[0] == 198 && (o[1] & 0xfe) == 18; // 198.18.0.0/15
            let is_reserved_class_e = (o[0] & 0xf0) == 240; // 240.0.0.0/4
            let is_ietf_protocol = o[0] == 192 && o[1] == 0 && o[2] == 0; // 192.0.0.0/24
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || is_this_net
                || is_cgnat
                || is_metadata
                || is_benchmarking
                || is_reserved_class_e
                || is_ietf_protocol
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            let seg = v6.segments();
            let is_unique_local = (o[0] & 0xfe) == 0xfc; // fc00::/7
            let is_link_local_v6 = o[0] == 0xfe && (o[1] & 0xc0) == 0x80; // fe80::/10
            let is_nat64 = (seg[0] == 0x0064
                && seg[1] == 0xff9b
                && seg[2] == 0
                && seg[3] == 0
                && seg[4] == 0
                && seg[5] == 0)
                || (seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 1);
            let is_6to4 = seg[0] == 0x2002;
            let is_teredo_or_doc_or_discard = (seg[0] == 0x2001
                && (seg[1] == 0x0000 || seg[1] == 0x0db8))
                || (seg[0] == 0x0100 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0);
            // RFC 2765 SIIT IPv4-translated prefix ::ffff:0:0/96
            if seg[0] == 0
                && seg[1] == 0
                && seg[2] == 0
                && seg[3] == 0
                && seg[4] == 0xffff
                && seg[5] == 0
            {
                let embedded_v4 = std::net::Ipv4Addr::new(
                    (seg[6] >> 8) as u8,
                    (seg[6] & 0xff) as u8,
                    (seg[7] >> 8) as u8,
                    (seg[7] & 0xff) as u8,
                );
                if is_restricted_rebinding_ip(&IpAddr::V4(embedded_v4)) {
                    return true;
                }
            }
            if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                if is_restricted_rebinding_ip(&IpAddr::V4(mapped_v4)) {
                    return true;
                }
            }
            if let Some(compat_v4) = v6.to_ipv4() {
                if !v6.is_loopback() && is_restricted_rebinding_ip(&IpAddr::V4(compat_v4)) {
                    return true;
                }
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || is_unique_local
                || is_link_local_v6
                || is_nat64
                || is_6to4
                || is_teredo_or_doc_or_discard
        }
    }
}

/// Validates an outbound agent URL against HTTPS-only transport, credential stripping,
/// bracketed IPv6 & mathematical IPv4/IPv6 SSRF ranges, and explicit domain allowlists.
pub fn validate_agent_egress_url(raw_url: &str, allowed_domains: &[String]) -> Result<Url, String> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return Err("SSRF_EMPTY_URL: Outbound URL cannot be empty".to_string());
    }

    // Synchronous nanosecond inline DLP Lineage check
    let check_res = global_lineage_tracker().check_egress_allowed_full(&trimmed, &None::<&str>, &None::<&str>);
    if let Err(block_info) = check_res {
        let is_blocked = block_info.policy.eq_ignore_ascii_case("QUARANTINE")
            || block_info.policy.eq_ignore_ascii_case("BLOCK")
            || block_info.classification.eq_ignore_ascii_case("CROWN_JEWEL");
        if is_blocked {
            emit_synthetic_blocked_span(Some(trimmed), None, None, &block_info);
            return Err(format!(
                "DLP_EGRESS_BLOCKED: Outbound request to '{}' blocked by DLP Lineage (policy={}, classification={}): {}",
                trimmed, block_info.policy, block_info.classification, block_info.reason
            ));
        }
    }

    if let Some(after_scheme) = trimmed.split("://").nth(1) {
        let authority = after_scheme
            .split(&['/', '?', '#'][..])
            .next()
            .unwrap_or("");
        let raw_host_port = authority.rsplit('@').next().unwrap_or(authority);
        let raw_host = if raw_host_port.starts_with('[') {
            raw_host_port.split(']').next().unwrap_or(raw_host_port)
        } else {
            raw_host_port.split(':').next().unwrap_or(raw_host_port)
        }
        .trim()
        .to_ascii_lowercase();
        if is_non_standard_ip_host_encoding(&raw_host) {
            return Err(format!(
                "SSRF_NON_STANDARD_IP_ENCODING (CIS 3.3): Host '{}' is prohibited",
                raw_host
            ));
        }
    }

    let parsed =
        Url::parse(trimmed).map_err(|e| format!("SSRF_MALFORMED_URL '{}': {}", trimmed, e))?;

    if parsed.scheme() != "https" {
        return Err(format!(
            "SSRF_INSECURE_SCHEME: '{}' is forbidden; only https:// is allowed",
            parsed.scheme()
        ));
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(
            "SSRF_EMBEDDED_CREDENTIALS: Userinfo credentials in URL are prohibited".to_string(),
        );
    }

    if let Some(port) = parsed.port() {
        if port != 443 {
            return Err(format!(
                "SSRF_NON_STANDARD_PORT: Port {} is forbidden; only 443 is permitted",
                port
            ));
        }
    }

    let host_str = match parsed.host() {
        Some(url::Host::Ipv4(v4)) => {
            if is_restricted_rebinding_ip(&IpAddr::V4(v4)) {
                return Err(format!(
                    "SSRF_IPV4_RESTRICTED: Destination IPv4 '{}' is in a forbidden range",
                    v4
                ));
            }
            v4.to_string()
        }
        Some(url::Host::Ipv6(v6)) => {
            if is_restricted_rebinding_ip(&IpAddr::V6(v6)) {
                return Err(format!(
                    "SSRF_IPV6_RESTRICTED: Destination IPv6 '[{}]' is in a forbidden range",
                    v6
                ));
            }
            format!("[{}]", v6)
        }
        Some(url::Host::Domain(d)) => {
            let lower = d.trim_end_matches('.').to_ascii_lowercase();
            let unbracketed = lower
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .unwrap_or(&lower);
            if let Ok(ip) = unbracketed.parse::<IpAddr>() {
                if is_restricted_rebinding_ip(&ip) {
                    return Err(format!(
                        "SSRF_DOMAIN_IP_RESTRICTED: '{}' resolves to restricted IP '{}'",
                        d, ip
                    ));
                }
            }
            if lower == "localhost"
                || lower.ends_with(".localhost")
                || lower.ends_with(".internal")
                || lower.ends_with(".local")
                || lower == "metadata.google.internal"
                || (lower.chars().all(|c| c.is_ascii_digit()) && !lower.contains('.'))
            {
                return Err(format!(
                    "SSRF_INTERNAL_HOSTNAME_BLOCKED: Host '{}' is prohibited",
                    d
                ));
            }
            lower
        }
        None => {
            return Err("SSRF_MISSING_HOST: Outbound URL has no valid host".to_string());
        }
    };

    if !allowed_domains.is_empty() {
        let permitted = allowed_domains.iter().any(|allowed| {
            let norm = allowed.trim().trim_end_matches('.').to_ascii_lowercase();
            host_str == norm || host_str.ends_with(&format!(".{}", norm))
        });
        if !permitted {
            return Err(format!(
                "EGRESS_DOMAIN_NOT_ALLOWLISTED: Host '{}' is not in approved allowlist",
                host_str
            ));
        }
    }

    Ok(parsed)
}

/// DNS-pinned outbound egress target (Finding 6: prevents DNS rebinding between validation and connect).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedEgress {
    pub url: Url,
    pub host: String,
    pub port: u16,
    /// Verified public IP addresses resolved once at validation time.
    pub pinned_addrs: Vec<IpAddr>,
}

impl PinnedEgress {
    /// Returns the `--resolve <host>:<port>:<ip1>,<ip2>` argument for `curl.exe` so `curl` never
    /// performs a second DNS lookup after [`resolve_and_pin`] has validated the addresses.
    pub fn curl_resolve_arg(&self) -> String {
        let ips = self
            .pinned_addrs
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(",");
        format!("{}:{}:{}", self.host, self.port, ips)
    }
}

/// Validates `raw_url` against [`validate_agent_egress_url`], resolves its hostname once via the
/// OS resolver, rejects the target if **any** returned A/AAAA record falls in a restricted range
/// ([`is_restricted_rebinding_ip`]), and returns a [`PinnedEgress`] whose IP addresses can be
/// pinned onto the HTTP client (`curl --resolve`).
pub fn resolve_and_pin(raw_url: &str, allowed_domains: &[String]) -> Result<PinnedEgress, String> {
    let parsed = validate_agent_egress_url(raw_url, allowed_domains)?;
    let port = parsed.port_or_known_default().unwrap_or(443);

    let (host_for_resolve, pinned_addrs) = match parsed.host() {
        Some(url::Host::Ipv4(v4)) => (v4.to_string(), vec![IpAddr::V4(v4)]),
        Some(url::Host::Ipv6(v6)) => (format!("[{}]", v6), vec![IpAddr::V6(v6)]),
        Some(url::Host::Domain(d)) => {
            let clean = d.trim_end_matches('.').to_ascii_lowercase();
            let sock_iter = (clean.as_str(), port).to_socket_addrs().map_err(|e| {
                format!("SSRF_DNS_RESOLUTION_FAILED for '{}:{}': {}", clean, port, e)
            })?;
            let mut addrs = Vec::new();
            for sa in sock_iter {
                let ip = sa.ip();
                if is_restricted_rebinding_ip(&ip) {
                    return Err(format!(
                        "SSRF_DNS_REBINDING_BLOCKED: Host '{}' resolved to restricted IP '{}'",
                        clean, ip
                    ));
                }
                if !addrs.contains(&ip) {
                    addrs.push(ip);
                }
            }
            if addrs.is_empty() {
                return Err(format!(
                    "SSRF_DNS_EMPTY: Host '{}' returned zero addresses",
                    clean
                ));
            }
            (clean, addrs)
        }
        None => {
            return Err("SSRF_MISSING_HOST".to_string());
        }
    };

    Ok(PinnedEgress {
        url: parsed,
        host: host_for_resolve,
        port,
        pinned_addrs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_standard_ip_encodings() {
        assert!(is_non_standard_ip_host_encoding("2130706433"));
        assert!(is_non_standard_ip_host_encoding("0x7f000001"));
        assert!(is_non_standard_ip_host_encoding("0177.0.0.1"));
        assert!(is_non_standard_ip_host_encoding("127.1"));
        assert!(!is_non_standard_ip_host_encoding("google.com"));
        assert!(!is_non_standard_ip_host_encoding("127.0.0.1"));
    }

    #[test]
    fn test_cis33_restricted_ip_ranges() {
        assert!(is_restricted_rebinding_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_restricted_rebinding_ip(&"10.0.0.1".parse().unwrap()));
        assert!(is_restricted_rebinding_ip(&"172.16.0.1".parse().unwrap()));
        assert!(is_restricted_rebinding_ip(&"192.168.1.1".parse().unwrap()));
        assert!(is_restricted_rebinding_ip(
            &"169.254.169.254".parse().unwrap()
        ));
        assert!(is_restricted_rebinding_ip(&"100.64.0.1".parse().unwrap()));
        assert!(is_restricted_rebinding_ip(&"0.0.0.0".parse().unwrap()));
        assert!(is_restricted_rebinding_ip(&"198.18.0.1".parse().unwrap()));
        assert!(is_restricted_rebinding_ip(&"240.0.0.1".parse().unwrap()));
        assert!(is_restricted_rebinding_ip(&"::1".parse().unwrap()));
        assert!(is_restricted_rebinding_ip(&"::".parse().unwrap()));
        assert!(is_restricted_rebinding_ip(&"fc00::1".parse().unwrap()));
        assert!(is_restricted_rebinding_ip(&"fe80::1".parse().unwrap()));
        assert!(is_restricted_rebinding_ip(
            &"64:ff9b::127.0.0.1".parse().unwrap()
        ));
        // RFC 2765 SIIT IPv4-translated prefix ::ffff:0:0/96
        assert!(is_restricted_rebinding_ip(
            &"::ffff:0:127.0.0.1".parse().unwrap()
        ));
        assert!(is_restricted_rebinding_ip(
            &"::ffff:0:10.0.0.1".parse().unwrap()
        ));
        assert!(is_restricted_rebinding_ip(
            &"::ffff:0:169.254.169.254".parse().unwrap()
        ));
        assert!(!is_restricted_rebinding_ip(
            &"::ffff:0:8.8.8.8".parse().unwrap()
        ));

        // Public IP should pass
        assert!(!is_restricted_rebinding_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_restricted_rebinding_ip(&"1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn test_synchronous_inline_egress_blocking_and_child_span() {
        clear_recent_blocked_spans();

        // Register test hook simulating DLP Lineage Tracker
        register_lineage_egress_hook(|url, file_path, hash| {
            if let Some(u) = url {
                if u.contains("tainted-exfil.com") {
                    return Err(EgressLineageBlockInfo {
                        policy: "QUARANTINE".to_string(),
                        classification: "CROWN_JEWEL".to_string(),
                        reason: "Outbound egress blocked: target destination is classified as CROWN_JEWEL leak sink".to_string(),
                        trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
                        span_id: Some("00f067aa0ba902b7".to_string()),
                    });
                }
            }
            if let Some(fp) = file_path {
                if fp.contains("secret.docx") {
                    return Err(EgressLineageBlockInfo {
                        policy: "QUARANTINE".to_string(),
                        classification: "CROWN_JEWEL".to_string(),
                        reason: "File egress blocked: secret.docx is tainted with QUARANTINE".to_string(),
                        trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
                        span_id: Some("00f067aa0ba902b7".to_string()),
                    });
                }
            }
            if let Some(h) = hash {
                if h == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
                    return Err(EgressLineageBlockInfo {
                        policy: "BLOCK".to_string(),
                        classification: "CONFIDENTIAL".to_string(),
                        reason: "Hash egress blocked: hash matches confidential artifact".to_string(),
                        trace_id: None,
                        span_id: None,
                    });
                }
            }
            Ok(())
        });

        // 1. Direct query through global_lineage_tracker() in nanoseconds
        let tracker = global_lineage_tracker();
        let res = tracker.check_egress_allowed_full(
            Some("https://tainted-exfil.com/upload"),
            None::<&str>,
            None::<&str>,
        );
        assert!(res.is_err());
        let info = res.unwrap_err();
        assert_eq!(info.policy, "QUARANTINE");
        assert_eq!(info.classification, "CROWN_JEWEL");

        // 2. Outbound egress blocked in validate_agent_egress_url
        let egress_url = "https://user:password123@tainted-exfil.com/upload";
        let val_res = validate_agent_egress_url(egress_url, &[]);
        assert!(val_res.is_err());
        let err_msg = val_res.unwrap_err();
        assert!(err_msg.contains("DLP_EGRESS_BLOCKED"));
        assert!(err_msg.contains("QUARANTINE"));
        assert!(err_msg.contains("CROWN_JEWEL"));

        // 3. Verify synthetic child span emission with status ERROR, dlp.action=BLOCKED, zero PII
        let spans = get_recent_blocked_spans();
        assert!(!spans.is_empty(), "A synthetic child span must have been emitted");
        let last_span = spans.last().unwrap();
        assert_eq!(last_span.status, "ERROR");
        assert_eq!(last_span.action, "BLOCKED");
        assert_eq!(last_span.policy, "QUARANTINE");
        assert_eq!(last_span.classification, "CROWN_JEWEL");
        assert_eq!(last_span.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(last_span.parent_span_id.as_deref(), Some("00f067aa0ba902b7"));

        // Verify zero-PII invariant on attributes
        assert_eq!(
            last_span.attributes.get("dlp.action").map(|s| s.as_str()),
            Some("BLOCKED")
        );
        assert_eq!(
            last_span.attributes.get("otel.status_code").map(|s| s.as_str()),
            Some("ERROR")
        );
        let span_url = last_span.attributes.get("url.full").expect("url.full attribute must exist");
        assert!(
            !span_url.contains("password123"),
            "Zero-PII violation: passwords must be sanitized from OTel span attributes"
        );
        assert!(
            !span_url.contains("user:"),
            "Zero-PII violation: userinfo must be sanitized from OTel span attributes"
        );

        // 4. File-based check_egress_allowed_inline
        let file_res = check_egress_allowed_inline(None::<&str>, Some("C:\\workspace\\secret.docx"), None::<&str>);
        assert!(file_res.is_err());
        assert!(file_res.unwrap_err().contains("DLP_EGRESS_BLOCKED"));

        // 5. Clean egress allowed
        let clean_res = check_egress_allowed_inline(
            Some("https://trusted-internal-repo.corp/api"),
            Some("C:\\workspace\\clean.txt"),
            None::<&str>,
        );
        assert!(clean_res.is_ok());
    }
}
