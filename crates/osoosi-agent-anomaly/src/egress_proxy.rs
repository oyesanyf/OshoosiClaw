//! Mathematical IPv4/IPv6 SSRF Normalization, CIS 3.3 Range Checks, and DNS Pinning (Finding 6).
//!
//! Provides defense-in-depth against DNS rebinding and SSRF bypasses:
//! 1. [`is_non_standard_ip_host_encoding`]: Detects decimal integer, hex, octal, and shortened quad encodings.
//! 2. [`is_restricted_rebinding_ip`]: Complete mathematical classification of restricted IPv4/IPv6 ranges (CIS 3.3).
//! 3. [`validate_agent_egress_url`]: HTTPS-only transport, credential stripping, trailing-dot normalization, and domain allowlists.
//! 4. [`resolve_and_pin`]: OS DNS resolution pinning returning [`PinnedEgress`] with `--resolve` formatting.

use std::net::{IpAddr, ToSocketAddrs};
use url::Url;

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
}
