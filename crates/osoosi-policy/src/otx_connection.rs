//! OTX IoC matching for **Sysmon network / DNS / hash** style events.
//!
//! Indicators are loaded by the background [`ThreatFeedFetcher::fetch_otx_indicators`](crate::feed::ThreatFeedFetcher::fetch_otx_indicators),
//! which uses **TAXII 1.1** by default (see `OTX_USE_TAXII`) and refreshes the in-memory
//! [`OtxIndicators`](crate::feed::OtxIndicators) plus SQLite via `upsert_otx_indicators`.  
//! **Each connection is matched locally** against that cache — there is no per-packet TAXII HTTP
//! round-trip (that would be too slow and rate-limited).

use crate::feed::OtxIndicators;
use osoosi_memory::MemoryStore;
use osoosi_types::{SysmonEvent, SysmonEventId};

/// Fixed confidence for an OTX IoC hit in [`PolicyEngine::scan_event`](crate::engine::PolicyEngine::scan_event) voting.
pub const OTX_CONSENSUS_CONFIDENCE: f32 = 0.95;

/// Weight multiplier for OTX in multi-voter **consensus** (network and DNS are primary C2 signals).
pub fn otx_consensus_weight(event: &SysmonEvent) -> f32 {
    match event.event_id {
        SysmonEventId::NetworkConnect | SysmonEventId::DnsQuery => 1.15,
        _ => 1.0,
    }
}

/// Lowercase, trim, and map IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to `a.b.c.d` for consistent IoC keys.
pub fn normalize_ip_for_otx(s: &str) -> String {
    let s = s.trim().to_ascii_lowercase();
    if let Some(v4) = s.strip_prefix("::ffff:") {
        v4.to_string()
    } else {
        s
    }
}

/// If `destination_ip` or DNS `query_name` (or other fields) match OTX data from the last feed sync, returns a human reason.
pub fn otx_match_sysmon_event(
    guard: &OtxIndicators,
    memory: &MemoryStore,
    event: &SysmonEvent,
) -> Option<String> {
    let destination_ip = event
        .data
        .get("DestinationIp")
        .and_then(|v| v.as_str())
        .map(|s| normalize_ip_for_otx(s))
        .unwrap_or_default();

    let source_ip = event
        .data
        .get("SourceIp")
        .and_then(|v| v.as_str())
        .map(normalize_ip_for_otx)
        .unwrap_or_default();
    let query_name = event
        .data
        .get("QueryName")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let hashes_field = event
        .data
        .get("Hashes")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let cmd_line = event
        .data
        .get("CommandLine")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let image = event
        .data
        .get("Image")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let mut hit: Option<String> = None;

    if !destination_ip.is_empty() {
        if guard.ips.contains(&destination_ip) {
            hit = Some(format!(
                "Destination IP {destination_ip} matched OTX IoC (in-memory, TAXII/REST sync)"
            ));
        } else if let Ok(true) = memory.is_indicator_malicious("ipv4", &destination_ip) {
            hit = Some(format!(
                "Destination IP {destination_ip} matched OTX IoC (SQLite, TAXII/REST sync)"
            ));
        }
    } else if !source_ip.is_empty() {
        if guard.ips.contains(&source_ip) {
            hit = Some(format!(
                "Source IP {source_ip} matched OTX IoC (in-memory, TAXII/REST sync)"
            ));
        } else if let Ok(true) = memory.is_indicator_malicious("ipv4", &source_ip) {
            hit = Some(format!(
                "Source IP {source_ip} matched OTX IoC (SQLite, TAXII/REST sync)"
            ));
        }
    } else if !query_name.is_empty() {
        if guard.domains.contains(&query_name) {
            hit = Some(format!("Domain {query_name} matched OTX IoC (cache)"));
        } else if let Ok(true) = memory.is_indicator_malicious("domain", &query_name) {
            hit = Some(format!("Domain {query_name} matched OTX IoC (SQLite)"));
        } else {
            for domain in &guard.domains {
                if query_name.ends_with(domain) {
                    hit = Some(format!(
                        "Domain {query_name} matched OTX suffix IoC {domain}"
                    ));
                    break;
                }
            }
        }
    } else if !hashes_field.is_empty() {
        for h in &guard.hashes {
            if hashes_field.contains(h) {
                hit = Some(format!("Hashes field matched OTX hash {h} (cache)"));
                break;
            }
        }
        if hit.is_none() {
            for hash_part in hashes_field.split(',') {
                let val = hash_part.split('=').nth(1).unwrap_or(hash_part).trim();
                if let Ok(true) = memory.is_indicator_malicious("hash", val) {
                    hit = Some(format!("Hashes field matched OTX hash {val} (SQLite)"));
                    break;
                }
            }
        }
    } else if !cmd_line.is_empty() {
        for url in &guard.urls {
            if cmd_line.contains(url) {
                hit = Some(format!("Command line matched OTX URL {url}"));
                break;
            }
        }
    } else if !image.is_empty() {
        for url in &guard.urls {
            if image.contains(url) {
                hit = Some(format!("Image path matched OTX URL {url}"));
                break;
            }
        }
    }

    hit
}

/// Convenience: look up a single destination IP (e.g. from a connection) against the current OTX sets.
pub fn otx_match_destination_ip(
    guard: &OtxIndicators,
    memory: &MemoryStore,
    destination_ip: &str,
) -> Option<String> {
    let ip = normalize_ip_for_otx(destination_ip);
    if ip.is_empty() {
        return None;
    }
    if guard.ips.contains(&ip) {
        return Some(format!("Destination IP {ip} matched OTX IoC (in-memory)"));
    }
    if let Ok(true) = memory.is_indicator_malicious("ipv4", &ip) {
        return Some(format!("Destination IP {ip} matched OTX IoC (SQLite)"));
    }
    None
}

/// Same as [`otx_match_sysmon_event`], with shared `RwLock` storage (e.g. from [`PolicyEngine`](crate::engine::PolicyEngine)).
pub fn otx_match_with_policy_state(
    indicators: &std::sync::Arc<std::sync::RwLock<OtxIndicators>>,
    memory: &std::sync::Arc<MemoryStore>,
    event: &SysmonEvent,
) -> Option<String> {
    let guard = indicators.read().ok()?;
    otx_match_sysmon_event(&guard, memory.as_ref(), event)
}
