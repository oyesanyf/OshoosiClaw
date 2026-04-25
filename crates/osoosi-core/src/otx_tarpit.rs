//! OTX-driven **reactive** response: tie Sysmon-observed activity to network QoS “tarpit” (throttle)
//! for the responsible process. Sysmon only logs; this layer executes the response via
//! [`crate::firewall::tarpit_process_network`] (Windows QoS) alongside CPU priority tarpit in
//! [`osoosi_runtime::TarpitManager`].
//!
//! No separate `win_event_log` loop — ingestion stays on the host event pipeline
//! (`process_telemetry` → `perform_action`).

use osoosi_types::{ResponseAction, SysmonEvent, SysmonEventId, ThreatSignature};

/// When false, skip per-process network QoS tarpit (CPU tarpit in `TarpitManager` may still run).
pub fn network_qos_tarpit_enabled() -> bool {
    !matches!(
        std::env::var("OSOOSI_NETWORK_TARPIT")
            .as_deref()
            .map(|s| s == "0" || s.eq_ignore_ascii_case("false") || s.eq_ignore_ascii_case("off")),
        Ok(true)
    )
}

fn reason_indicates_otx(sig: &ThreatSignature) -> bool {
    sig.reason
        .as_deref()
        .map(|r| {
            let u = r.to_ascii_lowercase();
            u.contains("otx")
        })
        .unwrap_or(false)
}

fn event_warrants_process_network_shaping(ev: &SysmonEvent) -> bool {
    matches!(
        ev.event_id,
        SysmonEventId::NetworkConnect | SysmonEventId::DnsQuery
    )
}

/// Apply Windows QoS “Ghost Tarpit” to the process image when Tarpit / GhostTarpit is in effect
/// and the threat is OTX- or network/DNS-originated. Returns a message for logs/audit.
#[cfg(target_os = "windows")]
pub fn try_apply_process_network_qostarpit(
    event: &SysmonEvent,
    signature: &ThreatSignature,
    action: ResponseAction,
) -> Option<String> {
    if !network_qos_tarpit_enabled() {
        return None;
    }
    if !matches!(action, ResponseAction::Tarpit | ResponseAction::GhostTarpit) {
        return None;
    }
    if !(reason_indicates_otx(signature) || event_warrants_process_network_shaping(event)) {
        return None;
    }
    let pid = event.data.get("ProcessId").and_then(|p| p.as_u64()).map(|v| v as u32);
    let image = event
        .data
        .get("Image")
        .and_then(|i| i.as_str())
        .filter(|s| !s.is_empty());
    let image = image?;
    match crate::firewall::tarpit_process_network(pid, Some(image)) {
        Ok(msg) => Some(msg),
        Err(e) => Some(format!("Network QoS tarpit not applied: {}", e)),
    }
}

#[cfg(not(target_os = "windows"))]
pub fn try_apply_process_network_qostarpit(
    _event: &SysmonEvent,
    _signature: &ThreatSignature,
    _action: ResponseAction,
) -> Option<String> {
    None
}

/// JSON payload for audit when QoS tarpit is attempted.
pub fn audit_payload(
    event: &SysmonEvent,
    signature: &ThreatSignature,
    action: ResponseAction,
    qos_msg: &str,
) -> serde_json::Value {
    serde_json::json!({
        "action": format!("{:?}", action),
        "confidence": signature.confidence,
        "event_id": event.event_id as u32,
        "image": event.data.get("Image"),
        "process_id": event.data.get("ProcessId"),
        "destination_ip": event.data.get("DestinationIp"),
        "query_name": event.data.get("QueryName"),
        "otx_in_reason": reason_indicates_otx(signature),
        "message": qos_msg,
    })
}
