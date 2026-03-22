use osoosi_types::{ResponseAction, SysmonEvent, SysmonEventId};
use std::collections::HashSet;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct TrafficThreat {
    pub confidence: f32,
    pub action: ResponseAction,
    pub tag: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct PromptAnalysis {
    pub task_response: String,
    pub final_response: String,
    pub confidence: f32,
    pub action: ResponseAction,
    pub tag: Option<String>,
    pub reason: String,
}

pub fn traffic_adapter_enabled() -> bool {
    std::env::var("OSOOSI_TRAFFIC_ADAPTER_ENABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true)
}

fn parse_u16_set(var: &str, defaults: &[u16]) -> HashSet<u16> {
    if let Ok(raw) = std::env::var(var) {
        let out: HashSet<u16> = raw
            .split(',')
            .filter_map(|v| v.trim().parse::<u16>().ok())
            .collect();
        if !out.is_empty() {
            return out;
        }
    }
    defaults.iter().copied().collect()
}

fn parse_lower_set(var: &str, defaults: &[&str]) -> HashSet<String> {
    if let Ok(raw) = std::env::var(var) {
        let out: HashSet<String> = raw
            .split(',')
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| !v.is_empty())
            .collect();
        if !out.is_empty() {
            return out;
        }
    }
    defaults.iter().map(|v| v.to_string()).collect()
}

fn looks_like_public_ip(s: &str) -> bool {
    let Ok(ip) = s.parse::<IpAddr>() else {
        return false;
    };
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_documentation())
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.is_multicast()
                || v6.is_unspecified())
        }
    }
}

fn basename_lower(image: &str) -> String {
    std::path::Path::new(image)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(image)
        .to_ascii_lowercase()
}

fn dga_like_domain_score(domain: &str) -> f32 {
    let first = domain
        .trim()
        .trim_end_matches('.')
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if first.len() < 20 {
        return 0.0;
    }
    let mut alpha = 0usize;
    let mut digits = 0usize;
    let mut vowels = 0usize;
    for c in first.chars() {
        if c.is_ascii_alphabetic() {
            alpha += 1;
            if matches!(c, 'a' | 'e' | 'i' | 'o' | 'u') {
                vowels += 1;
            }
        } else if c.is_ascii_digit() {
            digits += 1;
        }
    }
    let len = first.len() as f32;
    let digit_ratio = digits as f32 / len;
    let vowel_ratio = if alpha > 0 {
        vowels as f32 / alpha as f32
    } else {
        0.0
    };
    if digit_ratio > 0.30 && vowel_ratio < 0.20 {
        0.42
    } else {
        0.0
    }
}

pub fn analyze(event: &SysmonEvent) -> Option<TrafficThreat> {
    if !traffic_adapter_enabled() {
        return None;
    }

    let tor_ports = parse_u16_set(
        "OSOOSI_TRAFFIC_TOR_PORTS",
        &[9001, 9030, 9050, 9051, 9150],
    );
    let vpn_ports = parse_u16_set(
        "OSOOSI_TRAFFIC_VPN_PORTS",
        &[500, 4500, 1194, 1701, 1723, 51820],
    );
    let suspicious_ports = parse_u16_set(
        "OSOOSI_TRAFFIC_SUSPICIOUS_PORTS",
        &[23, 4444, 6667, 1337, 31337],
    );
    let ddns_domains = parse_lower_set(
        "OSOOSI_TRAFFIC_DDNS_DOMAINS",
        &["duckdns.org", "no-ip.org", "ddns.net", "hopto.org", "zapto.org"],
    );
    let lolbins = parse_lower_set(
        "OSOOSI_TRAFFIC_LOLBINS",
        &[
            "powershell.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "rundll32.exe",
            "mshta.exe",
            "regsvr32.exe",
            "bitsadmin.exe",
            "certutil.exe",
        ],
    );
    let c2_tokens = parse_lower_set(
        "OSOOSI_TRAFFIC_C2_TOKENS",
        &[
            "dnscat",
            "iodine",
            "cobaltstrike",
            "sliver",
            "metasploit",
            "beacon",
            "empire",
        ],
    );

    match event.event_id {
        SysmonEventId::NetworkConnect => {
            let image = event
                .data
                .get("Image")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let process = basename_lower(image);
            let cmd = event
                .data
                .get("CommandLine")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            let dst_ip = event
                .data
                .get("DestinationIp")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let dst_port = event
                .data
                .get("DestinationPort")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<u16>().ok())
                .or_else(|| {
                    event.data
                        .get("DestinationPort")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u16)
                })
                .unwrap_or(0);

            let mut score = 0.0f32;
            let mut reasons = Vec::new();
            let mut tag = "TRAFFIC:ANOMALY".to_string();
            let is_public = looks_like_public_ip(dst_ip);

            if is_public && lolbins.contains(&process) {
                score += 0.34;
                reasons.push("lolbin process made outbound public connection");
                tag = "TRAFFIC:AAD".to_string();
            }
            if tor_ports.contains(&dst_port) {
                score += 0.55;
                reasons.push("destination port aligns with Tor control/relay profile");
                tag = "TRAFFIC:TBD".to_string();
            } else if vpn_ports.contains(&dst_port) {
                score += 0.33;
                reasons.push("destination port aligns with encrypted VPN profile");
                tag = "TRAFFIC:EVD".to_string();
            }
            if suspicious_ports.contains(&dst_port) {
                score += 0.30;
                reasons.push("destination port is commonly abused by C2/backdoors");
                tag = "TRAFFIC:BND".to_string();
            }
            if cmd.contains(" -enc ")
                || cmd.contains("frombase64string")
                || cmd.contains("iwr ")
                || cmd.contains("invoke-webrequest")
            {
                score += 0.22;
                reasons.push("command line shows encoded/download-exec indicators");
                tag = "TRAFFIC:MTD".to_string();
            }

            if score < 0.50 {
                return None;
            }
            let confidence = score.min(0.95);
            let action = if confidence >= 0.85 {
                ResponseAction::GhostTarpit
            } else {
                ResponseAction::Alert
            };
            return Some(TrafficThreat {
                confidence,
                action,
                tag,
                reason: reasons.join("; "),
            });
        }
        SysmonEventId::DnsQuery => {
            let query = event
                .data
                .get("QueryName")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            if query.is_empty() {
                return None;
            }
            let results = event
                .data
                .get("QueryResults")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_ascii_lowercase();

            let mut score = dga_like_domain_score(&query);
            let mut reasons = Vec::new();
            let mut tag = "TRAFFIC:ANOMALY".to_string();
            if score > 0.0 {
                reasons.push("query resembles DGA-like high-entropy label");
                tag = "TRAFFIC:BND".to_string();
            }
            if ddns_domains.iter().any(|d| query.ends_with(d)) {
                score += 0.30;
                reasons.push("query targets dynamic DNS infrastructure");
                tag = "TRAFFIC:AAD".to_string();
            }
            if c2_tokens.iter().any(|t| query.contains(t) || results.contains(t)) {
                score += 0.55;
                reasons.push("query/results contain known C2 framework tokens");
                tag = "TRAFFIC:MTD".to_string();
            }
            let ip_count = results.matches("::ffff:").count() + results.matches("type: 1").count();
            if ip_count >= 8 {
                score += 0.22;
                reasons.push("query results show fast-flux-like multi-IP response");
                tag = "TRAFFIC:BND".to_string();
            }

            if score < 0.50 {
                return None;
            }
            let confidence = score.min(0.93);
            let action = if confidence >= 0.85 {
                ResponseAction::GhostTarpit
            } else {
                ResponseAction::Alert
            };
            return Some(TrafficThreat {
                confidence,
                action,
                tag,
                reason: reasons.join("; "),
            });
        }
        _ => {}
    }
    None
}

pub fn analyze_prompt(human_instruction: &str, traffic_data: &str) -> PromptAnalysis {
    let task_response = infer_task_from_instruction(human_instruction, traffic_data);
    let synthetic = synthetic_event_from_packet_text(traffic_data);

    if let Some(threat) = analyze(&synthetic) {
        PromptAnalysis {
            task_response,
            final_response: format!(
                "suspicious ({:.2}) - {} [{}]",
                threat.confidence, threat.reason, threat.tag
            ),
            confidence: threat.confidence,
            action: threat.action,
            tag: Some(threat.tag),
            reason: threat.reason,
        }
    } else {
        PromptAnalysis {
            task_response,
            final_response: "benign/low-risk based on current traffic heuristics".to_string(),
            confidence: 0.25,
            action: ResponseAction::Alert,
            tag: None,
            reason: "no high-confidence traffic anomalies matched".to_string(),
        }
    }
}

fn infer_task_from_instruction(human_instruction: &str, traffic_data: &str) -> String {
    let text = format!("{} {}", human_instruction, traffic_data).to_ascii_lowercase();
    if text.contains("tor") {
        "Tor Behavior Detection".to_string()
    } else if text.contains("vpn") {
        "Encrypted VPN Detection".to_string()
    } else if text.contains("botnet") {
        "Botnet Detection".to_string()
    } else if text.contains("http") || text.contains("url") || text.contains("web attack") {
        "Web Attack Detection".to_string()
    } else if text.contains("malware") {
        "Malware Traffic Detection".to_string()
    } else {
        "Network Traffic Detection".to_string()
    }
}

fn synthetic_event_from_packet_text(traffic_data: &str) -> SysmonEvent {
    use chrono::Utc;
    use serde_json::json;

    let lower = traffic_data.to_ascii_lowercase();
    let mut map = serde_json::Map::new();

    if let Some(image) = extract_first_value(&lower, &["process", "image", "exe"]) {
        map.insert("Image".to_string(), json!(image));
    } else {
        map.insert("Image".to_string(), json!("trafficllm-adapter"));
    }

    if let Some(cmd) = extract_first_value(&lower, &["commandline", "cmdline", "command"]) {
        map.insert("CommandLine".to_string(), json!(cmd));
    }

    if let Some(ip) = extract_first_value(&lower, &["ip.dst", "dst_ip", "destinationip"]) {
        map.insert("DestinationIp".to_string(), json!(ip));
    }
    if let Some(ip) = extract_first_value(&lower, &["ip.src", "src_ip", "sourceip"]) {
        map.insert("SourceIp".to_string(), json!(ip));
    }

    if let Some(port) = extract_first_numeric(&lower, &["tcp.dstport", "udp.dstport", "dstport", "destinationport"]) {
        map.insert("DestinationPort".to_string(), json!(port.to_string()));
    }

    if let Some(host) = extract_domain_candidate(&lower) {
        map.insert("QueryName".to_string(), json!(host));
    }
    map.insert("QueryResults".to_string(), json!(traffic_data));

    let event_id = if map.get("QueryName").is_some() {
        SysmonEventId::DnsQuery
    } else {
        SysmonEventId::NetworkConnect
    };
    SysmonEvent {
        event_id,
        timestamp: Utc::now(),
        computer: "trafficllm-adapter".to_string(),
        data: json!(map),
    }
}

fn extract_first_numeric(input: &str, keys: &[&str]) -> Option<u16> {
    for key in keys {
        if let Some(v) = extract_value_after_key(input, key) {
            let digits: String = v.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(p) = digits.parse::<u16>() {
                return Some(p);
            }
        }
    }
    None
}

fn extract_first_value(input: &str, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(v) = extract_value_after_key(input, key) {
            let cleaned = v
                .trim_matches(|c: char| c == '"' || c == '\'' || c == '<' || c == '>')
                .trim()
                .to_string();
            if !cleaned.is_empty() {
                return Some(cleaned);
            }
        }
    }
    None
}

fn extract_value_after_key(input: &str, key: &str) -> Option<String> {
    let needle = format!("{}:", key);
    let idx = input.find(&needle)?;
    let start = idx + needle.len();
    let rest = &input[start..];
    let end = rest.find([',', ';', '\n', '\r']).unwrap_or(rest.len());
    Some(rest[..end].trim().to_string())
}

fn extract_domain_candidate(input: &str) -> Option<String> {
    for token in input
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == '"' || c == '\'')
    {
        let t = token.trim().trim_matches('.');
        if t.len() < 4 {
            continue;
        }
        if t.contains('.') && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            && !t.chars().all(|c| c.is_ascii_digit() || c == '.') {
                return Some(t.to_string());
            }
    }
    None
}
