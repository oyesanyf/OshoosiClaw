//! Cross-platform log readers: Windows (System, Application, Security),
//! Linux (journald, syslog), macOS (unified log, system.log).

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single log event from any platform, normalized for behavioral analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub source: String,
    pub event_id: u32,
    pub timestamp: DateTime<Utc>,
    pub computer: String,
    pub data: HashMap<String, serde_json::Value>,
}

impl From<&osoosi_types::HostSecurityEvent> for LogEvent {
    fn from(event: &osoosi_types::HostSecurityEvent) -> Self {
        let mut data = HashMap::new();
        if let Some(obj) = event.data.as_object() {
            for (k, v) in obj {
                data.insert(k.clone(), v.clone());
            }
        }
        let source_str = if let Some(channel) = data.get("Channel").and_then(|v| v.as_str()) {
            if channel.contains("Sysmon") {
                "Microsoft-Windows-Sysmon".to_string()
            } else {
                format!("windows:{}", channel)
            }
        } else if let Some(provider) = data.get("Provider").and_then(|v| v.as_str()) {
            if provider.contains("Sysmon") {
                "Microsoft-Windows-Sysmon".to_string()
            } else {
                format!("windows:{}", provider)
            }
        } else {
            format!("{:?}", event.source)
        };
        Self {
            source: source_str,
            event_id: event.event_id,
            timestamp: event.timestamp,
            computer: event.computer.clone(),
            data,
        }
    }
}

impl osoosi_telemetry::canary::CanaryEventRef for LogEvent {
    fn canary_payload(&self) -> String {
        serde_json::to_string(&self.data).unwrap_or_default()
    }
}

impl osoosi_telemetry::canary::CanaryEventRef for &LogEvent {
    fn canary_payload(&self) -> String {
        serde_json::to_string(&self.data).unwrap_or_default()
    }
}

impl From<&LogEvent> for osoosi_types::HostSecurityEvent {
    fn from(event: &LogEvent) -> Self {
        Self {
            source: osoosi_types::HostEventSource::WindowsEventLog,
            event_id: event.event_id,
            timestamp: event.timestamp,
            computer: event.computer.clone(),
            data: serde_json::to_value(&event.data).unwrap_or(serde_json::Value::Null),
            causal_parent: None,
        }
    }
}

/// Cross-platform behavioral log reader.
/// Reads System, Application, and Security logs (Windows) or equivalents (Linux, macOS).
#[derive(Clone)]
pub struct BehavioralLogReader {
    #[cfg(target_os = "windows")]
    channels: Vec<String>,
    #[cfg(target_os = "windows")]
    last_poll_times: std::sync::Arc<std::sync::Mutex<HashMap<String, chrono::DateTime<chrono::Utc>>>>,
    #[cfg(target_os = "linux")]
    paths: Vec<String>,
    #[cfg(target_os = "linux")]
    use_journald: bool,
    #[cfg(target_os = "macos")]
    use_unified: bool,
    #[cfg(target_os = "macos")]
    paths: Vec<String>,
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    _placeholder: (),
}

impl BehavioralLogReader {
    /// Create reader with platform-appropriate default log sources.
    pub fn new() -> Self {
        #[cfg(target_os = "windows")]
        {
            let channels = std::env::var("OSOOSI_BEHAVIORAL_CHANNELS")
                .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
                .unwrap_or_else(|_| {
                    vec![
                        "System".to_string(),
                        "Application".to_string(),
                        "Security".to_string(),
                        "Microsoft-Windows-Sysmon/Operational".to_string(),
                        "Microsoft-Windows-PowerShell/Operational".to_string(),
                        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
                            .to_string(),
                    ]
                });
            Self { 
                channels,
                last_poll_times: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
            }
        }

        #[cfg(target_os = "linux")]
        {
            let paths = std::env::var("OSOOSI_BEHAVIORAL_LOGS")
                .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
                .unwrap_or_else(|_| {
                    vec![
                        "/var/log/syslog".to_string(),
                        "/var/log/auth.log".to_string(),
                        "/var/log/secure".to_string(),
                        "/var/log/audit/audit.log".to_string(),
                        "/var/log/nginx/access.log".to_string(),
                        "/var/log/apache2/access.log".to_string(),
                    ]
                });
            Self {
                paths,
            }
        }

        #[cfg(target_os = "macos")]
        {
            let paths = std::env::var("OSOOSI_BEHAVIORAL_LOGS")
                .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
                .unwrap_or_else(|_| {
                    vec![
                        "/var/log/system.log".to_string(),
                        "/var/log/secure.log".to_string(),
                        "/var/log/apache2/access_log".to_string(),
                    ]
                });
            Self { paths }
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Self { _placeholder: () }
        }
    }

    /// Poll for new events from all configured sources.
    pub fn poll_events(&self) -> Result<Vec<LogEvent>> {
        let mut out = Vec::new();

        #[cfg(target_os = "windows")]
        {
            for channel in &self.channels {
                if let Ok(events) = self.query_windows_channel(channel) {
                    out.extend(events);
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            for path in &self.paths {
                if let Ok(events) = Self::read_linux_log_file(path) {
                    out.extend(events);
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            for path in &self.paths {
                if let Ok(events) = Self::read_macos_log_file(path) {
                    out.extend(events);
                }
            }
        }

        out.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        Ok(out)
    }
}

impl Default for BehavioralLogReader {
    fn default() -> Self {
        Self::new()
    }
}

// --- Windows ---

#[cfg(target_os = "windows")]
impl BehavioralLogReader {
    fn query_windows_channel(&self, channel: &str) -> Result<Vec<LogEvent>> {
        use windows::core::HSTRING;
        use windows::Win32::System::EventLog::{
            EvtQuery, EvtNext, EvtRender, EvtClose, EvtRenderEventXml,
            EvtQueryChannelPath, EvtQueryForwardDirection, EVT_HANDLE
        };


        let mut query = format!("*[System[TimeCreated[timediff(@SystemTime) <= 600000]]]");
        
        {
            let last_times = self.last_poll_times.lock().unwrap();
            if let Some(t) = last_times.get(channel) {
                let ts_str = t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                query = format!("*[System[TimeCreated[@SystemTime > '{}']]]", ts_str);
            }
        }

        let channel_h = HSTRING::from(channel);
        let query_h = HSTRING::from(query);

        let handle = unsafe {
            match EvtQuery(
                None,
                &channel_h,
                &query_h,
                EvtQueryChannelPath.0 | EvtQueryForwardDirection.0,
            ) {
                Ok(h) => h,
                Err(e) => {
                    tracing::debug!("EvtQuery channel unavailable for {}: {}", channel, e);
                    return Ok(Vec::new());
                }
            }
        };

        let mut out = Vec::new();

        unsafe {
            let mut events = [0isize; 50];
            let mut returned = 0;

            while EvtNext(handle, &mut events, 0, 0, &mut returned).is_ok() && returned > 0 {
                for i in 0..returned as usize {
                    let evt = EVT_HANDLE(events[i]);
                    let mut buffer_used = 0;
                    let mut property_count = 0;

                    let _ = EvtRender(None, evt, EvtRenderEventXml.0 as u32, 0, None, &mut buffer_used, &mut property_count);

                    let mut buffer: Vec<u16> = vec![0; (buffer_used / 2) as usize];
                    if EvtRender(
                        None, 
                        evt, 
                        EvtRenderEventXml.0 as u32, 
                        buffer.len() as u32 * 2, 
                        Some(buffer.as_mut_ptr() as *mut std::ffi::c_void), 
                        &mut buffer_used, 
                        &mut property_count
                    ).is_ok() {
                        let xml = String::from_utf16_lossy(&buffer);
                        let clean_xml = xml.trim_end_matches('\0');
                        if let Some(parsed) = parse_single_windows_event(clean_xml, channel) {
                            out.push(parsed);
                        }
                    }
                    let _ = EvtClose(evt);
                }
            }

            let _ = EvtClose(handle);
        }

        // Update watermark per-channel
        {
            let mut last_times = self.last_poll_times.lock().unwrap();
            if let Some(latest) = out.iter().map(|e| e.timestamp).max() {
                last_times.insert(channel.to_string(), latest);
            } else if !last_times.contains_key(channel) {
                last_times.insert(channel.to_string(), chrono::Utc::now());
            }
        }

        Ok(out)
    }

    fn _parse_windows_xml(xml: &str, channel: &str) -> Result<Vec<LogEvent>> {
        let mut out = Vec::new();
        for block in xml.split("<Event>").filter(|s| s.contains("</Event>")) {
            let full = format!("<Event>{}", block);
            if let Some(ev) = parse_single_windows_event(&full, channel) {
                out.push(ev);
            }
        }
        Ok(out)
    }
}

#[cfg(target_os = "windows")]
fn parse_single_windows_event(xml: &str, channel: &str) -> Option<LogEvent> {
    let event_id = extract_xml_tag(xml, "EventID")
        .or_else(|| extract_xml_tag(xml, "System").and_then(|s| extract_xml_tag(&s, "EventID")))
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);

    let time_str = extract_xml_attr(xml, "TimeCreated", "SystemTime")
        .or_else(|| extract_xml_tag(xml, "TimeCreated"));
    let timestamp = time_str
        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);

    let computer = extract_xml_tag(xml, "Computer")
        .or_else(|| extract_xml_tag(xml, "System").and_then(|s| extract_xml_tag(&s, "Computer")))
        .unwrap_or_else(|| "localhost".to_string());

    let mut data = HashMap::new();
    data.insert(
        "raw".to_string(),
        serde_json::json!(xml.chars().take(500).collect::<String>()),
    );
    if let Some(msg) = extract_xml_tag(xml, "Message") {
        data.insert("Message".to_string(), serde_json::json!(msg));
    }
    if let Some(provider) = extract_xml_attr(xml, "Provider", "Name").or_else(|| extract_xml_tag(xml, "Provider")) {
        data.insert("Provider".to_string(), serde_json::json!(provider));
    }
    data.insert("Channel".to_string(), serde_json::json!(channel));

    for (name, value) in extract_event_data(xml) {
        data.insert(name, serde_json::json!(value));
    }

    // Normalize numeric and hex string fields (ProcessId, Ports, etc.) into integer numbers
    let numeric_keys = [
        "ProcessId", "SourceProcessId", "TargetProcessId", "ParentProcessId",
        "NewProcessId", "DestinationPort", "SourcePort",
    ];
    for key in numeric_keys {
        if let Some(val) = data.get(key) {
            if let Some(s) = val.as_str() {
                let trimmed = s.trim();
                let parsed = if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
                    u64::from_str_radix(hex, 16).ok()
                } else {
                    trimmed.parse::<u64>().ok()
                };
                if let Some(n) = parsed {
                    data.insert(key.to_string(), serde_json::json!(n));
                }
            }
        }
    }

    // Windows Security Event 4688 Normalization
    if event_id == 4688 {
        if !data.contains_key("Image") {
            if let Some(new_proc) = data.get("NewProcessName").cloned() {
                data.insert("Image".to_string(), new_proc);
            }
        }
        if !data.contains_key("ParentImage") {
            if let Some(parent_proc) = data.get("ParentProcessName").cloned() {
                data.insert("ParentImage".to_string(), parent_proc);
            }
        }
        if !data.contains_key("ProcessId") {
            if let Some(pid_val) = data.get("NewProcessId").cloned() {
                data.insert("ProcessId".to_string(), pid_val);
            }
        }
        if !data.contains_key("User") {
            if let Some(u) = data.get("SubjectUserName").cloned() {
                data.insert("User".to_string(), u);
            }
        }
    }

    // Sysmon event normalization
    if !data.contains_key("Image") {
        if let Some(src_img) = data.get("SourceImage").cloned() {
            data.insert("Image".to_string(), src_img);
        }
    }
    if !data.contains_key("ProcessId") {
        if let Some(src_pid) = data.get("SourceProcessId").cloned() {
            data.insert("ProcessId".to_string(), src_pid);
        }
    }

    let source = if channel.contains("Sysmon") 
        || data.get("Provider").and_then(|v| v.as_str()).map(|p| p.contains("Sysmon")).unwrap_or(false) 
    {
        "Microsoft-Windows-Sysmon".to_string()
    } else {
        format!("windows:{}", channel)
    };

    Some(LogEvent {
        source,
        event_id,
        timestamp,
        computer,
        data,
    })
}

#[cfg(target_os = "windows")]
fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let mut search_from = 0;
    let pattern = format!("<{}", tag);
    while let Some(tag_idx) = xml[search_from..].find(&pattern) {
        let abs_start = search_from + tag_idx;
        let after_tag_name = abs_start + pattern.len();
        if after_tag_name < xml.len() {
            let next_char = xml.as_bytes()[after_tag_name];
            if next_char == b'>' || next_char == b' ' || next_char == b'/' || next_char == b'\t' || next_char == b'\n' || next_char == b'\r' {
                if let Some(close_bracket) = xml[abs_start..].find('>') {
                    let tag_header = &xml[abs_start..abs_start + close_bracket + 1];
                    if tag_header.ends_with("/>") {
                        search_from = abs_start + close_bracket + 1;
                        continue;
                    }
                    let content_start = abs_start + close_bracket + 1;
                    let close_tag = format!("</{}>", tag);
                    if let Some(end_idx) = xml[content_start..].find(&close_tag) {
                        return Some(xml[content_start..content_start + end_idx].trim().to_string());
                    }
                }
            }
        }
        search_from = abs_start + 1;
    }
    None
}

#[cfg(target_os = "windows")]
fn extract_xml_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let mut search_from = 0;
    let pattern = format!("<{}", tag);
    while let Some(tag_idx) = xml[search_from..].find(&pattern) {
        let abs_start = search_from + tag_idx;
        let after_tag_name = abs_start + pattern.len();
        if after_tag_name < xml.len() {
            let next_char = xml.as_bytes()[after_tag_name];
            if next_char == b'>' || next_char == b' ' || next_char == b'/' || next_char == b'\t' {
                if let Some(close_bracket) = xml[abs_start..].find('>') {
                    let tag_header = &xml[abs_start..abs_start + close_bracket + 1];
                    let attr_pattern = format!("{}=\"", attr);
                    if let Some(attr_idx) = tag_header.find(&attr_pattern) {
                        let val_start = attr_idx + attr_pattern.len();
                        if let Some(val_end) = tag_header[val_start..].find('"') {
                            return Some(tag_header[val_start..val_start + val_end].to_string());
                        }
                    }
                }
            }
        }
        search_from = abs_start + 1;
    }
    None
}

#[cfg(target_os = "windows")]
fn extract_event_data(xml: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(event_data_idx) = xml.find("<EventData") {
        if let Some(close_bracket) = xml[event_data_idx..].find('>') {
            let content_start = event_data_idx + close_bracket + 1;
            if let Some(end_idx) = xml[content_start..].find("</EventData>") {
                let inner = &xml[content_start..content_start + end_idx];
                let mut pos = 0;
                let mut unnamed_idx = 0;
                while let Some(data_idx) = inner[pos..].find("<Data") {
                    let abs_data = pos + data_idx;
                    if let Some(bracket) = inner[abs_data..].find('>') {
                        let header = &inner[abs_data..abs_data + bracket + 1];
                        let val_start = abs_data + bracket + 1;
                        if let Some(val_end) = inner[val_start..].find("</Data>") {
                            let val = inner[val_start..val_start + val_end].trim();
                            let name = if let Some(n_idx) = header.find("Name=\"") {
                                let n_start = n_idx + 6;
                                if let Some(n_end) = header[n_start..].find('"') {
                                    header[n_start..n_start + n_end].to_string()
                                } else {
                                    let s = format!("Data_{}", unnamed_idx);
                                    unnamed_idx += 1;
                                    s
                                }
                            } else {
                                let s = format!("Data_{}", unnamed_idx);
                                unnamed_idx += 1;
                                s
                            };
                            if !name.is_empty() {
                                out.push((name, val.to_string()));
                            }
                            pos = val_start + val_end + 7;
                            continue;
                        }
                    }
                    pos = abs_data + 5;
                }
            }
        }
    }
    out
}

// --- Linux ---

#[cfg(target_os = "linux")]
impl BehavioralLogReader {
    fn read_linux_log_file(&self, path: &str) -> Result<Vec<LogEvent>> {
        let path_obj = std::path::Path::new(path);
        if !path_obj.exists() {
            return Ok(Vec::new());
        }

        let content = std::fs::read_to_string(path_obj)?;
        let mut out = Vec::new();
        for line in content.lines().rev().take(50) {
            let mut data = HashMap::new();
            data.insert("raw".to_string(), serde_json::json!(line));

            // Special handling for iboss:json web logs
            if path.contains("iboss") || line.trim().starts_with('{') {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                    if let Some(msg) = v
                        .get("message")
                        .or_else(|| v.get("msg"))
                        .and_then(|m| m.as_str())
                    {
                        data.insert("Message".to_string(), serde_json::json!(msg));
                    }
                    if let Some(url) = v.get("url").and_then(|u| u.as_str()) {
                        data.insert("URL".to_string(), serde_json::json!(url));
                    }
                    data.insert("parsed_json".to_string(), v);
                }
            }

            if line.contains("sshd") || line.contains("login") || line.contains("sudo") {
                data.insert("Image".to_string(), serde_json::json!("sshd"));
            }
            if !data.contains_key("Message") {
                if let Some(msg) = line.splitn(5, ' ').nth(4) {
                    data.insert("Message".to_string(), serde_json::json!(msg));
                }
            }

            out.push(LogEvent {
                source: format!("linux:{}", path_obj.display()),
                event_id: 0,
                timestamp: Utc::now(),
                computer: hostname::get()
                    .ok()
                    .and_then(|h| h.into_string().ok())
                    .unwrap_or_else(|| "localhost".to_string()),
                data,
            });
        }
        Ok(out)
    }
}

// --- macOS ---

#[cfg(target_os = "macos")]
impl BehavioralLogReader {
    fn read_macos_log_file(path: &str) -> Result<Vec<LogEvent>> {
        let path = std::path::Path::new(path);
        if !path.exists() {
            return Ok(Vec::new());
        }

        let content = std::fs::read_to_string(path)?;
        let mut out = Vec::new();
        for line in content.lines().rev().take(50) {
            let mut data = HashMap::new();
            data.insert("raw".to_string(), serde_json::json!(line));
            if let Some(msg) = line.splitn(5, ' ').nth(4) {
                data.insert("Message".to_string(), serde_json::json!(msg));
            }

            out.push(LogEvent {
                source: format!("macos:{}", path.display()),
                event_id: 0,
                timestamp: Utc::now(),
                computer: hostname::get()
                    .ok()
                    .and_then(|h| h.into_string().ok())
                    .unwrap_or_else(|| "localhost".to_string()),
                data,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_event_from_host_security_event_sysmon() {
        let mut data = serde_json::Map::new();
        data.insert("Image".to_string(), serde_json::json!(r"C:\Windows\System32\cmd.exe"));
        data.insert("Provider".to_string(), serde_json::json!("Microsoft-Windows-Sysmon"));
        data.insert("Channel".to_string(), serde_json::json!("Microsoft-Windows-Sysmon/Operational"));

        let hse = osoosi_types::HostSecurityEvent {
            source: osoosi_types::HostEventSource::WindowsEventLog,
            event_id: 1,
            timestamp: Utc::now(),
            computer: "host1".to_string(),
            data: serde_json::Value::Object(data),
            causal_parent: None,
        };

        let log_event: LogEvent = (&hse).into();
        assert_eq!(log_event.source, "Microsoft-Windows-Sysmon");
        assert_eq!(log_event.event_id, 1);
        assert_eq!(log_event.data.get("Image").and_then(|v| v.as_str()), Some(r"C:\Windows\System32\cmd.exe"));
    }

    #[test]
    fn test_log_event_from_host_security_event_security() {
        let mut data = serde_json::Map::new();
        data.insert("NewProcessName".to_string(), serde_json::json!(r"C:\Windows\System32\whoami.exe"));
        data.insert("Channel".to_string(), serde_json::json!("Security"));

        let hse = osoosi_types::HostSecurityEvent {
            source: osoosi_types::HostEventSource::WindowsEventLog,
            event_id: 4688,
            timestamp: Utc::now(),
            computer: "host2".to_string(),
            data: serde_json::Value::Object(data),
            causal_parent: None,
        };

        let log_event: LogEvent = (&hse).into();
        assert_eq!(log_event.source, "windows:Security");
        assert_eq!(log_event.event_id, 4688);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_parse_single_windows_event_sysmon_xml() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon"/>
    <EventID>3</EventID>
    <Computer>node-1</Computer>
    <TimeCreated SystemTime="2026-09-21T05:00:00.000000Z"/>
  </System>
  <EventData>
    <Data Name="Image">C:\Tools\nc.exe</Data>
    <Data Name="DestinationIp">198.51.100.23</Data>
    <Data Name="DestinationPort">4444</Data>
  </EventData>
</Event>"#;

        let ev = parse_single_windows_event(xml, "Microsoft-Windows-Sysmon/Operational").expect("Should parse");
        assert_eq!(ev.source, "Microsoft-Windows-Sysmon");
        assert_eq!(ev.event_id, 3);
        assert_eq!(ev.data.get("DestinationIp").and_then(|v| v.as_str()), Some("198.51.100.23"));
        assert_eq!(ev.data.get("DestinationPort").and_then(|v| v.as_u64()), Some(4444));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_parse_single_windows_event_security_4688_xml() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID Qualifiers="16384">4688</EventID>
    <Computer>node-sec</Computer>
    <TimeCreated SystemTime="2026-09-21T05:01:00.000000Z"/>
  </System>
  <EventData>
    <Data Name="NewProcessId">0x1f4</Data>
    <Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
    <Data Name="ParentProcessName">C:\Windows\explorer.exe</Data>
    <Data Name="SubjectUserName">Analyst</Data>
  </EventData>
</Event>"#;

        let ev = parse_single_windows_event(xml, "Security").expect("Should parse");
        assert_eq!(ev.source, "windows:Security");
        assert_eq!(ev.event_id, 4688);
        assert_eq!(ev.data.get("Image").and_then(|v| v.as_str()), Some(r"C:\Windows\System32\cmd.exe"));
        assert_eq!(ev.data.get("ParentImage").and_then(|v| v.as_str()), Some(r"C:\Windows\explorer.exe"));
        assert_eq!(ev.data.get("ProcessId").and_then(|v| v.as_u64()), Some(500));
        assert_eq!(ev.data.get("User").and_then(|v| v.as_str()), Some("Analyst"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_extract_xml_tag_with_self_closing_tag_prefix() {
        let xml = r#"<Event><System><Correlation/><Channel/><EventID>3</EventID><Channel>Microsoft-Windows-Sysmon/Operational</Channel></System></Event>"#;
        assert_eq!(extract_xml_tag(xml, "EventID"), Some("3".to_string()));
        assert_eq!(extract_xml_tag(xml, "Channel"), Some("Microsoft-Windows-Sysmon/Operational".to_string()));
    }
}
