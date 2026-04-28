//! Cross-platform log readers: Windows (System, Application, Security),
//! Linux (journald, syslog), macOS (unified log, system.log).

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::warn;

/// A single log event from any platform, normalized for behavioral analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub source: String,
    pub event_id: u32,
    pub timestamp: DateTime<Utc>,
    pub computer: String,
    pub data: HashMap<String, serde_json::Value>,
}

/// Cross-platform behavioral log reader.
/// Reads System, Application, and Security logs (Windows) or equivalents (Linux, macOS).
pub struct BehavioralLogReader {
    #[cfg(target_os = "windows")]
    channels: Vec<String>,
    #[cfg(target_os = "windows")]
    last_poll_time: std::sync::Arc<std::sync::Mutex<Option<chrono::DateTime<chrono::Utc>>>>,
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
                last_poll_time: std::sync::Arc::new(std::sync::Mutex::new(None)),
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
        use windows::core::{HSTRING, w, PCWSTR};
        use windows::Win32::System::EventLog::{
            EvtQuery, EvtNext, EvtRender, EvtClose, EvtRenderEventXml,
            EvtQueryChannelPath, EvtQueryForwardDirection, EVT_HANDLE
        };
        use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS, GetLastError};

        let mut query = format!("*[System[TimeCreated[timediff(@SystemTime) <= 600000]]]");
        
        {
            let last_time = self.last_poll_time.lock().unwrap();
            if let Some(t) = *last_time {
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
                    warn!("EvtQuery failed for {}: {}", channel, e);
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

        // Update watermark
        if let Some(latest) = out.iter().map(|e| e.timestamp).max() {
            let mut last_time = self.last_poll_time.lock().unwrap();
            *last_time = Some(latest);
        }

        Ok(out)
    }

    fn parse_windows_xml(xml: &str, channel: &str) -> Result<Vec<LogEvent>> {
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

    let time_str = extract_xml_tag(xml, "TimeCreated")
        .and_then(|s| extract_xml_attr(&s, "SystemTime"))
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
    if let Some(provider) = extract_xml_tag(xml, "Provider") {
        data.insert("Provider".to_string(), serde_json::json!(provider));
    }
    for (name, value) in extract_event_data(xml) {
        data.insert(name, serde_json::json!(value));
    }

    Some(LogEvent {
        source: format!("windows:{}", channel),
        event_id,
        timestamp,
        computer,
        data,
    })
}

#[cfg(target_os = "windows")]
fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    xml.find(&open)
        .map(|start| start + open.len())
        .and_then(|start| xml[start..].find(&close).map(|end| (start, start + end)))
        .map(|(start, end)| xml[start..end].trim().to_string())
}

#[cfg(target_os = "windows")]
fn extract_xml_attr(xml: &str, attr: &str) -> Option<String> {
    let pattern = format!("{}=\"", attr);
    xml.find(&pattern)
        .map(|i| i + pattern.len())
        .and_then(|start| xml[start..].find('"').map(|end| (start, start + end)))
        .map(|(start, end)| xml[start..end].to_string())
}

#[cfg(target_os = "windows")]
fn extract_event_data(xml: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(data) = xml
        .split("<EventData>")
        .nth(1)
        .and_then(|s| s.split("</EventData>").next())
    {
        for part in data.split("<Data Name=\"") {
            if part.contains("</Data>") {
                if let Some(name_end) = part.find('"') {
                    let name = part[..name_end].to_string();
                    if let Some(val_start) = part.find(">") {
                        let after_gt = &part[val_start + 1..];
                        if let Some(val_end) = after_gt.find("</Data>") {
                            let val = after_gt[..val_end].trim().to_string();
                            if !name.is_empty() {
                                out.push((name, val));
                            }
                        }
                    }
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
