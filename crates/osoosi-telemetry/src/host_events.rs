//! Cross-platform host security event readers.
//!
//! Reads security event logs from Windows Event Log, Linux auditd, and macOS audit.
//! All events are normalized for the policy engine.

#[cfg(not(target_os = "windows"))]
use chrono::Utc;
use osoosi_types::HostSecurityEvent;
#[cfg(not(target_os = "windows"))]
use serde_json::json;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::{BufRead, BufReader};
#[cfg(not(target_os = "windows"))]
use std::path::Path;


/// Trait for platform-specific host event sources.
pub trait HostEventReader: Send + Sync {
    /// Read new events since last poll. Returns normalized HostSecurityEvent list.
    fn poll_events(&mut self) -> anyhow::Result<Vec<HostSecurityEvent>>;
    /// Human-readable source identifier currently used by this reader.
    fn source_name(&self) -> String;
}

/// Create the appropriate reader for the current OS.
pub fn create_host_event_reader(channel_or_path: &str) -> anyhow::Result<Box<dyn HostEventReader + Send + Sync>> {
    #[cfg(target_os = "windows")]
    {
        // On Windows, we use the WindowsEventReader which polls the Event Log (Sysmon).
        // It also starts the NativeETWReader as a background task for injection hooks.
        Ok(Box::new(WindowsEventReader::new(channel_or_path)?))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(LinuxEbpfReader::new(channel_or_path)?))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(MacAuditReader::new(channel_or_path)?))
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Err(anyhow::anyhow!("Unsupported OS for host event reading"))
    }
}

// --- Native eBPF (Linux) ---

#[cfg(target_os = "linux")]
pub struct NativeEbpfReader {
    rx: tokio::sync::mpsc::Receiver<HostSecurityEvent>,
}

#[cfg(target_os = "linux")]
impl NativeEbpfReader {
    pub fn new() -> anyhow::Result<Self> {
        let (tx, rx) = tokio::sync::mpsc::channel(10_000);
        let engine = super::native::NativeTelemetryEngine::new(tx);
        
        tokio::spawn(async move {
            if let Err(e) = engine.run().await {
                tracing::error!("Native Telemetry Engine (Linux eBPF) failed: {}", e);
            }
        });
        
        Ok(Self { rx })
    }
}

#[cfg(target_os = "linux")]
impl HostEventReader for NativeEbpfReader {
    fn poll_events(&mut self) -> anyhow::Result<Vec<HostSecurityEvent>> {
        let mut out = Vec::new();
        while let Ok(event) = self.rx.try_recv() {
            out.push(event);
        }
        Ok(out)
    }

    fn source_name(&self) -> String {
        "native-kernel-ebpf".to_string()
    }
}

#[cfg(target_os = "linux")]
pub struct LinuxEbpfReader {
    audit: LinuxAuditReader,
    ebpf: NativeEbpfReader,
}

#[cfg(target_os = "linux")]
impl LinuxEbpfReader {
    pub fn new(path: &str) -> anyhow::Result<Self> {
        Ok(Self {
            audit: LinuxAuditReader::new(path)?,
            ebpf: NativeEbpfReader::new()?,
        })
    }
}

#[cfg(target_os = "linux")]
impl HostEventReader for LinuxEbpfReader {
    fn poll_events(&mut self) -> anyhow::Result<Vec<HostSecurityEvent>> {
        let mut out = self.audit.poll_events()?;
        if let Ok(mut ebpf_events) = self.ebpf.poll_events() {
            out.append(&mut ebpf_events);
        }
        Ok(out)
    }

    fn source_name(&self) -> String {
        format!("linux-ebpf-hybrid:{}", self.audit.path)
    }
}

// --- Native ETW (SysmonX Port) ---

#[cfg(target_os = "windows")]
pub struct NativeETWReader {
    rx: tokio::sync::mpsc::Receiver<HostSecurityEvent>,
}

#[cfg(target_os = "windows")]
impl NativeETWReader {
    pub fn new() -> anyhow::Result<Self> {
        let (tx, rx) = tokio::sync::mpsc::channel(10_000);
        let engine = super::native::NativeTelemetryEngine::new(tx);
        
        // Spawn the native engine in a background task
        tokio::spawn(async move {
            if let Err(e) = engine.run().await {
                tracing::error!("Native Telemetry Engine failed: {}", e);
            }
        });
        
        Ok(Self { rx })
    }
}

#[cfg(target_os = "windows")]
impl HostEventReader for NativeETWReader {
    fn poll_events(&mut self) -> anyhow::Result<Vec<HostSecurityEvent>> {
        let mut out = Vec::new();
        // Drain the channel buffer
        while let Ok(event) = self.rx.try_recv() {
            out.push(event);
        }
        Ok(out)
    }

    fn source_name(&self) -> String {
        "native-kernel-etw".to_string()
    }
}

#[cfg(target_os = "windows")]
#[derive(Clone, Debug)]
pub struct WindowsChannelSubscription {
    pub channel: String,
    pub query_filter: Option<String>,
    pub last_poll_time: Option<chrono::DateTime<chrono::Utc>>,
    pub is_available: bool,
}

#[cfg(target_os = "windows")]
pub struct WindowsEventReader {
    channels: Vec<WindowsChannelSubscription>,
    native: NativeETWReader,
}

#[cfg(target_os = "windows")]
impl WindowsEventReader {
    pub fn new(channel: &str) -> anyhow::Result<Self> {
        let mut channels = Vec::new();

        if channel.is_empty() || channel == "default" || channel == "Microsoft-Windows-Sysmon/Operational" {
            // Sysmon: capture ALL Sysmon event IDs (no restrictive filter)
            channels.push(WindowsChannelSubscription {
                channel: "Microsoft-Windows-Sysmon/Operational".to_string(),
                query_filter: None,
                last_poll_time: None,
                is_available: true,
            });
            // Concurrently ingest Windows Security (Audit Process Creation / Event 4688) so no blindness occurs
            channels.push(WindowsChannelSubscription {
                channel: "Security".to_string(),
                query_filter: Some("EventID=4688".to_string()),
                last_poll_time: None,
                is_available: true,
            });
            // Native Windows DNS Client Operational channel
            channels.push(WindowsChannelSubscription {
                channel: "Microsoft-Windows-DNS-Client/Operational".to_string(),
                query_filter: None,
                last_poll_time: None,
                is_available: true,
            });
        } else {
            // User requested a specific channel
            channels.push(WindowsChannelSubscription {
                channel: channel.to_string(),
                query_filter: None,
                last_poll_time: None,
                is_available: true,
            });
            // Concurrently retain Security 4688 if not already Security
            if channel != "Security" {
                channels.push(WindowsChannelSubscription {
                    channel: "Security".to_string(),
                    query_filter: Some("EventID=4688".to_string()),
                    last_poll_time: None,
                    is_available: true,
                });
            }
        }

        Ok(Self {
            channels,
            native: NativeETWReader::new()?,
        })
    }

    pub fn split_event_xml(xml: &str) -> Vec<String> {
        let mut out = Vec::new();
        for block in xml.split("<Event xmlns=").filter(|s| !s.trim().is_empty()) {
            if block.contains("</Event>") {
                out.push(format!("<Event xmlns={}", block));
            }
        }
        out
    }
}

#[cfg(target_os = "windows")]
impl HostEventReader for WindowsEventReader {
    fn poll_events(&mut self) -> anyhow::Result<Vec<HostSecurityEvent>> {
        use windows::core::HSTRING;
        use windows::Win32::System::EventLog::{
            EvtQuery, EvtNext, EvtRender, EvtClose, EvtRenderEventXml,
            EvtQueryChannelPath, EvtQueryForwardDirection, EVT_HANDLE
        };

        let mut out = Vec::new();
        
        // 1. Get hook events from native engine
        if let Ok(mut native_events) = self.native.poll_events() {
            out.append(&mut native_events);
        }

        // 2. Poll configured Event Log channels concurrently
        for sub in &mut self.channels {
            let mut query = match &sub.query_filter {
                Some(filter) => format!("*[System[({}) and TimeCreated[timediff(@SystemTime) <= 3600000]]]", filter),
                None => "*[System[TimeCreated[timediff(@SystemTime) <= 3600000]]]".to_string(),
            };

            if let Some(t) = sub.last_poll_time {
                let ts_str = t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                query = match &sub.query_filter {
                    Some(filter) => format!("*[System[({}) and TimeCreated[@SystemTime > '{}']]]", filter, ts_str),
                    None => format!("*[System[TimeCreated[@SystemTime > '{}']]]", ts_str),
                };
            }

            let channel_h = HSTRING::from(&sub.channel);
            let query_h = HSTRING::from(query);

            let handle = unsafe {
                match EvtQuery(
                    None,
                    &channel_h,
                    &query_h,
                    EvtQueryChannelPath.0 | EvtQueryForwardDirection.0,
                ) {
                    Ok(h) => {
                        if !sub.is_available {
                            tracing::info!(
                                "Windows event channel '{}' is now available and connected.",
                                sub.channel
                            );
                            sub.is_available = true;
                        }
                        h
                    }
                    Err(e) => {
                        if sub.is_available {
                            tracing::info!(
                                "Windows event channel '{}' not currently available ({}). Will dynamically verify each poll.",
                                sub.channel, e
                            );
                            sub.is_available = false;
                        }
                        continue;
                    }
                }
            };

            let mut channel_events = Vec::new();
            unsafe {
                let mut events = [0isize; 100];
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
                            
                            if let Some(ev) = Self::parse_xml(clean_xml) {
                                channel_events.push(ev);
                            }
                        }
                        let _ = EvtClose(evt);
                    }
                }
                let _ = EvtClose(handle);
            }

            if let Some(latest) = channel_events.iter().map(|e| e.timestamp).max() {
                sub.last_poll_time = Some(latest);
            } else if sub.last_poll_time.is_none() {
                sub.last_poll_time = Some(chrono::Utc::now());
            }

            out.append(&mut channel_events);
        }

        Ok(out)
    }

    fn source_name(&self) -> String {
        let active: Vec<&str> = self
            .channels
            .iter()
            .map(|c| c.channel.as_str())
            .collect();
        format!("windows-event-log:{}", active.join("+"))
    }
}

#[cfg(target_os = "windows")]
impl WindowsEventReader {
    pub fn parse_xml(xml: &str) -> Option<HostSecurityEvent> {
        let event_id = Self::extract_tag_value(xml, "EventID")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        
        let computer = Self::extract_tag_value(xml, "Computer").unwrap_or_else(|| "localhost".to_string());
        
        // Extract timestamp from TimeCreated SystemTime attribute
        let timestamp = Self::extract_tag_attribute(xml, "TimeCreated", "SystemTime")
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(chrono::Utc::now);

        let provider = Self::extract_tag_attribute(xml, "Provider", "Name");
        let channel = Self::extract_tag_value(xml, "Channel");

        let mut data = serde_json::Map::new();

        if let Some(p) = provider {
            data.insert("Provider".to_string(), serde_json::json!(p));
        }
        if let Some(c) = channel {
            data.insert("Channel".to_string(), serde_json::json!(c));
        }

        // Extract EventData key-value pairs
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
                                    data.insert(name, serde_json::json!(val));
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

        if let Some(record_id) = Self::extract_tag_value(xml, "EventRecordID") {
            data.insert("EventRecordID".to_string(), serde_json::json!(record_id));
        }

        // For Event ID 3008 (DNS Client query completed), ensure fields like QueryName, QueryType, QueryResults, QueryStatus are populated into data
        if event_id == 3008 {
            let dns_fields = [
                "QueryName",
                "QueryType",
                "QueryResults",
                "QueryStatus",
                "QueryOptions",
            ];
            for field in dns_fields {
                if !data.contains_key(field) {
                    if let Some(val) = Self::extract_tag_value(xml, field) {
                        data.insert(field.to_string(), serde_json::json!(val));
                    }
                }
            }
            // Positional fallback if EventData had unnamed <Data>...</Data>
            if !data.contains_key("QueryName") {
                if let Some(v) = data.get("Data_0").cloned() {
                    data.insert("QueryName".to_string(), v);
                }
            }
            if !data.contains_key("QueryType") {
                if let Some(v) = data.get("Data_1").cloned() {
                    data.insert("QueryType".to_string(), v);
                }
            }
            if !data.contains_key("QueryOptions") {
                if let Some(v) = data.get("Data_2").cloned() {
                    data.insert("QueryOptions".to_string(), v);
                }
            }
            if !data.contains_key("QueryStatus") {
                if let Some(v) = data.get("Data_3").cloned() {
                    data.insert("QueryStatus".to_string(), v);
                }
            }
            if !data.contains_key("QueryResults") {
                if let Some(v) = data.get("Data_4").cloned() {
                    data.insert("QueryResults".to_string(), v);
                }
            }
        }

        // --- NORMALIZATION ---
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

        // Windows Security Event 4688 normalization
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

        // Sysmon ProcessAccess (10) and CreateRemoteThread (8) normalization
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

        // If ProcessId is not found in EventData, check <Execution ProcessID="..." /> and parse as integer
        if !data.contains_key("ProcessId") {
            if let Some(exec_pid_str) = Self::extract_tag_attribute(xml, "Execution", "ProcessID")
                .or_else(|| Self::extract_tag_attribute(xml, "Execution", "ProcessId"))
            {
                let trimmed = exec_pid_str.trim();
                let parsed = if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
                    u64::from_str_radix(hex, 16).ok()
                } else {
                    trimmed.parse::<u64>().ok()
                };
                if let Some(pid) = parsed {
                    data.insert("ProcessId".to_string(), serde_json::json!(pid));
                }
            }
        }

        Some(HostSecurityEvent {
            source: osoosi_types::HostEventSource::WindowsEventLog,
            event_id,
            timestamp,
            computer,
            data: serde_json::Value::Object(data),
            causal_parent: None,
        })
    }

    pub fn extract_tag_value(xml: &str, tag: &str) -> Option<String> {
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

    pub fn extract_tag_attribute(xml: &str, tag: &str, attr: &str) -> Option<String> {
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
                        let attr_pattern = format!("{}=\"", attr);
                        if let Some(attr_idx) = tag_header.find(&attr_pattern) {
                            let val_start = attr_idx + attr_pattern.len();
                            if let Some(val_end) = tag_header[val_start..].find('"') {
                                return Some(tag_header[val_start..val_start + val_end].to_string());
                            }
                        }
                        let attr_single = format!("{}='", attr);
                        if let Some(attr_idx) = tag_header.find(&attr_single) {
                            let val_start = attr_idx + attr_single.len();
                            if let Some(val_end) = tag_header[val_start..].find('\'') {
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
}

#[cfg(all(test, target_os = "windows"))]
mod windows_tests {
    use super::*;

    fn sample_sysmon_xml(record_id: u64, image: &str) -> String {
        format!(
            r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon"/>
    <EventID>1</EventID>
    <Computer>test-host</Computer>
    <EventRecordID>{record_id}</EventRecordID>
    <TimeCreated SystemTime="2026-09-21T05:10:00.000000Z"/>
  </System>
  <EventData>
    <Data Name="Image">{image}</Data>
    <Data Name="ProcessId">4242</Data>
  </EventData>
</Event>"#
        )
    }

    #[test]
    fn splits_namespaced_concatenated_wevtutil_xml() {
        let blob = format!(
            "{}{}",
            sample_sysmon_xml(10, r"C:\Windows\System32\cmd.exe"),
            sample_sysmon_xml(11, r"C:\Windows\System32\notepad.exe")
        );

        let events = WindowsEventReader::split_event_xml(&blob);
        assert_eq!(events.len(), 2);
        assert!(events[0].starts_with("<Event"));
        assert!(events[0].contains("<EventRecordID>10</EventRecordID>"));
        assert!(events[1].contains("<EventRecordID>11</EventRecordID>"));
    }

    #[tokio::test]
    async fn parses_namespaced_sysmon_xml() {
        let event = WindowsEventReader::parse_xml(&sample_sysmon_xml(12, r"C:\Windows\System32\cmd.exe"))
            .expect("namespaced Sysmon XML should parse");

        assert_eq!(event.event_id as u32, 1);
        assert_eq!(event.computer, "test-host");
        assert_eq!(
            event.data.get("Image").and_then(|v| v.as_str()),
            Some(r"C:\Windows\System32\cmd.exe")
        );
        assert_eq!(
            event.data.get("EventRecordID").and_then(|v| v.as_str()),
            Some("12")
        );
        assert_eq!(
            event.data.get("Provider").and_then(|v| v.as_str()),
            Some("Microsoft-Windows-Sysmon")
        );
    }

    #[tokio::test]
    async fn parses_windows_security_4688_xml_with_normalization() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID Qualifiers="0">4688</EventID>
    <Computer>sec-host</Computer>
    <EventRecordID>9988</EventRecordID>
    <TimeCreated SystemTime="2026-09-21T05:12:00.000000Z"/>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="NewProcessId">0x10a4</Data>
    <Data Name="NewProcessName">C:\Windows\System32\whoami.exe</Data>
    <Data Name="CommandLine">whoami /all</Data>
    <Data Name="ParentProcessName">C:\Windows\System32\cmd.exe</Data>
    <Data Name="SubjectUserName">AdminUser</Data>
  </EventData>
</Event>"#;

        let event = WindowsEventReader::parse_xml(xml).expect("Security 4688 XML should parse");

        assert_eq!(event.event_id, 4688);
        assert_eq!(event.computer, "sec-host");
        assert_eq!(
            event.data.get("Image").and_then(|v| v.as_str()),
            Some(r"C:\Windows\System32\whoami.exe")
        );
        assert_eq!(
            event.data.get("ParentImage").and_then(|v| v.as_str()),
            Some(r"C:\Windows\System32\cmd.exe")
        );
        assert_eq!(
            event.data.get("ProcessId").and_then(|v| v.as_u64()),
            Some(4260) // 0x10a4 = 4260
        );
        assert_eq!(
            event.data.get("User").and_then(|v| v.as_str()),
            Some("AdminUser")
        );
    }

    #[tokio::test]
    async fn parses_sysmon_process_access_and_dns() {
        // Sysmon Event 10: ProcessAccess
        let xml_10 = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon"/>
    <EventID>10</EventID>
    <Computer>target-box</Computer>
  </System>
  <EventData>
    <Data Name="SourceProcessId">5500</Data>
    <Data Name="SourceImage">C:\Tools\mimikatz.exe</Data>
    <Data Name="TargetProcessId">672</Data>
    <Data Name="TargetImage">C:\Windows\System32\lsass.exe</Data>
    <Data Name="GrantedAccess">0x1010</Data>
  </EventData>
</Event>"#;
        let ev10 = WindowsEventReader::parse_xml(xml_10).expect("Sysmon 10 should parse");
        assert_eq!(ev10.event_id, 10);
        assert_eq!(ev10.data.get("Image").and_then(|v| v.as_str()), Some(r"C:\Tools\mimikatz.exe"));
        assert_eq!(ev10.data.get("ProcessId").and_then(|v| v.as_u64()), Some(5500));
        assert_eq!(ev10.data.get("TargetProcessId").and_then(|v| v.as_u64()), Some(672));
        assert_eq!(ev10.data.get("TargetImage").and_then(|v| v.as_str()), Some(r"C:\Windows\System32\lsass.exe"));

        // Sysmon Event 22: DNS Query
        let xml_22 = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon"/>
    <EventID>22</EventID>
    <Computer>dns-box</Computer>
  </System>
  <EventData>
    <Data Name="ProcessId">1234</Data>
    <Data Name="Image">C:\Windows\System32\curl.exe</Data>
    <Data Name="QueryName">c2.malicious.net</Data>
    <Data Name="QueryStatus">0</Data>
  </EventData>
</Event>"#;
        let ev22 = WindowsEventReader::parse_xml(xml_22).expect("Sysmon 22 should parse");
        assert_eq!(ev22.event_id, 22);
        assert_eq!(ev22.data.get("ProcessId").and_then(|v| v.as_u64()), Some(1234));
        assert_eq!(ev22.data.get("QueryName").and_then(|v| v.as_str()), Some("c2.malicious.net"));

        // Sysmon Event 3: Network Connect
        let xml_3 = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon"/>
    <EventID>3</EventID>
    <Computer>net-box</Computer>
  </System>
  <EventData>
    <Data Name="ProcessId">8899</Data>
    <Data Name="Image">C:\Tools\nc.exe</Data>
    <Data Name="DestinationIp">198.51.100.23</Data>
    <Data Name="DestinationPort">4444</Data>
  </EventData>
</Event>"#;
        let ev3 = WindowsEventReader::parse_xml(xml_3).expect("Sysmon 3 should parse");
        assert_eq!(ev3.event_id, 3);
        assert_eq!(ev3.data.get("ProcessId").and_then(|v| v.as_u64()), Some(8899));
        assert_eq!(ev3.data.get("DestinationPort").and_then(|v| v.as_u64()), Some(4444));

        // Sysmon Event 7: ImageLoaded should NOT populate TargetFilename
        let xml_7 = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon"/>
    <EventID>7</EventID>
    <Computer>img-box</Computer>
  </System>
  <EventData>
    <Data Name="ProcessId">3344</Data>
    <Data Name="Image">C:\Windows\System32\cmd.exe</Data>
    <Data Name="ImageLoaded">C:\Windows\System32\amsi.dll</Data>
  </EventData>
</Event>"#;
        let ev7 = WindowsEventReader::parse_xml(xml_7).expect("Sysmon 7 should parse");
        assert_eq!(ev7.event_id, 7);
        assert_eq!(ev7.data.get("ImageLoaded").and_then(|v| v.as_str()), Some(r"C:\Windows\System32\amsi.dll"));
        assert_eq!(ev7.data.get("TargetFilename"), None);
    }

    #[test]
    fn test_extract_tag_value_with_self_closing_tag_prefix() {
        let xml = r#"<Event><System><Correlation/><Channel/><EventID>1</EventID><Channel>Security</Channel></System></Event>"#;
        assert_eq!(WindowsEventReader::extract_tag_value(xml, "EventID"), Some("1".to_string()));
        assert_eq!(WindowsEventReader::extract_tag_value(xml, "Channel"), Some("Security".to_string()));
    }

    #[tokio::test]
    async fn parses_sysmon_dns_event_22_comprehensive() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/>
    <EventID>22</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Computer>win-sensor-01</Computer>
    <EventRecordID>34567</EventRecordID>
    <TimeCreated SystemTime="2026-09-23T20:15:30.000000Z"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2026-09-23 20:15:30.123</Data>
    <Data Name="ProcessGuid">{B856338C-D9AA-63D1-2B00-000000000E00}</Data>
    <Data Name="ProcessId">4321</Data>
    <Data Name="QueryName">c2.malicious.example.com</Data>
    <Data Name="QueryStatus">0</Data>
    <Data Name="QueryResults">::ffff:192.0.2.1;198.51.100.10;</Data>
    <Data Name="Image">C:\Windows\System32\curl.exe</Data>
    <Data Name="User">WORKGROUP\SYSTEM</Data>
  </EventData>
</Event>"#;

        let event = WindowsEventReader::parse_xml(xml).expect("Sysmon Event 22 should parse");
        assert_eq!(event.event_id, 22);
        assert_eq!(event.computer, "win-sensor-01");
        assert_eq!(
            event.data.get("Provider").and_then(|v| v.as_str()),
            Some("Microsoft-Windows-Sysmon")
        );
        assert_eq!(
            event.data.get("ProcessId").and_then(|v| v.as_u64()),
            Some(4321)
        );
        assert_eq!(
            event.data.get("QueryName").and_then(|v| v.as_str()),
            Some("c2.malicious.example.com")
        );
        assert_eq!(
            event.data.get("QueryStatus").and_then(|v| v.as_str()),
            Some("0")
        );
        assert_eq!(
            event.data.get("QueryResults").and_then(|v| v.as_str()),
            Some("::ffff:192.0.2.1;198.51.100.10;")
        );
        assert_eq!(
            event.data.get("Image").and_then(|v| v.as_str()),
            Some(r"C:\Windows\System32\curl.exe")
        );
    }

    #[tokio::test]
    async fn parses_windows_dns_client_event_3008() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-DNS-Client" Guid="{1C950233-BE22-409B-B16E-2E3890372570}"/>
    <EventID>3008</EventID>
    <Version>0</Version>
    <Level>4</Level>
    <Task>1014</Task>
    <Opcode>0</Opcode>
    <Keywords>0x4000000000000000</Keywords>
    <TimeCreated SystemTime="2026-09-23T20:20:00.000000Z"/>
    <EventRecordID>98765</EventRecordID>
    <Execution ProcessID="5544" ThreadID="1122"/>
    <Channel>Microsoft-Windows-DNS-Client/Operational</Channel>
    <Computer>dns-host-01</Computer>
  </System>
  <EventData>
    <Data Name="QueryName">api.github.com</Data>
    <Data Name="QueryType">1</Data>
    <Data Name="QueryOptions">1073741824</Data>
    <Data Name="QueryStatus">0</Data>
    <Data Name="QueryResults">140.82.121.4;</Data>
  </EventData>
</Event>"#;

        let event = WindowsEventReader::parse_xml(xml).expect("Windows DNS Client Event 3008 should parse");
        assert_eq!(event.event_id, 3008);
        assert_eq!(event.computer, "dns-host-01");
        assert_eq!(
            event.data.get("Provider").and_then(|v| v.as_str()),
            Some("Microsoft-Windows-DNS-Client")
        );
        assert_eq!(
            event.data.get("Channel").and_then(|v| v.as_str()),
            Some("Microsoft-Windows-DNS-Client/Operational")
        );
        // ProcessID must be extracted from <Execution ProcessID="5544" ... />
        assert_eq!(
            event.data.get("ProcessId").and_then(|v| v.as_u64()),
            Some(5544)
        );
        assert_eq!(
            event.data.get("QueryName").and_then(|v| v.as_str()),
            Some("api.github.com")
        );
        assert_eq!(
            event.data.get("QueryType").and_then(|v| v.as_str()),
            Some("1")
        );
        assert_eq!(
            event.data.get("QueryStatus").and_then(|v| v.as_str()),
            Some("0")
        );
        assert_eq!(
            event.data.get("QueryResults").and_then(|v| v.as_str()),
            Some("140.82.121.4;")
        );
    }

    #[tokio::test]
    async fn parses_windows_dns_client_event_3008_hex_pid() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-DNS-Client"/>
    <EventID>3008</EventID>
    <Execution ProcessID="0x15A8"/>
    <Channel>Microsoft-Windows-DNS-Client/Operational</Channel>
  </System>
  <EventData>
    <Data Name="QueryName">update.microsoft.com</Data>
    <Data Name="QueryType">28</Data>
    <Data Name="QueryStatus">0</Data>
    <Data Name="QueryResults">2603:1030:b:1::1f;</Data>
  </EventData>
</Event>"#;

        let event = WindowsEventReader::parse_xml(xml).expect("Hex ProcessID 3008 should parse");
        assert_eq!(event.event_id, 3008);
        // 0x15A8 = 5544
        assert_eq!(
            event.data.get("ProcessId").and_then(|v| v.as_u64()),
            Some(5544)
        );
        assert_eq!(
            event.data.get("QueryName").and_then(|v| v.as_str()),
            Some("update.microsoft.com")
        );
        assert_eq!(
            event.data.get("QueryResults").and_then(|v| v.as_str()),
            Some("2603:1030:b:1::1f;")
        );
    }

    #[tokio::test]
    async fn parses_windows_dns_client_event_3008_unnamed_data() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-DNS-Client"/>
    <EventID>3008</EventID>
    <Execution ProcessID="7788"/>
  </System>
  <EventData>
    <Data>auth.example.org</Data>
    <Data>1</Data>
    <Data>0</Data>
    <Data>0</Data>
    <Data>192.0.2.53;</Data>
  </EventData>
</Event>"#;

        let event = WindowsEventReader::parse_xml(xml).expect("Unnamed EventData 3008 should parse");
        assert_eq!(event.event_id, 3008);
        assert_eq!(
            event.data.get("ProcessId").and_then(|v| v.as_u64()),
            Some(7788)
        );
        assert_eq!(
            event.data.get("QueryName").and_then(|v| v.as_str()),
            Some("auth.example.org")
        );
        assert_eq!(
            event.data.get("QueryType").and_then(|v| v.as_str()),
            Some("1")
        );
        assert_eq!(
            event.data.get("QueryResults").and_then(|v| v.as_str()),
            Some("192.0.2.53;")
        );
    }
}

// --- Linux ---

#[cfg(target_os = "linux")]
struct LinuxAuditReader {
    path: String,
    last_pos: u64,
    is_audit_format: bool,
}

#[cfg(target_os = "linux")]
impl LinuxAuditReader {
    fn new(path: &str) -> anyhow::Result<Self> {
        let p = if path.is_empty() || path == "default" {
            if Path::new("/var/log/audit/audit.log").exists() {
                "/var/log/audit/audit.log"
            } else {
                "/var/log/auth.log"
            }
        } else {
            path
        };
        let is_audit_format = p.contains("audit");
        Ok(Self {
            path: p.to_string(),
            last_pos: 0,
            is_audit_format,
        })
    }

    fn parse_audit_line(&self, line: &str) -> Option<HostSecurityEvent> {
        if self.is_audit_format && line.starts_with("type=") {
            self.parse_audit_format(line)
        } else if !self.is_audit_format || !line.starts_with("type=") {
            self.parse_auth_log_format(line)
        } else {
            None
        }
    }

    fn parse_auth_log_format(&self, line: &str) -> Option<HostSecurityEvent> {
        let mut data = serde_json::Map::new();
        data.insert("raw".to_string(), json!(line));
        let cmd = if line.contains("Accepted") || line.contains("Failed") {
            "sshd"
        } else if line.contains("session opened") || line.contains("session closed") {
            "pam"
        } else {
            "auth"
        };
        data.insert("Image".to_string(), json!(cmd));
        data.insert("CommandLine".to_string(), json!(line));
        Some(HostSecurityEvent {
            source: HostEventSource::LinuxAuthLog,
            event_id: 4624,
            timestamp: Utc::now(),
            computer: hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "localhost".to_string()),
            data: json!(data),
            causal_parent: None,
        })
    }

    fn parse_audit_format(&self, line: &str) -> Option<HostSecurityEvent> {
        let mut data = serde_json::Map::new();
        let mut event_type = "";
        let mut msg_ts = 0.0f64;

        for part in line.split_whitespace() {
            if let Some((k, v)) = part.split_once('=') {
                let v = v.trim_matches('"');
                match k {
                    "type" => event_type = v,
                    "msg" => {
                        if let Some(ts) = v.strip_prefix("audit(").and_then(|s| s.split(':').next())
                        {
                            msg_ts = ts.parse().unwrap_or(0.0);
                        }
                    }
                    "exe" => {
                        data.insert("Image".to_string(), json!(v));
                    }
                    "comm" => {
                        data.insert("CommandLine".to_string(), json!(v));
                    }
                    "key" => {
                        data.insert("key".to_string(), json!(v));
                    }
                    "pid" => {
                        if let Ok(n) = v.parse::<u32>() {
                            data.insert("ProcessId".to_string(), json!(n));
                        }
                    }
                    "success" => {
                        data.insert("success".to_string(), json!(v));
                    }
                    "syscall" => {
                        data.insert("syscall".to_string(), json!(v));
                    }
                    _ => {
                        data.insert(k.to_string(), json!(v));
                    }
                }
            }
        }

        let event_id = match event_type {
            "SYSCALL" => 1,
            "EXECVE" => 1,
            "PATH" => 11,
            "SOCKADDR" => 3,
            "USER_LOGIN" => 4624,
            _ => 0,
        };

        if !data.contains_key("CommandLine") {
            data.insert("CommandLine".to_string(), json!(event_type));
        }
        if !data.contains_key("Image") {
            data.insert(
                "Image".to_string(),
                json!(data
                    .get("CommandLine")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")),
            );
        }

        let timestamp = if msg_ts > 0.0 {
            chrono::DateTime::from_timestamp(msg_ts as i64, 0)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now)
        } else {
            Utc::now()
        };

        Some(HostSecurityEvent {
            source: HostEventSource::LinuxAudit,
            event_id,
            timestamp,
            computer: hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "localhost".to_string()),
            data: json!(data),
            causal_parent: None,
        })
    }
}

#[cfg(target_os = "linux")]
impl HostEventReader for LinuxAuditReader {
    fn poll_events(&mut self) -> anyhow::Result<Vec<HostSecurityEvent>> {
        let file = File::open(&self.path)?;
        let meta = file.metadata()?;
        let file_len = meta.len();
        let reader = BufReader::new(file);
        let mut out = Vec::new();

        if self.is_audit_format {
            let mut current_record = String::new();
            for line in reader.lines().flatten() {
                if line.starts_with("type=") {
                    if !current_record.is_empty() {
                        if let Some(ev) = self.parse_audit_line(&current_record) {
                            out.push(ev);
                        }
                    }
                    current_record = line;
                } else if !current_record.is_empty() {
                    current_record.push(' ');
                    current_record.push_str(&line);
                }
            }
            if !current_record.is_empty() {
                if let Some(ev) = self.parse_audit_line(&current_record) {
                    out.push(ev);
                }
            }
        } else {
            for line in reader.lines().flatten().rev().take(50) {
                if line.contains("Accepted") || line.contains("Failed") || line.contains("session")
                {
                    if let Some(ev) = self.parse_audit_line(&line) {
                        out.push(ev);
                    }
                }
            }
        }

        self.last_pos = file_len;
        Ok(out)
    }

    fn source_name(&self) -> String {
        format!("linux-log:{}", self.path)
    }
}

// --- macOS ---

#[cfg(target_os = "macos")]
struct MacAuditReader {
    path: String,
}

#[cfg(target_os = "macos")]
struct MacAuditReader {
    path: String,
}

#[cfg(target_os = "macos")]
impl MacAuditReader {
    fn new(path: &str) -> anyhow::Result<Self> {
        let p = if path.is_empty() || path == "default" {
            "/var/log/secure.log"
        } else {
            path
        };
        Ok(Self {
            path: p.to_string(),
        })
    }

    fn parse_syslog_line(&self, line: &str) -> Option<HostSecurityEvent> {
        let mut data = serde_json::Map::new();
        data.insert("raw".to_string(), json!(line));
        if let Some(msg) = line.splitn(5, ' ').nth(4) {
            data.insert("CommandLine".to_string(), json!(msg));
            if msg.contains("sshd") || msg.contains("login") {
                data.insert("Image".to_string(), json!("sshd"));
            } else {
                data.insert("Image".to_string(), json!("system"));
            }
        } else {
            data.insert("Image".to_string(), json!("unknown"));
            data.insert("CommandLine".to_string(), json!(line));
        }
        Some(HostSecurityEvent {
            source: HostEventSource::MacAudit,
            event_id: 0,
            timestamp: Utc::now(),
            computer: hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "localhost".to_string()),
            data: json!(data),
            causal_parent: None,
        })
    }
}

#[cfg(target_os = "macos")]
impl HostEventReader for MacAuditReader {
    fn poll_events(&mut self) -> anyhow::Result<Vec<HostSecurityEvent>> {
        let mut out = Vec::new();
        if Path::new(&self.path).exists() {
            if let Ok(content) = std::fs::read_to_string(&self.path) {
                for line in content.lines().rev().take(50) {
                    if line.contains("Accepted")
                        || line.contains("Failed")
                        || line.contains("session")
                    {
                        if let Some(ev) = self.parse_syslog_line(line) {
                            out.push(ev);
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    fn source_name(&self) -> String {
        format!("mac-log:{}", self.path)
    }
}

// --- Synthetic Canary Telemetry Stream Integration ---

/// Maps an incoming HostSecurityEvent to its corresponding CanaryChannel and string payload.
pub fn event_to_canary_payload(event: &HostSecurityEvent) -> Option<(crate::canary::CanaryChannel, String)> {
    let payload = event.data.to_string();
    let channel = match (event.source, event.event_id) {
        (osoosi_types::HostEventSource::WindowsEventLog, 1 | 4688) => Some(crate::canary::CanaryChannel::ProcessCreation),
        (osoosi_types::HostEventSource::LinuxAudit | osoosi_types::HostEventSource::Ebpf | osoosi_types::HostEventSource::MacAudit | osoosi_types::HostEventSource::MacUnifiedLog, 1 | 59 | 221) => Some(crate::canary::CanaryChannel::ProcessCreation),
        (osoosi_types::HostEventSource::WindowsEventLog, 22 | 3008) => Some(crate::canary::CanaryChannel::DnsResolution),
        (osoosi_types::HostEventSource::WindowsEventLog, 7) => Some(crate::canary::CanaryChannel::ImageLoad),
        _ => {
            if crate::canary::is_canary_payload(&payload) {
                if payload.contains(".probe.invalid") || payload.contains("probe.invalid") {
                    Some(crate::canary::CanaryChannel::DnsResolution)
                } else if payload.contains("osoosi_canary_") {
                    Some(crate::canary::CanaryChannel::ImageLoad)
                } else {
                    Some(crate::canary::CanaryChannel::ProcessCreation)
                }
            } else {
                None
            }
        }
    }?;

    Some((channel, payload))
}

// Internal import of inspect_event_for_canary for batch helper
use crate::canary::inspect_event_for_canary;

/// Batch inspection of incoming HostSecurityEvents against a CanaryCorrelator.
pub fn inspect_events_for_canary_batch(
    correlator: &mut crate::canary::CanaryCorrelator,
    events: &[HostSecurityEvent],
) -> Vec<uuid::Uuid> {
    events
        .iter()
        .filter_map(|ev| inspect_event_for_canary(correlator, ev))
        .collect()
}

