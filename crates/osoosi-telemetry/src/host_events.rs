//! Cross-platform host security event readers.
//!
//! Reads security event logs from Windows Event Log, Linux auditd, and macOS audit.
//! All events are normalized for the policy engine.

#[cfg(not(target_os = "windows"))]
use chrono::Utc;
use osoosi_types::{HostEventSource, HostSecurityEvent};
#[cfg(not(target_os = "windows"))]
use serde_json::json;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::{BufRead, BufReader};
#[cfg(not(target_os = "windows"))]
use std::path::Path;
#[cfg(target_os = "windows")]
use tracing::info;

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
pub struct WindowsEventReader {
    channel: String,
    last_poll_time: Option<chrono::DateTime<chrono::Utc>>,
    native: NativeETWReader,
}

#[cfg(target_os = "windows")]
impl WindowsEventReader {
    pub fn new(channel: &str) -> anyhow::Result<Self> {
        let channel = if channel.is_empty() || channel == "default" {
            "Microsoft-Windows-Sysmon/Operational".to_string()
        } else {
            channel.to_string()
        };
        Ok(Self {
            channel,
            last_poll_time: None,
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

        // 2. Poll Event Log
        let mut query = format!("*[System[TimeCreated[timediff(@SystemTime) <= 3600000]]]");
        if let Some(t) = self.last_poll_time {
            let ts_str = t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            query = format!("*[System[TimeCreated[@SystemTime > '{}']]]", ts_str);
        }

        let channel_h = HSTRING::from(&self.channel);
        let query_h = HSTRING::from(query);

        let handle = unsafe {
            match EvtQuery(
                None,
                &channel_h,
                &query_h,
                EvtQueryChannelPath.0 | EvtQueryForwardDirection.0,
            ) {
                Ok(h) => h,
                Err(_) => return Ok(out),
            }
        };

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
                        
                        // We need a parser. Since SysmonParser is used in tests but missing, 
                        // we'll implement a basic inline parser here for now to ensure data flows.
                        if let Some(ev) = self.parse_xml(clean_xml) {
                            out.push(ev);
                        }
                    }
                    let _ = EvtClose(evt);
                }
            }
            let _ = EvtClose(handle);
        }

        if let Some(latest) = out.iter().map(|e| e.timestamp).max() {
            self.last_poll_time = Some(latest);
        }

        Ok(out)
    }

    fn source_name(&self) -> String {
        format!("windows-event-log:{}", self.channel)
    }
}

#[cfg(target_os = "windows")]
impl WindowsEventReader {
    fn parse_xml(&self, xml: &str) -> Option<HostSecurityEvent> {
        let event_id = self.extract_tag(xml, "EventID")
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or(0);
        
        let computer = self.extract_tag(xml, "Computer").unwrap_or_else(|| "localhost".to_string());
        
        let mut data = serde_json::Map::new();
        // Extract EventData
        if let Some(event_data) = xml.split("<EventData>").nth(1).and_then(|s| s.split("</EventData>").next()) {
            for part in event_data.split("<Data Name=\"").skip(1) {
                if let Some(name_end) = part.find('"') {
                    let name = &part[..name_end];
                    if let Some(val_start) = part.find('>') {
                        if let Some(val_end) = part[val_start+1..].find("</Data>") {
                            let val = &part[val_start+1..val_start+1+val_end];
                            data.insert(name.to_string(), serde_json::json!(val.trim()));
                        }
                    }
                }
            }
        }

        Some(HostSecurityEvent {
            source: osoosi_types::HostEventSource::WindowsEventLog,
            event_id: event_id as u32,
            timestamp: chrono::Utc::now(), // Best effort if parsing timestamp fails
            computer,
            data: serde_json::Value::Object(data),
            causal_parent: None,
        })
    }

    fn extract_tag(&self, xml: &str, tag: &str) -> Option<String> {
        let open = format!("<{}>", tag);
        let close = format!("</{}>", tag);
        xml.find(&open)
            .map(|start| start + open.len())
            .and_then(|start| xml[start..].find(&close).map(|end| (start, start + end)))
            .map(|(start, end)| xml[start..end].trim().to_string())
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

    #[test]
    fn parses_namespaced_sysmon_xml() {
        let reader = WindowsEventReader::new("default").unwrap();
        let event = reader
            .parse_xml(&sample_sysmon_xml(12, r"C:\Windows\System32\cmd.exe"))
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
