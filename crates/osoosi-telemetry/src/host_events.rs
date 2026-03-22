//! Cross-platform host security event readers.
//!
//! Reads security event logs from Windows Event Log, Linux auditd, and macOS audit.
//! All events are normalized for the policy engine.

use osoosi_types::{HostEventSource, HostSecurityEvent};
#[cfg(target_os = "windows")]
use tracing::{debug, warn};
#[cfg(not(target_os = "windows"))]
use chrono::Utc;
#[cfg(not(target_os = "windows"))]
use serde_json::json;
#[cfg(not(target_os = "windows"))]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::io::{BufRead, BufReader};
#[cfg(target_os = "linux")]
use std::fs::File;

/// Trait for platform-specific host event sources.
pub trait HostEventReader: Send + Sync {
    /// Read new events since last poll. Returns normalized HostSecurityEvent list.
    fn poll_events(&mut self) -> anyhow::Result<Vec<HostSecurityEvent>>;
    /// Human-readable source identifier currently used by this reader.
    fn source_name(&self) -> String;
}

/// Create the appropriate reader for the current OS.
pub fn create_host_event_reader(channel_or_path: &str) -> anyhow::Result<Box<dyn HostEventReader>> {
    #[cfg(target_os = "windows")]
    {
        Ok(Box::new(WindowsEventReader::new(channel_or_path)?))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(LinuxAuditReader::new(channel_or_path)?))
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

// --- Windows ---

#[cfg(target_os = "windows")]
struct WindowsEventReader {
    channel: String,
    #[allow(dead_code)]
    last_bookmark: Option<String>,
    sysmon_parser: super::SysmonParser,
}

#[cfg(target_os = "windows")]
impl WindowsEventReader {
    fn new(channel: &str) -> anyhow::Result<Self> {
        let preferred = if channel.trim().is_empty() || channel == "default" {
            "Microsoft-Windows-Sysmon/Operational".to_string()
        } else {
            channel.to_string()
        };
        let resolved = Self::resolve_windows_channel(&preferred);
        if resolved != preferred {
            warn!(
                "Requested event channel '{}' not found. Falling back to '{}'.",
                preferred, resolved
            );
        }
        Ok(Self {
            channel: resolved,
            last_bookmark: None,
            sysmon_parser: super::SysmonParser::new(),
        })
    }

    fn resolve_windows_channel(preferred: &str) -> String {
        // Candidate fallback order:
        // 1) user requested channel
        // 2) Sysmon operational
        // 3) Security
        // 4) System
        // 5) Application
        let mut candidates = vec![
            preferred.to_string(),
            "Microsoft-Windows-Sysmon/Operational".to_string(),
            "Security".to_string(),
            "System".to_string(),
            "Application".to_string(),
        ];
        candidates.dedup();
        for c in candidates {
            if Self::channel_exists(&c) {
                return c;
            }
        }
        // Keep preferred if nothing matches; query error will explain.
        preferred.to_string()
    }

    fn channel_exists(channel: &str) -> bool {
        use std::process::Command;
        Command::new("wevtutil")
            .args(["gl", channel])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn query_wevtutil(&self) -> anyhow::Result<Vec<String>> {
        use std::process::Command;
        let mut cmd = Command::new("wevtutil");
        cmd.args(["qe", &self.channel, "/rd:true", "/e:root", "/c:50", "/f:xml"]);
        let output = cmd.output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let msg = if stderr.contains("Access is denied") || stderr.contains("access denied") {
                format!(
                    "wevtutil failed (access denied). OpenỌ̀ṣọ́ọ̀sì runs unprivileged—it does not request admin. \
                    Admin must grant read access: add the OpenỌ̀ṣọ́ọ̀sì service account to 'Event Log Readers' group, \
                    or set channel ACL via: wevtutil gl \"{}\" then wevtutil sl \"{}\" /ca:<SDDL>",
                    self.channel, self.channel
                )
            } else if stderr.contains("The specified channel could not be found") {
                format!(
                    "wevtutil failed: channel '{}' was not found. Install/configure Sysmon or set OSOOSI_EVENT_SOURCE to an existing channel (e.g., Security/System/Application). Details: {}",
                    self.channel,
                    stderr
                )
            } else {
                format!("wevtutil failed: {}", stderr)
            };
            return Err(anyhow::anyhow!("{}", msg));
        }
        let xml = String::from_utf8_lossy(&output.stdout);
        let events: Vec<String> = xml
            .split("<Event>")
            .filter(|s| s.contains("</Event>"))
            .map(|s| format!("<Event>{}", s))
            .collect();
        Ok(events)
    }
}

#[cfg(target_os = "windows")]
impl HostEventReader for WindowsEventReader {
    fn poll_events(&mut self) -> anyhow::Result<Vec<HostSecurityEvent>> {
        let xml_events = self.query_wevtutil()?;
        let mut out = Vec::new();
        for xml in xml_events {
            match self.sysmon_parser.parse_xml(&xml) {
                Ok(sysmon) => {
                    out.push(HostSecurityEvent {
                        source: HostEventSource::WindowsEventLog,
                        event_id: sysmon.event_id as u32,
                        timestamp: sysmon.timestamp,
                        computer: sysmon.computer,
                        data: sysmon.data,
                        causal_parent: None,
                    });
                }
                Err(e) => {
                    debug!("Skipping unparsable Windows event XML: {}", e);
                }
            }
        }
        Ok(out)
    }

    fn source_name(&self) -> String {
        format!("windows-eventlog:{}", self.channel)
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
                        if let Some(ts) = v.strip_prefix("audit(").and_then(|s| s.split(':').next()) {
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
            data.insert("Image".to_string(), json!(data.get("CommandLine").and_then(|v| v.as_str()).unwrap_or("unknown")));
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
                if line.contains("Accepted") || line.contains("Failed") || line.contains("session") {
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
                    if line.contains("Accepted") || line.contains("Failed") || line.contains("session") {
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
