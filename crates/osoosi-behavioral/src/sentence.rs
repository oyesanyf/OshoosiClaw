//! Convert log events to behavioral sentences for SecureBERT-style classification.
//!
//! Produces natural-language descriptions like:
//! "Process cmd.exe executed by user from C:\Windows\System32. CommandLine: powershell -enc ..."

use crate::LogEvent;

/// Convert a log event to a behavioral sentence suitable for transformer inference.
pub fn event_to_behavioral_sentence(event: &LogEvent) -> String {
    let mut parts = Vec::new();

    // Windows Event ID 4688 = Process Creation
    if event.event_id == 4688 || event.data.contains_key("NewProcessName") {
        let proc_name = event.data.get("NewProcessName")
            .or(event.data.get("Image"))
            .and_then(|v| v.as_str())
            .and_then(|s| std::path::Path::new(s).file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        let parent = event.data.get("ParentProcessName")
            .or(event.data.get("ParentImage"))
            .and_then(|v| v.as_str())
            .and_then(|s| std::path::Path::new(s).file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        let user = event.data.get("SubjectUserName")
            .or(event.data.get("User"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let cmd = event.data.get("CommandLine")
            .or(event.data.get("Command"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        parts.push(format!("Process {} (parent: {}) executed by {}.", proc_name, parent, user));
        if !cmd.is_empty() && cmd.len() < 300 {
            parts.push(format!("CommandLine: {}", cmd));
        }
    }

    // Sysmon-style (from osoosi-types SysmonEventId)
    if event.source.contains("Sysmon") {
        if let Some(img) = event.data.get("Image").and_then(|v| v.as_str()) {
            let exe = std::path::Path::new(img).file_name().and_then(|n| n.to_str()).unwrap_or(img);
            let parent = event.data.get("ParentImage")
                .and_then(|v| v.as_str())
                .and_then(|s| std::path::Path::new(s).file_name())
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");
            let cmd = event.data.get("CommandLine").and_then(|v| v.as_str()).unwrap_or("");
            parts.push(format!("Process {} started by parent {}.", exe, parent));
            if !cmd.is_empty() && cmd.len() < 300 {
                parts.push(format!("Command: {}", cmd));
            }
        }
    }

    // Network / DNS
    if event.data.contains_key("QueryName") || event.data.contains_key("DestinationIp") {
        if let Some(q) = event.data.get("QueryName").and_then(|v| v.as_str()) {
            let img = event.data.get("Image").and_then(|v| v.as_str()).unwrap_or("process");
            parts.push(format!("Process {} queried DNS: {}.", img, q));
        }
        if let Some(ip) = event.data.get("DestinationIp").and_then(|v| v.as_str()) {
            let img = event.data.get("Image").and_then(|v| v.as_str()).unwrap_or("process");
            let port = event.data.get("DestinationPort").and_then(|v| v.as_u64()).unwrap_or(0);
            parts.push(format!("Process {} connected to {}:{}", img, ip, port));
        }
    }

    // File creation
    if event.data.contains_key("TargetFilename") || event.data.contains_key("TargetFileName") {
        let target = event.data.get("TargetFilename")
            .or(event.data.get("TargetFileName"))
            .and_then(|v| v.as_str())
            .unwrap_or("file");
        let img = event.data.get("Image").and_then(|v| v.as_str()).unwrap_or("process");
        parts.push(format!("Process {} created file: {}", img, target));
    }

    // PowerShell Behavioral (EventID 4104 is ScriptBlock logging)
    if event.source.contains("PowerShell") {
        if let Some(script) = event.data.get("ScriptBlockText").and_then(|v| v.as_str()) {
            parts.push(format!("PowerShell script block executed: {}", script.chars().take(200).collect::<String>()));
        } else if let Some(cmd) = event.data.get("CommandLine").and_then(|v| v.as_str()) {
            parts.push(format!("PowerShell command: {}", cmd));
        }
    }

    // Session Behavioral (Logon/Logoff)
    if event.source.contains("TerminalServices") || event.event_id == 4624 {
        let addr = event.data.get("SourceNetworkAddress")
            .or(event.data.get("Address"))
            .and_then(|v| v.as_str())
            .unwrap_or("local");
        let user = event.data.get("TargetUserName")
            .or(event.data.get("User"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        parts.push(format!("User session established for {} from {}.", user, addr));
    }

    // Application Logs (Web Servers)
    let raw_lc = event.data.get("raw").and_then(|v| v.as_str()).map(|s| s.to_lowercase()).unwrap_or_default();
    if event.source.contains("nginx") || event.source.contains("apache") || raw_lc.contains("http/") {
        if raw_lc.contains("select ") || raw_lc.contains("union ") || raw_lc.contains("<script") {
            parts.push("Suspicious web request payload detected (SQLi/XSS pattern).".to_string());
        }
        if let Some(raw) = event.data.get("raw").and_then(|v| v.as_str()) {
            parts.push(format!("Web app log: {}", raw.chars().take(200).collect::<String>()));
        }
    }

    // Fallback: use Message or raw
    if parts.is_empty() {
        if let Some(msg) = event.data.get("Message").and_then(|v| v.as_str()) {
            parts.push(msg.chars().take(300).collect::<String>());
        } else if let Some(raw) = event.data.get("raw").and_then(|v| v.as_str()) {
            parts.push(raw.chars().take(300).collect::<String>());
        } else {
            parts.push(format!("Event {} from {}", event.event_id, event.source));
        }
    }

    parts.join(" ")
}
