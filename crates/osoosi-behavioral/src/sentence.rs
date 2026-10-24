//! Convert log events to behavioral sentences for SecureBERT-style classification.
//!
//! Produces natural-language descriptions like:
//! "Process cmd.exe executed by user from C:\Windows\System32. CommandLine: powershell -enc ..."

use crate::LogEvent;

/// Extract event PID from all possible PID field names and string/hex representations.
pub fn extract_event_pid(event: &LogEvent) -> Option<u64> {
    let pid_keys = [
        "ProcessId",
        "ProcessID",
        "process_id",
        "PID",
        "pid",
        "TargetProcessId",
        "SourceProcessId",
        "NewProcessId",
        "ExecutionProcessId",
    ];
    for k in pid_keys {
        if let Some(v) = event.data.get(k) {
            if let Some(n) = v.as_u64() {
                return Some(n);
            }
            if let Some(s) = v.as_str() {
                let trimmed = s.trim();
                let parsed = if let Some(hex) = trimmed
                    .strip_prefix("0x")
                    .or_else(|| trimmed.strip_prefix("0X"))
                {
                    u64::from_str_radix(hex, 16).ok()
                } else {
                    trimmed.parse::<u64>().ok()
                };
                if let Some(n) = parsed {
                    return Some(n);
                }
            }
        }
    }
    None
}

/// Helper to extract sentence PID from event fields with extract_event_pid fallback.
pub fn extract_sentence_pid(event: &LogEvent) -> Option<u64> {
    let pid_keys = [
        "ProcessId",
        "ProcessID",
        "process_id",
        "PID",
        "pid",
        "TargetProcessId",
        "SourceProcessId",
        "NewProcessId",
    ];
    for k in pid_keys {
        if let Some(v) = event.data.get(k) {
            if let Some(n) = v.as_u64() {
                return Some(n);
            }
            if let Some(s) = v.as_str() {
                let trimmed = s.trim();
                let parsed = if let Some(hex) = trimmed
                    .strip_prefix("0x")
                    .or_else(|| trimmed.strip_prefix("0X"))
                {
                    u64::from_str_radix(hex, 16).ok()
                } else {
                    trimmed.parse::<u64>().ok()
                };
                if let Some(n) = parsed {
                    return Some(n);
                }
            }
        }
    }
    extract_event_pid(event)
}

/// Helper to safely extract the leaf filename from either Windows or Unix paths across platforms.
pub(crate) fn path_leaf_name(path: &str) -> &str {
    let trimmed = path.trim().trim_end_matches(|c| c == '/' || c == '\\');
    let s = trimmed.strip_prefix(r"\\?\").unwrap_or(trimmed);
    s.rsplit(|c| c == '/' || c == '\\').next().unwrap_or(s)
}

/// Helper to extract sentence image from event fields, falling back to PID/System/Process-{pid} invariants.
pub fn extract_sentence_image(event: &LogEvent) -> String {
    let image_keys = [
        "Image",
        "SourceImage",
        "TargetImage",
        "ImageName",
        "ImageFileName",
        "ProcessName",
        "process_name",
        "NewProcessName",
        "ParentImage",
    ];
    let mut resolved = String::new();
    for k in image_keys {
        if let Some(v) = event.data.get(k) {
            if let Some(s) = v.as_str() {
                let trimmed = s.trim();
                if !trimmed.is_empty() && trimmed != "unknown" {
                    let file_name = path_leaf_name(trimmed);
                    let (sanitized, _) = osoosi_types::sanitize_untrusted_log_field(file_name, 128);
                    if !sanitized.is_empty() && sanitized != "unknown" {
                        resolved = sanitized;
                        break;
                    }
                }
            }
        }
    }

    if resolved.is_empty() || resolved == "unknown" {
        if let Some(pid) = extract_sentence_pid(event) {
            if pid == 4 {
                return "System".to_string();
            } else if pid == 0 {
                return "System Idle Process".to_string();
            } else {
                return format!("Process-{}", pid);
            }
        }
    }

    if resolved.is_empty() || resolved == "unknown" {
        if let Some(msg) = event.data.get("Message").and_then(|v| v.as_str()) {
            let trimmed = msg.trim();
            if !trimmed.is_empty() {
                return trimmed.chars().take(64).collect();
            }
        }
        if !event.source.is_empty() && event.source != "unknown" {
            return event.source.clone();
        }
        if !event.computer.is_empty() && event.computer != "unknown" {
            return format!("Host-{}", event.computer);
        }
        return "HostProcess".to_string();
    }

    resolved
}

pub use event_to_behavioral_sentence as generate_behavioral_sentence;

/// Convert a log event to a behavioral sentence suitable for transformer inference.
pub fn event_to_behavioral_sentence(event: &LogEvent) -> String {
    let mut parts = Vec::new();

    // Windows Event ID 4688 = Process Creation
    let is_4688 = event.event_id == 4688 || event.data.contains_key("NewProcessName");
    if is_4688 {
        let raw_proc_path = event
            .data
            .get("NewProcessName")
            .or(event.data.get("Image"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let raw_proc_name = path_leaf_name(raw_proc_path);
        let raw_parent_path = event
            .data
            .get("ParentProcessName")
            .or(event.data.get("ParentImage"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let raw_parent_name = path_leaf_name(raw_parent_path);
        let raw_user = event
            .data
            .get("SubjectUserName")
            .or(event.data.get("User"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let raw_cmd = event
            .data
            .get("CommandLine")
            .or(event.data.get("Command"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let hashes = event
            .data
            .get("Hashes")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let integrity = event
            .data
            .get("IntegrityLevel")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let (proc_path, _) = osoosi_types::sanitize_untrusted_log_field(raw_proc_path, 256);
        let (proc_name, _) = osoosi_types::sanitize_untrusted_log_field(raw_proc_name, 128);
        let (parent_path, _) = osoosi_types::sanitize_untrusted_log_field(raw_parent_path, 256);
        let (parent_name, _) = osoosi_types::sanitize_untrusted_log_field(raw_parent_name, 128);
        let (user, _) = osoosi_types::sanitize_untrusted_log_field(raw_user, 64);
        let (cmd, _) = osoosi_types::sanitize_untrusted_log_field(raw_cmd, 1024);

        parts.push(format!(
            "Process {} (path: {}, integrity: {}) was executed by user {} from parent {} (path: {}).",
            proc_name, proc_path, integrity, user, parent_name, parent_path
        ));
        if !hashes.is_empty() {
            parts.push(format!("Hashes: {}", hashes));
        }
        if !cmd.is_empty() {
            parts.push(format!("CommandLine: {}", cmd));
        }
    }

    // Sysmon-style (from Event ID 1 to 29)
    let is_sysmon = event.source.to_lowercase().contains("sysmon")
        || event
            .data
            .get("Provider")
            .and_then(|v| v.as_str())
            .map(|p| p.to_lowercase().contains("sysmon"))
            .unwrap_or(false)
        || event
            .data
            .get("Channel")
            .and_then(|v| v.as_str())
            .map(|c| c.to_lowercase().contains("sysmon"))
            .unwrap_or(false)
        || (event.event_id >= 1
            && event.event_id <= 29
            && (event.data.contains_key("UtcTime")
                || event.data.contains_key("ProcessGuid")
                || event.data.contains_key("ProcessLifetimeMs")));

    if is_sysmon {
        let event_id = event
            .data
            .get("EventId")
            .or(event.data.get("EventID"))
            .and_then(|v| v.as_i64())
            .unwrap_or(event.event_id as i64);

        let exe = extract_sentence_image(event);

        match event_id {
            1 => {
                // Process Creation
                let raw_parent = event
                    .data
                    .get("ParentImage")
                    .and_then(|v| v.as_str())
                    .map(path_leaf_name)
                    .unwrap_or("unknown");
                let raw_cmd = event
                    .data
                    .get("CommandLine")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let (parent, _) = osoosi_types::sanitize_untrusted_log_field(raw_parent, 128);
                let (cmd, _) = osoosi_types::sanitize_untrusted_log_field(raw_cmd, 512);
                parts.push(format!("Process {} started by parent {}.", exe, parent));
                if !cmd.is_empty() && cmd.len() < 500 {
                    parts.push(format!("Command: {}", cmd));
                }
            }
            2 => {
                // Change File Creation Time (Timestomping)
                let raw_target = event
                    .data
                    .get("TargetFilename")
                    .and_then(|v| v.as_str())
                    .unwrap_or("file");
                let (target, _) = osoosi_types::sanitize_untrusted_log_field(raw_target, 256);
                parts.push(format!(
                    "Process {} altered creation time on {} (Timestomping Anti-Forensics).",
                    exe, target
                ));
            }
            3 => {
                // Network Connect
                let dest_ip = event
                    .data
                    .get("DestinationIp")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let port = event
                    .data
                    .get("DestinationPort")
                    .and_then(|v| {
                        v.as_u64()
                            .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
                    })
                    .unwrap_or(0);
                let proto = event
                    .data
                    .get("Protocol")
                    .and_then(|v| v.as_str())
                    .unwrap_or("TCP");
                parts.push(format!(
                    "Process {} established network connection to {}:{} ({}).",
                    exe, dest_ip, port, proto
                ));
            }
            4 => {
                // Sysmon Service State Change
                let state = event
                    .data
                    .get("State")
                    .and_then(|v| v.as_str())
                    .unwrap_or("state changed");
                parts.push(format!("Sysmon service state changed: {}.", state));
            }
            5 => {
                // Process Terminated
                let pid_str = extract_sentence_pid(event)
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "0".to_string());
                let exe_str = extract_sentence_image(event);
                parts.push(format!("Process {} (PID {}) terminated.", exe_str, pid_str));
            }
            6 => {
                // Driver Loaded (Kernel Rootkit / BYOVD)
                let loaded = event
                    .data
                    .get("ImageLoaded")
                    .and_then(|v| v.as_str())
                    .unwrap_or("driver");
                let sig = event
                    .data
                    .get("Signature")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unsigned");
                parts.push(format!(
                    "Kernel driver loaded: {} (Signature: {}).",
                    loaded, sig
                ));
            }
            7 => {
                // Image Loaded (DLL Hijacking)
                let loaded_full = event
                    .data
                    .get("ImageLoaded")
                    .and_then(|v| v.as_str())
                    .unwrap_or("module");
                let loaded_name = path_leaf_name(loaded_full);
                let (loaded, _) = osoosi_types::sanitize_untrusted_log_field(loaded_name, 128);
                let sig = event
                    .data
                    .get("Signature")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unsigned");
                parts.push(format!(
                    "Process {} loaded dynamic module {} (Signature: {}).",
                    exe, loaded, sig
                ));
            }
            8 => {
                // CreateRemoteThread (Process Injection)
                let target_full = event
                    .data
                    .get("TargetImage")
                    .and_then(|v| v.as_str())
                    .unwrap_or("target");
                let target_name = path_leaf_name(target_full);
                let (target, _) = osoosi_types::sanitize_untrusted_log_field(target_name, 128);
                let start_addr = event
                    .data
                    .get("StartAddress")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0x0");
                parts.push(format!(
                    "Process {} injected remote thread into target {} at {}.",
                    exe, target, start_addr
                ));
            }
            9 => {
                // RawAccessRead (Direct Volume / Shadow Copy Access)
                let device = event
                    .data
                    .get("Device")
                    .and_then(|v| v.as_str())
                    .unwrap_or("volume");
                parts.push(format!(
                    "Process {} attempted direct raw access read on {}.",
                    exe, device
                ));
            }
            10 => {
                // ProcessAccess (LSASS Credential Dumping)
                let target_full = event
                    .data
                    .get("TargetImage")
                    .and_then(|v| v.as_str())
                    .unwrap_or("target");
                let target_name = path_leaf_name(target_full);
                let (target, _) = osoosi_types::sanitize_untrusted_log_field(target_name, 128);
                let access = event
                    .data
                    .get("GrantedAccess")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                parts.push(format!(
                    "Process {} requested handle access ({}) into target {}.",
                    exe, access, target
                ));
            }
            11 => {
                // FileCreate (Drop / Ransomware)
                let raw_target = event
                    .data
                    .get("TargetFilename")
                    .and_then(|v| v.as_str())
                    .unwrap_or("file");
                let (target, _) = osoosi_types::sanitize_untrusted_log_field(raw_target, 256);
                parts.push(format!("Process {} created file: {}.", exe, target));
            }
            12..=14 => {
                // Registry Event (Persistence / Run Keys)
                let raw_obj = event
                    .data
                    .get("TargetObject")
                    .and_then(|v| v.as_str())
                    .unwrap_or("key");
                let (obj, _) = osoosi_types::sanitize_untrusted_log_field(raw_obj, 256);
                let op = event
                    .data
                    .get("EventType")
                    .and_then(|v| v.as_str())
                    .unwrap_or("RegistryModification");
                parts.push(format!(
                    "Process {} performed registry operation ({}) on {}.",
                    exe, op, obj
                ));
            }
            15 => {
                // Alternate Data Stream (MOTW Bypass)
                let target = event
                    .data
                    .get("TargetFilename")
                    .and_then(|v| v.as_str())
                    .unwrap_or("stream");
                let hash = event
                    .data
                    .get("Hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                parts.push(format!(
                    "Alternate Data Stream (ADS) written to {} by {} (Hash: {}).",
                    target, exe, hash
                ));
            }
            16 => {
                // Sysmon Config Change
                let config = event
                    .data
                    .get("Configuration")
                    .and_then(|v| v.as_str())
                    .unwrap_or("updated");
                parts.push(format!("Sysmon configuration change detected: {}.", config));
            }
            17 | 18 => {
                // Pipe Created / Connected (Cobalt Strike / C2)
                let raw_pipe = event
                    .data
                    .get("PipeName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("pipe");
                let (pipe, _) = osoosi_types::sanitize_untrusted_log_field(raw_pipe, 128);
                parts.push(format!(
                    "Process {} created or connected to named pipe {}.",
                    exe, pipe
                ));
            }
            19..=21 => {
                // WMI Event Filter / Consumer (WMI Persistence)
                let raw_name = event
                    .data
                    .get("Name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("WMI");
                let raw_query = event
                    .data
                    .get("Query")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let (name, _) = osoosi_types::sanitize_untrusted_log_field(raw_name, 128);
                let (query, _) = osoosi_types::sanitize_untrusted_log_field(raw_query, 256);
                parts.push(format!(
                    "WMI persistence event detected (Name: {}, Query: {}).",
                    name, query
                ));
            }
            22 => {
                // DNS Query
                let raw_query = event
                    .data
                    .get("QueryName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("query");
                let (query, _) = osoosi_types::sanitize_untrusted_log_field(raw_query, 256);
                parts.push(format!("Process {} queried DNS record: {}.", exe, query));
            }
            23 | 26 => {
                // File Delete / Shredding
                let raw_target = event
                    .data
                    .get("TargetFilename")
                    .and_then(|v| v.as_str())
                    .unwrap_or("file");
                let (target, _) = osoosi_types::sanitize_untrusted_log_field(raw_target, 256);
                parts.push(format!("Process {} deleted file: {}.", exe, target));
            }
            24 => {
                // Clipboard Capture
                parts.push(format!(
                    "Process {} accessed or modified system clipboard contents.",
                    exe
                ));
            }
            25 => {
                // Process Tampering (Process Hollowing / Herpaderping)
                let kind = event
                    .data
                    .get("Type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Hollowing");
                parts.push(format!(
                    "Process tampering/hollowing anomaly detected on {} (Type: {}).",
                    exe, kind
                ));
            }
            27..=29 => {
                // File Block / Executable Intercept
                let raw_target = event
                    .data
                    .get("TargetFilename")
                    .and_then(|v| v.as_str())
                    .unwrap_or("executable");
                let (target, _) = osoosi_types::sanitize_untrusted_log_field(raw_target, 256);
                parts.push(format!(
                    "Sysmon executable/shredding defense triggered on {} by {}.",
                    target, exe
                ));
            }
            _ => {
                // Generic Sysmon event
                if let Some(raw_cmd) = event.data.get("CommandLine").and_then(|v| v.as_str()) {
                    let (safe_cmd, _) = osoosi_types::sanitize_untrusted_log_field(raw_cmd, 512);
                    parts.push(format!(
                        "Sysmon Event {} from {}: {}",
                        event_id, exe, safe_cmd
                    ));
                } else {
                    parts.push(format!("Sysmon Event {} from {}.", event_id, exe));
                }
            }
        }
    }

    // Generic Process Terminate (Non-Sysmon Event ID 5)
    if !is_sysmon && event.event_id == 5 {
        let pid_str = extract_sentence_pid(event)
            .map(|p| p.to_string())
            .unwrap_or_else(|| "0".to_string());
        let exe_str = extract_sentence_image(event);
        parts.push(format!("Process {} (PID {}) terminated.", exe_str, pid_str));
    }

    // Network / DNS (Generic, only if not already handled by Sysmon)
    if !is_sysmon
        && (event.data.contains_key("QueryName") || event.data.contains_key("DestinationIp"))
    {
        if let Some(q) = event.data.get("QueryName").and_then(|v| v.as_str()) {
            let img = event
                .data
                .get("Image")
                .and_then(|v| v.as_str())
                .unwrap_or("process");
            parts.push(format!("Process {} queried DNS: {}.", img, q));
        }
        if let Some(ip) = event.data.get("DestinationIp").and_then(|v| v.as_str()) {
            let img = event
                .data
                .get("Image")
                .and_then(|v| v.as_str())
                .unwrap_or("process");
            let port = event
                .data
                .get("DestinationPort")
                .and_then(|v| {
                    v.as_u64()
                        .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
                })
                .unwrap_or(0);
            parts.push(format!("Process {} connected to {}:{}", img, ip, port));
        }
    }

    // File creation (Generic, only if not already handled by Sysmon and not 4688)
    if !is_sysmon
        && !is_4688
        && (event.data.contains_key("TargetFilename") || event.data.contains_key("TargetFileName"))
    {
        let target = event
            .data
            .get("TargetFilename")
            .or(event.data.get("TargetFileName"))
            .and_then(|v| v.as_str())
            .unwrap_or("file");
        let img = event
            .data
            .get("Image")
            .and_then(|v| v.as_str())
            .unwrap_or("process");
        parts.push(format!("Process {} created file: {}", img, target));
    }

    // Windows Security Auditing & Management Events
    if (event.source.contains("Security")
        || event.source.contains("Microsoft-Windows-Security-Auditing"))
        && !is_4688
    {
        match event.event_id {
            4698 | 4702 => {
                // Scheduled Task Created / Updated (Persistence)
                let task_name = event
                    .data
                    .get("TaskName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Task");
                let task_content = event
                    .data
                    .get("TaskContent")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                parts.push(format!(
                    "Scheduled task created/updated: {} (Content: {}).",
                    task_name, task_content
                ));
            }
            4720 | 4726 | 4728 | 4738 => {
                // User & Group Management (Privilege Escalation)
                let target_user = event
                    .data
                    .get("TargetUserName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("user");
                let member_name = event
                    .data
                    .get("MemberName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                parts.push(format!(
                    "User/Group modification event {} on target {} (Member: {}).",
                    event.event_id, target_user, member_name
                ));
            }
            1102 => {
                // Audit Log Cleared (Anti-Forensics)
                parts.push(
                    "Windows Security Audit Log was explicitly cleared (Event ID 1102)."
                        .to_string(),
                );
            }
            _ => {}
        }
    }

    // Windows Service Control Manager (System Event 7045 - Service Installed)
    if event.event_id == 7045 || event.source.contains("Service Control Manager") {
        let svc_name = event
            .data
            .get("ServiceName")
            .and_then(|v| v.as_str())
            .unwrap_or("service");
        let img_path = event
            .data
            .get("ImagePath")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let svc_type = event
            .data
            .get("ServiceType")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        parts.push(format!(
            "New Windows Service installed: {} (Binary: {}, Type: {}).",
            svc_name, img_path, svc_type
        ));
    }

    // Windows Defender Events (1116: Malware Detected, 1117: Action Taken, 5001: Real-time Disabled)
    if event.source.contains("Windows Defender") {
        match event.event_id {
            1116 | 1117 => {
                let threat = event
                    .data
                    .get("ThreatName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Threat");
                let path = event
                    .data
                    .get("Path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                parts.push(format!(
                    "Windows Defender threat alert (Event {}): {} found at {}.",
                    event.event_id, threat, path
                ));
            }
            5001 => {
                parts.push(
                    "Windows Defender Real-time Protection was disabled (Event ID 5001)."
                        .to_string(),
                );
            }
            _ => {}
        }
    }

    // AppLocker / Code Integrity (8002: Allowed, 8004: Blocked)
    if event.source.contains("AppLocker") || event.source.contains("CodeIntegrity") {
        let policy_name = event
            .data
            .get("PolicyName")
            .and_then(|v| v.as_str())
            .unwrap_or("AppLocker");
        let file = event
            .data
            .get("FilePath")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        parts.push(format!(
            "AppLocker policy event {} on file {}: {}.",
            event.event_id, file, policy_name
        ));
    }

    // PowerShell Behavioral (EventID 4104 is ScriptBlock logging, 4103 is Pipeline)
    if event.source.contains("PowerShell") {
        if let Some(script) = event.data.get("ScriptBlockText").and_then(|v| v.as_str()) {
            parts.push(format!(
                "PowerShell script block executed: {}",
                script.chars().take(2000).collect::<String>()
            ));
        } else if let Some(cmd) = event.data.get("CommandLine").and_then(|v| v.as_str()) {
            parts.push(format!(
                "PowerShell command: {}",
                cmd.chars().take(1024).collect::<String>()
            ));
        }
    }

    // Session Behavioral (Logon/Logoff)
    if event.source.contains("TerminalServices") || event.event_id == 4624 {
        let addr = event
            .data
            .get("SourceNetworkAddress")
            .or(event.data.get("Address"))
            .and_then(|v| v.as_str())
            .unwrap_or("local");
        let user = event
            .data
            .get("TargetUserName")
            .or(event.data.get("User"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        parts.push(format!(
            "User session established for {} from {}.",
            user, addr
        ));
    }

    // Application Logs (Web Servers)
    let raw_lc = event
        .data
        .get("raw")
        .and_then(|v| v.as_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    if event.source.contains("nginx") || event.source.contains("apache") || raw_lc.contains("http/")
    {
        if raw_lc.contains("select ") || raw_lc.contains("union ") || raw_lc.contains("<script") {
            parts.push("Suspicious web request payload detected (SQLi/XSS pattern).".to_string());
        }
        if let Some(raw) = event.data.get("raw").and_then(|v| v.as_str()) {
            parts.push(format!(
                "Web app log: {}",
                raw.chars().take(200).collect::<String>()
            ));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_sysmon_event(event_id: u32, data_kv: Vec<(&str, serde_json::Value)>) -> LogEvent {
        let mut data = HashMap::new();
        data.insert(
            "Provider".to_string(),
            serde_json::json!("Microsoft-Windows-Sysmon"),
        );
        for (k, v) in data_kv {
            data.insert(k.to_string(), v);
        }
        LogEvent {
            source: "Microsoft-Windows-Sysmon".to_string(),
            event_id,
            timestamp: chrono::Utc::now(),
            computer: "test-node".to_string(),
            data,
        }
    }

    #[test]
    fn test_sysmon_process_creation() {
        let ev = make_sysmon_event(
            1,
            vec![
                ("Image", serde_json::json!(r"C:\Windows\System32\cmd.exe")),
                ("ParentImage", serde_json::json!(r"C:\Windows\explorer.exe")),
                ("CommandLine", serde_json::json!("cmd.exe /c dir")),
            ],
        );
        let s = event_to_behavioral_sentence(&ev);
        assert!(s.contains("cmd.exe started by parent explorer.exe"));
    }

    #[test]
    fn test_sysmon_network_connect() {
        let ev = make_sysmon_event(
            3,
            vec![
                ("Image", serde_json::json!(r"C:\Windows\System32\curl.exe")),
                ("DestinationIp", serde_json::json!("198.51.100.1")),
                ("DestinationPort", serde_json::json!(443)),
                ("Protocol", serde_json::json!("TCP")),
            ],
        );
        let s = event_to_behavioral_sentence(&ev);
        assert!(s.contains("curl.exe established network connection to 198.51.100.1:443 (TCP)"));
    }

    #[test]
    fn test_sysmon_image_load() {
        let ev = make_sysmon_event(
            7,
            vec![
                (
                    "Image",
                    serde_json::json!(r"C:\Windows\System32\notepad.exe"),
                ),
                (
                    "ImageLoaded",
                    serde_json::json!(r"C:\Windows\System32\amsi.dll"),
                ),
                ("Signature", serde_json::json!("Microsoft Windows")),
            ],
        );
        let s = event_to_behavioral_sentence(&ev);
        assert!(s.contains("notepad.exe loaded dynamic module amsi.dll"));
        assert!(!s.contains("created file"));
    }

    #[test]
    fn test_sysmon_create_remote_thread() {
        let ev = make_sysmon_event(
            8,
            vec![
                ("SourceImage", serde_json::json!(r"C:\Malware\inject.exe")),
                (
                    "TargetImage",
                    serde_json::json!(r"C:\Windows\System32\svchost.exe"),
                ),
                ("StartAddress", serde_json::json!("0x7FFE0000")),
            ],
        );
        let s = event_to_behavioral_sentence(&ev);
        assert!(s.contains("inject.exe injected remote thread into target svchost.exe"));
    }

    #[test]
    fn test_sysmon_process_access() {
        let ev = make_sysmon_event(
            10,
            vec![
                ("SourceImage", serde_json::json!(r"C:\Tools\mimikatz.exe")),
                (
                    "TargetImage",
                    serde_json::json!(r"C:\Windows\System32\lsass.exe"),
                ),
                ("GrantedAccess", serde_json::json!("0x1010")),
            ],
        );
        let s = event_to_behavioral_sentence(&ev);
        assert!(s.contains("mimikatz.exe requested handle access (0x1010) into target lsass.exe"));
    }

    #[test]
    fn test_sysmon_file_create() {
        let ev = make_sysmon_event(
            11,
            vec![
                ("Image", serde_json::json!(r"C:\Tools\drop.exe")),
                ("TargetFilename", serde_json::json!(r"C:\Temp\payload.dll")),
            ],
        );
        let s = event_to_behavioral_sentence(&ev);
        assert!(s.contains(r"drop.exe created file: C:\Temp\payload.dll"));
    }

    #[test]
    fn test_sysmon_registry_events() {
        let ev = make_sysmon_event(
            13,
            vec![
                ("Image", serde_json::json!(r"C:\Windows\reg.exe")),
                (
                    "TargetObject",
                    serde_json::json!(
                        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Persist"
                    ),
                ),
                ("EventType", serde_json::json!("SetValue")),
            ],
        );
        let s = event_to_behavioral_sentence(&ev);
        assert!(s.contains("reg.exe performed registry operation (SetValue) on HKLM"));
    }

    #[test]
    fn test_sysmon_dns_query() {
        let ev = make_sysmon_event(
            22,
            vec![
                (
                    "Image",
                    serde_json::json!(r"C:\Windows\System32\nslookup.exe"),
                ),
                ("QueryName", serde_json::json!("c2-beacon.example.com")),
            ],
        );
        let s = event_to_behavioral_sentence(&ev);
        assert!(s.contains("nslookup.exe queried DNS record: c2-beacon.example.com"));
    }

    #[test]
    fn test_sysmon_process_tampering() {
        let ev = make_sysmon_event(
            25,
            vec![
                ("Image", serde_json::json!(r"C:\Malware\hollow.exe")),
                ("Type", serde_json::json!("ProcessHollowing")),
            ],
        );
        let s = event_to_behavioral_sentence(&ev);
        assert!(s.contains(
            "Process tampering/hollowing anomaly detected on hollow.exe (Type: ProcessHollowing)"
        ));
    }

    #[test]
    fn test_windows_security_4688_process_creation() {
        let mut data = HashMap::new();
        data.insert(
            "NewProcessName".to_string(),
            serde_json::json!(r"C:\Windows\System32\powershell.exe"),
        );
        data.insert(
            "ParentProcessName".to_string(),
            serde_json::json!(r"C:\Windows\System32\cmd.exe"),
        );
        data.insert(
            "CommandLine".to_string(),
            serde_json::json!("powershell.exe -enc AAAA"),
        );
        data.insert("SubjectUserName".to_string(), serde_json::json!("SYSTEM"));

        let ev = LogEvent {
            source: "windows:Security".to_string(),
            event_id: 4688,
            timestamp: chrono::Utc::now(),
            computer: "dc01".to_string(),
            data,
        };

        let s = event_to_behavioral_sentence(&ev);
        assert!(s.contains("Process powershell.exe"));
        assert!(s.contains("was executed by user SYSTEM from parent cmd.exe"));
        assert_eq!(s.matches("executed").count(), 1);
    }

    #[test]
    fn test_event_5_sysmon_process_terminate_with_image_and_pid() {
        let ev = make_sysmon_event(
            5,
            vec![
                (
                    "Image",
                    serde_json::json!(r"C:\Windows\System32\notepad.exe"),
                ),
                ("ProcessId", serde_json::json!(1234)),
            ],
        );
        let s = event_to_behavioral_sentence(&ev);
        assert_eq!(s, "Process notepad.exe (PID 1234) terminated.");
    }

    #[test]
    fn test_event_5_system_pid_4_resolves_system() {
        let ev = make_sysmon_event(5, vec![("ProcessId", serde_json::json!(4))]);
        let s = event_to_behavioral_sentence(&ev);
        assert_eq!(s, "Process System (PID 4) terminated.");
    }

    #[test]
    fn test_event_5_idle_pid_0_resolves_idle() {
        let ev = make_sysmon_event(5, vec![("ProcessId", serde_json::json!(0))]);
        let s = event_to_behavioral_sentence(&ev);
        assert_eq!(s, "Process System Idle Process (PID 0) terminated.");
    }

    #[test]
    fn test_event_5_numeric_pid_without_image_resolves_process_pid() {
        let ev = make_sysmon_event(5, vec![("ProcessId", serde_json::json!(8820))]);
        let s = event_to_behavioral_sentence(&ev);
        assert_eq!(s, "Process Process-8820 (PID 8820) terminated.");
    }

    #[test]
    fn test_event_5_zero_unknown_invariant_never_unknown() {
        let ev = make_sysmon_event(5, vec![]);
        let s = event_to_behavioral_sentence(&ev);
        assert!(!s.contains("Process unknown (PID unknown) terminated."));
        assert!(s.contains("terminated."));
    }
}
