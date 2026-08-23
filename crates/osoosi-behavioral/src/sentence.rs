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
        let proc_path = event
            .data
            .get("NewProcessName")
            .or(event.data.get("Image"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let proc_name = std::path::Path::new(proc_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(proc_path);
        let parent_path = event
            .data
            .get("ParentProcessName")
            .or(event.data.get("ParentImage"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let parent_name = std::path::Path::new(parent_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(parent_path);
        let user = event
            .data
            .get("SubjectUserName")
            .or(event.data.get("User"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let cmd = event
            .data
            .get("CommandLine")
            .or(event.data.get("Command"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let hashes = event.data.get("Hashes").and_then(|v| v.as_str()).unwrap_or("");
        let integrity = event.data.get("IntegrityLevel").and_then(|v| v.as_str()).unwrap_or("unknown");

        parts.push(format!(
            "Process {} (path: {}, integrity: {}) was executed by user {} from parent {} (path: {}).",
            proc_name, proc_path, integrity, user, parent_name, parent_path
        ));
        if !hashes.is_empty() {
            parts.push(format!("Hashes: {}", hashes));
        }
        if !cmd.is_empty() {
            parts.push(format!("CommandLine: {}", cmd.chars().take(1024).collect::<String>()));
        }
    }

    // Sysmon-style (from Event ID 1 to 29)
    if event.source.contains("Sysmon") {
        let event_id = event
            .data
            .get("EventId")
            .or(event.data.get("EventID"))
            .and_then(|v| v.as_i64())
            .unwrap_or(event.event_id as i64);

        let img = event
            .data
            .get("Image")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let exe = std::path::Path::new(img)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(img);

        match event_id {
            1 => {
                // Process Creation
                let parent = event
                    .data
                    .get("ParentImage")
                    .and_then(|v| v.as_str())
                    .and_then(|s| std::path::Path::new(s).file_name())
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");
                let cmd = event
                    .data
                    .get("CommandLine")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                parts.push(format!("Process {} started by parent {}.", exe, parent));
                if !cmd.is_empty() && cmd.len() < 500 {
                    parts.push(format!("Command: {}", cmd));
                }
            }
            2 => {
                // Change File Creation Time (Timestomping)
                let target = event.data.get("TargetFilename").and_then(|v| v.as_str()).unwrap_or("file");
                parts.push(format!("Process {} altered creation time on {} (Timestomping Anti-Forensics).", exe, target));
            }
            3 => {
                // Network Connect
                let dest_ip = event.data.get("DestinationIp").and_then(|v| v.as_str()).unwrap_or("unknown");
                let port = event.data.get("DestinationPort").and_then(|v| v.as_u64()).unwrap_or(0);
                parts.push(format!("Process {} established network connection to {}:{}.", exe, dest_ip, port));
            }
            6 => {
                // Driver Loaded (Kernel Rootkit / BYOVD)
                let loaded = event.data.get("ImageLoaded").and_then(|v| v.as_str()).unwrap_or("driver");
                let sig = event.data.get("Signature").and_then(|v| v.as_str()).unwrap_or("unsigned");
                parts.push(format!("Kernel driver loaded: {} (Signature: {}).", loaded, sig));
            }
            7 => {
                // Image Loaded (DLL Hijacking)
                let loaded = event.data.get("ImageLoaded").and_then(|v| v.as_str()).unwrap_or("module");
                let sig = event.data.get("Signature").and_then(|v| v.as_str()).unwrap_or("unsigned");
                parts.push(format!("Process {} loaded dynamic module {} (Signature: {}).", exe, loaded, sig));
            }
            8 => {
                // CreateRemoteThread (Process Injection)
                let target = event.data.get("TargetImage").and_then(|v| v.as_str()).unwrap_or("target");
                let start_addr = event.data.get("StartAddress").and_then(|v| v.as_str()).unwrap_or("0x0");
                parts.push(format!("Process {} injected remote thread into target {} at {}.", exe, target, start_addr));
            }
            9 => {
                // RawAccessRead (Direct Volume / Shadow Copy Access)
                let device = event.data.get("Device").and_then(|v| v.as_str()).unwrap_or("volume");
                parts.push(format!("Process {} attempted direct raw access read on {}.", exe, device));
            }
            10 => {
                // ProcessAccess (LSASS Credential Dumping)
                let target = event.data.get("TargetImage").and_then(|v| v.as_str()).unwrap_or("target");
                let access = event.data.get("GrantedAccess").and_then(|v| v.as_str()).unwrap_or("unknown");
                parts.push(format!("Process {} requested handle access ({}) into target {}.", exe, access, target));
            }
            11 => {
                // FileCreate (Drop / Ransomware)
                let target = event.data.get("TargetFilename").and_then(|v| v.as_str()).unwrap_or("file");
                parts.push(format!("Process {} created file: {}.", exe, target));
            }
            12 | 13 | 14 => {
                // Registry Event (Persistence / Run Keys)
                let obj = event.data.get("TargetObject").and_then(|v| v.as_str()).unwrap_or("key");
                let op = event.data.get("EventType").and_then(|v| v.as_str()).unwrap_or("RegistryModification");
                parts.push(format!("Process {} performed registry operation ({}) on {}.", exe, op, obj));
            }
            15 => {
                // Alternate Data Stream (MOTW Bypass)
                let target = event.data.get("TargetFilename").and_then(|v| v.as_str()).unwrap_or("stream");
                let hash = event.data.get("Hash").and_then(|v| v.as_str()).unwrap_or("");
                parts.push(format!("Alternate Data Stream (ADS) written to {} (Hash: {}).", target, hash));
            }
            17 | 18 => {
                // Pipe Created / Connected (Cobalt Strike / C2)
                let pipe = event.data.get("PipeName").and_then(|v| v.as_str()).unwrap_or("pipe");
                parts.push(format!("Process {} created or connected to named pipe {}.", exe, pipe));
            }
            19 | 20 | 21 => {
                // WMI Event Filter / Consumer (WMI Persistence)
                let name = event.data.get("Name").and_then(|v| v.as_str()).unwrap_or("WMI");
                let query = event.data.get("Query").and_then(|v| v.as_str()).unwrap_or("");
                parts.push(format!("WMI persistence event detected (Name: {}, Query: {}).", name, query));
            }
            22 => {
                // DNS Query
                let query = event.data.get("QueryName").and_then(|v| v.as_str()).unwrap_or("query");
                parts.push(format!("Process {} queried DNS record: {}.", exe, query));
            }
            23 | 26 => {
                // File Delete / Shredding
                let target = event.data.get("TargetFilename").and_then(|v| v.as_str()).unwrap_or("file");
                parts.push(format!("Process {} deleted file: {}.", exe, target));
            }
            24 => {
                // Clipboard Capture
                parts.push(format!("Process {} accessed or modified system clipboard contents.", exe));
            }
            25 => {
                // Process Tampering (Process Hollowing / Herpaderping)
                let kind = event.data.get("Type").and_then(|v| v.as_str()).unwrap_or("Hollowing");
                parts.push(format!("Process tampering/hollowing anomaly detected on {} (Type: {}).", exe, kind));
            }
            27 | 28 | 29 => {
                // File Block / Executable Intercept
                let target = event.data.get("TargetFilename").and_then(|v| v.as_str()).unwrap_or("executable");
                parts.push(format!("Sysmon executable/shredding defense triggered on {} by {}.", target, exe));
            }
            _ => {
                // Generic Sysmon event
                if let Some(cmd) = event.data.get("CommandLine").and_then(|v| v.as_str()) {
                    parts.push(format!("Sysmon Event {} from {}: {}", event_id, exe, cmd));
                } else {
                    parts.push(format!("Sysmon Event {} from {}.", event_id, exe));
                }
            }
        }
    }

    // Network / DNS
    if event.data.contains_key("QueryName") || event.data.contains_key("DestinationIp") {
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
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            parts.push(format!("Process {} connected to {}:{}", img, ip, port));
        }
    }

    // File creation
    if event.data.contains_key("TargetFilename") || event.data.contains_key("TargetFileName") {
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
    if event.source.contains("Security") || event.source.contains("Microsoft-Windows-Security-Auditing") {
        match event.event_id {
            4688 => {
                // Process Creation with Token Elevation
                let new_proc = event.data.get("NewProcessName").and_then(|v| v.as_str()).unwrap_or("process");
                let creator = event.data.get("ParentProcessName").and_then(|v| v.as_str()).unwrap_or("parent");
                let cmd = event.data.get("CommandLine").and_then(|v| v.as_str()).unwrap_or("");
                let token = event.data.get("TokenElevationType").and_then(|v| v.as_str()).unwrap_or("");
                parts.push(format!("Process {} executed by parent {} (Token: {}).", new_proc, creator, token));
                if !cmd.is_empty() {
                    parts.push(format!("Command: {}", cmd));
                }
            }
            4698 | 4702 => {
                // Scheduled Task Created / Updated (Persistence)
                let task_name = event.data.get("TaskName").and_then(|v| v.as_str()).unwrap_or("Task");
                let task_content = event.data.get("TaskContent").and_then(|v| v.as_str()).unwrap_or("");
                parts.push(format!("Scheduled task created/updated: {} (Content: {}).", task_name, task_content));
            }
            4720 | 4726 | 4728 | 4738 => {
                // User & Group Management (Privilege Escalation)
                let target_user = event.data.get("TargetUserName").and_then(|v| v.as_str()).unwrap_or("user");
                let member_name = event.data.get("MemberName").and_then(|v| v.as_str()).unwrap_or("");
                parts.push(format!("User/Group modification event {} on target {} (Member: {}).", event.event_id, target_user, member_name));
            }
            1102 => {
                // Audit Log Cleared (Anti-Forensics)
                parts.push("Windows Security Audit Log was explicitly cleared (Event ID 1102).".to_string());
            }
            _ => {}
        }
    }

    // Windows Service Control Manager (System Event 7045 - Service Installed)
    if event.event_id == 7045 || event.source.contains("Service Control Manager") {
        let svc_name = event.data.get("ServiceName").and_then(|v| v.as_str()).unwrap_or("service");
        let img_path = event.data.get("ImagePath").and_then(|v| v.as_str()).unwrap_or("");
        let svc_type = event.data.get("ServiceType").and_then(|v| v.as_str()).unwrap_or("");
        parts.push(format!("New Windows Service installed: {} (Binary: {}, Type: {}).", svc_name, img_path, svc_type));
    }

    // Windows Defender Events (1116: Malware Detected, 1117: Action Taken, 5001: Real-time Disabled)
    if event.source.contains("Windows Defender") {
        match event.event_id {
            1116 | 1117 => {
                let threat = event.data.get("ThreatName").and_then(|v| v.as_str()).unwrap_or("Threat");
                let path = event.data.get("Path").and_then(|v| v.as_str()).unwrap_or("");
                parts.push(format!("Windows Defender threat alert (Event {}): {} found at {}.", event.event_id, threat, path));
            }
            5001 => {
                parts.push("Windows Defender Real-time Protection was disabled (Event ID 5001).".to_string());
            }
            _ => {}
        }
    }

    // AppLocker / Code Integrity (8002: Allowed, 8004: Blocked)
    if event.source.contains("AppLocker") || event.source.contains("CodeIntegrity") {
        let policy_name = event.data.get("PolicyName").and_then(|v| v.as_str()).unwrap_or("AppLocker");
        let file = event.data.get("FilePath").and_then(|v| v.as_str()).unwrap_or("");
        parts.push(format!("AppLocker policy event {} on file {}: {}.", event.event_id, file, policy_name));
    }

    // PowerShell Behavioral (EventID 4104 is ScriptBlock logging, 4103 is Pipeline)
    if event.source.contains("PowerShell") {
        if let Some(script) = event.data.get("ScriptBlockText").and_then(|v| v.as_str()) {
            parts.push(format!(
                "PowerShell script block executed: {}",
                script.chars().take(2000).collect::<String>()
            ));
        } else if let Some(cmd) = event.data.get("CommandLine").and_then(|v| v.as_str()) {
            parts.push(format!("PowerShell command: {}", cmd.chars().take(1024).collect::<String>()));
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
