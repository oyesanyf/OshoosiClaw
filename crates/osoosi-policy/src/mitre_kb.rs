//! Comprehensive MITRE ATT&CK Enterprise Knowledge Base (KB)
//!
//! Authoritative repository of Tactics, Techniques, Sub-techniques, Mitigations,
//! and Threat Actor Groups (CTI) for OpenỌ̀ṣọ́ọ̀sì Agentic EDR.

use osoosi_types::mitre::*;
use std::collections::HashMap;
use std::sync::OnceLock;

static CATALOG: OnceLock<Option<MitreCatalog>> = OnceLock::new();

/// Return a reference to the loaded authoritative MITRE ATT&CK & ATLAS catalog if available on disk.
pub fn get_catalog() -> Option<&'static MitreCatalog> {
    CATALOG.get_or_init(|| {
        let path = osoosi_types::config::resolve_mitre_catalog_path();
        if path.is_file() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(cat) = serde_json::from_str::<MitreCatalog>(&content) {
                    tracing::info!(
                        "Loaded authoritative MITRE ATT&CK Catalog from {}: {} tactics, {} techniques, {} mitigations, {} groups",
                        path.display(),
                        cat.tactics.len(),
                        cat.techniques.len(),
                        cat.mitigations.len(),
                        cat.groups.len()
                    );
                    return Some(cat);
                } else {
                    tracing::warn!("Failed to parse MITRE catalog at {}", path.display());
                }
            }
        }
        None
    }).as_ref()
}

/// Returns all 15 MITRE ATT&CK Enterprise Tactics.
pub fn get_all_tactics() -> Vec<MitreTactic> {
    if let Some(cat) = get_catalog() {
        if !cat.tactics.is_empty() {
            return cat.tactics.clone();
        }
    }
    get_static_tactics()
}

/// Fallback static compiled tactics.
pub fn get_static_tactics() -> Vec<MitreTactic> {
    let techniques = get_all_techniques();
    let mut count_map: HashMap<&str, usize> = HashMap::new();
    for t in &techniques {
        *count_map.entry(&t.tactic_id).or_insert(0) += 1;
    }

    vec![
        MitreTactic::new(
            "TA0043",
            "Reconnaissance",
            "Adversaries gathering information to plan future adversary operations.",
            *count_map.get("TA0043").unwrap_or(&0),
        ),
        MitreTactic::new(
            "TA0042",
            "Resource Development",
            "Adversaries establishing resources to support operations.",
            *count_map.get("TA0042").unwrap_or(&0),
        ),
        MitreTactic::new(
            "TA0001",
            "Initial Access",
            "Adversaries trying to get into your network.",
            *count_map.get("TA0001").unwrap_or(&0),
        ),
        MitreTactic::new(
            "TA0002",
            "Execution",
            "Adversaries trying to run malicious code on your endpoints.",
            *count_map.get("TA0002").unwrap_or(&0),
        ),
        MitreTactic::new(
            "TA0003",
            "Persistence",
            "Adversaries trying to maintain their foothold across restarts.",
            *count_map.get("TA0003").unwrap_or(&0),
        ),
        MitreTactic::new(
            "TA0004",
            "Privilege Escalation",
            "Adversaries trying to gain higher-level permissions.",
            *count_map.get("TA0004").unwrap_or(&0),
        ),
        MitreTactic::new(
            "TA0005",
            "Defense Evasion",
            "Adversaries trying to avoid being detected by security software.",
            *count_map.get("TA0005").unwrap_or(&0),
        ),
        MitreTactic::new(
            "TA0112",
            "Defense Impairment",
            "Adversaries deliberately disabling security tools and defensive capabilities.",
            *count_map.get("TA0112").unwrap_or(&0),
        ),
        MitreTactic::new(
            "TA0006",
            "Credential Access",
            "Adversaries trying to steal account names and passwords.",
            *count_map.get("TA0006").unwrap_or(&0),
        ),
        MitreTactic::new(
            "TA0007",
            "Discovery",
            "Adversaries trying to observe system and network environment.",
            *count_map.get("TA0007").unwrap_or(&0),
        ),
        MitreTactic::new(
            "TA0008",
            "Lateral Movement",
            "Adversaries trying to move through your environment.",
            *count_map.get("TA0008").unwrap_or(&0),
        ),
        MitreTactic::new(
            "TA0009",
            "Collection",
            "Adversaries trying to gather data of interest to their goal.",
            *count_map.get("TA0009").unwrap_or(&0),
        ),
        MitreTactic::new(
            "TA0011",
            "Command and Control",
            "Adversaries communicating with compromised systems to control them.",
            *count_map.get("TA0011").unwrap_or(&0),
        ),
        MitreTactic::new(
            "TA0010",
            "Exfiltration",
            "Adversaries trying to steal data from your network.",
            *count_map.get("TA0010").unwrap_or(&0),
        ),
        MitreTactic::new(
            "TA0040",
            "Impact",
            "Adversaries trying to manipulate, interrupt, or destroy systems and data.",
            *count_map.get("TA0040").unwrap_or(&0),
        ),
    ]
}

/// Returns the comprehensive catalog of MITRE ATT&CK & ATLAS Enterprise Techniques.
pub fn get_all_techniques() -> Vec<MitreTechnique> {
    if let Some(cat) = get_catalog() {
        if !cat.techniques.is_empty() {
            return cat.techniques.clone();
        }
    }
    get_static_techniques()
}

/// Fallback static compiled techniques.
pub fn get_static_techniques() -> Vec<MitreTechnique> {
    vec![
        // --- 1. Reconnaissance (TA0043) ---
        MitreTechnique {
            id: "T1595".into(),
            name: "Active Scanning".into(),
            tactic_id: "TA0043".into(),
            tactic_name: "Reconnaissance".into(),
            description: "Adversaries may execute active reconnaissance scans to gather information in victim infrastructure.".into(),
            data_sources: vec!["Network Traffic: Network Traffic Flow".into(), "Sensor Health: Network Sensor".into()],
            mitigations: vec!["M1037: Filter Network Traffic".into(), "M1031: Network Intrusion Prevention".into()],
            groups: vec!["APT28".into(), "Volt Typhoon".into(), "Lazarus Group".into()],
            detection_mechanisms: vec!["WFP NetFilter".into(), "Sigma Rule: Network Port Scan".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1595.001", "Scanning IP Blocks", "Scanning broad IP blocks to discover targets."),
                MitreSubtechnique::new("T1595.002", "Vulnerability Scanning", "Targeting specific network services with vulnerability probe suites."),
            ],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1592".into(),
            name: "Gather Victim Host Information".into(),
            tactic_id: "TA0043".into(),
            tactic_name: "Reconnaissance".into(),
            description: "Adversaries may gather information about the victim's host configuration, OS version, and patch state.".into(),
            data_sources: vec!["Network Traffic: Web Traffic".into()],
            mitigations: vec!["M1054: Software Configuration".into()],
            groups: vec!["APT29".into(), "Sandworm Team".into()],
            detection_mechanisms: vec!["EDR Telemetry Audit".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1592.001", "Hardware", "Extracting system vendor, BIOS, and device specs."),
                MitreSubtechnique::new("T1592.002", "Software", "Identifying installed software and runtime patch levels."),
            ],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1596".into(),
            name: "Search Open Technical Databases".into(),
            tactic_id: "TA0043".into(),
            tactic_name: "Reconnaissance".into(),
            description: "Adversaries may search open technical databases like DNS records and WHOIS for target reconnaissance.".into(),
            data_sources: vec!["Internet Scan Logs".into()],
            mitigations: vec!["M1056: Pre-compromise Threat Intelligence".into()],
            groups: vec!["APT29".into(), "FIN7".into()],
            detection_mechanisms: vec!["OTX / TAXII Threat Feeds".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1596.001", "DNS Records", "Querying public DNS zone records."),
                MitreSubtechnique::new("T1596.002", "WHOIS", "Extracting domain registration identities."),
            ],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1598".into(),
            name: "Phishing for Information".into(),
            tactic_id: "TA0043".into(),
            tactic_name: "Reconnaissance".into(),
            description: "Adversaries may send phishing messages to elicit sensitive technical or administrative intelligence.".into(),
            data_sources: vec!["Application Log: Email Gateway".into()],
            mitigations: vec!["M1017: User Training".into(), "M1021: Restrict Web-Based Content".into()],
            groups: vec!["Scattered Spider".into(), "APT28".into()],
            detection_mechanisms: vec!["Email Threat Scanner".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1598.001", "Spearphishing Service", "Targeting technical personnel via fake vendor queries."),
            ],
            ..Default::default()
        },

        // --- 2. Resource Development (TA0042) ---
        MitreTechnique {
            id: "T1650".into(),
            name: "Acquire Access".into(),
            tactic_id: "TA0042".into(),
            tactic_name: "Resource Development".into(),
            description: "Adversaries may purchase or broker access from initial access brokers (IABs) on darknet forums.".into(),
            data_sources: vec!["Threat Intelligence Feeds".into()],
            mitigations: vec!["M1036: Account Use Policies".into(), "M1026: Privileged Account Management".into()],
            groups: vec!["LockBit".into(), "BlackCat".into(), "Wizard Spider".into()],
            detection_mechanisms: vec!["OTX Darknet CTI Voter".into()],
            subtechniques: vec![],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1583".into(),
            name: "Acquire Infrastructure".into(),
            tactic_id: "TA0042".into(),
            tactic_name: "Resource Development".into(),
            description: "Adversaries may buy, lease, or rent infrastructure (domains, VPS, bulletproof hosting) for operations.".into(),
            data_sources: vec!["External CTI Feed".into()],
            mitigations: vec!["M1056: Pre-compromise Threat Intelligence".into()],
            groups: vec!["APT29".into(), "Lazarus Group".into(), "Volt Typhoon".into()],
            detection_mechanisms: vec!["OTX TAXII Feed".into(), "CISA KEV Integration".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1583.001", "Domains", "Purchasing deceptive lookalike domains."),
                MitreSubtechnique::new("T1583.003", "Virtual Private Server", "Leasing cloud compute instances for C2 staging."),
            ],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1586".into(),
            name: "Compromise Accounts".into(),
            tactic_id: "TA0042".into(),
            tactic_name: "Resource Development".into(),
            description: "Adversaries may compromise accounts on third-party services to support operations.".into(),
            data_sources: vec!["Identity Provider Logs".into()],
            mitigations: vec!["M1018: User Account Management".into()],
            groups: vec!["APT29".into(), "Scattered Spider".into()],
            detection_mechanisms: vec!["Mesh Identity Attestation".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1586.002", "Email Accounts", "Hijacking corporate email accounts for trusted spearphishing."),
            ],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1587".into(),
            name: "Develop Capabilities".into(),
            tactic_id: "TA0042".into(),
            tactic_name: "Resource Development".into(),
            description: "Adversaries develop custom malware, shellcode, and automated exploit payloads.".into(),
            data_sources: vec!["Threat Intel Feeds".into()],
            mitigations: vec!["M1050: Exploit Protection".into()],
            groups: vec!["Sandworm Team".into(), "Turla".into(), "Lazarus Group".into()],
            detection_mechanisms: vec!["YARA-X Rules".into(), "Nabla Binary Classifier".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1587.001", "Malware", "Writing compiled C/Rust/Go custom implants."),
                MitreSubtechnique::new("T1587.004", "Exploits", "Engineering zero-day and n-day weaponized exploits."),
            ],
            ..Default::default()
        },

        // --- 3. Initial Access (TA0001) ---
        MitreTechnique {
            id: "T1566".into(),
            name: "Phishing".into(),
            tactic_id: "TA0001".into(),
            tactic_name: "Initial Access".into(),
            description: "Adversaries send phishing messages with malicious attachments or links to execute code on victim endpoints.".into(),
            data_sources: vec!["Process: Process Creation".into(), "File: File Creation".into()],
            mitigations: vec!["M1021: Restrict Web-Based Content".into(), "M1038: Execution Prevention".into()],
            groups: vec!["APT29".into(), "APT28".into(), "FIN7".into()],
            detection_mechanisms: vec!["Sysmon Event 1".into(), "Sysmon Event 11".into(), "Sigma Rule: Office Child Process".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1566.001", "Spearphishing Attachment", "Sending email with weaponized Office, PDF, or ISO attachment."),
                MitreSubtechnique::new("T1566.002", "Spearphishing Link", "Luring user to click a link delivering payload or credential harvester."),
            ],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1190".into(),
            name: "Exploit Public-Facing Application".into(),
            tactic_id: "TA0001".into(),
            tactic_name: "Initial Access".into(),
            description: "Adversaries exploit vulnerabilities in public-facing software to achieve arbitrary remote execution.".into(),
            data_sources: vec!["Application Log".into(), "Process: Process Creation".into(), "Network Traffic".into()],
            mitigations: vec!["M1051: Update Software & Patching".into(), "M1037: Filter Network Traffic".into()],
            groups: vec!["Volt Typhoon".into(), "LockBit".into(), "Lazarus Group".into()],
            detection_mechanisms: vec!["CISA KEV Matcher".into(), "NVD CVE Tagger".into(), "Sysmon Event 1".into()],
            subtechniques: vec![],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1133".into(),
            name: "External Remote Services".into(),
            tactic_id: "TA0001".into(),
            tactic_name: "Initial Access".into(),
            description: "Adversaries leverage external remote access services (VPNs, Citrix, RDP gateways) with stolen credentials.".into(),
            data_sources: vec!["Logon Session: Creation".into(), "User Account: Authentication".into()],
            mitigations: vec!["M1036: Account Use Policies".into(), "M1030: Network Segmentation".into()],
            groups: vec!["Volt Typhoon".into(), "BlackCat".into()],
            detection_mechanisms: vec!["Windows Event 4624 (Logon Type 10)".into(), "Agent Egress Isolation Voter".into()],
            subtechniques: vec![],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1195".into(),
            name: "Supply Chain Compromise".into(),
            tactic_id: "TA0001".into(),
            tactic_name: "Initial Access".into(),
            description: "Adversaries manipulate software development tools, third-party packages, or update channels.".into(),
            data_sources: vec!["File: File Modification".into(), "Module: Module Load".into()],
            mitigations: vec!["M1047: Audit & Security Logging".into(), "M1054: Software Configuration".into()],
            groups: vec!["APT29".into(), "Lazarus Group".into()],
            detection_mechanisms: vec!["Authenticode Validation".into(), "Catalog Signature Verification".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1195.001", "Compromise Software Dependencies", "Backdooring npm, PyPI, or crates dependencies."),
                MitreSubtechnique::new("T1195.002", "Compromise Software Supply Chain", "Injecting malicious updates into official distribution mirrors."),
            ],
            ..Default::default()
        },

        // --- 4. Execution (TA0002) ---
        MitreTechnique {
            id: "T1059".into(),
            name: "Command and Scripting Interpreter".into(),
            tactic_id: "TA0002".into(),
            tactic_name: "Execution".into(),
            description: "Adversaries abuse command and scripting interpreters (PowerShell, cmd, bash, python) to execute commands.".into(),
            data_sources: vec!["Process: Process Creation".into(), "Command: Command Execution".into(), "Script: Script Execution".into()],
            mitigations: vec!["M1038: Execution Prevention".into(), "M1028: Operating System Configuration".into()],
            groups: vec!["APT29".into(), "APT28".into(), "Lazarus Group".into(), "FIN7".into(), "Volt Typhoon".into()],
            detection_mechanisms: vec!["Sysmon Event 1".into(), "Sigma Rule: Suspicious PowerShell Flags".into(), "AMSI Inspection".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1059.001", "PowerShell", "Executing commands via powershell.exe with hidden window or encoded parameters."),
                MitreSubtechnique::new("T1059.003", "Windows Command Shell", "Executing commands via cmd.exe batch scripts or builtins."),
                MitreSubtechnique::new("T1059.004", "Unix Shell", "Executing commands via sh, bash, or zsh scripts."),
                MitreSubtechnique::new("T1059.005", "Visual Basic", "Executing scripts via wscript.exe or cscript.exe."),
            ],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1053".into(),
            name: "Scheduled Task/Job".into(),
            tactic_id: "TA0002".into(),
            tactic_name: "Execution".into(),
            description: "Adversaries schedule tasks or jobs to execute programs at recurring intervals or upon system start.".into(),
            data_sources: vec!["Process: Process Creation".into(), "Scheduled Job: Scheduled Job Creation".into()],
            mitigations: vec!["M1028: Operating System Configuration".into(), "M1026: Privileged Account Management".into()],
            groups: vec!["APT29".into(), "LockBit".into(), "Sandworm Team".into()],
            detection_mechanisms: vec!["Sysmon Event 1".into(), "Sigma Rule: schtasks /create".into(), "Task Scheduler ETW".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1053.005", "Scheduled Task", "Creating Windows scheduled tasks via schtasks.exe or COM interfaces."),
                MitreSubtechnique::new("T1053.003", "Cron", "Creating Linux cron jobs in /etc/crontab or crontab -e."),
            ],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1569".into(),
            name: "System Services".into(),
            tactic_id: "TA0002".into(),
            tactic_name: "Execution".into(),
            description: "Adversaries abuse system service controllers to execute malicious binaries as high-privilege services.".into(),
            data_sources: vec!["Process: Process Creation".into(), "Service: Service Creation".into()],
            mitigations: vec!["M1028: Operating System Configuration".into(), "M1038: Execution Prevention".into()],
            groups: vec!["Lazarus Group".into(), "Turla".into()],
            detection_mechanisms: vec!["Sysmon Event 1".into(), "Windows System Event 7045".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1569.002", "Service Execution", "Using sc.exe or PowerShell Start-Service to run payloads."),
            ],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1047".into(),
            name: "Windows Management Instrumentation".into(),
            tactic_id: "TA0002".into(),
            tactic_name: "Execution".into(),
            description: "Adversaries abuse WMI to execute malicious commands and query environment telemetry.".into(),
            data_sources: vec!["Process: Process Creation".into(), "WMI: WMI Event".into()],
            mitigations: vec!["M1026: Privileged Account Management".into(), "M1047: Audit & Security Logging".into()],
            groups: vec!["APT29".into(), "FIN7".into()],
            detection_mechanisms: vec!["Sysmon Event 19, 20, 21".into(), "Sigma Rule: wmic process call create".into()],
            subtechniques: vec![],
            ..Default::default()
        },

        // --- 5. Persistence (TA0003) ---
        MitreTechnique {
            id: "T1547".into(),
            name: "Boot or Logon Autostart Execution".into(),
            tactic_id: "TA0003".into(),
            tactic_name: "Persistence".into(),
            description: "Adversaries configure system settings to automatically execute a program during boot or logon.".into(),
            data_sources: vec!["Windows Registry: Registry Key Modification".into(), "File: File Creation".into()],
            mitigations: vec!["M1022: Restrict File and Directory Permissions".into(), "M1038: Execution Prevention".into()],
            groups: vec!["APT28".into(), "Lazarus Group".into(), "LockBit".into()],
            detection_mechanisms: vec!["Sysmon Event 12, 13, 14".into(), "Registry Repair Engine".into(), "Sigma: Run Key Added".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1547.001", "Registry Run Keys / Startup Folder", "Adding entries under HKCU/HKLM Run keys or Startup folder."),
                MitreSubtechnique::new("T1547.009", "Shortcut Modification", "Modifying .lnk files pointing to clean executables to add payload arguments."),
            ],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1543".into(),
            name: "Create or Modify System Process".into(),
            tactic_id: "TA0003".into(),
            tactic_name: "Persistence".into(),
            description: "Adversaries create or modify system processes (services, systemd daemons) to maintain persistence.".into(),
            data_sources: vec!["Service: Service Creation".into(), "Windows Registry: Registry Key Modification".into()],
            mitigations: vec!["M1028: Operating System Configuration".into()],
            groups: vec!["Turla".into(), "Sandworm Team".into()],
            detection_mechanisms: vec!["Sysmon Event 13".into(), "Service Monitor".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1543.003", "Windows Service", "Creating new service via sc create pointing to malicious binary."),
            ],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1574".into(),
            name: "Hijack Execution Flow".into(),
            tactic_id: "TA0003".into(),
            tactic_name: "Persistence".into(),
            description: "Adversaries execute their own malicious code by hijacking the way operating systems run programs (e.g. DLL Side-Loading).".into(),
            data_sources: vec!["Module: Module Load".into(), "File: File Creation".into()],
            mitigations: vec!["M1038: Execution Prevention".into(), "M1042: Disable or Remove Feature or Program".into()],
            groups: vec!["APT29".into(), "Volt Typhoon".into(), "Lazarus Group".into()],
            detection_mechanisms: vec!["Sysmon Event 7 (ImageLoad)".into(), "Authenticode Module Verifier".into(), "Sigma Rule: DLL Side-Loading".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1574.002", "DLL Side-Loading", "Placing an unsigned malicious DLL adjacent to a signed executable."),
                MitreSubtechnique::new("T1574.001", "DLL Search Order Hijacking", "Exploiting search directory priority to execute rogue libraries."),
            ],
            ..Default::default()
        },

        // --- 6. Privilege Escalation (TA0004) ---
        MitreTechnique {
            id: "T1055".into(),
            name: "Process Injection".into(),
            tactic_id: "TA0004".into(),
            tactic_name: "Privilege Escalation".into(),
            description: "Adversaries inject code into running processes to evade process-based defenses and elevate privileges.".into(),
            data_sources: vec!["Process: Process Access".into(), "Process: Process Modification".into()],
            mitigations: vec!["M1050: Exploit Protection".into(), "M1040: Behavior Prevention on Endpoint".into()],
            groups: vec!["APT29".into(), "Lazarus Group".into(), "BlackCat".into(), "LockBit".into()],
            detection_mechanisms: vec!["Sysmon Event 8 (CreateRemoteThread)".into(), "Sysmon Event 25 (ProcessTampering)".into(), "HollowsHunter Native Memory Scanner".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1055.001", "Dynamic-link Library Injection", "Injecting DLL paths via VirtualAllocEx and CreateRemoteThread."),
                MitreSubtechnique::new("T1055.012", "Process Hollowing", "Unmapping process memory space and replacing with malicious payload."),
            ],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1548".into(),
            name: "Abuse Elevation Control Mechanism".into(),
            tactic_id: "TA0004".into(),
            tactic_name: "Privilege Escalation".into(),
            description: "Adversaries circumvent elevation mechanisms like Windows UAC or sudo rules to gain SYSTEM/root.".into(),
            data_sources: vec!["Process: Process Creation".into(), "Windows Registry: Registry Key Modification".into()],
            mitigations: vec!["M1052: User Account Control".into()],
            groups: vec!["FIN7".into(), "Sandworm Team".into()],
            detection_mechanisms: vec!["Sysmon Event 1".into(), "Sigma Rule: UAC Bypass via Fodhelper / Eventvwr".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1548.002", "Bypass User Account Control", "Leveraging auto-elevating binaries or registry mockups to bypass UAC."),
            ],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1134".into(),
            name: "Access Token Manipulation".into(),
            tactic_id: "TA0004".into(),
            tactic_name: "Privilege Escalation".into(),
            description: "Adversaries modify or duplicate Windows access tokens to operate under different security contexts.".into(),
            data_sources: vec!["Process: Process Access".into()],
            mitigations: vec!["M1026: Privileged Account Management".into()],
            groups: vec!["APT29".into(), "Wizard Spider".into()],
            detection_mechanisms: vec!["Sysmon Event 10".into(), "Token Stealing Canary".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1134.001", "Token Impersonation/Theft", "Duplicating tokens from privileged processes like winlogon or lsass."),
            ],
            ..Default::default()
        },

        // --- 7. Defense Evasion (TA0005) ---
        MitreTechnique {
            id: "T1564".into(),
            name: "Hide Artifacts".into(),
            tactic_id: "TA0005".into(),
            tactic_name: "Defense Evasion".into(),
            description: "Adversaries hide presence by concealing files, directories, windows, or alternate data streams.".into(),
            data_sources: vec!["File: File Modification".into(), "Command: Command Execution".into()],
            mitigations: vec!["M1022: Restrict File and Directory Permissions".into()],
            groups: vec!["Lazarus Group".into(), "FIN7".into()],
            detection_mechanisms: vec!["Sysmon Event 1 (attrib.exe +h)".into(), "Sigma: Hiding Files with Attrib".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1564.001", "Hidden Files and Directories", "Applying hidden or system attribute flags to evasion targets."),
                MitreSubtechnique::new("T1564.004", "NTFS File Attributes", "Writing malicious executables into alternate data streams (ADS)."),
            ],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1036".into(),
            name: "Masquerading".into(),
            tactic_id: "TA0005".into(),
            tactic_name: "Defense Evasion".into(),
            description: "Adversaries manipulate process names, paths, or file extensions to blend into benign system activity.".into(),
            data_sources: vec!["Process: Process Creation".into(), "File: File Creation".into()],
            mitigations: vec!["M1038: Execution Prevention".into()],
            groups: vec!["APT28".into(), "Sandworm Team".into(), "Volt Typhoon".into()],
            detection_mechanisms: vec!["Sysmon Event 1".into(), "Military Engine: Decoy Process Locator".into(), "Authenticode Verifier".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1036.005", "Match Legitimate Name or Location", "Running svchost.exe or lsass.exe outside of System32."),
            ],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1112".into(),
            name: "Modify Registry".into(),
            tactic_id: "TA0005".into(),
            tactic_name: "Defense Evasion".into(),
            description: "Adversaries modify Windows Registry entries to hide evidence or tamper with configuration.".into(),
            data_sources: vec!["Windows Registry: Registry Key Modification".into()],
            mitigations: vec!["M1028: Operating System Configuration".into()],
            groups: vec!["LockBit".into(), "BlackCat".into()],
            detection_mechanisms: vec!["Sysmon Event 13".into(), "Registry Repair Rollback".into()],
            subtechniques: vec![],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1070".into(),
            name: "Indicator Removal".into(),
            tactic_id: "TA0005".into(),
            tactic_name: "Defense Evasion".into(),
            description: "Adversaries delete event logs, file artifacts, and history to prevent post-incident forensic analysis.".into(),
            data_sources: vec!["Command: Command Execution".into(), "File: File Deletion".into()],
            mitigations: vec!["M1047: Audit & Security Logging".into(), "M1053: Data Backup & Immutability".into()],
            groups: vec!["Volt Typhoon".into(), "Sandworm Team".into()],
            detection_mechanisms: vec!["Sysmon Event 1 (wevtutil cl)".into(), "WORM Audit Trail Attestation".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1070.001", "Clear Windows Event Logs", "Executing wevtutil.exe to wipe Security/System logs."),
                MitreSubtechnique::new("T1070.004", "File Deletion", "Securely wiping artifacts via sdelete or native del."),
            ],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1218".into(),
            name: "System Binary Proxy Execution".into(),
            tactic_id: "TA0005".into(),
            tactic_name: "Defense Evasion".into(),
            description: "Adversaries execute code through trusted signed binaries (LOLBins) like rundll32, regsvr32, mshta.".into(),
            data_sources: vec!["Process: Process Creation".into(), "Command: Command Execution".into()],
            mitigations: vec!["M1038: Execution Prevention".into()],
            groups: vec!["APT29".into(), "FIN7".into(), "Volt Typhoon".into()],
            detection_mechanisms: vec!["Sysmon Event 1".into(), "Sigma Rule: Rundll32 with Suspicious Exports".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1218.011", "Rundll32", "Executing DLL export functions via rundll32.exe."),
                MitreSubtechnique::new("T1218.005", "Mshta", "Executing malicious VBScript or JScript via mshta.exe."),
                MitreSubtechnique::new("T1218.010", "Regsvr32", "Executing COM scriptlets via regsvr32.exe /s /u /i."),
            ],
            ..Default::default()
        },

        // --- 8. Defense Impairment (TA0112) ---
        MitreTechnique {
            id: "T1562".into(),
            name: "Impair Defenses".into(),
            tactic_id: "TA0112".into(),
            tactic_name: "Defense Impairment".into(),
            description: "Adversaries intentionally disable or modify security tools, firewalls, and logging agents.".into(),
            data_sources: vec!["Service: Service Modification".into(), "Process: Process Termination".into(), "Windows Registry".into()],
            mitigations: vec!["M1028: Operating System Configuration".into(), "M1047: Audit & Security Logging".into()],
            groups: vec!["LockBit".into(), "BlackCat".into(), "Sandworm Team".into()],
            detection_mechanisms: vec!["Sysmon Event 1 (sc stop WinDefend)".into(), "Heartbeat Anti-Blinding Engine".into(), "Sigma Rule: Disable Defender".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1562.001", "Disable or Modify Tools", "Unloading drivers, killing EDR processes, disabling AMSI."),
                MitreSubtechnique::new("T1562.004", "Disable or Modify System Firewall", "Using netsh advfirewall to allow arbitrary ingress."),
            ],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1685".into(),
            name: "Disable or Modify Tools".into(),
            tactic_id: "TA0112".into(),
            tactic_name: "Defense Impairment".into(),
            description: "Adversaries neutralize endpoint sensors, tampering with agent configurations and telemetry pipes.".into(),
            data_sources: vec!["Process: Process Termination".into(), "Driver: Driver Unload".into()],
            mitigations: vec!["M1040: Behavior Prevention on Endpoint".into()],
            groups: vec!["Wizard Spider".into(), "LockBit".into()],
            detection_mechanisms: vec!["Agent Self-Defense Sentinel".into(), "eBPF/ETW Stream Integrity Check".into()],
            subtechniques: vec![],
            ..Default::default()
        },

        // --- 9. Credential Access (TA0006) ---
        MitreTechnique {
            id: "T1003".into(),
            name: "OS Credential Dumping".into(),
            tactic_id: "TA0006".into(),
            tactic_name: "Credential Access".into(),
            description: "Adversaries attempt to dump system credentials from memory, SAM database, or NTDS.dit.".into(),
            data_sources: vec!["Process: Process Access".into(), "Command: Command Execution".into()],
            mitigations: vec!["M1026: Privileged Account Management".into(), "M1010: Deploy Compromised Credential Detection".into()],
            groups: vec!["APT29".into(), "APT28".into(), "Volt Typhoon".into(), "FIN7".into(), "Lazarus Group".into()],
            detection_mechanisms: vec!["Sysmon Event 10 (LSASS Access Mask 0x1010/0x143a)".into(), "Synthetic Honey-Credentials".into(), "Sigma: Mimikatz / Procdump".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1003.001", "LSASS Memory", "Dumping plaintext credentials and hashes from LSASS memory space."),
                MitreSubtechnique::new("T1003.002", "Security Account Manager", "Extracting local hashes from HKLM\\SAM and HKLM\\SYSTEM."),
                MitreSubtechnique::new("T1003.003", "NTDS", "Extracting Active Directory ntds.dit database via ntdsutil or vssadmin."),
            ],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1110".into(),
            name: "Brute Force".into(),
            tactic_id: "TA0006".into(),
            tactic_name: "Credential Access".into(),
            description: "Adversaries use password guessing or password spraying against accounts to acquire valid credentials.".into(),
            data_sources: vec!["User Account: Authentication".into()],
            mitigations: vec!["M1036: Account Use Policies".into()],
            groups: vec!["APT28".into(), "BlackCat".into()],
            detection_mechanisms: vec!["Windows Event 4625 Failure Spikes".into(), "Dynamic Tarpit Throttler".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1110.001", "Password Guessing", "Targeting single accounts with high-frequency password dictionary attacks."),
                MitreSubtechnique::new("T1110.003", "Password Spraying", "Iterating a single common password across hundreds of domain users."),
            ],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1558".into(),
            name: "Steal or Forge Kerberos Tickets".into(),
            tactic_id: "TA0006".into(),
            tactic_name: "Credential Access".into(),
            description: "Adversaries abuse Kerberos ticketing (Kerberoasting, AS-REP Roasting, Golden/Silver tickets) to compromise credentials.".into(),
            data_sources: vec!["Active Directory: Kerberos Ticket Request".into()],
            mitigations: vec!["M1026: Privileged Account Management".into()],
            groups: vec!["FIN7".into(), "Wizard Spider".into()],
            detection_mechanisms: vec!["Event 4769 RC4 Encryption Requests".into(), "Kerberos Honey-SPN Canary".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1558.003", "Kerberoasting", "Requesting TGS service tickets for user accounts with SPNs to crack offline."),
            ],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1555".into(),
            name: "Credentials from Password Stores".into(),
            tactic_id: "TA0006".into(),
            tactic_name: "Credential Access".into(),
            description: "Adversaries search local system password stores, web browsers, and credential vaults for cached secrets.".into(),
            data_sources: vec!["File: File Access".into()],
            mitigations: vec!["M1041: Encrypt Sensitive Information".into()],
            groups: vec!["Lazarus Group".into(), "LockBit".into()],
            detection_mechanisms: vec!["Browser Guard: Login Data Vault Access".into(), "Sysmon Event 11".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1555.003", "Web Browsers", "Extracting SQLite Login Data and cookies from Chrome, Edge, Firefox."),
            ],
            ..Default::default()
        },

        // --- 10. Discovery (TA0007) ---
        MitreTechnique {
            id: "T1082".into(),
            name: "System Information Discovery".into(),
            tactic_id: "TA0007".into(),
            tactic_name: "Discovery".into(),
            description: "Adversaries gather detailed information about the operating system, architecture, and hardware specs.".into(),
            data_sources: vec!["Process: Process Creation".into(), "Command: Command Execution".into()],
            mitigations: vec!["M1047: Audit & Security Logging".into()],
            groups: vec!["APT29".into(), "APT28".into(), "Lazarus Group".into(), "Volt Typhoon".into(), "BlackCat".into()],
            detection_mechanisms: vec!["Sysmon Event 1 (systeminfo / hostname)".into(), "Sigma Rule: Discovery Commands".into()],
            subtechniques: vec![],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1033".into(),
            name: "System Owner/User Discovery".into(),
            tactic_id: "TA0007".into(),
            tactic_name: "Discovery".into(),
            description: "Adversaries may attempt to identify the primary user, currently logged in user, prior user, or whether the user is an administrator.".into(),
            data_sources: vec!["Process: Process Creation".into(), "Command: Command Execution".into()],
            mitigations: vec!["M1047: Audit & Security Logging".into()],
            groups: vec!["APT29".into(), "APT28".into(), "Lazarus Group".into(), "Wizard Spider".into()],
            detection_mechanisms: vec!["Sysmon Event 1 (whoami)".into(), "Sigma Rule: Whoami Execution".into()],
            subtechniques: vec![],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1057".into(),
            name: "Process Discovery".into(),
            tactic_id: "TA0007".into(),
            tactic_name: "Discovery".into(),
            description: "Adversaries enumerate running processes to understand what software and security tools are running.".into(),
            data_sources: vec!["Process: Process Creation".into(), "Command: Command Execution".into()],
            mitigations: vec!["M1047: Audit & Security Logging".into()],
            groups: vec!["APT29".into(), "Sandworm Team".into(), "Volt Typhoon".into()],
            detection_mechanisms: vec!["Sysmon Event 1 (tasklist / ps)".into(), "Sigma: Process Enumeration".into()],
            subtechniques: vec![],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1046".into(),
            name: "Network Service Discovery".into(),
            tactic_id: "TA0007".into(),
            tactic_name: "Discovery".into(),
            description: "Adversaries attempt to enumerate remote services over the local network to locate target pivots.".into(),
            data_sources: vec!["Network Traffic: Network Connection".into()],
            mitigations: vec!["M1030: Network Segmentation".into()],
            groups: vec!["Volt Typhoon".into(), "APT28".into()],
            detection_mechanisms: vec!["Military Engine: Phantom Mesh Scout".into(), "Sysmon Event 3".into()],
            subtechniques: vec![],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1016".into(),
            name: "System Network Configuration Discovery".into(),
            tactic_id: "TA0007".into(),
            tactic_name: "Discovery".into(),
            description: "Adversaries look for details about the network configuration, adapters, IP addresses, and routing tables.".into(),
            data_sources: vec!["Process: Process Creation".into(), "Command: Command Execution".into()],
            mitigations: vec!["M1047: Audit & Security Logging".into()],
            groups: vec!["Volt Typhoon".into(), "Lazarus Group".into(), "APT29".into()],
            detection_mechanisms: vec!["Sysmon Event 1 (ipconfig / route print / netstat)".into(), "Sigma: Network Discovery".into()],
            subtechniques: vec![],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1087".into(),
            name: "Account Discovery".into(),
            tactic_id: "TA0007".into(),
            tactic_name: "Discovery".into(),
            description: "Adversaries enumerate accounts and administrative groups to plan privilege escalation and lateral movement.".into(),
            data_sources: vec!["Command: Command Execution".into()],
            mitigations: vec!["M1047: Audit & Security Logging".into()],
            groups: vec!["APT29".into(), "LockBit".into(), "Wizard Spider".into()],
            detection_mechanisms: vec!["Sysmon Event 1 (net user / net group / whoami /groups)".into(), "Sigma: Account Enumeration".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1087.001", "Local Accounts", "Querying local SAM accounts via net localgroup."),
                MitreSubtechnique::new("T1087.002", "Domain Accounts", "Querying Active Directory LDAP for domain admin accounts."),
            ],
            ..Default::default()
        },

        // --- 11. Lateral Movement (TA0008) ---
        MitreTechnique {
            id: "T1021".into(),
            name: "Remote Services".into(),
            tactic_id: "TA0008".into(),
            tactic_name: "Lateral Movement".into(),
            description: "Adversaries log into remote systems using valid credentials on services like RDP, SMB, and SSH.".into(),
            data_sources: vec!["Network Traffic: Network Connection".into(), "Logon Session: Creation".into()],
            mitigations: vec!["M1030: Network Segmentation".into(), "M1035: Limit Access to Resource Over Network".into()],
            groups: vec!["Volt Typhoon".into(), "BlackCat".into(), "LockBit".into(), "APT29".into()],
            detection_mechanisms: vec!["Sysmon Event 3 (Port 3389/445)".into(), "Military Engine: Mesh Whispering".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1021.001", "Remote Desktop Protocol", "Connecting to remote workstations via mstsc.exe."),
                MitreSubtechnique::new("T1021.002", "SMB/Windows Admin Shares", "Accessing ADMIN$ or C$ shares to push payloads."),
                MitreSubtechnique::new("T1021.004", "SSH", "Logging into Unix servers via SSH keys."),
            ],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1570".into(),
            name: "Lateral Tool Transfer".into(),
            tactic_id: "TA0008".into(),
            tactic_name: "Lateral Movement".into(),
            description: "Adversaries transfer tools, scripts, or malware payloads between compromised internal systems.".into(),
            data_sources: vec!["File: File Creation".into(), "Network Traffic".into()],
            mitigations: vec!["M1037: Filter Network Traffic".into()],
            groups: vec!["Sandworm Team".into(), "Lazarus Group".into()],
            detection_mechanisms: vec!["Sysmon Event 11".into(), "YARA-X Lateral Wire Scanner".into()],
            subtechniques: vec![],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1550".into(),
            name: "Use Alternate Authentication Material".into(),
            tactic_id: "TA0008".into(),
            tactic_name: "Lateral Movement".into(),
            description: "Adversaries use alternate authentication material (NTLM hashes, Kerberos tickets) to authenticate without passwords.".into(),
            data_sources: vec!["User Account: Authentication".into()],
            mitigations: vec!["M1026: Privileged Account Management".into()],
            groups: vec!["APT29".into(), "FIN7".into()],
            detection_mechanisms: vec!["Windows Event 4624 (Logon Type 3 NTLM)".into(), "Mimikatz Pass-The-Hash Voter".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1550.002", "Pass the Hash", "Authenticating to remote services using NTLM hashes instead of plain text."),
            ],
            ..Default::default()
        },

        // --- 12. Collection (TA0009) ---
        MitreTechnique {
            id: "T1119".into(),
            name: "Automated Collection".into(),
            tactic_id: "TA0009".into(),
            tactic_name: "Collection".into(),
            description: "Adversaries employ automated batch scripts to search for and stage sensitive files on the filesystem.".into(),
            data_sources: vec!["Process: Process Creation".into(), "Command: Command Execution".into()],
            mitigations: vec!["M1022: Restrict File and Directory Permissions".into()],
            groups: vec!["APT28".into(), "Volt Typhoon".into(), "BlackCat".into()],
            detection_mechanisms: vec!["Sysmon Event 1".into(), "PII Classifier".into(), "Sigma: Scripted File Gathering".into()],
            subtechniques: vec![],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1005".into(),
            name: "Data from Local System".into(),
            tactic_id: "TA0009".into(),
            tactic_name: "Collection".into(),
            description: "Adversaries search local storage drives and database files for confidential business documents.".into(),
            data_sources: vec!["File: File Access".into()],
            mitigations: vec!["M1041: Encrypt Sensitive Information".into()],
            groups: vec!["APT29".into(), "LockBit".into()],
            detection_mechanisms: vec!["Sysmon Event 11".into(), "Military Engine: Loitering Strike Watcher".into()],
            subtechniques: vec![],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1113".into(),
            name: "Screen Capture".into(),
            tactic_id: "TA0009".into(),
            tactic_name: "Collection".into(),
            description: "Adversaries take screenshots to gather visual evidence of user activity and open documents.".into(),
            data_sources: vec!["Process: Process Creation".into(), "Command: Command Execution".into()],
            mitigations: vec!["M1040: Behavior Prevention on Endpoint".into()],
            groups: vec!["FIN7".into(), "Silence".into()],
            detection_mechanisms: vec!["GDI Screen Capture Hook".into(), "Sysmon Event 1".into()],
            subtechniques: vec![],
            ..Default::default()
        },

        // --- 13. Command and Control (TA0011) ---
        MitreTechnique {
            id: "T1071".into(),
            name: "Application Layer Protocol".into(),
            tactic_id: "TA0011".into(),
            tactic_name: "Command and Control".into(),
            description: "Adversaries communicate using OSI application layer protocols (HTTP, HTTPS, DNS) to blend in with traffic.".into(),
            data_sources: vec!["Network Traffic: Network Traffic Content".into(), "Network Traffic: Network Connection".into()],
            mitigations: vec!["M1037: Filter Network Traffic".into(), "M1031: Network Intrusion Prevention".into()],
            groups: vec!["APT29".into(), "APT28".into(), "Lazarus Group".into(), "Volt Typhoon".into(), "BlackCat".into()],
            detection_mechanisms: vec!["WFP NetFilter Egress Sandbox".into(), "Sysmon Event 3".into(), "Sigma: Beaconing C2 Traffic".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1071.001", "Web Protocols", "C2 beacons disguised as HTTPS web browser requests."),
                MitreSubtechnique::new("T1071.004", "DNS", "C2 communication tunneled through malicious DNS subdomains (DNS Tunneling)."),
            ],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1573".into(),
            name: "Encrypted Channel".into(),
            tactic_id: "TA0011".into(),
            tactic_name: "Command and Control".into(),
            description: "Adversaries employ cryptography (TLS, AES, custom algorithms) to obscure C2 instructions and stolen data.".into(),
            data_sources: vec!["Network Traffic: Network Traffic Flow".into()],
            mitigations: vec!["M1031: Network Intrusion Prevention".into()],
            groups: vec!["APT29".into(), "Sandworm Team".into()],
            detection_mechanisms: vec!["JA3 / JA4 Fingerprint Voter".into(), "Agent Egress Voter".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1573.001", "Symmetric Cryptography", "C2 commands encrypted with AES or ChaCha20."),
                MitreSubtechnique::new("T1573.002", "Asymmetric Cryptography", "Implant using RSA or Curve25519 to verify operator keys."),
            ],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1105".into(),
            name: "Ingress Tool Transfer".into(),
            tactic_id: "TA0011".into(),
            tactic_name: "Command and Control".into(),
            description: "Adversaries transfer tools or other files from an external system into a compromised network.".into(),
            data_sources: vec!["File: File Creation".into(), "Network Traffic: Network Connection".into()],
            mitigations: vec!["M1037: Filter Network Traffic".into(), "M1038: Execution Prevention".into()],
            groups: vec!["Volt Typhoon".into(), "Lazarus Group".into(), "LockBit".into(), "BlackCat".into()],
            detection_mechanisms: vec!["Sysmon Event 1 (certutil -urlcache / curl / bitsadmin)".into(), "Static Analyzer (CAPA/YARA)".into()],
            subtechniques: vec![],
            ..Default::default()
        },

        // --- 14. Exfiltration (TA0010) ---
        MitreTechnique {
            id: "T1041".into(),
            name: "Exfiltration Over C2 Channel".into(),
            tactic_id: "TA0010".into(),
            tactic_name: "Exfiltration".into(),
            description: "Adversaries steal sensitive data by transmitting it over existing established Command and Control channels.".into(),
            data_sources: vec!["Command: Command Execution".into(), "Network Traffic: Network Traffic Flow".into()],
            mitigations: vec!["M1037: Filter Network Traffic".into()],
            groups: vec!["APT29".into(), "Lazarus Group".into(), "Sandworm Team".into()],
            detection_mechanisms: vec!["High-Volume Egress Alert".into(), "Agent Network Egress Voter".into()],
            subtechniques: vec![],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1567".into(),
            name: "Exfiltration Over Web Service".into(),
            tactic_id: "TA0010".into(),
            tactic_name: "Exfiltration".into(),
            description: "Adversaries exfiltrate data to public cloud storage services (MEGA, Google Drive, OneDrive, Discord).".into(),
            data_sources: vec!["Network Traffic: Web Traffic".into()],
            mitigations: vec!["M1037: Filter Network Traffic".into()],
            groups: vec!["BlackCat".into(), "LockBit".into()],
            detection_mechanisms: vec!["Cloud Storage Destination Monitor".into(), "WFP Egress Filter".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1567.002", "Exfiltration to Cloud Storage", "Uploading archived bundles to AWS S3 or MEGA."),
            ],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1048".into(),
            name: "Exfiltration Over Alternative Protocol".into(),
            tactic_id: "TA0010".into(),
            tactic_name: "Exfiltration".into(),
            description: "Adversaries steal data by piping it over non-C2 protocols like FTP, DNS, or raw TCP sockets.".into(),
            data_sources: vec!["Network Traffic: Network Connection".into()],
            mitigations: vec!["M1037: Filter Network Traffic".into()],
            groups: vec!["APT28".into(), "FIN7".into()],
            detection_mechanisms: vec!["Sysmon Event 3".into(), "Agent Egress Sandbox".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1048.003", "Exfiltration Over Unencrypted Non-C2 Protocol", "Pushing stolen files over raw FTP or DNS."),
            ],
            ..Default::default()
        },

        // --- 15. Impact (TA0040) ---
        MitreTechnique {
            id: "T1486".into(),
            name: "Data Encrypted for Impact".into(),
            tactic_id: "TA0040".into(),
            tactic_name: "Impact".into(),
            description: "Adversaries encrypt data on target systems to interrupt availability and extort ransom payments.".into(),
            data_sources: vec!["File: File Modification".into(), "Process: Process Creation".into()],
            mitigations: vec!["M1053: Data Backup & Immutability".into(), "M1040: Behavior Prevention on Endpoint".into()],
            groups: vec!["LockBit".into(), "BlackCat".into(), "Wizard Spider".into()],
            detection_mechanisms: vec!["Synthetic Ransomware Honey-Canary".into(), "Mass File Renaming Sentinel".into(), "Entropy Spike Detector".into()],
            subtechniques: vec![],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1490".into(),
            name: "Inhibit System Recovery".into(),
            tactic_id: "TA0040".into(),
            tactic_name: "Impact".into(),
            description: "Adversaries delete or disable system recovery mechanisms (Volume Shadow Copies, system restore points, bcdedit).".into(),
            data_sources: vec!["Command: Command Execution".into(), "Process: Process Creation".into()],
            mitigations: vec!["M1053: Data Backup & Immutability".into()],
            groups: vec!["LockBit".into(), "BlackCat".into(), "Sandworm Team".into()],
            detection_mechanisms: vec!["Sysmon Event 1 (vssadmin delete shadows / wbadmin / bcdedit)".into(), "Sigma: Inhibit System Recovery".into(), "WORM Backup Lock".into()],
            subtechniques: vec![],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1499".into(),
            name: "Endpoint Denial of Service".into(),
            tactic_id: "TA0040".into(),
            tactic_name: "Impact".into(),
            description: "Adversaries degrade or crash target systems by exhausting CPU, memory, or thread pools.".into(),
            data_sources: vec!["Sensor Health: Host Sensor".into()],
            mitigations: vec!["M1028: Operating System Configuration".into()],
            groups: vec!["Sandworm Team".into()],
            detection_mechanisms: vec!["Adaptive Telemetry Controller".into(), "Socket Exhaustion Guard".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1499.001", "OS Exhaustion Flood", "Flooding internal handles and thread creation to induce BSOD."),
            ],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1489".into(),
            name: "Service Stop".into(),
            tactic_id: "TA0040".into(),
            tactic_name: "Impact".into(),
            description: "Adversaries stop or disable critical business services to disrupt operations or unlock database files.".into(),
            data_sources: vec!["Service: Service Modification".into(), "Command: Command Execution".into()],
            mitigations: vec!["M1028: Operating System Configuration".into()],
            groups: vec!["LockBit".into(), "Sandworm Team".into()],
            detection_mechanisms: vec!["Sysmon Event 1 (net stop / sc stop)".into(), "Service Supervisor".into()],
            subtechniques: vec![],
            ..Default::default()
        },
        MitreTechnique {
            id: "T1561".into(),
            name: "Disk Wipe".into(),
            tactic_id: "TA0040".into(),
            tactic_name: "Impact".into(),
            description: "Adversaries overwrite disk sectors and master boot records (MBR/GPT) to render the system completely unbootable.".into(),
            data_sources: vec!["Drive: Drive Access".into()],
            mitigations: vec!["M1053: Data Backup & Immutability".into()],
            groups: vec!["Sandworm Team".into(), "Lazarus Group".into()],
            detection_mechanisms: vec!["Physical Drive Lock".into(), "TPM Attested Integrity Check".into()],
            subtechniques: vec![
                MitreSubtechnique::new("T1561.001", "Disk Content Wipe", "Zeroing or corrupting raw filesystem partitions."),
                MitreSubtechnique::new("T1561.002", "Disk Structure Wipe", "Destroying MBR/GPT partition tables to induce boot failure."),
            ],
            ..Default::default()
        },

        // --- MITRE ATLAS AI Threat Matrix Techniques ---
        MitreTechnique {
            id: "AML.T0043".into(),
            name: "Adversarial Prompt Injection / Tool-Argument Injection".into(),
            tactic_id: "TA0002".into(),
            tactic_name: "Execution".into(),
            description: "Adversaries craft malicious prompt inputs or jailbreak sequences that manipulate an autonomous LLM agent into executing arbitrary downstream shell commands, unauthorized sub-processes, or abusing tool arguments.".into(),
            platforms: vec!["AI Agent".into(), "LLM Runtime".into(), "Python".into(), "Node.js".into()],
            data_sources: vec!["Process: Process Creation (Sysmon Event 1)".into(), "Command: Scriptblock Execution (Windows PowerShell 4104)".into(), "AI Agent Tool-Execution Telemetry".into()],
            voter: "AiSecurityAuditVoter".into(),
            consensus_action: "Tarpit".into(),
            mitigations: vec!["AML.M0015: User Prompt Sanitization & Invariant Enforcement".into(), "AML.M0016: Restrict Tool / Subprocess Execution Privileges".into()],
            groups: vec!["Lazarus Group".into(), "Scattered Spider".into(), "Volt Typhoon".into()],
            detection_mechanisms: vec!["OpenỌ̀ṣọ́ọ̀sì AiSecurityAuditVoter".into(), "Sysmon Event 1 (Process Creation)".into()],
            is_atlas: true,
            sigma_rules: vec!["AI Agent Shell Injection Attempt".into(), "Tool Argument Traversal Pattern".into()],
            subtechniques: vec![],
        },
        MitreTechnique {
            id: "AML.T0044".into(),
            name: "AI Tool Path Traversal / Insecure Output Handling".into(),
            tactic_id: "TA0002".into(),
            tactic_name: "Execution".into(),
            description: "Adversaries supply crafted path traversal sequences into LLM agent tool parameters, tricking the autonomous agent into reading or overwriting sensitive host resources outside its workspace boundary.".into(),
            platforms: vec!["AI Agent".into(), "LLM Runtime".into(), "FileSystem".into()],
            data_sources: vec!["File: File Access / Modification (Sysmon Event 11)".into(), "Process: Process Creation (Sysmon Event 1)".into(), "Kernel DACL Boundary Violations".into()],
            voter: "AiSecurityAuditVoter".into(),
            consensus_action: "Tarpit".into(),
            mitigations: vec!["AML.M0016: Restrict Tool / Subprocess Execution Privileges".into(), "AML.M0018: Isolate AI Agent Runtime & State".into()],
            groups: vec!["APT29".into(), "Volt Typhoon".into()],
            detection_mechanisms: vec!["OpenỌ̀ṣọ́ọ̀sì AiSecurityAuditVoter".into(), "Sysmon Event 11 (File Modification)".into()],
            is_atlas: true,
            sigma_rules: vec!["AI Tool Workspace Path Traversal".into()],
            subtechniques: vec![],
        },
        MitreTechnique {
            id: "AML.T0048".into(),
            name: "Agent Memory & State Poisoning".into(),
            tactic_id: "TA0003".into(),
            tactic_name: "Persistence".into(),
            description: "Adversaries tamper with long-term agent state, persistent memory stores, or policy configuration files (.agents/memory.md, osoosi.toml) to introduce persistent backdoor instructions that survive restarts and session resets.".into(),
            platforms: vec!["AI Agent".into(), "Vector Database".into(), "Memory Store".into()],
            data_sources: vec!["File: File Modification (Sysmon Event 11)".into(), "Registry: Key Value Tampering (Sysmon Event 13)".into(), "Differential Privacy & Merkle Audit Trail".into()],
            voter: "AiSecurityAuditVoter".into(),
            consensus_action: "Isolate".into(),
            mitigations: vec!["AML.M0018: Isolate AI Agent Runtime & State".into(), "AML.M0015: User Prompt Sanitization & Invariant Enforcement".into()],
            groups: vec!["APT28".into(), "Midnight Blizzard".into(), "Sandworm Team".into()],
            detection_mechanisms: vec!["OpenỌ̀ṣọ́ọ̀sì AiSecurityAuditVoter".into(), "Sysmon Event 11 (File Modification)".into()],
            is_atlas: true,
            sigma_rules: vec!["Agent State File Unauthorized Modification".into()],
            subtechniques: vec![],
        },
        MitreTechnique {
            id: "AML.T0040".into(),
            name: "AI Runtime Remote Thread Injection".into(),
            tactic_id: "TA0004".into(),
            tactic_name: "Privilege Escalation".into(),
            description: "Adversaries inject shellcode or create remote execution threads inside active AI runtime worker processes (python.exe, node.exe, ollama.exe) to elevate privileges, evade defensive hooks, or hijack autonomous agent credentials.".into(),
            platforms: vec!["Windows".into(), "Linux".into(), "AI Agent".into()],
            data_sources: vec!["Process: CreateRemoteThread (Sysmon Event 8)".into(), "Process: ProcessAccess (Sysmon Event 10)".into(), "ETW Threat-Intelligence Telemetry".into()],
            voter: "AiSecurityAuditVoter".into(),
            consensus_action: "Isolate".into(),
            mitigations: vec!["AML.M0016: Restrict Tool / Subprocess Execution Privileges".into(), "AML.M0018: Isolate AI Agent Runtime & State".into()],
            groups: vec!["Wizard Spider".into(), "Lazarus Group".into()],
            detection_mechanisms: vec!["OpenỌ̀ṣọ́ọ̀sì AiSecurityAuditVoter".into(), "Sysmon Event 8 (CreateRemoteThread)".into()],
            is_atlas: true,
            sigma_rules: vec!["Remote Thread Created In AI Runtime Process".into()],
            subtechniques: vec![],
        },
        MitreTechnique {
            id: "AML.T0029".into(),
            name: "Disarm AI Safeguards / Runtime Memory Tampering".into(),
            tactic_id: "TA0112".into(),
            tactic_name: "Defense Impairment".into(),
            description: "Adversaries tamper with the memory space of EDR monitoring agents or AI safeguard processes, modifying protection invariants, unhooking syscalls, or requesting PROCESS_VM_WRITE access to disarm defensive telemetry.".into(),
            platforms: vec!["AI Agent".into(), "Windows".into(), "Linux".into()],
            data_sources: vec!["Process: ProcessAccess (Sysmon Event 10)".into(), "Driver / Kernel Invariant Monitor".into(), "Hardware Breakpoint & Thread Context Inspection".into()],
            voter: "AiSecurityAuditVoter".into(),
            consensus_action: "Isolate".into(),
            mitigations: vec!["AML.M0018: Isolate AI Agent Runtime & State".into()],
            groups: vec!["LockBit".into(), "BlackCat / ALPHV".into(), "Turla".into()],
            detection_mechanisms: vec!["OpenỌ̀ṣọ́ọ̀sì AiSecurityAuditVoter".into(), "Sysmon Event 10 (ProcessAccess)".into()],
            is_atlas: true,
            sigma_rules: vec!["Suspicious Write Process Memory Into Agent Engine".into()],
            subtechniques: vec![],
        },
        MitreTechnique {
            id: "AML.T0051".into(),
            name: "LLM Jailbreak / Prompt Obfuscation".into(),
            tactic_id: "TA0005".into(),
            tactic_name: "Defense Evasion".into(),
            description: "Adversaries bypass AI alignment guardrails using obfuscated multi-turn payloads, base64 encoding, rot13, markdown smuggling, or character escaping to induce the AI agent into executing forbidden behaviors.".into(),
            platforms: vec!["AI Agent".into(), "LLM Runtime".into()],
            data_sources: vec!["Process: Process Creation (Sysmon Event 1)".into(), "Agentic Minimax Drift Tracker".into(), "Canary Variable & Trap Monitoring".into()],
            voter: "AgenticVoter".into(),
            consensus_action: "Tarpit".into(),
            mitigations: vec!["AML.M0015: User Prompt Sanitization & Invariant Enforcement".into(), "AML.M0005: Model Output Sanitation / Guardrails".into()],
            groups: vec!["Scattered Spider".into(), "FIN7".into()],
            detection_mechanisms: vec!["OpenỌ̀ṣọ́ọ̀sì AgenticVoter".into(), "Sysmon Event 1 (Process Creation)".into()],
            is_atlas: true,
            sigma_rules: vec!["Obfuscated Base64 Shell In AI Prompt Context".into()],
            subtechniques: vec![],
        },
        MitreTechnique {
            id: "AML.T0054".into(),
            name: "Training Data / System Prompt Exfiltration".into(),
            tactic_id: "TA0010".into(),
            tactic_name: "Exfiltration".into(),
            description: "Adversaries probe autonomous AI agents to reveal proprietary system prompts, embedded API secrets, canary environment variables, or private training examples through side-channel query techniques.".into(),
            platforms: vec!["AI Agent".into(), "Cloud".into(), "LLM Runtime".into()],
            data_sources: vec!["Network: Outbound Connection (Sysmon Event 3)".into(), "AI Agent Canary Tripwire Trigger".into(), "Agent Egress Controller Audit".into()],
            voter: "AgenticVoter".into(),
            consensus_action: "Alert".into(),
            mitigations: vec!["AML.M0005: Model Output Sanitation / Guardrails".into(), "AML.M0018: Isolate AI Agent Runtime & State".into()],
            groups: vec!["APT29".into(), "Midnight Blizzard".into()],
            detection_mechanisms: vec!["OpenỌ̀ṣọ́ọ̀sì AgenticVoter".into(), "Sysmon Event 3 (Network Connection)".into()],
            is_atlas: true,
            sigma_rules: vec!["Canary Token In Outbound Network Traffic".into()],
            subtechniques: vec![],
        },
        MitreTechnique {
            id: "AML.T0042".into(),
            name: "Denial of ML Service / Sponge Attacks".into(),
            tactic_id: "TA0040".into(),
            tactic_name: "Impact".into(),
            description: "Adversaries craft computationally heavy inputs or infinite agent reasoning trajectories (sponge inputs) designed to exhaust hardware resources, spike memory utilization, and deny service to autonomous EDR inference.".into(),
            platforms: vec!["AI Agent".into(), "Model Inference".into(), "GPU / CPU".into()],
            data_sources: vec!["Process: CPU / GPU Saturation Metrics".into(), "Agent Trajectory Bounded PRM Step Counter".into(), "Adaptive Resource Category Monitor".into()],
            voter: "AgenticVoter".into(),
            consensus_action: "Tarpit".into(),
            mitigations: vec!["AML.M0016: Restrict Tool / Subprocess Execution Privileges".into()],
            groups: vec!["Sandworm Team".into(), "Silence".into()],
            detection_mechanisms: vec!["OpenỌ̀ṣọ́ọ̀sì AgenticVoter".into(), "Process Saturation Watchdog".into()],
            is_atlas: true,
            sigma_rules: vec!["Rapid Process Spawn Loop In AI Agent Context".into()],
            subtechniques: vec![],
        },
        MitreTechnique {
            id: "AML.T0031".into(),
            name: "Model Poisoning / Serialization Backdoors".into(),
            tactic_id: "TA0001".into(),
            tactic_name: "Initial Access".into(),
            description: "Adversaries distribute backdoored neural network weights or poisoned serialization files (e.g. pickle, ONNX, PyTorch checkpoints) that trigger remote code execution upon model initialization or load arbitrary payloads.".into(),
            platforms: vec!["PyTorch".into(), "ONNX".into(), "HuggingFace".into(), "Python".into()],
            data_sources: vec!["File: FileCreate / Download (Sysmon Event 11)".into(), "Malware: ONNX / MalConv Byte Inspection".into(), "YARA-X Model Deserialization Signatures".into()],
            voter: "ZeroDayVoter".into(),
            consensus_action: "Isolate".into(),
            mitigations: vec!["AML.M0017: Verify Cryptographic Integrity of Model Weights".into()],
            groups: vec!["Lazarus Group".into(), "APT28".into()],
            detection_mechanisms: vec!["OpenỌ̀ṣọ́ọ̀sì ZeroDayVoter".into(), "Sysmon Event 11 (FileCreate)".into()],
            is_atlas: true,
            sigma_rules: vec!["Malicious Model Weights Download Or Deserialization".into()],
            subtechniques: vec![],
        },
    ]
}

/// Returns the comprehensive catalog of MITRE ATT&CK Mitigations.
pub fn get_mitigations() -> Vec<MitreMitigation> {
    if let Some(cat) = get_catalog() {
        if !cat.mitigations.is_empty() {
            return cat.mitigations.clone();
        }
    }
    get_static_mitigations()
}

/// Fallback static compiled mitigations.
pub fn get_static_mitigations() -> Vec<MitreMitigation> {
    vec![
        MitreMitigation {
            id: "M1010".into(),
            name: "Deploy Compromised Credential Detection".into(),
            description: "Deploy mechanisms to detect compromised credentials on endpoints and identify unauthorized access attempts.".into(),
            techniques: vec!["T1003".into(), "T1110".into()],
            defense_type: "Detective".into(),
        },
        MitreMitigation {
            id: "M1013".into(),
            name: "Application Developer Guidance".into(),
            description: "Ensure applications validate user input, use safe API calls, and enforce memory safety.".into(),
            techniques: vec!["T1190".into(), "T1055".into()],
            defense_type: "Preventative".into(),
        },
        MitreMitigation {
            id: "M1017".into(),
            name: "User Training".into(),
            description: "Train users to be aware of social engineering techniques, spearphishing attachments, and suspicious links.".into(),
            techniques: vec!["T1566".into(), "T1598".into()],
            defense_type: "Administrative".into(),
        },
        MitreMitigation {
            id: "M1018".into(),
            name: "User Account Management".into(),
            description: "Manage the creation, modification, and disabling of user accounts across the enterprise identity provider.".into(),
            techniques: vec!["T1586".into(), "T1078".into()],
            defense_type: "Identity Governance".into(),
        },
        MitreMitigation {
            id: "M1021".into(),
            name: "Restrict Web-Based Content".into(),
            description: "Restrict use of certain web-based content and script execution in browsers and email clients.".into(),
            techniques: vec!["T1566".into(), "T1189".into()],
            defense_type: "Sandboxing".into(),
        },
        MitreMitigation {
            id: "M1022".into(),
            name: "Restrict File and Directory Permissions".into(),
            description: "Restrict access to sensitive files and directories using explicit NTFS/ACLs to prevent tampering.".into(),
            techniques: vec!["T1547".into(), "T1564".into(), "T1119".into()],
            defense_type: "Access Control".into(),
        },
        MitreMitigation {
            id: "M1026".into(),
            name: "Privileged Account Management".into(),
            description: "Manage the use of privileged accounts to prevent credential dumping and lateral impersonation.".into(),
            techniques: vec!["T1003".into(), "T1053".into(), "T1134".into(), "T1558".into()],
            defense_type: "Access Control".into(),
        },
        MitreMitigation {
            id: "M1028".into(),
            name: "Operating System Configuration".into(),
            description: "Harden operating system configurations to block insecure defaults, auto-runs, and execution surfaces.".into(),
            techniques: vec!["T1059".into(), "T1543".into(), "T1112".into(), "T1562".into(), "T1489".into()],
            defense_type: "Hardening".into(),
        },
        MitreMitigation {
            id: "M1030".into(),
            name: "Network Segmentation".into(),
            description: "Architect network segments and zero-trust perimeters to prevent lateral traversal.".into(),
            techniques: vec!["T1046".into(), "T1021".into(), "T1133".into()],
            defense_type: "Architectural".into(),
        },
        MitreMitigation {
            id: "M1031".into(),
            name: "Network Intrusion Prevention".into(),
            description: "Deploy intrusion prevention systems (NIPS/WFP) to inspect network packets and block anomalous traffic.".into(),
            techniques: vec!["T1595".into(), "T1071".into(), "T1573".into()],
            defense_type: "Network Defense".into(),
        },
        MitreMitigation {
            id: "M1035".into(),
            name: "Limit Access to Resource Over Network".into(),
            description: "Prevent access to remote internal administration shares and remote management protocols over the wire.".into(),
            techniques: vec!["T1021".into()],
            defense_type: "Network Defense".into(),
        },
        MitreMitigation {
            id: "M1036".into(),
            name: "Account Use Policies".into(),
            description: "Enforce strict password complexity, multi-factor authentication, and account lockout thresholds.".into(),
            techniques: vec!["T1110".into(), "T1650".into(), "T1133".into()],
            defense_type: "Administrative".into(),
        },
        MitreMitigation {
            id: "M1037".into(),
            name: "Filter Network Traffic".into(),
            description: "Filter inbound and outbound network traffic using Windows Filtering Platform (WFP) and hardware firewalls.".into(),
            techniques: vec!["T1071".into(), "T1105".into(), "T1041".into(), "T1567".into(), "T1048".into()],
            defense_type: "Preventative Sandbox".into(),
        },
        MitreMitigation {
            id: "M1038".into(),
            name: "Execution Prevention".into(),
            description: "Block unapproved binaries, scripts, and DLLs from executing using AppLocker, WDAC, or EDR policies.".into(),
            techniques: vec!["T1059".into(), "T1566".into(), "T1547".into(), "T1574".into(), "T1036".into(), "T1218".into()],
            defense_type: "Preventative".into(),
        },
        MitreMitigation {
            id: "M1040".into(),
            name: "Behavior Prevention on Endpoint".into(),
            description: "Use behavioral monitoring to identify and terminate malicious process chains and memory corruption attempts.".into(),
            techniques: vec!["T1055".into(), "T1685".into(), "T1113".into(), "T1486".into()],
            defense_type: "Behavioral EDR".into(),
        },
        MitreMitigation {
            id: "M1041".into(),
            name: "Encrypt Sensitive Information".into(),
            description: "Encrypt files, credentials, and databases at rest to render exfiltrated or dumped data useless.".into(),
            techniques: vec!["T1555".into(), "T1005".into()],
            defense_type: "Cryptographic".into(),
        },
        MitreMitigation {
            id: "M1042".into(),
            name: "Disable or Remove Feature or Program".into(),
            description: "Remove unnecessary applications, legacy protocols, and deprecated administrative tools.".into(),
            techniques: vec!["T1574".into()],
            defense_type: "Attack Surface Reduction".into(),
        },
        MitreMitigation {
            id: "M1047".into(),
            name: "Audit & Security Logging".into(),
            description: "Collect high-fidelity telemetry (ETW, Sysmon, Auditd, eBPF) for real-time behavioral correlation.".into(),
            techniques: vec!["T1082".into(), "T1057".into(), "T1016".into(), "T1087".into(), "T1070".into()],
            defense_type: "Telemetry / Detective".into(),
        },
        MitreMitigation {
            id: "M1049".into(),
            name: "Antivirus/Antimalware".into(),
            description: "Deploy multi-engine static and behavioral antimalware (YARA-X, Nabla AST, heuristics).".into(),
            techniques: vec!["T1587".into(), "T1055".into()],
            defense_type: "Detective / Preventative".into(),
        },
        MitreMitigation {
            id: "M1050".into(),
            name: "Exploit Protection".into(),
            description: "Enforce hardware-enforced exploit mitigations (DEP, ASLR, CFG, ACG, CET) on all endpoints.".into(),
            techniques: vec!["T1055".into(), "T1587".into()],
            defense_type: "Kernel Protection".into(),
        },
        MitreMitigation {
            id: "M1051".into(),
            name: "Update Software & Patching".into(),
            description: "Regularly update software, operating systems, and firmware based on CISA KEV and NVD vulnerability intelligence.".into(),
            techniques: vec!["T1190".into()],
            defense_type: "Patch Management".into(),
        },
        MitreMitigation {
            id: "M1052".into(),
            name: "User Account Control".into(),
            description: "Configure Windows User Account Control to Always Notify to prevent stealth elevation.".into(),
            techniques: vec!["T1548".into()],
            defense_type: "Access Control".into(),
        },
        MitreMitigation {
            id: "M1053".into(),
            name: "Data Backup & Immutability".into(),
            description: "Maintain immutable, offsite, and write-once-read-many (WORM) backups to survive ransomware destruction.".into(),
            techniques: vec!["T1486".into(), "T1490".into(), "T1561".into()],
            defense_type: "Resilience".into(),
        },
        MitreMitigation {
            id: "M1054".into(),
            name: "Software Configuration".into(),
            description: "Configure software to disable unnecessary remote services and enforce zero-trust policies.".into(),
            techniques: vec!["T1592".into(), "T1195".into()],
            defense_type: "Hardening".into(),
        },
        MitreMitigation {
            id: "M1056".into(),
            name: "Pre-compromise Threat Intelligence".into(),
            description: "Ingest and correlate global threat intelligence feeds (Nostr mesh, OTX, CISA KEV) before incidents occur.".into(),
            techniques: vec!["T1596".into(), "T1583".into()],
            defense_type: "Threat Intelligence".into(),
        },

        // --- MITRE ATLAS AI Mitigations ---
        MitreMitigation {
            id: "AML.M0005".into(),
            name: "Model Output Sanitation / Guardrails".into(),
            description: "Filter and validate all generative AI tool outputs and function calls before passing to system shells or execution sinks.".into(),
            techniques: vec!["AML.T0043".into(), "AML.T0051".into(), "AML.T0054".into()],
            defense_type: "AI Guardrail".into(),
        },
        MitreMitigation {
            id: "AML.M0015".into(),
            name: "User Prompt Sanitization & Invariant Enforcement".into(),
            description: "Enforce strict syntactic and semantic input guardrails and invariant constraints to neutralize adversarial prompt injections.".into(),
            techniques: vec!["AML.T0043".into(), "AML.T0048".into(), "AML.T0051".into()],
            defense_type: "AI Guardrail".into(),
        },
        MitreMitigation {
            id: "AML.M0016".into(),
            name: "Restrict Tool / Subprocess Execution Privileges".into(),
            description: "Sandbox downstream tool processes spawned by AI agents with restricted kernel access tokens and path isolation.".into(),
            techniques: vec!["AML.T0043".into(), "AML.T0044".into(), "AML.T0040".into(), "AML.T0042".into()],
            defense_type: "Kernel Isolation".into(),
        },
        MitreMitigation {
            id: "AML.M0017".into(),
            name: "Verify Cryptographic Integrity of Model Weights".into(),
            description: "Enforce SHA-256 and digital signature validation on all ONNX, PyTorch, and GGUF model binaries before loading into runtime.".into(),
            techniques: vec!["AML.T0031".into()],
            defense_type: "Cryptographic Verification".into(),
        },
        MitreMitigation {
            id: "AML.M0018".into(),
            name: "Isolate AI Agent Runtime & State".into(),
            description: "Isolate agent memory files (.agents/memory.md), state directories, and runtime memory spaces using OS DACLs and memory protection.".into(),
            techniques: vec!["AML.T0044".into(), "AML.T0048".into(), "AML.T0040".into(), "AML.T0029".into(), "AML.T0054".into()],
            defense_type: "State Isolation".into(),
        },
    ]
}

/// Returns the catalog of MITRE Threat Actor Groups / CTI Profiles.
pub fn get_threat_groups() -> Vec<MitreGroup> {
    if let Some(cat) = get_catalog() {
        if !cat.groups.is_empty() {
            return cat.groups.clone();
        }
    }
    get_static_threat_groups()
}

/// Fallback static compiled threat groups.
pub fn get_static_threat_groups() -> Vec<MitreGroup> {
    vec![
        MitreGroup {
            id: "G0016".into(),
            name: "APT29".into(),
            description: "Russian Foreign Intelligence Service (SVR) state-sponsored cyber espionage group, active since 2008.".into(),
            aliases: vec!["Cozy Bear".into(), "Nobelium".into(), "Midnight Blizzard".into(), "The Dukes".into()],
            techniques: vec!["T1566".into(), "T1059".into(), "T1055".into(), "T1003".into(), "T1082".into(), "T1071".into(), "T1195".into()],
        },
        MitreGroup {
            id: "G0007".into(),
            name: "APT28".into(),
            description: "Russian General Staff Main Intelligence Directorate (GRU) military cyber unit, active since mid-2000s.".into(),
            aliases: vec!["Fancy Bear".into(), "Forest Blizzard".into(), "Pawn Storm".into(), "Sofacy".into()],
            techniques: vec!["T1595".into(), "T1566".into(), "T1059".into(), "T1003".into(), "T1082".into(), "T1110".into(), "T1071".into()],
        },
        MitreGroup {
            id: "G0032".into(),
            name: "Lazarus Group".into(),
            description: "North Korean state-sponsored threat group responsible for high-profile cyber operations and financial theft.".into(),
            aliases: vec!["Hidden Cobra".into(), "Zinc".into(), "Guardians of Peace".into()],
            techniques: vec!["T1587".into(), "T1190".into(), "T1059".into(), "T1055".into(), "T1574".into(), "T1071".into(), "T1105".into()],
        },
        MitreGroup {
            id: "G0046".into(),
            name: "FIN7".into(),
            description: "Financially motivated cybercrime syndicate targeting hospitality, retail, and restaurant sectors.".into(),
            aliases: vec!["Carbanak".into(), "Sangria Tempest".into(), "Elbrus".into()],
            techniques: vec!["T1566".into(), "T1059".into(), "T1047".into(), "T1218".into(), "T1003".into(), "T1558".into()],
        },
        MitreGroup {
            id: "G0034".into(),
            name: "Sandworm Team".into(),
            description: "Destructive cyber warfare unit operated by Russian GRU Unit 74455, responsible for BlackEnergy and NotPetya.".into(),
            aliases: vec!["TeleBots".into(), "Voodoo Bear".into(), "Seashell Blizzard".into(), "BlackEnergy Group".into()],
            techniques: vec!["T1587".into(), "T1053".into(), "T1070".into(), "T1570".into(), "T1490".into(), "T1561".into()],
        },
        MitreGroup {
            id: "G0140".into(),
            name: "LockBit".into(),
            description: "Prolific Ransomware-as-a-Service (RaaS) syndicate conducting double extortion across global enterprises.".into(),
            aliases: vec!["LockBit 3.0".into(), "Bitwise Spider".into()],
            techniques: vec!["T1650".into(), "T1190".into(), "T1053".into(), "T1547".into(), "T1112".into(), "T1562".into(), "T1486".into(), "T1490".into()],
        },
        MitreGroup {
            id: "G1017".into(),
            name: "Volt Typhoon".into(),
            description: "People's Republic of China state-sponsored actor emphasizing Living-off-the-Land (LotL) and stealth persistence in critical infrastructure.".into(),
            aliases: vec!["Bronze Silhouette".into(), "Vanguard Panda".into(), "Insidious Taurus".into()],
            techniques: vec!["T1595".into(), "T1190".into(), "T1133".into(), "T1059".into(), "T1036".into(), "T1070".into(), "T1082".into(), "T1016".into(), "T1021".into()],
        },
        MitreGroup {
            id: "G1003".into(),
            name: "BlackCat".into(),
            description: "Sophisticated Rust-based ransomware cartel known for aggressive extortion and high-speed multi-threaded encryption.".into(),
            aliases: vec!["ALPHV".into(), "Noberus".into()],
            techniques: vec!["T1650".into(), "T1133".into(), "T1055".into(), "T1112".into(), "T1562".into(), "T1082".into(), "T1021".into(), "T1486".into(), "T1490".into()],
        },
        MitreGroup {
            id: "G0010".into(),
            name: "Turla".into(),
            description: "Russia-based sophisticated espionage group infamous for complex rootkits and satellite-based C2 operations.".into(),
            aliases: vec!["Waterbug".into(), "Venomous Bear".into(), "Krypton".into()],
            techniques: vec!["T1587".into(), "T1569".into(), "T1543".into(), "T1055".into(), "T1071".into()],
        },
        MitreGroup {
            id: "G0102".into(),
            name: "Wizard Spider".into(),
            description: "Financially motivated threat group based in Russia that operates TrickBot, Ryuk, Conti, and BazarLoader.".into(),
            aliases: vec!["UNC1878".into(), "Grim Spider".into()],
            techniques: vec!["T1055".into(), "T1134".into(), "T1685".into(), "T1087".into(), "T1486".into()],
        },
        MitreGroup {
            id: "G1015".into(),
            name: "Scattered Spider".into(),
            description: "Financially motivated cybercrime group skilled in identity provider social engineering, SIM swapping, and MFA fatigue.".into(),
            aliases: vec!["UNC3944".into(), "0ktapus".into(), "Octo Tempest".into()],
            techniques: vec!["T1598".into(), "T1586".into(), "T1133".into(), "T1078".into(), "T1003".into()],
        },
        MitreGroup {
            id: "G0058".into(),
            name: "Charming Kitten".into(),
            description: "Iranian state-sponsored cyber espionage operator targeting dissidents, academic researchers, and diplomats.".into(),
            aliases: vec!["Mint Sandstorm".into(), "Phosphorus".into(), "APT35".into()],
            techniques: vec!["T1566".into(), "T1059".into(), "T1190".into(), "T1082".into(), "T1071".into()],
        },
        MitreGroup {
            id: "G0091".into(),
            name: "Silence".into(),
            description: "Financially motivated threat group targeting financial institutions across Eastern Europe and Asia.".into(),
            aliases: vec!["Whisper".into()],
            techniques: vec!["T1566".into(), "T1059".into(), "T1113".into(), "T1071".into()],
        },
        MitreGroup {
            id: "G0049".into(),
            name: "OilRig".into(),
            description: "Iranian threat group conducting espionage against Middle Eastern government agencies and financial entities.".into(),
            aliases: vec!["Helix Kitten".into(), "Crambus".into(), "APT34".into()],
            techniques: vec!["T1566".into(), "T1059".into(), "T1071".into(), "T1053".into(), "T1082".into()],
        },
        MitreGroup {
            id: "G0069".into(),
            name: "MuddyWater".into(),
            description: "Subordinate element of Iranian Ministry of Intelligence and Security (MOIS) targeting telecommunications and oil.".into(),
            aliases: vec!["Mango Sandstorm".into(), "Static Kitten".into()],
            techniques: vec!["T1566".into(), "T1059".into(), "T1071".into(), "T1055".into(), "T1082".into()],
        },
        MitreGroup {
            id: "G0009".into(),
            name: "Deep Panda".into(),
            description: "Chinese state-sponsored espionage group targeting healthcare, defense, and high-technology industries.".into(),
            aliases: vec!["Kung Fu Kittens".into(), "Shell Crew".into(), "Pinkpanther".into()],
            techniques: vec!["T1190".into(), "T1059".into(), "T1003".into(), "T1082".into(), "T1071".into()],
        },
    ]
}

/// Generates a comprehensive summary of the MITRE ATT&CK Matrix posture.
pub fn get_matrix_summary() -> MitreMatrixSummary {
    let tactics = get_all_tactics();
    let techniques = get_all_techniques();

    let total_techniques = techniques.len();
    let covered_techniques = techniques.iter().filter(|t| t.is_covered()).count();
    let coverage_percentage = if total_techniques > 0 {
        (covered_techniques as f32 / total_techniques as f32) * 100.0
    } else {
        0.0
    };

    let mut active_detections_by_tactic: HashMap<String, usize> = HashMap::new();
    let mut active_detections_by_technique: HashMap<String, usize> = HashMap::new();
    for tech in &techniques {
        let count = active_detections_by_tactic.entry(tech.tactic_id.clone()).or_insert(0);
        *count += tech.detection_mechanisms.len();
        if !tech.detection_mechanisms.is_empty() {
            active_detections_by_technique.insert(tech.id.clone(), tech.detection_mechanisms.len());
        }
    }
    let total_mitigations = get_mitigations().len();
    let total_groups = get_threat_groups().len();

    MitreMatrixSummary {
        tactics,
        techniques,
        total_techniques,
        covered_techniques,
        coverage_percentage,
        active_detections_by_tactic,
        active_detections_by_technique,
        total_mitigations,
        total_groups,
    }
}

/// Look up a technique by ID or Name (case-insensitive, e.g. "T1082", "t1082", "attack.t1082", "AML.T0043").
pub fn lookup_technique(id_or_name: &str) -> Option<MitreTechnique> {
    let raw = id_or_name.trim().to_uppercase();
    let clean_id = raw
        .strip_prefix("ATTACK.")
        .or_else(|| raw.strip_prefix("ATLAS."))
        .unwrap_or(&raw);
    let normalized_id = clean_id.replace(['-', '_'], ".");

    get_all_techniques().into_iter().find(|t| {
        t.id.eq_ignore_ascii_case(clean_id)
            || t.id.eq_ignore_ascii_case(&normalized_id)
            || t.name.eq_ignore_ascii_case(id_or_name.trim())
            || t.subtechniques.iter().any(|s| {
                s.id.eq_ignore_ascii_case(clean_id) || s.id.eq_ignore_ascii_case(&normalized_id)
            })
    })
}

/// Look up a tactic by ID or Name (e.g. "TA0002" or "Execution").
pub fn lookup_tactic(id_or_name: &str) -> Option<MitreTactic> {
    let clean = id_or_name.trim().to_uppercase();
    get_all_tactics().into_iter().find(|t| {
        t.id.eq_ignore_ascii_case(&clean) || t.name.eq_ignore_ascii_case(id_or_name.trim())
    })
}

/// Extract MITRE ATT&CK references from rule titles, tag strings, or reason texts.
/// E.g. parses "attack.t1082", "T1059.001", or "attack.discovery".
pub fn extract_mitre_from_text(text: &str) -> Option<(String, String, String)> {
    let text_lower = text.to_lowercase();

    // Look for explicit T-pattern like T1082 or t1059.001 or ATLAS AML.T0043
    let words = text_lower.split(|c: char| {
        c.is_whitespace() || c == ',' || c == ';' || c == ':' || c == '[' || c == ']' || c == '(' || c == ')' || c == '{' || c == '}' || c == '|' || c == '/' || c == '\\' || c == '"' || c == '\''
    });
    for raw_word in words {
        let word = raw_word.trim_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != '-' && c != '_');
        let candidate = word
            .strip_prefix("attack.")
            .or_else(|| word.strip_prefix("atlas."))
            .unwrap_or(word);

        let cand_norm = candidate.replace(['-', '_'], ".");
        if cand_norm.starts_with("aml.t") {
            if let Some(tech) = lookup_technique(&cand_norm) {
                return Some((tech.tactic_name, tech.id, tech.name));
            }
        } else if candidate.starts_with('t') && candidate.len() >= 5 {
            let num_part = &candidate[1..5];
            if num_part.chars().all(|c| c.is_ascii_digit()) {
                if let Some(tech) = lookup_technique(candidate) {
                    // Check if candidate matched a specific subtechnique
                    if let Some(sub) = tech.subtechniques.iter().find(|s| s.id.eq_ignore_ascii_case(candidate)) {
                        return Some((tech.tactic_name, sub.id.clone(), format!("{}: {}", tech.name, sub.name)));
                    }
                    return Some((tech.tactic_name, tech.id, tech.name));
                }
            }
        }
    }

    // Check for tactic-level tags like attack.execution, attack.defense_evasion, etc.
    let tactic_words = text_lower.split(|c: char| !c.is_alphanumeric() && c != '.' && c != '_');
    for word in tactic_words {
        let candidate = word.strip_prefix("attack.").unwrap_or(word);
        let normalized = candidate.replace('_', " ");
        if let Some(tac) = lookup_tactic(&normalized) {
            if let Some(first_tech) = get_all_techniques().into_iter().find(|t| t.tactic_id == tac.id) {
                return Some((tac.name, first_tech.id, first_tech.name));
            }
        }
    }

    // Keyword heuristics if no explicit ID found
    if text_lower.contains("systeminfo") {
        return lookup_technique("T1082").map(|t| (t.tactic_name, t.id, t.name));
    }
    if text_lower.contains("whoami") {
        return lookup_technique("T1033").map(|t| (t.tactic_name, t.id, t.name));
    }
    if text_lower.contains("powershell") || text_lower.contains("pwsh") {
        return lookup_technique("T1059").map(|t| (t.tactic_name, "T1059.001".into(), "Command and Scripting Interpreter: PowerShell".into()));
    }
    if text_lower.contains("shadows") || text_lower.contains("vssadmin") {
        return lookup_technique("T1490").map(|t| (t.tactic_name, t.id, t.name));
    }
    if text_lower.contains("lsass") || text_lower.contains("mimikatz") {
        return lookup_technique("T1003").map(|t| (t.tactic_name, "T1003.001".into(), "OS Credential Dumping: LSASS Memory".into()));
    }
    if text_lower.contains("attrib") {
        return lookup_technique("T1564").map(|t| (t.tactic_name, "T1564.001".into(), "Hide Artifacts: Hidden Files and Directories".into()));
    }

    None
}

/// Intelligently infer MITRE ATT&CK tactic, technique ID, and technique name from event telemetry.
pub fn infer_mitre_from_event(
    event_id: u32,
    image: &str,
    command_line: &str,
) -> Option<(String, String, String)> {
    let img_lower = image.to_lowercase();
    let cmd_lower = command_line.to_lowercase();

    // 1. Process Creation & Execution Commands (Sysmon Event ID 1)
    if event_id == 1 || event_id == 0 {
        // Impact: Inhibit System Recovery (T1490)
        if cmd_lower.contains("vssadmin delete shadows")
            || cmd_lower.contains("wbadmin delete catalog")
            || (cmd_lower.contains("bcdedit") && cmd_lower.contains("recoveryenabled no"))
            || (cmd_lower.contains("bcdedit") && cmd_lower.contains("bootstatuspolicy ignoreallfailures"))
        {
            return Some((
                "Impact".into(),
                "T1490".into(),
                "Inhibit System Recovery".into(),
            ));
        }

        // Impact: Service Stop (T1489)
        if (cmd_lower.contains("net stop") || cmd_lower.contains("sc stop") || cmd_lower.contains("stop-service"))
            && (cmd_lower.contains("windefend") || cmd_lower.contains("mssql") || cmd_lower.contains("backup"))
        {
            return Some((
                "Impact".into(),
                "T1489".into(),
                "Service Stop".into(),
            ));
        }

        // Defense Evasion: Hide Artifacts (T1564.001)
        if (img_lower.ends_with("attrib.exe") || cmd_lower.contains("attrib")) && cmd_lower.contains("+h") {
            return Some((
                "Defense Evasion".into(),
                "T1564.001".into(),
                "Hide Artifacts: Hidden Files and Directories".into(),
            ));
        }

        // Defense Impairment: Impair Defenses (T1562.001)
        if cmd_lower.contains("disableantivirussw")
            || cmd_lower.contains("set-mppreference -disablerealtimemonitoring $true")
            || cmd_lower.contains("netsh advfirewall set allprofiles state off")
        {
            return Some((
                "Defense Impairment".into(),
                "T1562.001".into(),
                "Impair Defenses: Disable or Modify Tools".into(),
            ));
        }

        // Discovery: System Information Discovery (T1082)
        if img_lower.ends_with("systeminfo.exe")
            || cmd_lower.contains("systeminfo")
            || (img_lower.ends_with("hostname.exe") && !img_lower.is_empty())
        {
            return Some((
                "Discovery".into(),
                "T1082".into(),
                "System Information Discovery".into(),
            ));
        }

        // Discovery: Account Discovery (T1087.001)
        if (cmd_lower.contains("net user") || cmd_lower.contains("net localgroup") || cmd_lower.contains("whoami /all"))
            && !cmd_lower.contains("/add")
        {
            return Some((
                "Discovery".into(),
                "T1087.001".into(),
                "Account Discovery: Local Accounts".into(),
            ));
        }

        // Discovery: System Owner/User Discovery (T1033)
        if img_lower.ends_with("whoami.exe")
            || img_lower == "whoami"
            || cmd_lower.contains("whoami")
        {
            return Some((
                "Discovery".into(),
                "T1033".into(),
                "System Owner/User Discovery".into(),
            ));
        }

        // Credential Access: OS Credential Dumping (T1003.001)
        if img_lower.contains("mimikatz")
            || img_lower.contains("procdump")
            || img_lower.contains("nanodump")
            || cmd_lower.contains("mimikatz")
            || cmd_lower.contains("procdump")
            || cmd_lower.contains("comsvcs.dll")
            || cmd_lower.contains("minidump")
            || cmd_lower.contains("nanodump")
        {
            return Some((
                "Credential Access".into(),
                "T1003.001".into(),
                "OS Credential Dumping: LSASS Memory".into(),
            ));
        }

        // Discovery: Network Configuration Discovery (T1016)
        if img_lower.ends_with("ipconfig.exe")
            || cmd_lower.contains("ipconfig /all")
            || cmd_lower.contains("route print")
            || img_lower.ends_with("netstat.exe")
        {
            return Some((
                "Discovery".into(),
                "T1016".into(),
                "System Network Configuration Discovery".into(),
            ));
        }

        // Discovery: Process Discovery (T1057)
        if img_lower.ends_with("tasklist.exe") || cmd_lower.contains("tasklist /v") {
            return Some((
                "Discovery".into(),
                "T1057".into(),
                "Process Discovery".into(),
            ));
        }

        // Persistence: Scheduled Task/Job (T1053.005)
        if (img_lower.ends_with("schtasks.exe") || cmd_lower.contains("schtasks")) && cmd_lower.contains("/create") {
            return Some((
                "Persistence".into(),
                "T1053.005".into(),
                "Scheduled Task/Job: Scheduled Task".into(),
            ));
        }

        // Defense Evasion: System Binary Proxy Execution: Rundll32 (T1218.011)
        if img_lower.ends_with("rundll32.exe") {
            return Some((
                "Defense Evasion".into(),
                "T1218.011".into(),
                "System Binary Proxy Execution: Rundll32".into(),
            ));
        }

        // Defense Evasion: System Binary Proxy Execution: Mshta (T1218.005)
        if img_lower.ends_with("mshta.exe") {
            return Some((
                "Defense Evasion".into(),
                "T1218.005".into(),
                "System Binary Proxy Execution: Mshta".into(),
            ));
        }

        // Defense Evasion: Modify Registry (T1112)
        if (img_lower.ends_with("reg.exe") || cmd_lower.contains("reg add")) && cmd_lower.contains("add") {
            return Some((
                "Defense Evasion".into(),
                "T1112".into(),
                "Modify Registry".into(),
            ));
        }

        // Command and Control: Ingress Tool Transfer (T1105)
        if (img_lower.ends_with("certutil.exe") && cmd_lower.contains("-urlcache"))
            || (img_lower.ends_with("bitsadmin.exe") && cmd_lower.contains("/transfer"))
            || cmd_lower.contains("curl -o")
            || cmd_lower.contains("wget -o")
        {
            return Some((
                "Command and Control".into(),
                "T1105".into(),
                "Ingress Tool Transfer".into(),
            ));
        }

        // Execution: Command and Scripting Interpreter (T1059.001 / T1059.003)
        if img_lower.ends_with("powershell.exe")
            || img_lower.ends_with("pwsh.exe")
            || img_lower == "powershell"
            || img_lower == "pwsh"
            || cmd_lower.contains("powershell")
            || cmd_lower.contains("pwsh")
        {
            return Some((
                "Execution".into(),
                "T1059.001".into(),
                "Command and Scripting Interpreter: PowerShell".into(),
            ));
        }
        if img_lower.ends_with("cmd.exe")
            || img_lower == "cmd"
            || cmd_lower.contains("cmd.exe /c")
            || cmd_lower.contains("cmd /c")
        {
            return Some((
                "Execution".into(),
                "T1059.003".into(),
                "Command and Scripting Interpreter: Windows Command Shell".into(),
            ));
        }
    }

    // 2. Network Connect (Sysmon Event ID 3)
    if event_id == 3 {
        return Some((
            "Command and Control".into(),
            "T1071".into(),
            "Application Layer Protocol".into(),
        ));
    }

    // 3. Image Loaded (Sysmon Event ID 7)
    if event_id == 7 {
        return Some((
            "Persistence".into(),
            "T1574.002".into(),
            "Hijack Execution Flow: DLL Side-Loading".into(),
        ));
    }

    // 4. CreateRemoteThread (Sysmon Event ID 8)
    if event_id == 8 {
        return Some((
            "Privilege Escalation".into(),
            "T1055.001".into(),
            "Process Injection: Dynamic-link Library Injection".into(),
        ));
    }

    // 5. ProcessAccess (Sysmon Event ID 10)
    if event_id == 10 {
        if img_lower.contains("lsass")
            || cmd_lower.contains("lsass")
            || cmd_lower.contains("procdump")
            || cmd_lower.contains("mimikatz")
            || cmd_lower.contains("comsvcs")
        {
            return Some((
                "Credential Access".into(),
                "T1003.001".into(),
                "OS Credential Dumping: LSASS Memory".into(),
            ));
        }
        if cmd_lower.contains("sam") || cmd_lower.contains("security") || cmd_lower.contains("ntds.dit") {
            return Some((
                "Credential Access".into(),
                "T1003.002".into(),
                "OS Credential Dumping: Security Account Manager".into(),
            ));
        }
        // Generic handle opens without credential store targets are not credential dumping
    }

    // 6. FileCreate (Sysmon Event ID 11)
    if event_id == 11 {
        // Autostart execution when dropped into Startup folders
        if cmd_lower.contains("\\startup\\")
            || cmd_lower.contains("start menu\\programs\\startup")
            || cmd_lower.contains("\\windows\\system32\\drivers")
        {
            return Some((
                "Persistence".into(),
                "T1547.001".into(),
                "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder".into(),
            ));
        }
        // Dropping executables or scripts into user AppData/Temp paths for persistence
        if (cmd_lower.ends_with(".exe") || cmd_lower.ends_with(".dll") || cmd_lower.ends_with(".ps1") || cmd_lower.ends_with(".vbs"))
            && (cmd_lower.contains("\\appdata\\") || cmd_lower.contains("\\temp\\") || cmd_lower.contains("\\public\\"))
        {
            return Some((
                "Persistence".into(),
                "T1547".into(),
                "Boot or Logon Autostart Execution".into(),
            ));
        }
    }

    // 7. RegistryEvent (Sysmon Event ID 12, 13, 14)
    if event_id == 12 || event_id == 13 || event_id == 14 {
        if cmd_lower.contains("\\currentversion\\run")
            || cmd_lower.contains("\\runonce")
            || cmd_lower.contains("\\services\\")
            || cmd_lower.contains("startup")
            || cmd_lower.contains("image file execution options")
        {
            return Some((
                "Persistence".into(),
                "T1547.001".into(),
                "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder".into(),
            ));
        }
        if cmd_lower.contains("policies")
            || cmd_lower.contains("windows defender")
            || cmd_lower.contains("firewallpolicy")
            || cmd_lower.contains("uac")
            || cmd_lower.contains("safeboot")
        {
            return Some((
                "Defense Evasion".into(),
                "T1112".into(),
                "Modify Registry".into(),
            ));
        }
    }

    // 8. ProcessTampering (Sysmon Event ID 25)
    if event_id == 25 {
        return Some((
            "Defense Evasion".into(),
            "T1055.012".into(),
            "Process Injection: Process Hollowing".into(),
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_enterprise_tactics() {
        let tactics = get_all_tactics();
        assert_eq!(tactics.len(), 15);
        let ids: Vec<&str> = tactics.iter().map(|t| t.id.as_str()).collect();
        assert!(ids.contains(&"TA0043")); // Recon
        assert!(ids.contains(&"TA0042")); // Resource Dev
        assert!(ids.contains(&"TA0001")); // Initial Access
        assert!(ids.contains(&"TA0002")); // Execution
        assert!(ids.contains(&"TA0003")); // Persistence
        assert!(ids.contains(&"TA0004")); // Priv Esc
        assert!(ids.contains(&"TA0005")); // Defense Evasion
        assert!(ids.contains(&"TA0112")); // Defense Impairment
        assert!(ids.contains(&"TA0006")); // Cred Access
        assert!(ids.contains(&"TA0007")); // Discovery
        assert!(ids.contains(&"TA0008")); // Lateral Movement
        assert!(ids.contains(&"TA0009")); // Collection
        assert!(ids.contains(&"TA0011")); // C2
        assert!(ids.contains(&"TA0010")); // Exfil
        assert!(ids.contains(&"TA0040")); // Impact
    }

    #[test]
    fn test_techniques_catalog_coverage() {
        let techniques = get_all_techniques();
        assert!(techniques.len() >= 30, "Techniques count should be rich");
        for t in &techniques {
            assert!(!t.id.is_empty());
            assert!(!t.name.is_empty());
            assert!(!t.tactic_id.is_empty());
            assert!(!t.tactic_name.is_empty());
        }

        let summary = get_matrix_summary();
        assert!(summary.coverage_percentage > 80.0, "Coverage should be high");
    }

    #[test]
    fn test_technique_and_tactic_lookup() {
        let t1082 = lookup_technique("T1082").expect("T1082 lookup");
        assert_eq!(t1082.name, "System Information Discovery");
        assert_eq!(t1082.tactic_name, "Discovery");

        let t1059 = lookup_technique("attack.t1059").expect("attack.t1059 lookup");
        assert_eq!(t1059.id, "T1059");

        let tactic = lookup_tactic("Execution").expect("Execution lookup");
        assert_eq!(tactic.id, "TA0002");
    }

    #[test]
    fn test_infer_mitre_from_event() {
        // vssadmin delete shadows -> T1490
        let (tac, tech, name) = infer_mitre_from_event(1, "vssadmin.exe", "vssadmin delete shadows /all /quiet")
            .expect("infer T1490");
        assert_eq!(tac, "Impact");
        assert_eq!(tech, "T1490");
        assert_eq!(name, "Inhibit System Recovery");

        // powershell.exe -> T1059.001
        let (tac, tech, _) = infer_mitre_from_event(1, "powershell.exe", "powershell.exe -enc AAAA")
            .expect("infer T1059.001");
        assert_eq!(tac, "Execution");
        assert_eq!(tech, "T1059.001");

        // systeminfo.exe -> T1082
        let (tac, tech, _) = infer_mitre_from_event(1, "systeminfo.exe", "systeminfo")
            .expect("infer T1082");
        assert_eq!(tac, "Discovery");
        assert_eq!(tech, "T1082");

        // whoami.exe -> T1033
        let (tac, tech, name) = infer_mitre_from_event(1, "whoami.exe", "whoami /priv")
            .expect("infer T1033");
        assert_eq!(tac, "Discovery");
        assert_eq!(tech, "T1033");
        assert_eq!(name, "System Owner/User Discovery");

        // mimikatz / lsass credential dumping -> T1003.001
        let (tac, tech, name) = infer_mitre_from_event(1, "mimikatz.exe", "sekurlsa::logonpasswords")
            .expect("infer T1003.001");
        assert_eq!(tac, "Credential Access");
        assert_eq!(tech, "T1003.001");
        assert_eq!(name, "OS Credential Dumping: LSASS Memory");

        // Sysmon Event 8 -> T1055.001
        let (tac, tech, _) = infer_mitre_from_event(8, "injector.exe", "")
            .expect("infer T1055.001");
        assert_eq!(tac, "Privilege Escalation");
        assert_eq!(tech, "T1055.001");
    }

    #[test]
    fn test_extract_mitre_from_text() {
        let res = extract_mitre_from_text("Sigma rule match: attack.t1082 systeminfo discovery detected")
            .expect("extract T1082");
        assert_eq!(res.1, "T1082");
        assert_eq!(res.0, "Discovery");

        let whoami_res = extract_mitre_from_text("Sigma rule match: attack.t1033 whoami priv discovery")
            .expect("extract T1033");
        assert_eq!(whoami_res.1, "T1033");
        assert_eq!(whoami_res.0, "Discovery");

        // Subtechnique precision test
        let sub_res = extract_mitre_from_text("Rule attack.t1059.001 powershell execution")
            .expect("extract T1059.001");
        assert_eq!(sub_res.1, "T1059.001");
        assert_eq!(sub_res.0, "Execution");

        // Tactic tag parsing
        let tac_res = extract_mitre_from_text("Alert tags: attack.privilege_escalation")
            .expect("extract privilege escalation");
        assert_eq!(tac_res.0, "Privilege Escalation");
    }

    #[test]
    fn test_infer_mitre_false_positive_prevention() {
        // Benign notepad creating a text file should NOT be flagged as T1547
        let benign_file = infer_mitre_from_event(11, "C:\\Windows\\notepad.exe", "notepad.exe C:\\Users\\Alice\\notes.txt");
        assert!(benign_file.is_none(), "Benign file creation should not be flagged as persistence");

        // Dropping executable into AppData should be flagged
        let drop_file = infer_mitre_from_event(11, "dropper.exe", "C:\\Users\\Alice\\AppData\\Local\\Temp\\update.exe")
            .expect("drop into Temp");
        assert_eq!(drop_file.1, "T1547");

        // Generic benign process handle should NOT be flagged as credential dumping
        let benign_handle = infer_mitre_from_event(10, "C:\\Windows\\explorer.exe", "notepad.exe");
        assert!(benign_handle.is_none(), "Generic process handle should not be flagged as credential dumping");

        // LSASS process access should be flagged as T1003.001
        let lsass_handle = infer_mitre_from_event(10, "mimikatz.exe", "lsass.exe")
            .expect("lsass access");
        assert_eq!(lsass_handle.1, "T1003.001");
        assert_eq!(lsass_handle.0, "Credential Access");
    }

    #[test]
    fn test_mitigations_and_groups() {
        let mitigations = get_mitigations();
        assert!(mitigations.len() >= 45, "Expected comprehensive mitigations from catalog, got {}", mitigations.len());
        assert!(mitigations.iter().any(|m| m.id == "AML.M0015"));
        assert!(mitigations.iter().any(|m| m.id == "AML.M0018"));

        let groups = get_threat_groups();
        assert!(groups.len() >= 170, "Expected comprehensive threat groups from catalog, got {}", groups.len());
        assert!(groups.iter().any(|g| g.name == "APT29"));
        assert!(groups.iter().any(|g| g.name == "LockBit"));
        assert!(groups.iter().any(|g| g.name == "Volt Typhoon"));
        assert!(groups.iter().any(|g| g.name == "Lazarus Group"));
    }

    #[test]
    fn test_mitre_atlas_catalog_and_extraction() {
        // 1. ATLAS technique lookup (standard and hyphenated/underscore formats)
        let aml43 = lookup_technique("AML.T0043").expect("AML.T0043 technique found");
        assert_eq!(aml43.name, "Adversarial Prompt Injection / Tool-Argument Injection");
        assert_eq!(aml43.voter, "AiSecurityAuditVoter");
        assert_eq!(aml43.consensus_action, "Tarpit");
        assert!(aml43.is_atlas);

        let aml43_hyphen = lookup_technique("AML-T0043").expect("AML-T0043 hyphenated lookup");
        assert_eq!(aml43_hyphen.id, "AML.T0043");

        let aml54 = lookup_technique("AML.T0054").expect("AML.T0054 technique found");
        assert_eq!(aml54.voter, "AgenticVoter");
        assert_eq!(aml54.consensus_action, "Alert");
        assert!(aml54.is_atlas);

        let aml48 = lookup_technique("AML_T0048").expect("AML_T0048 underscore lookup");
        assert_eq!(aml48.id, "AML.T0048");
        assert_eq!(aml48.consensus_action, "Isolate");

        // 2. ATLAS text extraction
        let (tac, tech, name) = extract_mitre_from_text(
            "AI Tool-Argument Injection [MITRE ATLAS AML.T0043 / Cloudflare AI-AND-LLM]: Process python spawned shell injection"
        ).expect("extract AML.T0043 from text");
        assert_eq!(tech, "AML.T0043");
        assert_eq!(tac, "Execution");
        assert!(name.contains("Adversarial Prompt Injection"));

        let (tac2, tech2, _) = extract_mitre_from_text(
            "Canary Trap Breach [Action: Isolate, MITRE ATLAS AML.T0054 / System Prompt Exfiltration]"
        ).expect("extract AML.T0054 from text");
        assert_eq!(tech2, "AML.T0054");
        assert_eq!(tac2, "Exfiltration");

        let (tac3, tech3, _) = extract_mitre_from_text(
            "Agentic Trajectory Breach [DefenseAction: IsolateProcess, MITRE ATLAS AML.T0042 / Denial of ML Service]"
        ).expect("extract AML.T0042 from text");
        assert_eq!(tech3, "AML.T0042");
        assert_eq!(tac3, "Impact");

        // Hyphenated ATLAS token in text extraction
        let (_, tech4, _) = extract_mitre_from_text(
            "Detection match: MITRE ATLAS AML-T0040 AI Runtime Remote Thread Injection"
        ).expect("extract hyphenated AML-T0040");
        assert_eq!(tech4, "AML.T0040");
    }
}
