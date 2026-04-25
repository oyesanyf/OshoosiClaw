//! Sysmon event types for EDR telemetry.
//!
//! Maps Windows Sysmon event IDs to structured types.
//! Used by the Policy Engine for TTP (Tactic, Technique, Procedure) detection.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Sysmon event ID — complete coverage of all Sysmon v15+ event types.
/// Generic variant used for non-Sysmon sources (Linux audit, macOS, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SysmonEventId {
    /// Generic/unknown (Linux audit, macOS, etc.)
    Generic = 0,
    /// Event 1: Process creation (full command line, hashes, parent PID)
    ProcessCreate = 1,
    /// Event 2: File creation time changed (detects timestomping)
    FileCreateTimeChange = 2,
    /// Event 3: Network connection (TCP/UDP, IPs, ports)
    NetworkConnect = 3,
    /// Event 4: Sysmon service state changed (started/stopped — tamper detection)
    SysmonServiceState = 4,
    /// Event 5: Process terminated
    ProcessTerminate = 5,
    /// Event 6: Driver loaded (signed/unsigned — rootkit detection)
    DriverLoad = 6,
    /// Event 7: Image/DLL loaded into a process (DLL sideloading)
    ImageLoad = 7,
    /// Event 8: CreateRemoteThread (code injection detection)
    CreateRemoteThread = 8,
    /// Event 9: RawAccessRead (direct disk access, bypassing filesystem)
    RawAccessRead = 9,
    /// Event 10: ProcessAccess (one process opening another — LSASS dumping)
    ProcessAccess = 10,
    /// Event 11: File created on disk
    FileCreate = 11,
    /// Event 12: Registry key/value created or deleted
    RegistryAddDelete = 12,
    /// Event 13: Registry value set
    RegistryValueSet = 13,
    /// Event 14: Registry key/value renamed
    RegistryRename = 14,
    /// Event 15: FileCreateStreamHash (Alternate Data Streams — hidden code)
    FileCreateStreamHash = 15,
    /// Event 16: Sysmon configuration changed (EDR config integrity)
    SysmonConfigChange = 16,
    /// Event 17: Named pipe created (lateral movement / Cobalt Strike)
    PipeCreated = 17,
    /// Event 18: Named pipe connected
    PipeConnected = 18,
    /// Event 19: WMI Event Filter created (fileless persistence)
    WmiEventFilter = 19,
    /// Event 20: WMI Event Consumer created
    WmiEventConsumer = 20,
    /// Event 21: WMI Consumer bound to filter (persistence complete)
    WmiConsumerBinding = 21,
    /// Event 22: DNS query (domain lookups by process — C2/DGA detection)
    DnsQuery = 22,
    /// Event 23: File delete (archived — ransomware recovery)
    FileDeleteArchived = 23,
    /// Event 24: Clipboard change (info-stealer detection)
    ClipboardChange = 24,
    /// Event 25: Process tampering (hollowing, herpaderping — stealth detection)
    ProcessTampering = 25,
    /// Event 26: File delete (logged but not archived)
    FileDeleteLogged = 26,
    /// Event 27: File block executable (blocked creation of executables)
    FileBlockExecutable = 27,
    /// Event 28: File block shredding (blocked secure deletion tools)
    FileBlockShredding = 28,
    /// Event 29: File executable detected (new executable on system)
    FileExecutableDetected = 29,
    /// Event 255: Sysmon error
    SysmonError = 255,
}

impl TryFrom<u16> for SysmonEventId {
    type Error = String;
    fn try_from(id: u16) -> Result<Self, Self::Error> {
        match id {
            0 => Ok(SysmonEventId::Generic),
            1 => Ok(SysmonEventId::ProcessCreate),
            2 => Ok(SysmonEventId::FileCreateTimeChange),
            3 => Ok(SysmonEventId::NetworkConnect),
            4 => Ok(SysmonEventId::SysmonServiceState),
            5 => Ok(SysmonEventId::ProcessTerminate),
            6 => Ok(SysmonEventId::DriverLoad),
            7 => Ok(SysmonEventId::ImageLoad),
            8 => Ok(SysmonEventId::CreateRemoteThread),
            9 => Ok(SysmonEventId::RawAccessRead),
            10 => Ok(SysmonEventId::ProcessAccess),
            11 => Ok(SysmonEventId::FileCreate),
            12 => Ok(SysmonEventId::RegistryAddDelete),
            13 => Ok(SysmonEventId::RegistryValueSet),
            14 => Ok(SysmonEventId::RegistryRename),
            15 => Ok(SysmonEventId::FileCreateStreamHash),
            16 => Ok(SysmonEventId::SysmonConfigChange),
            17 => Ok(SysmonEventId::PipeCreated),
            18 => Ok(SysmonEventId::PipeConnected),
            19 => Ok(SysmonEventId::WmiEventFilter),
            20 => Ok(SysmonEventId::WmiEventConsumer),
            21 => Ok(SysmonEventId::WmiConsumerBinding),
            22 => Ok(SysmonEventId::DnsQuery),
            23 => Ok(SysmonEventId::FileDeleteArchived),
            24 => Ok(SysmonEventId::ClipboardChange),
            25 => Ok(SysmonEventId::ProcessTampering),
            26 => Ok(SysmonEventId::FileDeleteLogged),
            27 => Ok(SysmonEventId::FileBlockExecutable),
            28 => Ok(SysmonEventId::FileBlockShredding),
            29 => Ok(SysmonEventId::FileExecutableDetected),
            255 => Ok(SysmonEventId::SysmonError),
            _ => Ok(SysmonEventId::Generic), // Unknown IDs map to Generic instead of erroring
        }
    }
}

/// Generic Sysmon event envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SysmonEvent {
    pub event_id: SysmonEventId,
    pub timestamp: DateTime<Utc>,
    pub computer: String,
    pub data: serde_json::Value,
    /// Optional: Resolved product version of the primary image in this event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_version: Option<String>,
}

/// Event 3: Network connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnectData {
    pub process_id: u32,
    pub process_name: String,
    pub image: String,
    pub destination_ip: String,
    pub destination_port: u16,
    pub protocol: String,
}

/// Event 8: CreateRemoteThread (process injection)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRemoteThreadData {
    pub source_process_id: u32,
    pub source_image: String,
    pub target_process_id: u32,
    pub target_image: String,
}

/// Event 11: FileCreate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileCreateData {
    pub process_id: u32,
    pub image: String,
    pub target_filename: String,
}

impl SysmonEvent {
    pub fn process_id(&self) -> Option<u32> {
        self.data.get("ProcessId").and_then(|v| v.as_u64()).map(|v| v as u32)
    }
}
