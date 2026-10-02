//! Strongly typed forensic artifact models for OpenỌ̀ṣọ́ọ̀sì.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Memory region artifact captured from process Virtual Address Descriptor (VAD) tables.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VadMemoryArtifact {
    #[serde(alias = "Pid", default)]
    pub pid: u32,
    #[serde(alias = "Address", default)]
    pub address: String,
    #[serde(alias = "Size", default)]
    pub size: u64,
    #[serde(alias = "Protection", default)]
    pub protection: String,
    #[serde(alias = "MappingType", default)]
    pub mapping_type: String,
    #[serde(alias = "Filename", default)]
    pub filename: Option<String>,
    #[serde(alias = "IsUnbackedExecutable", default)]
    pub is_unbacked_executable: bool,
}

/// Raw NTFS Master File Table (MFT) record vs Win32 discrepancy artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MftDiscrepancyArtifact {
    #[serde(alias = "EntryNumber", default)]
    pub entry_number: u64,
    #[serde(alias = "FullPath", default)]
    pub full_path: String,
    #[serde(alias = "InUse", default)]
    pub in_use: bool,
    #[serde(alias = "Size", default)]
    pub size: u64,
    #[serde(alias = "Created0x10", alias = "Created", default)]
    pub created: Option<String>,
    #[serde(alias = "Modified0x10", alias = "Modified", default)]
    pub modified: Option<String>,
    #[serde(alias = "IsHiddenFromWin32Api", default)]
    pub is_hidden_from_win32_api: bool,
}

/// Host persistence artifact (Registry Run keys, Services, Tasks).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PersistenceArtifact {
    #[serde(alias = "ArtifactType", default)]
    pub artifact_type: String,
    #[serde(alias = "Name", default)]
    pub name: String,
    #[serde(alias = "Path", default)]
    pub path: String,
    #[serde(alias = "CommandLine", alias = "Command", default)]
    pub command_line: Option<String>,
    #[serde(alias = "IsSigned", default)]
    pub is_signed: Option<bool>,
}

/// Network socket connection artifact from netstat inspection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkSocketArtifact {
    #[serde(alias = "Pid", default)]
    pub pid: u32,
    #[serde(alias = "ProcessName", default)]
    pub process_name: Option<String>,
    #[serde(alias = "LocalAddress", default)]
    pub local_address: String,
    #[serde(alias = "RemoteAddress", default)]
    pub remote_address: String,
    #[serde(alias = "Status", default)]
    pub status: String,
}

/// Consolidated forensic investigation report enriched with telemetry corroboration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ForensicInvestigationReport {
    pub investigation_id: String,
    pub triggered_by_alert: Option<String>,
    pub technique: Option<String>,
    pub target_pid: Option<u32>,
    pub target_path: Option<String>,
    pub vad_findings: Vec<VadMemoryArtifact>,
    pub mft_discrepancies: Vec<MftDiscrepancyArtifact>,
    pub corroborated: bool,
    pub confidence_delta: f32,
    pub summary: String,
    pub timestamp: DateTime<Utc>,
}
