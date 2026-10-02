//! Mock forensic artifacts and simulated driver for hermetic testing.

use crate::models::{
    ForensicInvestigationReport, MftDiscrepancyArtifact, NetworkSocketArtifact,
    PersistenceArtifact, VadMemoryArtifact,
};
use chrono::Utc;

pub struct MockVelociraptorDriver;

impl MockVelociraptorDriver {
    /// Returns simulated VAD memory records, including normal backed regions and
    /// an unbacked executable region indicating process injection / shellcode hollowing.
    pub fn mock_vad_artifacts(pid: u32) -> Vec<VadMemoryArtifact> {
        vec![
            VadMemoryArtifact {
                pid,
                address: "0x7ff70000".to_string(),
                size: 40960,
                protection: "PAGE_EXECUTE_READ".to_string(),
                mapping_type: "IMAGE".to_string(),
                filename: Some("C:\\Windows\\System32\\svchost.exe".to_string()),
                is_unbacked_executable: false,
            },
            VadMemoryArtifact {
                pid,
                address: "0x7ff80000".to_string(),
                size: 65536,
                protection: "PAGE_READWRITE".to_string(),
                mapping_type: "PRIVATE".to_string(),
                filename: None,
                is_unbacked_executable: false,
            },
            // Malicious / injected unbacked executable segment
            VadMemoryArtifact {
                pid,
                address: "0x02a10000".to_string(),
                size: 8192,
                protection: "PAGE_EXECUTE_READWRITE".to_string(),
                mapping_type: "PRIVATE".to_string(),
                filename: None,
                is_unbacked_executable: true,
            },
        ]
    }

    /// Returns simulated MFT discrepancies, including an active file recorded in raw MFT
    /// that is hidden from Win32 enumeration APIs (rootkit DKOM hiding).
    pub fn mock_mft_artifacts() -> Vec<MftDiscrepancyArtifact> {
        vec![
            MftDiscrepancyArtifact {
                entry_number: 1024,
                full_path: "C:\\Windows\\System32\\drivers\\etc\\hosts".to_string(),
                in_use: true,
                size: 824,
                created: Some("2024-01-01T00:00:00Z".to_string()),
                modified: Some("2024-01-01T00:00:00Z".to_string()),
                is_hidden_from_win32_api: false,
            },
            // Rootkit / hidden driver present in raw MFT but invisible to Win32
            MftDiscrepancyArtifact {
                entry_number: 999999,
                full_path: "C:\\Windows\\System32\\drivers\\syscloak_rootkit.sys".to_string(),
                in_use: true,
                size: 45056,
                created: Some("2026-10-01T12:00:00Z".to_string()),
                modified: Some("2026-10-01T12:00:00Z".to_string()),
                is_hidden_from_win32_api: true,
            },
        ]
    }

    /// Returns simulated network socket connections.
    pub fn mock_network_artifacts(pid: u32) -> Vec<NetworkSocketArtifact> {
        vec![NetworkSocketArtifact {
            pid,
            process_name: Some("svchost.exe".to_string()),
            local_address: "192.168.1.50:49152".to_string(),
            remote_address: "198.51.100.23:443".to_string(),
            status: "ESTABLISHED".to_string(),
        }]
    }

    /// Returns simulated persistence mechanisms.
    pub fn mock_persistence_artifacts() -> Vec<PersistenceArtifact> {
        vec![PersistenceArtifact {
            artifact_type: "RegistryRun".to_string(),
            name: "SecurityHealthSystray".to_string(),
            path: "C:\\Windows\\system32\\SecurityHealthSystray.exe".to_string(),
            command_line: Some("\"C:\\Windows\\system32\\SecurityHealthSystray.exe\"".to_string()),
            is_signed: Some(true),
        }]
    }

    /// Builds a full mock forensic report.
    pub fn mock_investigation_report(pid: Option<u32>, path: Option<String>) -> ForensicInvestigationReport {
        let p = pid.unwrap_or(1234);
        let vad = Self::mock_vad_artifacts(p);
        let mft = Self::mock_mft_artifacts();

        ForensicInvestigationReport {
            investigation_id: uuid::Uuid::new_v4().to_string(),
            triggered_by_alert: Some("ALERT-MOCK-INJECTION".to_string()),
            technique: Some("T1055".to_string()),
            target_pid: Some(p),
            target_path: path,
            vad_findings: vad,
            mft_discrepancies: mft,
            corroborated: true,
            confidence_delta: 0.20,
            summary: "Hermetic mock forensic sweep corroborated unbacked executable memory segment.".to_string(),
            timestamp: Utc::now(),
        }
    }
}
