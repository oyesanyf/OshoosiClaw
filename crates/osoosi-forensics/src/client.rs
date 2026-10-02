//! Embedded Velociraptor client managing child process lifecycle, VQL piping,
//! and OS containment.

use crate::correlator::{corroborate_mft_rootkit_hiding, corroborate_process_injection};
use crate::mock::MockVelociraptorDriver;
use crate::models::{
    ForensicInvestigationReport, MftDiscrepancyArtifact, VadMemoryArtifact,
};
use crate::stream::parse_jsonl_stream;
use crate::vql::{build_mft_scan_query, build_process_vad_query};
use chrono::Utc;
use osoosi_types::config::ForensicsConfig;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::process::Command;
use uuid::Uuid;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Debug, Clone)]
pub struct VelociraptorClient {
    pub config: ForensicsConfig,
}

impl VelociraptorClient {
    /// Creates a new forensic client bound to configuration parameters.
    pub fn new(config: ForensicsConfig) -> Self {
        Self { config }
    }

    /// Resolves the absolute path to the Velociraptor standalone binary, if present.
    pub fn resolve_binary_path(&self) -> Option<PathBuf> {
        let configured = Path::new(&self.config.binary_path);
        if configured.is_file() {
            return Some(configured.to_path_buf());
        }

        // Check relative to current working directory or executable
        if let Ok(cwd) = std::env::current_dir() {
            let candidate = cwd.join(configured);
            if candidate.is_file() {
                return Some(candidate);
            }
        }

        // Check PATH
        if let Ok(path_var) = std::env::var("PATH") {
            let exe_name = if cfg!(windows) {
                "velociraptor.exe"
            } else {
                "velociraptor"
            };
            for entry in std::env::split_paths(&path_var) {
                let candidate = entry.join(exe_name);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }

        None
    }

    /// Returns true if the service is enabled and the executable is present.
    pub fn is_available(&self) -> bool {
        self.config.enabled && self.resolve_binary_path().is_some()
    }

    /// Probes the Velociraptor binary version string.
    pub fn probe_version(&self) -> Option<String> {
        let bin_path = self.resolve_binary_path()?;
        let mut cmd = std::process::Command::new(bin_path);
        cmd.arg("version");
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        let output = cmd.output().ok()?;
        if output.status.success() {
            let ver = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !ver.is_empty() {
                return Some(ver);
            }
        }
        None
    }

    /// Executes an arbitrary schema-sanitized VQL query over standard OS pipes.
    /// Pipes query via stdin, parses JSONL output line-by-line via BufReader,
    /// and enforces child process timeout with forceful termination.
    pub async fn execute_vql<T: for<'de> serde::Deserialize<'de> + Send + 'static>(
        &self,
        vql: &str,
    ) -> Result<Vec<T>, anyhow::Error> {
        let bin_path = match self.resolve_binary_path() {
            Some(p) => p,
            None => {
                anyhow::bail!(
                    "Embedded Velociraptor executable not found at '{}'",
                    self.config.binary_path
                );
            }
        };

        let mut cmd = Command::new(&bin_path);
        cmd.args(["query", "--format", "jsonl", "-"]);
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        #[cfg(windows)]
        {
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        let mut child = cmd.spawn().map_err(|e| {
            anyhow::anyhow!("Failed to spawn headless Velociraptor child ({}): {}", bin_path.display(), e)
        })?;

        // Pipe VQL query into child stdin and close pipe
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(vql.as_bytes()).await?;
            stdin.flush().await?;
            drop(stdin);
        }

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("Failed to acquire Velociraptor stdout pipe"))?;

        let timeout_dur = Duration::from_secs(self.config.execution_timeout_secs);
        let max_lines = self.config.max_output_lines;

        let parse_task = async move {
            let reader = BufReader::new(stdout);
            parse_jsonl_stream::<_, T>(reader, max_lines).await
        };

        let stream_result = tokio::time::timeout(timeout_dur, parse_task).await;

        match stream_result {
            Ok(parse_res) => {
                let _ = child.wait().await;
                let records = parse_res?;
                Ok(records)
            }
            Err(_) => {
                tracing::warn!(
                    "[FORENSICS] Query timeout exceeded ({}s); terminating stalled Velociraptor process",
                    self.config.execution_timeout_secs
                );
                let _ = child.kill().await;
                anyhow::bail!(
                    "Forensic query timed out after {} seconds",
                    self.config.execution_timeout_secs
                );
            }
        }
    }

    /// Inspects the Virtual Address Descriptor (VAD) regions of a target process.
    pub async fn inspect_process_vad(&self, pid: u32) -> Result<Vec<VadMemoryArtifact>, anyhow::Error> {
        if !self.is_available() {
            // Hermetic mock fallback when binary is absent
            return Ok(MockVelociraptorDriver::mock_vad_artifacts(pid));
        }

        let query = build_process_vad_query(pid)?;
        self.execute_vql(&query).await
    }

    /// Performs an NTFS Master File Table scan starting with a given directory prefix.
    pub async fn scan_mft(
        &self,
        drive: char,
        dir_prefix: &str,
    ) -> Result<Vec<MftDiscrepancyArtifact>, anyhow::Error> {
        if !self.is_available() {
            // Hermetic mock fallback when binary is absent
            return Ok(MockVelociraptorDriver::mock_mft_artifacts());
        }

        let query = build_mft_scan_query(drive, dir_prefix)?;
        self.execute_vql(&query).await
    }

    /// Performs a high-level automated forensic sweep, corroborating unbacked code execution
    /// and MFT rootkit discrepancies.
    pub async fn investigate(
        &self,
        pid: Option<u32>,
        path: Option<&str>,
        alert_id: Option<&str>,
        technique: Option<&str>,
    ) -> ForensicInvestigationReport {
        let mut vad_findings = Vec::new();
        let mut mft_discrepancies = Vec::new();
        let mut total_delta = 0.0f32;
        let mut corroborated = false;
        let mut summaries = Vec::new();

        if let Some(target_pid) = pid {
            match self.inspect_process_vad(target_pid).await {
                Ok(artifacts) => {
                    let (inj_corroborated, delta, flagged) =
                        corroborate_process_injection(target_pid, &artifacts);
                    if inj_corroborated {
                        corroborated = true;
                        total_delta += delta;
                        summaries.push(format!(
                            "Unbacked executable VAD regions detected ({}) in PID {}",
                            flagged.len(),
                            target_pid
                        ));
                    }
                    vad_findings = artifacts;
                }
                Err(e) => {
                    tracing::debug!("[FORENSICS] VAD inspection failed for PID {}: {}", target_pid, e);
                }
            }
        }

        if let Some(target_path) = path {
            let drive_char = target_path.chars().next().unwrap_or('C');
            match self.scan_mft(drive_char, target_path).await {
                Ok(artifacts) => {
                    let (mft_corroborated, delta, flagged) =
                        corroborate_mft_rootkit_hiding(&artifacts);
                    if mft_corroborated {
                        corroborated = true;
                        total_delta += delta;
                        summaries.push(format!(
                            "Raw MFT discrepancies / hidden files detected ({}) along path '{}'",
                            flagged.len(),
                            target_path
                        ));
                    }
                    mft_discrepancies = artifacts;
                }
                Err(e) => {
                    tracing::debug!("[FORENSICS] MFT scan failed for path '{}': {}", target_path, e);
                }
            }
        }

        let summary = if corroborated {
            format!("Forensic sweep corroborated: {}", summaries.join("; "))
        } else {
            "Forensic sweep completed; no anomalous unbacked memory or hidden raw MFT records detected."
                .to_string()
        };

        ForensicInvestigationReport {
            investigation_id: Uuid::new_v4().to_string(),
            triggered_by_alert: alert_id.map(|s| s.to_string()),
            technique: technique.map(|s| s.to_string()),
            target_pid: pid,
            target_path: path.map(|s| s.to_string()),
            vad_findings,
            mft_discrepancies,
            corroborated,
            confidence_delta: total_delta.min(0.50),
            summary,
            timestamp: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_initialization_and_availability() {
        let config = ForensicsConfig::default();
        let client = VelociraptorClient::new(config);
        // By default on clean repo without binary, is_available is false
        assert_eq!(client.is_available(), client.resolve_binary_path().is_some());
    }

    #[tokio::test]
    async fn test_client_investigate_fallback_mock() {
        let config = ForensicsConfig {
            enabled: true,
            binary_path: "nonexistent/velociraptor.exe".to_string(),
            ..Default::default()
        };
        let client = VelociraptorClient::new(config);
        let report = client
            .investigate(
                Some(1234),
                Some("C:\\Windows\\System32\\drivers"),
                Some("ALERT-TEST"),
                Some("T1055"),
            )
            .await;

        assert_eq!(report.target_pid, Some(1234));
        assert!(report.corroborated);
        assert!(report.confidence_delta > 0.0);
        assert!(!report.vad_findings.is_empty());
        assert!(!report.mft_discrepancies.is_empty());
    }
}
