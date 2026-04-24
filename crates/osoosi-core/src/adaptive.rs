//! Adaptive Telemetry Controller.
//!
//! Dynamically scales telemetry fidelity based on system resources and detection activity.

use sysinfo::System;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TelemetryMode {
    Silent,   // Minimal events (Process creation only)
    Normal,   // Standard EDR profile
    Burst,    // Full fidelity (Network, Registry, FileSystem, DLLs)
}

pub struct TelemetryController {
    current_mode: Arc<RwLock<TelemetryMode>>,
    sys: Arc<RwLock<System>>,
}

impl TelemetryController {
    pub fn new() -> Self {
        Self {
            current_mode: Arc::new(RwLock::new(TelemetryMode::Normal)),
            sys: Arc::new(RwLock::new(System::new_all())),
        }
    }

    /// Start a background task to monitor resources and adapt telemetry.
    pub fn start_adaptive_loop(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60)); // Check every minute
            loop {
                interval.tick().await;
                if let Err(e) = self.run_adaptation_check().await {
                    warn!("Adaptive telemetry check failed: {}", e);
                }
            }
        });
    }

    async fn run_adaptation_check(&self) -> anyhow::Result<()> {
        let mut sys = self.sys.write().await;
        sys.refresh_cpu();
        
        let cpu_usage = sys.global_cpu_info().cpu_usage();
        let mut current_mode = self.current_mode.write().await;

        if cpu_usage > 85.0 && *current_mode != TelemetryMode::Silent {
            info!("ADAPTIVE TELEMETRY: CPU load high ({:.1}%). Switching to SILENT mode to preserve performance.", cpu_usage);
            *current_mode = TelemetryMode::Silent;
            self.apply_telemetry_profile(TelemetryMode::Silent).await?;
        } else if cpu_usage < 40.0 && *current_mode == TelemetryMode::Silent {
            info!("ADAPTIVE TELEMETRY: CPU load stabilized ({:.1}%). Restoring NORMAL mode.", cpu_usage);
            *current_mode = TelemetryMode::Normal;
            self.apply_telemetry_profile(TelemetryMode::Normal).await?;
        }

        Ok(())
    }

    /// Explicitly trigger BURST mode (high fidelity) during a suspicious event.
    pub async fn trigger_burst_mode(&self, duration_secs: u64) -> anyhow::Result<()> {
        let mut current_mode = self.current_mode.write().await;
        if *current_mode == TelemetryMode::Burst {
            return Ok(());
        }

        warn!("ADAPTIVE TELEMETRY: Suspicious activity detected! Initiating BURST mode (full fidelity) for {}s.", duration_secs);
        let old_mode = *current_mode;
        *current_mode = TelemetryMode::Burst;
        self.apply_telemetry_profile(TelemetryMode::Burst).await?;

        let controller = Arc::new(self.clone());
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(duration_secs)).await;
            info!("ADAPTIVE TELEMETRY: Burst period ended. Restoring original mode.");
            let mut mode = controller.current_mode.write().await;
            *mode = old_mode;
            let _ = controller.apply_telemetry_profile(old_mode).await;
        });

        Ok(())
    }

    async fn apply_telemetry_profile(&self, mode: TelemetryMode) -> anyhow::Result<()> {
        #[cfg(target_os = "windows")]
        {
            let config_xml = match mode {
                TelemetryMode::Silent => "<Sysmon schemaversion='4.91'><EventFiltering><ProcessCreate onmatch='include'/></EventFiltering></Sysmon>",
                TelemetryMode::Normal => "<Sysmon schemaversion='4.91'><EventFiltering><ProcessCreate onmatch='exclude'/><NetworkConnect onmatch='exclude'/><FileCreate onmatch='exclude'/></EventFiltering></Sysmon>",
                TelemetryMode::Burst  => "<Sysmon schemaversion='4.91'><EventFiltering><ProcessCreate onmatch='exclude'/><NetworkConnect onmatch='exclude'/><ImageLoad onmatch='exclude'/><FileCreate onmatch='exclude'/><RegistryEvent onmatch='exclude'/><ProcessAccess onmatch='exclude'/><FileDeleteDetected onmatch='exclude'/></EventFiltering></Sysmon>",
            };

            let temp_config = std::env::temp_dir().join("sysmon_adaptive_config.xml");
            std::fs::write(&temp_config, config_xml)?;
            
            // Re-apply sysmon config
            let status = std::process::Command::new("sysmon.exe")
                .args(["-c", &temp_config.to_string_lossy()])
                .status()?;
            
            if !status.success() {
                return Err(anyhow::anyhow!("Failed to apply Sysmon adaptive profile via sysmon -c"));
            }
        }
        
        info!("Applied adaptive profile: {:?}", mode);
        Ok(())
    }
}

impl Clone for TelemetryController {
    fn clone(&self) -> Self {
        Self {
            current_mode: self.current_mode.clone(),
            sys: self.sys.clone(),
        }
    }
}
