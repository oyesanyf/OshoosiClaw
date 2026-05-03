//! Adaptive Telemetry Controller.
//!
//! Dynamically scales telemetry fidelity based on system resources and detection activity.

use std::sync::Arc;
use sysinfo::System;
use tokio::sync::{RwLock, Semaphore};
use tracing::{info, warn};

pub struct ResourceGuard {
    pub ai: Arc<Semaphore>,
    pub io: Arc<Semaphore>,
    pub net: Arc<Semaphore>,
}

#[derive(Debug, Clone, Copy)]
pub enum ResourceCategory {
    AI,
    IO,
    Net,
}

impl ResourceGuard {
    pub fn new() -> Self {
        Self {
            ai: Arc::new(Semaphore::new(4)),
            io: Arc::new(Semaphore::new(16)),
            net: Arc::new(Semaphore::new(32)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TelemetryMode {
    Silent, // Minimal events (Process creation only)
    Normal, // Standard EDR profile
    Burst,  // Full fidelity (Network, Registry, FileSystem, DLLs)
}

pub struct TelemetryController {
    current_mode: Arc<RwLock<TelemetryMode>>,
    sys: Arc<RwLock<System>>,
    pub guard: Arc<ResourceGuard>,
}

impl TelemetryController {
    pub fn new() -> Self {
        Self {
            current_mode: Arc::new(RwLock::new(TelemetryMode::Normal)),
            sys: Arc::new(RwLock::new(System::new_all())),
            guard: Arc::new(ResourceGuard::new()),
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
            info!(
                "ADAPTIVE TELEMETRY: CPU load stabilized ({:.1}%). Restoring NORMAL mode.",
                cpu_usage
            );
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
        info!(
            "Adaptive telemetry mode set to {:?} (Sysmon config unchanged — full event IDs remain enabled)",
            mode
        );
        Ok(())
    }

    /// Calculate a recommended concurrency limit for background tasks (e.g. file scanning, hashing).
    pub async fn get_concurrency_limit(&self) -> usize {
        let mut sys = self.sys.write().await;
        sys.refresh_cpu();
        let cpu_usage = sys.global_cpu_info().cpu_usage();
        let mode = *self.current_mode.read().await;

        let base = match mode {
            TelemetryMode::Silent => 2,
            TelemetryMode::Normal => 8,
            TelemetryMode::Burst => 32,
        };

        // Scale down if CPU is high
        if cpu_usage > 75.0 {
            (base / 4).max(1)
        } else if cpu_usage > 50.0 {
            (base / 2).max(2)
        } else {
            base
        }
    }

    /// Spawn a task with adaptive concurrency based on the resource category.
    pub fn spawn_adaptive<F, T>(&self, category: ResourceCategory, task: F)
    where
        F: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let semaphore = match category {
            ResourceCategory::AI => self.guard.ai.clone(),
            ResourceCategory::IO => self.guard.io.clone(),
            ResourceCategory::Net => self.guard.net.clone(),
        };
        crate::hybrid_runtime::spawn_smart(semaphore, task);
    }

    /// Execute a task with adaptive concurrency and return the result.
    pub async fn run_adaptive<F, T>(&self, category: ResourceCategory, task: F) -> anyhow::Result<T>
    where
        F: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let semaphore = match category {
            ResourceCategory::AI => self.guard.ai.clone(),
            ResourceCategory::IO => self.guard.io.clone(),
            ResourceCategory::Net => self.guard.net.clone(),
        };
        crate::hybrid_runtime::run_smart(semaphore, task).await
    }
}

impl Clone for TelemetryController {
    fn clone(&self) -> Self {
        Self {
            current_mode: self.current_mode.clone(),
            sys: self.sys.clone(),
            guard: self.guard.clone(),
        }
    }
}
