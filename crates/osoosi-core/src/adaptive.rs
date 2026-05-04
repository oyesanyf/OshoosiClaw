//! Adaptive Telemetry Controller.
//!
//! Dynamically scales telemetry fidelity based on system resources and detection activity.

use std::sync::Arc;
use std::time::Instant;
use sysinfo::System;
use tokio::sync::{RwLock, Semaphore};
use tracing::{info, warn};

pub struct ResourceGuard {
    pub ai: Arc<Semaphore>,
    pub io: Arc<Semaphore>,
    pub net: Arc<Semaphore>,
    /// Tracks permits we've "stolen" to throttle concurrency
    pub(crate) ai_throttled: Arc<tokio::sync::Mutex<usize>>,
    pub(crate) io_throttled: Arc<tokio::sync::Mutex<usize>>,
    pub(crate) net_throttled: Arc<tokio::sync::Mutex<usize>>,
}

#[derive(Debug, Clone, Copy)]
pub enum ResourceCategory {
    AI,
    IO,
    Net,
}

impl ResourceGuard {
    pub fn new() -> Self {
        let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        
        // Intelligent initial baselines scaled by core count
        let ai_limit = (cpus / 2).clamp(2, 8);
        let io_limit = (cpus * 2).clamp(8, 64);
        let net_limit = (cpus * 4).clamp(16, 128);

        Self {
            ai: Arc::new(Semaphore::new(ai_limit)),
            io: Arc::new(Semaphore::new(io_limit)),
            net: Arc::new(Semaphore::new(net_limit)),
            ai_throttled: Arc::new(tokio::sync::Mutex::new(0)),
            io_throttled: Arc::new(tokio::sync::Mutex::new(0)),
            net_throttled: Arc::new(tokio::sync::Mutex::new(0)),
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
    pub(crate) current_mode: Arc<RwLock<TelemetryMode>>,
    pub(crate) event_rate: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) last_poll_time: Arc<RwLock<Instant>>,
    sys: Arc<RwLock<System>>,
    pub guard: Arc<ResourceGuard>,
}

impl TelemetryController {
    pub fn new() -> Self {
        Self {
            current_mode: Arc::new(RwLock::new(TelemetryMode::Normal)),
            event_rate: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            last_poll_time: Arc::new(RwLock::new(Instant::now())),
            sys: Arc::new(RwLock::new(System::new_all())),
            guard: Arc::new(ResourceGuard::new()),
        }
    }

    /// Start a background task to monitor resources and adapt telemetry.
    pub fn start_adaptive_loop(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5)); // Check every 5s for bursts
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
        sys.refresh_memory();

        let cpu_usage = sys.global_cpu_info().cpu_usage();
        let mem_usage = sys.used_memory() as f64 / sys.total_memory() as f64 * 100.0;
        let mut current_mode = self.current_mode.write().await;

        // Calculate event rate (events per second since last check)
        let now = Instant::now();
        let mut last_poll = self.last_poll_time.write().await;
        let elapsed = now.duration_since(*last_poll).as_secs_f64();
        let current_events = self.event_rate.swap(0, std::sync::atomic::Ordering::SeqCst);
        let events_per_sec = if elapsed > 0.1 { current_events as f64 / elapsed } else { 0.0 };
        *last_poll = now;

        // 1. Mode adjustment (Silent/Normal/Burst)
        let is_burst = events_per_sec > 500.0; // More than 500 events/sec is a burst

        if (cpu_usage > 85.0 || mem_usage > 90.0 || is_burst) && *current_mode != TelemetryMode::Silent {
            if is_burst {
                warn!("ADAPTIVE PERFORMANCE: Event burst detected ({:.0} eps). Entering SILENT mode to protect ingestion.", events_per_sec);
            } else {
                warn!("ADAPTIVE PERFORMANCE: System under pressure (CPU: {:.1}%, MEM: {:.1}%). Entering SILENT mode.", cpu_usage, mem_usage);
            }
            *current_mode = TelemetryMode::Silent;
            self.apply_telemetry_profile(TelemetryMode::Silent).await?;
        } else if cpu_usage < 40.0 && mem_usage < 70.0 && !is_burst && *current_mode == TelemetryMode::Silent {
            info!("ADAPTIVE PERFORMANCE: System load stabilized. Restoring NORMAL mode.");
            *current_mode = TelemetryMode::Normal;
            self.apply_telemetry_profile(TelemetryMode::Normal).await?;
        }

        // 2. Intelligent Concurrency Throttling (The "Brain")
        self.rebalance_concurrency(cpu_usage, mem_usage).await;

        Ok(())
    }

    /// Dynamically adjust semaphore permits by acquiring/releasing "throttle" permits.
    async fn rebalance_concurrency(&self, cpu: f32, mem: f64) {
        let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        
        let (ai_target, io_target, net_target) = if cpu > 90.0 || mem > 95.0 {
            (1, 2, 4) // Emergency throttle
        } else if cpu > 70.0 || mem > 85.0 {
            (2.max(cpus / 4), 4.max(cpus), 8.max(cpus * 2)) // Heavy load
        } else if cpu > 40.0 {
            (4.max(cpus / 2), 16.max(cpus * 2), 32.max(cpus * 4)) // Normal
        } else {
            (8.max(cpus), 32.max(cpus * 4), 64.max(cpus * 8)) // Idle / High Perf
        };

        self.adjust_semaphore(&self.guard.ai, &self.guard.ai_throttled, ai_target).await;
        self.adjust_semaphore(&self.guard.io, &self.guard.io_throttled, io_target).await;
        self.adjust_semaphore(&self.guard.net, &self.guard.net_throttled, net_target).await;
    }

    async fn adjust_semaphore(&self, sem: &Arc<Semaphore>, throttled: &Arc<tokio::sync::Mutex<usize>>, target: usize) {
        let mut currently_throttled = throttled.lock().await;
        let total_capacity = sem.available_permits() + *currently_throttled;
        
        if target < total_capacity {
            let to_steal = total_capacity - target;
            // We want to reduce available permits by 'to_steal'
            // We do this by acquiring them and keeping them in 'throttled'
            if let Ok(permits) = sem.try_acquire_many(to_steal as u32) {
                permits.forget();
                *currently_throttled += to_steal;
            }
        } else if target > total_capacity {
            let to_release = target - total_capacity;
            let can_release = to_release.min(*currently_throttled);
            if can_release > 0 {
                sem.add_permits(can_release);
                *currently_throttled -= can_release;
            }
        }
    }

    pub fn report_event(&self) {
        self.event_rate.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
