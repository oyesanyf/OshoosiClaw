//! Adaptive Telemetry Controller.
//!
//! Dynamically scales telemetry fidelity based on system resources and detection activity.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use sysinfo::System;
use tokio::sync::{RwLock, Semaphore};
use tracing::{info, warn};
use osoosi_types::{Priority, ResourceCategory, TelemetryControllerInterface, TelemetryMode};

pub struct ResourceGuard {
    pub ai: Arc<Semaphore>,
    pub io: Arc<Semaphore>,
    pub net: Arc<Semaphore>,
    pub(crate) ai_base: usize,
    pub(crate) io_base: usize,
    pub(crate) net_base: usize,
    /// Tracks permits we've "stolen" (positive) or "added" (negative) to throttle concurrency
    pub(crate) ai_throttled: Arc<tokio::sync::Mutex<isize>>,
    pub(crate) io_throttled: Arc<tokio::sync::Mutex<isize>>,
    pub(crate) net_throttled: Arc<tokio::sync::Mutex<isize>>,
    iteration: Arc<std::sync::atomic::AtomicUsize>,
}



impl ResourceGuard {
    pub fn new() -> Self {
        let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        
        // Intelligent initial baselines scaled by core count
        // Scaled initial baselines based on core count
        // DRASTIC OPTIMIZATION: Limit AI concurrency to a tiny fraction of cores.
        // Even 1 Gemma-4 inference can peg a core and 12GB of RAM.
        let ai_limit = (cpus / 4).clamp(1, 4); 
        let io_limit = (cpus * 2).clamp(8, 32); 
        let net_limit = (cpus * 4).clamp(16, 128);

        Self {
            ai: Arc::new(Semaphore::new(ai_limit)),
            io: Arc::new(Semaphore::new(io_limit)),
            net: Arc::new(Semaphore::new(net_limit)),
            ai_base: ai_limit,
            io_base: io_limit,
            net_base: net_limit,
            ai_throttled: Arc::new(tokio::sync::Mutex::new(0)),
            io_throttled: Arc::new(tokio::sync::Mutex::new(0)),
            net_throttled: Arc::new(tokio::sync::Mutex::new(0)),
            iteration: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }
}



#[derive(Clone)]
pub struct TelemetryController {
    pub(crate) current_mode: Arc<std::sync::RwLock<TelemetryMode>>,
    pub(crate) event_rate: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) last_poll_time: Arc<std::sync::RwLock<Instant>>,
    pub(crate) last_cpu_usage: Arc<std::sync::atomic::AtomicU32>,
    pub(crate) last_mem_usage: Arc<std::sync::atomic::AtomicU32>,
    sys: Arc<RwLock<System>>,
    pub guard: Arc<ResourceGuard>,
    pub(crate) task_sender: tokio::sync::mpsc::UnboundedSender<DeferredTask>,
    pub(crate) task_rx: Arc<std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<DeferredTask>>>>,
    pub(crate) socket_exhaustion: Arc<std::sync::atomic::AtomicBool>,
}

pub struct DeferredTask {
    pub category: ResourceCategory,
    pub priority: Priority,
    pub task: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>,
}

impl TelemetryController {
    pub fn new() -> Self {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<DeferredTask>();
        Self {
            current_mode: Arc::new(std::sync::RwLock::new(TelemetryMode::Normal)),
            event_rate: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            last_poll_time: Arc::new(std::sync::RwLock::new(Instant::now())),
            last_cpu_usage: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            last_mem_usage: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            sys: Arc::new(RwLock::new(System::new_all())),
            guard: Arc::new(ResourceGuard::new()),
            task_sender: tx,
            task_rx: Arc::new(std::sync::Mutex::new(Some(rx))),
            socket_exhaustion: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start a background task to monitor resources and adapt telemetry.
    /// Start a background task to monitor resources and adapt telemetry.
    pub fn start_adaptive_loop(self: Arc<Self>) {
        let mut task_rx = self.task_rx.lock().unwrap().take().expect("start_adaptive_loop called twice");
        
        // Task 1: Resource Monitor
        let monitor_self = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                if let Err(e) = monitor_self.run_adaptation_check().await {
                    warn!("Adaptive telemetry check failed: {}", e);
                }
            }
        });

        // Task 2: Deferred Task Worker
        let worker_self = self.clone();
        tokio::spawn(async move {
            let mut local_queue = std::collections::VecDeque::new();
            loop {
                // 1. Collect new tasks
                while let Ok(d) = task_rx.try_recv() {
                    local_queue.push_back(d);
                }

                if local_queue.is_empty() {
                    if let Some(d) = task_rx.recv().await {
                        local_queue.push_back(d);
                    } else {
                        break; // Channel closed
                    }
                }

                // 2. Process tasks based on mode
                let mode = *worker_self.current_mode.read().unwrap();
                if mode == TelemetryMode::Burst {
                    // During burst, we only process High priority tasks if any (though usually only Low are deferred)
                    // and we wait.
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }

                // Process a batch
                let mut processed = 0;
                while processed < 16 && !local_queue.is_empty() {
                    if let Some(d) = local_queue.pop_front() {
                        worker_self.execute_deferred(d);
                        processed += 1;
                    }
                }
                
                // Yield to allow other tasks to run
                tokio::task::yield_now().await;
            }
        });
    }

    fn execute_deferred(&self, deferred: DeferredTask) {
        let semaphore = match deferred.category {
            ResourceCategory::AI => self.guard.ai.clone(),
            ResourceCategory::IO => self.guard.io.clone(),
            ResourceCategory::Net => self.guard.net.clone(),
        };
        crate::hybrid_runtime::spawn_smart(semaphore, deferred.task);
    }

    async fn run_adaptation_check(&self) -> anyhow::Result<()> {
        let (cpu_usage, mem_usage) = {
            let sys_arc = self.sys.clone();
            tokio::task::spawn_blocking(move || {
                let mut sys = sys_arc.blocking_write();
                sys.refresh_cpu();
                sys.refresh_memory();
                (sys.global_cpu_info().cpu_usage(), sys.used_memory() as f64 / sys.total_memory() as f64 * 100.0)
            }).await?
        };

        self.last_cpu_usage.store(cpu_usage.to_bits(), std::sync::atomic::Ordering::Relaxed);
        self.last_mem_usage.store((mem_usage as f32).to_bits(), std::sync::atomic::Ordering::Relaxed);

        let events_per_sec = {
            let now = Instant::now();
            let mut last_poll = self.last_poll_time.write().unwrap();
            let elapsed = now.duration_since(*last_poll).as_secs_f64();
            let current_events = self.event_rate.swap(0, std::sync::atomic::Ordering::SeqCst);
            let eps = if elapsed > 0.1 { current_events as f64 / elapsed } else { 0.0 };
            *last_poll = now;
            eps
        };

        let mut next_mode = None;
        {
            let mut current_mode = self.current_mode.write().unwrap();

            // 1. Mode adjustment (Silent/Normal/Burst)
            let is_burst = events_per_sec > 500.0; // More than 500 events/sec is a burst

            if (cpu_usage > 85.0 || mem_usage > 90.0 || is_burst) && *current_mode != TelemetryMode::Silent {
                if is_burst {
                    warn!("ADAPTIVE PERFORMANCE: Event burst detected ({:.0} eps). Mode: {:?} -> SILENT. System load: CPU={:.1}%, MEM={:.1}%", events_per_sec, *current_mode, cpu_usage, mem_usage);
                } else {
                    warn!("ADAPTIVE PERFORMANCE: Resource pressure high. Mode: {:?} -> SILENT. System load: CPU={:.1}%, MEM={:.1}%, EPS={:.1}", *current_mode, cpu_usage, mem_usage, events_per_sec);
                }
                *current_mode = TelemetryMode::Silent;
                next_mode = Some(TelemetryMode::Silent);
            } else if cpu_usage < 40.0 && mem_usage < 70.0 && !is_burst && *current_mode == TelemetryMode::Silent {
                info!("ADAPTIVE PERFORMANCE: System load stabilized. Mode: SILENT -> NORMAL. CPU={:.1}%, MEM={:.1}%, EPS={:.1}", cpu_usage, mem_usage, events_per_sec);
                *current_mode = TelemetryMode::Normal;
                next_mode = Some(TelemetryMode::Normal);
            } else {
                tracing::debug!("ADAPTIVE PERFORMANCE: Check complete. CPU={:.1}%, MEM={:.1}%, EPS={:.1}, Mode={:?}", cpu_usage, mem_usage, events_per_sec, *current_mode);
            }
        }

        if (self.guard.iteration.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 12) == 0 {
            let ai_cap = self.guard.ai_base as isize - *self.guard.ai_throttled.lock().await;
            let io_cap = self.guard.io_base as isize - *self.guard.io_throttled.lock().await;
            let net_cap = self.guard.net_base as isize - *self.guard.net_throttled.lock().await;
            let mode = *self.current_mode.read().unwrap();
            info!("ADAPTIVE HEALTH: CPU={:.1}%, MEM={:.1}%, EPS={:.1}, Mode={:?}. AI_Limit={}, IO_Limit={}, NET_Limit={}", 
                cpu_usage, mem_usage, events_per_sec, mode, ai_cap, io_cap, net_cap
            );
        }

        if let Some(mode) = next_mode {
            self.apply_telemetry_profile(mode).await?;
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

        tracing::debug!("ADAPTIVE CONCURRENCY: Rebalancing targets [AI={}, IO={}, NET={}] based on CPU={:.1}%, MEM={:.1}%", ai_target, io_target, net_target, cpu, mem);

        self.adjust_semaphore("AI", &self.guard.ai, &self.guard.ai_throttled, self.guard.ai_base, ai_target).await;
        self.adjust_semaphore("IO", &self.guard.io, &self.guard.io_throttled, self.guard.io_base, io_target).await;
        self.adjust_semaphore("NET", &self.guard.net, &self.guard.net_throttled, self.guard.net_base, net_target).await;
    }

    async fn adjust_semaphore(&self, name: &str, sem: &Arc<Semaphore>, throttled: &Arc<tokio::sync::Mutex<isize>>, base_limit: usize, target: usize) {
        let mut currently_throttled = throttled.lock().await;
        let current_effective_limit = base_limit as isize - *currently_throttled;
        
        if (target as isize) < current_effective_limit {
            let to_steal = (current_effective_limit - target as isize) as usize;
            if let Ok(permits) = sem.try_acquire_many(to_steal as u32) {
                permits.forget();
                *currently_throttled += to_steal as isize;
                info!("ADAPTIVE CONCURRENCY: Throttled {} pool. Capacity: {} -> {}. (Stole {})", name, current_effective_limit, target, to_steal);
            } else {
                tracing::debug!("ADAPTIVE CONCURRENCY: Delaying throttle for {} pool. Permits currently in use.", name);
            }
        } else if (target as isize) > current_effective_limit {
            let to_release = (target as isize - current_effective_limit) as usize;
            sem.add_permits(to_release);
            *currently_throttled -= to_release as isize;
            info!("ADAPTIVE CONCURRENCY: Boosted {} pool. Capacity: {} -> {}. (Added {})", name, current_effective_limit, target, to_release);
        }
    }

    pub fn report_event(&self) {
        self.event_rate.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Explicitly trigger BURST mode (high fidelity) during a suspicious event.
    pub async fn trigger_burst_mode(&self, duration_secs: u64) -> anyhow::Result<()> {
        let old_mode = {
            let mut current_mode = self.current_mode.write().unwrap();
            if *current_mode == TelemetryMode::Burst {
                return Ok(());
            }

            warn!("ADAPTIVE TELEMETRY: Suspicious activity detected! Initiating BURST mode (full fidelity) for {}s.", duration_secs);
            let old = *current_mode;
            *current_mode = TelemetryMode::Burst;
            old
        };
        
        self.apply_telemetry_profile(TelemetryMode::Burst).await?;

        let controller = Arc::new(self.clone());
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(duration_secs)).await;
            info!("ADAPTIVE TELEMETRY: Burst period ended. Restoring original mode.");
            {
                let mut mode = controller.current_mode.write().unwrap();
                *mode = old_mode;
            }
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

    /// Spawn a task with adaptive concurrency based on the resource category and priority.
    pub fn spawn_adaptive<F, T>(&self, category: ResourceCategory, priority: Priority, task: F)
    where
        F: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let mode = self.current_mode.read().unwrap().clone();
        
        // Yielding logic: During an alert (Burst mode), Low priority tasks (like background hashing) 
        // are deferred to a priority queue to prevent interference with telemetry ingestion.
        if mode == TelemetryMode::Burst && priority == Priority::Low {
            tracing::debug!("ADAPTIVE CONCURRENCY: Queuing Low priority task during Burst mode.");
            let _ = self.task_sender.send(DeferredTask {
                category,
                priority,
                task: Box::pin(async move {
                    let _ = task.await;
                }),
            });
            return;
        }

        let semaphore = match category {
            ResourceCategory::AI => self.guard.ai.clone(),
            ResourceCategory::IO => self.guard.io.clone(),
            ResourceCategory::Net => self.guard.net.clone(),
        };
        crate::hybrid_runtime::spawn_smart(semaphore, task);
    }

    /// Execute a task with adaptive concurrency and return the result.
    pub async fn run_adaptive<F, T>(&self, category: ResourceCategory, priority: Priority, task: F) -> anyhow::Result<T>
    where
        F: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let mode = self.current_mode.read().unwrap().clone();
        
        if mode == TelemetryMode::Burst && priority == Priority::Low {
             // Yield: wait for mode to stabilize
             tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        let semaphore = match category {
            ResourceCategory::AI => self.guard.ai.clone(),
            ResourceCategory::IO => self.guard.io.clone(),
            ResourceCategory::Net => self.guard.net.clone(),
        };
        crate::hybrid_runtime::run_smart(semaphore, task).await
    }

    pub fn is_socket_exhaustion(&self) -> bool {
        self.socket_exhaustion.load(Ordering::Relaxed)
    }

    pub fn set_socket_exhaustion(&self, value: bool) {
        self.socket_exhaustion.store(value, Ordering::Relaxed);
    }

    pub async fn get_concurrency_limit(&self) -> usize {
        let throttled = self.guard.io_throttled.lock().await;
        (self.guard.io_base as isize - *throttled).max(0) as usize
    }
}

impl TelemetryControllerInterface for TelemetryController {
    fn spawn_adaptive(&self, category: ResourceCategory, priority: Priority, task: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>) {
        self.spawn_adaptive(category, priority, task);
    }

    fn report_event(&self) {
        self.report_event();
    }

    fn is_burst_mode(&self) -> bool {
        *self.current_mode.read().unwrap() == TelemetryMode::Burst
    }
    
    fn is_silent_mode(&self) -> bool {
        *self.current_mode.read().unwrap() == TelemetryMode::Silent
    }

    fn is_socket_exhaustion(&self) -> bool {
        self.is_socket_exhaustion()
    }

    fn set_socket_exhaustion(&self, value: bool) {
        self.set_socket_exhaustion(value);
    }

    fn get_concurrency_limit(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = usize> + Send + '_>> {
        Box::pin(self.get_concurrency_limit())
    }
}
