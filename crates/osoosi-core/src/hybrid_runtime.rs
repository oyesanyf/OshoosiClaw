//! **Hybrid concurrency**: Tokio for I/O (telemetry, mesh, DB) and Rayon for CPU-heavy work
//! (policy consensus path with entropy, parallel sandbox file scans, ML-style batch work).
//!
//! All CPU-tier work should go through [`run_on_rayon`] or [`spawn_rayon`] so it uses the
//! same global Rayon pool configured in [`init_hybrid_concurrency`], never blocking Tokio
//! worker threads for compute-heavy work.
//!
//! # Configuration
//! - **Tokio** worker threads: `OSOOSI_TOKIO_WORKER_THREADS` (default `4`, clamped 2–32).
//! - **Tokio blocking** pool cap: see [`max_blocking_threads`] (coordinates with I/O + `spawn_blocking`).
//! - **Rayon** global pool: `max(1, available_parallelism - 2)`.

use tokio::sync::oneshot;

/// Build the global Rayon thread pool. Idempotent: safe from `main`, [`EdrOrchestrator::new`](crate::EdrOrchestrator::new), and tests.
pub fn init_hybrid_concurrency() {
    if rayon::ThreadPoolBuilder::new()
        .num_threads(configured_rayon_threads())
        .thread_name(|i| format!("osoosi-rayon-{}", i))
        .build_global()
        .is_err()
    {
        // Global pool already installed (e.g. tests, second call).
    }
}

/// Logical Rayon thread count (matches pool when we successfully install it).
fn configured_rayon_threads() -> usize {
    if let Ok(s) = std::env::var("OSOOSI_RAYON_THREADS") {
        if let Ok(n) = s.parse::<usize>() {
            return n.max(1);
        }
    }
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    cpus.saturating_sub(2).max(1)
}

/// Rayon pool size (for logging / health).
pub fn rayon_thread_count() -> usize {
    configured_rayon_threads()
}

/// Tokio worker thread count for the CLI / orchestrator.
pub fn tokio_worker_threads() -> usize {
    std::env::var("OSOOSI_TOKIO_WORKER_THREADS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .map(|n| n.clamp(2, 32))
        .unwrap_or(4)
}

/// Tokio `spawn_blocking` pool size — high enough for SQLite/ORT helpers, bounded so it does not fight Rayon.
pub fn max_blocking_threads() -> usize {
    let w = tokio_worker_threads();
    w.saturating_mul(8).clamp(32, 512)
}

/// **Bridge:** run CPU work on the Rayon pool; await from async code without blocking Tokio I/O workers.
pub async fn run_on_rayon<F, R>(f: F) -> anyhow::Result<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    init_hybrid_concurrency();
    let (tx, rx) = oneshot::channel();
    rayon::spawn(move || {
        let out = f();
        let _ = tx.send(out);
    });
    rx.await
        .map_err(|_| anyhow::anyhow!("Rayon compute task dropped (panic or runtime shutdown)"))
}

/// Fire-and-forget work on the Rayon pool (e.g. parallel file scan after sandbox).
pub fn spawn_rayon(f: impl FnOnce() + Send + 'static) {
    init_hybrid_concurrency();
    rayon::spawn(f);
}
