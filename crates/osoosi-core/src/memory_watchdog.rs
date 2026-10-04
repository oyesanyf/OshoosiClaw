//! Proactive Out-Of-Memory (OOM) and Low-Memory Watchdog for OpenỌ̀ṣọ́ọ̀sì.
//!
//! Continuously monitors available system RAM to detect low-memory conditions
//! and impending Windows commit limit exhaustion before the OS terminates the process.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tracing::{error, warn};

static WATCHDOG_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Memory pressure state based on available RAM threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryPressureLevel {
    Critical,
    Warning,
    Normal,
}

/// Evaluates available RAM in MB into pressure levels:
/// - < 250 MB: Critical
/// - < 600 MB: Warning
/// - >= 600 MB: Normal
pub fn evaluate_memory_pressure(avail_mb: f64) -> MemoryPressureLevel {
    if avail_mb < 250.0 {
        MemoryPressureLevel::Critical
    } else if avail_mb < 600.0 {
        MemoryPressureLevel::Warning
    } else {
        MemoryPressureLevel::Normal
    }
}

/// Get current available system RAM in megabytes (MB).
pub fn get_available_memory_mb() -> f64 {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();
    sys.available_memory() as f64 / (1024.0 * 1024.0)
}

/// Spawns a proactive memory watchdog background task (if not already running).
///
/// Loops every 2 seconds:
/// - Uses `sysinfo::System::new()` and `refresh_memory()`.
/// - Calculates available RAM in MB: `avail_mb = sys.available_memory() as f64 / (1024.0 * 1024.0)`
/// - If `avail_mb < 250.0`:
///   - Emits critical error & stderr alert (debounced to once every 10s).
/// - Else if `avail_mb < 600.0`:
///   - Emits warning (debounced to once every 30s).
pub fn spawn_memory_watchdog() -> Option<tokio::task::JoinHandle<()>> {
    if WATCHDOG_ACTIVE.swap(true, Ordering::SeqCst) {
        return None;
    }

    let handle = tokio::spawn(async move {
        let mut sys = sysinfo::System::new();
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        let mut last_critical: Option<Instant> = None;
        let mut last_warn: Option<Instant> = None;

        loop {
            interval.tick().await;

            sys.refresh_memory();
            let avail_mb = sys.available_memory() as f64 / (1024.0 * 1024.0);

            if avail_mb < 250.0 {
                let should_log = last_critical.map_or(true, |t| t.elapsed() >= Duration::from_secs(10));
                if should_log {
                    error!(
                        "🚨 [CRITICAL MEMORY EXHAUSTION] System free RAM is critically low: {:.1} MB! High risk of OS Out-Of-Memory (OOM) termination!",
                        avail_mb
                    );
                    eprintln!(
                        "\n🚨 [OUT OF MEMORY DANGER] Free RAM is only {:.1} MB! Windows commit limit nearing exhaustion. Check running applications.\n",
                        avail_mb
                    );
                    last_critical = Some(Instant::now());
                }
            } else if avail_mb < 600.0 {
                let should_log = last_warn.map_or(true, |t| t.elapsed() >= Duration::from_secs(30));
                if should_log {
                    warn!(
                        "⚠️ [LOW MEMORY WARNING] Available system RAM is low: {:.1} MB. Heavy tasks throttled.",
                        avail_mb
                    );
                    last_warn = Some(Instant::now());
                }
            }
        }
    });

    Some(handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluate_memory_pressure_thresholds() {
        assert_eq!(evaluate_memory_pressure(100.0), MemoryPressureLevel::Critical);
        assert_eq!(evaluate_memory_pressure(249.9), MemoryPressureLevel::Critical);
        assert_eq!(evaluate_memory_pressure(250.0), MemoryPressureLevel::Warning);
        assert_eq!(evaluate_memory_pressure(599.9), MemoryPressureLevel::Warning);
        assert_eq!(evaluate_memory_pressure(600.0), MemoryPressureLevel::Normal);
        assert_eq!(evaluate_memory_pressure(8192.0), MemoryPressureLevel::Normal);
    }

    #[test]
    fn test_get_available_memory_mb_returns_sensible_value() {
        let avail = get_available_memory_mb();
        assert!(avail > 0.0, "Available RAM should be positive: {}", avail);
    }

    #[tokio::test]
    async fn test_spawn_memory_watchdog_idempotence() {
        // First spawn may return Some or None depending on other tests
        let _ = spawn_memory_watchdog();
        // Subsequent spawn must return None
        let second = spawn_memory_watchdog();
        assert!(second.is_none(), "Watchdog must be idempotent");
    }
}
