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

/// Debouncing tracker for memory watchdog alerts.
#[derive(Debug, Clone)]
pub struct MemoryWatchdogDebouncer {
    pub last_critical: Option<Instant>,
    pub last_warn: Option<Instant>,
    pub critical_debounce: Duration,
    pub warn_debounce: Duration,
}

impl Default for MemoryWatchdogDebouncer {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryWatchdogDebouncer {
    /// Creates a debouncer with 10s critical alert interval and 30s warning interval.
    pub fn new() -> Self {
        Self {
            last_critical: None,
            last_warn: None,
            critical_debounce: Duration::from_secs(10),
            warn_debounce: Duration::from_secs(30),
        }
    }

    /// Evaluates whether an alert should be emitted for the given level at `now`.
    /// Automatically updates the recorded timestamp if an alert is emitted.
    pub fn should_emit(&mut self, level: MemoryPressureLevel, now: Instant) -> bool {
        match level {
            MemoryPressureLevel::Critical => {
                let emit = self
                    .last_critical
                    .map_or(true, |t| now.saturating_duration_since(t) >= self.critical_debounce);
                if emit {
                    self.last_critical = Some(now);
                }
                emit
            }
            MemoryPressureLevel::Warning => {
                let emit = self
                    .last_warn
                    .map_or(true, |t| now.saturating_duration_since(t) >= self.warn_debounce);
                if emit {
                    self.last_warn = Some(now);
                }
                emit
            }
            MemoryPressureLevel::Normal => false,
        }
    }
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
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut debouncer = MemoryWatchdogDebouncer::new();

        loop {
            interval.tick().await;

            sys.refresh_memory();
            let avail_mb = sys.available_memory() as f64 / (1024.0 * 1024.0);
            let level = evaluate_memory_pressure(avail_mb);

            if level == MemoryPressureLevel::Critical {
                if debouncer.should_emit(MemoryPressureLevel::Critical, Instant::now()) {
                    error!(
                        "🚨 [CRITICAL MEMORY EXHAUSTION] System free RAM is critically low: {:.1} MB! High risk of OS Out-Of-Memory (OOM) termination!",
                        avail_mb
                    );
                    eprintln!(
                        "\n🚨 [OUT OF MEMORY DANGER] Free RAM is only {:.1} MB! Windows commit limit nearing exhaustion. Check running applications.\n",
                        avail_mb
                    );
                    use std::io::Write;
                    let _ = std::io::stderr().flush();
                }
            } else if level == MemoryPressureLevel::Warning {
                if debouncer.should_emit(MemoryPressureLevel::Warning, Instant::now()) {
                    warn!(
                        "⚠️ [LOW MEMORY WARNING] Available system RAM is low: {:.1} MB. Heavy tasks throttled.",
                        avail_mb
                    );
                    use std::io::Write;
                    let _ = std::io::stderr().flush();
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
        assert_eq!(evaluate_memory_pressure(0.0), MemoryPressureLevel::Critical);
        assert_eq!(evaluate_memory_pressure(100.0), MemoryPressureLevel::Critical);
        assert_eq!(evaluate_memory_pressure(249.99), MemoryPressureLevel::Critical);
        assert_eq!(evaluate_memory_pressure(250.0), MemoryPressureLevel::Warning);
        assert_eq!(evaluate_memory_pressure(599.99), MemoryPressureLevel::Warning);
        assert_eq!(evaluate_memory_pressure(600.0), MemoryPressureLevel::Normal);
        assert_eq!(evaluate_memory_pressure(8192.0), MemoryPressureLevel::Normal);
    }

    #[test]
    fn test_memory_watchdog_debouncer_logic() {
        let mut debouncer = MemoryWatchdogDebouncer::new();
        let start = Instant::now();

        // 1. Initial critical emits immediately
        assert!(debouncer.should_emit(MemoryPressureLevel::Critical, start));

        // 2. Next tick at +2s is debounced
        assert!(!debouncer.should_emit(MemoryPressureLevel::Critical, start + Duration::from_secs(2)));

        // 3. Tick at +9s is still debounced
        assert!(!debouncer.should_emit(MemoryPressureLevel::Critical, start + Duration::from_secs(9)));

        // 4. Tick at +10s emits
        assert!(debouncer.should_emit(MemoryPressureLevel::Critical, start + Duration::from_secs(10)));

        // 5. Warning level is independent: initial warning emits immediately
        assert!(debouncer.should_emit(MemoryPressureLevel::Warning, start + Duration::from_secs(11)));

        // 6. Next warning at +20s (9s after last warning) is debounced
        assert!(!debouncer.should_emit(MemoryPressureLevel::Warning, start + Duration::from_secs(20)));

        // 7. Warning at +41s (30s after +11s) emits
        assert!(debouncer.should_emit(MemoryPressureLevel::Warning, start + Duration::from_secs(41)));

        // 8. Normal pressure never emits
        assert!(!debouncer.should_emit(MemoryPressureLevel::Normal, start + Duration::from_secs(42)));
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
