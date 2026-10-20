//! Targeted Startup & On-Demand `RDTSC` Syscall Timing-Shear Diagnostic.
//!
//! Repurposes the timing-shear covariance detector from a continuous background L3 cache eviction
//! radiator (which would degrade shared-cache performance and suffer P/E-core frequency noise)
//! into a strictly bounded, targeted micro-benchmark triggered ONLY:
//! 1. Once during initial agent startup (`TimingShearTrigger::InitialAgentStartup`), or
//! 2. On-demand when a secondary threat indicator fires (`TimingShearTrigger::SecondaryThreatIndicator`).

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Bounded sample count per targeted diagnostic run (< 0.2 ms total execution time).
pub const TIMING_SHEAR_SAMPLE_COUNT: usize = 32;

/// Trigger context for a targeted `RDTSC` syscall timing-shear diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimingShearTrigger {
    /// Executed once during initial agent startup to detect hypervisor/VMM or bootkit inline hooks.
    InitialAgentStartup,
    /// Executed on-demand when a secondary threat indicator fires on a specific process/subsystem.
    SecondaryThreatIndicator {
        indicator: String,
        suspicious_pid: u32,
    },
}

/// Result of a bounded `RDTSC` timing-shear micro-benchmark across critical kernel transitions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimingShearReport {
    pub trigger: TimingShearTrigger,
    pub sample_count: usize,
    pub median_syscall_cycles: u64,
    pub mad_syscall_cycles: u64,
    pub median_vmexit_cycles: u64,
    pub mad_vmexit_cycles: u64,
    pub shear_ratio: f64,
    /// $2 \times 2$ timing-shear covariance matrix $[\Sigma_{11}, \Sigma_{12}, \Sigma_{21}, \Sigma_{22}]$.
    pub covariance_matrix_2x2: [f64; 4],
    pub hypervisor_or_inline_hook_suspected: bool,
    pub continuous_background_radiator_active: bool,
}

/// Reads the hardware timestamp counter (`RDTSC`) without evicting L3 cache lines.
#[inline]
pub fn read_hardware_tsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_mm_lfence();
        let tsc = core::arch::x86_64::_rdtsc();
        core::arch::x86_64::_mm_lfence();
        tsc
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    }
}

/// Executes a lightweight kernel/TEB syscall probe (`GetCurrentProcessId` / `getpid`) and returns `RDTSC` delta cycles.
#[inline]
fn measure_syscall_delta_cycles() -> u64 {
    let t0 = read_hardware_tsc();
    let pid = std::process::id();
    std::hint::black_box(pid);
    let t1 = read_hardware_tsc();
    t1.saturating_sub(t0)
}

/// Executes a serializing instruction boundary (`CPUID` leaf 0 on `x86_64`) to measure VMM/hypervisor intercept shear.
#[inline]
fn measure_serializing_vmexit_delta_cycles() -> u64 {
    let t0 = read_hardware_tsc();
    #[cfg(target_arch = "x86_64")]
    {
        let res = core::arch::x86_64::__cpuid(0);
        std::hint::black_box(res.eax);
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
    let t1 = read_hardware_tsc();
    t1.saturating_sub(t0)
}

fn compute_median_and_mad(samples: &[u64]) -> (u64, u64) {
    if samples.is_empty() {
        return (0, 0);
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let mid = sorted.len() / 2;
    let median = sorted[mid];

    let mut deviations: Vec<u64> = sorted.iter().map(|&x| x.abs_diff(median)).collect();
    deviations.sort_unstable();
    let mad = deviations[deviations.len() / 2];
    (median, mad)
}

/// Targeted Startup & On-Demand `RDTSC` Syscall Timing-Shear Diagnostic Controller.
///
/// Explicitly forbids continuous background L3 cache eviction loops; executes bounded micro-benchmarks
/// only at startup or when triggered by a secondary threat indicator.
pub struct TargetedTimingShearDiagnostic {
    startup_completed: Mutex<bool>,
    last_on_demand_run: Mutex<Option<Instant>>,
    last_report: Mutex<Option<TimingShearReport>>,
    min_on_demand_cooldown: Duration,
}

impl Default for TargetedTimingShearDiagnostic {
    fn default() -> Self {
        Self::new()
    }
}

impl TargetedTimingShearDiagnostic {
    pub fn new() -> Self {
        Self {
            startup_completed: Mutex::new(false),
            last_on_demand_run: Mutex::new(None),
            last_report: Mutex::new(None),
            min_on_demand_cooldown: Duration::from_secs(5),
        }
    }

    pub fn with_cooldown(min_on_demand_cooldown: Duration) -> Self {
        Self {
            startup_completed: Mutex::new(false),
            last_on_demand_run: Mutex::new(None),
            last_report: Mutex::new(None),
            min_on_demand_cooldown,
        }
    }

    /// Architectural invariant: continuous L3 cache eviction radiators are strictly disabled.
    pub const fn has_background_radiator(&self) -> bool {
        false
    }

    /// Runs the initial agent startup integrity check once (returning the cached startup report on subsequent calls).
    pub fn run_startup_check(&self) -> TimingShearReport {
        if let Ok(mut done) = self.startup_completed.lock() {
            if *done {
                if let Ok(guard) = self.last_report.lock() {
                    if let Some(ref rep) = *guard {
                        return rep.clone();
                    }
                }
            }
            *done = true;
        }
        let report = Self::execute_micro_benchmark(TimingShearTrigger::InitialAgentStartup);
        if let Ok(mut guard) = self.last_report.lock() {
            *guard = Some(report.clone());
        }
        report
    }

    /// Runs an on-demand timing-shear micro-benchmark when a secondary threat indicator fires.
    ///
    /// Rate-limited by `min_on_demand_cooldown` so rapid alerts never degrade host CPU performance.
    pub fn run_on_secondary_indicator(
        &self,
        indicator: &str,
        suspicious_pid: u32,
    ) -> Option<TimingShearReport> {
        if indicator.trim().is_empty() {
            return None;
        }
        if let Ok(mut last_guard) = self.last_on_demand_run.lock() {
            if let Some(prev) = *last_guard {
                if prev.elapsed() < self.min_on_demand_cooldown {
                    return self.last_report.lock().ok().and_then(|g| g.clone());
                }
            }
            *last_guard = Some(Instant::now());
        }
        let report = Self::execute_micro_benchmark(TimingShearTrigger::SecondaryThreatIndicator {
            indicator: indicator.trim().to_string(),
            suspicious_pid,
        });
        if let Ok(mut guard) = self.last_report.lock() {
            *guard = Some(report.clone());
        }
        Some(report)
    }

    /// Executes the bounded 32-iteration `RDTSC` timing-shear micro-benchmark.
    pub fn execute_micro_benchmark(trigger: TimingShearTrigger) -> TimingShearReport {
        // Warm up instruction pipeline (2 iterations)
        for _ in 0..2 {
            let _ = measure_syscall_delta_cycles();
            let _ = measure_serializing_vmexit_delta_cycles();
        }

        let mut sys_samples = Vec::with_capacity(TIMING_SHEAR_SAMPLE_COUNT);
        let mut vmm_samples = Vec::with_capacity(TIMING_SHEAR_SAMPLE_COUNT);

        for _ in 0..TIMING_SHEAR_SAMPLE_COUNT {
            sys_samples.push(measure_syscall_delta_cycles());
            vmm_samples.push(measure_serializing_vmexit_delta_cycles());
        }

        let (med_sys, mad_sys) = compute_median_and_mad(&sys_samples);
        let (med_vmm, mad_vmm) = compute_median_and_mad(&vmm_samples);

        let n = TIMING_SHEAR_SAMPLE_COUNT as f64;
        let mean_sys = sys_samples.iter().map(|&x| x as f64).sum::<f64>() / n;
        let mean_vmm = vmm_samples.iter().map(|&x| x as f64).sum::<f64>() / n;

        let mut var_sys = 0.0;
        let mut var_vmm = 0.0;
        let mut cov = 0.0;
        for i in 0..TIMING_SHEAR_SAMPLE_COUNT {
            let ds = (sys_samples[i] as f64) - mean_sys;
            let dv = (vmm_samples[i] as f64) - mean_vmm;
            var_sys += ds * ds;
            var_vmm += dv * dv;
            cov += ds * dv;
        }
        let denom = (n - 1.0).max(1.0);
        var_sys /= denom;
        var_vmm /= denom;
        cov /= denom;

        let denom_sys = (med_sys.max(1)) as f64;
        let shear_ratio = (med_vmm as f64) / denom_sys;

        // Only flag suspected inline hook / hypervisor intercept when both median cycles and shear ratio
        // exceed conservative thresholds (avoiding false positives on hybrid P/E cores).
        let hypervisor_or_inline_hook_suspected =
            med_vmm > 25_000 && shear_ratio > 80.0 && mad_vmm < med_vmm;

        TimingShearReport {
            trigger,
            sample_count: TIMING_SHEAR_SAMPLE_COUNT,
            median_syscall_cycles: med_sys,
            mad_syscall_cycles: mad_sys,
            median_vmexit_cycles: med_vmm,
            mad_vmexit_cycles: mad_vmm,
            shear_ratio,
            covariance_matrix_2x2: [var_sys, cov, cov, var_vmm],
            hypervisor_or_inline_hook_suspected,
            continuous_background_radiator_active: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_targeted_rdtsc_timing_shear_startup_and_on_demand() {
        let diag = TargetedTimingShearDiagnostic::with_cooldown(Duration::from_millis(10));
        assert!(!diag.has_background_radiator());

        // 1. Startup check
        let rep_startup = diag.run_startup_check();
        assert_eq!(rep_startup.trigger, TimingShearTrigger::InitialAgentStartup);
        assert_eq!(rep_startup.sample_count, TIMING_SHEAR_SAMPLE_COUNT);
        assert!(!rep_startup.continuous_background_radiator_active);
        assert!(rep_startup.covariance_matrix_2x2[0] >= 0.0);
        assert!(rep_startup.covariance_matrix_2x2[3] >= 0.0);

        // 2. On-demand check triggered by secondary threat indicator
        std::thread::sleep(Duration::from_millis(15));
        let rep_ondemand = diag
            .run_on_secondary_indicator("Sysmon-EventID-25-Hollowing", 4242)
            .expect("Secondary threat indicator must trigger on-demand RDTSC diagnostic");
        assert_eq!(
            rep_ondemand.trigger,
            TimingShearTrigger::SecondaryThreatIndicator {
                indicator: "Sysmon-EventID-25-Hollowing".to_string(),
                suspicious_pid: 4242,
            }
        );
        assert!(!rep_ondemand.continuous_background_radiator_active);

        // 3. Empty indicator is rejected
        assert!(diag.run_on_secondary_indicator("   ", 4242).is_none());
    }
}
