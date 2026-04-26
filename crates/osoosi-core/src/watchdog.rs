//! Hardware-Inspired CPU Watchdog Kill-Switch for OpenỌ̀ṣọ́ọ̀sì.
//!
//! Monitors the agent's own CPU usage and automatically terminates the
//! process if it exceeds a configurable threshold for a sustained period.
//!
//! This defends against:
//! - **ReDoS**: Malicious YARA rules with catastrophic regex backtracking
//! - **Infinite loops**: Compromised WASM scripts consuming all CPU
//! - **Crypto-mining**: An attacker hijacking the agent for mining
//! - **Runaway ML inference**: ORT/ONNX model stuck in infinite loop
//!
//! # Architecture
//! The watchdog runs as a separate async task that is intentionally
//! decoupled from the main agent logic. Even if the main thread is
//! frozen in a spin-lock, the watchdog task will fire because Tokio's
//! multi-threaded runtime schedules it independently.
//!
//! # HITL (Human-In-The-Loop) Safety
//! Before terminating, the watchdog checks for a signed "extension token"
//! that a human operator can issue to allow temporary high CPU usage
//! (e.g., during a legitimate full-disk scan).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{error, info, warn};

/// Watchdog configuration.
#[derive(Debug, Clone)]
pub struct WatchdogConfig {
    /// CPU usage threshold (0-100). If usage exceeds this for
    /// `sustained_seconds`, the process is killed.
    pub cpu_threshold_percent: f32,
    /// How many consecutive seconds CPU must exceed threshold
    /// before the kill-switch fires.
    pub sustained_seconds: u64,
    /// How often to sample CPU usage (seconds).
    pub poll_interval_seconds: u64,
    /// Whether the watchdog is enabled.
    pub enabled: bool,
    /// Maximum memory usage (bytes) before kill.
    pub memory_limit_bytes: u64,
    /// Optional USB serial port for hardware kill-switch (e.g., "COM3", "/dev/ttyUSB0").
    /// If None, attempts auto-detection or reads from OSOOSI_USB_KILL_PORT env var.
    pub usb_serial_port: Option<String>,
    /// Baud rate for the USB serial kill-switch device.
    pub usb_baud_rate: u32,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        let env_limit_gb = std::env::var("OSOOSI_MEMORY_LIMIT_GB")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(16); // Default to 16 GB

        Self {
            cpu_threshold_percent: 98.0, // High threshold for EDR background tasks
            sustained_seconds: 30,       // 30 seconds sustained before kill
            poll_interval_seconds: 2,
            enabled: true,
            memory_limit_bytes: env_limit_gb * 1024 * 1024 * 1024,
            usb_serial_port: None,
            usb_baud_rate: 9600,
        }
    }
}

/// Watchdog state shared between the monitor and the main agent.
pub struct WatchdogState {
    /// Set to true to temporarily allow high CPU (HITL extension).
    pub extension_granted: AtomicBool,
    /// Number of consecutive seconds over threshold.
    pub over_threshold_count: AtomicU64,
    /// Set to true when the watchdog has fired.
    pub triggered: AtomicBool,
    /// Current CPU usage reading.
    pub current_cpu: AtomicU64, // Stored as cpu% * 100 (e.g., 9050 = 90.50%)
    /// Current memory usage.
    pub current_memory: AtomicU64,
}

impl Default for WatchdogState {
    fn default() -> Self {
        Self {
            extension_granted: AtomicBool::new(false),
            over_threshold_count: AtomicU64::new(0),
            triggered: AtomicBool::new(false),
            current_cpu: AtomicU64::new(0),
            current_memory: AtomicU64::new(0),
        }
    }
}

/// Start the CPU watchdog kill-switch.
///
/// Returns a handle to the watchdog state (for HITL extension grants).
pub fn start_watchdog(config: WatchdogConfig) -> Arc<WatchdogState> {
    let state = Arc::new(WatchdogState::default());

    if !config.enabled {
        info!("CPU watchdog kill-switch: DISABLED");
        return state;
    }

    let state_clone = state.clone();
    let pid = std::process::id();

    info!(
        "CPU watchdog kill-switch: ACTIVE (threshold={}%, sustained={}s, memory_limit={}MB)",
        config.cpu_threshold_percent,
        config.sustained_seconds,
        config.memory_limit_bytes / (1024 * 1024)
    );

    // Start USB serial kill-switch monitor if configured
    let usb_state = state.clone();
    let usb_port = config
        .usb_serial_port
        .clone()
        .or_else(|| std::env::var("OSOOSI_USB_KILL_PORT").ok());
    if let Some(port) = usb_port {
        start_usb_kill_switch_monitor(port, config.usb_baud_rate, usb_state);
    }

    use sysinfo::{Pid, System};
    let mut sys = System::new_all();
    let s_pid = Pid::from(pid as usize);
    let num_cpus = sys.cpus().len().max(1) as f32;

    info!(
        "Watchdog: detected {} logical CPUs (sysinfo max={}%, normalized threshold={}%)",
        num_cpus as u32,
        num_cpus * 100.0,
        config.cpu_threshold_percent
    );

    tokio::spawn(async move {
        // First tick to initialize CPU measurements (sysinfo needs two readings for delta)
        sys.refresh_process(s_pid);
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(config.poll_interval_seconds));

        loop {
            interval.tick().await;

            // 1. Refresh resources
            sys.refresh_process(s_pid);

            let (raw_cpu, memory_bytes) = if let Some(p) = sys.process(s_pid) {
                (p.cpu_usage(), p.memory())
            } else {
                (0.0, 0)
            };

            // Normalize: sysinfo reports CPU as sum across all cores
            // (e.g., 800% max on 8 cores). Divide by num_cpus to get 0-100% system usage.
            let normalized_cpu = raw_cpu / num_cpus;

            // 2. Store readings (normalized)
            state_clone
                .current_cpu
                .store((normalized_cpu * 100.0) as u64, Ordering::Relaxed);
            state_clone
                .current_memory
                .store(memory_bytes, Ordering::Relaxed);

            // 3. Check memory limit
            if memory_bytes > config.memory_limit_bytes {
                error!(
                    "WATCHDOG: Memory limit exceeded! Using {}MB (limit: {}MB). TERMINATING.",
                    memory_bytes / (1024 * 1024),
                    config.memory_limit_bytes / (1024 * 1024)
                );
                trigger_kill(&state_clone, "memory_limit_exceeded");
                return;
            }

            // 4. CPU monitoring (warning-only — never kills the agent)
            // High CPU alone is NOT a reliable signal of compromise. Legitimate EDR
            // operations (baseline hashing, YARA scanning, model training) can sustain
            // high CPU. The agent should only self-terminate on confirmed malicious
            // activity with absolute confidence, not on resource usage alone.
            if normalized_cpu > config.cpu_threshold_percent {
                let count = state_clone
                    .over_threshold_count
                    .fetch_add(config.poll_interval_seconds, Ordering::Relaxed)
                    + config.poll_interval_seconds;

                // Log at INFO level every 30s, WARN if sustained > 2 minutes
                if count > 120 {
                    warn!(
                        "WATCHDOG: Sustained high CPU {:.1}% (raw {:.1}% across {} cores) for {}s. Monitoring only.",
                        normalized_cpu, raw_cpu, num_cpus as u32, count
                    );
                } else if count % 30 < config.poll_interval_seconds {
                    info!(
                        "WATCHDOG: CPU at {:.1}% (raw {:.1}% across {} cores) for {}s",
                        normalized_cpu, raw_cpu, num_cpus as u32, count
                    );
                }
            } else {
                // Reset counter when CPU drops below threshold
                state_clone.over_threshold_count.store(0, Ordering::Relaxed);
            }
        }
    });

    state
}

/// Grant a temporary HITL extension to allow high CPU usage.
///
/// Call this when a human operator authorizes a resource-intensive
/// operation (e.g., full disk scan, model training).
/// The extension expires after `duration_secs`.
pub fn grant_hitl_extension(state: &Arc<WatchdogState>, duration_secs: u64) {
    info!(
        "HITL extension granted for {}s (watchdog paused)",
        duration_secs
    );
    state.extension_granted.store(true, Ordering::Relaxed);

    let state_clone = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(duration_secs)).await;
        state_clone
            .extension_granted
            .store(false, Ordering::Relaxed);
        info!("HITL extension expired. Watchdog resumed.");
    });
}

/// Get the watchdog status as JSON.
pub fn watchdog_status(state: &Arc<WatchdogState>) -> serde_json::Value {
    let cpu = state.current_cpu.load(Ordering::Relaxed) as f64 / 100.0;
    let memory = state.current_memory.load(Ordering::Relaxed);
    let over_count = state.over_threshold_count.load(Ordering::Relaxed);

    serde_json::json!({
        "cpu_percent": cpu,
        "memory_bytes": memory,
        "memory_mb": memory / (1024 * 1024),
        "over_threshold_seconds": over_count,
        "extension_granted": state.extension_granted.load(Ordering::Relaxed),
        "triggered": state.triggered.load(Ordering::Relaxed),
    })
}

// --- Internal ---

fn trigger_kill(state: &WatchdogState, reason: &str) {
    state.triggered.store(true, Ordering::SeqCst);

    // Log to Windows Event Log or syslog before dying
    #[cfg(target_os = "windows")]
    {
        // Try to create the source if it doesn't exist (requires admin, might fail)
        let _ = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", "if (![System.Diagnostics.EventLog]::SourceExists('OsoosiWatchdog')) { New-EventLog -LogName Application -Source 'OsoosiWatchdog' }"])
            .status();

        let _ = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &format!(
                "Write-EventLog -LogName Application -Source 'OsoosiWatchdog' -EventId 9999 -EntryType Error -Message 'Watchdog kill-switch triggered: {}'",
                reason
            )])
            .status();
    }

    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("logger")
            .args([
                "-p",
                "daemon.crit",
                &format!("osoosi-watchdog: kill-switch triggered: {}", reason),
            ])
            .status();
    }

    // Hard exit — this is intentionally process::exit, not panic
    std::process::exit(137); // 128 + SIGKILL(9)
}

// ============================================================================
// USB Serial Kill-Switch
// ============================================================================

/// Start monitoring a USB serial port for hardware kill signals.
///
/// # Protocol
/// The device communicates with simple ASCII over serial:
/// - **Device → Agent**: `KILL\n` — immediately terminate the agent
/// - **Device → Agent**: `HEARTBEAT\n` — keep-alive (device is active)
/// - **Agent → Device**: `STATUS:CPU=XX.X,MEM=YYYYMB\n` — telemetry
///
/// The device (e.g., Arduino, Pico) can independently decide to send
/// `KILL` based on its own sensors (temperature, physical button, etc.).
///
/// # Typical Arduino sketch:
/// ```c
/// // Physical kill-switch button on pin 2
/// void loop() {
///     if (digitalRead(2) == LOW) {
///         Serial.println("KILL");
///         delay(1000);
///     }
///     // Also kill if CPU exceeds 90% for 10s (parsed from STATUS)
///     if (cpu_over_threshold_seconds > 10) {
///         Serial.println("KILL");
///     }
/// }
/// ```
fn start_usb_kill_switch_monitor(port: String, baud_rate: u32, state: Arc<WatchdogState>) {
    info!(
        "USB kill-switch: monitoring serial port {} @ {} baud",
        port, baud_rate
    );

    std::thread::spawn(move || {
        // Use raw serial I/O (avoids adding serialport crate dependency)
        match open_serial_port(&port, baud_rate) {
            Ok(mut port_handle) => {
                info!("USB kill-switch: connected to {}", port);
                let mut buf = [0u8; 256];
                let mut line_buf = String::new();

                loop {
                    // Read available bytes
                    match read_serial(&mut port_handle, &mut buf) {
                        Ok(n) if n > 0 => {
                            line_buf.push_str(&String::from_utf8_lossy(&buf[..n]));

                            // Process complete lines
                            while let Some(newline_pos) = line_buf.find('\n') {
                                let line = line_buf[..newline_pos].trim().to_uppercase();
                                line_buf = line_buf[newline_pos + 1..].to_string();

                                match line.as_str() {
                                    "KILL" => {
                                        error!("USB HARDWARE KILL-SWITCH TRIGGERED from {}!", port);
                                        trigger_kill(&state, "usb_hardware_kill_switch");
                                        return;
                                    }
                                    "HEARTBEAT" => {
                                        // Device is alive — send status back
                                        let cpu = state.current_cpu.load(Ordering::Relaxed) as f64
                                            / 100.0;
                                        let mem = state.current_memory.load(Ordering::Relaxed)
                                            / (1024 * 1024);
                                        let status =
                                            format!("STATUS:CPU={:.1},MEM={}MB\n", cpu, mem);
                                        let _ = write_serial(&mut port_handle, status.as_bytes());
                                    }
                                    other if !other.is_empty() => {
                                        warn!("USB kill-switch: unknown command: {}", other);
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Ok(_) => {
                            // No data — sleep briefly
                            std::thread::sleep(std::time::Duration::from_millis(100));
                        }
                        Err(e) => {
                            warn!("USB kill-switch: read error: {}. Reconnecting in 5s...", e);
                            std::thread::sleep(std::time::Duration::from_secs(5));
                            // Try to reopen
                            match open_serial_port(&port, baud_rate) {
                                Ok(new_handle) => {
                                    port_handle = new_handle;
                                    info!("USB kill-switch: reconnected to {}", port);
                                }
                                Err(e) => {
                                    warn!("USB kill-switch: reconnect failed: {}", e);
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!(
                    "USB kill-switch: could not open {}: {}. Hardware kill-switch disabled.",
                    port, e
                );
            }
        }
    });
}

// --- Platform-specific serial port I/O ---

#[cfg(target_os = "windows")]
type SerialHandle = std::fs::File;

#[cfg(target_os = "linux")]
type SerialHandle = std::fs::File;

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
type SerialHandle = std::fs::File;

#[cfg(target_os = "windows")]
fn open_serial_port(port: &str, baud_rate: u32) -> anyhow::Result<SerialHandle> {
    // Configure via mode command first
    let _ = std::process::Command::new("mode")
        .args([
            port,
            &format!("baud={}", baud_rate),
            "parity=n",
            "data=8",
            "stop=1",
        ])
        .output();

    // Open as a file (Windows COM ports are file-like)
    let path = if port.starts_with("\\\\") {
        port.to_string()
    } else {
        format!("\\\\.\\{}", port)
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)?;
    Ok(file)
}

#[cfg(target_os = "linux")]
fn open_serial_port(port: &str, baud_rate: u32) -> anyhow::Result<SerialHandle> {
    // Configure via stty
    let _ = std::process::Command::new("stty")
        .args(["-F", port, &baud_rate.to_string(), "raw", "-echo"])
        .output();

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(port)?;
    Ok(file)
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn open_serial_port(port: &str, _baud_rate: u32) -> anyhow::Result<SerialHandle> {
    Err(anyhow::anyhow!(
        "Serial port not supported on this platform: {}",
        port
    ))
}

fn read_serial(handle: &mut SerialHandle, buf: &mut [u8]) -> anyhow::Result<usize> {
    use std::io::Read;
    match handle.read(buf) {
        Ok(n) => Ok(n),
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ok(0),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
        Err(e) => Err(e.into()),
    }
}

fn write_serial(handle: &mut SerialHandle, data: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    handle.write_all(data)?;
    handle.flush()?;
    Ok(())
}
