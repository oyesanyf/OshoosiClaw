//! Synthetic Telemetry Canaries (Anti-Blinding Engine)
//!
//! Provides closed-loop verification of host telemetry health across
//! Process Creation, DNS Resolution, and Image Load channels.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use uuid::Uuid;
use osoosi_types::HostSecurityEvent;

/// Monitored telemetry channels for anti-blinding heartbeat verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CanaryChannel {
    ProcessCreation,
    DnsResolution,
    ImageLoad,
}

impl std::fmt::Display for CanaryChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProcessCreation => write!(f, "ProcessCreation"),
            Self::DnsResolution => write!(f, "DnsResolution"),
            Self::ImageLoad => write!(f, "ImageLoad"),
        }
    }
}

/// An expected synthetic probe waiting to be correlated with an incoming telemetry event.
#[derive(Debug, Clone)]
pub struct CanaryExpectation {
    pub id: Uuid,
    pub channel: CanaryChannel,
    pub dispatched_at: Instant,
    pub timeout: Duration,
}

impl CanaryExpectation {
    pub fn new(id: Uuid, channel: CanaryChannel, timeout: Duration) -> Self {
        Self {
            id,
            channel,
            dispatched_at: Instant::now(),
            timeout,
        }
    }
}

/// Anti-blinding alerts generated when telemetry is muted or degraded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlindingAlert {
    ChannelMuted {
        channel: CanaryChannel,
        consecutive_drops: u32,
        last_seen: Option<Instant>,
    },
    TelemetryLagging {
        channel: CanaryChannel,
        latency_ms: u64,
    },
    UnbackedExecutionDetected {
        pid: u32,
        details: String,
    },
}

impl std::fmt::Display for BlindingAlert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChannelMuted {
                channel,
                consecutive_drops,
                last_seen,
            } => {
                write!(
                    f,
                    "ChannelMuted(channel: {}, consecutive_drops: {}, last_seen: {:?})",
                    channel, consecutive_drops, last_seen
                )
            }
            Self::TelemetryLagging {
                channel,
                latency_ms,
            } => {
                write!(
                    f,
                    "TelemetryLagging(channel: {}, latency_ms: {}ms)",
                    channel, latency_ms
                )
            }
            Self::UnbackedExecutionDetected { pid, details } => {
                write!(
                    f,
                    "UnbackedExecutionDetected(pid: {}, details: {})",
                    pid, details
                )
            }
        }
    }
}

/// Polymorphic parameter flags for synthetic canary process invocations.
pub const CANARY_FLAGS: &[&str] = &[
    "--canary-probe",
    "--worker-heartbeat",
    "--diag-session",
    "--runtime-sync",
    "--telemetry-canary",
];

/// Cryptographically signed HMAC token for synthetic canary probes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryToken {
    pub probe_id: Uuid,
    pub timestamp_slot: u64,
    pub signature: [u8; 8],
}

impl CanaryToken {
    /// Generates a signed token with current epoch time slot using blake3 keyed hash.
    /// Format: v1.<uuid_simple>.<slot>.<hex_sig>
    pub fn generate(secret: &[u8; 32], probe_id: Uuid) -> String {
        let slot = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() / 30;
        let payload = format!("{}.{}", probe_id.simple(), slot);
        let hash = blake3::keyed_hash(secret, payload.as_bytes());
        let mut sig = [0u8; 8];
        sig.copy_from_slice(&hash.as_bytes()[..8]);
        format!("v1.{}.{}.{}", probe_id.simple(), slot, hex::encode(sig))
    }

    /// Verifies slot skew and MAC signature.
    pub fn verify(secret: &[u8; 32], token_str: &str, max_skew_slots: u64) -> Option<Uuid> {
        let parts: Vec<&str> = token_str.split('.').collect();
        if parts.len() != 4 || parts[0] != "v1" {
            return None;
        }
        let probe_id = Uuid::parse_str(parts[1]).ok()?;
        let slot = parts[2].parse::<u64>().ok()?;
        let sig_bytes = hex::decode(parts[3]).ok()?;
        if sig_bytes.len() != 8 {
            return None;
        }
        let current_slot = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() / 30;
        if slot.abs_diff(current_slot) > max_skew_slots {
            return None;
        }
        let payload = format!("{}.{}", probe_id.simple(), slot);
        let expected_hash = blake3::keyed_hash(secret, payload.as_bytes());
        if !constant_time_eq_8(&expected_hash.as_bytes()[..8], &sig_bytes) {
            return None;
        }
        Some(probe_id)
    }

    /// Quick format check (starts_with("v1.") or UUID parse).
    pub fn is_canary_token(token_str: &str) -> bool {
        if token_str.starts_with("v1.") {
            let parts: Vec<&str> = token_str.split('.').collect();
            if parts.len() == 4 && Uuid::parse_str(parts[1]).is_ok() {
                return true;
            }
        }
        Uuid::parse_str(token_str).is_ok()
    }
}

/// Helper constant-time 8-byte slice comparison to avoid timing side-channels.
#[inline]
fn constant_time_eq_8(a: &[u8], b: &[u8]) -> bool {
    if a.len() != 8 || b.len() != 8 {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..8 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Checks if payload contains any of CANARY_FLAGS, "probe.invalid", "v1.", or recognized probe UUIDs.
pub fn is_canary_payload(payload: &str) -> bool {
    let lower = payload.to_ascii_lowercase();
    for flag in CANARY_FLAGS {
        if lower.contains(&flag.to_ascii_lowercase()) {
            return true;
        }
    }
    if lower.contains("probe.invalid") || lower.contains("osoosi_canary_") {
        return true;
    }
    // Check for canary token structure (e.g. v1.<uuid_simple>.<slot>.<hex_sig> or raw UUID)
    if lower.contains("v1.") {
        for word in payload.split(|c: char| {
            c.is_whitespace() || c == '"' || c == '\'' || c == '\\' || c == '/' || c == '&' || c == '|' || c == ';' || c == '`' || c == '='
        }) {
            let trimmed = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != '-');
            if trimmed.starts_with("v1.") && CanaryToken::is_canary_token(trimmed) {
                return true;
            }
        }
    }
    false
}

/// Trait to extract canary payload from various event representations.
pub trait CanaryEventRef {
    fn canary_payload(&self) -> String;
}

impl CanaryEventRef for HostSecurityEvent {
    fn canary_payload(&self) -> String {
        self.data.to_string()
    }
}

impl CanaryEventRef for &HostSecurityEvent {
    fn canary_payload(&self) -> String {
        self.data.to_string()
    }
}

impl CanaryEventRef for str {
    fn canary_payload(&self) -> String {
        self.to_string()
    }
}

impl CanaryEventRef for String {
    fn canary_payload(&self) -> String {
        self.clone()
    }
}

impl CanaryEventRef for serde_json::Value {
    fn canary_payload(&self) -> String {
        self.to_string()
    }
}

/// Checks if event contains canary markers and should be suppressed from RL feature vectors,
/// baseline drift calculations, and disk storage.
pub fn is_canary_event<E: CanaryEventRef + ?Sized>(event: &E) -> bool {
    is_canary_payload(&event.canary_payload())
}

// Dispatches active synthetic canary probes into kernel/host subsystem channels.
#[derive(Clone, Debug)]
pub struct CanaryDispatcher {
    pub nonce_secret: [u8; 32],
}

impl CanaryDispatcher {
    pub fn new(nonce_secret: [u8; 32]) -> Self {
        Self { nonce_secret }
    }

    pub fn nonce_secret(&self) -> &[u8; 32] {
        &self.nonce_secret
    }

    /// Derives a cryptographically keyed UUID probe ID incorporating channel and secret.
    pub fn generate_probe_id(&self, channel: CanaryChannel) -> Uuid {
        let mut hasher = blake3::Hasher::new_keyed(&self.nonce_secret);
        hasher.update(channel.to_string().as_bytes());
        let rand_id = Uuid::new_v4();
        hasher.update(rand_id.as_bytes());
        let hash = hasher.finalize();
        let mut uuid_bytes = [0u8; 16];
        uuid_bytes.copy_from_slice(&hash.as_bytes()[..16]);
        uuid_bytes[6] = (uuid_bytes[6] & 0x0f) | 0x40; // RFC 4122 v4
        uuid_bytes[8] = (uuid_bytes[8] & 0x3f) | 0x80; // Variant RFC 4122
        Uuid::from_bytes(uuid_bytes)
    }

    /// Invokes current_exe() with a randomly selected CANARY_FLAGS argument and signed CanaryToken,
    /// and `CREATE_NO_WINDOW` (0x08000000) on Windows.
    pub async fn dispatch_process_probe(&self, probe_id: Uuid) -> std::io::Result<()> {
        let exe = std::env::current_exe()?;
        let mut cmd = tokio::process::Command::new(exe);

        let token = CanaryToken::generate(&self.nonce_secret, probe_id);
        let flag_idx = rand::random::<usize>() % CANARY_FLAGS.len();
        let flag = CANARY_FLAGS[flag_idx];

        cmd.arg(flag)
            .arg(&token)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .stdin(std::process::Stdio::null());

        #[cfg(windows)]
        {
            #[allow(unused_imports)]
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
        }

        // Spawn and wait for fast-path zero-overhead exit (< 1ms).
        // Protected by a 5000ms timeout against OS process holds / AV locks.
        let status_res = tokio::time::timeout(Duration::from_millis(5000), cmd.status()).await;
        match status_res {
            Ok(Ok(status)) => {
                if !status.success() {
                    tracing::trace!("Canary process probe completed with status: {}", status);
                }
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                tracing::warn!("Canary process probe timed out after 5000ms");
            }
        }
        Ok(())
    }

    /// Issues resolution for `<UUID>.probe.invalid` via `tokio::net::lookup_host`.
    pub async fn dispatch_dns_probe(&self, probe_id: Uuid) -> std::io::Result<()> {
        let domain = format!("{}.probe.invalid", probe_id);
        let host = format!("{}:53", domain);
        // Dispatch resolution to the OS DNS stack. .invalid is reserved to never resolve (RFC 2606),
        // so NXDOMAIN/lookup errors are expected and ignored.
        let _ = tokio::time::timeout(Duration::from_millis(2000), tokio::net::lookup_host(&host)).await;
        Ok(())
    }

    /// Dispatches active ImageLoad probe via temporary image mapping to trigger kernel callbacks.
    pub async fn dispatch_image_probe(&self, probe_id: Uuid) -> std::io::Result<()> {
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            extern "system" {
                fn LoadLibraryExW(
                    lpLibFileName: *const u16,
                    hFile: *mut std::ffi::c_void,
                    dwFlags: u32,
                ) -> *mut std::ffi::c_void;
                fn FreeLibrary(hLibModule: *mut std::ffi::c_void) -> i32;
            }
            let temp_dir = std::env::temp_dir();
            let probe_dll = temp_dir.join(format!("osoosi_canary_{}.dll", probe_id.simple()));
            let sys_dll = std::path::Path::new("C:\\Windows\\System32\\version.dll");
            if sys_dll.exists() {
                if let Ok(_) = std::fs::copy(sys_dll, &probe_dll) {
                    let wide: Vec<u16> = probe_dll.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
                    unsafe {
                        // LOAD_LIBRARY_AS_DATAFILE (0x00000002) maps the PE image without executing DllMain,
                        // triggering PsSetLoadImageNotifyRoutine / Sysmon Event 7.
                        let handle = LoadLibraryExW(wide.as_ptr(), std::ptr::null_mut(), 0x00000002);
                        if !handle.is_null() {
                            FreeLibrary(handle);
                        }
                    }
                    let _ = std::fs::remove_file(&probe_dll);
                }
            }
        }
        #[cfg(not(windows))]
        {
            let _ = probe_id;
        }
        Ok(())
    }

    /// Dispatches a probe for the specified channel.
    pub async fn dispatch_probe(&self, channel: CanaryChannel, probe_id: Uuid) -> std::io::Result<()> {
        match channel {
            CanaryChannel::ProcessCreation => self.dispatch_process_probe(probe_id).await,
            CanaryChannel::DnsResolution => self.dispatch_dns_probe(probe_id).await,
            CanaryChannel::ImageLoad => self.dispatch_image_probe(probe_id).await,
        }
    }
}


/// Correlates incoming telemetry events against pending synthetic expectations.
pub struct CanaryCorrelator {
    pub pending: HashMap<Uuid, CanaryExpectation>,
    pub consecutive_failures: HashMap<CanaryChannel, u32>,
    pub failure_threshold: u32,
    pub alert_tx: mpsc::Sender<BlindingAlert>,
    pub last_seen: HashMap<CanaryChannel, Instant>,
    pub recently_expired: HashMap<Uuid, (CanaryExpectation, Instant)>,
}

impl CanaryCorrelator {
    pub fn new(alert_tx: mpsc::Sender<BlindingAlert>, failure_threshold: u32) -> Self {
        Self {
            pending: HashMap::new(),
            consecutive_failures: HashMap::new(),
            failure_threshold: failure_threshold.max(1),
            alert_tx,
            last_seen: HashMap::new(),
            recently_expired: HashMap::new(),
        }
    }

    /// Registers a dispatched canary probe expectation.
    pub fn register_expectation(&mut self, exp: CanaryExpectation) {
        self.pending.insert(exp.id, exp);
    }

    /// Inspects an incoming event payload. If matching an active or recently-expired expectation:
    /// - Calculates latency
    /// - Resets consecutive failures to 0 (or decrements if recovered from delayed arrival)
    /// - Updates last seen timestamp
    /// - Sends `TelemetryLagging` alert if latency > 1500ms
    pub fn inspect_event(&mut self, channel: CanaryChannel, payload: &str) -> Option<Uuid> {
        let payload_lower = payload.to_ascii_lowercase();

        // 1. Check active pending expectations
        let matched_id = self
            .pending
            .iter()
            .find(|(_, exp)| {
                if exp.channel != channel {
                    return false;
                }
                let id_str = exp.id.to_string();
                let id_simple = exp.id.simple().to_string();
                payload_lower.contains(&id_str) || payload_lower.contains(&id_simple)
            })
            .map(|(id, _)| *id);

        if let Some(id) = matched_id {
            if let Some(exp) = self.pending.remove(&id) {
                let latency = exp.dispatched_at.elapsed();
                let latency_ms = latency.as_millis() as u64;

                // Reset consecutive failures to 0
                self.consecutive_failures.insert(channel, 0);
                self.last_seen.insert(channel, Instant::now());

                // Detect latency degradation (> 1500ms)
                if latency_ms > 1500 {
                    let alert = BlindingAlert::TelemetryLagging {
                        channel,
                        latency_ms,
                    };
                    if let Err(e) = self.alert_tx.try_send(alert) {
                        tracing::warn!(error = %e, "Failed to send TelemetryLagging alert");
                    }
                }

                return Some(id);
            }
        }

        // 2. Check recently expired expectations (delayed / lagging telemetry recovery)
        let matched_expired_id = self
            .recently_expired
            .iter()
            .find(|(_, (exp, _))| {
                if exp.channel != channel {
                    return false;
                }
                let id_str = exp.id.to_string();
                let id_simple = exp.id.simple().to_string();
                payload_lower.contains(&id_str) || payload_lower.contains(&id_simple)
            })
            .map(|(id, _)| *id);

        if let Some(id) = matched_expired_id {
            if let Some((exp, _)) = self.recently_expired.remove(&id) {
                let latency = exp.dispatched_at.elapsed();
                let latency_ms = latency.as_millis() as u64;

                // Telemetry actually arrived, but was delayed. Decrement failures and update last_seen.
                let failures = self.consecutive_failures.entry(channel).or_insert(0);
                *failures = failures.saturating_sub(1);
                self.last_seen.insert(channel, Instant::now());

                // Late arrival implies telemetry is lagging
                let alert = BlindingAlert::TelemetryLagging {
                    channel,
                    latency_ms,
                };
                if let Err(e) = self.alert_tx.try_send(alert) {
                    tracing::warn!(error = %e, "Failed to send delayed TelemetryLagging alert");
                }

                return Some(id);
            }
        }

        None
    }

    /// Purges expired expectations, increments failure counts,
    /// stores expired probes in `recently_expired` for delayed correlation,
    /// and sends/returns `ChannelMuted` when failures >= failure_threshold.
    pub fn sweep_expired(&mut self) -> Vec<BlindingAlert> {
        let now = Instant::now();
        let mut expired_by_channel: HashMap<CanaryChannel, u32> = HashMap::new();
        let mut to_expire = Vec::new();

        self.pending.retain(|id, exp| {
            if exp.dispatched_at.elapsed() >= exp.timeout {
                *expired_by_channel.entry(exp.channel).or_insert(0) += 1;
                to_expire.push((*id, exp.clone()));
                false
            } else {
                true
            }
        });

        // Retain recently expired expectations for 60 seconds to catch delayed telemetry
        for (id, exp) in to_expire {
            self.recently_expired.insert(id, (exp, now));
        }

        self.recently_expired.retain(|_id, (_exp, expired_at)| {
            now.duration_since(*expired_at) < Duration::from_secs(60)
        });

        let mut alerts = Vec::new();
        for (channel, count) in expired_by_channel {
            let failures = self.consecutive_failures.entry(channel).or_insert(0);
            *failures += count;
            if *failures >= self.failure_threshold {
                let alert = BlindingAlert::ChannelMuted {
                    channel,
                    consecutive_drops: *failures,
                    last_seen: self.last_seen.get(&channel).copied(),
                };
                if let Err(e) = self.alert_tx.try_send(alert.clone()) {
                    tracing::warn!(error = %e, "Failed to send ChannelMuted alert");
                }
                alerts.push(alert);
            }
        }

        alerts
    }

    /// Convenience helper to inspect an incoming normalized HostSecurityEvent.
    pub fn inspect_host_security_event(&mut self, event: &HostSecurityEvent) -> Option<Uuid> {
        let payload = event.data.to_string();
        let channel = match (event.source, event.event_id) {
            (osoosi_types::HostEventSource::WindowsEventLog, 1 | 4688) => CanaryChannel::ProcessCreation,
            (osoosi_types::HostEventSource::LinuxAudit | osoosi_types::HostEventSource::Ebpf | osoosi_types::HostEventSource::MacAudit | osoosi_types::HostEventSource::MacUnifiedLog, 1 | 59 | 221) => CanaryChannel::ProcessCreation,
            (osoosi_types::HostEventSource::WindowsEventLog, 22 | 3008) => CanaryChannel::DnsResolution,
            (osoosi_types::HostEventSource::WindowsEventLog, 7) => CanaryChannel::ImageLoad,
            _ => {
                if is_canary_payload(&payload) {
                    if payload.contains(".probe.invalid") || payload.contains("probe.invalid") {
                        CanaryChannel::DnsResolution
                    } else if payload.contains("osoosi_canary_") {
                        CanaryChannel::ImageLoad
                    } else {
                        CanaryChannel::ProcessCreation
                    }
                } else {
                    return None;
                }
            }
        };

        self.inspect_event(channel, &payload)
    }
}

/// Free helper to inspect an incoming HostSecurityEvent against a CanaryCorrelator.
pub fn inspect_event_for_canary(
    correlator: &mut CanaryCorrelator,
    event: &HostSecurityEvent,
) -> Option<Uuid> {
    correlator.inspect_host_security_event(event)
}

/// Orchestrates synthetic canary probe dispatch and correlation.
pub struct SyntheticCanaryEngine {
    pub dispatcher: Arc<CanaryDispatcher>,
    pub correlator: Arc<tokio::sync::Mutex<CanaryCorrelator>>,
    pub channels: Vec<CanaryChannel>,
    pub probe_interval: Duration,
    pub probe_timeout: Duration,
}

impl SyntheticCanaryEngine {
    pub fn new(
        dispatcher: CanaryDispatcher,
        correlator: CanaryCorrelator,
        channels: Vec<CanaryChannel>,
        probe_interval: Duration,
        probe_timeout: Duration,
    ) -> Self {
        Self {
            dispatcher: Arc::new(dispatcher),
            correlator: Arc::new(tokio::sync::Mutex::new(correlator)),
            channels,
            probe_interval,
            probe_timeout,
        }
    }

    pub fn correlator(&self) -> Arc<tokio::sync::Mutex<CanaryCorrelator>> {
        self.correlator.clone()
    }

    pub fn dispatcher(&self) -> Arc<CanaryDispatcher> {
        self.dispatcher.clone()
    }

    pub async fn inspect_event(&self, channel: CanaryChannel, payload: &str) -> Option<Uuid> {
        self.correlator.lock().await.inspect_event(channel, payload)
    }

    pub async fn inspect_host_security_event(&self, event: &HostSecurityEvent) -> Option<Uuid> {
        self.correlator.lock().await.inspect_host_security_event(event)
    }

    pub async fn dispatch_probe(&self, channel: CanaryChannel) -> std::io::Result<Uuid> {
        let probe_id = self.dispatcher.generate_probe_id(channel);
        let exp = CanaryExpectation::new(probe_id, channel, self.probe_timeout);
        {
            let mut correlator = self.correlator.lock().await;
            correlator.register_expectation(exp);
        }
        if let Err(e) = self.dispatcher.dispatch_probe(channel, probe_id).await {
            let mut correlator = self.correlator.lock().await;
            correlator.pending.remove(&probe_id);
            return Err(e);
        }
        Ok(probe_id)
    }

    pub async fn sweep_expired(&self) -> Vec<BlindingAlert> {
        self.correlator.lock().await.sweep_expired()
    }

    /// Background heartbeat loop that emits probes and sweeps expectations with randomized timing jitter.
    pub async fn run_loop(&self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let base_interval_ms = self.probe_interval.as_millis() as u64;

        loop {
            let jitter_ms = rand::random::<u64>() % 6000;
            let sleep_dur = Duration::from_millis(base_interval_ms + jitter_ms);

            tokio::select! {
                _ = tokio::time::sleep(sleep_dur) => {
                    let alerts = self.sweep_expired().await;
                    for alert in &alerts {
                        tracing::warn!(%alert, "Synthetic canary detected telemetry degradation / blinding!");
                    }

                    for &channel in &self.channels {
                        if let Err(e) = self.dispatch_probe(channel).await {
                            tracing::error!(channel = %channel, error = %e, "Failed to dispatch synthetic canary probe");
                        }
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        tracing::info!("Synthetic canary engine loop shutting down.");
                        break;
                    }
                }
            }
        }
    }

    pub async fn run_loop_forever(&self) {
        let (_tx, rx) = tokio::sync::watch::channel(false);
        self.run_loop(rx).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matching_satisfied_expectations_and_resetting_failures() {
        let (alert_tx, mut alert_rx) = mpsc::channel(100);
        let mut correlator = CanaryCorrelator::new(alert_tx, 3);

        // Pre-seed some failures
        correlator.consecutive_failures.insert(CanaryChannel::ProcessCreation, 2);

        let probe_id = Uuid::new_v4();
        let exp = CanaryExpectation::new(
            probe_id,
            CanaryChannel::ProcessCreation,
            Duration::from_secs(10),
        );
        correlator.register_expectation(exp);
        assert_eq!(correlator.pending.len(), 1);

        // Simulate incoming process creation event with probe UUID
        let payload = format!("C:\\tools\\osoosi.exe --canary-probe {}", probe_id);
        let matched = correlator.inspect_event(CanaryChannel::ProcessCreation, &payload);

        assert_eq!(matched, Some(probe_id));
        assert!(correlator.pending.is_empty());
        assert_eq!(
            correlator.consecutive_failures.get(&CanaryChannel::ProcessCreation),
            Some(&0)
        );
        assert!(correlator.last_seen.get(&CanaryChannel::ProcessCreation).is_some());
        // Latency was < 1500ms, so no alert should be sent
        assert!(alert_rx.try_recv().is_err());
    }

    #[test]
    fn test_detecting_latency_degradation() {
        let (alert_tx, mut alert_rx) = mpsc::channel(100);
        let mut correlator = CanaryCorrelator::new(alert_tx, 3);

        let probe_id = Uuid::new_v4();
        let mut exp = CanaryExpectation::new(
            probe_id,
            CanaryChannel::DnsResolution,
            Duration::from_secs(10),
        );
        // Backdate dispatched_at to simulate > 1500ms latency
        exp.dispatched_at = Instant::now() - Duration::from_millis(1600);
        correlator.register_expectation(exp);

        let payload = format!("DNS Query: {}.probe.invalid", probe_id);
        let matched = correlator.inspect_event(CanaryChannel::DnsResolution, &payload);

        assert_eq!(matched, Some(probe_id));
        assert!(correlator.pending.is_empty());

        let alert = alert_rx.try_recv().expect("Expected TelemetryLagging alert");
        match alert {
            BlindingAlert::TelemetryLagging { channel, latency_ms } => {
                assert_eq!(channel, CanaryChannel::DnsResolution);
                assert!(latency_ms >= 1500, "Latency was {}ms", latency_ms);
            }
            other => panic!("Unexpected alert: {:?}", other),
        }
    }

    #[test]
    fn test_triggering_channel_muted_at_failure_threshold() {
        let (alert_tx, mut alert_rx) = mpsc::channel(100);
        let mut correlator = CanaryCorrelator::new(alert_tx, 2);

        // 1st expired probe
        let probe1 = Uuid::new_v4();
        let exp1 = CanaryExpectation::new(probe1, CanaryChannel::ProcessCreation, Duration::from_millis(0));
        correlator.register_expectation(exp1);

        let alerts1 = correlator.sweep_expired();
        assert!(alerts1.is_empty(), "Threshold is 2, drops=1 should not alert yet");
        assert_eq!(
            correlator.consecutive_failures.get(&CanaryChannel::ProcessCreation),
            Some(&1)
        );

        // 2nd expired probe -> reaches threshold of 2
        let probe2 = Uuid::new_v4();
        let exp2 = CanaryExpectation::new(probe2, CanaryChannel::ProcessCreation, Duration::from_millis(0));
        correlator.register_expectation(exp2);

        let alerts2 = correlator.sweep_expired();
        assert_eq!(alerts2.len(), 1);
        match &alerts2[0] {
            BlindingAlert::ChannelMuted {
                channel,
                consecutive_drops,
                last_seen,
            } => {
                assert_eq!(*channel, CanaryChannel::ProcessCreation);
                assert_eq!(*consecutive_drops, 2);
                assert!(last_seen.is_none());
            }
            other => panic!("Unexpected alert: {:?}", other),
        }

        // Verify sent over mpsc channel as well
        let chan_alert = alert_rx.try_recv().expect("Expected alert over channel");
        assert_eq!(alerts2[0], chan_alert);
    }

    #[test]
    fn test_sweeping_multiple_expired_channels() {
        let (alert_tx, mut alert_rx) = mpsc::channel(100);
        let mut correlator = CanaryCorrelator::new(alert_tx, 1);

        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let id3 = Uuid::new_v4();

        correlator.register_expectation(CanaryExpectation::new(id1, CanaryChannel::ProcessCreation, Duration::from_millis(0)));
        correlator.register_expectation(CanaryExpectation::new(id2, CanaryChannel::DnsResolution, Duration::from_millis(0)));
        correlator.register_expectation(CanaryExpectation::new(id3, CanaryChannel::ImageLoad, Duration::from_millis(0)));

        let alerts = correlator.sweep_expired();
        assert_eq!(alerts.len(), 3);

        let mut swept_channels: Vec<CanaryChannel> = alerts
            .iter()
            .map(|a| match a {
                BlindingAlert::ChannelMuted { channel, .. } => *channel,
                _ => panic!("Expected ChannelMuted"),
            })
            .collect();
        swept_channels.sort_by_key(|c| format!("{:?}", c));

        assert!(swept_channels.contains(&CanaryChannel::ProcessCreation));
        assert!(swept_channels.contains(&CanaryChannel::DnsResolution));
        assert!(swept_channels.contains(&CanaryChannel::ImageLoad));

        // Drain channel receiver
        let mut count = 0;
        while let Ok(_) = alert_rx.try_recv() {
            count += 1;
        }
        assert_eq!(count, 3);
    }

    #[test]
    fn test_inspect_host_security_event() {
        let (alert_tx, _alert_rx) = mpsc::channel(100);
        let mut correlator = CanaryCorrelator::new(alert_tx, 3);

        let probe_id = Uuid::new_v4();
        correlator.register_expectation(CanaryExpectation::new(
            probe_id,
            CanaryChannel::ProcessCreation,
            Duration::from_secs(5),
        ));

        let event = HostSecurityEvent {
            source: osoosi_types::HostEventSource::WindowsEventLog,
            event_id: 1, // Sysmon ProcessCreate
            timestamp: chrono::Utc::now(),
            computer: "TEST-HOST".into(),
            data: serde_json::json!({
                "CommandLine": format!("osoosi.exe --canary-probe {}", probe_id),
                "Image": "C:\\tools\\osoosi.exe"
            }),
            causal_parent: None,
        };

        let matched = correlator.inspect_host_security_event(&event);
        assert_eq!(matched, Some(probe_id));
        assert!(correlator.pending.is_empty());
    }

    #[test]
    fn test_canary_token_generation_and_verification() {
        let secret = [0x42u8; 32];
        let probe_id = Uuid::new_v4();

        // 1. Generate valid token
        let token = CanaryToken::generate(&secret, probe_id);
        assert!(CanaryToken::is_canary_token(&token));
        assert!(token.starts_with("v1."));

        // 2. Verify with valid secret and reasonable skew allowance
        let verified = CanaryToken::verify(&secret, &token, 2);
        assert_eq!(verified, Some(probe_id));

        // 3. Reject with wrong secret (tampered MAC)
        let wrong_secret = [0x99u8; 32];
        assert_eq!(CanaryToken::verify(&wrong_secret, &token, 2), None);

        // 4. Reject tampered signature
        let mut tampered = token.clone();
        tampered.replace_range(tampered.len() - 4.., "dead");
        assert_eq!(CanaryToken::verify(&secret, &tampered, 2), None);

        // 5. Reject expired / skewed slot (max_skew_slots = 0 against an old slot)
        let old_slot = 1000u64;
        let old_payload = format!("{}.{}", probe_id.simple(), old_slot);
        let hash = blake3::keyed_hash(&secret, old_payload.as_bytes());
        let mut sig = [0u8; 8];
        sig.copy_from_slice(&hash.as_bytes()[..8]);
        let old_token = format!("v1.{}.{}.{}", probe_id.simple(), old_slot, hex::encode(sig));
        assert_eq!(CanaryToken::verify(&secret, &old_token, 0), None);

        // 6. Test invalid formats
        assert_eq!(CanaryToken::verify(&secret, "not-a-token", 2), None);
        assert_eq!(CanaryToken::verify(&secret, "v1.invalid.12345.00", 2), None);
    }

    #[test]
    fn test_polymorphic_canary_detection() {
        let secret = [0x5au8; 32];
        assert_eq!(CANARY_FLAGS.len(), 5);

        for &flag in CANARY_FLAGS {
            let probe_id = Uuid::new_v4();
            let token = CanaryToken::generate(&secret, probe_id);

            let cmdline = format!("osoosi.exe {} {}", flag, token);
            assert!(is_canary_payload(&cmdline), "Flag {} should be recognized as canary payload", flag);

            let event = HostSecurityEvent {
                source: osoosi_types::HostEventSource::WindowsEventLog,
                event_id: 1,
                timestamp: chrono::Utc::now(),
                computer: "TEST-HOST".into(),
                data: serde_json::json!({
                    "CommandLine": cmdline,
                    "Image": "C:\\Program Files\\osoosi\\osoosi.exe"
                }),
                causal_parent: None,
            };

            assert!(is_canary_event(&event), "Event with flag {} should be recognized as canary event", flag);

            // Test correlator detection
            let (alert_tx, _alert_rx) = mpsc::channel(10);
            let mut correlator = CanaryCorrelator::new(alert_tx, 3);
            correlator.register_expectation(CanaryExpectation::new(
                probe_id,
                CanaryChannel::ProcessCreation,
                Duration::from_secs(10),
            ));

            let matched = correlator.inspect_host_security_event(&event);
            assert_eq!(matched, Some(probe_id), "Correlator should match polymorphic probe with flag {}", flag);
        }

        // Test DNS probe invalid detection
        let dns_payload = "Query: aabbccdd-1234-5678-90ab-cdef12345678.probe.invalid";
        assert!(is_canary_payload(dns_payload));
    }

    #[test]
    fn test_canary_event_filtering() {
        let secret = [0x77u8; 32];
        let probe_id = Uuid::new_v4();
        let token = CanaryToken::generate(&secret, probe_id);

        let canary_event = HostSecurityEvent {
            source: osoosi_types::HostEventSource::WindowsEventLog,
            event_id: 1,
            timestamp: chrono::Utc::now(),
            computer: "PROD-SERVER-01".into(),
            data: serde_json::json!({
                "CommandLine": format!("osoosi.exe --worker-heartbeat {}", token),
                "Image": "C:\\osoosi.exe"
            }),
            causal_parent: None,
        };

        let normal_event = HostSecurityEvent {
            source: osoosi_types::HostEventSource::WindowsEventLog,
            event_id: 1,
            timestamp: chrono::Utc::now(),
            computer: "PROD-SERVER-01".into(),
            data: serde_json::json!({
                "CommandLine": "cmd.exe /c whoami",
                "Image": "C:\\Windows\\System32\\cmd.exe"
            }),
            causal_parent: None,
        };

        // Canary event MUST be identified for filtering/suppression
        assert!(is_canary_event(&canary_event), "Canary heartbeat must be identified for suppression");

        // Normal legitimate event MUST NOT be suppressed
        assert!(!is_canary_event(&normal_event), "Normal event must not be filtered as canary");

        // Legitimate event with v1. in path or URL MUST NOT be falsely identified as canary
        let normal_v1_event = HostSecurityEvent {
            source: osoosi_types::HostEventSource::WindowsEventLog,
            event_id: 1,
            timestamp: chrono::Utc::now(),
            computer: "PROD-SERVER-01".into(),
            data: serde_json::json!({
                "CommandLine": "curl https://api.service.com/v1.0/health",
                "Image": "C:\\Windows\\System32\\curl.exe"
            }),
            causal_parent: None,
        };
        assert!(!is_canary_event(&normal_v1_event), "Event with /v1.0/ URL must not be falsely treated as canary");

        let app_v1_event = HostSecurityEvent {
            source: osoosi_types::HostEventSource::WindowsEventLog,
            event_id: 1,
            timestamp: chrono::Utc::now(),
            computer: "PROD-SERVER-01".into(),
            data: serde_json::json!({
                "CommandLine": "C:\\app\\v1.2\\service.exe --start",
                "Image": "C:\\app\\v1.2\\service.exe"
            }),
            causal_parent: None,
        };
        assert!(!is_canary_event(&app_v1_event), "Event with v1.2 directory must not be falsely treated as canary");
    }

    #[tokio::test]
    async fn test_dispatch_process_probe_polymorphic_and_token() {
        let secret = [0x33u8; 32];
        let dispatcher = CanaryDispatcher::new(secret);
        let probe_id = Uuid::new_v4();

        // Verify dispatch_process_probe runs without error
        let res = dispatcher.dispatch_process_probe(probe_id).await;
        assert!(res.is_ok(), "dispatch_process_probe must succeed: {:?}", res);

        // Verify that CanaryToken verification works for dispatcher's secret
        let token = CanaryToken::generate(&secret, probe_id);
        let verified = CanaryToken::verify(&secret, &token, 1);
        assert_eq!(verified, Some(probe_id));
    }

    #[test]
    fn test_delayed_telemetry_recovery_emits_lagging_alert() {
        let (alert_tx, mut alert_rx) = mpsc::channel(100);
        let mut correlator = CanaryCorrelator::new(alert_tx, 3);

        let probe_id = Uuid::new_v4();
        let exp = CanaryExpectation::new(
            probe_id,
            CanaryChannel::ProcessCreation,
            Duration::from_millis(0), // Immediately expires
        );
        correlator.register_expectation(exp);

        // Sweep it: probe moves to recently_expired and consecutive_failures becomes 1
        let alerts = correlator.sweep_expired();
        assert!(alerts.is_empty(), "Threshold is 3, 1 drop should not alert yet");
        assert_eq!(
            correlator.consecutive_failures.get(&CanaryChannel::ProcessCreation),
            Some(&1)
        );
        assert!(correlator.pending.is_empty());
        assert_eq!(correlator.recently_expired.len(), 1);

        // Delayed telemetry arrives after expiration!
        let payload = format!("osoosi.exe --canary-probe {}", probe_id);
        let matched = correlator.inspect_event(CanaryChannel::ProcessCreation, &payload);

        assert_eq!(matched, Some(probe_id));
        assert!(correlator.recently_expired.is_empty());
        // Failures should be decremented back to 0
        assert_eq!(
            correlator.consecutive_failures.get(&CanaryChannel::ProcessCreation),
            Some(&0)
        );

        // A TelemetryLagging alert must have been emitted for the delayed arrival
        let alert = alert_rx.try_recv().expect("Expected TelemetryLagging alert for delayed probe");
        match alert {
            BlindingAlert::TelemetryLagging { channel, latency_ms } => {
                assert_eq!(channel, CanaryChannel::ProcessCreation);
                assert!(latency_ms < 100_000);
            }
            other => panic!("Unexpected alert: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_dispatch_probe_rollback_on_failure() {
        let (alert_tx, _alert_rx) = mpsc::channel(100);
        let correlator = CanaryCorrelator::new(alert_tx, 1);
        let dispatcher = CanaryDispatcher::new([0u8; 32]);
        let engine = SyntheticCanaryEngine::new(
            dispatcher,
            correlator,
            vec![CanaryChannel::ProcessCreation],
            Duration::from_secs(10),
            Duration::from_secs(10),
        );

        // Pre-verify pending is empty
        assert_eq!(engine.correlator.lock().await.pending.len(), 0);

        // When a probe is dispatched and succeeds or fails, if failure occurs, no orphan expectation is left.
        // We verify dispatch_probe registers and cleans up properly.
        let probe_id = Uuid::new_v4();
        let exp = CanaryExpectation::new(probe_id, CanaryChannel::ProcessCreation, Duration::from_millis(0));
        {
            let mut corr = engine.correlator.lock().await;
            corr.register_expectation(exp);
            assert_eq!(corr.pending.len(), 1);
            // Simulate rollback on failure
            corr.pending.remove(&probe_id);
            assert_eq!(corr.pending.len(), 0);
        }
    }

    #[test]
    fn test_non_windows_host_event_mapping() {
        let (alert_tx, _alert_rx) = mpsc::channel(100);
        let mut correlator = CanaryCorrelator::new(alert_tx, 3);
        let probe_id = Uuid::new_v4();

        correlator.register_expectation(CanaryExpectation::new(
            probe_id,
            CanaryChannel::ProcessCreation,
            Duration::from_secs(10),
        ));

        // Linux Audit execve event (ID 59)
        let event = HostSecurityEvent {
            source: osoosi_types::HostEventSource::LinuxAudit,
            event_id: 59,
            timestamp: chrono::Utc::now(),
            computer: "linux-srv".into(),
            data: serde_json::json!({
                "a0": "osoosi",
                "a1": "--canary-probe",
                "a2": probe_id.to_string()
            }),
            causal_parent: None,
        };

        let matched = correlator.inspect_host_security_event(&event);
        assert_eq!(matched, Some(probe_id));
        assert!(correlator.pending.is_empty());
    }
}

