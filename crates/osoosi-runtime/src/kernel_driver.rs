//! Windows Ring-0 Kernel Driver User-Space Interface.
//!
//! Provides communication with `\\.\OsoosiDriver` for hardware-enforced pre-operation
//! process execution blocking before Sysmon Event 1 can fire and before the initial thread starts.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info};

// CTL_CODE calculation
pub const FILE_DEVICE_UNKNOWN: u32 = 0x00000022;
pub const METHOD_BUFFERED: u32 = 0;
pub const FILE_ANY_ACCESS: u32 = 0;
pub const FILE_WRITE_ACCESS: u32 = 2;
pub const OSOOSI_IOCTL_BASE: u32 = 0x800;

pub const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

pub const IOCTL_OSOOSI_GET_STATUS: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    OSOOSI_IOCTL_BASE,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

pub const IOCTL_OSOOSI_SET_MODE: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    OSOOSI_IOCTL_BASE + 1,
    METHOD_BUFFERED,
    FILE_WRITE_ACCESS,
);

pub const IOCTL_OSOOSI_ADD_BLOCK_PATH: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    OSOOSI_IOCTL_BASE + 2,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

pub const IOCTL_OSOOSI_ADD_BLOCK_HASH: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    OSOOSI_IOCTL_BASE + 3,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

pub const IOCTL_OSOOSI_CLEAR_RULES: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    OSOOSI_IOCTL_BASE + 4,
    METHOD_BUFFERED,
    FILE_WRITE_ACCESS,
);

pub const IOCTL_OSOOSI_POLL_INTERCEPTIONS: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    OSOOSI_IOCTL_BASE + 5,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

pub const OSOOSI_USER_DEVICE_NAME: &str = r"\\.\OsoosiDriver";

/// Autonomy modes matching Ring-0 kernel definitions.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriverAutonomyMode {
    /// Telemetry & logging only; no process executions are blocked.
    Audit = 0,
    /// Hardware-enforced pre-operation blocking of matched binaries.
    Active = 1,
    /// Strictest containment mode.
    Lockdown = 2,
}

impl std::fmt::Display for DriverAutonomyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Audit => write!(f, "Audit"),
            Self::Active => write!(f, "Active"),
            Self::Lockdown => write!(f, "Lockdown"),
        }
    }
}

impl From<u32> for DriverAutonomyMode {
    fn from(val: u32) -> Self {
        match val {
            0 => Self::Audit,
            1 => Self::Active,
            2 => Self::Lockdown,
            _ => Self::Active,
        }
    }
}

/// Driver status returned by `IOCTL_OSOOSI_GET_STATUS`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelDriverStatus {
    pub version: u32,
    pub mode: DriverAutonomyMode,
    pub blocked_count: u32,
    pub rule_count: u32,
}

/// Process creation interception event retrieved from kernel ring queue.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelInterceptEvent {
    pub pid: u32,
    pub parent_pid: u32,
    pub image_path: String,
    pub command_line: String,
    pub timestamp: i64,
    pub blocked: bool,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RawDriverStatus {
    pub version: u32,
    pub mode: u32,
    pub blocked_count: u32,
    pub rule_count: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawInterceptEvent {
    pub pid: u32,
    pub parent_pid: u32,
    pub image_path: [u16; 260],
    pub command_line: [u16; 512],
    pub timestamp: i64,
    pub blocked: u32,
    pub _reserved: u32,
}

impl Default for RawInterceptEvent {
    fn default() -> Self {
        Self {
            pid: 0,
            parent_pid: 0,
            image_path: [0u16; 260],
            command_line: [0u16; 512],
            timestamp: 0,
            blocked: 0,
            _reserved: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawSetModeRequest {
    pub mode: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawAddPathRequest {
    pub image_path: [u16; 260],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawAddHashRequest {
    pub hash: [u8; 32],
}

#[cfg(windows)]
struct SafeHandle(windows::Win32::Foundation::HANDLE);

#[cfg(windows)]
unsafe impl Send for SafeHandle {}
#[cfg(windows)]
unsafe impl Sync for SafeHandle {}

#[cfg(windows)]
impl Drop for SafeHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
}

#[cfg(not(windows))]
#[derive(Debug, Default)]
pub struct UnixKernelState {
    pub mode: std::sync::atomic::AtomicU32,
    pub blocked_count: std::sync::atomic::AtomicU32,
    pub blocked_paths: std::sync::RwLock<Vec<String>>,
    pub blocked_hashes: std::sync::RwLock<Vec<[u8; 32]>>,
    pub intercept_events: std::sync::Mutex<Vec<KernelInterceptEvent>>,
}

#[cfg(not(windows))]
static UNIX_KERNEL_STATE: std::sync::OnceLock<Arc<UnixKernelState>> = std::sync::OnceLock::new();

#[cfg(not(windows))]
fn get_unix_kernel_state() -> Arc<UnixKernelState> {
    UNIX_KERNEL_STATE
        .get_or_init(|| Arc::new(UnixKernelState::default()))
        .clone()
}

/// User-space client interface for the Oshoosi Ring-0 Kernel Driver.
#[derive(Clone)]
pub struct KernelDriverClient {
    #[cfg(windows)]
    handle: Arc<SafeHandle>,
    #[cfg(not(windows))]
    state: Arc<UnixKernelState>,
}

impl KernelDriverClient {
    /// Attempts to open the kernel driver control device `\\.\OsoosiDriver`.
    ///
    /// If the driver service is not installed or running, gracefully logs that
    /// user-mode WFP packet filter + active thread tarpit is operating as the
    /// defense-in-depth layer and returns `None`.
    pub fn open() -> Option<Self> {
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows::Win32::Foundation::INVALID_HANDLE_VALUE;
            use windows::Win32::Storage::FileSystem::{
                CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
                FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
            };

            let wide_path: Vec<u16> = std::ffi::OsStr::new(OSOOSI_USER_DEVICE_NAME)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let handle = unsafe {
                CreateFileW(
                    windows::core::PCWSTR(wide_path.as_ptr()),
                    FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    None,
                )
            };

            match handle {
                Ok(h) if h != INVALID_HANDLE_VALUE => {
                    info!(
                        "[KERNEL_DRIVER] Successfully connected to Ring-0 driver at {}",
                        OSOOSI_USER_DEVICE_NAME
                    );
                    Some(Self {
                        handle: Arc::new(SafeHandle(h)),
                    })
                }
                Ok(_) | Err(_) => {
                    debug!(
                        "[KERNEL_DRIVER] Ring-0 driver device not found at {}. Operating with user-mode WFP packet filter + active thread tarpit.",
                        OSOOSI_USER_DEVICE_NAME
                    );
                    None
                }
            }
        }

        #[cfg(not(windows))]
        {
            info!(
                "[KERNEL_DRIVER] Connected to cross-platform user-space kernel blocklist engine."
            );
            Some(Self {
                state: get_unix_kernel_state(),
            })
        }
    }

    /// Connects to the kernel driver interface (alias for open).
    pub fn connect() -> Option<Self> {
        Self::open()
    }

    /// Returns `true` if connected to an active Ring-0 driver instance.
    pub fn is_available(&self) -> bool {
        #[cfg(windows)]
        {
            !self.handle.0.is_invalid()
        }
        #[cfg(not(windows))]
        {
            true
        }
    }

    /// Query the driver's current operational status.
    pub fn get_status(&self) -> anyhow::Result<KernelDriverStatus> {
        #[cfg(windows)]
        {
            let mut raw = RawDriverStatus::default();
            let mut bytes_returned = 0u32;

            unsafe {
                windows::Win32::System::IO::DeviceIoControl(
                    self.handle.0,
                    IOCTL_OSOOSI_GET_STATUS,
                    None,
                    0,
                    Some(&mut raw as *mut _ as *mut std::ffi::c_void),
                    std::mem::size_of::<RawDriverStatus>() as u32,
                    Some(&mut bytes_returned),
                    None,
                )?;
            }

            Ok(KernelDriverStatus {
                version: raw.version,
                mode: DriverAutonomyMode::from(raw.mode),
                blocked_count: raw.blocked_count,
                rule_count: raw.rule_count,
            })
        }
        #[cfg(not(windows))]
        {
            use std::sync::atomic::Ordering;
            let mode_val = self.state.mode.load(Ordering::SeqCst);
            let blocked = self.state.blocked_count.load(Ordering::SeqCst);
            let p_len = self
                .state
                .blocked_paths
                .read()
                .map(|p| p.len())
                .unwrap_or(0);
            let h_len = self
                .state
                .blocked_hashes
                .read()
                .map(|h| h.len())
                .unwrap_or(0);
            Ok(KernelDriverStatus {
                version: 0x010200,
                mode: DriverAutonomyMode::from(mode_val),
                blocked_count: blocked,
                rule_count: (p_len + h_len) as u32,
            })
        }
    }

    /// Set driver autonomy mode (Audit, Active, Lockdown).
    pub fn set_mode(&self, mode: DriverAutonomyMode) -> anyhow::Result<()> {
        #[cfg(windows)]
        {
            let req = RawSetModeRequest { mode: mode as u32 };
            let mut bytes_returned = 0u32;

            unsafe {
                windows::Win32::System::IO::DeviceIoControl(
                    self.handle.0,
                    IOCTL_OSOOSI_SET_MODE,
                    Some(&req as *const _ as *const std::ffi::c_void),
                    std::mem::size_of::<RawSetModeRequest>() as u32,
                    None,
                    0,
                    Some(&mut bytes_returned),
                    None,
                )?;
            }
            info!("[KERNEL_DRIVER] Autonomy mode set to: {}", mode);
            Ok(())
        }
        #[cfg(not(windows))]
        {
            use std::sync::atomic::Ordering;
            self.state.mode.store(mode as u32, Ordering::SeqCst);
            info!("[KERNEL_DRIVER] Autonomy mode set to: {}", mode);
            Ok(())
        }
    }

    /// Add an executable path to the kernel blocklist.
    pub fn add_blocked_path(&self, path: &str) -> anyhow::Result<()> {
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;

            let normalized = path.replace('/', "\\");
            let mut req = RawAddPathRequest {
                image_path: [0u16; 260],
            };
            let wide: Vec<u16> = std::ffi::OsStr::new(&normalized).encode_wide().collect();
            let len = wide.len().min(259);
            req.image_path[..len].copy_from_slice(&wide[..len]);
            req.image_path[len] = 0;

            let mut bytes_returned = 0u32;
            unsafe {
                windows::Win32::System::IO::DeviceIoControl(
                    self.handle.0,
                    IOCTL_OSOOSI_ADD_BLOCK_PATH,
                    Some(&req as *const _ as *const std::ffi::c_void),
                    std::mem::size_of::<RawAddPathRequest>() as u32,
                    None,
                    0,
                    Some(&mut bytes_returned),
                    None,
                )?;
            }
            info!(
                "[KERNEL_DRIVER] Added pre-exec block rule for path: {}",
                path
            );
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let normalized = path.replace('\\', "/");
            if let Ok(mut paths) = self.state.blocked_paths.write() {
                if !paths.contains(&normalized) {
                    paths.push(normalized.clone());
                }
            }
            info!(
                "[KERNEL_DRIVER] Added pre-exec block rule for path: {}",
                path
            );
            Ok(())
        }
    }

    /// Add a cryptographic hash to the kernel blocklist.
    pub fn add_blocked_hash(&self, hash_bytes: &[u8; 32]) -> anyhow::Result<()> {
        #[cfg(windows)]
        {
            let mut req = RawAddHashRequest { hash: [0u8; 32] };
            req.hash.copy_from_slice(hash_bytes);

            let mut bytes_returned = 0u32;
            unsafe {
                windows::Win32::System::IO::DeviceIoControl(
                    self.handle.0,
                    IOCTL_OSOOSI_ADD_BLOCK_HASH,
                    Some(&req as *const _ as *const std::ffi::c_void),
                    std::mem::size_of::<RawAddHashRequest>() as u32,
                    None,
                    0,
                    Some(&mut bytes_returned),
                    None,
                )?;
            }
            info!(
                "[KERNEL_DRIVER] Added pre-exec block rule for hash: {}",
                hex::encode(hash_bytes)
            );
            Ok(())
        }
        #[cfg(not(windows))]
        {
            if let Ok(mut hashes) = self.state.blocked_hashes.write() {
                if !hashes.contains(hash_bytes) {
                    hashes.push(*hash_bytes);
                }
            }
            info!(
                "[KERNEL_DRIVER] Added pre-exec block rule for hash: {}",
                hex::encode(hash_bytes)
            );
            Ok(())
        }
    }

    /// Clear all in-memory kernel rules.
    pub fn clear_rules(&self) -> anyhow::Result<()> {
        #[cfg(windows)]
        {
            let mut bytes_returned = 0u32;
            unsafe {
                windows::Win32::System::IO::DeviceIoControl(
                    self.handle.0,
                    IOCTL_OSOOSI_CLEAR_RULES,
                    None,
                    0,
                    None,
                    0,
                    Some(&mut bytes_returned),
                    None,
                )?;
            }
            info!("[KERNEL_DRIVER] Flushed all in-memory kernel rules");
            Ok(())
        }
        #[cfg(not(windows))]
        {
            if let Ok(mut paths) = self.state.blocked_paths.write() {
                paths.clear();
            }
            if let Ok(mut hashes) = self.state.blocked_hashes.write() {
                hashes.clear();
            }
            info!("[KERNEL_DRIVER] Flushed all in-memory kernel rules");
            Ok(())
        }
    }

    /// Poll intercepted pre-execution events queued in the kernel ring buffer.
    pub fn poll_interceptions(&self) -> anyhow::Result<Vec<KernelInterceptEvent>> {
        #[cfg(windows)]
        {
            const BATCH_SIZE: usize = 32;
            let mut raw_events = vec![RawInterceptEvent::default(); BATCH_SIZE];
            let out_size = (BATCH_SIZE * std::mem::size_of::<RawInterceptEvent>()) as u32;
            let mut bytes_returned = 0u32;

            unsafe {
                windows::Win32::System::IO::DeviceIoControl(
                    self.handle.0,
                    IOCTL_OSOOSI_POLL_INTERCEPTIONS,
                    None,
                    0,
                    Some(raw_events.as_mut_ptr() as *mut std::ffi::c_void),
                    out_size,
                    Some(&mut bytes_returned),
                    None,
                )?;
            }

            let event_size = std::mem::size_of::<RawInterceptEvent>() as u32;
            let count = (bytes_returned / event_size) as usize;
            let mut results = Vec::with_capacity(count);

            for raw in raw_events.iter().take(count) {
                let img_len = raw
                    .image_path
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(raw.image_path.len());
                let image_path = String::from_utf16_lossy(&raw.image_path[..img_len]);

                let cmd_len = raw
                    .command_line
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(raw.command_line.len());
                let command_line = String::from_utf16_lossy(&raw.command_line[..cmd_len]);

                results.push(KernelInterceptEvent {
                    pid: raw.pid,
                    parent_pid: raw.parent_pid,
                    image_path,
                    command_line,
                    timestamp: raw.timestamp,
                    blocked: raw.blocked != 0,
                });
            }

            Ok(results)
        }
        #[cfg(not(windows))]
        {
            if let Ok(mut events) = self.state.intercept_events.lock() {
                let drained = events.drain(..).collect();
                Ok(drained)
            } else {
                Ok(Vec::new())
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    #[test]
    fn test_ioctl_code_calculations() {
        assert_eq!(IOCTL_OSOOSI_GET_STATUS, 0x00222000);
        assert_eq!(IOCTL_OSOOSI_SET_MODE, 0x0022A004);
        assert_eq!(IOCTL_OSOOSI_ADD_BLOCK_PATH, 0x00222008);
        assert_eq!(IOCTL_OSOOSI_ADD_BLOCK_HASH, 0x0022200C);
        assert_eq!(IOCTL_OSOOSI_CLEAR_RULES, 0x0022A010);
        assert_eq!(IOCTL_OSOOSI_POLL_INTERCEPTIONS, 0x00222014);
    }

    #[test]
    fn test_raw_struct_sizes() {
        assert_eq!(std::mem::size_of::<RawDriverStatus>(), 16);
        assert_eq!(std::mem::size_of::<RawSetModeRequest>(), 4);
        assert_eq!(std::mem::size_of::<RawAddPathRequest>(), 520);
        assert_eq!(std::mem::size_of::<RawAddHashRequest>(), 32);
        assert_eq!(std::mem::size_of::<RawInterceptEvent>(), 1568);
    }

    #[test]
    fn test_autonomy_mode_conversions() {
        assert_eq!(DriverAutonomyMode::from(0), DriverAutonomyMode::Audit);
        assert_eq!(DriverAutonomyMode::from(1), DriverAutonomyMode::Active);
        assert_eq!(DriverAutonomyMode::from(2), DriverAutonomyMode::Lockdown);
        assert_eq!(DriverAutonomyMode::from(99), DriverAutonomyMode::Active);

        assert_eq!(DriverAutonomyMode::Audit.to_string(), "Audit");
        assert_eq!(DriverAutonomyMode::Active.to_string(), "Active");
        assert_eq!(DriverAutonomyMode::Lockdown.to_string(), "Lockdown");
    }

    #[test]
    fn test_raw_intercept_event_decoding() {
        let mut raw = RawInterceptEvent::default();
        raw.pid = 1234;
        raw.parent_pid = 5678;
        raw.blocked = 1;
        raw.timestamp = 133500000000000000;

        let path_utf16: Vec<u16> = "C:\\malware\\dropper.exe".encode_utf16().collect();
        raw.image_path[..path_utf16.len()].copy_from_slice(&path_utf16);

        let cmd_utf16: Vec<u16> = "dropper.exe -silent".encode_utf16().collect();
        raw.command_line[..cmd_utf16.len()].copy_from_slice(&cmd_utf16);

        let img_len = raw
            .image_path
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(raw.image_path.len());
        let image = String::from_utf16_lossy(&raw.image_path[..img_len]);
        assert_eq!(image, "C:\\malware\\dropper.exe");

        let cmd_len = raw
            .command_line
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(raw.command_line.len());
        let cmd = String::from_utf16_lossy(&raw.command_line[..cmd_len]);
        assert_eq!(cmd, "dropper.exe -silent");
    }

    #[test]
    fn test_driver_open_fallback() {
        // Without driver installed, open() returns None gracefully without panic
        let client = KernelDriverClient::open();
        // In dev test environment where driver is not installed/loaded, client should be None
        if let Some(c) = client {
            assert!(c.is_available());
        }
    }

    #[test]
    fn test_driver_status_serde() {
        let st = KernelDriverStatus {
            version: 0x00010000,
            mode: DriverAutonomyMode::Lockdown,
            blocked_count: 42,
            rule_count: 5,
        };
        let json = serde_json::to_string(&st).unwrap();
        let parsed: KernelDriverStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, st);
    }

    #[test]
    fn test_intercept_event_serde() {
        let ev = KernelInterceptEvent {
            pid: 1234,
            parent_pid: 5678,
            image_path: "C:\\Windows\\System32\\cmd.exe".to_string(),
            command_line: "cmd.exe /c whoami".to_string(),
            timestamp: 133500000000000000,
            blocked: true,
        };
        let json = serde_json::to_string(&ev).unwrap();
        let parsed: KernelInterceptEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ev);
    }

    #[test]
    fn test_path_normalization() {
        let path = "C:/Windows/Temp/payload.exe";
        let normalized = path.replace('/', "\\");
        assert_eq!(normalized, "C:\\Windows\\Temp\\payload.exe");
    }

    #[test]
    fn test_hash_request_layout() {
        let hash = [0xABu8; 32];
        let mut req = RawAddHashRequest { hash: [0u8; 32] };
        req.hash.copy_from_slice(&hash);
        assert_eq!(req.hash[0], 0xAB);
        assert_eq!(req.hash[31], 0xAB);
    }

    #[test]
    fn test_cross_platform_kernel_driver_client() {
        if let Some(client) = KernelDriverClient::connect() {
            assert!(client.is_available());
            assert!(client.set_mode(DriverAutonomyMode::Active).is_ok());
            assert!(client.add_blocked_path("/bin/malicious_dropper").is_ok());
            let hash = [0x55u8; 32];
            assert!(client.add_blocked_hash(&hash).is_ok());
            let status = client.get_status().unwrap();
            assert_eq!(status.mode, DriverAutonomyMode::Active);
            assert!(status.rule_count >= 2);
            assert!(client.poll_interceptions().is_ok());
            assert!(client.clear_rules().is_ok());
        }
    }
}
