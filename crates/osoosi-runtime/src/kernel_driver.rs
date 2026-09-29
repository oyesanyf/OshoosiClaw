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
pub const OSOOSI_IOCTL_BASE: u32 = 0x800;

pub const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

pub const IOCTL_OSOOSI_GET_STATUS: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, OSOOSI_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS);

pub const IOCTL_OSOOSI_SET_MODE: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, OSOOSI_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS);

pub const IOCTL_OSOOSI_ADD_BLOCK_PATH: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, OSOOSI_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS);

pub const IOCTL_OSOOSI_ADD_BLOCK_HASH: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, OSOOSI_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS);

pub const IOCTL_OSOOSI_CLEAR_RULES: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, OSOOSI_IOCTL_BASE + 4, METHOD_BUFFERED, FILE_ANY_ACCESS);

pub const IOCTL_OSOOSI_POLL_INTERCEPTIONS: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, OSOOSI_IOCTL_BASE + 5, METHOD_BUFFERED, FILE_ANY_ACCESS);

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

/// User-space client interface for the Oshoosi Ring-0 Kernel Driver.
#[derive(Clone)]
pub struct KernelDriverClient {
    #[cfg(windows)]
    handle: Arc<SafeHandle>,
    #[cfg(not(windows))]
    _marker: std::marker::PhantomData<()>,
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
                    info!("[KERNEL_DRIVER] Successfully connected to Ring-0 driver at {}", OSOOSI_USER_DEVICE_NAME);
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
            None
        }
    }

    /// Returns `true` if connected to an active Ring-0 driver instance.
    pub fn is_available(&self) -> bool {
        #[cfg(windows)]
        {
            !self.handle.0.is_invalid()
        }
        #[cfg(not(windows))]
        {
            false
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
            anyhow::bail!("Kernel driver is only supported on Windows")
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
            let _ = mode;
            anyhow::bail!("Kernel driver is only supported on Windows")
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
            info!("[KERNEL_DRIVER] Added pre-exec block rule for path: {}", path);
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = path;
            anyhow::bail!("Kernel driver is only supported on Windows")
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
            info!("[KERNEL_DRIVER] Added pre-exec block rule for hash: {}", hex::encode(hash_bytes));
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = hash_bytes;
            anyhow::bail!("Kernel driver is only supported on Windows")
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
            anyhow::bail!("Kernel driver is only supported on Windows")
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
                let img_len = raw.image_path.iter().position(|&c| c == 0).unwrap_or(raw.image_path.len());
                let image_path = String::from_utf16_lossy(&raw.image_path[..img_len]);

                let cmd_len = raw.command_line.iter().position(|&c| c == 0).unwrap_or(raw.command_line.len());
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
            anyhow::bail!("Kernel driver is only supported on Windows")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioctl_code_calculations() {
        assert_eq!(IOCTL_OSOOSI_GET_STATUS, 0x00222000);
        assert_eq!(IOCTL_OSOOSI_SET_MODE, 0x00222004);
        assert_eq!(IOCTL_OSOOSI_ADD_BLOCK_PATH, 0x00222008);
        assert_eq!(IOCTL_OSOOSI_ADD_BLOCK_HASH, 0x0022200C);
        assert_eq!(IOCTL_OSOOSI_CLEAR_RULES, 0x00222010);
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

        let img_len = raw.image_path.iter().position(|&c| c == 0).unwrap_or(raw.image_path.len());
        let image = String::from_utf16_lossy(&raw.image_path[..img_len]);
        assert_eq!(image, "C:\\malware\\dropper.exe");

        let cmd_len = raw.command_line.iter().position(|&c| c == 0).unwrap_or(raw.command_line.len());
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
}
