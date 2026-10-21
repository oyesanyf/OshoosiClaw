//! Environment-Keyed Honeytokens (HDS Traps).
//!
//! Deploys dynamic trap files that are uniquely keyed to the asset ID.
//! Any access to these files triggers a high-confidence autonomy flag.

use std::fs;
use std::path::{Path, PathBuf};
use tracing::info;

pub struct HoneytokenManager {
    pub base_path: PathBuf,
    pub asset_id: String,
}

impl HoneytokenManager {
    pub fn new(base_path: PathBuf, asset_id: String) -> Self {
        Self {
            base_path,
            asset_id,
        }
    }

    /// Deploy a deception honeytoken (e.g. 'backup_credentials.txt').
    /// The file content is keyed to the asset_id to track exfiltration.
    pub fn deploy_trap(&self, name: &str) -> anyhow::Result<PathBuf> {
        let trap_path = self.base_path.join(name);

        let rev_asset_id: String = self.asset_id.chars().rev().collect();
        let payload = format!(
            "--- OSOOSI DECEPTION LAYER ---\n\
             AssetID: {}\n\
             Key: hds-traps-v1-{}\n\
             GeneratedAt: {}\n\n\
             DB_USER=osoosi_admin\n\
             DB_PASS=osoosi_{}\n",
            self.asset_id,
            uuid::Uuid::new_v4(),
            chrono::Utc::now(),
            rev_asset_id
        );

        fs::write(&trap_path, payload)?;
        info!("DECEPTION: Deployed honeytoken trap at {:?}", trap_path);

        Ok(trap_path)
    }

    /// Clean up deployed traps.
    pub fn cleanup_traps(&self) -> anyhow::Result<()> {
        if self.base_path.exists() {
            for entry in fs::read_dir(&self.base_path)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    let _ = fs::remove_file(path);
                }
            }
        }
        Ok(())
    }

    /// Deploy a diskless ephemeral canary named pipe on Windows.
    #[cfg(windows)]
    pub fn deploy_diskless_canary_pipe(
        &self,
        session_id: &str,
    ) -> anyhow::Result<(String, windows::Win32::Foundation::HANDLE)> {
        use windows::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows::Win32::Storage::FileSystem::{
            FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
        };
        use windows::Win32::System::Pipes::{
            CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_TYPE_BYTE, PIPE_WAIT,
        };
        use windows::core::PCWSTR;

        let rand_hex = format!("{:016x}", uuid::Uuid::new_v4().as_u128());
        let pipe_name = format!(r"\\.\pipe\osoosi_canary_{}_{}", session_id, rand_hex);
        let wide_pipe: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();

        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR::from_raw(wide_pipe.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                4096,
                4096,
                0,
                None,
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            return Err(anyhow::anyhow!(
                "Failed to create ephemeral canary named pipe {}: {:?}",
                pipe_name,
                std::io::Error::last_os_error()
            ));
        }

        info!("DECEPTION: Deployed diskless ephemeral canary named pipe {}", pipe_name);
        Ok((pipe_name, handle))
    }

    /// Fallback for diskless ephemeral pipe on non-Windows platforms.
    #[cfg(not(windows))]
    pub fn deploy_diskless_canary_pipe(&self, _session_id: &str) -> anyhow::Result<String> {
        Err(anyhow::anyhow!("Named pipe canary is only supported on Windows"))
    }

    /// Deploy a diskless ephemeral in-memory canary file descriptor (memfd) on Linux.
    #[cfg(target_os = "linux")]
    pub fn deploy_diskless_canary_memfd(
        &self,
        name: &str,
        payload: &[u8],
    ) -> anyhow::Result<std::os::fd::RawFd> {
        use std::ffi::CString;
        let c_name = CString::new(name).unwrap_or_else(|_| CString::new("edr_canary_token").unwrap());
        let fd = unsafe {
            libc::syscall(libc::SYS_memfd_create, c_name.as_ptr(), libc::MFD_CLOEXEC) as std::os::fd::RawFd
        };
        if fd < 0 {
            return Err(anyhow::anyhow!(
                "memfd_create failed: {:?}",
                std::io::Error::last_os_error()
            ));
        }
        if !payload.is_empty() {
            let written = unsafe {
                libc::write(fd, payload.as_ptr() as *const libc::c_void, payload.len())
            };
            if written < 0 {
                unsafe { libc::close(fd); }
                return Err(anyhow::anyhow!(
                    "Failed to write payload to memfd: {:?}",
                    std::io::Error::last_os_error()
                ));
            }
            unsafe {
                libc::lseek(fd, 0, libc::SEEK_SET);
            }
        }
        info!("DECEPTION: Deployed diskless ephemeral memfd canary fd {}", fd);
        Ok(fd)
    }

    /// Fallback for memfd canary on non-Linux platforms.
    #[cfg(not(target_os = "linux"))]
    pub fn deploy_diskless_canary_memfd(&self, _name: &str, _payload: &[u8]) -> anyhow::Result<i32> {
        Err(anyhow::anyhow!("memfd_create canary is only supported on Linux"))
    }
}

/// Alias for HoneytokenManager to support CanaryManager naming convention.
pub type CanaryManager = HoneytokenManager;

/// Verify if a file event is a 'trap hit'.
pub fn is_trap_hit(path: &Path, trap_locations: &[PathBuf]) -> bool {
    trap_locations.iter().any(|p| p == path)
}

/// Ephemeral Agent Session Canary for Moving Target Defense.
/// Generates per-session randomized canary environment variable keys, values, and decoy tool schemas.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct EphemeralAgentCanary {
    pub session_id: String,
    pub env_var_name: String,
    pub canary_token: String,
    pub decoy_tool_name: String,
}

impl EphemeralAgentCanary {
    /// Generates a randomized, ephemeral canary set for an agent session.
    pub fn generate_for_session(session_id: &str) -> Self {
        let rand_hex = format!("{:032x}", uuid::Uuid::new_v4().as_u128());
        let env_var_name = format!("OSOOSI_CANARY_{}", rand_hex[..8].to_ascii_uppercase());
        let canary_token = format!("sk-canary-{}-{}", session_id, &rand_hex[8..20]);
        let decoy_tool_name = format!("execute_admin_privilege_override_{}", &rand_hex[..6]);

        Self {
            session_id: session_id.to_string(),
            env_var_name,
            canary_token,
            decoy_tool_name,
        }
    }
}
