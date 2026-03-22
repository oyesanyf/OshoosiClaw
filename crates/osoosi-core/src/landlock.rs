//! Landlock-based Filesystem Sandboxing for OpenỌ̀ṣọ́ọ̀sì.
//!
//! Uses the Linux Landlock LSM (Linux Security Module) to enforce
//! mandatory filesystem access controls at the kernel level. Once
//! applied, even root cannot bypass these restrictions.
//!
//! This provides a "jail" around the agent that prevents:
//! - YARA rules/ML models from being tampered with (read-only)
//! - Quarantine escape (write-only to quarantine dir)
//! - Arbitrary filesystem traversal by compromised WASM scripts
//!
//! # Platform Support
//! - **Linux 5.13+**: Full Landlock support
//! - **Linux < 5.13**: Graceful degradation (warning only)
//! - **Windows/macOS**: Not supported (uses OpenShell instead)

use std::path::PathBuf;
#[allow(unused_imports)]
use tracing::{info, warn, error};

/// Landlock sandbox configuration.
#[derive(Debug, Clone)]
pub struct LandlockConfig {
    /// Paths that can only be read (YARA rules, models, config).
    pub read_only_paths: Vec<PathBuf>,
    /// Paths that can be read and written (logs, quarantine, DB).
    pub writable_paths: Vec<PathBuf>,
    /// Whether to fail hard if Landlock is not supported.
    pub strict_mode: bool,
}

impl Default for LandlockConfig {
    fn default() -> Self {
        Self {
            read_only_paths: vec![
                PathBuf::from("/opt/osoosi/yara"),
                PathBuf::from("/opt/osoosi/models"),
                PathBuf::from("/opt/osoosi/config"),
                PathBuf::from("/opt/osoosi/dashboard"),
                PathBuf::from("/usr"),
                PathBuf::from("/lib"),
                PathBuf::from("/etc"),
            ],
            writable_paths: vec![
                PathBuf::from("/opt/osoosi/logs"),
                PathBuf::from("/opt/osoosi/quarantine"),
                PathBuf::from("/opt/osoosi/data"),
                PathBuf::from("/opt/osoosi/certs"),
                PathBuf::from("/tmp"),
            ],
            strict_mode: false,
        }
    }
}

/// Apply the Landlock sandbox to the current process.
///
/// After calling this function, the process can ONLY access the paths
/// specified in the config. All other filesystem access is denied by
/// the kernel — even for root.
#[cfg(target_os = "linux")]
pub fn apply_landlock_sandbox(config: &LandlockConfig) -> anyhow::Result<()> {
    use std::os::unix::io::AsRawFd;

    // Check Landlock availability
    let abi = match landlock_abi_version() {
        Some(v) => v,
        None => {
            if config.strict_mode {
                anyhow::bail!("Landlock not supported on this kernel. Upgrade to Linux 5.13+");
            }
            warn!("Landlock not supported on this kernel. Filesystem sandbox disabled.");
            warn!("Consider upgrading to Linux 5.13+ or using OpenShell containerization.");
            return Ok(());
        }
    };

    info!("Applying Landlock filesystem sandbox (ABI v{})...", abi);

    // Create the ruleset
    let ruleset_fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &landlock_ruleset_attr(abi) as *const _,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };

    if ruleset_fd < 0 {
        let err = std::io::Error::last_os_error();
        if config.strict_mode {
            anyhow::bail!("Failed to create Landlock ruleset: {}", err);
        }
        warn!("Failed to create Landlock ruleset: {}. Continuing without sandbox.", err);
        return Ok(());
    }

    let ruleset_fd = ruleset_fd as i32;

    // Add read-only rules
    for path in &config.read_only_paths {
        if path.exists() {
            if let Err(e) = add_landlock_path_rule(ruleset_fd, path, false) {
                warn!("Could not add read-only rule for {:?}: {}", path, e);
            }
        }
    }

    // Add writable rules
    for path in &config.writable_paths {
        if path.exists() {
            if let Err(e) = add_landlock_path_rule(ruleset_fd, path, true) {
                warn!("Could not add writable rule for {:?}: {}", path, e);
            }
        }
    }

    // Restrict self — this is irreversible!
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        warn!("PR_SET_NO_NEW_PRIVS failed: {}", err);
    }

    let ret = unsafe {
        libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0u32)
    };

    unsafe { libc::close(ruleset_fd); }

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        if config.strict_mode {
            anyhow::bail!("Failed to apply Landlock restriction: {}", err);
        }
        warn!("Failed to apply Landlock restriction: {}. Continuing without sandbox.", err);
        return Ok(());
    }

    info!("Landlock filesystem sandbox ACTIVE. {} read-only, {} writable paths.",
        config.read_only_paths.len(), config.writable_paths.len());
    Ok(())
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn apply_landlock_sandbox(config: &LandlockConfig) -> anyhow::Result<()> {
    warn!("Landlock sandboxing is Linux-only. Using OpenShell for containment on this platform.");
    let _ = config;
    Ok(())
}

// --- Landlock syscall helpers ---

#[cfg(target_os = "linux")]
#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[cfg(target_os = "linux")]
fn landlock_ruleset_attr(abi: u32) -> LandlockRulesetAttr {
    // ABI v1 access flags
    let mut flags: u64 = 
        (1 << 0)  | // EXECUTE
        (1 << 1)  | // WRITE_FILE
        (1 << 2)  | // READ_FILE
        (1 << 3)  | // READ_DIR
        (1 << 4)  | // REMOVE_DIR
        (1 << 5)  | // REMOVE_FILE
        (1 << 6)  | // MAKE_CHAR
        (1 << 7)  | // MAKE_DIR
        (1 << 8)  | // MAKE_REG
        (1 << 9)  | // MAKE_SOCK
        (1 << 10) | // MAKE_FIFO
        (1 << 11) | // MAKE_BLOCK
        (1 << 12);  // MAKE_SYM

    if abi >= 2 {
        flags |= (1 << 13); // REFER (move/rename across dirs)
    }
    if abi >= 3 {
        flags |= (1 << 14); // TRUNCATE
    }

    LandlockRulesetAttr {
        handled_access_fs: flags,
    }
}

#[cfg(target_os = "linux")]
fn landlock_abi_version() -> Option<u32> {
    // SYS_landlock_create_ruleset with NULL attr and size 0 returns the ABI version
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0usize,
            1u32, // LANDLOCK_CREATE_RULESET_VERSION
        )
    };
    if ret >= 0 {
        Some(ret as u32)
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

#[cfg(target_os = "linux")]
fn add_landlock_path_rule(ruleset_fd: i32, path: &std::path::Path, writable: bool) -> anyhow::Result<()> {
    use std::os::unix::io::AsRawFd;

    let fd = std::fs::File::open(path)?;
    let parent_fd = fd.as_raw_fd();

    let read_access: u64 = (1 << 2) | (1 << 3); // READ_FILE | READ_DIR
    let write_access: u64 = (1 << 1) | (1 << 4) | (1 << 5) | (1 << 8); // WRITE_FILE | REMOVE_DIR | REMOVE_FILE | MAKE_REG

    let allowed_access = if writable {
        read_access | write_access
    } else {
        read_access
    };

    let attr = LandlockPathBeneathAttr {
        allowed_access,
        parent_fd,
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd,
            1u32, // LANDLOCK_RULE_PATH_BENEATH
            &attr as *const _,
            0u32,
        )
    };

    if ret < 0 {
        Err(anyhow::anyhow!("landlock_add_rule failed: {}", std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}
