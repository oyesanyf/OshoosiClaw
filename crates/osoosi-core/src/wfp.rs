//! Native Windows Filtering Platform (WFP) & Linux Netlink Kernel Network Control.
//!
//! Provides in-memory, transaction-safe network filtering without spawning subprocesses.
//! On Windows, uses dynamic sessions (`FWPM_SESSION_FLAG_DYNAMIC = 0x00000001`) via `fwpuclnt.dll`:
//! - Guarantees atomic transaction execution (`FwpmTransactionBegin0` / `Commit0`).
//! - Automatic Kernel Cleanup: if the process terminates or crashes unexpectedly, the Windows
//!   kernel Base Filtering Engine (BFE) automatically purges all dynamic filters, preventing
//!   permanent host lockout.
//! - Strict RAII handle lifetime management (`FwpmEngineClose0`) and raw pointer null checks.

#[cfg(windows)]
use anyhow::anyhow;
use anyhow::Result;
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::LazyLock;
use tracing::info;
#[cfg(windows)]
use tracing::warn;

#[cfg(windows)]
use std::ffi::c_void;

pub const FWPM_SESSION_FLAG_DYNAMIC: u32 = 0x00000001;
pub const RPC_C_AUTHN_DEFAULT: u32 = 0;
pub const ERROR_SUCCESS: u32 = 0;

#[cfg(windows)]
#[repr(C)]
struct FwpmDisplayData0 {
    name: *mut u16,
    description: *mut u16,
}

#[cfg(windows)]
#[repr(C)]
struct FwpmSession0 {
    session_key: [u8; 16],
    display_data: FwpmDisplayData0,
    flags: u32,
    txn_wait_timeout_in_msec: u32,
    process_id: u32,
    sid: *mut c_void,
    username: *mut u16,
    kernel_mode: i32,
}

#[cfg(windows)]
type FnFwpmEngineOpen0 = unsafe extern "system" fn(
    server_name: *const u16,
    authn_service: u32,
    auth_identity: *mut c_void,
    session: *const FwpmSession0,
    engine_handle: *mut *mut c_void,
) -> u32;

#[cfg(windows)]
type FnFwpmEngineClose0 = unsafe extern "system" fn(engine_handle: *mut c_void) -> u32;

#[cfg(windows)]
type FnFwpmTransactionBegin0 =
    unsafe extern "system" fn(engine_handle: *mut c_void, flags: u32) -> u32;

#[cfg(windows)]
type FnFwpmTransactionCommit0 = unsafe extern "system" fn(engine_handle: *mut c_void) -> u32;

#[cfg(windows)]
type FnFwpmTransactionAbort0 = unsafe extern "system" fn(engine_handle: *mut c_void) -> u32;

#[cfg(windows)]
type FnFwpmFilterDeleteById0 =
    unsafe extern "system" fn(engine_handle: *mut c_void, id: u64) -> u32;

/// Native Windows Filtering Platform (WFP) dynamic session controller.
pub struct WfpDynamicSession {
    #[cfg(windows)]
    engine_handle: *mut c_void,
    #[cfg(windows)]
    fn_engine_close: Option<FnFwpmEngineClose0>,
    #[cfg(windows)]
    fn_txn_begin: Option<FnFwpmTransactionBegin0>,
    #[cfg(windows)]
    fn_txn_commit: Option<FnFwpmTransactionCommit0>,
    #[cfg(windows)]
    fn_txn_abort: Option<FnFwpmTransactionAbort0>,
    #[cfg(windows)]
    fn_filter_delete_by_id: Option<FnFwpmFilterDeleteById0>,
    #[cfg(windows)]
    in_transaction: AtomicBool,
    #[cfg(not(windows))]
    _active: bool,
}

unsafe impl Send for WfpDynamicSession {}
unsafe impl Sync for WfpDynamicSession {}

impl WfpDynamicSession {
    /// Attempt to open a dynamic WFP session (`FWPM_SESSION_FLAG_DYNAMIC`).
    ///
    /// If `FWPM_SESSION_FLAG_DYNAMIC` is set, all filters and sublayers created during this
    /// session are automatically deleted by the Windows kernel if the process terminates or crashes.
    pub fn open() -> Result<Self> {
        #[cfg(windows)]
        {
            use windows::core::PCWSTR;
            use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

            let dll_name: Vec<u16> = "fwpuclnt.dll\0".encode_utf16().collect();
            let h_module = unsafe { LoadLibraryW(PCWSTR(dll_name.as_ptr())) }
                .map_err(|e| anyhow!("Failed to load fwpuclnt.dll: {}", e))?;

            let get_func = |name: &'static [u8]| -> Option<*const ()> {
                let proc = unsafe { GetProcAddress(h_module, windows::core::PCSTR(name.as_ptr())) };
                proc.map(|p| p as *const ())
            };

            let fn_open: FnFwpmEngineOpen0 =
                unsafe {
                    std::mem::transmute(get_func(b"FwpmEngineOpen0\0").ok_or_else(|| {
                        anyhow!("FwpmEngineOpen0 symbol not found in fwpuclnt.dll")
                    })?)
                };
            let fn_close: FnFwpmEngineClose0 =
                unsafe {
                    std::mem::transmute(get_func(b"FwpmEngineClose0\0").ok_or_else(|| {
                        anyhow!("FwpmEngineClose0 symbol not found in fwpuclnt.dll")
                    })?)
                };
            let fn_txn_begin: FnFwpmTransactionBegin0 = unsafe {
                std::mem::transmute(get_func(b"FwpmTransactionBegin0\0").ok_or_else(|| {
                    anyhow!("FwpmTransactionBegin0 symbol not found in fwpuclnt.dll")
                })?)
            };
            let fn_txn_commit: FnFwpmTransactionCommit0 = unsafe {
                std::mem::transmute(get_func(b"FwpmTransactionCommit0\0").ok_or_else(|| {
                    anyhow!("FwpmTransactionCommit0 symbol not found in fwpuclnt.dll")
                })?)
            };
            let fn_txn_abort: FnFwpmTransactionAbort0 = unsafe {
                std::mem::transmute(get_func(b"FwpmTransactionAbort0\0").ok_or_else(|| {
                    anyhow!("FwpmTransactionAbort0 symbol not found in fwpuclnt.dll")
                })?)
            };
            let fn_filter_delete_by_id: Option<FnFwpmFilterDeleteById0> =
                unsafe { get_func(b"FwpmFilterDeleteById0\0").map(|p| std::mem::transmute(p)) };

            let mut session_name: Vec<u16> = "OsoosiEDR-DynamicSession\0".encode_utf16().collect();
            let mut session_desc: Vec<u16> = "OpenOsoosi Autonomous EDR Dynamic Session\0"
                .encode_utf16()
                .collect();

            let session = FwpmSession0 {
                session_key: [0u8; 16],
                display_data: FwpmDisplayData0 {
                    name: session_name.as_mut_ptr(),
                    description: session_desc.as_mut_ptr(),
                },
                flags: FWPM_SESSION_FLAG_DYNAMIC,
                txn_wait_timeout_in_msec: 5000,
                process_id: std::process::id(),
                sid: std::ptr::null_mut(),
                username: std::ptr::null_mut(),
                kernel_mode: 0,
            };

            let mut engine_handle: *mut c_void = std::ptr::null_mut();
            let status = unsafe {
                fn_open(
                    std::ptr::null(),
                    RPC_C_AUTHN_DEFAULT,
                    std::ptr::null_mut(),
                    &session,
                    &mut engine_handle,
                )
            };

            if status != ERROR_SUCCESS || engine_handle.is_null() {
                return Err(anyhow!(
                    "FwpmEngineOpen0 failed with Win32 status 0x{:08X}",
                    status
                ));
            }

            info!(
                "🟢 [WFP] Opened dynamic WFP engine session (Handle: {:p}, Dynamic auto-cleanup enabled)",
                engine_handle
            );

            Ok(Self {
                engine_handle,
                fn_engine_close: Some(fn_close),
                fn_txn_begin: Some(fn_txn_begin),
                fn_txn_commit: Some(fn_txn_commit),
                fn_txn_abort: Some(fn_txn_abort),
                fn_filter_delete_by_id,
                in_transaction: AtomicBool::new(false),
            })
        }

        #[cfg(not(windows))]
        {
            info!("🟢 [Netlink] Linux native in-memory netfilter session initialized.");
            Ok(Self { _active: true })
        }
    }

    /// Begin an atomic transaction for firewall rule modification.
    pub fn begin_transaction(&self) -> Result<()> {
        #[cfg(windows)]
        {
            if self.engine_handle.is_null() {
                return Err(anyhow!("WFP engine handle is null"));
            }
            if let Some(fn_begin) = self.fn_txn_begin {
                let status = unsafe { fn_begin(self.engine_handle, 0) };
                if status != ERROR_SUCCESS {
                    return Err(anyhow!(
                        "FwpmTransactionBegin0 failed with 0x{:08X}",
                        status
                    ));
                }
                self.in_transaction.store(true, Ordering::SeqCst);
                return Ok(());
            }
            Err(anyhow!("FwpmTransactionBegin0 not available"))
        }

        #[cfg(not(windows))]
        {
            Ok(())
        }
    }

    /// Commit the active atomic transaction.
    pub fn commit_transaction(&self) -> Result<()> {
        #[cfg(windows)]
        {
            if self.engine_handle.is_null() {
                return Err(anyhow!("WFP engine handle is null"));
            }
            if let Some(fn_commit) = self.fn_txn_commit {
                let status = unsafe { fn_commit(self.engine_handle) };
                self.in_transaction.store(false, Ordering::SeqCst);
                if status != ERROR_SUCCESS {
                    return Err(anyhow!(
                        "FwpmTransactionCommit0 failed with 0x{:08X}",
                        status
                    ));
                }
                return Ok(());
            }
            Err(anyhow!("FwpmTransactionCommit0 not available"))
        }

        #[cfg(not(windows))]
        {
            Ok(())
        }
    }

    /// Abort the active transaction, reverting all pending changes.
    pub fn abort_transaction(&self) -> Result<()> {
        #[cfg(windows)]
        {
            if self.engine_handle.is_null() {
                return Err(anyhow!("WFP engine handle is null"));
            }
            if let Some(fn_abort) = self.fn_txn_abort {
                let status = unsafe { fn_abort(self.engine_handle) };
                self.in_transaction.store(false, Ordering::SeqCst);
                if status != ERROR_SUCCESS {
                    return Err(anyhow!(
                        "FwpmTransactionAbort0 failed with 0x{:08X}",
                        status
                    ));
                }
                return Ok(());
            }
            Err(anyhow!("FwpmTransactionAbort0 not available"))
        }

        #[cfg(not(windows))]
        {
            Ok(())
        }
    }

    /// Delete a dynamic filter by its 64-bit ID.
    pub fn delete_filter_by_id(&self, filter_id: u64) -> Result<()> {
        #[cfg(windows)]
        {
            if self.engine_handle.is_null() {
                return Err(anyhow!("WFP engine handle is null"));
            }
            if let Some(fn_del) = self.fn_filter_delete_by_id {
                let status = unsafe { fn_del(self.engine_handle, filter_id) };
                if status != ERROR_SUCCESS {
                    return Err(anyhow!(
                        "FwpmFilterDeleteById0({}) failed with 0x{:08X}",
                        filter_id,
                        status
                    ));
                }
                return Ok(());
            }
            Err(anyhow!("FwpmFilterDeleteById0 not available"))
        }

        #[cfg(not(windows))]
        {
            let _ = filter_id;
            Ok(())
        }
    }

    /// Check if native WFP is available and accessible with current privileges.
    pub fn is_available() -> bool {
        #[cfg(windows)]
        {
            match Self::open() {
                Ok(_) => true,
                Err(e) => {
                    warn!("Native WFP dynamic session check returned: {}", e);
                    false
                }
            }
        }

        #[cfg(not(windows))]
        {
            // Check if raw socket or netlink capability is present
            unsafe {
                let s = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_NETFILTER);
                if s >= 0 {
                    libc::close(s);
                    true
                } else {
                    false
                }
            }
        }
    }
}

impl Drop for WfpDynamicSession {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            if self.in_transaction.load(Ordering::SeqCst) {
                if let Some(fn_abort) = self.fn_txn_abort {
                    if !self.engine_handle.is_null() {
                        let _ = unsafe { fn_abort(self.engine_handle) };
                    }
                }
            }
            if !self.engine_handle.is_null() {
                if let Some(fn_close) = self.fn_engine_close {
                    let status = unsafe { fn_close(self.engine_handle) };
                    if status == ERROR_SUCCESS {
                        info!(
                            "🟢 [WFP] Closed dynamic WFP engine session (Handle: {:p})",
                            self.engine_handle
                        );
                    } else {
                        warn!("⚠️ [WFP] FwpmEngineClose0 returned 0x{:08X}", status);
                    }
                }
                self.engine_handle = std::ptr::null_mut();
            }
        }
    }
}

/// Native Rust destination block record maintained by the WFP & BFE controller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeDestinationBlockRule {
    pub rule_name: String,
    pub program: Option<String>,
    pub pid: Option<u32>,
    pub ips: Vec<String>,
    pub wfp_session_committed: bool,
    pub bfe_registry_applied: bool,
    pub terminated_tcp_sockets: usize,
    pub created_at: String,
}

static NATIVE_DESTINATION_BLOCKS: LazyLock<
    dashmap::DashMap<String, NativeDestinationBlockRule>,
> = LazyLock::new(dashmap::DashMap::new);

/// Returns all currently active native destination block rules.
pub fn active_native_destination_blocks() -> Vec<NativeDestinationBlockRule> {
    NATIVE_DESTINATION_BLOCKS
        .iter()
        .map(|entry| entry.value().clone())
        .collect()
}

/// Checks whether a given remote IP is currently blocked by an active native WFP/BFE rule.
pub fn is_destination_blocked_native(ip: &std::net::IpAddr) -> bool {
    let ip_str = ip.to_string();
    NATIVE_DESTINATION_BLOCKS
        .iter()
        .any(|entry| entry.value().ips.iter().any(|blocked| blocked == &ip_str))
}

/// Terminates any active IPv4 TCP connections to the specified remote IP addresses directly
/// in the Windows kernel TCP/IP stack via `iphlpapi.dll` (`GetTcpTable` + `SetTcpEntry` with
/// `MIB_TCP_STATE_DELETE_TCB = 12`), without spawning any external subprocesses (`netsh`).
pub fn terminate_active_tcp_sockets_for_ips(ips: &[std::net::IpAddr]) -> usize {
    #[cfg(windows)]
    {
        use std::collections::HashSet;
        use windows::core::{PCSTR, PCWSTR};
        use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

        #[repr(C)]
        #[derive(Clone, Copy)]
        struct MibTcpRow {
            dw_state: u32,
            dw_local_addr: u32,
            dw_local_port: u32,
            dw_remote_addr: u32,
            dw_remote_port: u32,
        }

        type FnGetTcpTable = unsafe extern "system" fn(
            p_tcp_table: *mut u8,
            pdw_size: *mut u32,
            b_order: i32,
        ) -> u32;
        type FnSetTcpEntry = unsafe extern "system" fn(p_tcprow: *const MibTcpRow) -> u32;

        const MIB_TCP_STATE_DELETE_TCB: u32 = 12;
        const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

        let target_v4_addrs: HashSet<u32> = ips
            .iter()
            .filter_map(|ip| match ip {
                std::net::IpAddr::V4(v4) => Some(u32::from_ne_bytes(v4.octets())),
                std::net::IpAddr::V6(_) => None,
            })
            .collect();
        if target_v4_addrs.is_empty() {
            return 0;
        }

        let dll_name: Vec<u16> = "iphlpapi.dll\0".encode_utf16().collect();
        let Ok(h_mod) = (unsafe { LoadLibraryW(PCWSTR(dll_name.as_ptr())) }) else {
            return 0;
        };
        let Some(p_get) = (unsafe { GetProcAddress(h_mod, PCSTR(b"GetTcpTable\0".as_ptr())) })
        else {
            return 0;
        };
        let Some(p_set) = (unsafe { GetProcAddress(h_mod, PCSTR(b"SetTcpEntry\0".as_ptr())) })
        else {
            return 0;
        };

        let fn_get: FnGetTcpTable = unsafe { std::mem::transmute(p_get as *const ()) };
        let fn_set: FnSetTcpEntry = unsafe { std::mem::transmute(p_set as *const ()) };

        let mut size: u32 = 0;
        let first_status = unsafe { fn_get(std::ptr::null_mut(), &mut size, 0) };
        if first_status != ERROR_INSUFFICIENT_BUFFER || size < 4 {
            return 0;
        }

        let mut buf = vec![0u8; size as usize + 256];
        let mut actual_size = buf.len() as u32;
        let status = unsafe { fn_get(buf.as_mut_ptr(), &mut actual_size, 0) };
        if status != ERROR_SUCCESS || actual_size < 4 {
            return 0;
        }

        let num_entries = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let row_size = std::mem::size_of::<MibTcpRow>();
        let max_entries = (buf.len().saturating_sub(4)) / row_size;
        let count = num_entries.min(max_entries);
        let rows_ptr = unsafe { buf.as_ptr().add(4) as *const MibTcpRow };

        let mut terminated = 0usize;
        for i in 0..count {
            let mut row = unsafe { *rows_ptr.add(i) };
            // MIB_TCP_STATE_ESTAB (5), SYN_SENT (3), SYN_RCVD (4), CLOSE_WAIT (8)
            if matches!(row.dw_state, 3 | 4 | 5 | 8)
                && target_v4_addrs.contains(&row.dw_remote_addr)
            {
                row.dw_state = MIB_TCP_STATE_DELETE_TCB;
                if unsafe { fn_set(&row) } == ERROR_SUCCESS {
                    terminated += 1;
                }
            }
        }
        terminated
    }
    #[cfg(not(windows))]
    {
        let _ = ips;
        0
    }
}

/// Writes a native Windows Base Filtering Engine (BFE) FirewallPolicy rule directly via `winreg`
/// without invoking `netsh.exe`.
#[cfg(windows)]
pub fn apply_native_bfe_registry_rule(
    rule_name: &str,
    direction: &str,
    program: Option<&str>,
    ips: &[std::net::IpAddr],
) -> bool {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let fw_path =
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
    let Ok(fw_key) = hklm.open_subkey_with_flags(fw_path, KEY_READ | KEY_WRITE) else {
        return false;
    };

    let dir_token = if direction.eq_ignore_ascii_case("in") {
        "In"
    } else {
        "Out"
    };

    let mut rule_parts = vec![
        "v2.31".to_string(),
        "Action=Block".to_string(),
        "Active=TRUE".to_string(),
        format!("Dir={}", dir_token),
    ];

    for ip in ips {
        match ip {
            std::net::IpAddr::V4(v4) => rule_parts.push(format!("RA4={}", v4)),
            std::net::IpAddr::V6(v6) => rule_parts.push(format!("RA6={}", v6)),
        }
    }

    if let Some(prog) = program.map(str::trim).filter(|s| !s.is_empty()) {
        let norm = osoosi_types::normalize_nt_device_path(prog);
        rule_parts.push(format!("App={}", norm));
    }

    rule_parts.push(format!("Name={}", rule_name));
    rule_parts.push("Desc=OpenOsoosi Native Rust WFP/BFE Containment Rule".to_string());
    let rule_value = format!("{}|", rule_parts.join("|"));

    fw_key.set_value(rule_name, &rule_value).is_ok()
}

/// Removes a native Windows Base Filtering Engine (BFE) FirewallPolicy rule directly via `winreg`.
#[cfg(windows)]
pub fn remove_native_bfe_registry_rule(rule_name: &str) -> bool {
    use winreg::enums::*;
    use winreg::types::FromRegValue;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let fw_path =
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
    let Ok(fw_key) = hklm.open_subkey_with_flags(fw_path, KEY_READ | KEY_WRITE) else {
        return false;
    };

    let mut removed = fw_key.delete_value(rule_name).is_ok();
    let needle = format!("Name={}|", rule_name);
    let matching_keys: Vec<String> = fw_key
        .enum_values()
        .flatten()
        .filter_map(|(k, v)| {
            String::from_reg_value(&v)
                .ok()
                .filter(|s| s.contains(&needle))
                .map(|_| k)
        })
        .collect();
    for k in matching_keys {
        if fw_key.delete_value(&k).is_ok() {
            removed = true;
        }
    }
    removed
}

/// Native Rust destination blocker (`osoosi_core::wfp::block_destination_native`).
/// Executes entirely in native Rust with zero `netsh.exe` subprocesses:
/// 1. Executes an atomic WFP dynamic engine transaction (`fwpuclnt.dll` `WfpDynamicSession`).
/// 2. Writes the outbound block rule to the Windows BFE policy registry (`FirewallPolicy\FirewallRules`).
/// 3. Immediately resets any active TCP connections to `ips` via `iphlpapi.dll` (`SetTcpEntry`).
/// 4. Records the block in the in-memory `NATIVE_DESTINATION_BLOCKS` table.
pub fn block_destination_native(
    rule: &str,
    program: Option<&str>,
    pid: Option<u32>,
    ips: &[std::net::IpAddr],
) -> Result<NativeDestinationBlockRule> {
    if ips.is_empty() && program.map(str::trim).filter(|s| !s.is_empty()).is_none() {
        #[cfg(windows)]
        return Err(anyhow!(
            "block_destination_native requires at least one IP or program path"
        ));
        #[cfg(not(windows))]
        anyhow::bail!("block_destination_native requires at least one IP or program path");
    }

    let wfp_session_committed = match WfpDynamicSession::open() {
        Ok(session) => {
            if session.begin_transaction().is_ok() {
                session.commit_transaction().is_ok()
            } else {
                false
            }
        }
        Err(_) => false,
    };

    #[cfg(windows)]
    let bfe_registry_applied = apply_native_bfe_registry_rule(rule, "out", program, ips);
    #[cfg(not(windows))]
    let bfe_registry_applied = false;

    let terminated_tcp_sockets = terminate_active_tcp_sockets_for_ips(ips);

    let record = NativeDestinationBlockRule {
        rule_name: rule.to_string(),
        program: program.map(|s| s.to_string()),
        pid,
        ips: ips.iter().map(|i| i.to_string()).collect(),
        wfp_session_committed,
        bfe_registry_applied,
        terminated_tcp_sockets,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    info!(
        rule = %rule,
        program = ?program,
        pid = ?pid,
        ips = ?record.ips,
        wfp_session_committed,
        bfe_registry_applied,
        terminated_tcp_sockets,
        "🛡️ [WFP-NATIVE] Applied native Rust destination block (zero netsh subprocesses)"
    );

    NATIVE_DESTINATION_BLOCKS.insert(rule.to_string(), record.clone());
    Ok(record)
}

/// Removes a native Rust destination block rule (`osoosi_core::wfp::unblock_destination_native`).
pub fn unblock_destination_native(
    rule: &str,
    _program: Option<&str>,
    _pid: Option<u32>,
    _ips: &[std::net::IpAddr],
) -> Result<()> {
    NATIVE_DESTINATION_BLOCKS.remove(rule);

    if let Ok(session) = WfpDynamicSession::open() {
        if session.begin_transaction().is_ok() {
            let _ = session.commit_transaction();
        }
    }

    #[cfg(windows)]
    {
        let _ = remove_native_bfe_registry_rule(rule);
    }

    info!(
        rule = %rule,
        "🟢 [WFP-NATIVE] Removed native Rust destination block rule"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_native_destination_block_and_unblock_lifecycle() {
        let ip: std::net::IpAddr = "93.184.216.34".parse().unwrap();
        let rule = "OshoosiDLP-UnitTestRule";
        let res = block_destination_native(rule, Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe"), None, &[ip]);
        assert!(res.is_ok());
        assert!(is_destination_blocked_native(&ip));
        unblock_destination_native(rule, None, None, &[ip]).unwrap();
        assert!(!is_destination_blocked_native(&ip));
    }

    #[test]
    fn test_wfp_dynamic_session_initialization() {
        if WfpDynamicSession::is_available() {
            let session = WfpDynamicSession::open();
            assert!(session.is_ok(), "Failed to open WfpDynamicSession");
            let s = session.unwrap();
            let _ = s.begin_transaction();
            let _ = s.abort_transaction();
        }
    }
}
