//! Process Token Posture Inspection, Mandatory De-Elevation & Job Object Confinement
//! (`crates/osoosi-sandbox/src/token_posture.rs`).
//!
//! Because `osoosi.exe` (OsoosiEDR) runs with elevated privileges to manage WFP, ETW sensors,
//! and process containment, any native child process spawned on behalf of an agent or tool
//! MUST NOT inherit that elevated token.
//!
//! This module provides:
//! - [`current_token_posture`] / [`TokenPosture::of_process`]: real `GetTokenInformation` inspection
//!   (`TokenElevation`, `TokenIntegrityLevel`, `TokenGroups`, `TokenPrivileges`).
//! - [`create_deelevated_token`]: `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE | LUA_TOKEN)` with
//!   `BUILTIN\Administrators` set to deny-only and the integrity label lowered to Medium.
//! - [`spawn_deelevated`] & [`spawn_deelevated_in_job`]: `CreateProcessAsUserW` in `CREATE_SUSPENDED`
//!   state; the *child's* token is re-inspected **and** `AssignProcessToJobObject` + `IsProcessInJob == TRUE`
//!   are verified **before** `ResumeThread`. If any invariant fails, the suspended process is
//!   terminated immediately (`TerminateProcess`) without `ResumeThread` ever being called.
//! - [`SandboxJobObject`]: RAII Windows Job Object enforcing `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`,
//!   `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`, `JOB_OBJECT_LIMIT_PROCESS_MEMORY`, and kernel I/O accounting
//!   (`QueryInformationJobObject(JobObjectBasicAndIoAccountingInformation = 8)`).

use osoosi_types::OctopusSecurityError;
use serde::{Deserialize, Serialize};

/// Environment marker set (process-scoped only) on a de-elevated relaunch to prevent relaunch loops.
pub const DEELEVATED_ENV_MARKER: &str = "OSOOSI_DEELEVATED";

/// Mandatory integrity RIDs (`S-1-16-<rid>`).
pub const INTEGRITY_UNTRUSTED: u32 = 0x0000;
pub const INTEGRITY_LOW: u32 = 0x1000;
pub const INTEGRITY_MEDIUM: u32 = 0x2000;
pub const INTEGRITY_HIGH: u32 = 0x3000;
pub const INTEGRITY_SYSTEM: u32 = 0x4000;

/// Privileges that, if merely *present* (even disabled) in an agent token, permit a breakout
/// (the holder can call `AdjustTokenPrivileges` to enable them).
pub const DANGEROUS_PRIVILEGES: &[&str] = &[
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeDebugPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeLoadDriverPrivilege",
    "SeImpersonatePrivilege",
    "SeTcbPrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeSecurityPrivilege",
    "SeManageVolumePrivilege",
    "SeCreateTokenPrivilege",
    "SeRelabelPrivilege",
    "SeSystemEnvironmentPrivilege",
];

/// Real, kernel-reported posture of a process token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenPosture {
    /// `TOKEN_ELEVATION.TokenIsElevated != 0`.
    pub elevated: bool,
    /// Mandatory integrity RID (e.g. `0x2000` = Medium, `0x3000` = High).
    pub integrity_rid: u32,
    /// `BUILTIN\Administrators` present with `SE_GROUP_ENABLED`.
    pub admins_enabled: bool,
    /// `BUILTIN\Administrators` present with `SE_GROUP_USE_FOR_DENY_ONLY`.
    pub admins_deny_only: bool,
    /// Every privilege present in the token (enabled or not).
    pub present_privileges: Vec<String>,
    /// Privileges currently enabled.
    pub enabled_privileges: Vec<String>,
}

impl TokenPosture {
    /// Dangerous privileges present in this token.
    pub fn dangerous_privileges_present(&self) -> Vec<String> {
        self.present_privileges
            .iter()
            .filter(|p| DANGEROUS_PRIVILEGES.iter().any(|d| d.eq_ignore_ascii_case(p)))
            .cloned()
            .collect()
    }

    /// Human-readable integrity level label.
    pub fn integrity_label(&self) -> &'static str {
        match self.integrity_rid {
            r if r >= INTEGRITY_SYSTEM => "System",
            r if r >= INTEGRITY_HIGH => "High",
            r if r >= INTEGRITY_MEDIUM => "Medium",
            r if r >= INTEGRITY_LOW => "Low",
            _ => "Untrusted",
        }
    }

    /// Fail-closed predicate used before resuming any agent process.
    /// Returns `Err(reasons)` listing every violated invariant.
    pub fn verify_agent_safe(&self) -> Result<(), Vec<String>> {
        let mut reasons = Vec::new();
        if self.elevated {
            reasons.push("TokenIsElevated != 0".to_string());
        }
        if self.integrity_rid > INTEGRITY_MEDIUM {
            reasons.push(format!(
                "integrity {} (0x{:x}) exceeds Medium",
                self.integrity_label(),
                self.integrity_rid
            ));
        }
        if self.admins_enabled {
            reasons.push("BUILTIN\\Administrators group is enabled".to_string());
        }
        let dangerous = self.dangerous_privileges_present();
        if !dangerous.is_empty() {
            reasons.push(format!("dangerous privileges present: {}", dangerous.join(", ")));
        }
        if reasons.is_empty() {
            Ok(())
        } else {
            Err(reasons)
        }
    }
}

/// Kernel-reported Job Object I/O and process accounting snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobAccountingSnapshot {
    pub total_processes: u32,
    pub active_processes: u32,
    pub total_terminated_processes: u32,
    pub read_operation_count: u64,
    pub write_operation_count: u64,
    pub other_operation_count: u64,
    pub read_transfer_bytes: u64,
    pub write_transfer_bytes: u64,
    pub other_transfer_bytes: u64,
}

#[cfg(windows)]
mod sys {
    use std::ffi::c_void;

    pub type HANDLE = *mut c_void;
    pub type BOOL = i32;
    pub type PSID = *mut c_void;

    pub const TOKEN_ASSIGN_PRIMARY: u32 = 0x0001;
    pub const TOKEN_DUPLICATE: u32 = 0x0002;
    pub const TOKEN_QUERY: u32 = 0x0008;
    pub const TOKEN_ADJUST_DEFAULT: u32 = 0x0080;

    pub const TOKEN_GROUPS_CLASS: u32 = 2;
    pub const TOKEN_PRIVILEGES_CLASS: u32 = 3;
    pub const TOKEN_ELEVATION_CLASS: u32 = 20;
    pub const TOKEN_INTEGRITY_LEVEL_CLASS: u32 = 25;

    pub const SE_GROUP_ENABLED: u32 = 0x0000_0004;
    pub const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x0000_0010;
    pub const SE_GROUP_INTEGRITY: u32 = 0x0000_0020;
    pub const SE_PRIVILEGE_ENABLED: u32 = 0x0000_0002;

    pub const DISABLE_MAX_PRIVILEGE: u32 = 0x1;
    pub const LUA_TOKEN: u32 = 0x4;

    pub const CREATE_SUSPENDED: u32 = 0x0000_0004;
    pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    pub const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;
    pub const INFINITE: u32 = 0xFFFF_FFFF;

    pub const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS: i32 = 9;
    pub const JOB_OBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION_CLASS: i32 = 8;
    pub const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: u32 = 0x0000_0008;
    pub const JOB_OBJECT_LIMIT_PROCESS_MEMORY: u32 = 0x0000_0100;
    pub const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;

    #[repr(C)]
    #[allow(non_snake_case)]
    #[derive(Clone, Copy)]
    pub struct STARTUPINFOW {
        pub cb: u32,
        pub lpReserved: *mut u16,
        pub lpDesktop: *mut u16,
        pub lpTitle: *mut u16,
        pub dwX: u32,
        pub dwY: u32,
        pub dwXSize: u32,
        pub dwYSize: u32,
        pub dwXCountChars: u32,
        pub dwYCountChars: u32,
        pub dwFillAttribute: u32,
        pub dwFlags: u32,
        pub wShowWindow: u16,
        pub cbReserved2: u16,
        pub lpReserved2: *mut u8,
        pub hStdInput: HANDLE,
        pub hStdOutput: HANDLE,
        pub hStdError: HANDLE,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    #[derive(Clone, Copy)]
    pub struct PROCESS_INFORMATION {
        pub hProcess: HANDLE,
        pub hThread: HANDLE,
        pub dwProcessId: u32,
        pub dwThreadId: u32,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    #[derive(Clone, Copy)]
    pub struct SID_AND_ATTRIBUTES {
        pub Sid: PSID,
        pub Attributes: u32,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    pub struct TOKEN_MANDATORY_LABEL {
        pub Label: SID_AND_ATTRIBUTES,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    #[derive(Clone, Copy)]
    pub struct LUID {
        pub LowPart: u32,
        pub HighPart: i32,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    #[derive(Clone, Copy)]
    pub struct LUID_AND_ATTRIBUTES {
        pub Luid: LUID,
        pub Attributes: u32,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    #[derive(Clone, Copy)]
    pub struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        pub PerProcessUserTimeLimit: i64,
        pub PerJobUserTimeLimit: i64,
        pub LimitFlags: u32,
        pub MinimumWorkingSetSize: usize,
        pub MaximumWorkingSetSize: usize,
        pub ActiveProcessLimit: u32,
        pub Affinity: usize,
        pub PriorityClass: u32,
        pub SchedulingClass: u32,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    #[derive(Clone, Copy)]
    pub struct IO_COUNTERS {
        pub ReadOperationCount: u64,
        pub WriteOperationCount: u64,
        pub OtherOperationCount: u64,
        pub ReadTransferCount: u64,
        pub WriteTransferCount: u64,
        pub OtherTransferCount: u64,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    #[derive(Clone, Copy)]
    pub struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        pub BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION,
        pub IoInfo: IO_COUNTERS,
        pub ProcessMemoryLimit: usize,
        pub JobMemoryLimit: usize,
        pub PeakProcessMemoryUsed: usize,
        pub PeakJobMemoryUsed: usize,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    #[derive(Clone, Copy)]
    pub struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION {
        pub TotalUserTime: i64,
        pub TotalKernelTime: i64,
        pub ThisPeriodTotalUserTime: i64,
        pub ThisPeriodTotalKernelTime: i64,
        pub TotalPageFaultCount: u32,
        pub TotalProcesses: u32,
        pub ActiveProcesses: u32,
        pub TotalTerminatedProcesses: u32,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    #[derive(Clone, Copy)]
    pub struct JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION {
        pub BasicInfo: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        pub IoInfo: IO_COUNTERS,
    }

    #[allow(clashing_extern_declarations)]
    #[link(name = "advapi32")]
    extern "system" {
        pub fn OpenProcessToken(
            ProcessHandle: HANDLE,
            DesiredAccess: u32,
            TokenHandle: *mut HANDLE,
        ) -> BOOL;
        pub fn GetTokenInformation(
            TokenHandle: HANDLE,
            TokenInformationClass: u32,
            TokenInformation: *mut c_void,
            TokenInformationLength: u32,
            ReturnLength: *mut u32,
        ) -> BOOL;
        pub fn SetTokenInformation(
            TokenHandle: HANDLE,
            TokenInformationClass: u32,
            TokenInformation: *const c_void,
            TokenInformationLength: u32,
        ) -> BOOL;
        pub fn CreateRestrictedToken(
            ExistingTokenHandle: HANDLE,
            Flags: u32,
            DisableSidCount: u32,
            SidsToDisable: *const c_void,
            DeletePrivilegeCount: u32,
            PrivilegesToDelete: *const c_void,
            RestrictedSidCount: u32,
            SidsToRestrict: *const c_void,
            NewTokenHandle: *mut HANDLE,
        ) -> BOOL;
        pub fn ConvertStringSidToSidW(StringSid: *const u16, Sid: *mut PSID) -> BOOL;
        pub fn EqualSid(pSid1: PSID, pSid2: PSID) -> BOOL;
        pub fn GetLengthSid(pSid: PSID) -> u32;
        pub fn GetSidSubAuthorityCount(pSid: PSID) -> *mut u8;
        pub fn GetSidSubAuthority(pSid: PSID, nSubAuthority: u32) -> *mut u32;
        pub fn LookupPrivilegeNameW(
            lpSystemName: *const u16,
            lpLuid: *const LUID,
            lpName: *mut u16,
            cchName: *mut u32,
        ) -> BOOL;
        pub fn CreateProcessAsUserW(
            hToken: HANDLE,
            lpApplicationName: *const u16,
            lpCommandLine: *mut u16,
            lpProcessAttributes: *const c_void,
            lpThreadAttributes: *const c_void,
            bInheritHandles: BOOL,
            dwCreationFlags: u32,
            lpEnvironment: *const c_void,
            lpCurrentDirectory: *const u16,
            lpStartupInfo: *const STARTUPINFOW,
            lpProcessInformation: *mut PROCESS_INFORMATION,
        ) -> BOOL;
    }

    #[allow(clashing_extern_declarations)]
    #[link(name = "kernel32")]
    extern "system" {
        pub fn GetCurrentProcess() -> HANDLE;
        pub fn CloseHandle(hObject: HANDLE) -> BOOL;
        pub fn LocalFree(hMem: *mut c_void) -> *mut c_void;
        pub fn GetLastError() -> u32;
        pub fn ResumeThread(hThread: HANDLE) -> u32;
        pub fn TerminateProcess(hProcess: HANDLE, uExitCode: u32) -> BOOL;
        pub fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: u32) -> u32;
        pub fn GetExitCodeProcess(hProcess: HANDLE, lpExitCode: *mut u32) -> BOOL;
        pub fn CreateJobObjectW(lpJobAttributes: *const c_void, lpName: *const u16) -> HANDLE;
        pub fn SetInformationJobObject(
            hJob: HANDLE,
            JobObjectInformationClass: i32,
            lpJobObjectInformation: *const c_void,
            cbJobObjectInformationLength: u32,
        ) -> BOOL;
        pub fn QueryInformationJobObject(
            hJob: HANDLE,
            JobObjectInformationClass: i32,
            lpJobObjectInformation: *mut c_void,
            cbJobObjectInformationLength: u32,
            lpReturnLength: *mut u32,
        ) -> BOOL;
        pub fn AssignProcessToJobObject(hJob: HANDLE, hProcess: HANDLE) -> BOOL;
        pub fn IsProcessInJob(ProcessHandle: HANDLE, JobHandle: HANDLE, Result: *mut BOOL) -> BOOL;
    }
}

/// RAII Windows Job Object for Tier 2 child confinement and I/O accounting.
pub struct SandboxJobObject {
    pub name: String,
    pub max_active_processes: u32,
    pub max_memory_bytes: usize,
    #[cfg(windows)]
    handle: sys::HANDLE,
}

unsafe impl Send for SandboxJobObject {}
unsafe impl Sync for SandboxJobObject {}

impl SandboxJobObject {
    pub fn create(
        name: impl Into<String>,
        max_active_processes: u32,
        max_memory_bytes: usize,
    ) -> Result<Self, OctopusSecurityError> {
        let name_str = name.into();
        #[cfg(windows)]
        {
            let h = unsafe { sys::CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if h.is_null() {
                return Err(last_err("CreateJobObjectW"));
            }
            let mut ext: sys::JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            ext.BasicLimitInformation.LimitFlags = sys::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                | sys::JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                | sys::JOB_OBJECT_LIMIT_PROCESS_MEMORY;
            ext.BasicLimitInformation.ActiveProcessLimit = max_active_processes.max(1);
            ext.ProcessMemoryLimit = max_memory_bytes.max(16 * 1024 * 1024);

            let ok = unsafe {
                sys::SetInformationJobObject(
                    h,
                    sys::JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
                    &ext as *const _ as *const std::ffi::c_void,
                    std::mem::size_of::<sys::JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if ok == 0 {
                let err = last_err("SetInformationJobObject");
                unsafe { sys::CloseHandle(h) };
                return Err(err);
            }
            Ok(Self {
                name: name_str,
                max_active_processes,
                max_memory_bytes,
                handle: h,
            })
        }
        #[cfg(not(windows))]
        {
            Ok(Self {
                name: name_str,
                max_active_processes,
                max_memory_bytes,
            })
        }
    }

    /// Queries kernel-reported I/O transfer bytes and process counts via
    /// `QueryInformationJobObject(JobObjectBasicAndIoAccountingInformation = 8)`.
    pub fn query_accounting(&self) -> Result<JobAccountingSnapshot, OctopusSecurityError> {
        #[cfg(windows)]
        {
            let mut info: sys::JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION =
                unsafe { std::mem::zeroed() };
            let mut ret_len: u32 = 0;
            let ok = unsafe {
                sys::QueryInformationJobObject(
                    self.handle,
                    sys::JOB_OBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION_CLASS,
                    &mut info as *mut _ as *mut std::ffi::c_void,
                    std::mem::size_of::<sys::JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION>() as u32,
                    &mut ret_len,
                )
            };
            if ok == 0 {
                return Err(last_err(
                    "QueryInformationJobObject(JobObjectBasicAndIoAccountingInformation)",
                ));
            }
            Ok(JobAccountingSnapshot {
                total_processes: info.BasicInfo.TotalProcesses,
                active_processes: info.BasicInfo.ActiveProcesses,
                total_terminated_processes: info.BasicInfo.TotalTerminatedProcesses,
                read_operation_count: info.IoInfo.ReadOperationCount,
                write_operation_count: info.IoInfo.WriteOperationCount,
                other_operation_count: info.IoInfo.OtherOperationCount,
                read_transfer_bytes: info.IoInfo.ReadTransferCount,
                write_transfer_bytes: info.IoInfo.WriteTransferCount,
                other_transfer_bytes: info.IoInfo.OtherTransferCount,
            })
        }
        #[cfg(not(windows))]
        {
            Ok(JobAccountingSnapshot {
                total_processes: 1,
                active_processes: 0,
                total_terminated_processes: 0,
                read_operation_count: 0,
                write_operation_count: 0,
                other_operation_count: 0,
                read_transfer_bytes: 0,
                write_transfer_bytes: 0,
                other_transfer_bytes: 0,
            })
        }
    }
}

#[cfg(windows)]
impl Drop for SandboxJobObject {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { sys::CloseHandle(self.handle) };
        }
    }
}

/// Owned Win32 handle closed on drop.
#[cfg(windows)]
#[derive(Debug)]
pub struct OwnedToken(sys::HANDLE);

#[cfg(windows)]
unsafe impl Send for OwnedToken {}
#[cfg(windows)]
unsafe impl Sync for OwnedToken {}

#[cfg(windows)]
impl OwnedToken {
    pub fn raw(&self) -> sys::HANDLE {
        self.0
    }
}

#[cfg(windows)]
impl Drop for OwnedToken {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { sys::CloseHandle(self.0) };
        }
    }
}

#[cfg(windows)]
fn last_err(ctx: &str) -> OctopusSecurityError {
    let code = unsafe { sys::GetLastError() };
    OctopusSecurityError::IsolationViolation(format!(
        "FAIL-CLOSED: {} failed (OS Error {})",
        ctx, code
    ))
}

#[cfg(windows)]
struct LocalSid(sys::PSID);

#[cfg(windows)]
impl LocalSid {
    fn from_str(s: &str) -> Result<Self, OctopusSecurityError> {
        let wide: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid: sys::PSID = std::ptr::null_mut();
        let ok = unsafe { sys::ConvertStringSidToSidW(wide.as_ptr(), &mut sid) };
        if ok == 0 || sid.is_null() {
            return Err(last_err(&format!("ConvertStringSidToSidW({})", s)));
        }
        Ok(Self(sid))
    }
}

#[cfg(windows)]
impl Drop for LocalSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { sys::LocalFree(self.0) };
        }
    }
}

#[cfg(windows)]
fn query_token_buffer(token: sys::HANDLE, class: u32) -> Result<Vec<u64>, OctopusSecurityError> {
    let mut needed: u32 = 0;
    unsafe { sys::GetTokenInformation(token, class, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return Err(last_err(&format!(
            "GetTokenInformation(class={}) size probe",
            class
        )));
    }
    let mut buf: Vec<u64> = vec![0u64; (needed as usize + 7) / 8];
    let ok = unsafe {
        sys::GetTokenInformation(
            token,
            class,
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(last_err(&format!("GetTokenInformation(class={})", class)));
    }
    Ok(buf)
}

#[cfg(windows)]
fn sid_integrity_rid(sid: sys::PSID) -> u32 {
    unsafe {
        let count_ptr = sys::GetSidSubAuthorityCount(sid);
        if count_ptr.is_null() || *count_ptr == 0 {
            return INTEGRITY_UNTRUSTED;
        }
        let rid_ptr = sys::GetSidSubAuthority(sid, (*count_ptr - 1) as u32);
        if rid_ptr.is_null() {
            INTEGRITY_UNTRUSTED
        } else {
            *rid_ptr
        }
    }
}

#[cfg(windows)]
fn privilege_name(luid: &sys::LUID) -> String {
    let mut buf = [0u16; 128];
    let mut len: u32 = buf.len() as u32;
    let ok =
        unsafe { sys::LookupPrivilegeNameW(std::ptr::null(), luid, buf.as_mut_ptr(), &mut len) };
    if ok == 0 {
        return format!("LUID({},{})", luid.HighPart, luid.LowPart);
    }
    String::from_utf16_lossy(&buf[..len as usize])
}

#[cfg(windows)]
impl TokenPosture {
    /// Inspects an open token handle (requires `TOKEN_QUERY`).
    pub fn of_token(token: sys::HANDLE) -> Result<Self, OctopusSecurityError> {
        let elev = query_token_buffer(token, sys::TOKEN_ELEVATION_CLASS)?;
        let elevated = (elev[0] as u32) != 0;

        let il = query_token_buffer(token, sys::TOKEN_INTEGRITY_LEVEL_CLASS)?;
        let label = unsafe { &*(il.as_ptr() as *const sys::TOKEN_MANDATORY_LABEL) };
        let integrity_rid = sid_integrity_rid(label.Label.Sid);

        let admins = LocalSid::from_str("S-1-5-32-544")?;
        let groups = query_token_buffer(token, sys::TOKEN_GROUPS_CLASS)?;
        let group_count = unsafe { *(groups.as_ptr() as *const u32) } as usize;
        let groups_ptr = unsafe {
            (groups.as_ptr() as *const u8).add(std::mem::size_of::<usize>())
                as *const sys::SID_AND_ATTRIBUTES
        };
        let mut admins_enabled = false;
        let mut admins_deny_only = false;
        for i in 0..group_count {
            let g = unsafe { *groups_ptr.add(i) };
            if unsafe { sys::EqualSid(g.Sid, admins.0) } != 0 {
                if g.Attributes & sys::SE_GROUP_USE_FOR_DENY_ONLY != 0 {
                    admins_deny_only = true;
                } else if g.Attributes & sys::SE_GROUP_ENABLED != 0 {
                    admins_enabled = true;
                }
            }
        }

        let privs = query_token_buffer(token, sys::TOKEN_PRIVILEGES_CLASS)?;
        let priv_count = unsafe { *(privs.as_ptr() as *const u32) } as usize;
        let priv_ptr =
            unsafe { (privs.as_ptr() as *const u8).add(4) as *const sys::LUID_AND_ATTRIBUTES };
        let mut present_privileges = Vec::with_capacity(priv_count);
        let mut enabled_privileges = Vec::new();
        for i in 0..priv_count {
            let p = unsafe { std::ptr::read_unaligned(priv_ptr.add(i)) };
            let name = privilege_name(&p.Luid);
            if p.Attributes & sys::SE_PRIVILEGE_ENABLED != 0 {
                enabled_privileges.push(name.clone());
            }
            present_privileges.push(name);
        }

        Ok(Self {
            elevated,
            integrity_rid,
            admins_enabled,
            admins_deny_only,
            present_privileges,
            enabled_privileges,
        })
    }

    /// Inspects the primary token of a process handle (requires `PROCESS_QUERY_LIMITED_INFORMATION`).
    pub fn of_process(process: sys::HANDLE) -> Result<Self, OctopusSecurityError> {
        let mut token: sys::HANDLE = std::ptr::null_mut();
        let ok = unsafe { sys::OpenProcessToken(process, sys::TOKEN_QUERY, &mut token) };
        if ok == 0 || token.is_null() {
            return Err(last_err("OpenProcessToken(TOKEN_QUERY)"));
        }
        let owned = OwnedToken(token);
        Self::of_token(owned.raw())
    }
}

/// Real posture of the current process token.
#[cfg(windows)]
pub fn current_token_posture() -> Result<TokenPosture, OctopusSecurityError> {
    TokenPosture::of_process(unsafe { sys::GetCurrentProcess() })
}

#[cfg(not(windows))]
pub fn current_token_posture() -> Result<TokenPosture, OctopusSecurityError> {
    let euid = unsafe { libc::geteuid() };
    Ok(TokenPosture {
        elevated: euid == 0,
        integrity_rid: if euid == 0 {
            INTEGRITY_SYSTEM
        } else {
            INTEGRITY_MEDIUM
        },
        admins_enabled: euid == 0,
        admins_deny_only: false,
        present_privileges: Vec::new(),
        enabled_privileges: Vec::new(),
    })
}

/// Creates a de-elevated primary token derived from the current process token:
/// - `DISABLE_MAX_PRIVILEGE`: deletes every privilege except `SeChangeNotifyPrivilege`.
/// - `LUA_TOKEN`: marks the token as a limited-user (UAC-filtered) token.
/// - `BUILTIN\Administrators` (`S-1-5-32-544`) set to `SE_GROUP_USE_FOR_DENY_ONLY`.
/// - Mandatory integrity label lowered to Medium (`S-1-16-8192`) if currently higher.
#[cfg(windows)]
pub fn create_deelevated_token() -> Result<OwnedToken, OctopusSecurityError> {
    let mut current: sys::HANDLE = std::ptr::null_mut();
    let ok = unsafe {
        sys::OpenProcessToken(
            sys::GetCurrentProcess(),
            sys::TOKEN_DUPLICATE
                | sys::TOKEN_QUERY
                | sys::TOKEN_ASSIGN_PRIMARY
                | sys::TOKEN_ADJUST_DEFAULT,
            &mut current,
        )
    };
    if ok == 0 || current.is_null() {
        return Err(last_err("OpenProcessToken(current)"));
    }
    let current = OwnedToken(current);

    let admins = LocalSid::from_str("S-1-5-32-544")?;
    let disable = [sys::SID_AND_ATTRIBUTES {
        Sid: admins.0,
        Attributes: 0,
    }];

    let mut restricted: sys::HANDLE = std::ptr::null_mut();
    let ok = unsafe {
        sys::CreateRestrictedToken(
            current.raw(),
            sys::DISABLE_MAX_PRIVILEGE | sys::LUA_TOKEN,
            disable.len() as u32,
            disable.as_ptr() as *const std::ffi::c_void,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            &mut restricted,
        )
    };
    if ok == 0 || restricted.is_null() {
        return Err(last_err(
            "CreateRestrictedToken(DISABLE_MAX_PRIVILEGE|LUA_TOKEN)",
        ));
    }
    let restricted = OwnedToken(restricted);

    let posture_before = TokenPosture::of_token(restricted.raw())?;
    if posture_before.integrity_rid > INTEGRITY_MEDIUM {
        let medium = LocalSid::from_str("S-1-16-8192")?;
        let label = sys::TOKEN_MANDATORY_LABEL {
            Label: sys::SID_AND_ATTRIBUTES {
                Sid: medium.0,
                Attributes: sys::SE_GROUP_INTEGRITY,
            },
        };
        let size = std::mem::size_of::<sys::TOKEN_MANDATORY_LABEL>() as u32
            + unsafe { sys::GetLengthSid(medium.0) };
        let ok = unsafe {
            sys::SetTokenInformation(
                restricted.raw(),
                sys::TOKEN_INTEGRITY_LEVEL_CLASS,
                &label as *const _ as *const std::ffi::c_void,
                size,
            )
        };
        if ok == 0 {
            return Err(last_err("SetTokenInformation(TokenIntegrityLevel=Medium)"));
        }
    }

    let posture = TokenPosture::of_token(restricted.raw())?;
    if let Err(reasons) = posture.verify_agent_safe() {
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FAIL-CLOSED: De-elevated token still unsafe: {}",
            reasons.join("; ")
        )));
    }
    Ok(restricted)
}

/// A child process launched under a verified de-elevated token.
#[cfg(windows)]
#[derive(Debug)]
pub struct DeelevatedChild {
    pub pid: u32,
    pub posture: TokenPosture,
    pub is_in_job: bool,
    process: sys::HANDLE,
}

#[cfg(windows)]
unsafe impl Send for DeelevatedChild {}

#[cfg(windows)]
impl DeelevatedChild {
    /// Blocks until the child exits and returns its exit code.
    pub fn wait(&self) -> Result<u32, OctopusSecurityError> {
        unsafe { sys::WaitForSingleObject(self.process, sys::INFINITE) };
        let mut code: u32 = 0;
        if unsafe { sys::GetExitCodeProcess(self.process, &mut code) } == 0 {
            return Err(last_err("GetExitCodeProcess"));
        }
        Ok(code)
    }
}

#[cfg(windows)]
impl Drop for DeelevatedChild {
    fn drop(&mut self) {
        if !self.process.is_null() {
            unsafe { sys::CloseHandle(self.process) };
        }
    }
}

/// Spawns `command_line` under [`create_deelevated_token`] without a custom job handle.
#[cfg(windows)]
pub fn spawn_deelevated(
    command_line: &str,
    hide_window: bool,
) -> Result<DeelevatedChild, OctopusSecurityError> {
    spawn_deelevated_in_job(command_line, hide_window, None)
}

/// Spawns `command_line` under [`create_deelevated_token`] and optionally binds it to a [`SandboxJobObject`].
///
/// FAIL-CLOSED (`RULE[windows_containment_invariants.md]`):
/// 1. Created with `CREATE_SUSPENDED`.
/// 2. Its primary token is inspected via `OpenProcessToken`, and [`TokenPosture::verify_agent_safe`] must pass.
/// 3. If `job` is provided, `AssignProcessToJobObject` and `IsProcessInJob == TRUE` must both succeed.
/// 4. If any check fails, `TerminateProcess` is called immediately before `ResumeThread`.
#[cfg(windows)]
pub fn spawn_deelevated_in_job(
    command_line: &str,
    hide_window: bool,
    job: Option<&SandboxJobObject>,
) -> Result<DeelevatedChild, OctopusSecurityError> {
    let token = create_deelevated_token()?;

    let mut si: sys::STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<sys::STARTUPINFOW>() as u32;
    let mut pi: sys::PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let mut wide_cmd: Vec<u16> = command_line
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut flags = sys::CREATE_SUSPENDED | sys::CREATE_UNICODE_ENVIRONMENT;
    if hide_window {
        flags |= sys::CREATE_NO_WINDOW;
    }

    let ok = unsafe {
        sys::CreateProcessAsUserW(
            token.raw(),
            std::ptr::null(),
            wide_cmd.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            flags,
            std::ptr::null(),
            std::ptr::null(),
            &si,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(last_err("CreateProcessAsUserW(de-elevated, CREATE_SUSPENDED)"));
    }

    let terminate = |reason: String| -> OctopusSecurityError {
        unsafe {
            sys::TerminateProcess(pi.hProcess, 1);
            sys::CloseHandle(pi.hThread);
            sys::CloseHandle(pi.hProcess);
        }
        OctopusSecurityError::IsolationViolation(reason)
    };

    let posture = match TokenPosture::of_process(pi.hProcess) {
        Ok(p) => p,
        Err(e) => {
            return Err(terminate(format!(
                "FAIL-CLOSED: child token inspection failed: {}",
                e
            )))
        }
    };
    if let Err(reasons) = posture.verify_agent_safe() {
        return Err(terminate(format!(
            "FAIL-CLOSED: suspended child token unsafe, terminated before ResumeThread: {}",
            reasons.join("; ")
        )));
    }

    let mut is_in_job = false;
    if let Some(job_obj) = job {
        let assigned = unsafe { sys::AssignProcessToJobObject(job_obj.handle, pi.hProcess) };
        if assigned == 0 {
            let code = unsafe { sys::GetLastError() };
            return Err(terminate(format!(
                "FAIL-CLOSED: AssignProcessToJobObject failed (OS Error {}) before ResumeThread",
                code
            )));
        }
        let mut in_job_flag: sys::BOOL = 0;
        let queried =
            unsafe { sys::IsProcessInJob(pi.hProcess, job_obj.handle, &mut in_job_flag) };
        if queried == 0 || in_job_flag == 0 {
            return Err(terminate(
                "FAIL-CLOSED: IsProcessInJob != TRUE before ResumeThread".to_string(),
            ));
        }
        is_in_job = true;
    }

    if unsafe { sys::ResumeThread(pi.hThread) } == u32::MAX {
        return Err(terminate(
            "FAIL-CLOSED: ResumeThread failed on verified child".to_string(),
        ));
    }
    unsafe { sys::CloseHandle(pi.hThread) };

    Ok(DeelevatedChild {
        pid: pi.dwProcessId,
        posture,
        is_in_job,
        process: pi.hProcess,
    })
}
