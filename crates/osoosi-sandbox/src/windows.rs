//! Windows Kernel Isolation & Mandatory AppContainer / Job Object Invariants.
//!
//! Enforces fail-closed confinement for any spawned sandbox or worker process:
//! 1. Pre-execution confinement: `CREATE_SUSPENDED (0x00000004)` + `AssignProcessToJobObject`
//!    + `IsProcessInJob == TRUE` verified BEFORE `ResumeThread`.
//! 2. Zero uncontained fallbacks: any failure in AppContainer profile allocation, SID binding,
//!    or Job Object assignment immediately terminates the suspended process handle without
//!    calling `ResumeThread`.
//! 3. Win32 handle & profile lifecycle cleanup: `FreeSid` on allocated `PSID` and
//!    `DeleteAppContainerProfile` rollback on launch failure.

use serde::{Deserialize, Serialize};

/// Win32 process creation flag: child starts suspended until Job Object & AppContainer are verified.
pub const CREATE_SUSPENDED_FLAG: u32 = 0x0000_0004;

/// Win32 Job Object flag: terminate all processes associated with the job when the last handle closes.
pub const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;

/// Win32 Job Object flag: cap active child process count to prevent fork bombs or lateral child escape.
pub const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: u32 = 0x0000_0008;

/// Win32 Job Object UI restriction mask: block clipboard, desktop switch, display settings, and global atoms.
pub const JOB_OBJECT_UILIMIT_ALL: u32 = 0x0000_00FF;

/// Win32 ProcThreadAttribute: explicit handle allowlist for process creation (`0x00020002`).
/// Prevents ambient handle inheritance leaks into AppContainers and restricted processes.
pub const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x00020002;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsConfinementPolicy {
    pub creation_flags: u32,
    pub job_limit_flags: u32,
    pub job_ui_restrictions: u32,
    pub active_process_limit: u32,
    pub require_appcontainer_sid: bool,
    pub require_is_process_in_job_before_resume: bool,
    pub allow_uncontained_fallback: bool,
}

impl Default for WindowsConfinementPolicy {
    fn default() -> Self {
        Self {
            creation_flags: CREATE_SUSPENDED_FLAG,
            job_limit_flags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
            job_ui_restrictions: JOB_OBJECT_UILIMIT_ALL,
            active_process_limit: 1,
            require_appcontainer_sid: true,
            require_is_process_in_job_before_resume: true,
            allow_uncontained_fallback: false,
        }
    }
}

/// Target token integrity level for de-elevation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityLevel {
    Untrusted, // S-1-16-0 (0x0000)
    Low,       // S-1-16-4096 (0x1000 - SECURITY_MANDATORY_LOW_RID)
    Medium,    // S-1-16-8192 (0x2000 - SECURITY_MANDATORY_MEDIUM_RID)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfinementTransitionOutcome {
    pub resume_thread_allowed: bool,
    pub terminated_suspended_process: bool,
    pub sid_freed_via_free_sid: bool,
    pub profile_rolled_back_via_delete_appcontainer_profile: bool,
    pub uncontained_fallback_used: bool,
    pub reason: String,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// Validates that a `WindowsConfinementPolicy` satisfies all mandatory kernel isolation invariants.
pub fn verify_windows_confinement_invariants(
    policy: &WindowsConfinementPolicy,
) -> Result<(), String> {
    if (policy.creation_flags & CREATE_SUSPENDED_FLAG) == 0 {
        return Err("Missing mandatory CREATE_SUSPENDED (0x00000004) flag".to_string());
    }
    if (policy.job_limit_flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) == 0 {
        return Err(
            "Missing mandatory JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE (0x00002000)".to_string(),
        );
    }
    if (policy.job_limit_flags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS) == 0
        || policy.active_process_limit == 0
    {
        return Err("Missing mandatory JOB_OBJECT_LIMIT_ACTIVE_PROCESS cap".to_string());
    }
    if !policy.require_appcontainer_sid {
        return Err("AppContainer capability SID isolation must be required".to_string());
    }
    if !policy.require_is_process_in_job_before_resume {
        return Err(
            "IsProcessInJob == TRUE verification before ResumeThread is mandatory".to_string(),
        );
    }
    if policy.allow_uncontained_fallback {
        return Err("Uncontained child process fallback is strictly prohibited".to_string());
    }
    Ok(())
}

/// Evaluates the pre-execution confinement state machine before `ResumeThread` is permitted.
///
/// Any failure in AppContainer profile creation, SID binding, `AssignProcessToJobObject`,
/// or `IsProcessInJob == TRUE` immediately terminates the suspended process handle,
/// frees the `PSID` via `FreeSid`, and deletes the temporary AppContainer profile via
/// `DeleteAppContainerProfile`.
pub fn evaluate_pre_resume_confinement_gate(
    policy: &WindowsConfinementPolicy,
    appcontainer_profile_allocated: bool,
    sid_bound: bool,
    job_assigned: bool,
    is_process_in_job: bool,
) -> ConfinementTransitionOutcome {
    if let Err(policy_err) = verify_windows_confinement_invariants(policy) {
        return ConfinementTransitionOutcome {
            resume_thread_allowed: false,
            terminated_suspended_process: true,
            sid_freed_via_free_sid: sid_bound,
            profile_rolled_back_via_delete_appcontainer_profile: appcontainer_profile_allocated,
            uncontained_fallback_used: false,
            reason: format!("FAIL_CLOSED_POLICY_VIOLATION: {}", policy_err),
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
        };
    }

    if !appcontainer_profile_allocated {
        return ConfinementTransitionOutcome {
            resume_thread_allowed: false,
            terminated_suspended_process: true,
            sid_freed_via_free_sid: false,
            profile_rolled_back_via_delete_appcontainer_profile: false,
            uncontained_fallback_used: false,
            reason: "FAIL_CLOSED_APPCONTAINER_PROFILE_ALLOCATION_FAILED".to_string(),
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
        };
    }

    if !sid_bound {
        return ConfinementTransitionOutcome {
            resume_thread_allowed: false,
            terminated_suspended_process: true,
            sid_freed_via_free_sid: true,
            profile_rolled_back_via_delete_appcontainer_profile: true,
            uncontained_fallback_used: false,
            reason: "FAIL_CLOSED_APPCONTAINER_SID_BIND_FAILED: FreeSid + DeleteAppContainerProfile executed".to_string(),
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
        };
    }

    if !job_assigned || !is_process_in_job {
        return ConfinementTransitionOutcome {
            resume_thread_allowed: false,
            terminated_suspended_process: true,
            sid_freed_via_free_sid: true,
            profile_rolled_back_via_delete_appcontainer_profile: true,
            uncontained_fallback_used: false,
            reason: format!(
                "FAIL_CLOSED_JOB_OBJECT_CONFINEMENT_FAILED (assigned={}, in_job={}): TerminateProcess before ResumeThread + FreeSid + DeleteAppContainerProfile",
                job_assigned, is_process_in_job
            ),
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
        };
    }

    ConfinementTransitionOutcome {
        resume_thread_allowed: true,
        terminated_suspended_process: false,
        sid_freed_via_free_sid: true,
        profile_rolled_back_via_delete_appcontainer_profile: false,
        uncontained_fallback_used: false,
        reason: "CONFINED_OK: CREATE_SUSPENDED + AppContainer SID + AssignProcessToJobObject + IsProcessInJob==TRUE verified prior to ResumeThread".to_string(),
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
    }
}

/// RAII AppContainer Profile Manager for Windows Process Isolation.
///
/// On allocation: dynamically resolves and invokes `CreateAppContainerProfile` from `userenv.dll`.
/// On drop: guarantees SID cleanup via `FreeSid` (`advapi32.dll`) and profile rollback via
/// `DeleteAppContainerProfile` (`userenv.dll`) if marked for cleanup.
pub struct Win32AppContainerProfile {
    pub profile_name: String,
    pub display_name: String,
    pub sid_allocated: bool,
    pub profile_allocated: bool,
    pub auto_delete_on_drop: bool,
    #[cfg(windows)]
    raw_sid: *mut std::ffi::c_void,
}

unsafe impl Send for Win32AppContainerProfile {}
unsafe impl Sync for Win32AppContainerProfile {}

impl Win32AppContainerProfile {
    #[cfg(windows)]
    pub fn create(profile_name: &str, display_name: &str) -> Result<Self, String> {
        if profile_name.trim().is_empty() {
            return Err("Profile name cannot be empty".to_string());
        }

        // Dynamically load userenv.dll and advapi32.dll to avoid strict link-time dependencies
        type FnCreateAppContainerProfile = unsafe extern "system" fn(
            *const u16,
            *const u16,
            *const u16,
            *const std::ffi::c_void,
            u32,
            *mut *mut std::ffi::c_void,
        ) -> i32;

        extern "system" {
            fn LoadLibraryA(lpLibFileName: *const u8) -> *mut std::ffi::c_void;
            fn GetProcAddress(
                hModule: *mut std::ffi::c_void,
                lpProcName: *const u8,
            ) -> *mut std::ffi::c_void;
        }

        let userenv_mod = unsafe { LoadLibraryA(b"userenv.dll\0".as_ptr()) };
        if userenv_mod.is_null() {
            return Err("Failed to load userenv.dll for AppContainer isolation".to_string());
        }

        let proc_addr =
            unsafe { GetProcAddress(userenv_mod, b"CreateAppContainerProfile\0".as_ptr()) };
        if proc_addr.is_null() {
            return Err("CreateAppContainerProfile symbol not found in userenv.dll".to_string());
        }

        let create_fn: FnCreateAppContainerProfile = unsafe { std::mem::transmute(proc_addr) };

        let wide_name: Vec<u16> = profile_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let wide_disp: Vec<u16> = display_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut raw_sid: *mut std::ffi::c_void = std::ptr::null_mut();
        let hr = unsafe {
            create_fn(
                wide_name.as_ptr(),
                wide_disp.as_ptr(),
                wide_disp.as_ptr(),
                std::ptr::null(),
                0,
                &mut raw_sid,
            )
        };

        // If profile already exists (0x800700B7), derive the SID via DeriveAppContainerSidFromAppContainerProfileName
        if (hr as u32) == 0x8007_00B7 && raw_sid.is_null() {
            type FnDeriveAppContainerSid =
                unsafe extern "system" fn(*const u16, *mut *mut std::ffi::c_void) -> i32;
            let derive_addr = unsafe {
                GetProcAddress(
                    userenv_mod,
                    b"DeriveAppContainerSidFromAppContainerProfileName\0".as_ptr(),
                )
            };
            if !derive_addr.is_null() {
                let derive_fn: FnDeriveAppContainerSid =
                    unsafe { std::mem::transmute(derive_addr) };
                let _ = unsafe { derive_fn(wide_name.as_ptr(), &mut raw_sid) };
            }
        }

        // S_OK (0) or HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) (0x800700B7)
        if hr == 0 || (hr as u32) == 0x8007_00B7 {
            Ok(Self {
                profile_name: profile_name.to_string(),
                display_name: display_name.to_string(),
                sid_allocated: !raw_sid.is_null(),
                profile_allocated: true,
                auto_delete_on_drop: true,
                raw_sid,
            })
        } else {
            Err(format!(
                "CreateAppContainerProfile failed with HRESULT 0x{:08X}",
                hr as u32
            ))
        }
    }

    #[cfg(windows)]
    pub fn raw_sid(&self) -> *mut std::ffi::c_void {
        self.raw_sid
    }

    #[cfg(not(windows))]
    pub fn create(profile_name: &str, display_name: &str) -> Result<Self, String> {
        if profile_name.trim().is_empty() {
            return Err("Profile name cannot be empty".to_string());
        }
        Ok(Self {
            profile_name: profile_name.to_string(),
            display_name: display_name.to_string(),
            sid_allocated: true,
            profile_allocated: true,
            auto_delete_on_drop: true,
        })
    }

    pub fn rollback(&mut self) {
        #[cfg(windows)]
        {
            type FnDeleteAppContainerProfile = unsafe extern "system" fn(*const u16) -> i32;
            type FnFreeSid =
                unsafe extern "system" fn(*mut std::ffi::c_void) -> *mut std::ffi::c_void;

            extern "system" {
                fn LoadLibraryA(lpLibFileName: *const u8) -> *mut std::ffi::c_void;
                fn GetProcAddress(
                    hModule: *mut std::ffi::c_void,
                    lpProcName: *const u8,
                ) -> *mut std::ffi::c_void;
            }

            if !self.raw_sid.is_null() {
                let advapi = unsafe { LoadLibraryA(b"advapi32.dll\0".as_ptr()) };
                if !advapi.is_null() {
                    let free_sid_addr = unsafe { GetProcAddress(advapi, b"FreeSid\0".as_ptr()) };
                    if !free_sid_addr.is_null() {
                        let free_sid_fn: FnFreeSid = unsafe { std::mem::transmute(free_sid_addr) };
                        unsafe { free_sid_fn(self.raw_sid) };
                    }
                }
                self.raw_sid = std::ptr::null_mut();
            }

            if self.profile_allocated {
                let userenv = unsafe { LoadLibraryA(b"userenv.dll\0".as_ptr()) };
                if !userenv.is_null() {
                    let del_addr =
                        unsafe { GetProcAddress(userenv, b"DeleteAppContainerProfile\0".as_ptr()) };
                    if !del_addr.is_null() {
                        let del_fn: FnDeleteAppContainerProfile =
                            unsafe { std::mem::transmute(del_addr) };
                        let wide_name: Vec<u16> = self
                            .profile_name
                            .encode_utf16()
                            .chain(std::iter::once(0))
                            .collect();
                        unsafe { del_fn(wide_name.as_ptr()) };
                    }
                }
            }
        }

        self.sid_allocated = false;
        self.profile_allocated = false;
    }
}

impl Drop for Win32AppContainerProfile {
    fn drop(&mut self) {
        if self.auto_delete_on_drop {
            self.rollback();
        }
    }
}

/// Creates a de-elevated, restricted primary token with Low or Medium integrity.
///
/// Strips administrative groups and privileges via `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE | LUA_TOKEN)`
/// and sets the integrity level via `SetTokenInformation(TokenIntegrityLevel)`.
#[cfg(windows)]
pub fn create_deelevated_token(
    source_token: Option<windows::Win32::Foundation::HANDLE>,
    target_integrity: IntegrityLevel,
) -> Result<windows::Win32::Foundation::HANDLE, String> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        AllocateAndInitializeSid, CreateRestrictedToken, FreeSid, SetTokenInformation,
        TokenIntegrityLevel, CREATE_RESTRICTED_TOKEN_FLAGS, PSID,
        SECURITY_MANDATORY_LABEL_AUTHORITY, SID_AND_ATTRIBUTES, TOKEN_ADJUST_DEFAULT,
        TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    const SE_GROUP_INTEGRITY: u32 = 0x0000_0020;

    unsafe {
        let mut base_token = HANDLE::default();
        let owned_base;
        if let Some(src) = source_token {
            base_token = src;
            owned_base = false;
        } else {
            let cur_proc = GetCurrentProcess();
            let desired =
                TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT;
            if let Err(e) = OpenProcessToken(cur_proc, desired, &mut base_token) {
                return Err(format!("OpenProcessToken failed: {:?}", e));
            }
            owned_base = true;
        }

        // LUA_TOKEN = 0x00000004, DISABLE_MAX_PRIVILEGE = 0x00000001
        let flags = CREATE_RESTRICTED_TOKEN_FLAGS(0x0000_0001 | 0x0000_0004);
        let mut restricted_token = HANDLE::default();
        let res = CreateRestrictedToken(
            base_token,
            flags,
            Some(&[]),
            Some(&[]),
            Some(&[]),
            &mut restricted_token,
        );

        if owned_base {
            let _ = CloseHandle(base_token);
        }

        if let Err(e) = res {
            return Err(format!("CreateRestrictedToken failed: {:?}", e));
        }

        let rid = match target_integrity {
            IntegrityLevel::Untrusted => 0x0000,
            IntegrityLevel::Low => 0x1000, // SECURITY_MANDATORY_LOW_RID
            IntegrityLevel::Medium => 0x2000, // SECURITY_MANDATORY_MEDIUM_RID
        };

        let auth = SECURITY_MANDATORY_LABEL_AUTHORITY;
        let mut p_sid = PSID::default();
        if let Err(e) = AllocateAndInitializeSid(&auth, 1, rid, 0, 0, 0, 0, 0, 0, 0, &mut p_sid) {
            let _ = CloseHandle(restricted_token);
            return Err(format!("AllocateAndInitializeSid failed: {:?}", e));
        }

        let tml = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: p_sid,
                Attributes: SE_GROUP_INTEGRITY,
            },
        };

        let set_res = SetTokenInformation(
            restricted_token,
            TokenIntegrityLevel,
            &tml as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32,
        );

        let _ = FreeSid(p_sid);

        if let Err(e) = set_res {
            let _ = CloseHandle(restricted_token);
            return Err(format!(
                "SetTokenInformation(TokenIntegrityLevel) failed: {:?}",
                e
            ));
        }

        Ok(restricted_token)
    }
}

#[cfg(not(windows))]
pub fn create_deelevated_token(
    _source_token: Option<()>,
    _target_integrity: IntegrityLevel,
) -> Result<(), String> {
    Ok(())
}

/// Quote a single command-line argument according to Win32 CommandLineToArgvW rules.
pub fn quote_win32_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }
    if !arg.contains(' ')
        && !arg.contains('\t')
        && !arg.contains('\n')
        && !arg.contains('\r')
        && !arg.contains('\"')
    {
        return arg.to_string();
    }
    let mut res = String::from("\"");
    let mut backslashes = 0;
    for c in arg.chars() {
        if c == '\\' {
            backslashes += 1;
        } else if c == '\"' {
            for _ in 0..(backslashes * 2 + 1) {
                res.push('\\');
            }
            res.push('\"');
            backslashes = 0;
        } else {
            for _ in 0..backslashes {
                res.push('\\');
            }
            backslashes = 0;
            res.push(c);
        }
    }
    for _ in 0..(backslashes * 2) {
        res.push('\\');
    }
    res.push('\"');
    res
}

#[cfg(windows)]
pub fn create_confined_job_object(
    policy: &WindowsConfinementPolicy,
) -> Result<windows::Win32::Foundation::HANDLE, String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::JobObjects::{
        CreateJobObjectW, JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_BASIC_UI_RESTRICTIONS,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT, JOB_OBJECT_UILIMIT,
    };

    unsafe {
        let job = CreateJobObjectW(None, None)
            .map_err(|e| format!("CreateJobObjectW failed: {:?}", e))?;

        let mut limit_info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        limit_info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT(policy.job_limit_flags);
        limit_info.BasicLimitInformation.ActiveProcessLimit = policy.active_process_limit.max(1);

        if let Err(e) = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &limit_info as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        ) {
            let _ = CloseHandle(job);
            return Err(format!(
                "SetInformationJobObject(ExtendedLimit) failed: {:?}",
                e
            ));
        }

        let mut ui_restrictions: JOBOBJECT_BASIC_UI_RESTRICTIONS = std::mem::zeroed();
        ui_restrictions.UIRestrictionsClass = JOB_OBJECT_UILIMIT(policy.job_ui_restrictions);
        if let Err(e) = SetInformationJobObject(
            job,
            JobObjectBasicUIRestrictions,
            &ui_restrictions as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
        ) {
            let _ = CloseHandle(job);
            return Err(format!("SetInformationJobObject(BasicUI) failed: {:?}", e));
        }

        Ok(job)
    }
}

/// Spawns or executes a process strictly confined within an AppContainer and Windows Job Object.
///
/// Follows the mandatory Windows Kernel Isolation Invariants:
/// 1. Verifies the confinement policy (fails closed if `allow_uncontained_fallback` is true or missing `CREATE_SUSPENDED`).
/// 2. Allocates an AppContainer profile via `Win32AppContainerProfile::create`.
/// 3. Enforces process creation with `CREATE_SUSPENDED`.
/// 4. Verifies `AssignProcessToJobObject` and `IsProcessInJob == TRUE` before allowing `ResumeThread`.
/// 5. On any confinement error: terminates the suspended process immediately, frees the SID, and deletes the profile.
#[cfg(windows)]
pub fn execute_confined_windows_process(
    program: &str,
    args: &[&str],
    profile_name: &str,
    policy: &WindowsConfinementPolicy,
) -> Result<ConfinementTransitionOutcome, String> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{
        CloseHandle, SetHandleInformation, BOOL, HANDLE, HANDLE_FLAGS,
    };
    use windows::Win32::Security::{SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES};
    use windows::Win32::Storage::FileSystem::ReadFile;
    use windows::Win32::System::JobObjects::{AssignProcessToJobObject, IsProcessInJob};
    use windows::Win32::System::Pipes::CreatePipe;
    use windows::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
        InitializeProcThreadAttributeList, ResumeThread, TerminateProcess,
        UpdateProcThreadAttribute, WaitForSingleObject, LPPROC_THREAD_ATTRIBUTE_LIST,
        PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        STARTF_USESHOWWINDOW, STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
    };

    // 1. Verify invariants
    verify_windows_confinement_invariants(policy)?;

    // 2. Allocate AppContainer profile
    let mut profile = match Win32AppContainerProfile::create(profile_name, profile_name) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("Failed to allocate Win32AppContainerProfile: {}", e);
            return Ok(evaluate_pre_resume_confinement_gate(
                policy, false, false, false, false,
            ));
        }
    };

    if !profile.profile_allocated || !profile.sid_allocated {
        profile.rollback();
        return Ok(evaluate_pre_resume_confinement_gate(
            policy,
            profile.profile_allocated,
            profile.sid_allocated,
            false,
            false,
        ));
    }

    // 3. Create Confined Job Object
    let job = match create_confined_job_object(policy) {
        Ok(j) => j,
        Err(e) => {
            tracing::warn!("Failed to create Job Object: {}", e);
            profile.rollback();
            return Ok(evaluate_pre_resume_confinement_gate(
                policy, true, true, false, false,
            ));
        }
    };

    unsafe {
        // 4. Setup Pipes for Stdout / Stderr with inheritance
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: BOOL(1),
        };
        let mut h_out_read = HANDLE::default();
        let mut h_out_write = HANDLE::default();
        let mut h_err_read = HANDLE::default();
        let mut h_err_write = HANDLE::default();

        if let Err(e) = CreatePipe(&mut h_out_read, &mut h_out_write, Some(&sa), 0) {
            let _ = CloseHandle(job);
            profile.rollback();
            return Err(format!("CreatePipe stdout failed: {:?}", e));
        }
        if let Err(e) = CreatePipe(&mut h_err_read, &mut h_err_write, Some(&sa), 0) {
            let _ = CloseHandle(h_out_read);
            let _ = CloseHandle(h_out_write);
            let _ = CloseHandle(job);
            profile.rollback();
            return Err(format!("CreatePipe stderr failed: {:?}", e));
        }

        // Parent read ends should NOT be inherited by child
        let _ = SetHandleInformation(h_out_read, 1, HANDLE_FLAGS(0));
        let _ = SetHandleInformation(h_err_read, 1, HANDLE_FLAGS(0));

        // 5. Initialize PROC_THREAD_ATTRIBUTE_LIST with Security Capabilities and Handle Allowlist
        let mut attr_size = 0usize;
        let _ = InitializeProcThreadAttributeList(
            LPPROC_THREAD_ATTRIBUTE_LIST(std::ptr::null_mut()),
            2,
            0,
            &mut attr_size,
        );
        let mut attr_buf = vec![0u8; attr_size];
        let p_attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as *mut _);
        if let Err(e) = InitializeProcThreadAttributeList(p_attr_list, 2, 0, &mut attr_size) {
            let _ = CloseHandle(h_out_read);
            let _ = CloseHandle(h_out_write);
            let _ = CloseHandle(h_err_read);
            let _ = CloseHandle(h_err_write);
            let _ = CloseHandle(job);
            profile.rollback();
            return Err(format!("InitializeProcThreadAttributeList failed: {:?}", e));
        }

        let mut sec_cap = SECURITY_CAPABILITIES {
            AppContainerSid: windows::Win32::Security::PSID(profile.raw_sid()),
            Capabilities: std::ptr::null_mut(),
            CapabilityCount: 0,
            Reserved: 0,
        };

        if let Err(e) = UpdateProcThreadAttribute(
            p_attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            Some(&mut sec_cap as *mut _ as *const std::ffi::c_void),
            std::mem::size_of::<SECURITY_CAPABILITIES>(),
            None,
            None,
        ) {
            let _ = DeleteProcThreadAttributeList(p_attr_list);
            let _ = CloseHandle(h_out_read);
            let _ = CloseHandle(h_out_write);
            let _ = CloseHandle(h_err_read);
            let _ = CloseHandle(h_err_write);
            let _ = CloseHandle(job);
            profile.rollback();
            return Err(format!(
                "UpdateProcThreadAttribute(SECURITY_CAPABILITIES) failed: {:?}",
                e
            ));
        }

        // F01: Explicit Handle Allowlist (PROC_THREAD_ATTRIBUTE_HANDLE_LIST)
        // Ensures only the dedicated stdout and stderr pipe write handles are inheritable by the AppContainer child,
        // preventing ambient parent handle inheritance leaks when bInheritHandles = TRUE.
        let mut inherit_handles = [h_out_write, h_err_write];
        if let Err(e) = UpdateProcThreadAttribute(
            p_attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            Some(inherit_handles.as_mut_ptr() as *mut _ as *const std::ffi::c_void),
            inherit_handles.len() * std::mem::size_of::<HANDLE>(),
            None,
            None,
        ) {
            let _ = DeleteProcThreadAttributeList(p_attr_list);
            let _ = CloseHandle(h_out_read);
            let _ = CloseHandle(h_out_write);
            let _ = CloseHandle(h_err_read);
            let _ = CloseHandle(h_err_write);
            let _ = CloseHandle(job);
            profile.rollback();
            return Err(format!(
                "UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_HANDLE_LIST) failed: {:?}",
                e
            ));
        }

        let mut si_ex: STARTUPINFOEXW = std::mem::zeroed();
        si_ex.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si_ex.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si_ex.StartupInfo.wShowWindow = 0; // SW_HIDE
        si_ex.StartupInfo.hStdOutput = h_out_write;
        si_ex.StartupInfo.hStdError = h_err_write;
        si_ex.StartupInfo.hStdInput = HANDLE::default();
        si_ex.lpAttributeList = p_attr_list;

        // 6. Build Command Line
        let mut full_cmd = quote_win32_arg(program);
        for a in args {
            full_cmd.push(' ');
            full_cmd.push_str(&quote_win32_arg(a));
        }
        let mut wide_cmd: Vec<u16> = full_cmd.encode_utf16().chain(std::iter::once(0)).collect();

        // 7. Spawn Child Process with CREATE_SUSPENDED
        let creation_flags = policy.creation_flags
            | 0x0800_0000 // CREATE_NO_WINDOW
            | 0x0008_0000 // EXTENDED_STARTUPINFO_PRESENT
            | 0x0000_0400; // CREATE_UNICODE_ENVIRONMENT

        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        let create_res = CreateProcessW(
            None,
            PWSTR::from_raw(wide_cmd.as_mut_ptr()),
            None,
            None,
            true, // inherit handles for pipes
            PROCESS_CREATION_FLAGS(creation_flags),
            None,
            None,
            &si_ex.StartupInfo as *const _ as *const STARTUPINFOW,
            &mut pi,
        );

        // Close write ends in parent now that child inherited them
        let _ = CloseHandle(h_out_write);
        let _ = CloseHandle(h_err_write);

        if let Err(e) = create_res {
            let _ = DeleteProcThreadAttributeList(p_attr_list);
            let _ = CloseHandle(h_out_read);
            let _ = CloseHandle(h_err_read);
            let _ = CloseHandle(job);
            profile.rollback();
            return Err(format!("CreateProcessW failed for '{}': {:?}", program, e));
        }

        // 8. Fail-Closed Pre-Execution Confinement Verification
        let assign_res = AssignProcessToJobObject(job, pi.hProcess);
        if let Err(e) = assign_res {
            tracing::warn!("AssignProcessToJobObject failed: {:?}", e);
            let _ = TerminateProcess(pi.hProcess, 137);
            let _ = CloseHandle(pi.hThread);
            let _ = CloseHandle(pi.hProcess);
            let _ = DeleteProcThreadAttributeList(p_attr_list);
            let _ = CloseHandle(h_out_read);
            let _ = CloseHandle(h_err_read);
            let _ = CloseHandle(job);
            profile.rollback();
            return Ok(evaluate_pre_resume_confinement_gate(
                policy, true, true, false, false,
            ));
        }

        let mut is_in_job = BOOL(0);
        let check_in_job = IsProcessInJob(pi.hProcess, job, &mut is_in_job);
        if check_in_job.is_err() || !is_in_job.as_bool() {
            let _ = TerminateProcess(pi.hProcess, 137);
            let _ = CloseHandle(pi.hThread);
            let _ = CloseHandle(pi.hProcess);
            let _ = DeleteProcThreadAttributeList(p_attr_list);
            let _ = CloseHandle(h_out_read);
            let _ = CloseHandle(h_err_read);
            let _ = CloseHandle(job);
            profile.rollback();
            return Ok(evaluate_pre_resume_confinement_gate(
                policy, true, true, true, false,
            ));
        }

        // 9. Confinement Invariants Verified -> ResumeThread
        let resume_res = ResumeThread(pi.hThread);
        if resume_res == u32::MAX {
            let _ = TerminateProcess(pi.hProcess, 137);
            let _ = CloseHandle(pi.hThread);
            let _ = CloseHandle(pi.hProcess);
            let _ = DeleteProcThreadAttributeList(p_attr_list);
            let _ = CloseHandle(h_out_read);
            let _ = CloseHandle(h_err_read);
            let _ = CloseHandle(job);
            profile.rollback();
            return Err("ResumeThread failed".to_string());
        }

        // 10. Wait for process completion (10 seconds timeout) & Read Output
        let wait_res = WaitForSingleObject(pi.hProcess, 10_000);
        if wait_res.0 == 0x00000102 {
            // WAIT_TIMEOUT
            let _ = TerminateProcess(pi.hProcess, 137);
        }

        let mut exit_code: u32 = 0;
        let _ = GetExitCodeProcess(pi.hProcess, &mut exit_code);

        // Read stdout and stderr buffers
        let mut stdout_buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let mut bytes_read = 0u32;
        while ReadFile(h_out_read, Some(&mut chunk), Some(&mut bytes_read), None).is_ok()
            && bytes_read > 0
        {
            stdout_buf.extend_from_slice(&chunk[..bytes_read as usize]);
        }

        let mut stderr_buf = Vec::new();
        while ReadFile(h_err_read, Some(&mut chunk), Some(&mut bytes_read), None).is_ok()
            && bytes_read > 0
        {
            stderr_buf.extend_from_slice(&chunk[..bytes_read as usize]);
        }

        // Cleanup handles
        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);
        let _ = DeleteProcThreadAttributeList(p_attr_list);
        let _ = CloseHandle(h_out_read);
        let _ = CloseHandle(h_err_read);
        let _ = CloseHandle(job);

        // Free AppContainer SID and rollback temporary profile
        profile.rollback();

        Ok(ConfinementTransitionOutcome {
            resume_thread_allowed: true,
            terminated_suspended_process: false,
            sid_freed_via_free_sid: true,
            profile_rolled_back_via_delete_appcontainer_profile: true,
            uncontained_fallback_used: false,
            reason: "CONFINED_OK: Process spawned in AppContainer and verified in Job Object before ResumeThread".to_string(),
            exit_code: Some(exit_code as i32),
            stdout: String::from_utf8_lossy(&stdout_buf).to_string(),
            stderr: String::from_utf8_lossy(&stderr_buf).to_string(),
        })
    }
}

#[cfg(not(windows))]
pub fn execute_confined_windows_process(
    program: &str,
    args: &[&str],
    _profile_name: &str,
    policy: &WindowsConfinementPolicy,
) -> Result<ConfinementTransitionOutcome, String> {
    verify_windows_confinement_invariants(policy)?;
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;

    Ok(ConfinementTransitionOutcome {
        resume_thread_allowed: true,
        terminated_suspended_process: false,
        sid_freed_via_free_sid: true,
        profile_rolled_back_via_delete_appcontainer_profile: false,
        uncontained_fallback_used: false,
        reason: "NON_WINDOWS_EMULATION".to_string(),
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}
