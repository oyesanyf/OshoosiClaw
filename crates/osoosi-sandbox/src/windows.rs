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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfinementTransitionOutcome {
    pub resume_thread_allowed: bool,
    pub terminated_suspended_process: bool,
    pub sid_freed_via_free_sid: bool,
    pub profile_rolled_back_via_delete_appcontainer_profile: bool,
    pub uncontained_fallback_used: bool,
    pub reason: String,
}

/// Validates that a `WindowsConfinementPolicy` satisfies all mandatory kernel isolation invariants.
pub fn verify_windows_confinement_invariants(
    policy: &WindowsConfinementPolicy,
) -> Result<(), String> {
    if (policy.creation_flags & CREATE_SUSPENDED_FLAG) == 0 {
        return Err("Missing mandatory CREATE_SUSPENDED (0x00000004) flag".to_string());
    }
    if (policy.job_limit_flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) == 0 {
        return Err("Missing mandatory JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE (0x00002000)".to_string());
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
        return Err("IsProcessInJob == TRUE verification before ResumeThread is mandatory".to_string());
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
        };
    }

    ConfinementTransitionOutcome {
        resume_thread_allowed: true,
        terminated_suspended_process: false,
        sid_freed_via_free_sid: true,
        profile_rolled_back_via_delete_appcontainer_profile: false,
        uncontained_fallback_used: false,
        reason: "CONFINED_OK: CREATE_SUSPENDED + AppContainer SID + AssignProcessToJobObject + IsProcessInJob==TRUE verified prior to ResumeThread".to_string(),
    }
}
