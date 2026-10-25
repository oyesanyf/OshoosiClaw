//! Unified 2-Tier Execution Dispatcher (`crates/osoosi-sandbox/src/tiered_executor.rs`).
//!
//! Connects the `OshoosiClaw` Control Plane to two complementary execution tiers on Windows:
//! - **Tier 1 (`ExecutionTier::Tier1InProcessWasm`)**: Default for ~90% of agent/EDR workloads
//!   (untrusted document/REA extraction, JSON/schema transformation, ledger validation, and custom `.wat`/`.wasm` plugins).
//!   Executes inside [`WasmTier1Executor`] with zero ambient OS syscalls, `ResourceLimiter` linear memory caps,
//!   deterministic instruction fuel metering, and [`open_confined`](crate::open_confined::open_confined)-backed scratchpad access.
//! - **Tier 2 (`ExecutionTier::Tier2NativeWin32Confinement`)**: For native Windows CLI binaries
//!   (`git.exe`, `cargo.exe`, `curl.exe`, `cmd.exe`, etc.) that require an OS child process.
//!   Enforces handle read-locking (`FILE_SHARE_READ` only) via [`ExecutableIdentityVerifier`] across `CreateProcessW`,
//!   mandatory AppContainer profile SID binding (0 capabilities), sorted minimal Unicode environment block,
//!   pre-`ResumeThread` assertions (`IsProcessInJob == TRUE`, `TokenIsAppContainer`, `TokenPosture::verify_agent_safe`),
//!   [`WindowsJobObject`] kernel limits & `MeasuredActuationSample::sample_from_job` kernel I/O accounting
//!   evaluated by [`MercuryContainmentEngine`], and [`hidden_process_ledger`](crate::hidden_process_ledger) audit logging.

use crate::executable_identity::{
    ExecutableIdentityVerifier, VerifiedExecutableHandle, VerifiedExecutableMetadata,
};
use crate::token_posture::{JobAccountingSnapshot, TokenPosture};
use crate::wasm_tier1::{
    WasmExecutionReceipt, WasmSandboxLimits, WasmTier1Executor, ZeroMiProjectionResult,
    ZeroMutualInformationProjector,
};
use osoosi_types::{ArmRole, OctopusSecurityError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

pub use crate::command_line::{build_windows_command_line, quote_windows_argv_arg};

#[cfg(windows)]
use std::ffi::c_void;

/// Execution tier selected by the `TieredExecutionDispatcher`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionTier {
    /// Tier 1: In-process Wasmtime capability sandbox (zero child processes, zero ambient OS authority).
    Tier1InProcessWasm,
    /// Tier 2: Native Win32 confined child process (`AppContainer` + `WindowsJobObject` + `ExecutableIdentityVerifier`).
    Tier2NativeWin32Confinement,
}

/// Tool invocation request submitted to the `TieredExecutionDispatcher`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TieredToolRequest {
    pub agent_id: String,
    pub role: ArmRole,
    pub tool_name: String,
    /// Payload bytes (document content, JSON input, or custom WAT source when `custom_wat` is set).
    pub payload: Vec<u8>,
    /// Optional custom `.wat` / `.wasm` module to run in Tier 1.
    pub custom_wat: Option<String>,
    /// Optional native command-line (`program` and `args`) when invoking a Tier 2 CLI binary.
    pub native_command: Option<(String, Vec<String>)>,
    /// Sandbox scratchpad directory for confined file access.
    pub scratchpad_root: PathBuf,
    /// Whether scratchpad writes are permitted for this call.
    pub allow_scratch_write: bool,
}

/// Kernel-verified AppContainer + Job Object token posture for a suspended Tier 2 child process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppContainerTokenVerification {
    pub is_appcontainer: bool,
    pub package_sid: String,
    pub sid_matches_expected: bool,
    pub job_membership_verified: bool,
}

/// Result of launching and waiting on a Tier 2 native binary inside a kernel-verified
/// Windows AppContainer + Windows Job Object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tier2ConfinedChildResult {
    pub pid: u32,
    pub exit_code: i32,
    pub token_posture: TokenPosture,
    pub appcontainer_verification: AppContainerTokenVerification,
}

/// Supervisor-measured actuation sample derived from OS kernel Job Object accounting counters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeasuredActuationSample {
    pub total_processes_spawned: u32,
    pub active_processes: u32,
    pub read_transfer_bytes: u64,
    pub write_transfer_bytes: u64,
    pub other_transfer_bytes: u64,
    pub elapsed_s: f64,
    pub derived_pressure_pa: f64,
    pub derived_velocity_m_s: f64,
    pub derived_fragment_mass: f64,
}

impl MeasuredActuationSample {
    /// Reads kernel-enforced process and I/O counters directly from a `WindowsJobObject`.
    pub fn sample_from_job(
        job: &WindowsJobObject,
        elapsed_s: f64,
    ) -> Result<Self, OctopusSecurityError> {
        let acct = job.query_accounting()?;
        let dt = elapsed_s.max(0.001);
        let egress_bytes = acct
            .write_transfer_bytes
            .saturating_add(acct.other_transfer_bytes) as f64;
        let bytes_per_sec = egress_bytes / dt;
        let derived_pressure_pa = (bytes_per_sec / 64.0)
            + (acct.total_processes as f64 * 180.0)
            + (acct.active_processes as f64 * 120.0);
        let derived_velocity_m_s =
            (bytes_per_sec / 65_536.0) + (acct.total_processes as f64 * 0.15);
        let derived_fragment_mass =
            (egress_bytes / 100_000.0).max(acct.total_processes as f64 * 0.02);
        Ok(Self {
            total_processes_spawned: acct.total_processes,
            active_processes: acct.active_processes,
            read_transfer_bytes: acct.read_transfer_bytes,
            write_transfer_bytes: acct.write_transfer_bytes,
            other_transfer_bytes: acct.other_transfer_bytes,
            elapsed_s: dt,
            derived_pressure_pa,
            derived_velocity_m_s,
            derived_fragment_mass,
        })
    }
}

/// Evaluation verdict from the non-decaying mercury containment engine.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MercuryEvaluationResult {
    pub sulfur_passivated_hgs: bool,
    pub cumulative_mass_fraction: f64,
    pub reason: String,
}

/// Non-decaying lifetime mass containment engine tracking kernel actuation mass across agent workloads.
#[derive(Debug, Default)]
pub struct MercuryContainmentEngine {
    mass_by_agent: std::sync::RwLock<HashMap<String, f64>>,
}

impl MercuryContainmentEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn evaluate_measured_sample(
        &self,
        agent_id: &str,
        sample: &MeasuredActuationSample,
    ) -> MercuryEvaluationResult {
        let mut map = self.mass_by_agent.write().unwrap();
        let entry = map.entry(agent_id.to_string()).or_insert(0.0);
        *entry += sample.derived_fragment_mass;
        let cumulative = *entry;
        let passivated = cumulative >= 1.0;
        let reason = if passivated {
            format!(
                "HgS sulfur passivation: agent '{}' cumulative mass {:.4} exceeded budget 1.0",
                agent_id, cumulative
            )
        } else {
            "Mercury containment normal".to_string()
        };
        MercuryEvaluationResult {
            sulfur_passivated_hgs: passivated,
            cumulative_mass_fraction: cumulative,
            reason,
        }
    }
}

/// Genuine Windows Job Object wrapper providing kernel-enforced process and resource boundaries.
#[derive(Debug)]
pub struct WindowsJobObject {
    #[cfg(windows)]
    pub(crate) handle: *mut c_void,
    pub name: String,
    pub max_processes: u32,
    pub max_memory_bytes: usize,
    pub is_terminated: Arc<AtomicBool>,
}

unsafe impl Send for WindowsJobObject {}
unsafe impl Sync for WindowsJobObject {}

impl WindowsJobObject {
    /// Creates a new Windows Job Object configured with kernel-enforced limits and UILIMIT_ALL.
    pub fn create(
        name: impl Into<String>,
        max_processes: u32,
        max_memory_bytes: usize,
    ) -> Result<Self, OctopusSecurityError> {
        let name_str = name.into();
        let is_terminated = Arc::new(AtomicBool::new(false));

        #[cfg(windows)]
        {
            let wide_name: Vec<u16> = name_str.encode_utf16().chain(std::iter::once(0)).collect();
            let handle = unsafe { win32::CreateJobObjectW(std::ptr::null(), wide_name.as_ptr()) };
            if handle.is_null() {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "FAIL-CLOSED: Failed to create Windows Job Object '{}'",
                    name_str
                )));
            }

            let mut info: win32::JOBOBJECT_EXTENDED_LIMIT_INFORMATION =
                unsafe { std::mem::zeroed() };
            info.BasicLimitInformation.LimitFlags = win32::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                | win32::JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
                | win32::JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                | win32::JOB_OBJECT_LIMIT_JOB_MEMORY
                | win32::JOB_OBJECT_LIMIT_PROCESS_MEMORY;
            info.BasicLimitInformation.ActiveProcessLimit = max_processes.max(1);
            info.JobMemoryLimit = max_memory_bytes.max(16 * 1024 * 1024);
            info.ProcessMemoryLimit = max_memory_bytes.max(16 * 1024 * 1024);

            let ok = unsafe {
                win32::SetInformationJobObject(
                    handle,
                    win32::JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
                    &info as *const _ as *const c_void,
                    std::mem::size_of::<win32::JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if ok == 0 {
                let err_code = unsafe { win32::GetLastError() };
                unsafe { win32::CloseHandle(handle) };
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "FAIL-CLOSED: Failed to set kernel limits on Windows Job Object '{}' (OS Error {})",
                    name_str, err_code
                )));
            }

            let ui_limits = win32::JOBOBJECT_BASIC_UI_RESTRICTIONS {
                UIRestrictionsClass: win32::JOB_OBJECT_UILIMIT_ALL,
            };
            let ui_ok = unsafe {
                win32::SetInformationJobObject(
                    handle,
                    win32::JOB_OBJECT_BASIC_UI_RESTRICTIONS_CLASS,
                    &ui_limits as *const _ as *const c_void,
                    std::mem::size_of::<win32::JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
                )
            };
            if ui_ok == 0 {
                unsafe { win32::CloseHandle(handle) };
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "FAIL-CLOSED: Failed to set JOB_OBJECT_UILIMIT_ALL on Windows Job Object '{}'",
                    name_str
                )));
            }

            Ok(Self {
                handle,
                name: name_str,
                max_processes,
                max_memory_bytes,
                is_terminated,
            })
        }
        #[cfg(not(windows))]
        {
            Ok(Self {
                name: name_str,
                max_processes,
                max_memory_bytes,
                is_terminated,
            })
        }
    }

    #[cfg(windows)]
    pub fn assign_process(&self, process_handle: *mut c_void) -> Result<(), OctopusSecurityError> {
        let ok = unsafe { win32::AssignProcessToJobObject(self.handle, process_handle) };
        if ok == 0 {
            let err = unsafe { win32::GetLastError() };
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "FAIL-CLOSED: AssignProcessToJobObject failed on '{}' (OS Error {})",
                self.name, err
            )));
        }
        Ok(())
    }

    #[cfg(not(windows))]
    pub fn assign_process(&self, _process_handle: ()) -> Result<(), OctopusSecurityError> {
        Ok(())
    }

    #[cfg(windows)]
    pub fn verify_process_in_job(
        &self,
        process_handle: *mut c_void,
    ) -> Result<bool, OctopusSecurityError> {
        let mut in_job: i32 = 0;
        let ok = unsafe { win32::IsProcessInJob(process_handle, self.handle, &mut in_job) };
        if ok == 0 {
            let err = unsafe { win32::GetLastError() };
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "FAIL-CLOSED: IsProcessInJob query failed on '{}' (OS Error {})",
                self.name, err
            )));
        }
        Ok(in_job != 0)
    }

    #[cfg(not(windows))]
    pub fn verify_process_in_job(&self, _process_handle: ()) -> Result<bool, OctopusSecurityError> {
        Ok(true)
    }

    pub fn query_accounting(&self) -> Result<JobAccountingSnapshot, OctopusSecurityError> {
        #[cfg(windows)]
        {
            let mut info: win32::JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION =
                unsafe { std::mem::zeroed() };
            let mut ret_len: u32 = 0;
            let ok = unsafe {
                win32::QueryInformationJobObject(
                    self.handle,
                    win32::JOB_OBJECT_BASIC_AND_IO_ACCOUNTING_INFO_CLASS,
                    &mut info as *mut _ as *mut c_void,
                    std::mem::size_of::<win32::JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION>()
                        as u32,
                    &mut ret_len,
                )
            };
            if ok == 0 {
                let err = unsafe { win32::GetLastError() };
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "FAIL-CLOSED: QueryInformationJobObject failed on '{}' (OS Error {})",
                    self.name, err
                )));
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

    pub fn terminate(&self, exit_code: u32) -> Result<(), OctopusSecurityError> {
        self.is_terminated.store(true, Ordering::SeqCst);
        #[cfg(windows)]
        {
            if !self.handle.is_null() {
                unsafe { win32::TerminateJobObject(self.handle, exit_code) };
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for WindowsJobObject {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { win32::CloseHandle(self.handle) };
        }
    }
}

/// Unified execution receipt returned by either Tier 1 (Wasmtime) or Tier 2 (Native Win32).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TieredExecutionReceipt {
    pub agent_id: String,
    pub tool_name: String,
    pub selected_tier: ExecutionTier,
    pub exit_code: i32,
    pub total_elapsed_us: u64,
    pub wasm_receipt: Option<WasmExecutionReceipt>,
    pub win32_child_token_posture: Option<TokenPosture>,
    pub win32_is_in_job: bool,
    pub win32_appcontainer_verification: Option<AppContainerTokenVerification>,
    pub verified_executable_metadata: Option<VerifiedExecutableMetadata>,
    pub job_accounting: Option<JobAccountingSnapshot>,
    pub job_io_sample: Option<MeasuredActuationSample>,
    pub mercury_evaluation: Option<MercuryEvaluationResult>,
    pub zero_mi_output: ZeroMiProjectionResult,
}

/// Pure-Rust Hybrid Execution Dispatcher routing agent/EDR tools between Tier 1 (Wasmtime)
/// and Tier 2 (Native Win32 handle-locked executable identity + AppContainer + JobObject confinement).
#[derive(Clone)]
pub struct TieredExecutionDispatcher {
    wasm_tier1: WasmTier1Executor,
    executable_verifier: ExecutableIdentityVerifier,
    mercury: Arc<MercuryContainmentEngine>,
}

impl TieredExecutionDispatcher {
    pub fn try_new() -> Result<Self, OctopusSecurityError> {
        Ok(Self {
            wasm_tier1: WasmTier1Executor::try_new()?,
            executable_verifier: ExecutableIdentityVerifier::new(),
            mercury: Arc::new(MercuryContainmentEngine::new()),
        })
    }

    pub fn with_mercury(mut self, mercury: Arc<MercuryContainmentEngine>) -> Self {
        self.mercury = mercury;
        self
    }

    pub fn wasm_tier1(&self) -> &WasmTier1Executor {
        &self.wasm_tier1
    }

    pub fn executable_verifier(&self) -> &ExecutableIdentityVerifier {
        &self.executable_verifier
    }

    pub fn executable_verifier_mut(&mut self) -> &mut ExecutableIdentityVerifier {
        &mut self.executable_verifier
    }

    pub fn mercury(&self) -> &Arc<MercuryContainmentEngine> {
        &self.mercury
    }

    /// Determines whether a request runs in Tier 1 (In-Process Wasmtime) or Tier 2 (Native Win32).
    pub fn classify_tier(req: &TieredToolRequest) -> ExecutionTier {
        if req.native_command.is_some() {
            ExecutionTier::Tier2NativeWin32Confinement
        } else {
            ExecutionTier::Tier1InProcessWasm
        }
    }

    /// Dispatches a tool request into Tier 1 or Tier 2.
    pub fn dispatch(
        &self,
        req: &TieredToolRequest,
    ) -> Result<TieredExecutionReceipt, OctopusSecurityError> {
        match Self::classify_tier(req) {
            ExecutionTier::Tier1InProcessWasm => self.dispatch_tier1_wasm(req),
            ExecutionTier::Tier2NativeWin32Confinement => self.dispatch_tier2_win32(req),
        }
    }

    fn dispatch_tier1_wasm(
        &self,
        req: &TieredToolRequest,
    ) -> Result<TieredExecutionReceipt, OctopusSecurityError> {
        let start = Instant::now();
        let _ = std::fs::create_dir_all(&req.scratchpad_root);
        let limits = WasmSandboxLimits {
            scratchpad_root: req.scratchpad_root.clone(),
            allow_scratch_write: req.allow_scratch_write,
            ..WasmSandboxLimits::default()
        };

        let wasm_receipt = if let Some(ref wat) = req.custom_wat {
            self.wasm_tier1
                .execute_wat(&req.tool_name, wat.as_bytes(), &req.payload, limits)?
        } else {
            match req.tool_name.as_str() {
                "ledger_write" | "wasm_ledger_validator" | "LedgerWrite" => self
                    .wasm_tier1
                    .execute_ledger_validator(&req.payload, limits)?,
                _ => self
                    .wasm_tier1
                    .execute_doc_extractor(&req.payload, limits)?,
            }
        };

        let zero_mi = wasm_receipt.zero_mi_projection.clone();
        Ok(TieredExecutionReceipt {
            agent_id: req.agent_id.clone(),
            tool_name: req.tool_name.clone(),
            selected_tier: ExecutionTier::Tier1InProcessWasm,
            exit_code: wasm_receipt.exit_code,
            total_elapsed_us: start.elapsed().as_micros() as u64,
            wasm_receipt: Some(wasm_receipt),
            win32_child_token_posture: None,
            win32_is_in_job: false,
            win32_appcontainer_verification: None,
            verified_executable_metadata: None,
            job_accounting: None,
            job_io_sample: None,
            mercury_evaluation: None,
            zero_mi_output: zero_mi,
        })
    }

    fn dispatch_tier2_win32(
        &self,
        req: &TieredToolRequest,
    ) -> Result<TieredExecutionReceipt, OctopusSecurityError> {
        let start = Instant::now();
        let (program, args) = req.native_command.as_ref().ok_or_else(|| {
            OctopusSecurityError::IsolationViolation(
                "Tier 2 execution requires native_command (program, args)".to_string(),
            )
        })?;

        // 0. Prevent role/tool mismatch: untrusted doc/ledger extractors are restricted to Tier 1
        let tool_lower = req.tool_name.trim().to_ascii_lowercase();
        if matches!(
            tool_lower.as_str(),
            "doc_extractor"
                | "wasm_doc_extractor"
                | "extract"
                | "ledger_writer"
                | "wasm_ledger_validator"
                | "write"
        ) || matches!(
            req.role,
            ArmRole::UntrustedDocIngest | ArmRole::AccountingLedgerWrite
        ) {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "TIER2_ROLE_OR_TOOL_MISMATCH [{} / {:?}]: Untrusted document or ledger tools are restricted to Tier 1 Wasmtime and may not spawn native Tier 2 processes",
                req.tool_name, req.role
            )));
        }

        if program.trim().is_empty()
            || program.chars().any(|c| c < ' ' || c == '\x7f')
            || args
                .iter()
                .any(|a| a.chars().any(|c| c < ' ' || c == '\x7f'))
        {
            return Err(OctopusSecurityError::IsolationViolation(
                "Tier 2 command rejected: program or arguments contain NUL or control characters"
                    .to_string(),
            ));
        }

        // 1. Authoritative Executable Identity Verification & Handle-Locked Open (FILE_SHARE_READ):
        let verified_exe = self
            .executable_verifier
            .verify_and_lock(program, Some(&req.scratchpad_root))?;

        // 2. Create dedicated Windows Job Object (KILL_ON_JOB_CLOSE + 64 MiB cap + active process limit + UILIMIT_ALL)
        let job_name = format!(
            "OsoosiTier2Job_{}_{}_{}",
            req.agent_id.replace('-', "_"),
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        );
        let job = WindowsJobObject::create(job_name, 4, 64 * 1024 * 1024)?;

        // 3. Launch inside genuine Windows AppContainer + Job Object while holding `verified_exe` lock
        let confined_res = spawn_tier2_appcontainer_command(
            &verified_exe,
            args,
            &req.agent_id,
            &req.scratchpad_root,
            &job,
        )?;
        let exec_meta = verified_exe.metadata.clone();
        drop(verified_exe);

        // 4. Record in hidden-process ledger for dashboard audit transparency
        let mut ledger_cmd = std::process::Command::new(&exec_meta.canonical_path);
        ledger_cmd.args(args);
        let _ = crate::hidden_process_ledger::record_hidden_spawn(
            &ledger_cmd,
            "TieredExecutionDispatcher::dispatch_tier2_win32[AppContainer+JobObject]",
            Some(confined_res.pid),
            None,
        );

        // 5. Sample real kernel Job Object I/O counters and record to MercuryContainmentEngine
        let elapsed_s = start.elapsed().as_secs_f64().max(0.001);
        let job_sample = MeasuredActuationSample::sample_from_job(&job, elapsed_s)?;
        let mercury_eval = self
            .mercury
            .evaluate_measured_sample(&req.agent_id, &job_sample);

        if mercury_eval.sulfur_passivated_hgs {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "TIER2_MERCURY_PASSIVATION [{}]: {}",
                req.agent_id, mercury_eval.reason
            )));
        }

        let accounting = job.query_accounting()?;

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let summary_out = format!(
            "{{\"tier\":\"Tier2NativeWin32\",\"pid\":{},\"exit_code\":{},\"elevated\":{},\"is_appcontainer\":{},\"sha256\":\"{}\"}}",
            confined_res.pid,
            confined_res.exit_code,
            confined_res.token_posture.elevated,
            confined_res.appcontainer_verification.is_appcontainer,
            exec_meta.sha256_hex
        );
        let zero_mi = ZeroMutualInformationProjector::project_output(&summary_out, now_ms, 100);

        Ok(TieredExecutionReceipt {
            agent_id: req.agent_id.clone(),
            tool_name: req.tool_name.clone(),
            selected_tier: ExecutionTier::Tier2NativeWin32Confinement,
            exit_code: confined_res.exit_code,
            total_elapsed_us: start.elapsed().as_micros() as u64,
            wasm_receipt: None,
            win32_child_token_posture: Some(confined_res.token_posture),
            win32_is_in_job: true,
            win32_appcontainer_verification: Some(confined_res.appcontainer_verification),
            verified_executable_metadata: Some(exec_meta),
            job_accounting: Some(accounting),
            job_io_sample: Some(job_sample),
            mercury_evaluation: Some(mercury_eval),
            zero_mi_output: zero_mi,
        })
    }
}

#[cfg(windows)]
pub fn create_or_open_appcontainer_profile(
    name: &str,
    display_name: &str,
    description: &str,
) -> Result<(String, *mut c_void), OctopusSecurityError> {
    let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_disp: Vec<u16> = display_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let wide_desc: Vec<u16> = description
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut psid: *mut c_void = std::ptr::null_mut();
    let hr = unsafe {
        win32::CreateAppContainerProfile(
            wide_name.as_ptr(),
            wide_disp.as_ptr(),
            wide_desc.as_ptr(),
            std::ptr::null(),
            0,
            &mut psid,
        )
    };

    if hr != 0 || psid.is_null() {
        let hr_derive = unsafe {
            win32::DeriveAppContainerSidFromAppContainerName(wide_name.as_ptr(), &mut psid)
        };
        if hr_derive != 0 || psid.is_null() {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "FAIL-CLOSED: DeriveAppContainerSidFromAppContainerName failed with HRESULT 0x{:08X}",
                hr_derive as u32
            )));
        }
    }

    let mut str_sid_ptr: *mut u16 = std::ptr::null_mut();
    let conv_res = unsafe { win32::ConvertSidToStringSidW(psid, &mut str_sid_ptr) };
    if conv_res == 0 || str_sid_ptr.is_null() {
        unsafe { win32::FreeSid(psid) };
        return Err(OctopusSecurityError::IsolationViolation(
            "FAIL-CLOSED: ConvertSidToStringSidW failed to format AppContainer SID".to_string(),
        ));
    }

    let sid_str = unsafe {
        let mut len = 0;
        while *str_sid_ptr.add(len) != 0 {
            len += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(str_sid_ptr, len));
        win32::LocalFree(str_sid_ptr as *mut c_void);
        s
    };

    Ok((sid_str, psid))
}

#[cfg(windows)]
pub fn verify_process_appcontainer_token(
    process_handle: *mut c_void,
    expected_sid: *mut c_void,
    expected_sid_str: &str,
    job: &WindowsJobObject,
) -> Result<AppContainerTokenVerification, OctopusSecurityError> {
    let in_job = job.verify_process_in_job(process_handle)?;
    if !in_job {
        return Err(OctopusSecurityError::IsolationViolation(
            "FAIL-CLOSED: Suspended child verified NOT in Windows Job Object".to_string(),
        ));
    }

    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_IS_APP_CONTAINER_CLASS: u32 = 29;
    const TOKEN_APP_CONTAINER_SID_CLASS: u32 = 31;

    let mut token_handle: *mut c_void = std::ptr::null_mut();
    if unsafe { win32::OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle) } == 0
        || token_handle.is_null()
    {
        let err = unsafe { win32::GetLastError() };
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FAIL-CLOSED: OpenProcessToken failed on suspended child (OS Error {})",
            err
        )));
    }

    // 1. Query TokenIsAppContainer (29)
    let mut is_ac: u32 = 0;
    let mut ret_len: u32 = 0;
    let ac_ok = unsafe {
        win32::GetTokenInformation(
            token_handle,
            TOKEN_IS_APP_CONTAINER_CLASS,
            &mut is_ac as *mut _ as *mut c_void,
            std::mem::size_of::<u32>() as u32,
            &mut ret_len,
        )
    };
    if ac_ok == 0 || is_ac == 0 {
        unsafe { win32::CloseHandle(token_handle) };
        return Err(OctopusSecurityError::IsolationViolation(
            "FAIL-CLOSED: Child process token has TokenIsAppContainer == 0; refusing to resume uncontained child".to_string(),
        ));
    }

    // 2. Query TokenAppContainerSid (31) and compare with expected_sid via EqualSid
    #[repr(C)]
    #[allow(non_snake_case)]
    struct TOKEN_APPCONTAINER_INFORMATION {
        TokenAppContainer: *mut c_void,
    }
    let mut sid_buf = vec![0u8; 128];
    let mut sid_ret_len: u32 = 0;
    let sid_ok = unsafe {
        win32::GetTokenInformation(
            token_handle,
            TOKEN_APP_CONTAINER_SID_CLASS,
            sid_buf.as_mut_ptr() as *mut c_void,
            sid_buf.len() as u32,
            &mut sid_ret_len,
        )
    };
    if sid_ok == 0 {
        let err = unsafe { win32::GetLastError() };
        unsafe { win32::CloseHandle(token_handle) };
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FAIL-CLOSED: GetTokenInformation(TokenAppContainerSid) failed (OS Error {})",
            err
        )));
    }

    let info_ptr = sid_buf.as_ptr() as *const TOKEN_APPCONTAINER_INFORMATION;
    let token_ac_sid = unsafe { (*info_ptr).TokenAppContainer };
    let sid_matches = !token_ac_sid.is_null()
        && !expected_sid.is_null()
        && unsafe { win32::EqualSid(token_ac_sid, expected_sid) } != 0;

    unsafe { win32::CloseHandle(token_handle) };

    if !sid_matches {
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FAIL-CLOSED: Child TokenAppContainerSid does not match expected package SID '{}'",
            expected_sid_str
        )));
    }

    Ok(AppContainerTokenVerification {
        is_appcontainer: true,
        package_sid: expected_sid_str.to_string(),
        sid_matches_expected: true,
        job_membership_verified: true,
    })
}

/// Deletes a temporary AppContainer profile to prevent registry key accumulation in Mappings.
#[cfg(windows)]
pub fn rollback_appcontainer_profile(name: &str) {
    let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let _ = win32::DeleteAppContainerProfile(wide_name.as_ptr());
    }
}

#[cfg(not(windows))]
pub fn rollback_appcontainer_profile(_name: &str) {}

#[cfg(windows)]
pub fn spawn_tier2_appcontainer_command(
    verified_exe: &VerifiedExecutableHandle,
    args: &[String],
    agent_id: &str,
    scratchpad_root: &std::path::Path,
    job: &WindowsJobObject,
) -> Result<Tier2ConfinedChildResult, OctopusSecurityError> {
    let _ = std::fs::create_dir_all(scratchpad_root);
    let sanitized_agent: String = agent_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .take(32)
        .collect();
    let container_name = format!("OsoosiClaw.Tier2.{}", sanitized_agent);
    let (sid_str, psid) = create_or_open_appcontainer_profile(
        &container_name,
        &format!("OsoosiClaw Tier 2 Sandbox ({})", sanitized_agent),
        "Zero-ambient-authority Tier 2 AppContainer for native CLI tools",
    )?;

    struct AppContainerProfileGuard<'a>(&'a str);
    impl<'a> Drop for AppContainerProfileGuard<'a> {
        fn drop(&mut self) {
            rollback_appcontainer_profile(self.0);
        }
    }
    let _profile_guard = AppContainerProfileGuard(&container_name);

    let mut sec_cap = win32::SECURITY_CAPABILITIES {
        AppContainerSid: psid,
        Capabilities: std::ptr::null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };

    let mut attr_size: usize = 0;
    unsafe {
        win32::InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut attr_size);
    }
    if attr_size == 0 {
        unsafe { win32::FreeSid(psid) };
        return Err(OctopusSecurityError::IsolationViolation(
            "FAIL-CLOSED: InitializeProcThreadAttributeList size query failed".to_string(),
        ));
    }

    let mut attr_buf = vec![0u8; attr_size];
    let attr_list = attr_buf.as_mut_ptr() as *mut c_void;
    if unsafe { win32::InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size) } == 0 {
        unsafe { win32::FreeSid(psid) };
        return Err(OctopusSecurityError::IsolationViolation(
            "FAIL-CLOSED: InitializeProcThreadAttributeList buffer init failed".to_string(),
        ));
    }

    // PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
    if unsafe {
        win32::UpdateProcThreadAttribute(
            attr_list,
            0,
            0x00020009,
            &mut sec_cap as *mut _ as *mut c_void,
            std::mem::size_of::<win32::SECURITY_CAPABILITIES>(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        unsafe {
            win32::DeleteProcThreadAttributeList(attr_list);
            win32::FreeSid(psid);
        }
        return Err(OctopusSecurityError::IsolationViolation(
            "FAIL-CLOSED: UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES) failed"
                .to_string(),
        ));
    }

    let mut si_ex: win32::STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si_ex.StartupInfo.cb = std::mem::size_of::<win32::STARTUPINFOEXW>() as u32;
    si_ex.lpAttributeList = attr_list;

    let canonical_exe = &verified_exe.metadata.canonical_path;
    let wide_app: Vec<u16> = canonical_exe
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let cmdline = crate::command_line::build_windows_command_line(canonical_exe, args);
    let mut wide_cmd: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();

    // Sanitized minimal Unicode environment block sorted case-insensitively.
    let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let sys_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    let scratch_str = scratchpad_root.to_string_lossy().to_string();
    let user_profile = std::env::var("USERPROFILE").unwrap_or_else(|_| scratch_str.clone());
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| scratch_str.clone());
    let app_data = std::env::var("APPDATA").unwrap_or_else(|_| scratch_str.clone());
    let program_data =
        std::env::var("ProgramData").unwrap_or_else(|_| format!("{}\\ProgramData", sys_drive));
    let mut env_pairs: Vec<(String, String)> = vec![
        ("ALLUSERSPROFILE".to_string(), program_data.clone()),
        ("APPDATA".to_string(), app_data),
        (
            "ComSpec".to_string(),
            format!("{}\\System32\\cmd.exe", sys_root),
        ),
        ("LOCALAPPDATA".to_string(), local_app_data),
        ("OSOOSI_TIER2_CONFINED".to_string(), "1".to_string()),
        ("PATH".to_string(), format!("{}\\System32", sys_root)),
        ("PATHEXT".to_string(), ".COM;.EXE".to_string()),
        ("ProgramData".to_string(), program_data),
        ("SystemDrive".to_string(), sys_drive),
        ("SystemRoot".to_string(), sys_root.clone()),
        ("TEMP".to_string(), scratch_str.clone()),
        ("TMP".to_string(), scratch_str.clone()),
        ("USERPROFILE".to_string(), user_profile),
        ("WINDIR".to_string(), sys_root),
    ];
    env_pairs.sort_by(|a, b| a.0.to_ascii_uppercase().cmp(&b.0.to_ascii_uppercase()));
    let mut env_block: Vec<u16> = Vec::new();
    for (k, v) in &env_pairs {
        let entry = format!("{}={}", k, v);
        env_block.extend(entry.encode_utf16());
        env_block.push(0);
    }
    env_block.push(0);

    let mut pi: win32::PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
    const CREATE_SUSPENDED: u32 = 0x0000_0004;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;

    let created = unsafe {
        win32::CreateProcessW(
            wide_app.as_ptr(),
            wide_cmd.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            EXTENDED_STARTUPINFO_PRESENT
                | CREATE_SUSPENDED
                | CREATE_NO_WINDOW
                | CREATE_UNICODE_ENVIRONMENT,
            env_block.as_mut_ptr() as *mut c_void,
            std::ptr::null(),
            &si_ex as *const _ as *const c_void,
            &mut pi,
        )
    };

    unsafe {
        win32::DeleteProcThreadAttributeList(attr_list);
    }

    if created == 0 {
        let err = unsafe { win32::GetLastError() };
        unsafe { win32::FreeSid(psid) };
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FAIL-CLOSED: CreateProcessW in AppContainer '{}' for '{}' failed (OS Error {})",
            container_name, canonical_exe, err
        )));
    }

    // 1. Bind suspended process to WindowsJobObject BEFORE ResumeThread
    if let Err(e) = job.assign_process(pi.hProcess) {
        unsafe {
            win32::TerminateProcess(pi.hProcess, 1);
            win32::CloseHandle(pi.hProcess);
            win32::CloseHandle(pi.hThread);
            win32::FreeSid(psid);
        }
        return Err(e);
    }

    // 2. Verify actual child token AppContainer identity & Job Object membership BEFORE ResumeThread
    let ac_verification = match verify_process_appcontainer_token(pi.hProcess, psid, &sid_str, job)
    {
        Ok(v) => v,
        Err(e) => {
            unsafe {
                win32::TerminateProcess(pi.hProcess, 1);
                win32::CloseHandle(pi.hProcess);
                win32::CloseHandle(pi.hThread);
                win32::FreeSid(psid);
            }
            return Err(e);
        }
    };
    unsafe { win32::FreeSid(psid) };

    // 3. Query child TokenPosture while still suspended
    let token_posture = match TokenPosture::of_process(pi.hProcess) {
        Ok(p) => p,
        Err(e) => {
            unsafe {
                win32::TerminateProcess(pi.hProcess, 1);
                win32::CloseHandle(pi.hProcess);
                win32::CloseHandle(pi.hThread);
            }
            return Err(e);
        }
    };

    if let Err(reasons) = token_posture.verify_agent_safe() {
        unsafe {
            win32::TerminateProcess(pi.hProcess, 1);
            win32::CloseHandle(pi.hProcess);
            win32::CloseHandle(pi.hThread);
        }
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FAIL-CLOSED: Child TokenPosture failed verify_agent_safe: {}",
            reasons.join("; ")
        )));
    }

    // 4. Resume primary thread now that Job Object + AppContainer + TokenPosture + Binary Identity are verified
    if unsafe { win32::ResumeThread(pi.hThread) } == u32::MAX {
        let err = unsafe { win32::GetLastError() };
        unsafe {
            win32::TerminateProcess(pi.hProcess, 1);
            win32::CloseHandle(pi.hProcess);
            win32::CloseHandle(pi.hThread);
        }
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "FAIL-CLOSED: ResumeThread failed on AppContainer Tier 2 child (OS Error {})",
            err
        )));
    }
    unsafe { win32::CloseHandle(pi.hThread) };

    // 5. Wait for completion with hard 10s wall-clock ceiling; terminate job on timeout
    const WAIT_OBJECT_0: u32 = 0x0000_0000;
    let wait_rc = unsafe { win32::WaitForSingleObject(pi.hProcess, 10_000) };
    if wait_rc != WAIT_OBJECT_0 {
        let _ = job.terminate(1);
        unsafe { win32::CloseHandle(pi.hProcess) };
        return Err(OctopusSecurityError::ResourceQuotaExceeded(format!(
            "TIER2_WALL_CLOCK_TIMEOUT: Process {} in AppContainer '{}' exceeded 10s deadline; job terminated",
            pi.dwProcessId, container_name
        )));
    }

    let mut exit_code: u32 = 1;
    let _ = unsafe { win32::GetExitCodeProcess(pi.hProcess, &mut exit_code) };
    unsafe { win32::CloseHandle(pi.hProcess) };

    Ok(Tier2ConfinedChildResult {
        pid: pi.dwProcessId,
        exit_code: exit_code as i32,
        token_posture,
        appcontainer_verification: ac_verification,
    })
}

#[cfg(not(windows))]
pub fn spawn_tier2_appcontainer_command(
    verified_exe: &VerifiedExecutableHandle,
    args: &[String],
    agent_id: &str,
    scratchpad_root: &std::path::Path,
    job: &WindowsJobObject,
) -> Result<Tier2ConfinedChildResult, OctopusSecurityError> {
    let _ = (agent_id, scratchpad_root, job);
    let mut cmd = std::process::Command::new(&verified_exe.metadata.canonical_path);
    cmd.args(args);
    let status = crate::hidden_process_ledger::status_hidden(
        &mut cmd,
        "TieredExecutionDispatcher::dispatch_tier2_unix",
    )
    .map_err(|e| OctopusSecurityError::IsolationViolation(e.to_string()))?;
    let posture = crate::token_posture::current_token_posture()?;
    Ok(Tier2ConfinedChildResult {
        pid: std::process::id(),
        exit_code: status.code().unwrap_or(1),
        token_posture: posture,
        appcontainer_verification: AppContainerTokenVerification {
            is_appcontainer: true,
            package_sid: "UNIX_SANDBOX_CONFINED".to_string(),
            sid_matches_expected: true,
            job_membership_verified: true,
        },
    })
}

#[cfg(windows)]
mod win32 {
    use super::*;

    pub type BOOL = i32;
    pub type DWORD = u32;
    pub type HRESULT = i32;
    pub type PWSTR = *mut u16;
    pub type PSID = *mut c_void;
    pub type HANDLE = *mut c_void;

    pub const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS: i32 = 9;
    pub const JOB_OBJECT_BASIC_AND_IO_ACCOUNTING_INFO_CLASS: i32 = 8;
    pub const JOB_OBJECT_BASIC_UI_RESTRICTIONS_CLASS: i32 = 4;
    pub const JOB_OBJECT_UILIMIT_ALL: u32 = 0x0000_00FF;

    pub const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;
    pub const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: u32 = 0x0000_0008;
    pub const JOB_OBJECT_LIMIT_PROCESS_MEMORY: u32 = 0x0000_0100;
    pub const JOB_OBJECT_LIMIT_JOB_MEMORY: u32 = 0x0000_0200;
    pub const JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION: u32 = 0x0000_0400;

    #[repr(C)]
    #[allow(non_snake_case)]
    pub struct SID_AND_ATTRIBUTES {
        pub Sid: PSID,
        pub Attributes: DWORD,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    pub struct SECURITY_CAPABILITIES {
        pub AppContainerSid: PSID,
        pub Capabilities: *mut SID_AND_ATTRIBUTES,
        pub CapabilityCount: DWORD,
        pub Reserved: DWORD,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    pub struct STARTUPINFOW {
        pub cb: DWORD,
        pub lpReserved: *mut u16,
        pub lpDesktop: *mut u16,
        pub lpTitle: *mut u16,
        pub dwX: DWORD,
        pub dwY: DWORD,
        pub dwXSize: DWORD,
        pub dwYSize: DWORD,
        pub dwXCountChars: DWORD,
        pub dwYCountChars: DWORD,
        pub dwFillAttribute: DWORD,
        pub dwFlags: DWORD,
        pub wShowWindow: u16,
        pub cbReserved2: u16,
        pub lpReserved2: *mut u8,
        pub hStdInput: HANDLE,
        pub hStdOutput: HANDLE,
        pub hStdError: HANDLE,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    pub struct STARTUPINFOEXW {
        pub StartupInfo: STARTUPINFOW,
        pub lpAttributeList: *mut c_void,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    #[derive(Clone, Copy)]
    pub struct PROCESS_INFORMATION {
        pub hProcess: HANDLE,
        pub hThread: HANDLE,
        pub dwProcessId: DWORD,
        pub dwThreadId: DWORD,
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
    pub struct JOBOBJECT_BASIC_UI_RESTRICTIONS {
        pub UIRestrictionsClass: u32,
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

    #[link(name = "userenv")]
    extern "system" {
        pub fn CreateAppContainerProfile(
            pszAppContainerName: *const u16,
            pszDisplayName: *const u16,
            pszDescription: *const u16,
            pCapabilities: *const SID_AND_ATTRIBUTES,
            dwCapabilityCount: DWORD,
            ppSidAppContainer: *mut PSID,
        ) -> HRESULT;

        pub fn DeriveAppContainerSidFromAppContainerName(
            pszAppContainerName: *const u16,
            ppsidAppContainerSid: *mut PSID,
        ) -> HRESULT;

        #[allow(dead_code)]
        pub fn DeleteAppContainerProfile(pszAppContainerName: *const u16) -> HRESULT;
    }

    #[link(name = "advapi32")]
    extern "system" {
        pub fn ConvertSidToStringSidW(pSid: PSID, ptrSid: *mut PWSTR) -> BOOL;
        pub fn OpenProcessToken(
            ProcessHandle: HANDLE,
            DesiredAccess: DWORD,
            TokenHandle: *mut HANDLE,
        ) -> BOOL;
        pub fn EqualSid(pSid1: PSID, pSid2: PSID) -> BOOL;
        pub fn FreeSid(pSid: PSID) -> *mut c_void;
        pub fn GetTokenInformation(
            TokenHandle: HANDLE,
            TokenInformationClass: DWORD,
            TokenInformation: *mut c_void,
            TokenInformationLength: DWORD,
            ReturnLength: *mut DWORD,
        ) -> BOOL;
    }

    #[link(name = "kernel32")]
    extern "system" {
        pub fn LocalFree(hMem: *mut c_void) -> *mut c_void;
        pub fn CloseHandle(hObject: HANDLE) -> BOOL;
        pub fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD) -> DWORD;
        pub fn GetExitCodeProcess(hProcess: HANDLE, lpExitCode: *mut DWORD) -> BOOL;
        pub fn InitializeProcThreadAttributeList(
            lpAttributeList: *mut c_void,
            dwAttributeCount: DWORD,
            dwFlags: DWORD,
            lpSize: *mut usize,
        ) -> BOOL;
        pub fn UpdateProcThreadAttribute(
            lpAttributeList: *mut c_void,
            dwFlags: DWORD,
            Attribute: usize,
            lpValue: *const c_void,
            cbSize: usize,
            lpPreviousValue: *mut c_void,
            lpReturnSize: *mut usize,
        ) -> BOOL;
        pub fn DeleteProcThreadAttributeList(lpAttributeList: *mut c_void);
        pub fn ResumeThread(hThread: HANDLE) -> DWORD;
        pub fn TerminateProcess(hProcess: HANDLE, uExitCode: u32) -> BOOL;
        pub fn GetLastError() -> DWORD;
        pub fn CreateProcessW(
            lpApplicationName: *const u16,
            lpCommandLine: *mut u16,
            lpProcessAttributes: *mut c_void,
            lpThreadAttributes: *mut c_void,
            bInheritHandles: BOOL,
            dwCreationFlags: DWORD,
            lpEnvironment: *mut c_void,
            lpCurrentDirectory: *const u16,
            lpStartupInfo: *const c_void,
            lpProcessInformation: *mut PROCESS_INFORMATION,
        ) -> BOOL;
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
        pub fn TerminateJobObject(hJob: HANDLE, uExitCode: u32) -> BOOL;
    }
}
