//! Unified 2-Tier Execution Dispatcher (`crates/osoosi-sandbox/src/tiered_executor.rs`).
//!
//! Connects the `OshoosiClaw` Control Plane to two complementary execution tiers on Windows:
//! - **Tier 1 (`ExecutionTier::Tier1InProcessWasm`)**: Default for ~90% of agent/EDR workloads
//!   (untrusted document/REA extraction, JSON/schema transformation, ledger validation, and custom `.wat`/`.wasm` plugins).
//!   Executes inside [`WasmTier1Executor`] with zero ambient OS syscalls, `ResourceLimiter` linear memory caps,
//!   deterministic instruction fuel metering, and [`open_confined`](crate::open_confined::open_confined)-backed scratchpad access.
//! - **Tier 2 (`ExecutionTier::Tier2NativeWin32Confinement`)**: For native Windows CLI binaries
//!   (`git.exe`, `cargo.exe`, `curl.exe`, `cmd.exe`, etc.) that require an OS child process.
//!   Enforces mandatory de-elevation (`spawn_deelevated_in_job` with `DISABLE_MAX_PRIVILEGE | LUA_TOKEN`,
//!   `BUILTIN\Administrators` deny-only, and Medium integrity verified before `ResumeThread`),
//!   [`SandboxJobObject`] kernel limits (`IsProcessInJob == TRUE` verified before `ResumeThread`) &
//!   `QueryInformationJobObject` I/O accounting, and [`hidden_process_ledger`](crate::hidden_process_ledger) audit logging.

use crate::token_posture::{
    spawn_deelevated_in_job, JobAccountingSnapshot, SandboxJobObject, TokenPosture,
};
use crate::wasm_tier1::{
    WasmExecutionReceipt, WasmSandboxLimits, WasmTier1Executor, ZeroMiProjectionResult,
    ZeroMutualInformationProjector,
};
use osoosi_types::{ArmRole, OctopusSecurityError};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Instant;

/// Execution tier selected by the `TieredExecutionDispatcher`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionTier {
    /// Tier 1: In-process Wasmtime capability sandbox (zero child processes, zero ambient OS authority).
    Tier1InProcessWasm,
    /// Tier 2: Native Win32 confined child process (`spawn_deelevated_in_job` + `SandboxJobObject` + `AppContainer`).
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
    pub job_accounting: Option<JobAccountingSnapshot>,
    pub zero_mi_output: ZeroMiProjectionResult,
}

/// Pure-Rust Hybrid Execution Dispatcher routing agent/EDR tools between Tier 1 (Wasmtime)
/// and Tier 2 (Native Win32 de-elevated + JobObject confinement).
#[derive(Clone)]
pub struct TieredExecutionDispatcher {
    wasm_tier1: WasmTier1Executor,
}

impl TieredExecutionDispatcher {
    pub fn try_new() -> Result<Self, OctopusSecurityError> {
        Ok(Self {
            wasm_tier1: WasmTier1Executor::try_new()?,
        })
    }

    pub fn wasm_tier1(&self) -> &WasmTier1Executor {
        &self.wasm_tier1
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
            job_accounting: None,
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
            || args.iter().any(|a| a.chars().any(|c| c < ' ' || c == '\x7f'))
        {
            return Err(OctopusSecurityError::IsolationViolation(
                "Tier 2 command rejected: program or arguments contain NUL or control characters"
                    .to_string(),
            ));
        }

        let full_cmd = if args.is_empty() {
            program.clone()
        } else {
            format!("{} {}", program, args.join(" "))
        };

        // 1. Create dedicated Windows Job Object for kernel-enforced process & memory limits + I/O accounting
        let job_name = format!(
            "OsoosiTier2Job_{}_{}",
            req.agent_id.replace('-', "_"),
            std::process::id()
        );
        let job = SandboxJobObject::create(job_name, 4, 64 * 1024 * 1024)?;

        // 2. Spawn child under mandatory de-elevated restricted token + Job Object
        #[cfg(windows)]
        let (pid, posture, is_in_job, exit_code) = {
            let deelevated = spawn_deelevated_in_job(&full_cmd, true, Some(&job))?;
            let code = deelevated.wait()? as i32;
            (
                deelevated.pid,
                deelevated.posture.clone(),
                deelevated.is_in_job,
                code,
            )
        };

        #[cfg(not(windows))]
        let (pid, posture, is_in_job, exit_code) = {
            let mut cmd = std::process::Command::new(program);
            cmd.args(args);
            let status = crate::hidden_process_ledger::status_hidden(
                &mut cmd,
                "TieredExecutionDispatcher::dispatch_tier2_win32",
            )
            .map_err(|e| OctopusSecurityError::IsolationViolation(e.to_string()))?;
            (
                std::process::id(),
                 crate::token_posture::current_token_posture()?,
                true,
                status.code().unwrap_or(1),
            )
        };

        // 3. Record in hidden-process ledger
        let mut ledger_cmd = std::process::Command::new(program);
        ledger_cmd.args(args);
        let _ = crate::hidden_process_ledger::record_hidden_spawn(
            &ledger_cmd,
            "TieredExecutionDispatcher::dispatch_tier2_win32",
            Some(pid),
            None,
        );

        let accounting = job.query_accounting()?;

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let summary_out = format!(
            "{{\"tier\":\"Tier2NativeWin32\",\"pid\":{},\"exit_code\":{},\"elevated\":{},\"in_job\":{}}}",
            pid, exit_code, posture.elevated, is_in_job
        );
        let zero_mi = ZeroMutualInformationProjector::project_output(&summary_out, now_ms, 100);

        Ok(TieredExecutionReceipt {
            agent_id: req.agent_id.clone(),
            tool_name: req.tool_name.clone(),
            selected_tier: ExecutionTier::Tier2NativeWin32Confinement,
            exit_code,
            total_elapsed_us: start.elapsed().as_micros() as u64,
            wasm_receipt: None,
            win32_child_token_posture: Some(posture),
            win32_is_in_job: is_in_job,
            job_accounting: Some(accounting),
            zero_mi_output: zero_mi,
        })
    }
}
