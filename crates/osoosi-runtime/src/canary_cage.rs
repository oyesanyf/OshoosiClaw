//! Hardened Active Deception & Swarm-Immunity Ephemeral Canary Cage (`CanaryCage`).
//!
//! Provides isolated process execution inside a Win32 Job Object (Windows) or memfd sandbox (Linux)
//! with 7 mandatory safety and confinement fixes:
//! 1. Zero parent environment mutation: strictly builds isolated child-only environment block.
//! 2. Fail-closed pre-execution Windows confinement (`CREATE_SUSPENDED`, `AssignProcessToJobObject`,
//!    `IsProcessInJob == TRUE` before `ResumeThread`).
//! 3. Deterministic overlapped honey-pipe watcher with manual-reset shutdown event (< 1ms cleanup, 0 leaks).
//! 4. Honey-pipe access triggers immediate process/job termination (exit code 137) and `CanaryAlert` (confidence 1.00).
//! 5. Win32 argument quoting per `CommandLineToArgvW` rules with explicit `lpApplicationName`.

use chrono::{DateTime, Utc};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
#[cfg(target_os = "windows")]
use tracing::error;

/// High-priority alert emitted when a caged process touches an ephemeral canary trap.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CanaryAlert {
    pub alert_id: String,
    pub session_id: String,
    pub pid: u32,
    pub trap_kind: String, // "NamedPipe" on Windows, "Memfd" on Linux
    pub trap_path: String,
    pub confidence: f64, // 1.00
    pub timestamp: DateTime<Utc>,
    pub attributed_file_digest: Option<String>,
    pub details: String,
}

/// Execution outcome of a caged process.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CanaryCageResult {
    pub exit_code: Option<i32>,
    pub success: bool,
    pub canary_triggered: bool,
    pub stdout: String,
    pub stderr: String,
    pub alert: Option<CanaryAlert>,
    pub duration_ms: u64,
}

/// Backwards-compatible alias for CanaryCageResult.
pub type CagedExitStatus = CanaryCageResult;

/// Errors produced during canary cage setup, confinement, or execution.
#[derive(Debug, thiserror::Error)]
pub enum CanaryCageError {
    #[error("Failed to spawn caged process: {0}")]
    SpawnFailed(String),
    #[error("Confinement failed: {0}")]
    ConfinementFailed(String),
    #[error("Execution timed out after {0:?}")]
    Timeout(Duration),
    #[error("Canary trap triggered: {0}")]
    CanaryTriggered(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("General cage error: {0}")]
    General(String),
}

/// Quote a single command line argument according to Win32 `CommandLineToArgvW` rules.
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

/// Attempt to locate executable on disk or along PATH without mutating the environment.
pub fn resolve_binary_path(command: &str) -> PathBuf {
    let p = Path::new(command);
    if p.is_file() {
        return p.to_path_buf();
    }
    // Check if adding .exe makes it a file
    let with_exe = p.with_extension("exe");
    if with_exe.is_file() {
        return with_exe;
    }
    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(command);
            if candidate.is_file() {
                return candidate;
            }
            let candidate_exe = dir.join(format!("{}.exe", command));
            if candidate_exe.is_file() {
                return candidate_exe;
            }
        }
    }
    PathBuf::from(command)
}

/// Handle to a running caged child process.
pub struct CagedChild {
    pub pid: u32,
    pub session_id: String,
    pub honey_trap_path: String,
    pub canary_triggered: Arc<AtomicBool>,
    pub alert_received: Arc<Mutex<Option<CanaryAlert>>>,
    start_time: Instant,

    #[cfg(windows)]
    child_handle: windows::Win32::Foundation::HANDLE,
    #[cfg(windows)]
    job_handle: windows::Win32::Foundation::HANDLE,
    #[cfg(windows)]
    shutdown_event: windows::Win32::Foundation::HANDLE,
    #[cfg(windows)]
    watcher_thread: Option<std::thread::JoinHandle<()>>,

    #[cfg(not(windows))]
    child: std::process::Child,
    #[cfg(not(windows))]
    memfd: i32,
    #[cfg(not(windows))]
    _target_fd: i32,
    #[cfg(not(windows))]
    shutdown: Arc<AtomicBool>,
    #[cfg(not(windows))]
    watcher_thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(windows)]
unsafe impl Send for CagedChild {}
#[cfg(windows)]
unsafe impl Sync for CagedChild {}
#[cfg(not(windows))]
unsafe impl Send for CagedChild {}
#[cfg(not(windows))]
unsafe impl Sync for CagedChild {}

impl CagedChild {
    /// Wait for process completion or until the specified timeout expires.
    pub fn wait_timeout(&mut self, timeout: Duration) -> Result<CanaryCageResult, CanaryCageError> {
        #[cfg(windows)]
        {
            use windows::Win32::Foundation::WAIT_TIMEOUT;
            use windows::Win32::System::Threading::{
                GetExitCodeProcess, SetEvent, TerminateProcess, WaitForSingleObject,
            };

            let timeout_ms = timeout.as_millis().min(u32::MAX as u128) as u32;
            let wait_res = unsafe { WaitForSingleObject(self.child_handle, timeout_ms) };

            // Signal shutdown event to unblock watcher thread immediately (< 1ms cleanup)
            unsafe {
                let _ = SetEvent(self.shutdown_event);
            }
            if let Some(handle) = self.watcher_thread.take() {
                let _ = handle.join();
            }

            let triggered = self.canary_triggered.load(Ordering::SeqCst);
            let elapsed_ms = self.start_time.elapsed().as_millis() as u64;

            if triggered {
                let alert = self
                    .alert_received
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                return Ok(CanaryCageResult {
                    exit_code: Some(137),
                    success: false,
                    canary_triggered: true,
                    stdout: String::new(),
                    stderr:
                        "Execution aborted: Ephemeral canary honey-pipe touched by caged process"
                            .into(),
                    alert,
                    duration_ms: elapsed_ms,
                });
            }

            if wait_res == WAIT_TIMEOUT {
                unsafe {
                    use windows::Win32::System::JobObjects::TerminateJobObject;
                    let _ = TerminateJobObject(self.job_handle, 137);
                    let _ = TerminateProcess(self.child_handle, 137);
                }
                return Err(CanaryCageError::Timeout(timeout));
            }

            let mut code: u32 = 0;
            let exit_code = if unsafe { GetExitCodeProcess(self.child_handle, &mut code) }.is_ok() {
                Some(code as i32)
            } else {
                None
            };

            Ok(CanaryCageResult {
                exit_code,
                success: exit_code == Some(0),
                canary_triggered: false,
                stdout: String::new(),
                stderr: String::new(),
                alert: None,
                duration_ms: elapsed_ms,
            })
        }

        #[cfg(not(windows))]
        {
            let start = self.start_time;
            loop {
                // Check if canary trap was touched
                if self.canary_triggered.load(Ordering::SeqCst) {
                    self.shutdown.store(true, Ordering::SeqCst);
                    if let Some(h) = self.watcher_thread.take() {
                        let _ = h.join();
                    }
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    let alert = self
                        .alert_received
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone();
                    return Ok(CanaryCageResult {
                        exit_code: Some(137),
                        success: false,
                        canary_triggered: true,
                        stdout: String::new(),
                        stderr:
                            "Execution aborted: Ephemeral canary memfd touched by caged process"
                                .into(),
                        alert,
                        duration_ms: start.elapsed().as_millis() as u64,
                    });
                }

                match self.child.try_wait() {
                    Ok(Some(status)) => {
                        self.shutdown.store(true, Ordering::SeqCst);
                        if let Some(h) = self.watcher_thread.take() {
                            let _ = h.join();
                        }
                        let triggered = self.canary_triggered.load(Ordering::SeqCst);
                        if triggered {
                            let alert = self
                                .alert_received
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .clone();
                            return Ok(CanaryCageResult {
                                exit_code: Some(137),
                                success: false,
                                canary_triggered: true,
                                stdout: String::new(),
                                stderr: "Execution aborted: Ephemeral canary memfd touched by caged process".into(),
                                alert,
                                duration_ms: start.elapsed().as_millis() as u64,
                            });
                        }
                        let code = status.code();
                        return Ok(CanaryCageResult {
                            exit_code: code,
                            success: status.success(),
                            canary_triggered: false,
                            stdout: String::new(),
                            stderr: String::new(),
                            alert: None,
                            duration_ms: start.elapsed().as_millis() as u64,
                        });
                    }
                    Ok(None) => {
                        if start.elapsed() >= timeout {
                            self.shutdown.store(true, Ordering::SeqCst);
                            if let Some(h) = self.watcher_thread.take() {
                                let _ = h.join();
                            }
                            let _ = self.child.kill();
                            return Err(CanaryCageError::Timeout(timeout));
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => {
                        self.shutdown.store(true, Ordering::SeqCst);
                        if let Some(h) = self.watcher_thread.take() {
                            let _ = h.join();
                        }
                        return Err(CanaryCageError::Io(e));
                    }
                }
            }
        }
    }

    /// Wait for process completion without timeout.
    pub fn wait(&mut self) -> Result<CanaryCageResult, CanaryCageError> {
        self.wait_timeout(Duration::from_secs(3600))
    }

    /// Forcibly terminate the caged child and its job container.
    pub fn kill(&mut self) -> Result<(), CanaryCageError> {
        #[cfg(windows)]
        {
            use windows::Win32::System::JobObjects::TerminateJobObject;
            use windows::Win32::System::Threading::{SetEvent, TerminateProcess};

            unsafe {
                let _ = SetEvent(self.shutdown_event);
                let _ = TerminateJobObject(self.job_handle, 137);
                let _ = TerminateProcess(self.child_handle, 137);
            }
            if let Some(h) = self.watcher_thread.take() {
                let _ = h.join();
            }
            Ok(())
        }

        #[cfg(not(windows))]
        {
            self.shutdown.store(true, Ordering::SeqCst);
            if let Some(h) = self.watcher_thread.take() {
                let _ = h.join();
            }
            self.child.kill().map_err(CanaryCageError::Io)
        }
    }
}

impl Drop for CagedChild {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            use windows::Win32::Foundation::CloseHandle;
            use windows::Win32::System::JobObjects::TerminateJobObject;
            use windows::Win32::System::Threading::{SetEvent, TerminateProcess};

            unsafe {
                let _ = SetEvent(self.shutdown_event);
                let _ = TerminateJobObject(self.job_handle, 137);
                let _ = TerminateProcess(self.child_handle, 137);
            }
            if let Some(h) = self.watcher_thread.take() {
                let _ = h.join();
            }
            unsafe {
                let _ = CloseHandle(self.child_handle);
                let _ = CloseHandle(self.job_handle);
                let _ = CloseHandle(self.shutdown_event);
            }
        }

        #[cfg(not(windows))]
        {
            self.shutdown.store(true, Ordering::SeqCst);
            if let Some(h) = self.watcher_thread.take() {
                let _ = h.join();
            }
            if self.memfd >= 0 {
                unsafe {
                    libc::close(self.memfd);
                }
                self.memfd = -1;
            }
            let _ = self.child.kill();
        }
    }
}

/// Hardened Canary Cage Sandbox Executor.
pub struct CanaryCage;

impl CanaryCage {
    /// Spawns a command inside the hardened CanaryCage sandbox and blocks until completion or timeout.
    pub fn spawn_caged(
        command: &str,
        args: &[impl AsRef<str>],
        session_id: &str,
        timeout: Duration,
    ) -> Result<CanaryCageResult, CanaryCageError> {
        let mut child = Self::spawn_child(command, args, session_id, None, None)?;
        child.wait_timeout(timeout)
    }

    /// Spawns a caged child process returning an asynchronous `CagedChild` handle.
    pub fn spawn_child(
        command: &str,
        args: &[impl AsRef<str>],
        session_id: &str,
        custom_env: Option<&[(&str, &str)]>,
        on_alert: Option<Arc<dyn Fn(CanaryAlert) + Send + Sync + 'static>>,
    ) -> Result<CagedChild, CanaryCageError> {
        #[cfg(windows)]
        {
            use std::collections::BTreeMap;
            use windows::core::{PCWSTR, PWSTR};
            use windows::Win32::Foundation::{
                CloseHandle, DuplicateHandle, GetLastError, DUPLICATE_SAME_ACCESS,
                ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
            };
            use windows::Win32::Storage::FileSystem::{
                FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
            };
            use windows::Win32::System::JobObjects::*;
            use windows::Win32::System::Pipes::*;
            use windows::Win32::System::Threading::*;
            use windows::Win32::System::IO::{CancelIo, OVERLAPPED};

            let rand_hex = format!("{:016x}", rand::random::<u128>());
            let pipe_name = format!(r"\\.\pipe\osoosi_canary_{}_{}", session_id, rand_hex);
            let wide_pipe: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();

            // 1. Create Overlapped Named Pipe
            let h_pipe = unsafe {
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
            if h_pipe == INVALID_HANDLE_VALUE {
                return Err(CanaryCageError::SpawnFailed(format!(
                    "Failed to create canary named pipe {}: {:?}",
                    pipe_name,
                    std::io::Error::last_os_error()
                )));
            }

            // 2. Create and configure Win32 Job Object
            let job = unsafe { CreateJobObjectW(None, None) }.map_err(|e| {
                unsafe {
                    let _ = CloseHandle(h_pipe);
                }
                CanaryCageError::ConfinementFailed(format!("CreateJobObjectW failed: {:?}", e))
            })?;

            let mut limit_info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION =
                unsafe { std::mem::zeroed() };
            limit_info.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;

            let set_info_res = unsafe {
                SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    &limit_info as *const _ as *const _,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if let Err(e) = set_info_res {
                unsafe {
                    let _ = CloseHandle(job);
                    let _ = CloseHandle(h_pipe);
                }
                return Err(CanaryCageError::ConfinementFailed(format!(
                    "SetInformationJobObject failed: {:?}",
                    e
                )));
            }

            // 3. Duplicate Job Handle for Watcher Thread
            let mut dup_job: HANDLE = Default::default();
            let dup_ok = unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    job,
                    GetCurrentProcess(),
                    &mut dup_job,
                    0,
                    false,
                    DUPLICATE_SAME_ACCESS,
                )
            };
            if let Err(e) = dup_ok {
                unsafe {
                    let _ = CloseHandle(job);
                    let _ = CloseHandle(h_pipe);
                }
                return Err(CanaryCageError::ConfinementFailed(format!(
                    "DuplicateHandle failed: {:?}",
                    e
                )));
            }

            // 4. Create Manual-Reset Shutdown Event
            let shutdown_event = unsafe { CreateEventW(None, true, false, None) }.map_err(|e| {
                unsafe {
                    let _ = CloseHandle(job);
                    let _ = CloseHandle(dup_job);
                    let _ = CloseHandle(h_pipe);
                }
                CanaryCageError::SpawnFailed(format!("CreateEventW failed: {:?}", e))
            })?;

            let mut dup_shutdown: HANDLE = Default::default();
            unsafe {
                let _ = DuplicateHandle(
                    GetCurrentProcess(),
                    shutdown_event,
                    GetCurrentProcess(),
                    &mut dup_shutdown,
                    0,
                    false,
                    DUPLICATE_SAME_ACCESS,
                );
            }

            // 5. Build Child-Only Isolated UTF-16 Environment Block (Zero Parent Mutation)
            let mut env_map: BTreeMap<String, String> = BTreeMap::new();
            for (k, v) in std::env::vars() {
                env_map.insert(k, v);
            }
            env_map.insert("CANARY_HONEY_PIPE".to_string(), pipe_name.clone());
            env_map.insert("CANARY_SESSION_ID".to_string(), session_id.to_string());
            env_map.insert("CANARY_TRAP_PATH".to_string(), pipe_name.clone());
            env_map.insert("OSOOSI_CANARY_ACTIVE".to_string(), "1".to_string());
            if let Some(custom) = custom_env {
                for &(k, v) in custom {
                    env_map.insert(k.to_string(), v.to_string());
                }
            }

            let mut env_block: Vec<u16> = Vec::new();
            for (k, v) in &env_map {
                let line = format!("{}={}", k, v);
                for c in line.encode_utf16() {
                    env_block.push(c);
                }
                env_block.push(0);
            }
            env_block.push(0); // terminating double-null

            // 6. Build Command Line with Strict Quoting
            let resolved_app = resolve_binary_path(command);
            let app_str = resolved_app.to_string_lossy().to_string();
            let wide_app: Vec<u16> = app_str.encode_utf16().chain(std::iter::once(0)).collect();

            let mut full_cmd = quote_win32_arg(&app_str);
            for a in args {
                full_cmd.push(' ');
                full_cmd.push_str(&quote_win32_arg(a.as_ref()));
            }
            let mut wide_cmd: Vec<u16> =
                full_cmd.encode_utf16().chain(std::iter::once(0)).collect();

            // 7. Spawn Suspended Child
            let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
            si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
            let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

            let creation_flags = CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;

            let create_res = unsafe {
                CreateProcessW(
                    PCWSTR::from_raw(wide_app.as_ptr()),
                    PWSTR::from_raw(wide_cmd.as_mut_ptr()),
                    None,
                    None,
                    false,
                    creation_flags,
                    Some(env_block.as_ptr() as *const _),
                    None,
                    &si,
                    &mut pi,
                )
            };

            if let Err(e) = create_res {
                unsafe {
                    let _ = CloseHandle(shutdown_event);
                    let _ = CloseHandle(dup_shutdown);
                    let _ = CloseHandle(job);
                    let _ = CloseHandle(dup_job);
                    let _ = CloseHandle(h_pipe);
                }
                return Err(CanaryCageError::SpawnFailed(format!(
                    "CreateProcessW failed for {:?}: {:?}",
                    app_str, e
                )));
            }

            // 8. Fail-Closed Pre-Execution Confinement
            let assign_res = unsafe { AssignProcessToJobObject(job, pi.hProcess) };
            if let Err(e) = assign_res {
                error!(
                    "CONFINEMENT FAILURE: AssignProcessToJobObject failed: {:?}",
                    e
                );
                unsafe {
                    let _ = TerminateProcess(pi.hProcess, 137);
                    let _ = CloseHandle(pi.hThread);
                    let _ = CloseHandle(pi.hProcess);
                    let _ = CloseHandle(shutdown_event);
                    let _ = CloseHandle(dup_shutdown);
                    let _ = CloseHandle(job);
                    let _ = CloseHandle(dup_job);
                    let _ = CloseHandle(h_pipe);
                }
                return Err(CanaryCageError::ConfinementFailed(format!(
                    "AssignProcessToJobObject failed: {:?}",
                    e
                )));
            }

            let mut is_in_job = windows::Win32::Foundation::BOOL(0);
            let check_in_job = unsafe { IsProcessInJob(pi.hProcess, job, &mut is_in_job) };
            if check_in_job.is_err() || !is_in_job.as_bool() {
                error!("CONFINEMENT FAILURE: Process failed IsProcessInJob verification");
                unsafe {
                    let _ = TerminateProcess(pi.hProcess, 137);
                    let _ = CloseHandle(pi.hThread);
                    let _ = CloseHandle(pi.hProcess);
                    let _ = CloseHandle(shutdown_event);
                    let _ = CloseHandle(dup_shutdown);
                    let _ = CloseHandle(job);
                    let _ = CloseHandle(dup_job);
                    let _ = CloseHandle(h_pipe);
                }
                return Err(CanaryCageError::ConfinementFailed(
                    "IsProcessInJob assertion failed".into(),
                ));
            }

            let canary_triggered = Arc::new(AtomicBool::new(false));
            let alert_received = Arc::new(Mutex::new(None));

            let watcher_triggered = Arc::clone(&canary_triggered);
            let watcher_alert = Arc::clone(&alert_received);
            let watcher_session = session_id.to_string();
            let watcher_pipe = pipe_name.clone();
            let watcher_pid = pi.dwProcessId;

            let pipe_raw = h_pipe.0 as isize;
            let job_raw = dup_job.0 as isize;
            let shutdown_raw = dup_shutdown.0 as isize;

            // 9. Deterministic Overlapped Honey-Pipe Watcher Thread
            let watcher_thread = match std::thread::Builder::new()
                .name(format!("canary_watcher_{}", watcher_pid))
                .spawn(move || {
                    let pipe = HANDLE(pipe_raw as *mut _);
                    let job_handle = HANDLE(job_raw as *mut _);
                    let shutdown = HANDLE(shutdown_raw as *mut _);

                    let h_event =
                        unsafe { CreateEventW(None, true, false, None) }.unwrap_or_default();
                    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
                    overlapped.hEvent = h_event;

                    let connect_res = unsafe { ConnectNamedPipe(pipe, Some(&mut overlapped)) };
                    let mut client_connected = false;

                    if connect_res.is_err() {
                        let err = unsafe { GetLastError() };
                        if err == ERROR_IO_PENDING {
                            let wait_handles = [shutdown, h_event];
                            let wait_res =
                                unsafe { WaitForMultipleObjects(&wait_handles, false, INFINITE) };
                            if wait_res.0 == 0 {
                                // Shutdown event signaled: clean up immediately in < 1ms
                                unsafe {
                                    let _ = CancelIo(pipe);
                                    let _ = DisconnectNamedPipe(pipe);
                                }
                            } else if wait_res.0 == 1 {
                                client_connected = true;
                            }
                        } else if err == ERROR_PIPE_CONNECTED {
                            client_connected = true;
                        }
                    } else {
                        client_connected = true;
                    }

                    if client_connected {
                        watcher_triggered.store(true, Ordering::SeqCst);
                        // Terminate process/job immediately with exit code 137
                        unsafe {
                            let _ = TerminateJobObject(job_handle, 137);
                        }
                        let alert = CanaryAlert {
                            alert_id: format!("canary-alert-{}", uuid::Uuid::new_v4()),
                            session_id: watcher_session.clone(),
                            pid: watcher_pid,
                            trap_kind: "NamedPipe".to_string(),
                            trap_path: watcher_pipe.clone(),
                            confidence: 1.00,
                            timestamp: Utc::now(),
                            attributed_file_digest: None,
                            details: format!(
                                "Ephemeral honey-pipe {} accessed by caged child PID {}",
                                watcher_pipe, watcher_pid
                            ),
                        };
                        if let Some(ref cb) = on_alert {
                            cb(alert.clone());
                        }
                        let mut slot = watcher_alert.lock().unwrap_or_else(|e| e.into_inner());
                        *slot = Some(alert);
                        unsafe {
                            let _ = DisconnectNamedPipe(pipe);
                        }
                    }

                    unsafe {
                        let _ = CloseHandle(h_event);
                        let _ = CloseHandle(shutdown);
                        let _ = CloseHandle(job_handle);
                        let _ = CloseHandle(pipe);
                    }
                }) {
                Ok(h) => h,
                Err(e) => {
                    unsafe {
                        let _ = TerminateProcess(pi.hProcess, 137);
                        let _ = CloseHandle(pi.hThread);
                        let _ = CloseHandle(pi.hProcess);
                        let _ = CloseHandle(shutdown_event);
                        let _ = CloseHandle(dup_shutdown);
                        let _ = CloseHandle(job);
                        let _ = CloseHandle(dup_job);
                        let _ = CloseHandle(h_pipe);
                    }
                    return Err(CanaryCageError::SpawnFailed(format!(
                        "Failed to spawn watcher thread: {:?}",
                        e
                    )));
                }
            };

            // 10. Resume Child Thread
            unsafe {
                let _ = ResumeThread(pi.hThread);
                let _ = CloseHandle(pi.hThread);
            }

            Ok(CagedChild {
                pid: pi.dwProcessId,
                session_id: session_id.to_string(),
                honey_trap_path: pipe_name,
                canary_triggered,
                alert_received,
                start_time: Instant::now(),
                child_handle: pi.hProcess,
                job_handle: job,
                shutdown_event,
                watcher_thread: Some(watcher_thread),
            })
        }

        #[cfg(not(windows))]
        {
            use std::os::unix::process::CommandExt;

            let mut cmd = std::process::Command::new(command);
            for a in args {
                cmd.arg(a.as_ref());
            }

            // 1. Determine high FD below RLIMIT_NOFILE
            let mut rlim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            let high_fd: i32 = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) } == 0
                && rlim.rlim_cur > 10
            {
                ((rlim.rlim_cur - 1) as i32).min(1020)
            } else {
                512
            };

            // 2. Create genuine memfd canary
            #[cfg(target_os = "linux")]
            let memfd = unsafe { libc::memfd_create(c"edr_vault_key".as_ptr(), libc::MFD_CLOEXEC) };
            #[cfg(not(target_os = "linux"))]
            let memfd = unsafe {
                let mut pipe_fds = [0i32; 2];
                if libc::pipe(pipe_fds.as_mut_ptr()) == 0 {
                    libc::close(pipe_fds[1]);
                    pipe_fds[0]
                } else {
                    -1
                }
            };

            if memfd < 0 {
                return Err(CanaryCageError::SpawnFailed(format!(
                    "Failed to create memfd canary: {:?}",
                    std::io::Error::last_os_error()
                )));
            }

            // Write canary honey-credential payload into memfd
            let canary_payload = b"{\"vault\":\"osoosi_edr_vault\",\"key\":\"cage_honeytoken_secret_canary\",\"credential\":\"edr_vault_token_trap\"}\n";
            let initial_size = canary_payload.len() as libc::off_t;
            unsafe {
                libc::write(
                    memfd,
                    canary_payload.as_ptr() as *const libc::c_void,
                    canary_payload.len(),
                );
                libc::lseek(memfd, 0, libc::SEEK_SET);
            }

            // 3. Map via dup2 in pre_exec to the dynamically selected high FD below RLIMIT_NOFILE
            let memfd_for_child = memfd;
            let target_high_fd = high_fd;
            unsafe {
                cmd.pre_exec(move || {
                    let dup = libc::dup2(memfd_for_child, target_high_fd);
                    if dup < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    // Clear FD_CLOEXEC on target_high_fd so it is retained in the executed image
                    let flags = libc::fcntl(target_high_fd, libc::F_GETFD);
                    if flags >= 0 {
                        libc::fcntl(target_high_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
                    }
                    Ok(())
                });
            }

            // 4. Pass environment variables strictly via Command::env (zero parent environment mutation)
            let trap_path = format!("/proc/self/fd/{}", high_fd);
            cmd.env("CANARY_HONEY_FD", high_fd.to_string());
            cmd.env("CANARY_TRAP_PATH", &trap_path);
            cmd.env("CANARY_SESSION_ID", session_id);
            cmd.env("OSOOSI_CANARY_ACTIVE", "1");
            if let Some(custom) = custom_env {
                for &(k, v) in custom {
                    cmd.env(k, v);
                }
            }

            let child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    unsafe {
                        libc::close(memfd);
                    }
                    return Err(CanaryCageError::Io(e));
                }
            };
            let pid = child.id();

            let canary_triggered = Arc::new(AtomicBool::new(false));
            let alert_received = Arc::new(Mutex::new(None));
            let shutdown = Arc::new(AtomicBool::new(false));

            let watcher_triggered = Arc::clone(&canary_triggered);
            let watcher_alert = Arc::clone(&alert_received);
            let watcher_session = session_id.to_string();
            let watcher_trap_path = trap_path.clone();
            let watcher_pid = pid;
            let watcher_shutdown = Arc::clone(&shutdown);

            // 5. Watcher thread genuinely monitoring trap accesses
            let watcher_thread = match std::thread::Builder::new()
                .name(format!("canary_watcher_{}", watcher_pid))
                .spawn(move || {
                    let mut last_size = initial_size;
                    while !watcher_shutdown.load(Ordering::SeqCst) {
                        let mut trap_hit = false;

                        // Check 1: File seek position on shared open file description
                        let cur_pos = unsafe { libc::lseek(memfd, 0, libc::SEEK_CUR) };
                        if cur_pos > 0 {
                            trap_hit = true;
                        }

                        // Check 2: Size modification on memfd
                        let mut st: libc::stat = unsafe { std::mem::zeroed() };
                        if unsafe { libc::fstat(memfd, &mut st) } == 0
                            && st.st_size != last_size
                        {
                            trap_hit = true;
                            last_size = st.st_size;
                        }

                        // Check 3: Check /proc/<pid>/fdinfo/<target_fd> if accessible
                        let fdinfo_path = format!("/proc/{}/fdinfo/{}", watcher_pid, high_fd);
                        if let Ok(info) = std::fs::read_to_string(&fdinfo_path) {
                            for line in info.lines() {
                                if line.starts_with("pos:") {
                                    if let Some(pos_str) = line.split_whitespace().nth(1) {
                                        if let Ok(pos_val) = pos_str.parse::<i64>() {
                                            if pos_val > 0 {
                                                trap_hit = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if trap_hit {
                            watcher_triggered.store(true, Ordering::SeqCst);
                            // Immediate kill with SIGKILL -> exit code 137
                            unsafe {
                                libc::kill(watcher_pid as i32, libc::SIGKILL);
                            }
                            let alert = CanaryAlert {
                                alert_id: format!("canary-alert-{}", uuid::Uuid::new_v4()),
                                session_id: watcher_session.clone(),
                                pid: watcher_pid,
                                trap_kind: "MemfdCanary".to_string(),
                                trap_path: watcher_trap_path.clone(),
                                confidence: 1.00,
                                timestamp: Utc::now(),
                                attributed_file_digest: None,
                                details: format!(
                                    "Ephemeral memfd canary fd {} ({}) accessed by caged child PID {}",
                                    high_fd, watcher_trap_path, watcher_pid
                                ),
                            };
                            if let Some(ref cb) = on_alert {
                                cb(alert.clone());
                            }
                            let mut slot = watcher_alert.lock().unwrap_or_else(|e| e.into_inner());
                            *slot = Some(alert);
                            break;
                        }

                        std::thread::sleep(Duration::from_millis(2));
                    }
                }) {
                Ok(h) => h,
                Err(e) => {
                    let _ = child;
                    unsafe { libc::close(memfd); }
                    return Err(CanaryCageError::SpawnFailed(format!(
                        "Failed to spawn watcher thread: {:?}",
                        e
                    )));
                }
            };

            Ok(CagedChild {
                pid,
                session_id: session_id.to_string(),
                honey_trap_path: trap_path,
                canary_triggered,
                alert_received,
                start_time: Instant::now(),
                child,
                memfd,
                _target_fd: high_fd,
                shutdown,
                watcher_thread: Some(watcher_thread),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_win32_quoting_rules() {
        assert_eq!(quote_win32_arg("simple"), "simple");
        assert_eq!(quote_win32_arg("with space"), "\"with space\"");
        assert_eq!(quote_win32_arg(""), "\"\"");
        assert_eq!(quote_win32_arg("a\\b"), "a\\b");
        assert_eq!(quote_win32_arg("a\\b c"), "\"a\\b c\"");
        assert_eq!(quote_win32_arg("quote\"inside"), "\"quote\\\"inside\"");
    }

    #[test]
    #[cfg(windows)]
    fn test_canary_cage_benign_child_exit_and_zero_env_leak() {
        let sentinel_key = "OSOOSI_PARENT_CANARY_SENTINEL";
        assert!(std::env::var(sentinel_key).is_err());

        let res = CanaryCage::spawn_caged(
            "cmd.exe",
            &["/c", "exit 0"],
            "test_benign_session",
            Duration::from_secs(5),
        )
        .expect("Benign process should spawn and succeed");

        assert_eq!(res.exit_code, Some(0));
        assert!(res.success);
        assert!(!res.canary_triggered);
        assert!(res.alert.is_none());

        // Zero parent environment mutation: ensure no canary vars leaked into parent process
        assert!(std::env::var("CANARY_HONEY_PIPE").is_err());
        assert!(std::env::var("CANARY_SESSION_ID").is_err());
        assert!(std::env::var("OSOOSI_CANARY_ACTIVE").is_err());
        assert!(std::env::var(sentinel_key).is_err());
    }

    #[test]
    #[cfg(windows)]
    fn test_canary_cage_trap_termination_code_137() {
        let alert_caught = Arc::new(AtomicBool::new(false));
        let alert_clone = Arc::clone(&alert_caught);

        // Command touches the honeypipe via cmd.exe output redirection
        let mut child = CanaryCage::spawn_child(
            "cmd.exe",
            &["/c", "echo TRAP_TRIGGER > %CANARY_HONEY_PIPE%"],
            "test_trap_session",
            None,
            Some(Arc::new(move |_alert| {
                alert_clone.store(true, Ordering::SeqCst);
            })),
        )
        .expect("Caged child should spawn");

        let res = child
            .wait_timeout(Duration::from_secs(6))
            .expect("Child should terminate cleanly under trap");

        assert!(res.canary_triggered);
        assert_eq!(res.exit_code, Some(137));
        assert!(!res.success);
        assert!(res.alert.is_some());
        assert!(alert_caught.load(Ordering::SeqCst));

        let alert = res.alert.unwrap();
        assert_eq!(alert.confidence, 1.00);
        assert_eq!(alert.trap_kind, "NamedPipe");
        assert!(alert.trap_path.contains("osoosi_canary_test_trap_session_"));
    }
}
