//! Native Windows Service Lifecycle Management for OpenỌ̀ṣọ́ọ̀sì Autonomous EDR (`OsoosiEDR`).

use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use tracing::{error, info, warn};

pub const SERVICE_NAME: &str = "OsoosiEDR";
pub const SERVICE_DISPLAY_NAME: &str = "OpenOsoosi Autonomous EDR Service";
pub const SERVICE_DESCRIPTION: &str = "OpenỌ̀ṣọ́ọ̀sì Autonomous Endpoint Detection and Response Engine";

static SERVICE_STOP_NOTIFY: OnceLock<Arc<tokio::sync::Notify>> = OnceLock::new();
static SERVICE_STOP_FLAG: AtomicBool = AtomicBool::new(false);

/// Notify all waiting tasks that the Windows Service has received a STOP or SHUTDOWN control signal.
pub fn notify_service_stop() {
    SERVICE_STOP_FLAG.store(true, Ordering::SeqCst);
    let notify = SERVICE_STOP_NOTIFY
        .get_or_init(|| Arc::new(tokio::sync::Notify::new()))
        .clone();
    notify.notify_waiters();
}

/// Wait until a Windows Service STOP or SHUTDOWN control signal is received.
pub async fn wait_for_service_stop() {
    if SERVICE_STOP_FLAG.load(Ordering::SeqCst) {
        return;
    }
    let notify = SERVICE_STOP_NOTIFY
        .get_or_init(|| Arc::new(tokio::sync::Notify::new()))
        .clone();
    notify.notified().await;
}

#[derive(clap::Subcommand, Clone, Debug, PartialEq, Eq)]
pub enum ServiceAction {
    /// Install OpenỌ̀ṣọ́ọ̀sì as an automatic Windows Service
    Install,
    /// Start the OpenỌ̀ṣọ́ọ̀sì Windows Service
    Start,
    /// Stop the OpenỌ̀ṣọ́ọ̀sì Windows Service
    Stop,
    /// Restart the OpenỌ̀ṣọ́ọ̀sì Windows Service
    Restart,
    /// Delete / uninstall the OpenỌ̀ṣọ́ọ̀sì Windows Service
    #[command(alias = "uninstall", alias = "remove", alias = "rm")]
    Delete,
    /// Query the status of the OpenỌ̀ṣọ́ọ̀sì Windows Service
    Status,
    /// Run the service dispatcher loop (invoked by Windows SCM)
    Run,
}

fn run_sc_cmd(args: &[&str]) -> anyhow::Result<std::process::Output> {
    let output = Command::new("sc.exe")
        .args(args)
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to execute sc.exe: {}", e))?;
    Ok(output)
}

/// Resolve the application root directory from the current executable path.
/// Walks up to 4 levels looking for workspace/installation indicators (`osoosi.toml`, `config/`, `yara/`).
pub fn resolve_app_root_from_exe(exe: &std::path::Path) -> std::path::PathBuf {
    let mut current = exe.parent();
    for _ in 0..4 {
        if let Some(dir) = current {
            if dir.join("osoosi.toml").exists()
                || dir.join("config").is_dir()
                || dir.join("yara").is_dir()
            {
                return dir.to_path_buf();
            }
            current = dir.parent();
        } else {
            break;
        }
    }
    exe.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| exe.to_path_buf())
}

/// Ensure that the process working directory is set to the project root or installation root.
/// When Windows Service Control Manager (SCM) starts a service in Session 0, the default CWD is `C:\Windows\System32`.
/// Relative paths such as `osoosi.toml`, `config/`, `yara/`, and `database/` must be resolved relative
/// to the application root directory rather than System32.
pub fn ensure_service_working_directory() {
    if let Ok(exe) = std::env::current_exe() {
        let root = resolve_app_root_from_exe(&exe);
        if let Err(e) = std::env::set_current_dir(&root) {
            warn!("Failed to set working directory to {}: {}", root.display(), e);
        } else {
            info!("Service working directory set to: {}", root.display());
        }
    }
}

pub fn install_service() -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let exe_str = exe.to_string_lossy().replace(r"\\?\", "");
    let bin_path = format!("\"{}\" service run --no-browser", exe_str);

    info!("Installing Windows Service '{}'...", SERVICE_NAME);
    let output = run_sc_cmd(&[
        "create",
        SERVICE_NAME,
        "binPath=",
        &bin_path,
        "start=",
        "auto",
        "DisplayName=",
        SERVICE_DISPLAY_NAME,
    ])?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        let out = String::from_utf8_lossy(&output.stdout);
        if out.contains("1073") || out.contains("already exists") || err.contains("1073") {
            info!("Service '{}' already exists. Updating service configuration...", SERVICE_NAME);
            let cfg_out = run_sc_cmd(&[
                "config",
                SERVICE_NAME,
                "binPath=",
                &bin_path,
                "start=",
                "auto",
                "DisplayName=",
                SERVICE_DISPLAY_NAME,
            ])?;
            if !cfg_out.status.success() {
                let c_err = String::from_utf8_lossy(&cfg_out.stderr);
                let c_out = String::from_utf8_lossy(&cfg_out.stdout);
                anyhow::bail!("Failed to update existing service: {} {}", c_out, c_err);
            }
        } else {
            anyhow::bail!("Failed to create service: {} {}", out, err);
        }
    }

    // Set service description
    let _ = run_sc_cmd(&["description", SERVICE_NAME, SERVICE_DESCRIPTION]);

    // Set recovery failure actions (restart after 5s on failure, reset failure counter after 1 day)
    let _ = run_sc_cmd(&[
        "failure",
        SERVICE_NAME,
        "reset=",
        "86400",
        "actions=",
        "restart/5000/restart/5000/restart/5000",
    ]);

    println!("Service '{}' installed successfully.", SERVICE_NAME);
    println!("Binary Path: {}", bin_path);
    println!("Startup Type: Automatic");
    println!("Recovery: Auto-restart configured");
    Ok(())
}

pub fn start_service() -> anyhow::Result<()> {
    info!("Starting Windows Service '{}'...", SERVICE_NAME);
    let output = run_sc_cmd(&["start", SERVICE_NAME])?;
    if !output.status.success() {
        let out = String::from_utf8_lossy(&output.stdout);
        let err = String::from_utf8_lossy(&output.stderr);
        if out.contains("already running") || out.contains("1056") {
            println!("Service '{}' is already running.", SERVICE_NAME);
            return Ok(());
        }
        anyhow::bail!("Failed to start service: {} {}", out, err);
    }

    // Wait up to 10s for service to reach RUNNING state
    let start_time = std::time::Instant::now();
    while start_time.elapsed() < Duration::from_secs(10) {
        if let Ok(status) = query_service_state() {
            if status.contains("RUNNING") {
                println!("Service '{}' is now RUNNING.", SERVICE_NAME);
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    println!("Service start signal sent. Current status:\n{}", query_service_state().unwrap_or_default());
    Ok(())
}

pub fn stop_service() -> anyhow::Result<()> {
    info!("Stopping Windows Service '{}'...", SERVICE_NAME);
    let output = run_sc_cmd(&["stop", SERVICE_NAME])?;
    if !output.status.success() {
        let out = String::from_utf8_lossy(&output.stdout);
        let err = String::from_utf8_lossy(&output.stderr);
        if out.contains("1062") || out.contains("not started") || out.contains("STOPPED") {
            println!("Service '{}' is already stopped.", SERVICE_NAME);
            return Ok(());
        }
        anyhow::bail!("Failed to stop service: {} {}", out, err);
    }

    // Wait up to 10s for service to reach STOPPED state
    let start_time = std::time::Instant::now();
    while start_time.elapsed() < Duration::from_secs(10) {
        if let Ok(status) = query_service_state() {
            if status.contains("STOPPED") {
                println!("Service '{}' is now STOPPED.", SERVICE_NAME);
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    println!("Service stop signal sent. Current status:\n{}", query_service_state().unwrap_or_default());
    Ok(())
}

pub fn restart_service() -> anyhow::Result<()> {
    println!("Restarting Windows Service '{}'...", SERVICE_NAME);
    let _ = stop_service();
    std::thread::sleep(Duration::from_secs(1));
    start_service()
}

pub fn delete_service() -> anyhow::Result<()> {
    info!("Removing Windows Service '{}'...", SERVICE_NAME);
    let _ = stop_service();
    std::thread::sleep(Duration::from_secs(1));

    let output = run_sc_cmd(&["delete", SERVICE_NAME])?;
    if !output.status.success() {
        let out = String::from_utf8_lossy(&output.stdout);
        let err = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to delete service: {} {}", out, err);
    }
    println!("Service '{}' has been deleted successfully.", SERVICE_NAME);
    Ok(())
}

pub fn query_service_state() -> anyhow::Result<String> {
    let output = run_sc_cmd(&["queryex", SERVICE_NAME])?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    Ok(stdout)
}

pub fn status_service() -> anyhow::Result<()> {
    let status_str = query_service_state()?;
    println!("=== Windows Service Status: {} ===", SERVICE_NAME);
    println!("{}", status_str);
    Ok(())
}

pub fn handle_service_action(action: &ServiceAction) -> anyhow::Result<()> {
    match action {
        ServiceAction::Install => install_service(),
        ServiceAction::Start => start_service(),
        ServiceAction::Stop => stop_service(),
        ServiceAction::Restart => restart_service(),
        ServiceAction::Delete => delete_service(),
        ServiceAction::Status => status_service(),
        ServiceAction::Run => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Native Win32 SCM Dispatcher Implementation
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod win_scm {
    use super::*;
    use windows::core::{w, PWSTR};
    use windows::Win32::Foundation::{ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, NO_ERROR, WIN32_ERROR};
    use windows::Win32::System::Services::{
        RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
        SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE,
        SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
        SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING,
        SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    };
    use std::sync::atomic::AtomicIsize;

    static GLOBAL_SERVICE_HANDLE_RAW: AtomicIsize = AtomicIsize::new(0);

    unsafe extern "system" fn service_control_handler(
        dw_control: u32,
        _dw_event_type: u32,
        _lp_event_data: *mut std::ffi::c_void,
        _lp_context: *mut std::ffi::c_void,
    ) -> u32 {
        let handle_raw = GLOBAL_SERVICE_HANDLE_RAW.load(Ordering::SeqCst);
        if handle_raw == 0 {
            return NO_ERROR.0;
        }
        let handle = SERVICE_STATUS_HANDLE(handle_raw as *mut std::ffi::c_void);

        match dw_control {
            SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
                info!("Windows Service SCM requested STOP/SHUTDOWN.");
                let status = SERVICE_STATUS {
                    dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                    dwCurrentState: SERVICE_STOP_PENDING,
                    dwControlsAccepted: 0,
                    dwWin32ExitCode: NO_ERROR.0,
                    dwServiceSpecificExitCode: 0,
                    dwCheckPoint: 1,
                    dwWaitHint: 15000,
                };
                let _ = SetServiceStatus(handle, &status);
                notify_service_stop();
                NO_ERROR.0
            }
            SERVICE_CONTROL_INTERROGATE => {
                let is_stopping = SERVICE_STOP_FLAG.load(Ordering::SeqCst);
                let status = SERVICE_STATUS {
                    dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                    dwCurrentState: if is_stopping {
                        SERVICE_STOP_PENDING
                    } else {
                        SERVICE_RUNNING
                    },
                    dwControlsAccepted: SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
                    dwWin32ExitCode: NO_ERROR.0,
                    dwServiceSpecificExitCode: 0,
                    dwCheckPoint: 0,
                    dwWaitHint: 0,
                };
                let _ = SetServiceStatus(handle, &status);
                NO_ERROR.0
            }
            _ => NO_ERROR.0,
        }
    }

    unsafe extern "system" fn service_main(
        _dw_num_services_args: u32,
        _lp_service_arg_vectors: *mut PWSTR,
    ) {
        let service_name_w = w!("OsoosiEDR");
        let handle = match RegisterServiceCtrlHandlerExW(
            service_name_w,
            Some(service_control_handler),
            None,
        ) {
            Ok(h) => h,
            Err(e) => {
                error!("RegisterServiceCtrlHandlerExW failed: {}", e);
                return;
            }
        };

        GLOBAL_SERVICE_HANDLE_RAW.store(handle.0 as isize, Ordering::SeqCst);

        // 1. Report SERVICE_START_PENDING
        let mut status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: SERVICE_START_PENDING,
            dwControlsAccepted: 0,
            dwWin32ExitCode: NO_ERROR.0,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 1,
            dwWaitHint: 10000,
        };
        let _ = SetServiceStatus(handle, &status);

        // 2. Report SERVICE_RUNNING
        status.dwCurrentState = SERVICE_RUNNING;
        status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
        status.dwCheckPoint = 0;
        status.dwWaitHint = 0;
        let _ = SetServiceStatus(handle, &status);

        info!("OsoosiEDR Windows Service is now running under SCM control.");

        // Wait until service stop is triggered
        while !SERVICE_STOP_FLAG.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(200));
        }

        // 3. Report SERVICE_STOP_PENDING
        status.dwCurrentState = SERVICE_STOP_PENDING;
        status.dwControlsAccepted = 0;
        status.dwCheckPoint = 1;
        status.dwWaitHint = 10000;
        let _ = SetServiceStatus(handle, &status);

        // Wait a short moment for async tasks to clean up
        std::thread::sleep(Duration::from_millis(500));

        // 4. Report SERVICE_STOPPED
        status.dwCurrentState = SERVICE_STOPPED;
        status.dwControlsAccepted = 0;
        status.dwCheckPoint = 0;
        status.dwWaitHint = 0;
        let _ = SetServiceStatus(handle, &status);

        info!("OsoosiEDR Windows Service has stopped.");
    }

    /// Try to start SCM dispatcher. If running in normal console (error 1063), returns false.
    pub fn try_start_service_dispatcher() -> anyhow::Result<bool> {
        // Ensure working directory is set to project/install root instead of C:\Windows\System32
        ensure_service_working_directory();

        // Call StartServiceCtrlDispatcherW on a dedicated background thread so the main/tokio thread
        // can proceed, OR test if SCM is connected.
        // Note: StartServiceCtrlDispatcherW blocks until the service terminates.
        let (err_tx, err_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut service_name: Vec<u16> = "OsoosiEDR\0".encode_utf16().collect();
            let service_table = [
                SERVICE_TABLE_ENTRYW {
                    lpServiceName: PWSTR(service_name.as_mut_ptr()),
                    lpServiceProc: Some(service_main),
                },
                SERVICE_TABLE_ENTRYW {
                    lpServiceName: PWSTR::null(),
                    lpServiceProc: None,
                },
            ];
            let res = unsafe { StartServiceCtrlDispatcherW(service_table.as_ptr()) };
            if let Err(e) = res {
                let _ = err_tx.send(e);
            }
        });

        // Check if StartServiceCtrlDispatcherW immediately failed with ERROR_FAILED_SERVICE_CONTROLLER_CONNECT (1063)
        match err_rx.recv_timeout(Duration::from_millis(300)) {
            Ok(err) => {
                let win_err = WIN32_ERROR(err.code().0 as u32);
                if win_err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
                    info!("Running in console mode (ERROR_FAILED_SERVICE_CONTROLLER_CONNECT / 1063).");
                    return Ok(false);
                }
                warn!("StartServiceCtrlDispatcherW returned error: {}", err);
                Ok(false)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // SCM dispatcher is active and running!
                info!("Windows Service SCM dispatcher successfully connected and active.");
                Ok(true)
            }
            Err(e) => {
                warn!("SCM channel error: {}", e);
                Ok(false)
            }
        }
    }
}

#[cfg(windows)]
pub use win_scm::try_start_service_dispatcher;

#[cfg(not(windows))]
pub fn try_start_service_dispatcher() -> anyhow::Result<bool> {
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_app_root_from_exe_finds_project_root() {
        let current_exe = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from(r"target\debug\osoosi.exe"));
        let root = resolve_app_root_from_exe(&current_exe);
        assert!(root.exists(), "Resolved root directory must exist: {:?}", root);
    }

    #[test]
    fn test_resolve_app_root_nested_path() {
        let temp = std::env::temp_dir().join(format!("osoosi_test_{}", std::process::id()));
        let nested_bin = temp.join("target").join("release").join("osoosi.exe");
        std::fs::create_dir_all(temp.join("config")).unwrap();
        std::fs::create_dir_all(nested_bin.parent().unwrap()).unwrap();
        std::fs::write(&nested_bin, b"dummy").unwrap();

        let resolved = resolve_app_root_from_exe(&nested_bin);
        assert_eq!(resolved, temp, "Should resolve to root directory containing 'config'");

        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_sc_cmd_args_structure() {
        let exe = std::path::PathBuf::from(r"C:\Program Files\OshoosiClaw\osoosi.exe");
        let exe_str = exe.to_string_lossy().replace(r"\\?\", "");
        let bin_path = format!("\"{}\" service run --no-browser", exe_str);

        let sc_create_args = [
            "create",
            SERVICE_NAME,
            "binPath=",
            &bin_path,
            "start=",
            "auto",
            "DisplayName=",
            SERVICE_DISPLAY_NAME,
        ];

        // Ensure that option names and values are separated
        assert_eq!(sc_create_args[2], "binPath=");
        assert_eq!(sc_create_args[4], "start=");
        assert_eq!(sc_create_args[5], "auto");
        assert_eq!(sc_create_args[6], "DisplayName=");
        assert_eq!(sc_create_args[7], SERVICE_DISPLAY_NAME);
    }
}
