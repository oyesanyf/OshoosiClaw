//! Native Windows Service Lifecycle Management for OpenỌ̀ṣọ́ọ̀sì Autonomous EDR (`OsoosiEDR`).

use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use tracing::{error, info, warn};

pub const SERVICE_NAME: &str = "OsoosiEDR";
pub const SERVICE_DISPLAY_NAME: &str = "OpenOsoosi Autonomous EDR Service";
pub const SERVICE_DESCRIPTION: &str =
    "OpenỌ̀ṣọ́ọ̀sì Autonomous Endpoint Detection and Response Engine";

static SERVICE_STOP_NOTIFY: OnceLock<Arc<tokio::sync::Notify>> = OnceLock::new();
static SERVICE_STOP_FLAG: AtomicBool = AtomicBool::new(false);
static SERVICE_SHUTDOWN_DONE: AtomicBool = AtomicBool::new(false);

/// Notify all waiting tasks that the Windows Service has received a STOP or SHUTDOWN control signal.
pub fn notify_service_stop() {
    SERVICE_STOP_FLAG.store(true, Ordering::SeqCst);
    let notify = SERVICE_STOP_NOTIFY
        .get_or_init(|| Arc::new(tokio::sync::Notify::new()))
        .clone();
    notify.notify_waiters();
}

/// Notify the Windows SCM dispatcher that daemon cleanup and socket shutdown is complete.
pub fn notify_service_shutdown_complete() {
    SERVICE_SHUTDOWN_DONE.store(true, Ordering::SeqCst);
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
    let output = Command::new(osoosi_types::resolve_system_binary("sc.exe"))
        .args(args)
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to execute sc.exe: {}", e))?;
    Ok(output)
}

#[cfg(windows)]
pub fn force_terminate_service_pid() -> anyhow::Result<()> {
    if let Ok(output) = run_sc_cmd(&["queryex", SERVICE_NAME]) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if let Some(rest) = line.trim().strip_prefix("PID") {
                if let Some(pid_str) = rest.trim().strip_prefix(':') {
                    if let Ok(pid) = pid_str.trim().parse::<u32>() {
                        if pid > 4 {
                            info!("Force terminating stuck service PID {}", pid);
                            let _ = Command::new(osoosi_types::resolve_system_binary("taskkill.exe"))
                                .args(["/F", "/T", "/PID", &pid.to_string()])
                                .stdout(std::process::Stdio::null())
                                .stderr(std::process::Stdio::null())
                                .status();
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn force_terminate_service_pid() -> anyhow::Result<()> {
    Ok(())
}

pub fn is_running_under_service_control() -> bool {
    #[cfg(windows)]
    {
        win_scm::is_service_dispatcher_active()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Resolve the application root directory from the current executable path.
/// Walks up to 5 levels looking for workspace/installation indicators (`osoosi.toml`, `config/`, `yara/`, `Cargo.toml`).
pub fn resolve_app_root_from_exe(exe: &std::path::Path) -> std::path::PathBuf {
    let mut current = exe.parent();
    for _ in 0..5 {
        if let Some(dir) = current {
            if dir.join("osoosi.toml").exists()
                || dir.join("config").is_dir()
                || dir.join("yara").is_dir()
                || dir.join("Cargo.toml").exists()
            {
                return dir.to_path_buf();
            }
            current = dir.parent();
        } else {
            break;
        }
    }
    exe.parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| exe.to_path_buf())
}

/// Ensure that the process working directory is set to the project root or installation root.
/// When Windows Service Control Manager (SCM) starts a service in Session 0, the default CWD is `C:\Windows\System32`.
/// Relative paths such as `osoosi.toml`, `config/`, `yara/`, and `database/` must be resolved relative
/// to the application root directory rather than System32.
pub fn ensure_service_working_directory() {
    if let Ok(exe) = std::env::current_exe() {
        let root = resolve_app_root_from_exe(&exe);
        if let Err(e) = std::env::set_current_dir(&root) {
            warn!(
                "Failed to set working directory to {}: {}",
                root.display(),
                e
            );
        } else {
            info!("Service working directory set to: {}", root.display());
        }
    }
}

/// Helper to ensure the command is running with elevated administrator privileges.
/// If not elevated on Windows, requests UAC elevation via PowerShell `Start-Process -Verb RunAs`.
fn ensure_elevated_for_service_action(action_arg: &str) -> anyhow::Result<bool> {
    #[cfg(windows)]
    {
        if osoosi_types::is_elevated() {
            return Ok(false);
        }
        let exe = std::env::current_exe()?;
        let exe_str = exe.to_string_lossy().replace(r"\\?\", "");
        println!(
            "[*] Administrator privileges required for 'osoosi service {}'. Requesting UAC elevation...",
            action_arg
        );
        let ps_cmd_target = format!("service {}", action_arg);
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            GetExitCodeProcess, WaitForSingleObject, INFINITE,
        };
        use windows::Win32::UI::Shell::{
            ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
        };
        use windows::Win32::UI::WindowsAndMessaging::SW_SHOW;

        let wide_verb: Vec<u16> = "runas".encode_utf16().chain(std::iter::once(0)).collect();
        let wide_file: Vec<u16> = exe_str.encode_utf16().chain(std::iter::once(0)).collect();
        let wide_params: Vec<u16> = ps_cmd_target
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut info = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS,
            lpVerb: PCWSTR(wide_verb.as_ptr()),
            lpFile: PCWSTR(wide_file.as_ptr()),
            lpParameters: PCWSTR(wide_params.as_ptr()),
            nShow: SW_SHOW.0,
            ..Default::default()
        };

        let success = unsafe { ShellExecuteExW(&mut info).is_ok() };
        if !success || info.hProcess.is_invalid() {
            anyhow::bail!(
                "Elevated 'osoosi service {}' failed or UAC prompt was declined.",
                action_arg
            );
        }

        let mut exit_code: u32 = 0;
        unsafe {
            WaitForSingleObject(info.hProcess, INFINITE);
            let _ = GetExitCodeProcess(info.hProcess, &mut exit_code);
            let _ = CloseHandle(info.hProcess);
        }

        if exit_code == 0 {
            println!(
                "[+] Service action '{}' completed successfully.",
                action_arg
            );
            if action_arg != "delete" {
                if let Ok(state) = query_service_state() {
                    println!("{}", state);
                }
            }
            Ok(true)
        } else {
            anyhow::bail!(
                "Elevated 'osoosi service {}' failed or UAC prompt was declined (exit code: {}).",
                action_arg,
                exit_code
            );
        }
    }
    #[cfg(not(windows))]
    {
        let _ = action_arg;
        Ok(false)
    }
}

pub fn is_dashboard_port_listening(port: u16) -> bool {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_millis(300)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = stream.set_write_timeout(Some(Duration::from_millis(400)));
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    if stream
        .write_all(b"GET /health HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buf = [0u8; 64];
    match stream.read(&mut buf) {
        Ok(n) if n > 0 => {
            let resp = String::from_utf8_lossy(&buf[..n]);
            resp.starts_with("HTTP/1.")
        }
        _ => false,
    }
}

pub fn wait_for_dashboard_ready(port: u16, timeout_secs: u64) -> bool {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);
    while start.elapsed() < timeout {
        if is_dashboard_port_listening(port) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    false
}

#[cfg(windows)]
pub fn spawn_detached_background_daemon() -> anyhow::Result<u32> {
    use std::os::windows::process::CommandExt;
    let exe = std::env::current_exe()?;
    let app_root = resolve_app_root_from_exe(&exe);
    let exe_clean = exe.to_string_lossy().replace(r"\\?\", "");
    let root_clean = app_root.to_string_lossy().replace(r"\\?\", "");
    info!(
        "Spawning detached background daemon: {} from {}",
        exe_clean, root_clean
    );

    // Spawn daemon process with CREATE_BREAKAWAY_FROM_JOB | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
    // so it is immune to parent terminal/shell Job Object closure without spawning powershell.
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x01000000;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
    const DETACHED_PROCESS: u32 = 0x00000008;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let child = Command::new(&exe)
        .arg("start")
        .arg("--no-browser")
        .current_dir(&app_root)
        .creation_flags(
            CREATE_BREAKAWAY_FROM_JOB
                | CREATE_NEW_PROCESS_GROUP
                | DETACHED_PROCESS
                | CREATE_NO_WINDOW,
        )
        .spawn()
        .or_else(|_| {
            Command::new(&exe)
                .arg("start")
                .arg("--no-browser")
                .current_dir(&app_root)
                .creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS | CREATE_NO_WINDOW)
                .spawn()
        })?;
    let pid = child.id();
    info!("Detached background daemon spawned with PID: {}", pid);
    Ok(pid)
}

#[cfg(not(windows))]
pub fn spawn_detached_background_daemon() -> anyhow::Result<u32> {
    use std::os::unix::process::CommandExt;
    let exe = std::env::current_exe()?;
    let app_root = resolve_app_root_from_exe(&exe);
    info!(
        "Spawning detached Linux/Unix background daemon: {} from {}",
        exe.display(),
        app_root.display()
    );
    let mut cmd = Command::new(&exe);
    cmd.arg("start")
        .arg("--no-browser")
        .current_dir(&app_root)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let child = cmd.spawn()?;
    let pid = child.id();
    info!(
        "Detached Linux/Unix background daemon spawned with PID: {}",
        pid
    );
    Ok(pid)
}

#[cfg(windows)]
pub fn install_service() -> anyhow::Result<()> {
    match ensure_elevated_for_service_action("install") {
        Ok(true) => return Ok(()),
        Ok(false) => {}
        Err(e) => {
            warn!("UAC elevation failed or was declined: {}. Falling back to detached background daemon...", e);
            if !is_dashboard_port_listening(3030) {
                let _ = spawn_detached_background_daemon()?;
            }
            if wait_for_dashboard_ready(3030, 30) {
                println!("[+] WebUI active at: http://127.0.0.1:3030/");
                return Ok(());
            } else {
                anyhow::bail!(
                    "Detached background daemon started but port 3030 did not become ready."
                );
            }
        }
    }
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
            info!(
                "Service '{}' already exists. Updating service configuration...",
                SERVICE_NAME
            );
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

    // Clear forced failure auto-restart actions so stopping or terminating the service never auto-respawns it
    let _ = run_sc_cmd(&[
        "failure",
        SERVICE_NAME,
        "reset=",
        "0",
        "actions=",
        "",
    ]);

    // Grant Interactive Users (IU) and Authenticated Users (AU) service restart privileges without UAC errors
    let _ = Command::new(osoosi_types::resolve_system_binary("sc.exe"))
        .args([
            "sdset",
            SERVICE_NAME,
            "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;IU)(A;;CCLCSWRPWPDTLOCRRC;;;AU)(A;;CCLCSWLOCRRC;;;SU)",
        ])
        .output();

    println!("Service '{}' installed successfully.", SERVICE_NAME);
    println!("Binary Path: {}", bin_path);
    println!("Startup Type: Automatic");
    println!("Recovery: Auto-restart configured");
    let _ = start_service();
    Ok(())
}

#[cfg(windows)]
pub fn start_service() -> anyhow::Result<()> {
    match ensure_elevated_for_service_action("start") {
        Ok(true) => return Ok(()),
        Ok(false) => {}
        Err(e) => {
            warn!("UAC elevation failed or was declined: {}. Falling back to detached background daemon...", e);
            if !is_dashboard_port_listening(3030) {
                let _ = spawn_detached_background_daemon()?;
            }
            if wait_for_dashboard_ready(3030, 30) {
                println!("[+] WebUI active at: http://127.0.0.1:3030/");
                return Ok(());
            } else {
                anyhow::bail!(
                    "Detached background daemon started but port 3030 did not become ready."
                );
            }
        }
    }
    if let Ok(state) = query_service_state() {
        if state.contains("STOP_PENDING") {
            warn!("Service '{}' is stuck in STOP_PENDING. Clearing stale process...", SERVICE_NAME);
            cleanup_stale_service_processes();
            let _ = force_terminate_service_pid();
            let wait_stop = std::time::Instant::now();
            while wait_stop.elapsed() < Duration::from_secs(5) {
                if let Ok(s) = query_service_state() {
                    if s.contains("STOPPED") {
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(300));
            }
        }
    }
    info!("Starting Windows Service '{}'...", SERVICE_NAME);
    let mut output = run_sc_cmd(&["start", SERVICE_NAME])?;
    if !output.status.success() {
        let out = String::from_utf8_lossy(&output.stdout).to_string();
        let _err = String::from_utf8_lossy(&output.stderr).to_string();
        if out.contains("1060")
            || out.contains("does not exist")
            || out.contains("FAILED 2")
            || out.contains("FAILED 3")
            || out.contains("1058")
            || out.contains("cannot find the file")
        {
            info!(
                "Service '{}' missing or misconfigured on host ({}). Auto-registering service...",
                SERVICE_NAME,
                out.trim()
            );
            if let Ok(exe) = std::env::current_exe() {
                let exe_str = exe.to_string_lossy().replace(r"\\?\", "");
                let bin_path = format!("\"{}\" service run --no-browser", exe_str);
                let _ = run_sc_cmd(&[
                    "create",
                    SERVICE_NAME,
                    "binPath=",
                    &bin_path,
                    "start=",
                    "auto",
                    "DisplayName=",
                    SERVICE_DISPLAY_NAME,
                ]);
                let _ = run_sc_cmd(&[
                    "config",
                    SERVICE_NAME,
                    "binPath=",
                    &bin_path,
                    "start=",
                    "auto",
                    "DisplayName=",
                    SERVICE_DISPLAY_NAME,
                ]);
                let _ = run_sc_cmd(&["description", SERVICE_NAME, SERVICE_DESCRIPTION]);
                let _ = run_sc_cmd(&[
                    "failure",
                    SERVICE_NAME,
                    "reset=",
                    "0",
                    "actions=",
                    "",
                ]);
                let _ = run_sc_cmd(&[
                    "sdset",
                    SERVICE_NAME,
                    "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;IU)(A;;CCLCSWRPWPDTLOCRRC;;;AU)(A;;CCLCSWLOCRRC;;;SU)",
                ]);
                output = run_sc_cmd(&["start", SERVICE_NAME])?;
            }
        }

        if !output.status.success() {
            let out = String::from_utf8_lossy(&output.stdout);
            let err = String::from_utf8_lossy(&output.stderr);
            if out.contains("already running") || out.contains("1056") {
                if let Ok(state) = query_service_state() {
                    if state.contains("STOP_PENDING") {
                        warn!(
                            "Service '{}' is stuck in STOP_PENDING on error 1056. Forcing termination...",
                            SERVICE_NAME
                        );
                        let _ = force_terminate_service_pid();
                        std::thread::sleep(Duration::from_secs(1));
                        output = run_sc_cmd(&["start", SERVICE_NAME])?;
                    }
                }
                if output.status.success() {
                    println!(
                        "Service '{}' started successfully after clearing STOP_PENDING.",
                        SERVICE_NAME
                    );
                } else {
                    println!("Service '{}' is already running.", SERVICE_NAME);
                }
            } else if out.contains("Access is denied")
                || err.contains("Access is denied")
                || out.contains("FAILED 5")
            {
                warn!("SCM start access denied. Falling back to detached background daemon...");
                if !is_dashboard_port_listening(3030) {
                    let _ = spawn_detached_background_daemon()?;
                }
                if wait_for_dashboard_ready(3030, 30) {
                    println!("[+] WebUI active at: http://127.0.0.1:3030/");
                    return Ok(());
                } else {
                    anyhow::bail!("Detached daemon started but WebUI port 3030 failed to respond.");
                }
            } else {
                anyhow::bail!("Failed to start service: {} {}", out, err);
            }
        }
    }

    // Wait up to 10s for service to reach RUNNING state
    let start_time = std::time::Instant::now();
    let mut is_running = false;
    while start_time.elapsed() < Duration::from_secs(10) {
        if let Ok(status) = query_service_state() {
            if status.contains("RUNNING") {
                println!("Service '{}' is now RUNNING.", SERVICE_NAME);
                is_running = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    if !is_running {
        println!(
            "Service start signal sent. Current status:\n{}",
            query_service_state().unwrap_or_default()
        );
    }

    // Wait up to 30s for WebUI port 3030 to be ready
    println!("[*] Waiting for WebUI (http://127.0.0.1:3030) to bind...");
    if wait_for_dashboard_ready(3030, 30) {
        println!("[+] WebUI active at: http://127.0.0.1:3030/");
    } else {
        warn!("Port 3030 not ready from Windows Service. Launching detached daemon fallback...");
        let _ = spawn_detached_background_daemon();
        if wait_for_dashboard_ready(3030, 20) {
            println!("[+] WebUI active at: http://127.0.0.1:3030/");
        }
    }

    Ok(())
}

#[cfg(windows)]
pub fn stop_service() -> anyhow::Result<()> {
    info!("Stopping Windows Service '{}'...", SERVICE_NAME);

    // Clear any SCM failure auto-restart actions so stopping or terminating never respawns the daemon
    let _ = run_sc_cmd(&["failure", SERVICE_NAME, "reset=", "0", "actions=", ""]);

    // Attempt direct stop first (Interactive Users have SERVICE_STOP permission via service DACL)
    let output = run_sc_cmd(&["stop", SERVICE_NAME])?;
    if !output.status.success() {
        let out = String::from_utf8_lossy(&output.stdout);
        let err = String::from_utf8_lossy(&output.stderr);
        if out.contains("1062")
            || out.contains("not started")
            || out.contains("STOPPED")
            || out.contains("1060")
            || out.contains("does not exist")
        {
            cleanup_stale_service_processes();
            let _ = osoosi_core::killchain::execute_host_disarm_unauthenticated();
            let _ = osoosi_core::firewall::remove_all_autoblock_rules();
            println!(
                "Service '{}' is already stopped. Host network restored.",
                SERVICE_NAME
            );
            return Ok(());
        }
        if (out.contains("Access is denied")
            || err.contains("Access is denied")
            || out.contains("FAILED 5"))
            && !osoosi_types::is_elevated()
        {
            if ensure_elevated_for_service_action("stop")? {
                return Ok(());
            }
        }
    }

    // Wait up to 3s for service to reach STOPPED state and PID : 0
    let start_time = std::time::Instant::now();
    while start_time.elapsed() < Duration::from_secs(3) {
        if let Ok(status) = query_service_state() {
            if status.contains("STOPPED")
                && (status.contains("PID                : 0") || !status.contains("PID"))
            {
                cleanup_stale_service_processes();
                let _ = osoosi_core::killchain::execute_host_disarm_unauthenticated();
                let _ = osoosi_core::firewall::remove_all_autoblock_rules();
                println!("Service '{}' is now STOPPED.", SERVICE_NAME);
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    if let Ok(status) = query_service_state() {
        if status.contains("STOP_PENDING") || status.contains("RUNNING") {
            warn!(
                "Service '{}' still active after 3s; force terminating PID...",
                SERVICE_NAME
            );
            let _ = force_terminate_service_pid();
            std::thread::sleep(Duration::from_millis(400));
        }
    }

    cleanup_stale_service_processes();
    let _ = osoosi_core::killchain::execute_host_disarm_unauthenticated();
    let _ = osoosi_core::firewall::remove_all_autoblock_rules();
    println!(
        "Service '{}' is now STOPPED.\n{}",
        SERVICE_NAME,
        query_service_state().unwrap_or_default()
    );
    Ok(())
}

#[cfg(windows)]
pub fn restart_service() -> anyhow::Result<()> {
    if ensure_elevated_for_service_action("restart")? {
        return Ok(());
    }
    println!("Restarting Windows Service '{}'...", SERVICE_NAME);
    let _ = stop_service();
    std::thread::sleep(Duration::from_secs(1));
    start_service()
}

#[cfg(windows)]
pub fn delete_service() -> anyhow::Result<()> {
    if let Ok(output) = run_sc_cmd(&["query", SERVICE_NAME]) {
        let out = String::from_utf8_lossy(&output.stdout);
        let err = String::from_utf8_lossy(&output.stderr);
        if out.contains("1060") || out.contains("does not exist") || err.contains("1060") {
            println!(
                "[+] Service '{}' is not installed (already removed).",
                SERVICE_NAME
            );
            return Ok(());
        }
    }

    if ensure_elevated_for_service_action("delete")? {
        return Ok(());
    }
    info!("Removing Windows Service '{}'...", SERVICE_NAME);
    let _ = stop_service();
    std::thread::sleep(Duration::from_secs(1));

    let output = run_sc_cmd(&["delete", SERVICE_NAME])?;
    if !output.status.success() {
        let out = String::from_utf8_lossy(&output.stdout);
        let err = String::from_utf8_lossy(&output.stderr);
        if out.contains("1060") || out.contains("does not exist") || err.contains("1060") {
            println!(
                "[+] Service '{}' is not installed (already removed).",
                SERVICE_NAME
            );
            return Ok(());
        }
        anyhow::bail!("Failed to delete service: {} {}", out, err);
    }
    println!("Service '{}' has been deleted successfully.", SERVICE_NAME);
    Ok(())
}

#[cfg(windows)]
pub fn query_service_state() -> anyhow::Result<String> {
    let output = run_sc_cmd(&["queryex", SERVICE_NAME])?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    Ok(stdout)
}

#[cfg(windows)]
pub fn status_service() -> anyhow::Result<()> {
    let status_str = query_service_state()?;
    println!("=== Windows Service Status: {} ===", SERVICE_NAME);
    println!("{}", status_str);
    Ok(())
}

// ---------------------------------------------------------------------------
// Linux / Unix systemd Service Implementation
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
fn get_systemd_unit_path() -> std::path::PathBuf {
    if osoosi_types::is_elevated() {
        std::path::PathBuf::from("/etc/systemd/system/osoosi-edr.service")
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        std::path::PathBuf::from(home).join(".config/systemd/user/osoosi-edr.service")
    }
}

#[cfg(not(windows))]
fn is_user_systemd() -> bool {
    !osoosi_types::is_elevated()
}

#[cfg(not(windows))]
fn run_systemctl(args: &[&str]) -> anyhow::Result<std::process::Output> {
    let mut cmd = Command::new("systemctl");
    if is_user_systemd() {
        cmd.arg("--user");
    }
    cmd.args(args);
    let out = cmd
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to execute systemctl: {}", e))?;
    Ok(out)
}

#[cfg(not(windows))]
pub fn install_service() -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let app_root = resolve_app_root_from_exe(&exe);
    let unit_path = get_systemd_unit_path();

    if let Some(parent) = unit_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let wanted_by = if is_user_systemd() {
        "default.target"
    } else {
        "multi-user.target"
    };

    let unit_content = format!(
        "[Unit]
Description=OpenOsoosi Autonomous EDR Service
After=network.target

[Service]
Type=simple
ExecStart={} service run --no-browser
WorkingDirectory={}
Restart=on-failure
RestartSec=5s
TimeoutStopSec=5s
KillMode=process

[Install]
WantedBy={}
",
        exe.display(),
        app_root.display(),
        wanted_by
    );

    match std::fs::write(&unit_path, unit_content) {
        Ok(_) => {
            println!("Installed systemd unit at: {}", unit_path.display());
            let _ = run_systemctl(&["daemon-reload"]);
            let _ = run_systemctl(&["enable", "osoosi-edr.service"]);
            println!("Service 'osoosi-edr' enabled via systemctl.");
            let _ = start_service();
            Ok(())
        }
        Err(e) => {
            warn!("Failed to write systemd unit file ({}): {}. Falling back to detached background daemon...", unit_path.display(), e);
            if !is_dashboard_port_listening(3030) {
                let _ = spawn_detached_background_daemon()?;
            }
            if wait_for_dashboard_ready(3030, 20) {
                println!("[+] WebUI active at: http://127.0.0.1:3030/");
                Ok(())
            } else {
                anyhow::bail!(
                    "Detached background daemon started but port 3030 did not become ready."
                );
            }
        }
    }
}

#[cfg(not(windows))]
pub fn start_service() -> anyhow::Result<()> {
    let mut systemctl_ok = false;
    if let Ok(out) = run_systemctl(&["start", "osoosi-edr.service"]) {
        if out.status.success() {
            println!("Service 'osoosi-edr' started via systemctl.");
            systemctl_ok = true;
        } else {
            let err = String::from_utf8_lossy(&out.stderr);
            warn!("systemctl start osoosi-edr.service failed: {}. Falling back to detached background daemon...", err);
        }
    } else {
        warn!("systemctl unavailable. Falling back to detached background daemon...");
    }

    if !systemctl_ok {
        if !is_dashboard_port_listening(3030) {
            let _ = spawn_detached_background_daemon()?;
        }
    }

    println!("[*] Waiting for WebUI (http://127.0.0.1:3030) to bind...");
    if wait_for_dashboard_ready(3030, 20) {
        println!("[+] WebUI active at: http://127.0.0.1:3030/");
        Ok(())
    } else {
        anyhow::bail!(
            "Service start initiated but WebUI port 3030 failed to respond within 20 seconds."
        );
    }
}

#[cfg(not(windows))]
pub fn stop_service() -> anyhow::Result<()> {
    let _ = osoosi_core::killchain::execute_host_disarm_unauthenticated();
    let _ = osoosi_core::firewall::remove_all_autoblock_rules();
    let _ = run_systemctl(&["stop", "osoosi-edr.service"]);
    cleanup_stale_service_processes();
    println!("Service 'osoosi-edr' stopped. Host network restored.");
    Ok(())
}

#[cfg(not(windows))]
pub fn restart_service() -> anyhow::Result<()> {
    println!("Restarting service 'osoosi-edr'...");
    let _ = stop_service();
    std::thread::sleep(Duration::from_millis(500));
    start_service()
}

#[cfg(not(windows))]
pub fn delete_service() -> anyhow::Result<()> {
    let _ = run_systemctl(&["stop", "osoosi-edr.service"]);
    let _ = run_systemctl(&["disable", "osoosi-edr.service"]);
    let unit_path = get_systemd_unit_path();
    if unit_path.exists() {
        let _ = std::fs::remove_file(&unit_path);
        let _ = run_systemctl(&["daemon-reload"]);
        println!(
            "Service 'osoosi-edr' unit removed from {}.",
            unit_path.display()
        );
    } else {
        println!(
            "Service 'osoosi-edr' unit not found at {}.",
            unit_path.display()
        );
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn query_service_state() -> anyhow::Result<String> {
    if let Ok(out) = run_systemctl(&["status", "osoosi-edr.service", "--no-pager"]) {
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        let status = if !stdout.trim().is_empty() {
            stdout
        } else {
            stderr
        };
        let port_listening = is_dashboard_port_listening(3030);
        Ok(format!(
            "{}\nWebUI Port 3030 Listening: {}",
            status.trim(),
            port_listening
        ))
    } else {
        let port_listening = is_dashboard_port_listening(3030);
        Ok(format!(
            "systemctl status unavailable. WebUI Port 3030 Listening: {}",
            port_listening
        ))
    }
}

#[cfg(not(windows))]
pub fn status_service() -> anyhow::Result<()> {
    let status_str = query_service_state()?;
    println!("=== Linux Service Status: osoosi-edr ===");
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
    use std::sync::atomic::AtomicIsize;
    use windows::core::{w, PWSTR};
    use windows::Win32::Foundation::{
        ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, NO_ERROR, WIN32_ERROR,
    };
    use windows::Win32::System::Services::{
        RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
        SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE,
        SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
        SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING,
        SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    };

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
                    dwWaitHint: 2000,
                };
                let _ = SetServiceStatus(handle, &status);
                notify_service_stop();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(1500));
                    let _ = osoosi_core::killchain::execute_host_disarm_unauthenticated();
                    let h_raw = GLOBAL_SERVICE_HANDLE_RAW.load(Ordering::SeqCst);
                    if h_raw != 0 {
                        let h = SERVICE_STATUS_HANDLE(h_raw as *mut std::ffi::c_void);
                        let stopped = SERVICE_STATUS {
                            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                            dwCurrentState: SERVICE_STOPPED,
                            dwControlsAccepted: 0,
                            dwWin32ExitCode: NO_ERROR.0,
                            dwServiceSpecificExitCode: 0,
                            dwCheckPoint: 0,
                            dwWaitHint: 0,
                        };
                        let _ = SetServiceStatus(h, &stopped);
                    }
                    std::process::exit(0);
                });
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

    pub fn is_service_dispatcher_active() -> bool {
        GLOBAL_SERVICE_HANDLE_RAW.load(Ordering::SeqCst) != 0
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

        // Ensure Interactive Users (IU) and Authenticated Users (AU) can query/stop/start service and clear forced restart actions
        let _ = Command::new(osoosi_types::resolve_system_binary("sc.exe"))
            .args(["failure", "OsoosiEDR", "reset=", "0", "actions=", ""])
            .output();
        let _ = Command::new(osoosi_types::resolve_system_binary("sc.exe"))
            .args([
                "sdset",
                "OsoosiEDR",
                "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;IU)(A;;CCLCSWRPWPDTLOCRRC;;;AU)(A;;CCLCSWLOCRRC;;;SU)",
            ])
            .output();

        // Wait until service stop is triggered
        while !SERVICE_STOP_FLAG.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(100));
        }

        // 3. Report SERVICE_STOP_PENDING
        status.dwCurrentState = SERVICE_STOP_PENDING;
        status.dwControlsAccepted = 0;
        status.dwCheckPoint = 1;
        status.dwWaitHint = 2000;
        let _ = SetServiceStatus(handle, &status);

        // Wait up to 800ms for daemon async cleanup to signal completion
        let shutdown_start = std::time::Instant::now();
        let mut checkpoint = 1;
        while !SERVICE_SHUTDOWN_DONE.load(Ordering::SeqCst)
            && shutdown_start.elapsed() < Duration::from_millis(800)
        {
            std::thread::sleep(Duration::from_millis(200));
            checkpoint += 1;
            status.dwCheckPoint = checkpoint;
            let _ = SetServiceStatus(handle, &status);
        }

        // 4. Disarm host isolation and unfreeze processes before reporting SERVICE_STOPPED
        let _ = osoosi_core::killchain::execute_host_disarm_unauthenticated();

        // Report SERVICE_STOPPED
        status.dwCurrentState = SERVICE_STOPPED;
        status.dwControlsAccepted = 0;
        status.dwCheckPoint = 0;
        status.dwWaitHint = 0;
        let _ = SetServiceStatus(handle, &status);

        info!("OsoosiEDR Windows Service has stopped.");
        std::process::exit(0);
    }

    pub fn cleanup_stale_service_processes() {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

        let my_pid = std::process::id();
        let mut sys = sysinfo::System::new();
        sys.refresh_processes();
        let mut terminated_any = false;
        for (pid, proc_info) in sys.processes() {
            let p = pid.as_u32();
            if p == my_pid || p <= 4 {
                continue;
            }
            let name = proc_info.name().to_ascii_lowercase();
            if name == "osoosi.exe" || name.starts_with("osoosi.old") {
                let cmd_joined = proc_info.cmd().join(" ").to_ascii_lowercase();
                let is_cli_ctl = cmd_joined.contains("service start")
                    || cmd_joined.contains("service restart")
                    || cmd_joined.contains("service stop")
                    || cmd_joined.contains("service status")
                    || cmd_joined.contains("service install");
                if !is_cli_ctl {
                    unsafe {
                        if let Ok(handle) = OpenProcess(PROCESS_TERMINATE, false, p) {
                            let _ = TerminateProcess(handle, 0);
                            let _ = CloseHandle(handle);
                            info!("Terminated stale osoosi daemon process PID {}", p);
                            terminated_any = true;
                        }
                    }
                }
            }
        }
        if terminated_any {
            std::thread::sleep(Duration::from_millis(600));
        }
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
                    info!(
                        "Running in console mode (ERROR_FAILED_SERVICE_CONTROLLER_CONNECT / 1063)."
                    );
                    return Ok(false);
                }
                warn!("StartServiceCtrlDispatcherW returned error: {}", err);
                Ok(false)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // SCM dispatcher is active and running!
                info!("Windows Service SCM dispatcher successfully connected and active.");
                cleanup_stale_service_processes();
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
pub use win_scm::{cleanup_stale_service_processes, try_start_service_dispatcher};

#[cfg(not(windows))]
pub fn try_start_service_dispatcher() -> anyhow::Result<bool> {
    Ok(false)
}

#[cfg(not(windows))]
pub fn cleanup_stale_service_processes() {
    let my_pid = std::process::id();
    let mut sys = sysinfo::System::new();
    sys.refresh_processes();
    let mut terminated_pids = Vec::new();
    for (pid, proc_info) in sys.processes() {
        let p = pid.as_u32();
        if p == my_pid || p <= 4 {
            continue;
        }
        let name = proc_info.name().to_ascii_lowercase();
        if name == "osoosi" || name == "osoosi-edr" {
            let cmd_joined = proc_info.cmd().join(" ").to_ascii_lowercase();
            let is_cli_ctl = cmd_joined.contains("service start")
                || cmd_joined.contains("service restart")
                || cmd_joined.contains("service stop")
                || cmd_joined.contains("service status")
                || cmd_joined.contains("service install");
            if !is_cli_ctl {
                let _ = Command::new("kill").args(["-15", &p.to_string()]).status();
                terminated_pids.push(p);
            }
        }
    }
    if !terminated_pids.is_empty() {
        std::thread::sleep(Duration::from_millis(400));
        for p in terminated_pids {
            let _ = Command::new("kill").args(["-9", &p.to_string()]).status();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_app_root_from_exe_finds_project_root() {
        let current_exe = std::env::current_exe()
            .unwrap_or_else(|_| std::path::PathBuf::from(r"target\debug\osoosi.exe"));
        let root = resolve_app_root_from_exe(&current_exe);
        assert!(
            root.exists(),
            "Resolved root directory must exist: {:?}",
            root
        );
    }

    #[test]
    fn test_resolve_app_root_nested_path() {
        let temp = std::env::temp_dir().join(format!("osoosi_test_{}", std::process::id()));
        let nested_bin = temp.join("target").join("release").join("osoosi.exe");
        std::fs::create_dir_all(temp.join("config")).unwrap();
        std::fs::create_dir_all(nested_bin.parent().unwrap()).unwrap();
        std::fs::write(&nested_bin, b"dummy").unwrap();

        let resolved = resolve_app_root_from_exe(&nested_bin);
        assert_eq!(
            resolved, temp,
            "Should resolve to root directory containing 'config'"
        );

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
