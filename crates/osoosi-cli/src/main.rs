use clap::{Parser, Subcommand};
use osoosi_core::EdrOrchestrator;
use osoosi_policy::ThreatFeedFetcher;

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use tracing::{info, error, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter, Layer};

#[derive(Parser)]
#[command(name = "osoosi")]
#[command(about = "OpenỌ̀ṣọ́ọ̀sì: Autonomous Security Agent", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the OpenỌ̀ṣọ́ọ̀sì security agent daemon
    Start,
    /// View the local threat intelligence status
    Status,
    /// Provisions dependencies (Sysmon on Windows/Linux)
    Provision {
        /// Optional: Force specific binary path (Windows only)
        #[arg(short, long)]
        binary: Option<String>,
        /// Optional: Path to config XML (Windows only)
        #[arg(short, long)]
        config: Option<String>,
    },
    /// View the forensic narrative of the last attack
    Story,
    /// Decentralized Trust Management (Identity & Certificates)
    Trust {
        #[command(subcommand)]
        action: TrustAction,
    },
    /// Start the web dashboard UI
    Dashboard {
        /// Port to listen on
        #[arg(short, long, default_value = "3030")]
        port: u16,
    },
    /// Grant OpenỌ̀ṣọ́ọ̀sì access to security event logs (run as Admin/root)
    GrantAccess,
    /// Check current privilege status (no changes made)
    CheckAccess,
    /// Remove all firewall rules created by the agent (restore internet). Run as Administrator.
    Unblock,
    /// Run the LLM agent (Llama 3.1 + LangChain). Requires: pip install -r agent/requirements.txt, ollama pull llama3.1:8b
    Agent,
    /// Rollback a previously applied patch. Requires Administrator/root.
    Rollback {
        /// Rollback the most recently applied patch (uses stored snapshot)
        #[arg(long)]
        last: bool,
        /// Rollback a specific patch by ID (e.g. KB1234567 on Windows, or package name on Linux)
        #[arg(short, long)]
        patch: Option<String>,
    },
    /// NVIDIA OpenShell sandbox management — run the agent in an isolated, policy-enforced environment
    Sandbox {
        #[command(subcommand)]
        action: SandboxAction,
    },
    /// Display the hardened security assessment (TEE, TPM, DPU, config integrity)
    SecurityStatus,
    /// Re-sign all critical configuration files (run after intentional edits)
    SignConfigs,
}

#[derive(Subcommand)]
pub enum TrustAction {
    /// Initialize the OpenỌ̀ṣọ́ọ̀sì Root CA
    InitCa,
    /// Issue an S2S Certificate for a peer node
    Issue {
        /// Peer Node DID
        #[arg(short, long)]
        peer_did: String,
        /// Output directory for peer certs
        #[arg(short, long, default_value = "./certs/peer")]
        out: String,
    },
    /// View local Node DID
    WhoAmI,
    /// Authorize a peer to join the mesh by signing its PeerID (Master Node only)
    AuthorizePeer {
        /// Peer ID to authorize
        #[arg(short, long)]
        peer_id: String,
    },
    /// Import NIST NSRL 'Known Good' file records.
    ImportNsrl {
        /// Path to the NIST Modern RDA sqlite file, or 'start' to download latest autonomously.
        path: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum SandboxAction {
    /// Create a new OpenShell sandbox and start the agent inside it
    Create {
        /// Sandbox name (default: osoosi)
        #[arg(short, long, default_value = "osoosi")]
        name: String,
        /// Path to OpenShell policy YAML (default: config/openshell-policy.yaml)
        #[arg(short, long)]
        policy: Option<String>,
    },
    /// Connect to a running sandbox (interactive terminal)
    Connect {
        /// Sandbox name (default: osoosi)
        #[arg(short, long, default_value = "osoosi")]
        name: String,
    },
    /// Show OpenShell status (installation, gateway, sandboxes)
    Status,
    /// Destroy a sandbox
    Destroy {
        /// Sandbox name (default: osoosi)
        #[arg(short, long, default_value = "osoosi")]
        name: String,
    },
    /// Deploy the OpenShell gateway (required before creating sandboxes)
    DeployGateway,
    /// Apply or update the security policy on a running sandbox
    ApplyPolicy {
        /// Sandbox name (default: osoosi)
        #[arg(short, long, default_value = "osoosi")]
        name: String,
        /// Path to policy YAML file
        #[arg(short, long)]
        policy: Option<String>,
    },
    /// Install the NVIDIA OpenShell CLI
    Install,
    /// Stream logs from a running sandbox
    Logs {
        /// Sandbox name (default: osoosi)
        #[arg(short, long, default_value = "osoosi")]
        name: String,
    },
}

/// Find ONNX Runtime dylib for load-dynamic. Checks ORT_DYLIB_PATH, exe dir, then ort cache.
fn find_onnxruntime_dylib() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("ORT_DYLIB_PATH") {
        let path = PathBuf::from(&p);
        if path.exists() {
            return Some(path);
        }
    }
    // Next to executable
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            #[cfg(windows)]
            let name = "onnxruntime.dll";
            #[cfg(target_os = "macos")]
            let name = "libonnxruntime.dylib";
            #[cfg(all(unix, not(target_os = "macos")))]
            let name = "libonnxruntime.so";
            let next_to = parent.join(name);
            if next_to.exists() {
                return Some(next_to);
            }
            let in_lib = parent.join("lib").join(name);
            if in_lib.exists() {
                return Some(in_lib);
            }
        }
    }
    // ort dfbin cache
    #[cfg(windows)]
    let cache_base = std::env::var("LOCALAPPDATA").ok().map(|s| PathBuf::from(s).join("ort.pyke.io").join("dfbin"));
    #[cfg(target_os = "macos")]
    let cache_base = std::env::var("HOME").ok().map(|h| PathBuf::from(h).join("Library").join("Caches").join("ort.pyke.io").join("dfbin"));
    #[cfg(all(unix, not(target_os = "macos")))]
    let cache_base = std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".cache").join("ort.pyke.io").join("dfbin"));
    #[cfg(not(any(windows, unix)))]
    let cache_base: Option<PathBuf> = None;

    if let Some(base) = cache_base {
        #[cfg(windows)]
        let dylib_name = "onnxruntime.dll";
        #[cfg(target_os = "macos")]
        let dylib_name = "libonnxruntime.dylib";
        #[cfg(all(unix, not(target_os = "macos")))]
        let dylib_name = "libonnxruntime.so";
        if let Ok(entries) = std::fs::read_dir(&base) {
            for target_dir in entries.flatten() {
                if target_dir.path().is_dir() {
                    if let Ok(hashes) = std::fs::read_dir(target_dir.path()) {
                        for hash_dir in hashes.flatten() {
                            let dylib = hash_dir.path().join("onnxruntime").join("lib").join(dylib_name);
                            if dylib.exists() {
                                return Some(dylib);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Initialize ONNX Runtime (load-dynamic). Must run before any ort usage.
fn init_ort() {
    // Find a compatible dylib and set ORT_DYLIB_PATH so ort's internal loader uses it
    if let Some(dylib) = find_onnxruntime_dylib() {
        let size_mb = std::fs::metadata(&dylib).map(|m| m.len() / (1024*1024)).unwrap_or(0);
        info!("Found ONNX Runtime at {:?} ({}MB). Attempting to load...", dylib, size_mb);
        std::env::set_var("ORT_DYLIB_PATH", &dylib);
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            match ort::init_from(&dylib) {
                Ok(builder) => {
                    builder.commit();
                    Ok(())
                }
                Err(e) => Err(format!("{}", e)),
            }
        })) {
            Ok(Ok(())) => {
                info!("ONNX Runtime successfully initialized from {:?}", dylib);
            }
            Ok(Err(e)) => {
                warn!("Failed to init ONNX Runtime from {:?}: {}. Disabling ML features.", dylib, e);
                std::env::set_var("OSOOSI_NO_ORT", "1");
            }
            Err(panic_err) => {
                let msg = panic_err.downcast_ref::<String>().map(|s| s.as_str())
                    .or_else(|| panic_err.downcast_ref::<&str>().copied())
                    .unwrap_or("unknown panic");
                warn!("ONNX Runtime panicked during init from {:?}: {}. Disabling ML features.", dylib, msg);
                std::env::set_var("OSOOSI_NO_ORT", "1");
            }
        }
    } else {
        warn!("ONNX Runtime dylib not found. Disabling ML features. To enable: set ORT_DYLIB_PATH or place onnxruntime.dll next to the executable.");
        std::env::set_var("OSOOSI_NO_ORT", "1");
    }
}

fn open_browser(url: &str) {
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd").args(["/c", "start", "", url]).spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}

fn init_logging() -> anyhow::Result<tracing_appender::non_blocking::WorkerGuard> {
    // Force INFO level for console unless overridden
    let console_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,osoosi=info"));

    // File logs can be more verbose
    let file_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,osoosi=debug"));

    // Main subscriber: Console (stderr) + File
    let stdout_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_ansi(true)
        .with_filter(console_filter);

    let logs_dir = Path::new("logs");
    let _ = std::fs::create_dir_all(logs_dir);
    
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(logs_dir.join("osoosi.log"))?;
    let (file_writer, guard) = tracing_appender::non_blocking(file);
    let file_layer = fmt::layer()
        .with_writer(file_writer)
        .with_ansi(false)
        .with_filter(file_filter);

    tracing_subscriber::registry()
        .with(stdout_layer)
        .with(file_layer)
        .init();

    info!("Logging initialized (Console: INFO, File: logs/osoosi.log)");
    // Optional: set OSOOSI_OTEL_ENABLED=1 and add osoosi_exporter::init_opentelemetry_layer()
    // to your subscriber for OpenTelemetry trace export.

    Ok(guard)
}

#[cfg(unix)]
async fn wait_for_shutdown() {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).unwrap();
    tokio::select! {
        _ = sigterm.recv() => {}
        _ = sigint.recv() => {}
    }
}

#[cfg(windows)]
async fn wait_for_shutdown() {
    let mut ctrl_c = tokio::signal::windows::ctrl_c().unwrap();
    let mut ctrl_break = tokio::signal::windows::ctrl_break().unwrap();
    let mut ctrl_close = tokio::signal::windows::ctrl_close().unwrap();
    let mut ctrl_logoff = tokio::signal::windows::ctrl_logoff().unwrap();
    let mut ctrl_shutdown = tokio::signal::windows::ctrl_shutdown().unwrap();

    tokio::select! {
        _ = ctrl_c.recv() => {}
        _ = ctrl_break.recv() => {}
        _ = ctrl_close.recv() => {}
        _ = ctrl_logoff.recv() => {}
        _ = ctrl_shutdown.recv() => {}
    }
}

fn main() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(8 * 1024 * 1024) // 8MB stack to prevent overflows in Debug/YARA
        .build()?;
    
    rt.block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    // 0. Auto-bootstrap security rules (Defender exclusions, Firewall allow)
    osoosi_core::privilege::bootstrap_security_rules();

    let _log_guard = init_logging()?;
    println!("OpenỌ̀ṣọ́ọ̀sì Orchestrator starting up...");

    // Initialize ONNX Runtime (load-dynamic) before any ort usage (magika, behavioral)
    init_ort();

    let cli = Cli::parse();

    match cli.command {
        Commands::Start => {
            // Pre-flight 0: Config integrity verification (Move 1: Merkle-Tree Integrity)
            let skip_integrity = std::env::var("OSOOSI_SKIP_INTEGRITY_CHECK")
                .map(|v| v == "1")
                .unwrap_or(false);
            if !skip_integrity {
                let tampered = osoosi_core::config_integrity::verify_all_critical_configs();
                if !tampered.is_empty() {
                    error!("FATAL: Config file tampering detected in: {:?}", tampered);
                    error!("The agent will NOT start with tampered configuration files.");
                    error!("If you intentionally edited these files, re-sign them with:");
                    error!("  osoosi sign-configs  (or set OSOOSI_SKIP_INTEGRITY_CHECK=1 to bypass)");
                    std::process::exit(78); // EX_CONFIG
                }
            }
            info!("Starting Odídẹrẹ́ Agent...");

            // Pre-flight 0b: Moving Target Defense — shuffle heap layout (Move 3: MTD)
            osoosi_core::hardened::mtd_shuffle_heap();
            osoosi_core::hardened::start_mtd_loop(Default::default());

            // Pre-flight 0c: Security assessment (TEE, TPM, DPU detection)
            let security = osoosi_core::hardened::assess_security();
            info!("Security score: {}/100 (TEE={}, TPM={}, DPU={})",
                security.security_score,
                security.tee.sgx_available || security.tee.sev_available,
                security.tpm.available,
                security.dpu.bluefield_detected,
            );
            
            // Pre-flight 1: System Requirements (RAM/CPU)
            let force_start = std::env::var("OSOOSI_FORCE_START").map(|v| v == "1").unwrap_or(false);
            if !force_start {
                if let Err(e) = osoosi_core::system_check::check_system_requirements(&Default::default()) {
                    error!("FATAL: {}", e);
                    error!("To bypass this check, set environment variable OSOOSI_FORCE_START=1");
                    std::process::exit(1);
                }
            } else {
                warn!("Bypassing system requirements check (OSOOSI_FORCE_START=1)");
            }

            // Deep Hardening 1: Digital Signature Enforcement (Military Grade)
            {
                let tampered = osoosi_core::config_integrity::verify_all_critical_configs();
                if !tampered.is_empty() {
                    if std::env::var("OSOOSI_SKIP_INTEGRITY_CHECK").is_err() {
                        error!("FATAL SECURITY FAILURE: Critical configuration files have INVALID SIGNATURES: {:?}", tampered);
                        error!("The agent will not start with unsigned/tampered instructions. Re-sign them with your Master Key or set OSOOSI_SKIP_INTEGRITY_CHECK=1 for debug.");
                        std::process::exit(1);
                    } else {
                        warn!("BYPASSING digital signature check (OSOOSI_SKIP_INTEGRITY_CHECK=1). THIS IS INSECURE.");
                    }
                }
            }

            // Deep Hardening 2: Landlock Filesystem Sandboxing (Linux Only)
            #[cfg(target_os = "linux")]
            {
                let config = osoosi_core::landlock::LandlockConfig::default();
                if let Err(e) = osoosi_core::landlock::apply_landlock_sandbox(&config) {
                    error!("FATAL: Failed to apply Landlock sandbox: {}. Strict security enforced.", e);
                    if config.strict_mode { std::process::exit(1); }
                }
            }

            // Pre-flight 2: check privileges
            let priv_status = osoosi_core::privilege::check_privileges();
            if priv_status.can_read_events {
                info!("Privilege check: OK (platform={}, can_read_events=true)", priv_status.platform);
            } else {
                error!(
                    "Privilege check: INSUFFICIENT — security event logs may not be readable. \
                     Run `osoosi grant-access` as {} to fix.",
                    if priv_status.platform == "windows" { "Administrator" }
                    else if priv_status.platform == "macos" { "root (or grant Full Disk Access)" }
                    else { "root (sudo)" }
                );
                for detail in &priv_status.details {
                    info!("  {}", detail);
                }
            }

            // Pre-flight 3: OpenShell Provisioning (Sandboxing requirement)
            {
                let openshell_manager = osoosi_core::openshell::OpenShellManager::new();
                if !openshell_manager.is_available() {
                    info!("[OpenShell] CLI not found. Running autonomous installation (pip/curl)...");
                    let result = osoosi_core::openshell::OpenShellManager::install();
                    if result.success {
                        info!("[OpenShell] Installation successful: {}", result.message);
                    } else {
                        warn!("[OpenShell] Autonomous installation failed: {}. Manual action: 'osoosi sandbox install'", result.message);
                    }
                } else {
                    info!("[OpenShell] CLI detected. Isolation features active.");
                }
            }

                        // Deep Hardening 3: Dead-Man's Switch (Watchdog Hardening)
            {
                let watchdog_config = osoosi_core::watchdog::WatchdogConfig::default();
                let _watchdog_state = osoosi_core::watchdog::start_watchdog(watchdog_config);
                info!("Dead-Man's Switch: Watchdog monitor active (Self-Protection layer).");
            }

            // Phase 3: Active Deception & Ghost Traps (Canaries)
            {
                let canary_manager = osoosi_core::canary::CanaryManager::new();
                let traps = canary_manager.deploy_canaries();
                info!("Phase 3: {} Ghost Trap Canaries deployed and monitored.", traps.len());
            }

            let orchestrator = std::sync::Arc::new(EdrOrchestrator::new().await?);

            // NSRL 'Known Good' database provisioning (Streaming Background Task)
            // Initiate immediately on start to ensure 'Known Good' database is populated autonomously.
            {
                let nsrl_orch = orchestrator.clone();
                tokio::spawn(async move {
                    let nsrl_count = nsrl_orch.memory().nsrl_record_count().unwrap_or(0);
                    let fetcher = osoosi_policy::ThreatFeedFetcher::new();
                    let nsrl_dir = std::env::temp_dir().join("osoosi-nsrl-bg");

                    if nsrl_count == 0 {
                        info!("[NSRL Background] No NSRL records found. Target directory: {:?}. Initiating autonomous streaming download...", nsrl_dir);
                        match fetcher.download_nsrl_streaming(&nsrl_dir).await {
                            Ok(db_path) => {
                                info!("[NSRL Background] Download complete. Importing records...");
                                match fetcher.import_nsrl_from_sqlite(&db_path).await {
                                    Ok(records) => {
                                        let count = records.len();
                                        match nsrl_orch.memory().upsert_nsrl_records(&records) {
                                            Ok(_) => info!("[NSRL Background] Successfully integrated {} 'Known Good' records.", count),
                                            Err(e) => error!("[NSRL Background] Storage failure: {}", e),
                                        }
                                    }
                                    Err(e) => error!("[NSRL Background] Parse failure: {}", e),
                                }
                            }
                            Err(e) => error!("[NSRL Background] Streaming download failed: {}. Re-try with 'osoosi trust import-nsrl' if persistent.", e),
                        }
                    } else {
                        info!("[NSRL Background] {} NSRL records active. Checking NIST for updates...", nsrl_count);
                        let current_version = "2025.03.1"; 
                        match fetcher.check_nsrl_updates(current_version).await {
                            Ok(updates) => {
                                if let Some((version, url, is_delta)) = updates.iter().find(|(_, _, d)| *d).or_else(|| updates.first()) {
                                    info!("[NSRL Background] Streaming {} update v{} from {}", if *is_delta { "delta" } else { "full" }, version, url);
                                    match fetcher.download_nsrl_streaming(&nsrl_dir).await {
                                        Ok(db_path) => {
                                            match fetcher.import_nsrl_from_sqlite(&db_path).await {
                                                Ok(records) => {
                                                    let count = records.len();
                                                    match nsrl_orch.memory().upsert_nsrl_records(&records) {
                                                        Ok(_) => info!("[NSRL Background] Update v{} applied ({} records).", version, count),
                                                        Err(e) => error!("[NSRL Background] Update storage failure: {}", e),
                                                    }
                                                }
                                                Err(e) => error!("[NSRL Background] Update parse failure: {}", e),
                                            }
                                        }
                                        Err(e) => error!("[NSRL Background] Update download failed: {}", e),
                                    }
                                }
                            }
                            Err(e) => info!("[NSRL Background] Update check skipped: {}", e),
                        }
                    }
                });
                info!("NSRL 'Known Good' autonomous background task dispatched to executor.");
            }

            // 0. Backup on start (if enabled in config)
            let backup_config = osoosi_types::load_backup_config();
            osoosi_core::backup::run_backup_on_start(&backup_config, Some(orchestrator.memory().clone()));

            // 0b. Refresh firewall allowlist (auto-update from URL before any blocking)
            osoosi_core::firewall::refresh_firewall_allowlist().await;
            let _ = osoosi_core::firewall::restore_autoblock_rules();

            // 0c. Refresh software replacement config (search-and-replace on malware)
            osoosi_core::software_replacement::refresh_software_replacement_map().await;

            // 1. Start mesh with join gate (peers auto-approved when reputation >= threshold)
            let autonomy = osoosi_types::load_autonomy_config();
            let join_gate = orchestrator.start_mesh_with_join_gate().await?;
            if autonomy.auto_approve_reputation_threshold < 1.0 {
                info!("Autonomous mode: peers with reputation >= {:.2} auto-approved", autonomy.auto_approve_reputation_threshold);
            } else {
                info!("Mesh started with reputation-based join gate. Approve peers via dashboard.");
            }
            if autonomy.auto_quarantine_malware {
                info!("Autonomous mode: malware files will be quarantined to {}", autonomy.quarantine_path);
            }

            // 2. Start dashboard with full backend (live status, threats, mesh stats, pending joins)
            // Try to start the dashboard on 3030, fallback to other ports if needed.
            let mut port = 3030u16;
            let mut success = false;
            let max_port = 3040;

            while port <= max_port {
                let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
                match tokio::net::TcpListener::bind(addr).await {
                    Ok(listener) => {
                        // Drop the listener so the dashboard can bind to it
                        drop(listener);
                        
                        let dashboard_join_gate = join_gate.clone();
                        let dashboard_orch = orchestrator.clone();
                        let current_port = port;
                        
                        tokio::spawn(async move {
                            if let Err(e) = osoosi_dashboard::start_dashboard_with_backend(
                                current_port,
                                Some(dashboard_join_gate),
                                Some(dashboard_orch),
                            ).await {
                                error!("Dashboard server error on port {}: {}", current_port, e);
                            }
                        });
                        
                        info!("Dashboard started successfully on port {}", port);
                        success = true;
                        break;
                    }
                    Err(_) => {
                        warn!("Port {} in use, trying next...", port);
                        port += 1;
                    }
                }
            }

            if success {
                tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                open_browser(&format!("http://127.0.0.1:{}", port));
            } else {
                error!("Dashboard could not be started after trying ports 3030-{}.", max_port);
            }

            // 3. Start threat fetcher
            let fetcher_orch = orchestrator.clone();
            tokio::spawn(async move {
                fetcher_orch.start_fetcher_loop().await;
            });



            // 3b. Start Repair Engine (patch discovery, optional auto-apply)
            let repair_enabled = std::env::var("OSOOSI_REPAIR_ENABLED")
                .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
                .unwrap_or(true);
            let repair_interval: u64 = std::env::var("OSOOSI_REPAIR_INTERVAL")
                .ok().and_then(|s| s.parse().ok()).unwrap_or(21600); // 6 hours
            let repair_auto_apply = std::env::var("OSOOSI_REPAIR_AUTO_APPLY")
                .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
                .unwrap_or(true);
            if repair_enabled {
                let repair_orch = orchestrator.clone();
                tokio::spawn(async move {
                    repair_orch.start_repair_loop(repair_interval, repair_auto_apply).await;
                });
                info!("Repair Engine active (interval: {}s, auto_apply: {})", repair_interval, repair_auto_apply);
            }


            // 3c. Start model training (uses self + peer data, saves to models/)
            let model_interval: u64 = std::env::var("OSOOSI_MODEL_TRAIN_INTERVAL")
                .ok().and_then(|s| s.parse().ok()).unwrap_or(60);
            orchestrator.start_model_training_loop(model_interval).await;
            info!("Model training active (interval: {}s, models in ./models/)", model_interval);

            // 3d. Start rule maintenance loop (YARA discovery, Sigma refresh, ClamAV)
            orchestrator.start_maintenance_loop();

            // 3e. Start CEREBUS CyberShield (Resource Monitoring & Process Guard)
            orchestrator.start_cybershield_monitor();

            // 3f. Start behavioral detector (System/App logs → SecureBERT-style first detection)
            orchestrator.start_behavioral_detector();

            // 4. Start file watcher: config file (osoosi.toml [telemetry].watch_paths) > OSOOSI_WATCH_PATHS env > all physical drives
            let watch_paths: Vec<String> = osoosi_types::load_watch_paths_from_config()
                .or_else(|| {
                    std::env::var("OSOOSI_WATCH_PATHS").ok().map(|s| {
                        let paths: Vec<String> = s.split(',').map(str::trim).filter(|x| !x.is_empty()).map(String::from).collect();
                        if paths.iter().any(|p| p.eq_ignore_ascii_case("all") || p == "*") {
                            osoosi_types::all_physical_drive_paths()
                        } else {
                            paths
                        }
                    })
                })
                .unwrap_or_else(osoosi_types::all_physical_drive_paths);
            let paths_refs: Vec<&str> = watch_paths.iter().map(String::as_str).collect();
            if let Err(e) = orchestrator.start_file_watcher_paths(&paths_refs).await {
                error!("Failed to start file watcher: {}", e);
            } else {
                info!("Active file watch on: {}", watch_paths.join(", "));
            }

            // 5. Start host security event loop (Windows Event Log, Linux auditd, macOS audit)
            let event_source = std::env::var("OSOOSI_EVENT_SOURCE")
                .unwrap_or_else(|_| {
                    #[cfg(target_os = "windows")]
                    { "Microsoft-Windows-Sysmon/Operational".to_string() }
                    #[cfg(not(target_os = "windows"))]
                    { "default".to_string() }
                });
            let poll_secs: u64 = std::env::var("OSOOSI_POLL_INTERVAL")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1);
            orchestrator.start_host_event_loop(&event_source, poll_secs).await;
            info!("Host security event logs are being read and used for protection.");

            // 6. Start Web Dashboard
            let dashboard_port: u16 = std::env::var("OSOOSI_DASHBOARD_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8080);
            let dash_backend = Some(orchestrator.clone());
            tokio::spawn(async move {
                if let Err(e) = osoosi_dashboard::start_dashboard_with_backend(
                    dashboard_port,
                    None, // JoinGate is managed by the orchestrator mesh loop
                    dash_backend,
                ).await {
                    tracing::error!("Dashboard server failed: {}", e);
                }
            });

            // Auto-open browser (best effort)
            let dashboard_url = format!("http://127.0.0.1:{}", dashboard_port);
            #[cfg(target_os = "windows")]
            { let _ = std::process::Command::new("cmd").args(["/C", "start", &dashboard_url]).spawn(); }
            #[cfg(target_os = "macos")]
            { let _ = std::process::Command::new("open").arg(&dashboard_url).spawn(); }
            #[cfg(target_os = "linux")]
            { let _ = std::process::Command::new("xdg-open").arg(&dashboard_url).spawn(); }
            
            info!("OpenỌ̀ṣọ́ọ̀sì Agent is live and monitoring.");

            // Optional: spawn LLM agent (Gemma + LangChain) for autonomous reasoning
            let llm_agent_enabled = std::env::var("OSOOSI_LLM_AGENT_ENABLED")
                .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if llm_agent_enabled {
                let script = std::path::Path::new("agent").join("run_agent.py");
                if script.exists() {
                    match std::process::Command::new("python")
                        .arg(&script)
                        .current_dir(".")
                        .spawn()
                    {
                        Ok(_) => info!("LLM Agent (Gemma + LangChain) spawned in background"),
                        Err(e) => error!("Failed to spawn LLM agent: {}", e),
                    }
                } else {
                    info!("LLM agent disabled: agent/run_agent.py not found");
                }
            }
            
            wait_for_shutdown().await;
            info!("Shutting down OpenỌ̀ṣọ́ọ̀sì Agent...");
            match osoosi_core::firewall::remove_all_autoblock_rules() {
                Ok(n) if n > 0 => info!("Removed {} firewall block rule(s) (Docker, Git, etc. unblocked)", n),
                Ok(_) => {}
                Err(e) => info!("Firewall cleanup skipped or partial: {} (run as Administrator to remove rules)", e),
            }
        }
        Commands::Status => {
            println!("Odídẹrẹ́ Status: Active");
            println!("Node ID: {}", uuid::Uuid::new_v4());
        }
        Commands::Provision { binary, config } => {
            use osoosi_telemetry::AgentProvisioner;
            info!("Provisioning Odídẹrẹ́ dependencies...");
            let provisioner = AgentProvisioner::new();
            
            if let Some(bin) = binary {
                match provisioner.install(&bin, config.as_ref()) {
                    Ok(_) => info!("Explicit provisioning complete."),
                    Err(e) => error!("Explicit provisioning failed: {}", e),
                }
            } else {
                match provisioner.provision_telemetry() {
                    Ok(_) => info!("Automated provisioning complete."),
                    Err(e) => error!("Automated provisioning failed: {}", e),
                }
            }
        }
        Commands::Story => {
            let orchestrator = EdrOrchestrator::new().await?;
            println!("{}", orchestrator.generate_story());
        }
        Commands::Dashboard { port } => {
            info!("Starting Odídẹrẹ́ Dashboard (base port {})...", port);
            let join_gate = None; // Dashboard command doesn't have a live mesh join gate in this context usually
            let orch = None;
            
            let mut current_port = port;
            let mut success = false;
            let max_port = port + 10;

            while current_port <= max_port {
                match osoosi_dashboard::start_dashboard_with_backend(current_port, join_gate.clone(), orch.clone()).await {
                    Ok(_) => {
                        info!("Dashboard started on port {}", current_port);
                        success = true;
                        break;
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        if err_str.contains("address already in use") || err_str.contains("os error 10048") {
                            warn!("Port {} in use, trying next...", current_port);
                            current_port += 1;
                        } else {
                            error!("Dashboard subcommand failed on port {}: {}", current_port, e);
                            break;
                        }
                    }
                }
            }

            if success {
                tokio::time::sleep(tokio::time::Duration::from_millis(800)).await;
                open_browser(&format!("http://127.0.0.1:{}", current_port));
                tokio::signal::ctrl_c().await?;
            } else {
                error!("Dashboard could not be started after trying ports {}-{}.", port, max_port);
            }
        }
        Commands::Trust { action } => {
            let orchestrator = EdrOrchestrator::new().await?;
            let tm = orchestrator.trust();
            
            match action {
                TrustAction::InitCa => {
                    tm.init_ca("./certs/ca")?;
                    info!("Root CA successfully initialized in ./certs/ca");
                }
                TrustAction::Issue { peer_did, out } => {
                    tm.issue_certificate("./certs/ca", &peer_did, &out)?;
                    info!("S2S Certificate for {} issued to {}", peer_did, out);
                }
                TrustAction::WhoAmI => {
                    println!("Node DID: {}", tm.did().id);
                    println!("Public Key: {}", tm.did().public_key);
                }
                TrustAction::AuthorizePeer { peer_id } => {
                    let proof = tm.generate_membership_proof(&peer_id);
                    println!("--- MASTER NODE AUTHORIZATION PROOF ---");
                    println!("Peer ID: {}", peer_id);
                    println!("Proof:   {}", proof);
                    println!("---------------------------------------");
                    println!("Add this proof to the authorized agent's osoosi.toml under [wire] as follows:");
                    println!("[wire]");
                    println!("membership_proof = \"{}\"", proof);
                }
                TrustAction::ImportNsrl { path } => {
                    let fetcher = ThreatFeedFetcher::new();

                    let db_path = match path {
                        Some(ref p) if p.eq_ignore_ascii_case("start") => {
                            info!("'start' triggered. Starting autonomous streaming download of NIST NSRL Modern RDS (v2025.03.1)...");
                            let temp_dir = std::env::temp_dir().join("osoosi-nsrl");
                            fetcher.download_nsrl_streaming(&temp_dir).await?
                        }
                        Some(p) => PathBuf::from(p),
                        None => {
                            info!("No path provided. Starting autonomous streaming download of NIST NSRL Modern RDS (v2025.03.1)...");
                            let temp_dir = std::env::temp_dir().join("osoosi-nsrl");
                            fetcher.download_nsrl_streaming(&temp_dir).await?
                        }
                    };

                    info!("Importing NSRL records from {}...", db_path.display());
                    let records: Vec<osoosi_types::NsrlRecord> = fetcher.import_nsrl_from_sqlite(&db_path).await?;
                    let count = records.len();
                    info!("Successfully parsed {} records from NIST RDA.", count);
                    
                    let memory = orchestrator.memory();
                    memory.upsert_nsrl_records(&records)?;
                    info!("Successfully integrated {} NSRL records into local trust database.", count);
                }
            }
        }
        Commands::GrantAccess => {
            #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
            {
                use osoosi_telemetry::AgentProvisioner;
                let provisioner = AgentProvisioner::new();
                info!("GrantAccess pre-step: ensuring telemetry dependencies are installed and configured...");
                match provisioner.provision_telemetry() {
                    Ok(_) => info!("Telemetry install/config pre-step complete."),
                    Err(e) => error!("Telemetry install/config pre-step failed: {}", e),
                }
                info!("GrantAccess pre-step: ensuring ClamAV is installed...");
                match provisioner.provision_clamav() {
                    Ok(_) => info!("ClamAV install pre-step complete."),
                    Err(e) => error!("ClamAV install pre-step failed: {}", e),
                }
                info!("GrantAccess pre-step: ensuring OpenSSL is installed...");
                match provisioner.provision_openssl() {
                    Ok(_) => info!("OpenSSL install pre-step complete."),
                    Err(e) => error!("OpenSSL install pre-step failed: {}", e),
                }
                info!("GrantAccess pre-step: ensuring FLARE FLOSS (Expert Deobfuscator) is installed...");
                match provisioner.provision_floss() {
                    Ok(_) => info!("FLOSS forensic tool install complete."),
                    Err(e) => error!("FLOSS forensic tool install failed: {}", e),
                }
                info!("GrantAccess pre-step: ensuring HollowsHunter (Memory Forensics) is installed...");
                match provisioner.provision_hollows_hunter() {
                    Ok(_) => info!("HollowsHunter memory forensics tool install complete."),
                    Err(e) => error!("HollowsHunter memory forensics tool install failed: {}", e),
                }

                // NSRL download moved to end of command as requested
            }

            println!("OpenỌ̀ṣọ́ọ̀sì Privilege Grant (platform: {})", osoosi_core::privilege::current_platform());
            println!("=========================================");
            
            // 1. Automatic Firewall Setup (Mesh and Dashboard)
            println!("[i] Configuring firewall rules...");
            match setup_firewall().await {
                Ok(_) => println!("[+] Firewall rules configured successfully."),
                Err(e) => println!("[!] Firewall setup failed: {} (manual setup may be required)", e),
            }

            // 2. Platform Privilege Grant
            let status = osoosi_core::privilege::grant_access();
            for action in &status.actions_taken {
                println!("[+] {}", action);
            }
            for detail in &status.details {
                println!("[i] {}", detail);
            }
            for err in &status.errors {
                println!("[!] {}", err);
            }
            println!();
            if status.can_read_events {
                println!("Result: SUCCESS — OpenỌ̀ṣọ́ọ̀sì can read security event logs.");
            } else if !status.errors.is_empty() {
                println!("Result: FAILED — see errors above.");
            } else {
                println!("Result: PARTIAL — manual steps may be required (see details above).");
            }

            // Move long-running NSRL download to the end so it doesn't block the privilege grant summary
            info!("Final task: ensuring NSRL 'Known Good' database is populated...");
            let fetcher = ThreatFeedFetcher::new();
            let temp_dir = std::env::temp_dir().join("osoosi-nsrl-grant");
            
            match fetcher.download_nsrl_streaming(&temp_dir).await {
                Ok(db_path) => {
                    info!("Autonomous NSRL download complete. Importing records...");
                    match fetcher.import_nsrl_from_sqlite(&db_path).await {
                        Ok(records) => {
                            let orchestrator: EdrOrchestrator = EdrOrchestrator::new().await?;
                            let count = records.len();
                            if let Err(e) = orchestrator.memory().upsert_nsrl_records(&records) {
                                error!("Failed to integrate NSRL records: {}", e);
                            } else {
                                info!("Successfully integrated {} NSRL records.", count);
                            }
                        }
                        Err(e) => error!("Failed to parse NSRL database: {}", e),
                    }
                }
                Err(e) => error!("Failed to download NSRL database: {}", e),
            }

            #[cfg(target_os = "macos")]
            {
                println!();
                println!("macOS entitlements.plist (for CI/CD codesigning):");
                println!("{}", osoosi_core::privilege::macos_entitlements_plist());
            }
        }
        Commands::CheckAccess => {
            println!("OpenỌ̀ṣọ́ọ̀sì Privilege Check (platform: {})", osoosi_core::privilege::current_platform());
            println!("=========================================");
            let status = osoosi_core::privilege::check_privileges();
            println!("Elevated/Root:      {}", status.is_elevated);
            println!("Can read events:    {}", status.can_read_events);
            println!("Can apply patches:  {}", status.can_apply_patches);
            println!();
            for detail in &status.details {
                println!("  {}", detail);
            }
            if !status.can_read_events {
                println!();
                println!("To fix, run: osoosi grant-access");
                #[cfg(target_os = "windows")]
                println!("  (right-click terminal -> Run as Administrator)");
                #[cfg(target_os = "linux")]
                println!("  (prefix with: sudo)");
            }
        }
        Commands::Unblock => {
            println!("Removing OpenỌ̀ṣọ́ọ̀sì firewall rules (restoring internet)...");
            match osoosi_core::firewall::remove_all_autoblock_rules() {
                Ok(n) if n > 0 => {
                    println!("Removed {} firewall rule(s). Internet access restored.", n);
                }
                Ok(_) => {
                    println!("No OpenỌ̀ṣọ́ọ̀sì firewall rules found. If internet is still blocked, check Windows Firewall manually.");
                }
                Err(e) => {
                    println!("Failed to remove rules: {}", e);
                    #[cfg(target_os = "windows")]
                    println!("Run this command as Administrator: right-click PowerShell -> Run as Administrator");
                }
            }
        }
        Commands::Rollback { last, patch } => {
            if !last && patch.is_none() {
                println!("Specify --last to rollback the most recent patch, or --patch <id>");
                println!("  Examples: osoosi rollback --last");
                println!("           osoosi rollback --patch KB1234567");
                println!("           osoosi rollback --patch openssl");
                return Ok(());
            }
            let orchestrator = EdrOrchestrator::new().await?;
            match orchestrator.rollback_patch(patch.as_deref(), last).await {
                Ok(_) => println!("Rollback completed successfully."),
                Err(e) => {
                    error!("Rollback failed: {}", e);
                    println!("Rollback failed: {}", e);
                    println!("Ensure you run as Administrator/root.");
                }
            }
        }
        Commands::Agent => {
            info!("Starting OpenỌ̀ṣọ́ọ̀sì LLM Agent (Gemma + LangChain)...");
            let agent_dir = std::path::Path::new("agent");
            let script = agent_dir.join("run_agent.py");
            if !script.exists() {
                error!("Agent script not found: {}. Run from project root.", script.display());
                println!("Ensure agent/run_agent.py exists. Install: pip install -r agent/requirements.txt");
                println!("Pull model: ollama pull llama3.1:8b");
                return Ok(());
            }
            let status = std::process::Command::new("python")
                .arg(script)
                .current_dir(".")
                .status();
            match status {
                Ok(s) if s.success() => {}
                Ok(s) => error!("Agent exited with code {:?}", s.code()),
                Err(e) => {
                    error!("Failed to run agent: {}. Ensure Python is installed, pip install -r agent/requirements.txt, and ollama pull llama3.1:8b", e);
                    println!("Try: python agent/run_agent.py");
                }
            }
        }
        Commands::Sandbox { action } => {
            use osoosi_core::openshell::OpenShellManager;
            let manager = OpenShellManager::new();

            match action {
                SandboxAction::Status => {
                    let status = manager.status();
                    println!("NVIDIA OpenShell Status");
                    println!("=======================");
                    println!("Installed:       {}", if status.installed { "✓ Yes" } else { "✗ No" });
                    if let Some(ref v) = status.version {
                        println!("Version:         {}", v);
                    }
                    println!("Gateway Running: {}", if status.gateway_running { "✓ Yes" } else { "✗ No" });
                    if !status.sandboxes.is_empty() {
                        println!("\nActive Sandboxes:");
                        for sb in &status.sandboxes {
                            println!("  {} ({})", sb.name, sb.status);
                        }
                    } else if status.gateway_running {
                        println!("\nNo active sandboxes.");
                    }
                    if !status.installed {
                        println!("\nInstall OpenShell: osoosi sandbox install");
                        println!("  Or: curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh");
                    }
                }
                SandboxAction::Install => {
                    println!("Installing NVIDIA OpenShell CLI...");
                    let result = OpenShellManager::install();
                    if result.success {
                        println!("✓ OpenShell installed successfully.");
                        println!("{}", result.message);
                    } else {
                        println!("✗ Installation failed: {}", result.message);
                    }
                }
                SandboxAction::DeployGateway => {
                    if !manager.is_available() {
                        println!("OpenShell is not installed. Run: osoosi sandbox install");
                        return Ok(());
                    }
                    println!("Deploying OpenShell gateway (this may take a moment)...");
                    let result = manager.deploy_gateway();
                    if result.success {
                        println!("✓ Gateway deployed successfully.");
                    } else {
                        println!("✗ Gateway deploy failed: {}", result.message);
                    }
                }
                SandboxAction::Create { name, policy } => {
                    if !manager.is_available() {
                        println!("OpenShell is not installed. Run: osoosi sandbox install");
                        return Ok(());
                    }
                    println!("Creating OpenShell sandbox '{}'...", name);
                    if let Some(ref p) = policy {
                        std::env::set_var("OPENSHELL_SANDBOX_POLICY", p);
                    }
                    let result = manager.create_sandbox(Some(&name));
                    if result.success {
                        println!("✓ Sandbox '{}' created. Agent running in isolated environment.", name);
                    } else {
                        println!("✗ Sandbox creation failed: {}", result.message);
                        println!("\nTroubleshooting:");
                        println!("  1. Ensure Docker is running");
                        println!("  2. Deploy gateway first: osoosi sandbox deploy-gateway");
                        println!("  3. Check logs: osoosi sandbox logs --name {}", name);
                    }
                }
                SandboxAction::Connect { name } => {
                    if !manager.is_available() {
                        println!("OpenShell is not installed. Run: osoosi sandbox install");
                        return Ok(());
                    }
                    let result = manager.connect_sandbox(Some(&name));
                    if !result.success {
                        println!("Failed to connect: {}", result.message);
                    }
                }
                SandboxAction::Destroy { name } => {
                    if !manager.is_available() {
                        println!("OpenShell is not installed.");
                        return Ok(());
                    }
                    println!("Destroying sandbox '{}'...", name);
                    let result = manager.destroy_sandbox(Some(&name));
                    if result.success {
                        println!("✓ Sandbox '{}' destroyed.", name);
                    } else {
                        println!("✗ Failed to destroy sandbox: {}", result.message);
                    }
                }
                SandboxAction::ApplyPolicy { name, policy } => {
                    if !manager.is_available() {
                        println!("OpenShell is not installed. Run: osoosi sandbox install");
                        return Ok(());
                    }
                    let policy_path = policy.as_ref().map(|p| std::path::Path::new(p.as_str()));
                    let result = manager.apply_policy(Some(&name), policy_path);
                    if result.success {
                        println!("✓ Policy applied to sandbox '{}'.", name);
                    } else {
                        println!("✗ Failed to apply policy: {}", result.message);
                    }
                }
                SandboxAction::Logs { name } => {
                    if !manager.is_available() {
                        println!("OpenShell is not installed.");
                        return Ok(());
                    }
                    manager.stream_logs(Some(&name));
                }
            }
        }
        Commands::SecurityStatus => {
            osoosi_core::hardened::print_security_assessment();
        }
        Commands::SignConfigs => {
            println!("Re-signing all critical configuration files...");
            osoosi_core::config_integrity::sign_all_critical_configs();
            println!("✓ All configuration files re-signed. The agent will accept them on next startup.");
        }
    }

    Ok(())
}
async fn setup_firewall() -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        
        let mesh_port = 4001; 
        let dashboard_port = 8080;

        // Check if rules exist, if not, create them
        let ps_cmd = format!(
            "if (-not (Get-NetFirewallRule -DisplayName 'OpenOdidere Mesh (TCP)' -ErrorAction SilentlyContinue)) {{ New-NetFirewallRule -DisplayName 'OpenOdidere Mesh (TCP)' -Direction Inbound -LocalPort {} -Protocol TCP -Action Allow }}; \
             if (-not (Get-NetFirewallRule -DisplayName 'OpenOdidere Mesh (UDP)' -ErrorAction SilentlyContinue)) {{ New-NetFirewallRule -DisplayName 'OpenOdidere Mesh (UDP)' -Direction Inbound -LocalPort {} -Protocol UDP -Action Allow }}; \
             if (-not (Get-NetFirewallRule -DisplayName 'OpenOdidere Dashboard' -ErrorAction SilentlyContinue)) {{ New-NetFirewallRule -DisplayName 'OpenOdidere Dashboard' -Direction Inbound -LocalPort {} -Protocol TCP -Action Allow }}",
            mesh_port, mesh_port, dashboard_port
        );

        let output = Command::new("powershell")
            .args(&["-Command", &ps_cmd])
            .output()?;

        if !output.status.success() {
             return Err(anyhow::anyhow!("PowerShell firewall command failed: {}", String::from_utf8_lossy(&output.stderr)));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        let mesh_port = 4001;
        let dashboard_port = 8080;

        // Try UFW (Ubuntu/Debian)
        let _ = Command::new("ufw").args(&["allow", &mesh_port.to_string(), "/tcp"]).status();
        let _ = Command::new("ufw").args(&["allow", &mesh_port.to_string(), "/udp"]).status();
        let _ = Command::new("ufw").args(&["allow", &dashboard_port.to_string(), "/tcp"]).status();

        // Try firewall-cmd (CentOS/RHEL)
        let _ = Command::new("firewall-cmd").args(&["--permanent", &format!("--add-port={}/tcp", mesh_port)]).status();
        let _ = Command::new("firewall-cmd").args(&["--permanent", &format!("--add-port={}/udp", mesh_port)]).status();
        let _ = Command::new("firewall-cmd").args(&["--permanent", &format!("--add-port={}/tcp", dashboard_port)]).status();
        let _ = Command::new("firewall-cmd").arg("--reload").status();

        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Ok(())
    }
}
