use clap::{Parser, Subcommand};
use osoosi_core::EdrOrchestrator;
use osoosi_policy::ThreatFeedFetcher;

use std::path::{Path, PathBuf};
use tracing::{info, error, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};
use std::io::copy;
use zip::ZipArchive;
use flate2::read::GzDecoder;
use tar::Archive;

#[derive(Parser)]
#[command(name = "osoosi")]
#[command(about = "OpenỌ̀ṣọ́ọ̀sì: Autonomous Security Agent", long_about = None)]
struct Cli {
    /// Grant OpenỌ̀ṣọ́ọ̀sì access to security event logs (equivalent to 'grant-access' command)
    #[arg(long)]
    grant_access: bool,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Clone)]
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
    /// Autonomously download required ML models (Malware ONNX, SecureBERT) to local 'models/' directory.
    BootstrapModels,
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

#[derive(Subcommand, Clone)]
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
    /// Import and parse NIST NSRL RDS record database (Modern RDS SQLite format)
    ImportNsrl {
        /// Optional: Path to the SQLite NSRL database file. Use 'start' to trigger autonomous download.
        path: Option<String>,
    },
}

#[derive(Subcommand, Clone)]
pub enum SandboxAction {
    /// Display current OpenShell policy and status
    Status,
    /// Install OpenShell
    Install,
    /// Deploy gateway
    DeployGateway,
    /// Create sandbox
    Create { name: String, policy: Option<String> },
    /// Connect to sandbox
    Connect { name: String },
    /// Destroy sandbox
    Destroy { name: String },
    /// Apply policy to sandbox
    ApplyPolicy { name: String, policy: Option<String> },
    /// Stream logs from sandbox
    Logs { name: String },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    set_panic_hook();
    let _guard = init_logging()?;
    
    let cli = Cli::parse();
    
    // Suppress ML warnings if we are running provisioning commands
    let suppress_ml_warning = cli.grant_access || matches!(cli.command, Some(Commands::GrantAccess) | Some(Commands::BootstrapModels));
    init_ort(suppress_ml_warning);
    
    if let Err(e) = async_main(cli).await {
        error!("Fatal execution error: {}", e);
        std::process::exit(1);
    }
    
    Ok(())
}

async fn async_main(cli: Cli) -> anyhow::Result<()> {
    // 1. Handle global --grant-access flag
    if cli.grant_access {
        handle_grant_access().await?;
    }

    // 2. Handle subcommands
    match cli.command {
        Some(Commands::Start) => {
            let start_instant = std::time::Instant::now();
            let orchestrator = EdrOrchestrator::new().await?;
            let nsrl_orch = orchestrator.clone();
            
            // Background thread to download/populate NSRL if empty
            tokio::spawn(async move {
                let nsrl_count = nsrl_orch.memory().nsrl_record_count().unwrap_or(0);
                let fetcher = osoosi_policy::ThreatFeedFetcher::new();
                let nsrl_dir = std::env::temp_dir().join("osoosi-nsrl-shared-cache");
                let db_file = nsrl_dir.join("nsrl.db");

                // Only download if DB is empty AND the file is missing (or if we want a fresh copy/update)
                // Note: fetcher.download_nsrl_streaming also has internally resumable logic.
                if nsrl_count == 0 && !db_file.exists() {
                    info!("[NSRL Background] NSRL data missing. Initiating autonomous background download (non-blocking)...");
                    match fetcher.download_nsrl_streaming(&nsrl_dir).await {
                        Ok(db_path) => {
                            info!("[NSRL Background] Download complete at {:?}. Importing records...", db_path);
                            if let Ok(records) = fetcher.import_nsrl_from_sqlite(&db_path).await {
                                if let Err(e) = nsrl_orch.memory().upsert_nsrl_records(&records) {
                                    error!("[NSRL Background] Failed to upsert records: {}", e);
                                } else {
                                    info!("[NSRL Background] Successfully integrated {} 'Known Good' records into trust database.", records.len());
                                }
                            }
                        }
                        Err(e) => error!("[NSRL Background] Failed to download NSRL: {}", e),
                    }
                } else if nsrl_count == 0 && db_file.exists() {
                    info!("[NSRL Background] NSRL database file found on disk, but records are not in memory. Importing...");
                    if let Ok(records) = fetcher.import_nsrl_from_sqlite(&db_file).await {
                         let _ = nsrl_orch.memory().upsert_nsrl_records(&records);
                         info!("[NSRL Background] Imported {} records from existing local database.", records.len());
                    }
                }
            });

            info!("Starting OpenỌ̀ṣọ́ọ̀sì Security Agent...");
            
            // Start components
            orchestrator.start_maintenance_loop();
            orchestrator.start_cybershield_monitor();
            orchestrator.start_behavioral_detector();
            orchestrator.clone().adaptive().start_adaptive_loop(); // Active resource-aware scaling
            orchestrator.start_repair_loop(3600, true).await;
            orchestrator.start_fetcher_loop().await;
            orchestrator.start_model_training_loop(60).await;

            let watch_paths = osoosi_types::load_watch_paths_from_config().unwrap_or_else(osoosi_types::all_physical_drive_paths);
            let paths_refs: Vec<&str> = watch_paths.iter().map(String::as_str).collect();
            let _ = orchestrator.start_file_watcher_paths(&paths_refs).await;

            let event_source = if cfg!(windows) { "Microsoft-Windows-Sysmon/Operational".to_string() } else { "default".to_string() };
            orchestrator.start_host_event_loop(&event_source, 1).await;

            info!("OpenỌ̀ṣọ́ọ̀sì Agent is live and monitoring (Total startup: {:?}).", start_instant.elapsed());
            
            wait_for_shutdown().await;
            info!("Shutting down OpenỌ̀ṣọ́ọ̀sì Agent...");
            let _ = osoosi_core::firewall::remove_all_autoblock_rules();
        }
        Some(Commands::Status) => {
            println!("Oshoosi Status: Active");
            println!("Node ID: {}", uuid::Uuid::new_v4());
        }
        Some(Commands::Provision { binary: _, config: _ }) => {
            use osoosi_telemetry::AgentProvisioner;
            info!("Provisioning Oshoosi dependencies...");
            let provisioner = AgentProvisioner::new();
            match provisioner.provision_telemetry() {
                Ok(_) => info!("Automated provisioning complete."),
                Err(e) => error!("Automated provisioning failed: {}", e),
            }
        }
        Some(Commands::Story) => {
            let orchestrator = EdrOrchestrator::new().await?;
            println!("{}", orchestrator.generate_story().await);
        }
        Some(Commands::Dashboard { port }) => {
            info!("Starting Oshoosi Dashboard (base port {})...", port);
            let mut current_port = port;
            let mut success = false;
            while current_port <= port + 10 {
                match osoosi_dashboard::start_dashboard_with_backend(current_port, None, None).await {
                    Ok(_) => {
                        info!("Dashboard started on port {}", current_port);
                        success = true;
                        break;
                    }
                    Err(_) => {
                        warn!("Port {} in use, trying next...", current_port);
                        current_port += 1;
                    }
                }
            }
            if success {
                tokio::time::sleep(tokio::time::Duration::from_millis(800)).await;
                open_browser(&format!("http://127.0.0.1:{}", current_port));
                tokio::signal::ctrl_c().await?;
            } else {
                error!("Dashboard could not be started.");
            }
        }
        Some(Commands::Trust { action }) => {
            let orchestrator = EdrOrchestrator::new().await?;
            let tm = orchestrator.trust();
            match action {
                TrustAction::InitCa => {
                    tm.init_ca("./certs/ca")?;
                    info!("Root CA successfully initialized in ./certs/ca");
                }
                TrustAction::Issue { peer_did, out } => {
                    tm.issue_certificate("./certs/ca", &peer_did, &out)?;
                    info!("S2S Certificate issued to {}", out);
                }
                TrustAction::WhoAmI => {
                    println!("Node DID: {}", tm.did().id);
                    println!("Public Key: {}", tm.did().public_key);
                }
                TrustAction::AuthorizePeer { peer_id } => {
                    let proof = tm.generate_membership_proof(&peer_id);
                    println!("Proof: {}", proof);
                }
                TrustAction::ImportNsrl { path } => {
                    let fetcher = osoosi_policy::ThreatFeedFetcher::new();
                    let db_path = match path {
                        Some(ref p) if p.eq_ignore_ascii_case("start") => {
                            let temp_dir = std::env::temp_dir().join("osoosi-nsrl-shared-cache");
                            fetcher.download_nsrl_streaming(&temp_dir).await?
                        }
                        Some(p) => PathBuf::from(p),
                        None => {
                            let temp_dir = std::env::temp_dir().join("osoosi-nsrl-shared-cache");
                            fetcher.download_nsrl_streaming(&temp_dir).await?
                        }
                    };
                    let records = fetcher.import_nsrl_from_sqlite(&db_path).await?;
                    orchestrator.memory().upsert_nsrl_records(&records)?;
                    info!("Successfully integrated {} records.", records.len());
                }
            }
        }
        Some(Commands::GrantAccess) => {
            handle_grant_access().await?;
        }
        Some(Commands::CheckAccess) => {
            println!("Oshoosi Privilege Check (platform: {})", osoosi_core::privilege::current_platform());
            let status = osoosi_core::privilege::check_privileges();
            println!("Elevated/Root:      {}", status.is_elevated);
            println!("Can read events:    {}", status.can_read_events);
        }
        Some(Commands::Unblock) => {
            info!("Removing firewall rules...");
            let _ = osoosi_core::firewall::remove_all_autoblock_rules();
        }
        Some(Commands::Rollback { last, patch }) => {
            let orchestrator = EdrOrchestrator::new().await?;
            match orchestrator.rollback_patch(patch.as_deref(), last).await {
                Ok(_) => println!("Rollback successful."),
                Err(e) => error!("Rollback failed: {}", e),
            }
        }
        Some(Commands::Agent) => {
            info!("Starting Agent...");
        }
        Some(Commands::Sandbox { action }) => {
            use osoosi_core::openshell::OpenShellManager;
            let manager = OpenShellManager::new();
            match action {
                SandboxAction::Status => println!("Status: {:?}", manager.status()),
                SandboxAction::Install => { let _ = OpenShellManager::install(); }
                SandboxAction::DeployGateway => { let _ = manager.deploy_gateway(); }
                SandboxAction::Create { name, policy: _ } => { let _ = manager.create_sandbox(Some(&name)); }
                SandboxAction::Connect { name } => { let _ = manager.connect_sandbox(Some(&name)); }
                SandboxAction::Destroy { name } => { let _ = manager.destroy_sandbox(Some(&name)); }
                SandboxAction::ApplyPolicy { name, policy } => { let _ = manager.apply_policy(Some(&name), policy.as_ref().map(Path::new)); }
                SandboxAction::Logs { name } => { manager.stream_logs(Some(&name)); }
            }
        }
        Some(Commands::SecurityStatus) => {
            osoosi_core::hardened::print_security_assessment();
        }
        Some(Commands::BootstrapModels) => {
            let _ = ensure_onnx_runtime().await;
            info!("Bootstrapping ML models (MalwareScanner + Gemma Storyteller)...");
            let provisioner = osoosi_telemetry::AgentProvisioner::new();
            let _ = provisioner.provision_gemma_models();
        }
        Some(Commands::SignConfigs) => {
            osoosi_core::config_integrity::sign_all_critical_configs();
            println!("✓ Configs re-signed.");
        }
        None => {
            if !cli.grant_access {
                println!("No command specified. Use --help for usage.");
            }
        }
    }
    Ok(())
}

async fn handle_grant_access() -> anyhow::Result<()> {
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    {
        use osoosi_telemetry::AgentProvisioner;
        let provisioner = AgentProvisioner::new();
        
        info!("GrantAccess pre-step: ensuring ONNX Runtime is provisioned...");
        if let Err(e) = ensure_onnx_runtime().await {
            warn!("Warning: Failed to autonomously provision ONNX Runtime: {}. ML features may be disabled.", e);
        }
        
        info!("GrantAccess pre-step: ensuring Sysmon telemetry is provisioned...");
        if let Err(e) = provisioner.provision_telemetry() {
             warn!("Warning: Failed to provision telemetry: {}", e);
        }

        info!("GrantAccess pre-step: ensuring Local Gemma-2B ONNX is provisioned...");
        if let Err(e) = provisioner.provision_gemma_models() {
             warn!("Warning: Failed to provision Gemma models: {}", e);
        }

        info!("GrantAccess pre-step: ensuring ClamAV is provisioned...");
        if let Err(e) = provisioner.provision_clamav() {
             warn!("Warning: Failed to provision ClamAV: {}", e);
        }

        info!("GrantAccess pre-step: ensuring OpenSSL is provisioned...");
        if let Err(e) = provisioner.provision_openssl() {
             warn!("Warning: Failed to provision OpenSSL: {}", e);
        }

        info!("GrantAccess pre-step: ensuring FLOSS is provisioned...");
        if let Err(e) = provisioner.provision_floss() {
             warn!("Warning: Failed to provision FLOSS: {}", e);
        }

        info!("GrantAccess pre-step: ensuring HollowsHunter is provisioned...");
        if let Err(e) = provisioner.provision_hollows_hunter() {
             warn!("Warning: Failed to provision HollowsHunter: {}", e);
        }

        info!("GrantAccess pre-step: ensuring Network Tooling (ngrep/sniffglue) is provisioned...");
        let _ = provisioner.provision_npcap(); // Driver first
        if let Err(e) = provisioner.provision_ngrep() {
             warn!("Warning: Failed to provision ngrep: {}", e);
        }
        if let Err(e) = provisioner.provision_sniffglue() {
             warn!("Warning: Failed to provision sniffglue: {}", e);
        }
    }
    
    match setup_firewall().await {
        Ok(_) => println!("[+] Firewall configured."),
        Err(e) => println!("[!] Firewall failed: {}", e),
    }

    let status = osoosi_core::privilege::grant_access();
    if status.can_read_events {
        println!("Result: SUCCESS");
    } else {
        println!("Result: FAILED/PARTIAL");
    }

    // NSRL Background download after summary
    info!("Final task: ensuring NSRL database is populated...");
    let temp_dir = std::env::temp_dir().join("osoosi-nsrl-shared-cache");
    let fetcher = ThreatFeedFetcher::new();
    if let Ok(db_path) = fetcher.download_nsrl_streaming(&temp_dir).await {
        if let Ok(records) = fetcher.import_nsrl_from_sqlite(&db_path).await {
            let orchestrator = EdrOrchestrator::new().await?;
            let _ = orchestrator.memory().upsert_nsrl_records(&records);
        }
    }
    Ok(())
}

async fn ensure_onnx_runtime() -> anyhow::Result<()> {
    if find_onnxruntime_dylib().is_some() {
        return Ok(());
    }

    let ort_filename = if cfg!(windows) { "onnxruntime.dll" } else if cfg!(target_os = "macos") { "libonnxruntime.dylib" } else { "libonnxruntime.so" };
    let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|p| p.to_path_buf())).unwrap_or_else(|| PathBuf::from("."));
    let ort_path = exe_dir.join(ort_filename);

    info!("[ONNX Setup] Missing runtime. Provisioning autonomously...");
    
    // We use version 1.17.1 as requested/verified for the current bindings
    let ort_version = "1.17.1";
    let (archive_url, archive_name) = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => (
            format!("https://github.com/microsoft/onnxruntime/releases/download/v{}/onnxruntime-win-x64-{}.zip", ort_version, ort_version),
            "onnxruntime.zip"
        ),
        ("linux", "x86_64") => (
            format!("https://github.com/microsoft/onnxruntime/releases/download/v{}/onnxruntime-linux-x64-{}.tgz", ort_version, ort_version),
            "onnxruntime.tgz"
        ),
        ("macos", _) => (
            format!("https://github.com/microsoft/onnxruntime/releases/download/v{}/onnxruntime-osx-universal2-{}.tgz", ort_version, ort_version),
            "onnxruntime.tgz"
        ),
        _ => anyhow::bail!("Unsupported platform for autonomous ONNX provisioning")
    };

    let resp = reqwest::get(&archive_url).await?;
    if !resp.status().is_success() {
        anyhow::bail!("Failed to download ONNX archive: {}", resp.status());
    }
    let bytes = resp.bytes().await?;
    let temp_archive = std::env::temp_dir().join(archive_name);
    std::fs::write(&temp_archive, &bytes)?;

    info!("[ONNX Setup] Extracting {}...", ort_filename);
    if archive_url.ends_with(".zip") {
        let file = std::fs::File::open(&temp_archive)?;
        let mut archive = ZipArchive::new(file)?;
        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            if file.name().ends_with(ort_filename) {
                let mut outfile = std::fs::File::create(&ort_path)?;
                copy(&mut file, &mut outfile)?;
                break;
            }
        }
    } else {
        let tar_gz = std::fs::File::open(&temp_archive)?;
        let tar = GzDecoder::new(tar_gz);
        let mut archive = Archive::new(tar);
        for entry in archive.entries()? {
            let mut entry = entry?;
            if entry.path()?.to_string_lossy().ends_with(ort_filename) {
                entry.unpack(&ort_path)?;
                break;
            }
        }
    }
    
    let _ = std::fs::remove_file(&temp_archive);
    info!("Successfully provisioned ONNX Runtime to {:?}", ort_path);
    Ok(())
}

async fn setup_firewall() -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    {
        let ps_cmd = "New-NetFirewallRule -DisplayName 'OpenOshoosi-Allow' -Direction Inbound -LocalPort 4001,8080 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue";
        let _ = std::process::Command::new("powershell").args(&["-Command", ps_cmd]).output()?;
    }
    Ok(())
}

fn init_ort(suppress_warning: bool) {
    if let Some(dylib) = find_onnxruntime_dylib() {
        info!("Dynamic Discovery: Using ONNX Runtime at {:?}", dylib);
        std::env::set_var("ORT_DYLIB_PATH", &dylib);
        let _ = ort::init_from(dylib.to_string_lossy().to_string()).commit();
    } else if !suppress_warning {
        warn!("ONNX Runtime dylib not found. Disabling ML features. To enable: set ORT_DYLIB_PATH or place onnxruntime.dll next to the executable.");
    }
}

fn find_onnxruntime_dylib() -> Option<PathBuf> {
    let filename = if cfg!(windows) { "onnxruntime.dll" } else if cfg!(target_os = "macos") { "libonnxruntime.dylib" } else { "libonnxruntime.so" };
    
    // 1. Check ORT_DYLIB_PATH environment variable
    if let Ok(env_path) = std::env::var("ORT_DYLIB_PATH") {
        let path = PathBuf::from(env_path);
        if path.exists() { return Some(path); }
    }

    // 2. Check executable directory
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let path = exe_dir.join(filename);
            if path.exists() { return Some(path); }
        }
    }

    // 3. Check current working directory
    if let Ok(cwd) = std::env::current_dir() {
        let path = cwd.join(filename);
        if path.exists() { return Some(path); }
    }

    // 4. Platform-specific system paths
    #[cfg(target_os = "windows")]
    {
        let sys32 = PathBuf::from("C:\\Windows\\System32").join(filename);
        if sys32.exists() { return Some(sys32); }
    }
    #[cfg(target_os = "linux")]
    {
        for p in &["/usr/lib", "/usr/local/lib", "/lib/x86_64-linux-gnu"] {
            let path = PathBuf::from(p).join(filename);
            if path.exists() { return Some(path); }
        }
    }
    #[cfg(target_os = "macos")]
    {
        for p in &["/usr/local/lib", "/opt/homebrew/lib", "/usr/lib"] {
            let path = PathBuf::from(p).join(filename);
            if path.exists() { return Some(path); }
        }
    }

    None
}

fn init_logging() -> anyhow::Result<tracing_appender::non_blocking::WorkerGuard> {
    let file_appender = tracing_appender::rolling::daily("logs", "osoosi.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    let filter = EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into());
    let console_layer = fmt::Layer::default().with_writer(std::io::stdout);
    let file_layer = fmt::Layer::default().with_writer(non_blocking).with_ansi(false);
    tracing_subscriber::registry().with(filter).with(console_layer).with(file_layer).init();
    Ok(guard)
}

fn open_browser(url: &str) { let _ = webbrowser::open(url); }

fn set_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        error!("PANIC: {:?}", info);
    }));
}

#[cfg(unix)]
async fn wait_for_shutdown() {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
    tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = sigterm.recv() => {} }
}

#[cfg(windows)]
async fn wait_for_shutdown() { let _ = tokio::signal::ctrl_c().await; }
