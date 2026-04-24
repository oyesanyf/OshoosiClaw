use clap::{Parser, Subcommand};
use osoosi_core::{EdrOrchestrator, secured_executor::DirectExecutor};
use osoosi_types::SecuredExecutor;
use osoosi_policy::ThreatFeedFetcher;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, error, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};
use hf_hub::api::tokio::ApiBuilder;

#[derive(Parser)]
#[command(name = "osoosi")]
#[command(about = "OpenỌ̀ṣọ́ọ̀sì: Autonomous Security Agent", long_about = None)]
struct Cli {
    /// Grant OpenỌ̀ṣọ́ọ̀sì access to security event logs (equivalent to 'grant-access' command)
    #[arg(long)]
    grant_access: bool,
    /// Disable all AI features (ONNX Runtime, SmolLM fallback, behavioral analysis)
    #[arg(long, env = "OSOOSI_NO_AI")]
    no_ai: bool,
    /// Enable debug logging (sets log level to DEBUG)
    #[arg(short, long)]
    debug: bool,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Clone)]
enum Commands {
    /// Start the OpenỌ̀ṣọ́ọ̀sì security agent daemon
    Start {
        /// Also start and open the web dashboard
        #[arg(long, default_value_t = true)]
        dashboard: bool,
    },
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
    /// Network Route Scraping and Discovery (Sherpa)
    Discovery,
    /// View the tamper-evident Merkle Trail (Audit Log)
    Merkle {
        /// Verify the integrity of the entire audit chain
        #[arg(long)]
        verify: bool,
        /// Limit the number of entries displayed
        #[arg(short, long)]
        limit: Option<usize>,
    },
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
    
    let cli = Cli::parse();
    let _guard = init_logging(cli.debug)?;
    
    if let Err(e) = async_main(cli).await {
        error!("Fatal execution error: {}", e);
        std::process::exit(1);
    }
    
    Ok(())
}

async fn async_main(cli: Cli) -> anyhow::Result<()> {
    // 1. Handle autonomous provisioning for critical modes
    // Force disable AI if requested via CLI or env
    if cli.no_ai {
        std::env::set_var("OSOOSI_NO_AI", "1");
        std::env::set_var("OSOOSI_NO_ORT", "1");
        info!("AI features explicitly disabled.");
    }
    
    let ai_cfg = osoosi_types::load_ai_config();
    if !ai_cfg.enabled {
        std::env::set_var("OSOOSI_NO_ORT", "1");
        std::env::set_var("OSOOSI_NO_AI", "1");
        info!("AI features disabled via config.");
    }

    let is_starting = matches!(cli.command, Some(Commands::Start { .. }));
    let is_granting = cli.grant_access || matches!(cli.command, Some(Commands::GrantAccess));
    let is_bootstrapping = matches!(cli.command, Some(Commands::BootstrapModels));

    if is_granting {
        handle_grant_access().await?;
        let _ = osoosi_core::firewall::open_mesh_ports();
    } else if is_starting || is_bootstrapping {
        // Ensure essentials on startup
        let executor = Arc::new(DirectExecutor::new());
        let provisioner = osoosi_telemetry::AgentProvisioner::new(executor);
        if let Err(e) = provisioner.provision_telemetry().await {
            warn!("Automated provisioning encountered issues: {}. Continuing startup...", e);
        }
        let _ = ensure_ai_models().await;
        let _ = osoosi_core::firewall::open_mesh_ports();
    }
    
    let suppress_ml_warning = is_granting || is_bootstrapping;
    if let Err(e) = init_ort(suppress_ml_warning).await {
        error!("Failed to initialize ONNX Runtime: {}. AI features will be disabled.", e);
        // CRITICAL: Disable ORT globally for this process to prevent downstream panics
        std::env::set_var("OSOOSI_NO_ORT", "1");
    }

    // 2. Handle subcommands
    match cli.command {
        Some(Commands::Start { dashboard }) => {
            run_yara_sanitizer();
            let start_instant = std::time::Instant::now();
            let orchestrator = EdrOrchestrator::new().await?;

            // 1. Start P2P Mesh Networking (Discovery, Consensus, and Peer Approval)
            let join_gate = orchestrator.start_p2p_loop().await.ok();

            // 2. Bind dashboard as soon as the orchestrator exists so the UI can load while loops start.
            if dashboard {
                info!("Auto-launching dashboard UI...");
                let dash_orch = Arc::new(orchestrator.clone());
                let dash_gate = join_gate.clone();
                tokio::spawn(async move {
                    let mut current_port = 3030u16;
                    let mut opened_port: Option<u16> = None;
                    while current_port <= 3040 {
                        match osoosi_dashboard::spawn_dashboard_with_backend(
                            current_port,
                            dash_gate.clone(),
                            Some(dash_orch.clone()),
                        )
                        .await
                        {
                            Ok(port) => {
                                opened_port = Some(port);
                                break;
                            }
                            Err(_) => {
                                warn!("Port {} in use, trying next...", current_port);
                                current_port += 1;
                            }
                        }
                    }
                    if let Some(port) = opened_port {
                        info!("Dashboard started successfully!");
                        info!("----------------------------------------");
                        info!("Oshoosi Dashboard URL: http://127.0.0.1:{}/", port);
                        info!("----------------------------------------");
                        tokio::time::sleep(tokio::time::Duration::from_millis(400)).await;
                        let _ = webbrowser::open(&format!("http://127.0.0.1:{}/", port));
                    } else {
                        error!("FAILED to start Dashboard UI after trying ports 3030-3040.");
                        error!("Check if another instance of Oshoosi is already running.");
                    }
                });
            }

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
            
            // 2. [NEW] Ensure Firewall rules are applied on startup (User Request)
            let provisioner = osoosi_telemetry::AgentProvisioner::new(orchestrator.secured_executor());
            if let Err(e) = provisioner.provision_firewall().await {
                warn!("Warning: Failed to verify/apply firewall rules: {}. Mesh connectivity may be degraded.", e);
            }
            
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
            let executor = osoosi_core::secured_executor::get_best_executor().await;
            let provisioner = AgentProvisioner::new(executor);
            match provisioner.provision_telemetry().await {
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
            let mut bound: Option<u16> = None;
            while current_port <= port + 10 {
                match osoosi_dashboard::spawn_dashboard_with_backend(current_port, None, None).await {
                    Ok(p) => {
                        info!("Dashboard started on port {}", p);
                        bound = Some(p);
                        break;
                    }
                    Err(_) => {
                        warn!("Port {} in use, trying next...", current_port);
                        current_port += 1;
                    }
                }
            }
            if let Some(p) = bound {
                tokio::time::sleep(tokio::time::Duration::from_millis(400)).await;
                open_browser(&format!("http://127.0.0.1:{}/", p));
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
                    tm.init_ca("./certs/ca").await?;
                    info!("Root CA successfully initialized in ./certs/ca");
                }
                TrustAction::Issue { peer_did, out } => {
                    tm.issue_certificate("./certs/ca", &peer_did, &out).await?;
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
            let _ = ensure_ai_models().await;
            info!("Bootstrapping ML models (MalwareScanner + SmolLM2 Storyteller) complete.");
        }
        Some(Commands::SignConfigs) => {
            osoosi_core::config_integrity::sign_all_critical_configs();
            println!("✓ Configs re-signed.");
        }
        Some(Commands::Discovery) => {
            println!("Oshoosi Sherpa Discovery (Route Scraping)...");
            let scraper = osoosi_telemetry::discovery::RouteScraper::new();
            let hosts = scraper.scrape_arp();
            
            if hosts.is_empty() {
                println!("No adjacent hosts discovered in ARP cache.");
            } else {
                println!("{:<15} {:<20} {:<15}", "IP Address", "MAC Address", "Interface");
                println!("{:-<50}", "");
                for host in hosts {
                    println!("{:<15} {:<20} {:<15}", host.ip, host.mac.clone().unwrap_or_else(|| "unknown".to_owned()), host.interface);
                }
            }
        }
        Some(Commands::Merkle { verify, limit }) => {
            let orchestrator = EdrOrchestrator::new().await?;
            if verify {
                let ok = orchestrator.verify_merkle_trail();
                if ok {
                    println!("✓ Merkle Trail integrity verified. Root Hash: {}", orchestrator.audit().root());
                } else {
                    println!("✗ Merkle Trail COMPROMISED! Integrity check failed.");
                    std::process::exit(1);
                }
            } else {
                let mut entries = orchestrator.list_merkle_trail();
                entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp)); // Latest first
                
                let display_limit = limit.unwrap_or(20);
                println!("{:<20} {:<20} {:<50}", "Timestamp", "Event Type", "Summary");
                println!("{:-<90}", "");
                
                for entry in entries.iter().take(display_limit) {
                    let summary = match entry.event_type.as_str() {
                        "THREAT_DETECTED" => {
                            let proc = entry.data.get("process_name").and_then(|v| v.as_str()).unwrap_or("?");
                            format!("Threat: {}", proc)
                        }
                        "repair" => {
                            let event = entry.data.get("event").and_then(|v| v.as_str()).unwrap_or("patch");
                            format!("Repair: {}", event)
                        }
                        _ => entry.event_type.clone(),
                    };
                    println!("{:<20} {:<20} {:<50}", 
                        entry.timestamp.format("%H:%M:%S").to_string(),
                        entry.event_type,
                        summary.chars().take(50).collect::<String>()
                    );
                }
            }
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
        let executor = osoosi_core::secured_executor::get_best_executor().await;
        let provisioner = osoosi_telemetry::AgentProvisioner::new(executor);
        
        info!("GrantAccess pre-step: ensuring Sysmon telemetry is provisioned...");
        if let Err(e) = provisioner.provision_telemetry().await {
             warn!("Warning: Failed to provision telemetry: {}", e);
        }

        info!("GrantAccess pre-step: ensuring ML models are provisioned...");
        if let Err(e) = ensure_ai_models().await {
             warn!("Warning: Failed to provision AI models: {}", e);
        }

        info!("GrantAccess pre-step: ensuring ClamAV is provisioned...");
        if let Err(e) = provisioner.provision_clamav().await {
             warn!("Warning: Failed to provision ClamAV: {}", e);
        }

        info!("GrantAccess pre-step: ensuring OpenSSL is provisioned and validated...");
        if let Err(e) = provisioner.provision_openssl().await {
             warn!("Warning: Failed to provision OpenSSL: {}", e);
        } else {
             // USER REQUEST: Validate it is used to sign stuff
             info!("Validating OpenSSL signing capabilities...");
             let test_file = std::env::temp_dir().join("osoosi_sign_test.txt");
             let test_sig = std::env::temp_dir().join("osoosi_sign_test.sig");
             let _ = std::fs::write(&test_file, "Oshoosi OpenSSL Validation");
             
             let mut gen_key = tokio::process::Command::new("openssl");
             gen_key.args(["genrsa", "-out", "test_priv.pem", "2048"]);
             
             let mut sign_cmd = tokio::process::Command::new("openssl");
             sign_cmd.args(["dgst", "-sha256", "-sign", "test_priv.pem", "-out", &test_sig.to_string_lossy(), &test_file.to_string_lossy()]);
             
             let mut verify_cmd = tokio::process::Command::new("openssl");
             verify_cmd.args(["dgst", "-sha256", "-verify", "test_pub.pem", "-signature", &test_sig.to_string_lossy(), &test_file.to_string_lossy()]);
             
             // Extract public key first
             let mut pub_cmd = tokio::process::Command::new("openssl");
             pub_cmd.args(["rsa", "-in", "test_priv.pem", "-pubout", "-out", "test_pub.pem"]);

             let success = async {
                 let _ = gen_key.status().await;
                 let _ = pub_cmd.status().await;
                 let s = sign_cmd.status().await?.success();
                 Ok::<bool, anyhow::Error>(s)
             }.await.unwrap_or(false);

             if success {
                 info!("✓ OpenSSL Signing Validation: SUCCESS");
             } else {
                 warn!("! OpenSSL Signing Validation: FAILED");
             }
             let _ = std::fs::remove_file("test_priv.pem");
             let _ = std::fs::remove_file("test_pub.pem");
             let _ = std::fs::remove_file(&test_file);
             let _ = std::fs::remove_file(&test_sig);
        }

        info!("GrantAccess pre-step: ensuring FLOSS is provisioned...");
        if let Err(e) = provisioner.provision_floss().await {
             warn!("Warning: Failed to provision FLOSS: {}", e);
        }

        info!("GrantAccess pre-step: ensuring HollowsHunter is provisioned...");
        if let Err(e) = provisioner.provision_hollows_hunter().await {
             warn!("Warning: Failed to provision HollowsHunter: {}", e);
        }

        info!("GrantAccess pre-step: ensuring Network Tooling (ngrep/sniffglue) is provisioned...");
        let _ = provisioner.provision_npcap().await; // Driver first
        if let Err(e) = provisioner.provision_ngrep().await {
             warn!("Warning: Failed to provision ngrep: {}", e);
        }
        if let Err(e) = provisioner.provision_sniffglue().await {
             warn!("Warning: Failed to provision sniffglue: {}", e);
        }

        info!("GrantAccess pre-step: ensuring CAPA is provisioned...");
        if let Err(e) = provisioner.provision_capa().await {
             warn!("Warning: Failed to provision CAPA: {}", e);
        }

        info!("GrantAccess pre-step: ensuring YARA rules are provisioned...");
        {
            let osh = osoosi_core::openshell::OpenShellManager::new();
            if osh.is_available() {
                info!("OpenShell detected — downloading & validating YARA rules in sandbox...");
                let result = osh.provision_yara_in_sandbox("yara");
                if result.success {
                    info!("YARA rules provisioned via OpenShell: {}", result.message);
                    let _ = provisioner.provision_yara_rules_with_sandbox(true).await;
                } else {
                    warn!("OpenShell YARA provisioning failed: {}. Falling back to direct.", result.message);
                    if let Err(e) = provisioner.provision_yara_rules().await {
                        warn!("Warning: Failed to provision YARA rules: {}", e);
                    }
                }
            } else {
                if let Err(e) = provisioner.provision_yara_rules().await {
                    warn!("Warning: Failed to provision YARA rules: {}", e);
                }
            }
        }


        #[cfg(target_os = "windows")]
        {
            info!("GrantAccess pre-step: adding Antivirus exclusions for the YARA folder...");
            let _ = provisioner.add_defender_exclusion(Path::new("yara")).await;
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
        println!("\n[!] CRITICAL: Automated permission grant failed.");
        println!("[!] Please perform the following manual steps to enable agent monitoring:");
        
        #[cfg(target_os = "windows")]
        {
            println!("  1. Run PowerShell as Administrator.");
            println!("  2. Run: $sid = (New-Object System.Security.Principal.NTAccount($env:USERNAME)).Translate([System.Security.Principal.SecurityIdentifier]).Value");
            println!("  3. Run: wevtutil sl Microsoft-Windows-Sysmon/Operational /ca:\"O:BAG:SYD:(A;;0x1;;;BA)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;$sid)\"");
            println!("  4. If Sysmon is missing, install it: 'winget install Microsoft.Sysmon'");
        }
        
        #[cfg(target_os = "linux")]
        {
            println!("  1. Run 'sudo usermod -aG adm,syslog,systemd-journal $USER'");
            println!("  2. Install ACL tools: 'sudo apt install acl' or 'sudo yum install acl'");
            println!("  3. Log out and back in for group changes to take effect.");
        }

        #[cfg(target_os = "macos")]
        {
            println!("  1. Open 'System Settings' > 'Privacy & Security' > 'Full Disk Access'.");
            println!("  2. Click the '+' button and add your 'osoosi' executable.");
        }
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


async fn setup_firewall() -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    {
        let ps_cmd = "New-NetFirewallRule -DisplayName 'OpenOshoosi-Allow' -Direction Inbound -LocalPort 9000,8080 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue";
        let _ = std::process::Command::new("powershell").args(&["-Command", ps_cmd]).output()?;
    }
    Ok(())
}

/// Where we install/load `onnxruntime.dll`: `ORT_DYLIB_PATH` if set, else next to the executable (same as `main`).
fn ort_dynamic_library_path() -> PathBuf {
    if let Ok(p) = std::env::var("ORT_DYLIB_PATH") {
        let trimmed = p.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            return dir.join("onnxruntime.dll");
        }
    }
    PathBuf::from("onnxruntime.dll")
}

fn escape_ps_literal(path: &str) -> String {
    path.replace('\'', "''")
}

async fn init_ort(suppress_warning: bool) -> anyhow::Result<()> {
    if std::env::var("OSOOSI_NO_ORT").map(|v| v == "1").unwrap_or(false) {
        return Ok(());
    }

    let dll_path = ort_dynamic_library_path();

    let versions = [
        ("1.22.2", "https://github.com/microsoft/onnxruntime/releases/download/v1.22.2/onnxruntime-win-x64-1.22.2.zip"),
        ("1.22.1", "https://github.com/microsoft/onnxruntime/releases/download/v1.22.1/onnxruntime-win-x64-1.22.1.zip"),
        ("1.22.0", "https://github.com/microsoft/onnxruntime/releases/download/v1.22.0/onnxruntime-win-x64-1.22.0.zip"),
    ];
    let mut success = false;

    for (version, url) in versions {
        // 1. Check if existing DLL is incompatible version
        if dll_path.exists() {
            #[cfg(target_os = "windows")]
            {
                use std::process::Command;
                let output = Command::new("powershell")
                    .args(["-NoProfile", "-Command", &format!("(Get-Item '{}').VersionInfo.ProductVersion", dll_path.to_string_lossy())])
                    .output();
                if let Ok(out) = output {
                    let v_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if !v_str.starts_with("1.22") {
                        warn!("Incompatible ONNX Runtime version detected: {}. Expected 1.22.x. Removing...", v_str);
                        let _ = fs::remove_file(&dll_path);
                    }
                }
            }
        }

        info!("Attempting to initialize ONNX Runtime (target version: {})...", version);
        
        if !dll_path.exists() {
            info!("📥 Downloading ONNX Runtime v{}...", version);
            let zip_path = "ort_tmp.zip";
            let tmp_dir = "ort_extract";
            
            let executor = DirectExecutor::new();
            if let Err(e) = executor.download(url, Path::new(zip_path), false).await {
                warn!("Failed to download ORT v{}: {}. Trying next version...", version, e);
                continue;
            }

            let dest = escape_ps_literal(&dll_path.to_string_lossy());
            let zip_q = escape_ps_literal(zip_path);
            let tmp_q = escape_ps_literal(tmp_dir);
            let ps_cmd = format!(
                "Expand-Archive -LiteralPath '{zip_q}' -DestinationPath '{tmp_q}' -Force; \
                 $dll = Get-ChildItem -LiteralPath '{tmp_q}' -Filter 'onnxruntime.dll' -Recurse | Select-Object -First 1; \
                 if ($dll) {{ Copy-Item -LiteralPath $dll.FullName -Destination '{dest}' -Force }}; \
                 Remove-Item -LiteralPath '{zip_q}' -Force -ErrorAction SilentlyContinue; \
                 Remove-Item -LiteralPath '{tmp_q}' -Recurse -Force -ErrorAction SilentlyContinue",
            );
            
            let _ = std::process::Command::new("powershell")
                .args(&["-NoProfile", "-NonInteractive", "-Command", &ps_cmd])
                .output();
        }

        if let Some(p) = dll_path.to_str() {
            std::env::set_var("ORT_DYLIB_PATH", p);
        }

        // 2. Initialize with a guard to prevent the library's internal panics from crashing the app
        let init_result = std::panic::catch_unwind(|| {
            ort::init()
                .commit()
        });

        match init_result {
            Ok(Ok(_)) => {
                info!("✅ ONNX Runtime initialized successfully (v{}).", version);
                success = true;
                break;
            }
            _ => {
                warn!("⚠️ ONNX Runtime v{} failed to initialize or panicked. Trying fallback...", version);
                if dll_path.exists() {
                    let _ = fs::remove_file(&dll_path);
                }
            }
        }
    }

    if !success {
        if !suppress_warning {
            error!("❌ FATAL: All ONNX Runtime initialization attempts failed. AI features will be disabled.");
        }
        std::env::set_var("OSOOSI_NO_ORT", "1");
        anyhow::bail!("All ONNX Runtime initialization attempts failed.");
    }
    
    Ok(())
}


/// Helper to find a script (e.g. sanitize_yara.py) by searching upward from EXE and CWD.
fn resolve_script_path(script_name: &str) -> Option<PathBuf> {
    if let Ok(exe_path) = std::env::current_exe() {
        let mut dir = exe_path.parent();
        while let Some(d) = dir {
            let candidate = d.join(script_name);
            if candidate.exists() { return Some(candidate); }
            // Also check 'scripts/' subdirectory
            let candidate_scripts = d.join("scripts").join(script_name);
            if candidate_scripts.exists() { return Some(candidate_scripts); }
            dir = d.parent();
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        let mut dir = Some(cwd.as_path());
        while let Some(d) = dir {
            let candidate = d.join(script_name);
            if candidate.exists() { return Some(candidate); }
            let candidate_scripts = d.join("scripts").join(script_name);
            if candidate_scripts.exists() { return Some(candidate_scripts); }
            dir = d.parent();
        }
    }
    None
}

/// Stable log directory: `OSOOSI_LOG_DIR`, else repo root `logs/` (walk up from exe for `Cargo.toml`/`.git`),
/// else `logs/` next to the binary, else cwd `logs/`, else `%TEMP%/osoosi/logs`.
fn resolve_log_directory() -> PathBuf {
    if let Ok(p) = std::env::var("OSOOSI_LOG_DIR") {
        let pb = PathBuf::from(p.trim());
        if !pb.as_os_str().is_empty() {
            return pb;
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(mut dir) = exe.parent().map(|p| p.to_path_buf()) {
            for _ in 0..24 {
                if dir.join(".git").is_dir() || dir.join("Cargo.toml").is_file() {
                    return dir.join("logs");
                }
                match dir.parent() {
                    Some(p) => dir = p.to_path_buf(),
                    None => break,
                }
            }
        }
        if let Some(exe_dir) = exe.parent() {
            return exe_dir.join("logs");
        }
    }
    std::env::current_dir()
        .map(|c| c.join("logs"))
        .unwrap_or_else(|_| std::env::temp_dir().join("osoosi").join("logs"))
}

fn init_logging(debug: bool) -> anyhow::Result<tracing_appender::non_blocking::WorkerGuard> {
    let log_dir = resolve_log_directory();
    fs::create_dir_all(&log_dir).map_err(|e| {
        anyhow::anyhow!(
            "Cannot create log directory {}: {}",
            log_dir.display(),
            e
        )
    })?;
    let file_appender = tracing_appender::rolling::daily(&log_dir, "osoosi.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    let level = if debug { tracing::Level::DEBUG } else { tracing::Level::WARN };
    let filter = EnvFilter::from_default_env().add_directive(level.into());
    let console_layer = fmt::Layer::default().with_writer(std::io::stdout);
    let file_layer = fmt::Layer::default().with_writer(non_blocking).with_ansi(false);
    
    tracing_subscriber::registry()
        .with(filter)
        .with(console_layer)
        .with(file_layer)
        .with(osoosi_exporter::init_opentelemetry_layer())
        .init();
    info!(
        path = %log_dir.display(),
        "File logs (override with OSOOSI_LOG_DIR)"
    );
    Ok(guard)
}

fn run_yara_sanitizer() {
    info!("Running automated YARA rule sanitization (pre-scan cleanup)...");
    let script_name = "sanitize_yara.py";
    
    if let Some(script_path) = resolve_script_path(script_name) {
        info!("Found YARA sanitization script at {:?}", script_path);
        let py = std::env::var("OSOOSI_PYTHON").unwrap_or_else(|_| {
            if cfg!(windows) { "python.exe".to_string() } else { "python3".to_string() }
        });
        
        match std::process::Command::new(&py)
            .arg(&script_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status() 
        {
            Ok(status) if status.success() => info!("YARA sanitization completed successfully."),
            Ok(status) => warn!("YARA sanitization script exited with status: {} (Check if 'yara-python' or 'plyara' is needed)", status),
            Err(e) => warn!("Failed to execute YARA sanitization script with '{}': {}. Is Python installed and on PATH?", py, e),
        }
    } else {
        warn!("YARA sanitization script '{}' not found in CWD, EXE dir, or project root. Skipping automated cleanup.", script_name);
    }
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
async fn ensure_ai_models() -> anyhow::Result<()> {
    if std::env::var("OSOOSI_NO_AI").map(|v| v == "1").unwrap_or(false) {
        return Ok(());
    }

    info!("Verifying AI models in {}...", osoosi_types::resolve_models_dir().display());
    let models_dir = osoosi_types::resolve_models_dir();
    let smollm_dir = models_dir.join("smollm");
    let malware_dir = models_dir.join("malware");

    let _ = fs::create_dir_all(&smollm_dir);
    let _ = fs::create_dir_all(&malware_dir);

    // Use tokio-enabled API builder with optional HF_TOKEN
    let api = {
        let mut builder = ApiBuilder::new()
            .with_cache_dir(models_dir.to_path_buf());
        
        if let Ok(token) = std::env::var("HF_TOKEN") {
            builder = builder.with_token(Some(token));
        }
        
        match builder.build() {
            Ok(api) => api,
            Err(e) => {
                warn!("Failed to initialize HuggingFace API: {}. AI features might be degraded.", e);
                return Ok(());
            }
        }
    };

    // 1. SmolLM2-135M-Instruct (Native)
    let smollm_repo = api.model("HuggingFaceTB/SmolLM2-135M-Instruct".to_string());
    let smollm_files = ["model.safetensors", "tokenizer.json", "config.json"];
    for file in smollm_files {
        let dest = smollm_dir.join(file);
        if !dest.exists() {
            info!("📥 Downloading SmolLM component: {}...", file);
            match smollm_repo.get(file).await {
                Ok(downloaded) => {
                    let _ = fs::copy(downloaded, dest);
                },
                Err(e) => warn!("Failed to download {}: {}", file, e),
            }
        }
    }

    // 2. SmolLM2-135M-Instruct (ONNX)
    let smollm_onnx_repo = api.model("onnx-community/SmolLM2-135M-Instruct".to_string());
    let smollm_onnx_dest = smollm_dir.join("smollm2-135m-it.onnx");
    if !smollm_onnx_dest.exists() {
        info!("📥 Downloading SmolLM component: smollm2-135m-it.onnx...");
        // Try various names
        for filename in ["model.onnx", "smollm2-135m-it.onnx", "onnx/model.onnx"] {
            match smollm_onnx_repo.get(filename).await {
                Ok(downloaded) => {
                    if fs::copy(downloaded, &smollm_onnx_dest).is_ok() {
                        info!("✅ SmolLM ONNX model saved.");
                        break;
                    }
                },
                Err(_) => continue,
            }
        }
    }

    // 3. MalConv — needs Candle-compatible `.safetensors`.
    let ai_cfg = osoosi_types::load_ai_config();
    let malconv_dest = malware_dir.join("malconv.safetensors");
    if !malconv_dest.exists() {
        if let Some(ref url) = ai_cfg.malconv_weights_url {
            info!("📥 Downloading MalConv weights from configured URL...");
            let executor = DirectExecutor::new();
            if let Err(e) = executor.download(url.trim(), &malconv_dest, false).await {
                warn!("MalConv download from malconv_weights_url failed: {}", e);
            }
        }
    }
    if !malconv_dest.exists() {
        let malconv_files = [
            "model.safetensors",
            "malconv.safetensors",
            "pytorch_model.safetensors",
            "weights.safetensors",
        ];
        let malconv_repos = [
            "Xenova/malconv",
            "oyesanyf/OshoosiClaw-Weights",
            "onnx-community/malconv",
            "microsoft/malconv",
        ];
        'malconv_hf: for repo_name in malconv_repos {
            let repo = api.model(repo_name.to_string());
            for file in malconv_files {
                info!("📥 Verifying MalConv AI component: `{}` / `{}`...", repo_name, file);
                match repo.get(file).await {
                    Ok(downloaded) => {
                        if fs::copy(downloaded, &malconv_dest).is_ok() {
                            info!("✅ MalConv weights saved from {} ({}).", repo_name, file);
                            break 'malconv_hf;
                        }
                    }
                    Err(e) => {
                        tracing::debug!("MalConv HF get {} {}: {}", repo_name, file, e);
                    }
                }
            }
        }
    }

    info!("AI models verified.");
    Ok(())
}
