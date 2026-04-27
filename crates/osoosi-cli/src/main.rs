use clap::{Parser, Subcommand};
use osoosi_core::{secured_executor::DirectExecutor, EdrOrchestrator};
use osoosi_policy::ThreatFeedFetcher;
use osoosi_types::SecuredExecutor;

use hf_hub::api::tokio::ApiBuilder;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{error, info, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

/// Fast `ATTACH`+`INSERT…SELECT` into the agent DB; on failure, fall back to loading all rows in Rust.
async fn import_nsrl_with_fallback(
    mem: &Arc<osoosi_memory::MemoryStore>,
    nist_path: &Path,
    fetcher: &ThreatFeedFetcher,
) {
    match mem.import_nsrl_from_nist_rds_sqlite(nist_path) {
        Ok(added) => {
            let total = mem.nsrl_record_count().unwrap_or(0);
            info!(
                "[NSRL] Fast bulk import from {:?}: {} new rows (nsrl total ~{}).",
                nist_path, added, total
            );
        }
        Err(e) => {
            warn!(
                "[NSRL] Fast SQL import failed ({}); falling back to row-by-row load (high RAM).",
                e
            );
            match fetcher.import_nsrl_from_sqlite(nist_path).await {
                Ok(records) => {
                    if let Err(e2) = mem.upsert_nsrl_records(&records) {
                        error!("[NSRL] Fallback upsert failed: {}", e2);
                    } else {
                        info!("[NSRL] Fallback: stored {} NSRL records.", records.len());
                    }
                }
                Err(e2) => error!("[NSRL] Fallback read failed: {}", e2),
            }
        }
    }
}

#[derive(Parser)]
#[command(name = "osoosi")]
#[command(about = "OpenỌ̀ṣọ́ọ̀sì: Autonomous Security Agent", long_about = None)]
struct Cli {
    /// Grant OpenỌ̀ṣọ́ọ̀sì access to security event logs (equivalent to `grant-access` subcommand). Works before or after subcommands, e.g. `osoosi start --grant-access`
    #[arg(long, global = true)]
    grant_access: bool,
    /// Disable all AI features (ONNX Runtime, SmolLM fallback, behavioral analysis)
    #[arg(long, env = "OSOOSI_NO_AI", global = true)]
    no_ai: bool,
    /// Enable debug logging (sets log level to DEBUG). Allowed before or after subcommands, e.g. `osoosi sandbox status --debug`
    #[arg(short, long, global = true)]
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
        /// Do not open the web dashboard (applies to this process and, with `--sandbox`, the agent in the sandbox)
        #[arg(long, default_value_t = false)]
        no_dashboard: bool,
        /// Run the agent inside an NVIDIA OpenShell sandbox (`openshell sandbox create` runs `osoosi start` inside). On success this process exits; no host daemon.
        #[arg(long)]
        sandbox: bool,
        /// Sandbox name when using `--sandbox` (default: osoosi)
        #[arg(long, default_value = "osoosi")]
        sandbox_name: String,
        /// Run `openshell gateway deploy` before creating the sandbox
        #[arg(long, default_value_t = false)]
        sandbox_deploy_gateway: bool,
        /// Windows helper: run the Linux Oshoosi build inside WSL2 and enable OpenShell sandboxing there.
        #[arg(long, alias = "wdlflag", default_value_t = false)]
        wsl: bool,
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
    Create {
        name: String,
        policy: Option<String>,
    },
    /// Connect to sandbox
    Connect { name: String },
    /// Destroy sandbox
    Destroy { name: String },
    /// Apply policy to sandbox
    ApplyPolicy {
        name: String,
        policy: Option<String>,
    },
    /// Stream logs from sandbox
    Logs { name: String },
}

fn main() -> anyhow::Result<()> {
    // Rayon global pool for CPU-tier analysis (policy+entropy bridge, parallel scans). Must run before any `rayon::spawn`.
    osoosi_core::init_hybrid_concurrency();
    let worker_threads = osoosi_core::tokio_worker_threads();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .max_blocking_threads(osoosi_core::max_blocking_threads())
        .enable_all()
        .thread_name_fn(|| {
            static C: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let n = C.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            format!("osoosi-tokio-{}", n)
        })
        .build()?;
    match rt.block_on(async {
        set_panic_hook();
        let cli = Cli::parse();
        let _guard = init_logging(cli.debug)?;
        async_main(cli).await
    }) {
        Ok(()) => Ok(()),
        Err(e) => {
            eprintln!("Fatal execution error: {}", e);
            std::process::exit(1);
        }
    }
}

async fn async_main(cli: Cli) -> anyhow::Result<()> {
    info!(
        tokio_workers = osoosi_core::tokio_worker_threads(),
        max_blocking = osoosi_core::max_blocking_threads(),
        rayon = osoosi_core::rayon_thread_count(),
        "Hybrid runtime: Tokio I/O + Rayon compute pools configured"
    );
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
        // Provision models during initial setup
        info!("🕸️ [SETUP] Provisioning AI models for first-run access...");
        let _ = ensure_ai_models().await;
    } 
    
    if is_bootstrapping {
        // Ensure essentials on bootstrap
        let executor = Arc::new(DirectExecutor::new());
        let provisioner = osoosi_telemetry::AgentProvisioner::new(executor);
        if let Err(e) = provisioner.provision_telemetry().await {
            warn!(
                "Automated provisioning encountered issues: {}. Continuing startup...",
                e
            );
        }
        let _ = ensure_ai_models().await;
        let _ = osoosi_core::firewall::open_mesh_ports();
    } else if is_starting {
        let executor = Arc::new(DirectExecutor::new());
        let provisioner = osoosi_telemetry::AgentProvisioner::new(executor);
        tokio::spawn(async move {
            info!("Startup provisioning is running in the background so Sysmon ingestion can begin immediately.");
            if let Err(e) = provisioner.provision_telemetry().await {
                warn!(
                    "Background provisioning encountered issues: {}. Agent monitoring continues.",
                    e
                );
            }
            let _ = ensure_ai_models().await;
        });
        let _ = osoosi_core::firewall::open_mesh_ports();
    }

    let suppress_ml_warning = is_granting || is_bootstrapping;
    if let Err(e) = init_ort(suppress_ml_warning).await {
        error!(
            "Failed to initialize ONNX Runtime: {}. AI features will be disabled.",
            e
        );
        // CRITICAL: Disable ORT globally for this process to prevent downstream panics
        std::env::set_var("OSOOSI_NO_ORT", "1");
    }

    // 2. Handle subcommands
    match cli.command {
        Some(Commands::Start {
            dashboard,
            no_dashboard,
            sandbox: start_in_sandbox,
            sandbox_name,
            sandbox_deploy_gateway,
            wsl,
        }) => {
            osoosi_core::tool_paths::discover_and_persist();
            run_yara_sanitizer();
            let with_dashboard = dashboard && !no_dashboard;

            if wsl {
                return start_inside_wsl(
                    with_dashboard,
                    start_in_sandbox,
                    &sandbox_name,
                    sandbox_deploy_gateway,
                );
            }

            if start_in_sandbox {
                use osoosi_core::openshell::OpenShellManager;
                let manager = OpenShellManager::new();
                if !manager.is_available() {
                    warn!(
                        "--sandbox: OpenShell CLI not found. Oshoosi checks tools/openshell/openshell(.exe), OPENSHELL_CLI_PATH, and PATH. NVIDIA OpenShell v0.0.36 does not publish a native Windows .exe asset; use WSL/Linux OpenShell or place a compatible openshell.exe in tools/openshell. Starting agent on the host instead."
                    );
                } else {
                    if sandbox_deploy_gateway {
                        let g = manager.deploy_gateway();
                        if !g.success {
                            warn!("--sandbox: gateway deploy did not succeed ({}). Proceeding to sandbox create…", g.message);
                        }
                    }
                    let extra: &[&str] = if with_dashboard {
                        &[]
                    } else {
                        &["--no-dashboard"]
                    };
                    let r = manager.create_sandbox(Some(sandbox_name.as_str()), extra);
                    if r.success {
                        info!("Sandbox created; agent is running inside OpenShell. Exiting host process.");
                        return Ok(());
                    }
                    warn!("--sandbox: OpenShell create failed ({}). Starting agent on the host instead.", r.message);
                }
            }

            let start_instant = std::time::Instant::now();
            let orchestrator = EdrOrchestrator::new().await?;

            // 1. Start P2P Mesh Networking (Discovery, Consensus, and Peer Approval)
            let join_gate = orchestrator.start_p2p_loop().await.ok();

            // 2. Bind dashboard as soon as the orchestrator exists so the UI can load while loops start.
            if with_dashboard {
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
                            info!("[NSRL Background] Download complete at {:?}. Importing (fast path when possible)...", db_path);
                            import_nsrl_with_fallback(
                                &nsrl_orch.memory(),
                                db_path.as_path(),
                                &fetcher,
                            )
                            .await;
                        }
                        Err(e) => error!("[NSRL Background] Failed to download NSRL: {}", e),
                    }
                } else if nsrl_count == 0 && db_file.exists() {
                    info!("[NSRL Background] NSRL SQLite found on disk but agent DB empty. Importing...");
                    import_nsrl_with_fallback(&nsrl_orch.memory(), &db_file, &fetcher).await;
                }
            });

            info!("Starting OpenỌ̀ṣọ́ọ̀sì Security Agent...");

            // 2. [NEW] Ensure Firewall rules are applied on startup (User Request)
            let provisioner =
                osoosi_telemetry::AgentProvisioner::new(orchestrator.secured_executor());
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

            let watch_paths = osoosi_types::load_watch_paths_from_config()
                .unwrap_or_else(osoosi_types::all_physical_drive_paths);
            let paths_refs: Vec<&str> = watch_paths.iter().map(String::as_str).collect();
            let _ = orchestrator.start_file_watcher_paths(&paths_refs).await;

            let event_source = if cfg!(windows) {
                "Microsoft-Windows-Sysmon/Operational".to_string()
            } else {
                "default".to_string()
            };
            orchestrator.start_host_event_loop(&event_source, 1).await;

            info!(
                "OpenỌ̀ṣọ́ọ̀sì Agent is live and monitoring (Total startup: {:?}).",
                start_instant.elapsed()
            );

            wait_for_shutdown().await;
            info!("Shutting down OpenỌ̀ṣọ́ọ̀sì Agent...");
            let _ = osoosi_core::firewall::remove_all_autoblock_rules();
        }
        Some(Commands::Status) => {
            println!("Oshoosi Status: Active");
            println!("Node ID: {}", uuid::Uuid::new_v4());
        }
        Some(Commands::Provision {
            binary: _,
            config: _,
        }) => {
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
                match osoosi_dashboard::spawn_dashboard_with_backend(current_port, None, None).await
                {
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
                    import_nsrl_with_fallback(&orchestrator.memory(), db_path.as_path(), &fetcher)
                        .await;
                    info!("NSRL import finished (see logs for row counts).");
                }
            }
        }
        Some(Commands::GrantAccess) => {
            // `handle_grant_access()` already ran when `is_granting` (top of `async_main`).
        }
        Some(Commands::CheckAccess) => {
            println!(
                "Oshoosi Privilege Check (platform: {})",
                osoosi_core::privilege::current_platform()
            );
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
                SandboxAction::Install => {
                    let _ = OpenShellManager::install();
                }
                SandboxAction::DeployGateway => {
                    let _ = manager.deploy_gateway();
                }
                SandboxAction::Create { name, policy: _ } => {
                    let _ = manager.create_sandbox(Some(&name), &[]);
                }
                SandboxAction::Connect { name } => {
                    let _ = manager.connect_sandbox(Some(&name));
                }
                SandboxAction::Destroy { name } => {
                    let _ = manager.destroy_sandbox(Some(&name));
                }
                SandboxAction::ApplyPolicy { name, policy } => {
                    let _ = manager.apply_policy(Some(&name), policy.as_ref().map(Path::new));
                }
                SandboxAction::Logs { name } => {
                    manager.stream_logs(Some(&name));
                }
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
                println!(
                    "{:<15} {:<20} {:<15}",
                    "IP Address", "MAC Address", "Interface"
                );
                println!("{:-<50}", "");
                for host in hosts {
                    println!(
                        "{:<15} {:<20} {:<15}",
                        host.ip,
                        host.mac.clone().unwrap_or_else(|| "unknown".to_owned()),
                        host.interface
                    );
                }
            }
        }
        Some(Commands::Merkle { verify, limit }) => {
            let orchestrator = EdrOrchestrator::new().await?;
            if verify {
                let ok = orchestrator.verify_merkle_trail();
                if ok {
                    println!(
                        "✓ Merkle Trail integrity verified. Root Hash: {}",
                        orchestrator.audit().root()
                    );
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
                            let proc = entry
                                .data
                                .get("process_name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("?");
                            format!("Threat: {}", proc)
                        }
                        "repair" => {
                            let event = entry
                                .data
                                .get("event")
                                .and_then(|v| v.as_str())
                                .unwrap_or("patch");
                            format!("Repair: {}", event)
                        }
                        _ => entry.event_type.clone(),
                    };
                    println!(
                        "{:<20} {:<20} {:<50}",
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

#[cfg(windows)]
fn start_inside_wsl(
    with_dashboard: bool,
    sandbox: bool,
    sandbox_name: &str,
    deploy_gateway: bool,
) -> anyhow::Result<()> {
    ensure_wsl_ready()?;

    let cwd = std::env::current_dir()?;
    let repo_root = find_repo_root_for_wsl(&cwd);
    let wsl_cwd = windows_path_to_wsl(&repo_root)?;
    let mut args = vec!["start".to_string()];
    if sandbox {
        args.push("--sandbox".to_string());
        args.push("--sandbox-name".to_string());
        args.push(sandbox_name.to_string());
        if deploy_gateway {
            args.push("--sandbox-deploy-gateway".to_string());
        }
    }
    if !with_dashboard {
        args.push("--no-dashboard".to_string());
    }

    let cmdline = args
        .iter()
        .map(|a| sh_quote(a))
        .collect::<Vec<_>>()
        .join(" ");
    let script = format!(
        "set -e; cd {}; \
         if ! command -v curl >/dev/null 2>&1; then \
           echo '[Oshoosi] Installing curl inside WSL...'; sudo apt-get update && sudo apt-get install -y curl ca-certificates; \
         fi; \
         if ! command -v cargo >/dev/null 2>&1; then \
           echo '[Oshoosi] Installing Rust toolchain inside WSL...'; curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; \
         fi; \
         export PATH=\"$HOME/.cargo/bin:$PATH\"; \
         if ! command -v openshell >/dev/null 2>&1; then \
           echo '[Oshoosi] Installing NVIDIA OpenShell inside WSL...'; curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh; export PATH=\"$HOME/.local/bin:$HOME/.cargo/bin:$PATH\"; \
         fi; \
         if ! docker info >/dev/null 2>&1; then \
           echo 'Docker is not reachable from WSL. Enable Docker Desktop WSL integration for this distro.' >&2; exit 126; \
         fi; \
         if ! command -v openshell >/dev/null 2>&1; then \
           echo 'OpenShell installation did not expose an openshell command in WSL PATH.' >&2; exit 127; \
         fi; \
         if [ ! -x ./target/release/osoosi ]; then \
           echo '[Oshoosi] Linux binary missing; building inside WSL...'; cargo build --release; \
         fi; \
         export OSOOSI_SECURE_RUNTIME=openshell; \
         exec ./target/release/osoosi {}",
        sh_quote(&wsl_cwd),
        cmdline
    );

    info!("Starting Oshoosi inside WSL2 at {}", wsl_cwd);
    let status = std::process::Command::new("wsl.exe")
        .args(["sh", "-lc", &script])
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "WSL Oshoosi start failed with status {}",
            status
        ))
    }
}

#[cfg(windows)]
fn ensure_wsl_ready() -> anyhow::Result<()> {
    let status = std::process::Command::new("wsl.exe")
        .arg("--status")
        .output();

    match status {
        Ok(output) if output.status.success() => {
            if wsl_has_distro()? {
                return Ok(());
            }
            provision_ubuntu_distro()?;
            Err(anyhow::anyhow!(
                "Oshoosi started Ubuntu provisioning for WSL. Run `osoosi start --wsl --sandbox ...` again after Ubuntu finishes first-run setup."
            ))
        }
        Ok(output) => {
            let combined = decode_command_output(&output.stdout, &output.stderr);
            let normalized = combined.replace('\0', "").to_ascii_lowercase();
            warn!(
                "WSL status is not usable yet (exit: {:?}). Provisioning WSL optional component. Details: {}",
                output.status.code(),
                normalized.trim()
            );
            provision_wsl_optional_component()?;
            Err(anyhow::anyhow!(
                "Oshoosi launched WSL optional-component provisioning. Approve the Windows UAC prompt if shown. Reboot Windows if requested, then run the same `osoosi start --wsl --sandbox ...` command again."
            ))
        }
        Err(e) => Err(anyhow::anyhow!("Could not run wsl.exe: {}", e)),
    }
}

#[cfg(windows)]
fn decode_command_output(stdout: &[u8], stderr: &[u8]) -> String {
    fn decode_one(bytes: &[u8]) -> String {
        if bytes.len() >= 2 && bytes.len() % 2 == 0 {
            let nul_odd = bytes.iter().skip(1).step_by(2).filter(|&&b| b == 0).count();
            if nul_odd > bytes.len() / 4 {
                let words = bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect::<Vec<_>>();
                return String::from_utf16_lossy(&words);
            }
        }
        String::from_utf8_lossy(bytes).to_string()
    }

    format!("{}\n{}", decode_one(stdout), decode_one(stderr))
}

#[cfg(windows)]
fn wsl_has_distro() -> anyhow::Result<bool> {
    let output = std::process::Command::new("wsl.exe")
        .args(["-l", "-q"])
        .output()?;
    if !output.status.success() {
        return Ok(false);
    }
    let text = String::from_utf8_lossy(&output.stdout)
        .replace('\0', "")
        .trim()
        .to_string();
    Ok(!text.is_empty())
}

#[cfg(windows)]
fn provision_wsl_optional_component() -> anyhow::Result<()> {
    let script =
        "Start-Process -Verb RunAs -FilePath wsl.exe -ArgumentList '--install --no-distribution'";
    let status = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Failed to launch elevated WSL optional-component installer: {}",
            status
        ))
    }
}

#[cfg(windows)]
fn provision_ubuntu_distro() -> anyhow::Result<()> {
    let status = std::process::Command::new("wsl.exe")
        .args(["--install", "-d", "Ubuntu"])
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Ubuntu WSL provisioning failed: {}",
            status
        ))
    }
}

#[cfg(not(windows))]
fn start_inside_wsl(
    _with_dashboard: bool,
    _sandbox: bool,
    _sandbox_name: &str,
    _deploy_gateway: bool,
) -> anyhow::Result<()> {
    Err(anyhow::anyhow!(
        "--wsl is only supported when launching from Windows"
    ))
}

#[cfg(windows)]
fn find_repo_root_for_wsl(start: &Path) -> PathBuf {
    for dir in start.ancestors() {
        if dir.join("Cargo.toml").is_file() && dir.join("crates").is_dir() {
            return dir.to_path_buf();
        }
        if dir.join("osoosi.toml").is_file() && dir.join("target").is_dir() {
            return dir.to_path_buf();
        }
    }
    start.to_path_buf()
}

#[cfg(windows)]
fn windows_path_to_wsl(path: &Path) -> anyhow::Result<String> {
    let mut s = path
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .replace('\\', "/");
    if let Some(rest) = s.strip_prefix("//?/") {
        s = rest.to_string();
    }
    if let Some(rest) = s.strip_prefix("//./") {
        s = rest.to_string();
    }
    let bytes = s.as_bytes();
    if bytes.len() >= 3 && bytes[1] == b':' && bytes[2] == b'/' {
        let drive = (bytes[0] as char).to_ascii_lowercase();
        let rest = &s[3..];
        return Ok(format!("/mnt/{}/{}", drive, rest));
    }
    Err(anyhow::anyhow!(
        "Cannot convert Windows path '{}' to a WSL /mnt/<drive>/ path",
        s
    ))
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
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
            sign_cmd.args([
                "dgst",
                "-sha256",
                "-sign",
                "test_priv.pem",
                "-out",
                &test_sig.to_string_lossy(),
                &test_file.to_string_lossy(),
            ]);

            let mut verify_cmd = tokio::process::Command::new("openssl");
            verify_cmd.args([
                "dgst",
                "-sha256",
                "-verify",
                "test_pub.pem",
                "-signature",
                &test_sig.to_string_lossy(),
                &test_file.to_string_lossy(),
            ]);

            // Extract public key first
            let mut pub_cmd = tokio::process::Command::new("openssl");
            pub_cmd.args([
                "rsa",
                "-in",
                "test_priv.pem",
                "-pubout",
                "-out",
                "test_pub.pem",
            ]);

            let success = async {
                let _ = gen_key.status().await;
                let _ = pub_cmd.status().await;
                let s = sign_cmd.status().await?.success();
                Ok::<bool, anyhow::Error>(s)
            }
            .await
            .unwrap_or(false);

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
                    warn!(
                        "OpenShell YARA provisioning failed: {}. Falling back to direct.",
                        result.message
                    );
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
        let orchestrator = EdrOrchestrator::new().await?;
        import_nsrl_with_fallback(&orchestrator.memory(), db_path.as_path(), &fetcher).await;
    }
    Ok(())
}

async fn setup_firewall() -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    {
        let ps_cmd = "New-NetFirewallRule -DisplayName 'OpenOshoosi-Allow' -Direction Inbound -LocalPort 9000,9876,3030,8080 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue";
        let _ = std::process::Command::new("powershell")
            .args(&["-Command", ps_cmd])
            .output()?;
    }
    osoosi_core::firewall::open_mesh_ports()?;
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
    if std::env::var("OSOOSI_NO_ORT")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
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
                    .args([
                        "-NoProfile",
                        "-Command",
                        &format!(
                            "(Get-Item '{}').VersionInfo.ProductVersion",
                            dll_path.to_string_lossy()
                        ),
                    ])
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

        info!(
            "Attempting to initialize ONNX Runtime (target version: {})...",
            version
        );

        if !dll_path.exists() {
            info!("📥 Downloading ONNX Runtime v{}...", version);
            let zip_path = "ort_tmp.zip";
            let tmp_dir = "ort_extract";

            let executor = DirectExecutor::new();
            if let Err(e) = executor.download(url, Path::new(zip_path), false).await {
                warn!(
                    "Failed to download ORT v{}: {}. Trying next version...",
                    version, e
                );
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
        let init_result = std::panic::catch_unwind(|| ort::init().commit());

        match init_result {
            Ok(Ok(_)) => {
                info!("✅ ONNX Runtime initialized successfully (v{}).", version);
                success = true;
                break;
            }
            _ => {
                warn!(
                    "⚠️ ONNX Runtime v{} failed to initialize or panicked. Trying fallback...",
                    version
                );
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
            if candidate.exists() {
                return Some(candidate);
            }
            // Also check 'scripts/' subdirectory
            let candidate_scripts = d.join("scripts").join(script_name);
            if candidate_scripts.exists() {
                return Some(candidate_scripts);
            }
            dir = d.parent();
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        let mut dir = Some(cwd.as_path());
        while let Some(d) = dir {
            let candidate = d.join(script_name);
            if candidate.exists() {
                return Some(candidate);
            }
            let candidate_scripts = d.join("scripts").join(script_name);
            if candidate_scripts.exists() {
                return Some(candidate_scripts);
            }
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
    fs::create_dir_all(&log_dir)
        .map_err(|e| anyhow::anyhow!("Cannot create log directory {}: {}", log_dir.display(), e))?;
    let file_appender = tracing_appender::rolling::daily(&log_dir, "osoosi.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    // Default: WARN when not in --debug. Always allow `target=consensus` at info so
    // `[CONSENSUS] voter YIELD` / round COMPLETE are visible without full crate INFO spam.
    // Use `--debug` or `RUST_LOG=consensus=debug` to see per-voter abstain / round start.
    let level = if debug {
        tracing::Level::DEBUG
    } else {
        tracing::Level::WARN
    };
    let filter = EnvFilter::from_default_env()
        .add_directive(level.into())
        .add_directive("consensus=info".parse().expect("static directive"));
    let console_layer = fmt::Layer::default().with_writer(std::io::stdout);
    let file_layer = fmt::Layer::default()
        .with_writer(non_blocking)
        .with_ansi(false);

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
            if cfg!(windows) {
                "python.exe".to_string()
            } else {
                "python3".to_string()
            }
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

fn open_browser(url: &str) {
    let _ = webbrowser::open(url);
}

fn set_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        error!("PANIC: {:?}", info);
    }));
}

#[cfg(unix)]
async fn wait_for_shutdown() {
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
    tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = sigterm.recv() => {} }
}

#[cfg(windows)]
async fn wait_for_shutdown() {
    let _ = tokio::signal::ctrl_c().await;
}
async fn ensure_ai_models() -> anyhow::Result<()> {
    if std::env::var("OSOOSI_NO_AI")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        return Ok(());
    }

    info!(
        "Verifying AI models in {}...",
        osoosi_types::resolve_models_dir().display()
    );
    ensure_ollama_model().await;

    let models_dir = osoosi_types::resolve_models_dir();
    let gemma_dir = models_dir.join("gemma4-e4b");
    let malware_dir = models_dir.join("malware");

    let _ = fs::create_dir_all(&gemma_dir);
    let _ = fs::create_dir_all(&malware_dir);

    // Use tokio-enabled API builder with optional HF_TOKEN
    let api = {
        let mut builder = ApiBuilder::new().with_cache_dir(models_dir.to_path_buf());

        if let Ok(token) = std::env::var("HF_TOKEN") {
            builder = builder.with_token(Some(token));
        }

        match builder.build() {
            Ok(api) => api,
            Err(e) => {
                warn!(
                    "Failed to initialize HuggingFace API: {}. AI features might be degraded.",
                    e
                );
                return Ok(());
            }
        }
    };

    // 1. Gemma 4 E4B ONNX (primary local reasoning model). Ollama is preferred
    // when installed; these files support pure ONNX Runtime deployments.
    let gemma_repo_name = std::env::var("OSOOSI_GEMMA_ONNX_REPO")
        .unwrap_or_else(|_| "onnx-community/gemma-4-E4B-it-ONNX".to_string());
    let gemma_repo = api.model(gemma_repo_name.clone());
    let gemma_model_dest = gemma_dir.join("model.onnx");
    let gemma_tokenizer_dest = gemma_dir.join("tokenizer.json");

    if !gemma_tokenizer_dest.exists() {
        for filename in ["tokenizer.json", "onnx/tokenizer.json"] {
            match gemma_repo.get(filename).await {
                Ok(downloaded) => {
                    if fs::copy(downloaded, &gemma_tokenizer_dest).is_ok() {
                        info!("Gemma 4 tokenizer saved from {}.", gemma_repo_name);
                        break;
                    }
                }
                Err(e) => tracing::debug!("Gemma tokenizer candidate {} failed: {}", filename, e),
            }
        }
    }

    if !gemma_model_dest.exists() {
        for filename in [
            "model.onnx",
            "onnx/model.onnx",
            "decoder_model_merged.onnx",
            "onnx/decoder_model_merged.onnx",
            "decoder_model.onnx",
            "onnx/decoder_model.onnx",
            "model_text_decoder.onnx",
            "onnx/model_text_decoder.onnx",
        ] {
            match gemma_repo.get(filename).await {
                Ok(downloaded) => {
                    if fs::copy(downloaded, &gemma_model_dest).is_ok() {
                        info!(
                            "Gemma 4 ONNX decoder saved from {} ({}) as model.onnx.",
                            gemma_repo_name, filename
                        );
                        break;
                    }
                }
                Err(e) => tracing::debug!("Gemma ONNX candidate {} failed: {}", filename, e),
            }
        }
    }

    if !gemma_model_dest.exists() || !gemma_tokenizer_dest.exists() {
        warn!(
            "Gemma 4 E4B ONNX files are incomplete in {:?}. Ollama Gemma is preferred when available; ONNX Gemma voter stays silent until model.onnx + tokenizer.json exist.",
            gemma_dir
        );
    }

    if std::env::var("OSOOSI_ENABLE_SMOLLM")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        let smollm_dir = models_dir.join("smollm");
        let _ = fs::create_dir_all(&smollm_dir);

        // Optional legacy SmolLM bootstrap. Disabled by default; Gemma 4 is primary.
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
                    }
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
                    }
                    Err(_) => continue,
                }
            }
        }

        // 3. MalConv — Candle-compatible `.safetensors` only. cycloevan/malconv on HF is Keras/TF (see model card), not an inference endpoint.
    }

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
        // Prefer repos that ship safetensors/ONNX; cycloevan/malconv is last (often TF-only / no hosted inference on HF).
        let malconv_repos = [
            "oyesanyf/OshoosiClaw-Weights",
            "Xenova/malconv",
            "onnx-community/malconv",
            "cycloevan/malconv",
        ];
        'malconv_hf: for repo_name in malconv_repos {
            let repo = api.model(repo_name.to_string());
            for file in malconv_files {
                info!(
                    "📥 Verifying MalConv AI component: `{}` / `{}`...",
                    repo_name, file
                );
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

async fn ensure_ollama_model() {
    let preferred = std::env::var("OSOOSI_OLLAMA_MODEL")
        .or_else(|_| std::env::var("OSOOSI_REASONING_MODEL"))
        .unwrap_or_else(|_| "gemma4:e4b".to_string());

    if !ollama_available().await {
        install_ollama_best_effort().await;
    }

    if !ollama_available().await {
        warn!(
            "Ollama not available after provisioning attempt. Gemma 4 ONNX files will be used if present; reasoning voters stay silent otherwise."
        );
        return;
    };

    info!("Ollama detected. Ensuring a local Gemma reasoning model is available...");
    let list = tokio::process::Command::new("ollama")
        .arg("list")
        .output()
        .await;
    let list_stdout = list
        .ok()
        .map(|out| String::from_utf8_lossy(&out.stdout).to_string())
        .unwrap_or_default();

    let mut candidates = vec![preferred.clone()];
    for fallback in ["gemma4:e4b", "gemma4:4b", "gemma3:4b", "gemma2:9b"] {
        if !candidates.iter().any(|m| m == fallback) {
            candidates.push(fallback.to_string());
        }
    }

    let mut selected = candidates
        .iter()
        .find(|model| list_stdout.contains(model.as_str()))
        .cloned();

    if selected.is_none() {
        for model in &candidates {
            match tokio::process::Command::new("ollama")
                .args(["pull", model])
                .status()
                .await
            {
                Ok(status) if status.success() => {
                    info!("Ollama model '{}' provisioned.", model);
                    selected = Some(model.clone());
                    break;
                }
                Ok(status) => {
                    warn!(
                        "ollama pull {} exited with status {}; trying next Gemma fallback.",
                        model, status
                    );
                }
                Err(e) => {
                    warn!(
                        "Failed to run ollama pull {}: {}; trying next Gemma fallback.",
                        model, e
                    );
                }
            }
        }
    }

    let Some(model) = selected else {
        warn!("No Ollama Gemma model could be provisioned. Gemma ONNX fallback remains available.");
        return;
    };

    if std::env::var("OSOOSI_REASONING_BACKEND").is_err() {
        std::env::set_var("OSOOSI_REASONING_BACKEND", "api");
    }
    if std::env::var("OSOOSI_REASONING_URL").is_err() {
        std::env::set_var(
            "OSOOSI_REASONING_URL",
            "http://127.0.0.1:11434/v1/chat/completions",
        );
    }
    if std::env::var("OSOOSI_REASONING_KEY").is_err() {
        std::env::set_var("OSOOSI_REASONING_KEY", "ollama");
    }
    std::env::set_var("OSOOSI_REASONING_MODEL", &model);
    if std::env::var("OSOOSI_OPENAI_API_BASE").is_err() {
        std::env::set_var("OSOOSI_OPENAI_API_BASE", "http://127.0.0.1:11434/v1");
    }
    if std::env::var("OSOOSI_OPENAI_API_KEY").is_err() {
        std::env::set_var("OSOOSI_OPENAI_API_KEY", "ollama");
    }
    if std::env::var("OSOOSI_OPENAI_MODEL").is_err() {
        std::env::set_var("OSOOSI_OPENAI_MODEL", &model);
    }
}

async fn ollama_available() -> bool {
    tokio::process::Command::new("ollama")
        .arg("--version")
        .status()
        .await
        .map(|status| status.success())
        .unwrap_or(false)
}

async fn install_ollama_best_effort() {
    if std::env::var("OSOOSI_SKIP_OLLAMA_INSTALL")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        return;
    }

    info!("Ollama not found. Attempting best-effort local Ollama installation...");

    #[cfg(target_os = "windows")]
    {
        let winget = tokio::process::Command::new("winget")
            .args([
                "install",
                "--id",
                "Ollama.Ollama",
                "-e",
                "--accept-package-agreements",
                "--accept-source-agreements",
            ])
            .status()
            .await;
        match winget {
            Ok(status) if status.success() => info!("Ollama installed with winget."),
            Ok(status) => warn!("winget Ollama install exited with status {}.", status),
            Err(e) => warn!(
                "winget not available or failed to start for Ollama install: {}",
                e
            ),
        }
    }

    #[cfg(target_os = "macos")]
    {
        let brew = tokio::process::Command::new("brew")
            .args(["install", "ollama"])
            .status()
            .await;
        match brew {
            Ok(status) if status.success() => info!("Ollama installed with Homebrew."),
            Ok(status) => warn!("brew Ollama install exited with status {}.", status),
            Err(e) => warn!(
                "Homebrew not available or failed to start for Ollama install: {}",
                e
            ),
        }
    }

    #[cfg(target_os = "linux")]
    {
        let shell = tokio::process::Command::new("sh")
            .args(["-c", "curl -fsSL https://ollama.com/install.sh | sh"])
            .status()
            .await;
        match shell {
            Ok(status) if status.success() => {
                info!("Ollama installed with official Linux installer.")
            }
            Ok(status) => warn!("Ollama Linux installer exited with status {}.", status),
            Err(e) => warn!("Failed to start Ollama Linux installer: {}", e),
        }
    }
}
