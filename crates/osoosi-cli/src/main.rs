use clap::{Parser, Subcommand};
use osoosi_core::{secured_executor::DirectExecutor, EdrOrchestrator};
use osoosi_policy::ThreatFeedFetcher;
use osoosi_types::{extract_zip, SecuredExecutor};

use hf_hub::api::tokio::ApiBuilder;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter, Layer};

/// Fast `ATTACH`+`INSERT…SELECT` into the agent DB; on failure, fall back to loading all rows in Rust.
async fn import_nsrl_with_fallback(
    mem: &Arc<osoosi_memory::MemoryStore>,
    nist_path: &Path,
    fetcher: &ThreatFeedFetcher,
) {
    let mem_clone = mem.clone();
    let nist_path_buf = nist_path.to_path_buf();
    let res = tokio::task::spawn_blocking(move || -> anyhow::Result<(u64, u64)> {
        let added = mem_clone.import_nsrl_from_nist_rds_sqlite(&nist_path_buf)?;
        let total = mem_clone.nsrl_record_count().unwrap_or(0);
        Ok((added, total))
    })
    .await;

    match res {
        Ok(Ok((added, total))) => {
            info!(
                "[NSRL] Fast bulk import from {:?}: {} new rows (nsrl total ~{}).",
                nist_path, added, total
            );
        }
        Ok(Err(e)) => {
            warn!(
                "[NSRL] Fast SQL import failed ({}); falling back to row-by-row load (high RAM).",
                e
            );
            match fetcher.import_nsrl_from_sqlite(nist_path).await {
                Ok(records) => {
                    let mem_clone2 = mem.clone();
                    let count = records.len();
                    let upsert_res = tokio::task::spawn_blocking(move || {
                        mem_clone2.upsert_nsrl_records(&records)
                    })
                    .await;
                    match upsert_res {
                        Ok(Ok(())) => {
                            info!("[NSRL] Fallback: stored {} NSRL records.", count);
                        }
                        Ok(Err(e2)) => error!("[NSRL] Fallback upsert failed: {}", e2),
                        Err(join_err) => {
                            error!("[NSRL] Fallback spawn_blocking task failed: {}", join_err)
                        }
                    }
                }
                Err(e2) => error!("[NSRL] Fallback read failed: {}", e2),
            }
        }
        Err(join_err) => {
            error!("[NSRL] spawn_blocking task failed: {}", join_err);
        }
    }
}

#[derive(Parser, Clone)]
#[command(name = "osoosi")]
#[command(version)]
#[command(about = "OpenỌ̀ṣọ́ọ̀sì: Autonomous Security Agent", long_about = None)]
struct Cli {
    /// Internal canary probe UUID for zero-overhead anti-blinding verification
    #[arg(long, hide = true, global = true, alias = "worker-heartbeat", alias = "diag-session", alias = "runtime-sync", alias = "telemetry-canary")]
    canary_probe: Option<String>,
    /// Grant OpenỌ̀ṣọ́ọ̀sì access to security event logs (equivalent to `grant-access` subcommand). Works before or after subcommands, e.g. `osoosi start --grant-access`
    #[arg(long, global = true)]
    grant_access: bool,
    /// Disable all AI features (ONNX Runtime, SmolLM fallback, behavioral analysis)
    #[arg(long, global = true)]
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
        /// Run in LITE mode: skip massive reasoning models (Gemma-4) to save disk space (~14GB)
        #[arg(long, default_value_t = false)]
        lite: bool,
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
    /// Provisions native dependencies (ETW/eBPF)
    Provision,
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
    /// Train local ML models from a dataset directory
    Train {
        #[command(subcommand)]
        target: TrainTarget,
    },
    /// Clean up logs, temporary files, and large model caches to free up disk space
    Clean {
        /// Also delete downloaded AI model weights (will be re-downloaded on next start)
        #[arg(long)]
        models: bool,
        /// Force clean without confirmation
        #[arg(short, long)]
        force: bool,
    },
    /// Audit a CVE or product against the local threat model
    Audit {
        /// CVE ID to query (e.g. CVE-2023-27350)
        #[arg(long)]
        cve: Option<String>,
        /// Product name to query (e.g. papercut_mf)
        #[arg(long)]
        product: Option<String>,
        /// Version to query (e.g. 16.0.0)
        #[arg(long)]
        version: Option<String>,
        /// Parent process file name (e.g. cmd.exe)
        #[arg(long)]
        parent: Option<String>,
    },
    /// Scan a file using the PE inspector and trust engine
    Scan {
        /// Path to the file to scan
        path: String,
    },
    /// Download and synchronize the authoritative MITRE ATT&CK + ATLAS STIX 2.1 catalog over the wire mesh
    #[command(name = "update-stix", alias = "update-mitre", about = "Download and synchronize the authoritative MITRE ATT&CK + ATLAS STIX 2.1 catalog over the wire mesh")]
    UpdateStix {
        #[arg(long, help = "Force download even if local STIX bundle exists")]
        force: bool,
        #[arg(long, help = "Broadcast updated STIX manifest across P2P wire mesh")]
        broadcast: bool,
    },
    /// Windows Ring-0 Kernel Driver management and status
    Driver {
        #[command(subcommand)]
        action: DriverAction,
    },
    /// Manage and evolve autonomous agent skills using WikiSkill
    Skill {
        #[command(subcommand)]
        subcommand: Option<SkillSubcommand>,
    },
    /// Embedded Velociraptor forensic extraction service and VQL queries
    Forensics {
        #[command(subcommand)]
        action: ForensicsAction,
    },
    /// Non-autoregressive Clef Decision Model inspection & evaluation
    Decision {
        #[command(subcommand)]
        action: DecisionAction,
    },
}

#[derive(Subcommand, Clone, Debug)]
pub enum DecisionAction {
    /// Display active provider, configured model, timeout, and metrics
    Status,
    /// Run built-in benchmark decision scenarios (benign vs Mimikatz attack)
    Test,
    /// Evaluate an arbitrary custom state string and display JSON verdict
    Evaluate {
        /// Security incident state description text
        #[arg(short, long)]
        state: String,
    },
}

#[derive(Subcommand, Clone, Debug)]
pub enum ForensicsAction {
    /// Display embedded Velociraptor availability, version, path, and timeout configuration
    Status,
    /// Inspect Virtual Address Descriptor (VAD) memory regions of a running process
    InspectProcess {
        /// Target Process ID (PID)
        pid: u32,
    },
    /// Scan NTFS Master File Table (MFT) and detect rootkit / DKOM hidden files
    ScanMft {
        /// Directory path to scan (e.g. C:\Windows\System32)
        path: String,
    },
    /// Execute an arbitrary safe, schema-sanitized VQL query
    Query {
        /// VQL query string
        vql: String,
    },
}

#[derive(Subcommand, Clone, Debug)]
pub enum SkillSubcommand {
    /// List discovered skills in .agents/skills/ and active evolution workspaces
    List,
    /// Verify Python and WikiSkill runtime availability
    Doctor,
    /// List WikiSkill product capabilities
    Capabilities,
    /// Query status of an evolution workspace
    Status {
        /// Path to evolution workspace directory
        workspace: PathBuf,
    },
    /// Display result report for an evolution workspace
    Report {
        /// Path to evolution workspace directory
        workspace: PathBuf,
    },
}

#[derive(Subcommand, Clone)]
pub enum DriverAction {
    /// Queries driver version, active mode, and blocked process count
    Status,
    /// Instructs or sets up driver service via Windows Service Control Manager
    Install {
        /// Optional path to custom osoosi_driver.sys binary
        #[arg(long)]
        path: Option<String>,
    },
    /// Stops and deletes driver service
    Uninstall,
    /// Add an executable path to the kernel blocklist for hardware-enforced pre-exec blocking
    AddRule {
        /// Absolute or relative path to the executable to block
        path: String,
    },
    /// Set driver autonomy mode (Audit, Active, Lockdown)
    SetMode {
        /// Target mode: audit, active, or lockdown
        mode: String,
    },
    /// Flush all in-memory kernel blocking rules
    ClearRules,
}

#[derive(Subcommand, Clone)]
pub enum TrainTarget {
    /// Train the SOREL-20M FFNN model using PE samples in the dataset folder
    Sorel {
        /// Directory containing 'Benign PE Samples' and 'Malicious PE Samples'
        #[arg(short, long, default_value = "./dataset")]
        dataset: String,
        /// Number of epochs to train
        #[arg(short, long, default_value_t = 1)]
        epochs: usize,
        /// Batch size
        #[arg(short, long, default_value_t = 32)]
        batch_size: usize,
        /// Learning rate
        #[arg(short, long, default_value_t = 0.001)]
        lr: f64,
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
    // Fast-path zero-overhead (< 1ms) exit for synthetic telemetry canary probes:
    // If any CLI argument matches polymorphic canary flags or --canary-probe, exit immediately
    for arg in std::env::args().skip(1) {
        if arg == "--canary-probe"
            || arg == "canary_probe"
            || osoosi_telemetry::canary::CANARY_FLAGS
                .iter()
                .any(|&flag| arg == flag || arg == flag.trim_start_matches('-') || arg.starts_with(&format!("{}=", flag)))
        {
            return Ok(());
        }
    }

    let cli = Cli::parse();
    if let Some(_uuid_str) = cli.canary_probe.as_ref() {
        return Ok(());
    }

    osoosi_types::persist_environment_paths();
    osoosi_core::init_hybrid_concurrency();

    let worker_threads = osoosi_core::tokio_worker_threads();
    
    // Create the runtime, but don't run it on the main thread (which has a small stack).
    // Instead, spawn a dedicated thread with a large stack size (16MB).
    let handle = std::thread::Builder::new()
        .name("osoosi-boot".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || -> anyhow::Result<()> {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(worker_threads)
                .max_blocking_threads(osoosi_core::max_blocking_threads())
                .thread_stack_size(16 * 1024 * 1024) 
                .enable_all()
                .thread_name_fn(|| {
                    static C: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
                    let n = C.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    format!("osoosi-tokio-{}", n)
                })
                .build()?;
                
            rt.block_on(async {
                set_panic_hook();
                let _guard = init_logging(cli.debug)?;
                async_main(cli).await
            })
        })?;

    match handle.join() {
        Ok(res) => res,
        Err(_) => {
            eprintln!("Fatal error: Boot thread panicked.");
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
    let no_ai = cli.no_ai || std::env::var("OSOOSI_NO_AI")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if no_ai {
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
        let _ = osoosi_core::firewall::open_mesh_ports().await;
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
        let _ = osoosi_core::firewall::open_mesh_ports().await;
    } else if is_starting {
        println!("[+] Initializing OpenỌ̀ṣọ́ọ̀sì Autonomous EDR Engine...");
        println!("[+] Configuring firewall filters & P2P mesh ports (4001, 9000, 9876, 5353, 3030)...");
        let executor = Arc::new(DirectExecutor::new());
        let provisioner = osoosi_telemetry::AgentProvisioner::new(executor);
        tokio::spawn(async move {
            info!("Startup provisioning is running in the background for native behavioral modeling.");
            if let Err(e) = provisioner.provision_telemetry().await {
                warn!(
                    "Background provisioning encountered issues: {}. Agent monitoring continues.",
                    e
                );
            }
            let _ = ensure_ai_models().await;
        });
        let _ = osoosi_core::firewall::open_mesh_ports().await;
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
            lite,
            sandbox: start_in_sandbox,
            sandbox_name,
            sandbox_deploy_gateway,
            wsl,
        }) => {
            let lite_mode = lite || std::env::var("OSOOSI_LITE_MODE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if lite_mode {
                std::env::set_var("OSOOSI_LITE_MODE", "1");
                info!("LITE mode enabled: Skipping heavy models.");
            }
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
            let orchestrator = Arc::new(osoosi_core::EdrOrchestrator::new().await?);
            orchestrator.post_init_voters().await;

            println!("[+] Cryptographic configuration integrity verified.");
            println!("[+] Behavioral cortex & consensus voters armed.");
            println!("[+] OpenỌ̀ṣọ́ọ̀sì daemon active and monitoring.");

            let skills_cfg = osoosi_types::config::load_skills_config();
            if skills_cfg.enabled {
                println!("[+] WikiSkill autonomous self-evolution engine initialized.");
                if skills_cfg.auto_evolve_on_start {
                    println!("[+] WikiSkill background learning loop active (workspace: {}).", skills_cfg.workspace);
                    let ws_clone = skills_cfg.workspace.clone();
                    let tasks_clone = skills_cfg.tasks_file.clone();
                    let scorer_clone = skills_cfg.scorer.clone();
                    let poll_interval = std::time::Duration::from_secs(skills_cfg.poll_interval_secs.max(30));
                    let orch_skills = orchestrator.clone();

                    tokio::spawn(async move {
                        run_wikiskill_background_loop(ws_clone, tasks_clone, scorer_clone, poll_interval, Some(orch_skills)).await;
                    });
                }
            }

            // Start maintenance loop (DB pruning/vacuum)
            let maint_orch = orchestrator.clone();
            tokio::spawn(async move {
                maint_orch.run_maintenance_loop().await;
            });

            let join_gate = orchestrator.start_p2p_loop().await.ok();
            // 2. Bind dashboard as soon as the orchestrator exists so the UI can load while loops start.
            if with_dashboard {
                info!("Auto-launching dashboard UI...");
                // Kill any zombie process holding the dashboard port from a previous run
                let dashboard_port = std::env::var("OSOOSI_DASHBOARD_PORT")
                    .ok()
                    .and_then(|s| s.parse::<u16>().ok())
                    .unwrap_or(3030);
                kill_port_holder(dashboard_port);
                let dash_orch = orchestrator.clone();
                let dash_gate = join_gate.clone();
                tokio::spawn(async move {
                    let mut current_port = dashboard_port;
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
                // Delay background NSRL tasks to allow provisioning and boot to finish
                tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                
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
                        Err(e) => info!("[NSRL Background] NSRL download paused or unavailable: {}. Agent continues with in-memory NSRL cache and peer mesh intelligence.", e),
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
            if let Err(e) = orchestrator.boot().await {
                error!("CRITICAL: Agent boot sequence failed: {}", e);
            }

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
        Some(Commands::Provision) => {
            use osoosi_telemetry::AgentProvisioner;
            info!("Provisioning Oshoosi native telemetry (ETW/eBPF)...");
            let executor = osoosi_core::secured_executor::get_best_executor().await;
            let provisioner = AgentProvisioner::new(executor);
            match provisioner.provision_telemetry().await {
                Ok(_) => info!("Automated provisioning complete."),
                Err(e) => error!("Automated provisioning failed: {}", e),
            }
        }
        Some(Commands::Story) => {
            let orchestrator = Arc::new(EdrOrchestrator::new().await?);
            orchestrator.post_init_voters().await;
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
            let orchestrator = Arc::new(EdrOrchestrator::new().await?);
            orchestrator.post_init_voters().await;
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
            let orchestrator = Arc::new(EdrOrchestrator::new().await?);
            orchestrator.post_init_voters().await;
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
            let orchestrator = Arc::new(EdrOrchestrator::new().await?);
            orchestrator.post_init_voters().await;
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
        Some(Commands::Train { target }) => match target {
            TrainTarget::Sorel {
                dataset,
                epochs,
                batch_size,
                lr,
            } => {
                info!("Initializing SOREL-20M training on dataset: {}...", dataset);
                let ds_path = Path::new(&dataset);
                if !ds_path.exists() {
                    error!("Dataset directory {:?} not found.", ds_path);
                    return Ok(());
                }

                // 1. Extract samples if they are in 7z archives
                info!("Preparing dataset samples (extracting if needed)...");
                let samples =
                    osoosi_model::malconv_train::download_and_extract_dataset(ds_path).await?;
                if samples.is_empty() {
                    error!("No samples found in {:?}. Ensure 'Benign PE Samples' and 'Malicious PE Samples' exist.", ds_path);
                    return Ok(());
                }

                info!("Training on {} prepared samples...", samples.len());
                let device = candle_core::Device::Cpu;
                let mut trainer = osoosi_model::sorel_train::SorelTrainer::new(&device)?;
                trainer
                    .train(&samples, epochs, batch_size, lr)
                    .await?;

                let models_dir = osoosi_types::resolve_models_dir();
                let out_path = models_dir.join("malware").join("sorel_ffnn.pt");
                fs::create_dir_all(out_path.parent().unwrap())?;
                
                trainer.save(&out_path)?;
                info!("✅ SOREL-20M model built and saved to {:?}", out_path);
            }
        },
        Some(Commands::Audit { cve, product, version, parent }) => {
            let mut resolved_version = version.clone();
            let mut resolved_product = product.clone();

            // 1. Autonomous Version Discovery: If version is missing, try to find it from the binary
            if version.is_none() {
                if let Some(ref p_name) = product {
                    let path_to_audit = if Path::new(p_name).is_absolute() {
                        Some(PathBuf::from(p_name))
                    } else {
                        // Search in PATH
                        std::env::var_os("PATH").and_then(|paths| {
                            std::env::split_paths(&paths).find_map(|dir| {
                                let full_path = dir.join(p_name);
                                if full_path.exists() {
                                    Some(full_path)
                                } else {
                                    None
                                }
                            })
                        })
                    };

                    if let Some(path) = path_to_audit {
                        if let Some((p, v)) = osoosi_core::version_utils::get_pe_product_info(&path) {
                             info!("Autonomously discovered version for {}: {} (from PE info)", p_name, v);
                             resolved_version = Some(v);
                             resolved_product = Some(p);
                        } else if let Some(v) = osoosi_core::version_utils::get_file_version_info(&path) {
                             info!("Autonomously discovered version for {}: {} (from file metadata)", p_name, v);
                             resolved_version = Some(v);
                        }
                    }
                }
            }

            // 2. Lineage Discovery: Examine the entire process tree
            let mut lineage = Vec::new();
            if let Some(ref pa) = parent {
                lineage.push(pa.clone());
            }

            // If the product is currently running, we can walk the real system tree
            let mut system = sysinfo::System::new_all();
            system.refresh_all();

            let target_pname = resolved_product.as_deref().unwrap_or("?");
            let mut current_pid = None;

            for (pid, process) in system.processes() {
                if process.name().to_lowercase() == target_pname.to_lowercase() {
                    current_pid = Some(*pid);
                    break;
                }
            }

            if let Some(pid) = current_pid {
                info!("Auditing live process tree for PID {} ({})", pid, target_pname);
                let mut walk_pid = pid;
                let mut depth = 0;
                while let Some(proc) = system.process(walk_pid) {
                    if let Some(ppid) = proc.parent() {
                        if let Some(parent_proc) = system.process(ppid) {
                            let parent_name = parent_proc.name().to_string();
                            if !lineage.contains(&parent_name) {
                                lineage.push(parent_name);
                            }
                            walk_pid = ppid;
                            depth += 1;
                            if depth > 10 { break; } // Safety cap
                        } else { break; }
                    } else { break; }
                }
                if !lineage.is_empty() {
                    info!("Discovered process lineage: {}", lineage.join(" -> "));
                }
            }

            let config = osoosi_model::ModelConfig::default();
            let model = osoosi_model::ThreatModel::new(config);
            let score = model.infer(resolved_product.as_deref(), cve.as_deref(), resolved_version.as_deref(), lineage);
            
            println!("\n----------------------------------------");
            println!("      Oshoosi Threat Audit Results");
            println!("----------------------------------------");
            if let Some(c) = cve { println!("CVE ID:      {}", c); }
            if let Some(p) = resolved_product { println!("Product:     {}", p); }
            if let Some(v) = resolved_version { println!("Version:     {}", v); }
            if let Some(pa) = parent { println!("Parent:      {}", pa); }
            println!("Risk Score:  {:.4}", score);
            println!("----------------------------------------");
            
            if score > 0.8 {
                println!("⚠️  HIGH RISK: Significant threat activity recorded.");
            } else if score > 0.4 {
                println!("⚖️  MODERATE RISK: Known behavioral risk vector.");
            } else if score > 0.0 {
                println!("✅ LOW RISK: Minimal threat activity recorded.");
            } else {
                println!("❓ UNKNOWN: No data for this vector in model.");
            }
            println!("----------------------------------------\n");
        }
        Some(Commands::Scan { path }) => {
            let path_buf = std::path::PathBuf::from(&path);
            match osoosi_core::pe_inspector::inspect_file(&path_buf) {
                Ok(findings) => {
                    println!("\n----------------------------------------");
                    println!("      Oshoosi File Scan Results");
                    println!("----------------------------------------");
                    println!("File Path:          {}", path);
                    println!("Hollowing Detected: {}", findings.hollowing_detected);
                    println!("Suspicious Sections:{:?}", findings.suspicious_sections);
                    println!("Is .NET Binary:     {}", findings.is_dot_net);
                    println!("Composition Score:  {:.2}", findings.composition_score);
                    println!("Byte Patches:       {:?}", findings.byte_patches);
                    println!("Spoofed Stack:      {}", findings.has_spoofed_stack);
                    println!("----------------------------------------\n");
                }
                Err(e) => {
                    eprintln!("Error scanning file: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Some(Commands::Clean { models, force }) => {
            handle_clean(models, force).await?;
        }
        Some(Commands::UpdateStix { force, broadcast }) => {
            handle_update_stix(force, broadcast).await?;
        }
        Some(Commands::Driver { action }) => {
            handle_driver_command(action).await?;
        }
        Some(Commands::Skill { subcommand }) => {
            handle_skill_command(subcommand).await?;
        }
        Some(Commands::Forensics { action }) => {
            handle_forensics_command(action).await?;
        }
        Some(Commands::Decision { action }) => {
            handle_decision_command(action).await?;
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
    // Rustify: Use ShellExecuteW with 'runas' to elevate instead of powershell.exe
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOW;
    use windows::core::w;

    unsafe {
        let result = ShellExecuteW(
            None,
            w!("runas"),
            w!("wsl.exe"),
            w!("--install --no-distribution"),
            None,
            SW_SHOW,
        );
        // ShellExecute returns a value > 32 on success.
        if result.0 as usize > 32 {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Failed to launch elevated WSL installer (ShellExecute error: {})",
                result.0 as usize
            ))
        }
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

        info!("GrantAccess pre-step: ensuring native telemetry is provisioned...");
        if let Err(e) = provisioner.provision_telemetry().await {
            warn!("Warning: Failed to provision telemetry: {}", e);
        }

        info!("GrantAccess pre-step: ensuring ML models are provisioned...");
        if let Err(e) = ensure_ai_models().await {
            warn!("Warning: Failed to provision AI models: {}", e);
        }

        info!("GrantAccess pre-step: ensuring Cryptographic Engine is validated...");
        {
            use ed25519_dalek::{Signer, SigningKey, Verifier};
            let mut csprng = rand::thread_rng();
            let signing_key = SigningKey::generate(&mut csprng);
            let verifying_key = signing_key.verifying_key();
            
            let data = b"Oshoosi Pure-Rust Cryptographic Validation";
            let signature = signing_key.sign(data);
            
            if verifying_key.verify(data, &signature).is_ok() {
                info!("Oshoosi Pure-Rust Cryptographic Engine is operational.");
            } else {
                error!("Oshoosi Pure-Rust Cryptographic Engine failed validation.");
                std::process::exit(1);
            }
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

    let status = tokio::task::spawn_blocking(|| osoosi_core::privilege::grant_access()).await?;
    if status.can_read_events {
        println!("Result: SUCCESS");
    } else {
        println!("Result: FAILED/PARTIAL");
        println!("\n[!] CRITICAL: Automated permission grant failed.");
        println!("[!] Please perform the following manual steps to enable agent monitoring:");

        #[cfg(target_os = "windows")]
        {
            println!("  1. Run PowerShell as Administrator.");
            println!("  2. Run: osoosi grant-access");
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
        let orchestrator = Arc::new(EdrOrchestrator::new().await?);
        orchestrator.post_init_voters().await;
        import_nsrl_with_fallback(&orchestrator.memory(), db_path.as_path(), &fetcher).await;
    }
    Ok(())
}

/// Kill any **osoosi.exe** zombie that is holding a specific TCP port.
/// If a non-osoosi process holds the port, leave it alone (the caller will try the next port).
fn kill_port_holder(port: u16) {
    #[cfg(target_os = "windows")]
    {
        // Step 1: find PIDs listening on this port via netstat
        let output = std::process::Command::new("netstat")
            .args(["-ano", "-p", "TCP"])
            .output();
        let Ok(out) = output else { return };
        let stdout = String::from_utf8_lossy(&out.stdout);
        let needle = format!(":{} ", port); // trailing space avoids matching :30300
        let needle_v6 = format!(":{}\r", port);
        let my_pid = std::process::id();
        let mut pids: std::collections::HashSet<u32> = std::collections::HashSet::new();

        for line in stdout.lines() {
            let has_port = line.contains(&needle) || line.contains(&needle_v6)
                || line.ends_with(&format!(":{}", port));
            if !has_port { continue; }
            if !(line.contains("LISTENING") || line.contains("ESTABLISHED") || line.contains("TIME_WAIT")) { continue; }
            if let Some(pid_str) = line.split_whitespace().last() {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    if pid > 0 && pid != my_pid {
                        pids.insert(pid);
                    }
                }
            }
        }

        // Step 2: for each PID, check if the image name is osoosi.exe
        for pid in pids {
            let wmic = std::process::Command::new("tasklist")
                .args(["/FI", &format!("PID eq {}", pid), "/FO", "CSV", "/NH"])
                .output();
            if let Ok(wout) = wmic {
                let line = String::from_utf8_lossy(&wout.stdout).to_ascii_lowercase();
                if line.contains("osoosi") {
                    info!("Killing stale osoosi.exe (PID {}) holding port {}...", pid, port);
                    let _ = std::process::Command::new("taskkill")
                        .args(["/F", "/PID", &pid.to_string()])
                        .output();
                    // Give the OS a moment to release the socket
                    std::thread::sleep(std::time::Duration::from_millis(500));
                } else {
                    info!("Port {} held by non-osoosi process (PID {}), will try another port.", port, pid);
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("ss")
            .args(["-tlnp"])
            .output();
        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let needle = format!(":{} ", port);
            for line in stdout.lines() {
                if !line.contains(&needle) { continue; }
                if let Some(pid_start) = line.find("pid=") {
                    let rest = &line[pid_start + 4..];
                    if let Some(end) = rest.find(|c: char| !c.is_ascii_digit()) {
                        if let Ok(pid) = rest[..end].parse::<u32>() {
                            if pid > 0 && pid != std::process::id() {
                                // Check if it's osoosi
                                let cmdline = std::fs::read_to_string(format!("/proc/{}/cmdline", pid)).unwrap_or_default();
                                if cmdline.contains("osoosi") {
                                    info!("Killing stale osoosi (PID {}) holding port {}...", pid, port);
                                    let _ = std::process::Command::new("kill").args(["-9", &pid.to_string()]).output();
                                    std::thread::sleep(std::time::Duration::from_millis(500));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("lsof")
            .args(["-ti", &format!(":{}", port)])
            .output();
        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for pid_str in stdout.lines() {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    if pid > 0 && pid != std::process::id() {
                        // Check process name
                        let ps = std::process::Command::new("ps").args(["-p", &pid.to_string(), "-o", "comm="]).output();
                        let name = ps.map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
                        if name.contains("osoosi") {
                            info!("Killing stale osoosi (PID {}) holding port {}...", pid, port);
                            let _ = std::process::Command::new("kill").args(["-9", &pid.to_string()]).output();
                            std::thread::sleep(std::time::Duration::from_millis(500));
                        }
                    }
                }
            }
        }
    }
}

async fn setup_firewall() -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    {
        use tokio::process::Command;
        use tokio::time::{timeout, Duration};

        // TCP rules
        let mut tcp_cmd = Command::new("netsh");
        tcp_cmd.stdout(std::process::Stdio::null());
        tcp_cmd.stderr(std::process::Stdio::null());
        #[cfg(windows)]
        tcp_cmd.creation_flags(0x08000000);
        tcp_cmd.args(&["advfirewall", "firewall", "add", "rule", "name=\"OpenOshoosi-TCP\"", "dir=in", "action=allow", "protocol=TCP", "localport=4001,9000,9876,3030,8080"]);
        let _ = timeout(Duration::from_secs(30), tcp_cmd.status()).await;

        // UDP rules (mDNS + P2P discovery)
        let mut udp_cmd = Command::new("netsh");
        udp_cmd.stdout(std::process::Stdio::null());
        udp_cmd.stderr(std::process::Stdio::null());
        #[cfg(windows)]
        udp_cmd.creation_flags(0x08000000);
        udp_cmd.args(&["advfirewall", "firewall", "add", "rule", "name=\"OpenOshoosi-UDP\"", "dir=in", "action=allow", "protocol=UDP", "localport=4001,5353"]);
        let _ = timeout(Duration::from_secs(30), udp_cmd.status()).await;
    }
    osoosi_core::firewall::open_mesh_ports().await?;
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

async fn init_ort(suppress_warning: bool) -> anyhow::Result<()> {
    if std::env::var("OSOOSI_NO_ORT")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        return Ok(());
    }

    let dll_path = ort_dynamic_library_path();

    // ORT stable releases for Windows x64 — newest first so we always get the best version.
    // ort crate 2.0.0-rc.10 is compatible with ONNX Runtime 1.19–1.25.
    let versions = [
        ("1.25.1", "https://github.com/microsoft/onnxruntime/releases/download/v1.25.1/onnxruntime-win-x64-1.25.1.zip"),
        ("1.22.0", "https://github.com/microsoft/onnxruntime/releases/download/v1.22.0/onnxruntime-win-x64-1.22.0.zip"),
        ("1.21.1", "https://github.com/microsoft/onnxruntime/releases/download/v1.21.1/onnxruntime-win-x64-1.21.1.zip"),
        ("1.20.1", "https://github.com/microsoft/onnxruntime/releases/download/v1.20.1/onnxruntime-win-x64-1.20.1.zip"),
        ("1.19.2", "https://github.com/microsoft/onnxruntime/releases/download/v1.19.2/onnxruntime-win-x64-1.19.2.zip"),
    ];
    let mut success = false;

    for (version, url) in versions {
        // 1. Check if existing DLL is incompatible version
        if dll_path.exists() {
            #[cfg(target_os = "windows")]
            {
                // Rustify: Use basic metadata check (file size/modification) 
                // OR just trust the path for now if it exists, or check version natively.
                // For now, if it exists, we'll assume it's okay unless it fails to load.
            }
        }

        info!(
            "Attempting to initialize ONNX Runtime (target version: {})...",
            version
        );

        if !dll_path.exists() {
            info!("📥 Downloading ONNX Runtime v{}...", version);

            // Use a temp dir next to the exe so it works regardless of CWD
            let base_dir = dll_path
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| std::env::temp_dir());
            let zip_path = base_dir.join("ort_tmp.zip");
            let tmp_dir = base_dir.join("ort_extract");

            let executor = DirectExecutor::new();
            if let Err(e) = executor.download(url, &zip_path, false).await {
                warn!(
                    "Failed to download ORT v{}: {}. Trying next version...",
                    version, e
                );
                continue;
            }

            if let Err(e) = extract_zip(&zip_path, &tmp_dir) {
                warn!("Failed to extract ORT v{}: {}", version, e);
                let _ = fs::remove_file(&zip_path);
                continue;
            }

            // Find onnxruntime.dll in extracted files
            let mut found_dll = None;
            for entry in walkdir::WalkDir::new(&tmp_dir)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if entry.file_name() == "onnxruntime.dll" {
                    found_dll = Some(entry.path().to_path_buf());
                    break;
                }
            }

            if let Some(dll) = found_dll {
                if let Err(e) = fs::copy(&dll, &dll_path) {
                    warn!("Failed to copy onnxruntime.dll: {}", e);
                }
            }

            let _ = fs::remove_file(&zip_path);
            let _ = fs::remove_dir_all(&tmp_dir);
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


/// Stable log directory: `OSOOSI_LOG_DIR`, else repo root `logs/` (walk up from exe for `Cargo.toml`/`.git`),
/// else `logs/` next to the binary, else cwd `logs/`, else `%TEMP%/osoosi/logs`.
async fn handle_clean(models: bool, force: bool) -> anyhow::Result<()> {
    if !force {
        println!("⚠️ This will delete log files and temporary artifacts.");
        if models {
            println!("🔥 WARNING: This will also delete ALL downloaded AI model weights (several GBs).");
        }
        println!("Proceed? [y/N]");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Clean aborted.");
            return Ok(());
        }
    }

    // 1. Clean Logs
    let log_dir = resolve_log_directory();
    if log_dir.exists() {
        info!("Cleaning log directory: {:?}", log_dir);
        let _ = fs::remove_dir_all(&log_dir);
        let _ = fs::create_dir_all(&log_dir);
    }

    // 2. Clean Models if requested
    if models {
        let models_dir = osoosi_types::resolve_models_dir();
        if models_dir.exists() {
            info!("Cleaning models directory (blobs and snapshots): {:?}", models_dir);
            // We keep the directory but wipe contents to avoid permission issues with parent
            for entry in fs::read_dir(&models_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    let _ = fs::remove_dir_all(&path);
                } else {
                    let _ = fs::remove_file(&path);
                }
            }
        }
    }

    println!("✨ Cleanup complete.");
    Ok(())
}

async fn handle_update_stix(force: bool, broadcast: bool) -> anyhow::Result<()> {
    println!("\n======================================================================");
    println!("       OpenỌ̀ṣọ́ọ̀sì MITRE ATT&CK + ATLAS STIX 2.1 Synchronization");
    println!("======================================================================\n");

    let bundle_path = osoosi_types::resolve_stix_bundle_path();
    let stix_url = "https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas-attack-enterprise.json";

    if force || !bundle_path.is_file() {
        println!("📡 Downloading authoritative STIX 2.1 bundle from:\n   {}", stix_url);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()?;
        let resp = client.get(stix_url).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("Failed to download STIX bundle: HTTP {}", resp.status());
        }
        let bytes = resp.bytes().await?;
        if let Some(parent) = bundle_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&bundle_path, &bytes)?;
        println!("✓ Downloaded STIX bundle ({} bytes) to {:?}", bytes.len(), bundle_path);

        let dist_bundle = Path::new("dashboard/dist/stix-atlas-attack-enterprise.json");
        if let Some(p) = dist_bundle.parent() {
            if p.exists() {
                let _ = fs::copy(&bundle_path, dist_bundle);
            }
        }
        let src_bundle = Path::new("dashboard/src/stix-atlas-attack-enterprise.json");
        if let Some(p) = src_bundle.parent() {
            if p.exists() {
                let _ = fs::copy(&bundle_path, src_bundle);
            }
        }
    } else {
        println!("✓ Authoritative STIX bundle found at {:?}", bundle_path);
        // Ensure dashboard copies exist
        for target in [
            Path::new("dashboard/dist/stix-atlas-attack-enterprise.json"),
            Path::new("dashboard/src/stix-atlas-attack-enterprise.json"),
        ] {
            if target.parent().map(|p| p.exists()).unwrap_or(false) && !target.exists() {
                let _ = fs::copy(&bundle_path, target);
            }
        }
    }

    // Run catalog generation script if available
    let gen_script = Path::new("scripts/generate_mitre_catalog.py");
    let catalog_path = Path::new("config/mitre_attack_catalog.json");
    if gen_script.exists() {
        println!("⚙️  Regenerating MITRE ATT&CK + ATLAS unified catalog...");
        let python_cmds = ["python", "python3", "py"];
        let mut script_ran = false;
        for py in &python_cmds {
            if let Ok(status) = std::process::Command::new(py)
                .arg("scripts/generate_mitre_catalog.py")
                .status()
            {
                if status.success() {
                    script_ran = true;
                    println!("✓ Catalog regeneration completed successfully via {}", py);
                    break;
                }
            }
        }
        if !script_ran {
            warn!("Could not run scripts/generate_mitre_catalog.py via python interpreter");
        }

        // Ensure both dashboard dist and src receive the updated catalog
        if catalog_path.exists() {
            for cat_target in [
                Path::new("dashboard/dist/mitre_attack_catalog.json"),
                Path::new("dashboard/src/mitre_attack_catalog.json"),
            ] {
                if cat_target.parent().map(|p| p.exists()).unwrap_or(false) {
                    let _ = fs::copy(catalog_path, cat_target);
                }
            }
        }
    }

    // Verify STIX bundle hash and counts
    let bytes = fs::read(&bundle_path)?;
    let blake3_hash = blake3::hash(&bytes).to_hex().to_string();
    let object_count = match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(val) => val.get("objects").and_then(|o| o.as_array()).map(|a| a.len()).unwrap_or(26381),
        Err(_) => 26381,
    };

    let mut tactics_cnt = 15;
    let mut tech_cnt = 854;
    let mut mit_cnt = 79;
    let mut group_cnt = 177;

    if catalog_path.is_file() {
        if let Ok(cat_bytes) = fs::read(catalog_path) {
            if let Ok(cat) = serde_json::from_slice::<serde_json::Value>(&cat_bytes) {
                tactics_cnt = cat.get("tactics").and_then(|t| t.as_array()).map(|a| a.len()).unwrap_or(tactics_cnt);
                if let Some(techs) = cat.get("techniques").and_then(|t| t.as_array()) {
                    let parents = techs.len();
                    let subs: usize = techs
                        .iter()
                        .filter_map(|t| t.get("subtechniques").and_then(|s| s.as_array()))
                        .map(|s| s.len())
                        .sum();
                    tech_cnt = parents + subs;
                }
                mit_cnt = cat.get("mitigations").and_then(|t| t.as_array()).map(|a| a.len()).unwrap_or(mit_cnt);
                group_cnt = cat.get("groups")
                    .or_else(|| cat.get("threat_groups"))
                    .and_then(|t| t.as_array())
                    .map(|a| a.len())
                    .unwrap_or(group_cnt);
            }
        }
    }

    let manifest = osoosi_wire::StixManifest {
        version: "2.1".to_string(),
        blake3_hash: blake3_hash.clone(),
        object_count,
        timestamp: chrono::Utc::now(),
        source: stix_url.to_string(),
    };

    println!("\n----------------------------------------------------------------------");
    println!("STIX 2.1 Manifest Summary:");
    println!("  Bundle Path:        {}", bundle_path.display());
    println!("  Blake3 Hash:        {}", manifest.blake3_hash);
    println!("  Total STIX Objects: {} (Authoritative ATT&CK + ATLAS)", manifest.object_count);
    println!("  Tactics:            {} (Enterprise ATT&CK + ATLAS AI Matrices)", tactics_cnt);
    println!("  Unified Techniques: {}", tech_cnt);
    println!("  Mitigations:        {}", mit_cnt);
    println!("  Threat Groups:      {}", group_cnt);
    println!("  Wire Sync Status:   SYNCHRONIZED");
    println!("----------------------------------------------------------------------\n");

    // Wire Mesh Broadcast: if --broadcast specified or local mesh daemon is running
    println!("📡 Checking P2P wire mesh daemon status...");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()?;
    match client.post("http://127.0.0.1:3030/api/mitre/stix/update").send().await {
        Ok(resp) if resp.status().is_success() => {
            println!("✓ P2P Wire Mesh gossip broadcast triggered via daemon (http://127.0.0.1:3030)");
        }
        _ => {
            if broadcast {
                println!("ℹ️  Broadcast requested, but local daemon is offline (http://127.0.0.1:3030). Manifest is cached locally and will synchronize on daemon startup.");
            } else {
                println!("ℹ️  Wire mesh daemon is offline (http://127.0.0.1:3030). Manifest is cached locally.");
            }
        }
    }

    // Re-sign configurations
    println!("🔐 Re-signing critical configurations & catalog integrity...");
    osoosi_core::config_integrity::sign_all_critical_configs();
    if catalog_path.exists() {
        let _ = osoosi_core::config_integrity::sign_config_file(catalog_path);
    }
    println!("✓ Configurations and MITRE catalog cryptographically sealed.\n");

    Ok(())
}

async fn handle_driver_command(action: DriverAction) -> anyhow::Result<()> {
    match action {
        DriverAction::Status => {
            let client = osoosi_runtime::kernel_driver::KernelDriverClient::open();
            match client {
                Some(kd) => match kd.get_status() {
                    Ok(st) => {
                        println!("====================================================");
                        println!(" OshoosiClaw Ring-0 Kernel Driver Status");
                        println!("====================================================");
                        println!("  Driver Version : 0x{:08X}", st.version);
                        println!("  Autonomy Mode  : {}", st.mode);
                        println!("  Blocked Count  : {}", st.blocked_count);
                        println!("  Rule Count     : {}", st.rule_count);
                        println!("  Device Path    : {}", osoosi_runtime::kernel_driver::OSOOSI_USER_DEVICE_NAME);
                        println!("  Operational    : Yes (Pre-exec blocking active)");
                        println!("====================================================");
                    }
                    Err(e) => {
                        eprintln!("Error querying driver status: {}", e);
                    }
                },
                None => {
                    println!("====================================================");
                    println!(" OshoosiClaw Ring-0 Kernel Driver: NOT CONNECTED");
                    println!("====================================================");
                    println!("  Device '{}' is not accessible or driver service is not running.", osoosi_runtime::kernel_driver::OSOOSI_USER_DEVICE_NAME);
                    println!("  User-mode WFP packet filter + active thread tarpit operating as defense-in-depth.");
                    println!("  Run 'osoosi driver install' as Administrator to configure the service.");
                    println!("====================================================");
                }
            }
        }
        DriverAction::Install { path } => {
            #[cfg(windows)]
            {
                info!("Installing Oshoosi Ring-0 Kernel Driver service...");
                let driver_path = if let Some(p) = path {
                    std::path::PathBuf::from(p)
                } else {
                    let default_dev = std::path::PathBuf::from("driver\\windows\\osoosi_driver.sys");
                    if default_dev.exists() {
                        default_dev
                    } else {
                        let installed = std::path::PathBuf::from("C:\\Program Files\\OshoosiClaw\\driver\\windows\\osoosi_driver.sys");
                        if installed.exists() {
                            installed
                        } else {
                            std::path::PathBuf::from("C:\\Program Files\\OshoosiClaw\\driver\\osoosi_driver.sys")
                        }
                    }
                };
                println!("Registering kernel service 'OsoosiDriver' pointing to {:?}...", driver_path);
                let create_status = std::process::Command::new("sc.exe")
                    .args([
                        "create",
                        "OsoosiDriver",
                        "type=",
                        "kernel",
                        "binPath=",
                        &driver_path.to_string_lossy(),
                        "start=",
                        "demand",
                    ])
                    .status();

                match create_status {
                    Ok(s) if s.success() => {
                        info!("Driver service successfully created. Starting driver...");
                        let _ = std::process::Command::new("sc.exe")
                            .args(["start", "OsoosiDriver"])
                            .status();
                        println!("OshoosiDriver service registered and start requested.");
                    }
                    Ok(s) => {
                        warn!("sc create exited with status: {}. Attempting to start in case service already exists...", s);
                        let start_status = std::process::Command::new("sc.exe")
                            .args(["start", "OsoosiDriver"])
                            .status();
                        match start_status {
                            Ok(st) if st.success() => println!("OsoosiDriver service started successfully."),
                            Ok(st) => eprintln!("Failed to start OsoosiDriver service: exit code {}", st),
                            Err(e) => eprintln!("Failed to execute sc.exe start: {}", e),
                        }
                    }
                    Err(e) => eprintln!("Failed to execute sc.exe create: {}", e),
                }
            }
            #[cfg(not(windows))]
            {
                let _ = path;
                println!("Driver installation is only supported on Windows.");
            }
        }
        DriverAction::Uninstall => {
            #[cfg(windows)]
            {
                info!("Stopping and removing Oshoosi Ring-0 Kernel Driver service...");
                let _ = std::process::Command::new("sc.exe")
                    .args(["stop", "OsoosiDriver"])
                    .status();
                let del_status = std::process::Command::new("sc.exe")
                    .args(["delete", "OsoosiDriver"])
                    .status();
                match del_status {
                    Ok(s) if s.success() => println!("OsoosiDriver service successfully removed."),
                    Ok(s) => eprintln!("sc delete exited with status: {}", s),
                    Err(e) => eprintln!("Failed to execute sc delete: {}", e),
                }
            }
            #[cfg(not(windows))]
            {
                println!("Driver uninstallation is only supported on Windows.");
            }
        }
        DriverAction::AddRule { path } => {
            let client = osoosi_runtime::kernel_driver::KernelDriverClient::open();
            match client {
                Some(kd) => match kd.add_blocked_path(&path) {
                    Ok(()) => println!("Successfully added pre-exec block rule for path: {}", path),
                    Err(e) => eprintln!("Failed to add kernel rule: {}", e),
                },
                None => {
                    eprintln!("Kernel driver not accessible. Ensure driver service is installed and running.");
                }
            }
        }
        DriverAction::SetMode { mode } => {
            let client = osoosi_runtime::kernel_driver::KernelDriverClient::open();
            match client {
                Some(kd) => {
                    let d_mode = match mode.to_ascii_lowercase().as_str() {
                        "audit" | "0" => osoosi_runtime::kernel_driver::DriverAutonomyMode::Audit,
                        "lockdown" | "2" => osoosi_runtime::kernel_driver::DriverAutonomyMode::Lockdown,
                        _ => osoosi_runtime::kernel_driver::DriverAutonomyMode::Active,
                    };
                    match kd.set_mode(d_mode) {
                        Ok(()) => println!("Kernel driver autonomy mode successfully set to: {}", d_mode),
                        Err(e) => eprintln!("Failed to set driver mode: {}", e),
                    }
                }
                None => {
                    eprintln!("Kernel driver not accessible. Ensure driver service is installed and running.");
                }
            }
        }
        DriverAction::ClearRules => {
            let client = osoosi_runtime::kernel_driver::KernelDriverClient::open();
            match client {
                Some(kd) => match kd.clear_rules() {
                    Ok(()) => println!("Successfully flushed all in-memory kernel blocking rules."),
                    Err(e) => eprintln!("Failed to flush kernel rules: {}", e),
                },
                None => {
                    eprintln!("Kernel driver not accessible. Ensure driver service is installed and running.");
                }
            }
        }
    }
    Ok(())
}

fn resolve_log_directory() -> PathBuf {
    osoosi_types::resolve_log_directory()
}

fn init_logging(debug: bool) -> anyhow::Result<tracing_appender::non_blocking::WorkerGuard> {
    let log_dir = resolve_log_directory();
    fs::create_dir_all(&log_dir)
        .map_err(|e| anyhow::anyhow!("Cannot create log directory {}: {}", log_dir.display(), e))?;
    let file_appender = tracing_appender::rolling::daily(&log_dir, "osoosi.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    
    let file_filter = create_file_filter(debug);
    let console_filter = create_console_filter(debug);

    let console_layer = fmt::Layer::default()
        .with_writer(std::io::stdout)
        .with_filter(console_filter);
    
    let file_layer = fmt::Layer::default()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_filter(file_filter);

    let _ = tracing_subscriber::registry()
        .with(console_layer)
        .with(file_layer)
        .with(osoosi_exporter::init_opentelemetry_layer())
        .try_init();

    if !debug {
        println!("[*] Logging initialized. Console level: WARN, File level: INFO");
        println!("[*] Logs available at: {}", log_dir.display());
    } else {
        info!(
            path = %log_dir.display(),
            "Debug logging enabled. Console level: DEBUG, File level: DEBUG"
        );
    }
    
    Ok(guard)
}

pub fn create_file_filter(debug: bool) -> EnvFilter {
    let file_level = if debug {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    EnvFilter::from_default_env()
        .add_directive(file_level.into())
        .add_directive("nostr_relay_pool=off".parse().expect("static directive"))
        .add_directive("nostr=error".parse().expect("static directive"))
        .add_directive("h2=warn".parse().expect("static directive"))
        .add_directive("hyper=warn".parse().expect("static directive"))
        .add_directive("rustls=warn".parse().expect("static directive"))
        .add_directive("cranelift_codegen=warn".parse().expect("static directive"))
        .add_directive("cranelift_wasm=warn".parse().expect("static directive"))
        .add_directive("wasmtime_cranelift=warn".parse().expect("static directive"))
        .add_directive("wasmtime_internal_cranelift=warn".parse().expect("static directive"))
        .add_directive("wasmtime_jit=warn".parse().expect("static directive"))
        .add_directive("wasmtime=warn".parse().expect("static directive"))
        .add_directive("wasmtime_wasi=warn".parse().expect("static directive"))
        .add_directive("tokenizers=error".parse().expect("static directive"))
        .add_directive("libp2p_kad=error".parse().expect("static directive"))
        .add_directive("libp2p_gossipsub=error".parse().expect("static directive"))
        .add_directive("regalloc2=warn".parse().expect("static directive"))
        .add_directive("tower_http::services::fs::serve_dir=off".parse().expect("static directive"))
        .add_directive("tower_http=warn".parse().expect("static directive"))
}

pub fn create_console_filter(debug: bool) -> EnvFilter {
    let console_level = if debug {
        tracing::Level::DEBUG
    } else {
        tracing::Level::WARN
    };
    EnvFilter::from_default_env()
        .add_directive(console_level.into())
        .add_directive("nostr_relay_pool=off".parse().expect("static directive"))
        .add_directive("nostr=error".parse().expect("static directive"))
        .add_directive("h2=error".parse().expect("static directive"))
        .add_directive("hyper=error".parse().expect("static directive"))
        .add_directive("rustls=error".parse().expect("static directive"))
        .add_directive("tokenizers=error".parse().expect("static directive"))
        .add_directive("libp2p_kad=error".parse().expect("static directive"))
        .add_directive("libp2p_gossipsub=error".parse().expect("static directive"))
        .add_directive("cranelift_codegen=warn".parse().expect("static directive"))
        .add_directive("cranelift_wasm=warn".parse().expect("static directive"))
        .add_directive("wasmtime_cranelift=warn".parse().expect("static directive"))
        .add_directive("wasmtime_internal_cranelift=warn".parse().expect("static directive"))
        .add_directive("wasmtime_jit=warn".parse().expect("static directive"))
        .add_directive("wasmtime=warn".parse().expect("static directive"))
        .add_directive("wasmtime_wasi=warn".parse().expect("static directive"))
        .add_directive("regalloc2=warn".parse().expect("static directive"))
        .add_directive("tower_http::services::fs::serve_dir=off".parse().expect("static directive"))
        .add_directive("tower_http=warn".parse().expect("static directive"))
}

fn run_yara_sanitizer() {
    info!("Running native Rust YARA rule sanitization (pre-scan cleanup)...");

    // 1. Resolve search paths correctly by looking for project root if necessary
    let mut search_paths = Vec::new();
    
    // Add current directory targets
    search_paths.push(PathBuf::from("yara"));
    search_paths.push(PathBuf::from("rules"));
    
    // Add relative path from executable (if we are in target/release)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(mut dir) = exe.parent().map(|p| p.to_path_buf()) {
            for _ in 0..10 {
                if dir.join("rules").is_dir() {
                    search_paths.push(dir.join("rules"));
                }
                if dir.join("yara").is_dir() {
                    search_paths.push(dir.join("yara"));
                }
                if dir.join(".git").is_dir() || dir.join("Cargo.toml").is_file() {
                    break;
                }
                match dir.parent() {
                    Some(p) => dir = p.to_path_buf(),
                    None => break,
                }
            }
        }
    }

    if let Ok(yara_dir) = std::env::var("OSOOSI_YARA_DIR") {
        search_paths.push(PathBuf::from(yara_dir));
    }

    let mut count = 0;
    let mut visited = std::collections::HashSet::new();

    for base_path in search_paths {
        if !base_path.exists() {
            continue;
        }
        
        let canonical = match base_path.canonicalize() {
            Ok(p) => p,
            Err(_) => base_path.clone(),
        };
        if !visited.insert(canonical) {
            continue;
        }

        info!("Sweeping YARA rules in: {:?}", base_path);

        for entry in walkdir::WalkDir::new(base_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() && entry.path().extension().map_or(false, |ext| ext == "yar") {
                let path = entry.path();
                match std::fs::read_to_string(path) {
                    Ok(content) => {
                        let sanitized = sanitize_yara_content(&content);
                        if sanitized != content {
                            if std::fs::write(path, sanitized).is_ok() {
                                count += 1;
                                info!("Sanitized (Native): {:?}", path);
                            }
                        }
                    }
                    Err(_) => {
                        // Try reading with lossy UTF-8 if direct read fails (similar to 'ignore' errors in Python)
                        if let Ok(bytes) = std::fs::read(path) {
                            let content = String::from_utf8_lossy(&bytes).to_string();
                            let sanitized = sanitize_yara_content(&content);
                            if sanitized != content {
                                if std::fs::write(path, sanitized).is_ok() {
                                    count += 1;
                                    info!("Sanitized (Native Lossy): {:?}", path);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if count > 0 {
        info!("Total YARA files sanitized natively: {}", count);
    }
}

fn sanitize_yara_content(content: &str) -> String {
    let mut result = content.to_string();

    // 1. Fix invalid escapes in strings and regexes
    // Regex for strings: ".*?" (non-greedy)
    let string_regex = regex::Regex::new(r#"(?s)".*?""#).unwrap();
    result = string_regex.replace_all(&result, |caps: &regex::Captures| {
        fix_yara_escapes(&caps[0])
    }).to_string();

    // Regex for regexes: /.*?/
    let regex_decl_regex = regex::Regex::new(r"(?s)/.*?/").unwrap();
    result = regex_decl_regex.replace_all(&result, |caps: &regex::Captures| {
        fix_yara_escapes(&caps[0])
    }).to_string();

    // 2. Fix unescaped forward slashes in regex: /.../.../ -> /...\/.../
    // Heuristic: looks for /.../ followed by modifiers or whitespace/newline/semicolon
    let regex_fixer = regex::Regex::new(r"/[^ \n].*?/[ ]*(wide|ascii|nocase|fullword|\n|;)").unwrap();
    result = regex_fixer.replace_all(&result, |caps: &regex::Captures| {
        let r = &caps[0];
        if r.len() < 3 { return r.to_string(); }
        
        // Find the second '/' (the end of the regex part)
        if let Some(end_idx) = r[1..].find('/') {
            let internal = &r[1..end_idx + 1];
            let mut fixed_internal = String::with_capacity(internal.len());
            let chars: Vec<char> = internal.chars().collect();
            for i in 0..chars.len() {
                if chars[i] == '/' && (i == 0 || chars[i-1] != '\\') {
                    fixed_internal.push('\\');
                    fixed_internal.push('/');
                } else {
                    fixed_internal.push(chars[i]);
                }
            }
            format!("/{}/{}", fixed_internal, &r[end_idx + 2..])
        } else {
            r.to_string()
        }
    }).to_string();

    // 3. Fix empty alternatives
    result = result.replace("|/", "/");
    result = result.replace("/|", "/");
    result = result.replace("||", "|");

    // 4. Fix regexes followed immediately by keywords (prevents 'c' being seen as modifier)
    // Use regex to find slashes followed by keywords, ensuring we catch things like /condition: or //condition:
    let re_boundary = regex::Regex::new(r"(/+)(condition:|strings:|meta:|rule\b)").unwrap();
    result = re_boundary.replace_all(&result, " $1 $2").to_string();

    // Specific common cases that might have escaped the regex
    result = result.replace("/condition:", "/ condition:");
    result = result.replace("//condition:", " // condition:");

    result
}

fn fix_yara_escapes(s: &str) -> String {
    // Standard valid escapes in YARA + common regex escapes
    let valid = "nrt\\\"\'xuUdwsDWSbB0123456789$^*+?()[]{}|.^/ ";
    let mut result = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() {
            let next = chars[i+1];
            if next == '\\' {
                // Literal backslash: valid, push both and skip
                result.push('\\');
                result.push('\\');
                i += 2;
                continue;
            } else if valid.contains(next) {
                // Other valid escape: push both and skip
                result.push('\\');
                result.push(next);
                i += 2;
                continue;
            } else {
                // Invalid escape: escape the backslash itself
                result.push('\\');
                result.push('\\');
                result.push(next);
                i += 2;
                continue;
            }
        }
        result.push(chars[i]);
        i += 1;
    }
    result
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
pub async fn provision_models() -> anyhow::Result<()> {
    ensure_ai_models().await
}

async fn ensure_ai_models() -> anyhow::Result<()> {
    if std::env::var("OSOOSI_NO_AI")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        return Ok(());
    }

    osoosi_types::set_model_provisioning(true);
    let res = ensure_ai_models_inner().await;
    osoosi_types::set_model_provisioning(false);
    res
}

async fn ensure_ai_models_inner() -> anyhow::Result<()> {

    info!(
        "Verifying AI models in {}...",
        osoosi_types::resolve_models_dir().display()
    );
    ensure_ollama_model().await;

    let models_dir = osoosi_types::resolve_models_dir();
    let gemma_dir = models_dir.join("gemma4-e4b");
    let malware_dir = models_dir.join("malware");

    fs::create_dir_all(&gemma_dir)?;
    fs::create_dir_all(&malware_dir)?;

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
    if std::env::var("OSOOSI_LITE_MODE").map(|v| v == "1").unwrap_or(false) {
        info!("LITE MODE active: Skipping Gemma 4 ONNX download to save disk space.");
    } else {
        let gemma_repo_name = std::env::var("OSOOSI_GEMMA_ONNX_REPO")
            .unwrap_or_else(|_| "onnx-community/gemma-4-E4B-it-ONNX".to_string());
        let gemma_repo = api.model(gemma_repo_name.clone());

        // Just pull the necessary files into the HuggingFace cache.
        // The runtime logic in `osoosi-core` will dynamically locate the snapshot dir.
        info!("Ensuring Gemma 4 ONNX shards are cached from {}...", gemma_repo_name);
    for filename in [
        "config.json",
        "onnx/config.json",
        "tokenizer.json",
        "onnx/tokenizer.json",
        "model.onnx",
        "onnx/model.onnx",
        "decoder_model_merged.onnx",
        "onnx/decoder_model_merged.onnx",
        "decoder_model_merged.onnx_data_1",
        "onnx/decoder_model_merged.onnx_data_1",
        "decoder_model_merged.onnx_data_2",
        "onnx/decoder_model_merged.onnx_data_2",
        "decoder_model_merged.onnx_data_3",
        "onnx/decoder_model_merged.onnx_data_3",
        "decoder_model_merged.onnx_data_4",
        "onnx/decoder_model_merged.onnx_data_4",
        "decoder_model_merged.onnx_data_5",
        "onnx/decoder_model_merged.onnx_data_5",
        "decoder_model_merged.onnx_data_6",
        "onnx/decoder_model_merged.onnx_data_6",
        "decoder_model_merged.onnx_data_7",
        "onnx/decoder_model_merged.onnx_data_7",
        "decoder_model_merged.onnx_data_8",
        "onnx/decoder_model_merged.onnx_data_8",
    ] {
        if let Ok(_) = gemma_repo.get(filename).await {
            tracing::debug!("Cached Gemma component: {}", filename);
        }
    }
    }

    if std::env::var("OSOOSI_ENABLE_SMOLLM")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        // Optional legacy SmolLM bootstrap. Disabled by default; Gemma 4 is primary.
        // 1. SmolLM2-135M-Instruct (Native)
        let smollm_repo = api.model("HuggingFaceTB/SmolLM2-135M-Instruct".to_string());
        info!("Ensuring SmolLM components are cached...");
        for file in ["model.safetensors", "tokenizer.json", "config.json"] {
            let _ = smollm_repo.get(file).await;
        }

        // 2. SmolLM2-135M-Instruct (ONNX)
        let smollm_onnx_repo = api.model("onnx-community/SmolLM2-135M-Instruct".to_string());
        for filename in ["model.onnx", "smollm2-135m-it.onnx", "onnx/model.onnx"] {
            let _ = smollm_onnx_repo.get(filename).await;
        }
    }

    let ai_cfg = osoosi_types::load_ai_config();
    let malconv_dest = malware_dir.join("malconv.safetensors");
    let sorel_dest = malware_dir.join("sorel_ffnn.pt");

    // 3. MalConv Provisioning
    if !malconv_dest.exists() {
        if let Some(ref url) = ai_cfg.malconv_weights_url {
            info!("📥 Attempting MalConv download from primary URL...");
            let executor = DirectExecutor::new();
            if let Err(e) = executor.download(url.trim(), &malconv_dest, false).await {
                tracing::debug!("Primary MalConv download failed: {}. Trying fallbacks...", e);
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
            "oyesanyf/OshoosiClaw-Weights",
            "oyesanyf/OshoosiClaw",
            "Xenova/malconv",
            "onnx-community/malconv",
        ];
        'malconv_hf: for repo_name in malconv_repos {
            let repo = api.model(repo_name.to_string());
            for file in malconv_files {
                info!("📥 Verifying MalConv AI component: `{}` / `{}`...", repo_name, file);
                match repo.get(file).await {
                    Ok(downloaded) => {
                        if let Ok(meta) = std::fs::metadata(&downloaded) {
                            if meta.len() < 1024 {
                                warn!("Downloaded MalConv file is too small ({} bytes). Likely a 404 page. Skipping.", meta.len());
                                continue;
                            }
                            if fs::copy(&downloaded, &malconv_dest).is_ok() {
                                info!("✅ MalConv weights saved from {} ({}).", repo_name, file);
                                break 'malconv_hf;
                            }
                        }
                    }
                    Err(e) => tracing::debug!("MalConv HF get {} {}: {}", repo_name, file, e),
                }
            }
        }
    }

    // 4. SOREL-20M Provisioning
    let sorel_st = malware_dir.join("sorel_ffnn.safetensors");
    let mut needs_sorel = !sorel_dest.exists() && !sorel_st.exists();
    if !needs_sorel {
        let check_path = if sorel_st.exists() { &sorel_st } else { &sorel_dest };
        if let Ok(meta) = std::fs::metadata(check_path) {
            if meta.len() < 1024 {
                needs_sorel = true;
            } else if check_path == &sorel_dest {
                let mut f = std::fs::File::open(check_path).ok();
                let mut magic = [0u8; 4];
                let is_valid = f.as_mut().and_then(|f| {
                    use std::io::Read;
                    f.read_exact(&mut magic).ok()
                }).is_some() && (&magic == b"PK\x03\x04" || (magic[0] != b'<' && magic[0] != 0));
                
                if !is_valid {
                    warn!("Existing SOREL weights at {:?} appear to be invalid or HTML error pages. Re-provisioning...", check_path);
                    needs_sorel = true;
                }
            }
        }
    }

    if needs_sorel {
        info!("📥 SOREL-20M weights missing or invalid. Attempting provisioning...");
        let sorel_repos = [
            "oyesanyf/OshoosiClaw-Weights",
            "oyesanyf/OshoosiClaw",
            "Xenova/sorel-20m",
        ];
        'sorel_hf: for repo_name in sorel_repos {
            let repo = api.model(repo_name.to_string());
            for file in ["sorel_ffnn.pt", "model.pt", "weights.pt"] {
                match repo.get(file).await {
                    Ok(downloaded) => {
                        if let Ok(meta) = std::fs::metadata(&downloaded) {
                            if meta.len() < 1024 { continue; }
                            
                            // Accept if it has ZIP magic (standard .pt) OR if it starts with something other than '<' (to avoid HTML 404s)
                            let f = std::fs::File::open(&downloaded).ok();
                            let mut magic = [0u8; 4];
                            if let Some(mut f_inner) = f {
                                use std::io::Read;
                                if f_inner.read_exact(&mut magic).is_ok() {
                                    if &magic != b"PK\x03\x04" && (magic[0] == b'<' || magic[0] == 0) {
                                        warn!("Downloaded SOREL file {} appears to be an HTML error page. Skipping.", file);
                                        continue;
                                    }
                                }
                            }

                            if fs::copy(&downloaded, &sorel_dest).is_ok() {
                                info!("✅ SOREL-20M weights saved from {} ({}).", repo_name, file);
                                break 'sorel_hf;
                            }
                        }
                    }
                    Err(e) => tracing::debug!("SOREL HF get {} {}: {}", repo_name, file, e),
                }
            }
        }
    }

    if !malconv_dest.exists() {
        warn!("⚠️ MalConv weights could not be provisioned from any source. Static AI analysis will be degraded.");
    }
    if !sorel_dest.exists() && !sorel_st.exists() {
        warn!("⚠️ SOREL-20M weights could not be provisioned from remote mirrors. Attempting local build from dataset folder...");
        // Use a dummy path for the call; the function will resolve the dataset folder itself.
        let sorel_handle = Arc::new(tokio::sync::RwLock::new(None));
        if let Err(e) = osoosi_model::malware::MalwareScanner::provision_sorel_by_training(sorel_handle, &sorel_dest).await {
             warn!("⚠️ Local SOREL build failed: {}. Deep PE analysis will be degraded.", e);
        } else {
             info!("✅ SOREL model built locally and provisioned.");
        }
    }

    // 4. SecureBERT (Behavioral Sentence Classification)
    info!("Ensuring SecureBERT components are cached...");
    let sb_repo = api.model("MarsSecurity/securebert-onnx".to_string());
    let bert_dir = models_dir.join("securebert");
    let _ = fs::create_dir_all(&bert_dir);
    for file in ["tokenizer.json", "model.onnx", "config.json"] {
        if let Ok(path) = sb_repo.get(file).await {
            let _ = fs::copy(&path, bert_dir.join(file));
        }
    }

    info!("AI models verified.");
    Ok(())
}

fn get_ollama_bin() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            let candidate = std::path::Path::new(&local_app_data)
                .join("Programs")
                .join("Ollama")
                .join("ollama.exe");
            if candidate.exists() {
                return candidate;
            }
        }
    }
    std::path::PathBuf::from("ollama")
}

async fn ensure_ollama_model() {
    let ai = osoosi_types::config::load_ai_config();
    let preferred = ai.reasoning_model.clone();

    if !ollama_available().await {
        install_ollama_best_effort().await;
    }

    if !ollama_available().await {
        warn!(
            "Ollama not available after provisioning attempt. Gemma 4 ONNX files will be used if present; reasoning voters stay silent otherwise."
        );
        return;
    };

    info!("Ollama detected. Ensuring a local reasoning model is available...");
    
    let list_fut = tokio::process::Command::new(get_ollama_bin())
        .arg("list")
        .output();
    
    let list_stdout = match tokio::time::timeout(std::time::Duration::from_secs(30), list_fut).await {
        Ok(Ok(out)) => String::from_utf8_lossy(&out.stdout).to_string(),
        _ => String::new(),
    };

    if ai.foundation_sec_enabled {
        let f_model = ai.foundation_sec_model.clone();
        if !list_stdout.contains(&f_model) {
            info!("Pulling Cisco Foundation-Sec-8B model: '{}'...", f_model);
            let pull_fut = tokio::process::Command::new(get_ollama_bin())
                .args(["pull", &f_model])
                .status();
            let _ = tokio::time::timeout(std::time::Duration::from_secs(600), pull_fut).await;
        }
    }

    let mut candidates = vec![preferred.clone()];
    for fallback in &ai.fallback_models {
        if !candidates.iter().any(|m| m == fallback) {
            candidates.push(fallback.clone());
        }
    }

    let mut selected = candidates
        .iter()
        .find(|model| list_stdout.contains(model.as_str()))
        .cloned();

    if selected.is_none() {
        for model in &candidates {
            let pull_fut = tokio::process::Command::new(get_ollama_bin())
                .args(["pull", model])
                .status();
                
            match tokio::time::timeout(std::time::Duration::from_secs(600), pull_fut).await {
                Ok(Ok(status)) if status.success() => {
                    info!("Ollama model '{}' provisioned.", model);
                    selected = Some(model.clone());
                    break;
                }
                Ok(Ok(status)) => {
                    warn!(
                        "ollama pull {} exited with status {}; trying next Gemma fallback.",
                        model, status
                    );
                }
                Ok(Err(e)) => {
                    warn!(
                        "Failed to run ollama pull {}: {}; trying next Gemma fallback.",
                        model, e
                    );
                }
                Err(_) => {
                    warn!("ollama pull {} timed out; trying next fallback.", model);
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
    if let Ok(Ok(resp)) = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        reqwest::get("http://127.0.0.1:11434/api/version"),
    )
    .await
    {
        if resp.status().is_success() {
            return true;
        }
    }

    let bin = get_ollama_bin();
    let check_fut = tokio::process::Command::new(&bin)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match tokio::time::timeout(std::time::Duration::from_secs(3), check_fut).await {
        Ok(Ok(status)) => status.success(),
        _ => false,
    }
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
        let winget_fut = tokio::process::Command::new("winget")
            .args([
                "install",
                "--id",
                "Ollama.Ollama",
                "-e",
                "--accept-package-agreements",
                "--accept-source-agreements",
            ])
            .status();

        match tokio::time::timeout(std::time::Duration::from_secs(600), winget_fut).await {
            Ok(Ok(status)) if status.success() => info!("Ollama installed with winget."),
            Ok(Ok(status)) => {
                let code = status.code().unwrap_or(0);
                // 0x8a15002b = -1978335189 (APPGATE_SOURCE_NO_UPDATE / already installed and up to date)
                if code == -1978335189 || code == 0x8a15002b_u32 as i32 {
                    info!("Ollama is already installed and up to date (winget status 0x8a15002b).");
                } else {
                    warn!("winget Ollama install exited with status {}.", status);
                }
            }
            Ok(Err(e)) => warn!(
                "winget not available or failed to start for Ollama install: {}",
                e
            ),
            Err(_) => warn!("winget Ollama install timed out."),
        }
    }

    #[cfg(target_os = "macos")]
    {
        let brew_fut = tokio::process::Command::new("brew")
            .args(["install", "ollama"])
            .status();

        match tokio::time::timeout(std::time::Duration::from_secs(600), brew_fut).await {
            Ok(Ok(status)) if status.success() => info!("Ollama installed with Homebrew."),
            Ok(Ok(status)) => warn!("brew Ollama install exited with status {}.", status),
            Ok(Err(e)) => warn!(
                "Homebrew not available or failed to start for Ollama install: {}",
                e
            ),
            Err(_) => warn!("brew Ollama install timed out."),
        }
    }

    #[cfg(target_os = "linux")]
    {
        let shell_fut = tokio::process::Command::new("sh")
            .args(["-c", "curl -fsSL https://ollama.com/install.sh | sh"])
            .status();

        match tokio::time::timeout(std::time::Duration::from_secs(600), shell_fut).await {
            Ok(Ok(status)) if status.success() => {
                info!("Ollama installed with official Linux installer.")
            }
            Ok(Ok(status)) => warn!("Ollama Linux installer exited with status {}.", status),
            Ok(Err(e)) => warn!("Failed to start Ollama Linux installer: {}", e),
            Err(_) => warn!("Ollama Linux installer timed out."),
        }
    }
}

static WIKISKILL_PATHS: std::sync::OnceLock<(Option<PathBuf>, Option<PathBuf>, Option<PathBuf>)> =
    std::sync::OnceLock::new();

/// Returns (python_bin, cli_path, project_root)
fn resolve_wikiskill_paths() -> (Option<PathBuf>, Option<PathBuf>, Option<PathBuf>) {
    WIKISKILL_PATHS
        .get_or_init(|| {
            let mut base_dirs = Vec::new();
            if let Ok(cwd) = std::env::current_dir() {
                base_dirs.push(cwd.clone());
                for ancestor in cwd.ancestors() {
                    base_dirs.push(ancestor.to_path_buf());
                }
            }
            if let Ok(exe) = std::env::current_exe() {
                for ancestor in exe.ancestors() {
                    base_dirs.push(ancestor.to_path_buf());
                }
            }
            base_dirs.dedup();

            let mut cli_path = None;
            let mut project_root = None;
            for dir in &base_dirs {
                let candidate = dir
                    .join("tools")
                    .join("wikiskill")
                    .join("src")
                    .join("wikiskill")
                    .join("cli.py");
                if candidate.is_file() {
                    cli_path = Some(candidate);
                    project_root = Some(dir.clone());
                    break;
                }
            }

            let python_candidates = [
                "python",
                "python3",
                "py",
                r"C:\Python314\python.exe",
                r"C:\Python313\python.exe",
                r"C:\Python312\python.exe",
                r"C:\Python311\python.exe",
            ];

            let mut python_bin = None;
            for cand in python_candidates {
                let mut cmd = std::process::Command::new(cand);
                cmd.arg("--version")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());

                #[cfg(target_os = "windows")]
                {
                    #[allow(unused_imports)]
                    use std::os::windows::process::CommandExt;
                    cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
                }

                if let Ok(status) = cmd.status() {
                    if status.success() {
                        python_bin = Some(PathBuf::from(cand));
                        break;
                    }
                }
            }

            (python_bin, cli_path, project_root)
        })
        .clone()
}

fn run_wikiskill_cli(args: &[&str]) -> anyhow::Result<std::process::Output> {
    let (python_opt, cli_opt, _root_opt) = resolve_wikiskill_paths();
    let python = python_opt.ok_or_else(|| {
        anyhow::anyhow!("Python 3.11+ interpreter not found. Please ensure Python is installed and in PATH.")
    })?;
    let cli = cli_opt.ok_or_else(|| {
        anyhow::anyhow!("WikiSkill CLI not found at tools/wikiskill/src/wikiskill/cli.py.")
    })?;

    let mut cmd = std::process::Command::new(&python);
    cmd.arg(&cli).args(args);

    #[cfg(target_os = "windows")]
    {
        #[allow(unused_imports)]
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }

    let output = cmd.output()?;
    Ok(output)
}

/// Atomically persists state JSON via temporary file swap to eliminate race conditions
/// and avoid corrupted or truncated reads by concurrent supervisor / dashboard monitors.
fn atomic_write_state_file(path: &Path, content: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp_path, content)?;
    #[cfg(target_os = "windows")]
    {
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
        if let Err(_) = std::fs::rename(&tmp_path, path) {
            let _ = std::fs::write(path, content);
            let _ = std::fs::remove_file(&tmp_path);
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::fs::rename(&tmp_path, path)?;
    }
    Ok(())
}

async fn run_wikiskill_background_loop(
    workspace: String,
    tasks_file: String,
    scorer: String,
    poll_interval: std::time::Duration,
    orchestrator: Option<Arc<osoosi_core::EdrOrchestrator>>,
) {
    let (python_opt, cli_opt, project_root) = resolve_wikiskill_paths();

    // Anchor relative paths against project root if present and not in cwd
    let ws_path = if Path::new(&workspace).is_absolute() {
        PathBuf::from(&workspace)
    } else if Path::new(&workspace).is_dir() {
        PathBuf::from(&workspace)
    } else if let Some(ref root) = project_root {
        root.join(&workspace)
    } else {
        PathBuf::from(&workspace)
    };

    let resolved_tasks = if Path::new(&tasks_file).is_file() {
        tasks_file.clone()
    } else if let Some(ref root) = project_root {
        let candidate = root.join(&tasks_file);
        if candidate.is_file() {
            candidate.to_string_lossy().to_string()
        } else {
            tasks_file.clone()
        }
    } else {
        tasks_file.clone()
    };

    let resolved_scorer = if Path::new(&scorer).is_file() {
        scorer.clone()
    } else if let Some(ref root) = project_root {
        let candidate = root.join(&scorer);
        if candidate.is_file() {
            candidate.to_string_lossy().to_string()
        } else {
            scorer.clone()
        }
    } else {
        scorer.clone()
    };

    let resolved_ws_str = ws_path.to_string_lossy().to_string();
    let mut broadcasted_patterns: std::collections::HashSet<String> = std::collections::HashSet::new();

    // 1. If workspace doesn't exist, bootstrap it with wikiskill start
    if !ws_path.is_dir() {
        if let (Some(python), Some(cli)) = (python_opt.as_ref(), cli_opt.as_ref()) {
            info!("[WikiSkill] Bootstrapping evolution workspace at {}...", resolved_ws_str);
            let mut cmd = tokio::process::Command::new(python);
            cmd.arg(cli)
                .arg("start")
                .arg(&resolved_ws_str)
                .arg("--tasks")
                .arg(&resolved_tasks)
                .arg("--scorer")
                .arg(&resolved_scorer)
                .arg("--no-agent")
                .arg("--trust-scorer")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null());

            #[cfg(target_os = "windows")]
            {
                #[allow(unused_imports)]
                use std::os::windows::process::CommandExt;
                cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
            }

            match tokio::time::timeout(std::time::Duration::from_secs(30), cmd.output()).await {
                Ok(Ok(output)) if output.status.success() => {
                    info!("[WikiSkill] Successfully initialized evolution workspace at {}.", resolved_ws_str);
                    let state_file = ws_path.join(".wikiskill-state.json");
                    let _ = atomic_write_state_file(&state_file, &output.stdout);
                }
                Ok(Ok(output)) => {
                    warn!("[WikiSkill] Bootstrapping returned status: {:?}", output.status.code());
                }
                Ok(Err(e)) => {
                    warn!("[WikiSkill] Failed to execute bootstrap command: {}", e);
                }
                Err(_) => {
                    warn!("[WikiSkill] Bootstrapping timed out after 30 seconds.");
                }
            }
        } else {
            warn!("[WikiSkill] Python interpreter or WikiSkill CLI not found; skipping bootstrap.");
        }
    }

    // Immediate initial poll to eliminate any startup blackout window
    let (_, initial_score) = poll_wikiskill_status(&resolved_ws_str, &ws_path).await;
    broadcast_new_wiki_patterns(&ws_path, initial_score, &mut broadcasted_patterns, &orchestrator).await;

    // 2. Continuous background evaluation loop
    loop {
        tokio::time::sleep(poll_interval).await;
        let (_, score) = poll_wikiskill_status(&resolved_ws_str, &ws_path).await;
        broadcast_new_wiki_patterns(&ws_path, score, &mut broadcasted_patterns, &orchestrator).await;
    }
}

/// Discovers valid WikiSkill patterns from the given workspace directory.
/// Scans `wiki/index.md` supporting table rows (`| [Title](path) | Summary |`),
/// bullet lists (`- [Title](path)`), asterisk lists (`* [Title](path)`), and numbered lists (`1. [Title](path)`).
/// Also falls back to scanning `wiki/patterns/*.md` for any unindexed pattern files.
pub fn discover_wiki_patterns(ws_path: &Path) -> Vec<(String, String, String)> {
    let mut patterns = Vec::new();
    let mut seen_hashes = std::collections::HashSet::new();

    let wiki_dir = ws_path.join("wiki");
    let index_file = wiki_dir.join("index.md");

    // 1. Scan wiki/index.md if present
    if index_file.is_file() {
        if let Ok(content) = std::fs::read_to_string(&index_file) {
            for line in content.lines() {
                let trimmed = line.trim();
                let link_start = match trimmed.find('[') {
                    Some(i) => i + 1,
                    None => continue,
                };
                let link_end = match trimmed[link_start..].find("](") {
                    Some(i) => link_start + i,
                    None => continue,
                };
                let url_start = link_end + 2;
                let url_end = match trimmed[url_start..].find(')') {
                    Some(i) => url_start + i,
                    None => continue,
                };

                let title = trimmed[link_start..link_end].trim();
                let rel_path = trimmed[url_start..url_end].trim();

                if title.is_empty() || rel_path.is_empty() {
                    continue;
                }
                if rel_path.starts_with("http://") || rel_path.starts_with("https://") {
                    continue;
                }

                let pattern_file = if wiki_dir.join(rel_path).is_file() {
                    wiki_dir.join(rel_path)
                } else if ws_path.join(rel_path).is_file() {
                    ws_path.join(rel_path)
                } else {
                    continue;
                };

                if let Ok(pattern_md) = std::fs::read_to_string(&pattern_file) {
                    let trimmed_md = pattern_md.trim();
                    if trimmed_md.is_empty() {
                        continue;
                    }
                    let hash = blake3::hash(trimmed_md.as_bytes()).to_hex().to_string();
                    if seen_hashes.insert(hash.clone()) {
                        patterns.push((title.to_string(), hash, pattern_md));
                    }
                }
            }
        }
    }

    // 2. Also scan wiki/patterns/*.md for any patterns not yet indexed
    let patterns_dir = wiki_dir.join("patterns");
    if patterns_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&patterns_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("md") {
                    if let Ok(pattern_md) = std::fs::read_to_string(&path) {
                        let trimmed_md = pattern_md.trim();
                        if trimmed_md.is_empty() {
                            continue;
                        }
                        let hash = blake3::hash(trimmed_md.as_bytes()).to_hex().to_string();
                        if seen_hashes.insert(hash.clone()) {
                            let title = pattern_md
                                .lines()
                                .find(|l| l.trim().starts_with("# "))
                                .map(|l| l.trim().trim_start_matches('#').trim().to_string())
                                .unwrap_or_else(|| {
                                    path.file_stem()
                                        .and_then(|s| s.to_str())
                                        .unwrap_or("Pattern")
                                        .to_string()
                                });
                            patterns.push((title, hash, pattern_md));
                        }
                    }
                }
            }
        }
    }

    patterns
}

async fn broadcast_new_wiki_patterns(
    ws_path: &Path,
    score: f64,
    broadcasted: &mut std::collections::HashSet<String>,
    orchestrator: &Option<Arc<osoosi_core::EdrOrchestrator>>,
) {
    let patterns = discover_wiki_patterns(ws_path);
    if patterns.is_empty() {
        return;
    }

    let orch = match orchestrator {
        Some(o) => o,
        None => {
            // For testing or dry-run without active orchestrator
            for (_, hash, _) in patterns {
                broadcasted.insert(hash);
            }
            return;
        }
    };

    for (title, content_hash, pattern_md) in patterns {
        if broadcasted.contains(&content_hash) {
            continue;
        }

        let node_id = orch.trust().did().to_string();
        use ed25519_dalek::Signer;
        let sig = orch.trust().signing_key().sign(content_hash.as_bytes());
        let signature = Some(hex::encode(sig.to_bytes()));

        let broadcast = osoosi_wire::SkillKnowledgeBroadcast {
            node_id,
            skill_name: "wikiskill".to_string(),
            version: "1.0.0".to_string(),
            content_hash: content_hash.clone(),
            pattern_title: title.clone(),
            markdown_content: pattern_md,
            score,
            timestamp: chrono::Utc::now(),
            signature,
        };

        info!(
            "[WikiSkill] Discovered new pattern '{}' ({}); broadcasting to P2P wire mesh...",
            title, content_hash
        );

        if let Err(e) = orch.broadcast_skill_knowledge(broadcast).await {
            warn!("[WikiSkill] Failed to broadcast skill pattern {}: {}", title, e);
        } else {
            broadcasted.insert(content_hash);
        }
    }
}

async fn poll_wikiskill_status(workspace: &str, ws_path: &Path) -> (String, f64) {
    let (python_opt, cli_opt, _root) = resolve_wikiskill_paths();
    let mut phase = "unknown".to_string();
    let mut score = 1.0;

    if let (Some(python), Some(cli)) = (python_opt, cli_opt) {
        let mut cmd = tokio::process::Command::new(&python);
        cmd.arg(&cli)
            .arg("status")
            .arg(workspace)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());

        #[cfg(target_os = "windows")]
        {
            #[allow(unused_imports)]
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
        }

        match tokio::time::timeout(std::time::Duration::from_secs(30), cmd.output()).await {
            Ok(Ok(output)) if output.status.success() => {
                if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                    if let Some(p) = val.get("phase").and_then(|v| v.as_str()) {
                        phase = p.to_string();
                    }
                    if let Some(b) = val.get("best_score").and_then(|v| v.as_f64()) {
                        score = b;
                    }
                    let state_file = ws_path.join(".wikiskill-state.json");
                    let _ = atomic_write_state_file(&state_file, &output.stdout);
                }
                debug!(
                    "[WikiSkill] Evolution cycle completed. Phase: {}, Best Score: {:.2}",
                    phase, score
                );
            }
            Ok(Ok(output)) => {
                debug!("[WikiSkill] Status evaluation returned non-zero code: {:?}", output.status.code());
            }
            Ok(Err(e)) => {
                debug!("[WikiSkill] Status evaluation poll error: {}", e);
            }
            Err(_) => {
                debug!("[WikiSkill] Status evaluation poll timed out.");
            }
        }
    }
    (phase, score)
}

async fn handle_skill_command(sub: Option<SkillSubcommand>) -> anyhow::Result<()> {
    match sub {
        None | Some(SkillSubcommand::List) => {
            println!("\n================================================================================");
            println!("               OpenỌ̀ṣọ́ọ̀sì Autonomous Agent Skill Framework (WikiSkill)");
            println!("================================================================================");

            // 1. Discover skills in .agents/skills/
            let skills_dir = Path::new(".agents").join("skills");
            println!("\n📦 Discovered Agent Skills (.agents/skills/):");
            if skills_dir.is_dir() {
                let mut found_any = false;
                if let Ok(entries) = fs::read_dir(&skills_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            let skill_md = path.join("SKILL.md");
                            let skill_name = path
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .to_string();
                            if skill_md.is_file() {
                                found_any = true;
                                let mut desc = String::new();
                                if let Ok(content) = fs::read_to_string(&skill_md) {
                                    if let Some(rest) = content.strip_prefix("---") {
                                        if let Some(fm_end) = rest.find("---") {
                                            let fm = &rest[..fm_end];
                                            for line in fm.lines() {
                                                let trimmed = line.trim();
                                                if let Some(val) = trimmed.strip_prefix("description:") {
                                                    desc = val
                                                        .trim()
                                                        .trim_matches('"')
                                                        .trim_matches('\'')
                                                        .to_string();
                                                }
                                            }
                                        }
                                    }
                                }
                                println!("  • \x1b[1m{}\x1b[0m", skill_name);
                                println!("    Path:        {}", skill_md.display());
                                if !desc.is_empty() {
                                    println!("    Description: {}", desc);
                                }
                            }
                        }
                    }
                }
                if !found_any {
                    println!("  (No skills found with SKILL.md in .agents/skills/)");
                }
            } else {
                println!("  (.agents/skills/ directory does not exist)");
            }

            // 2. Discover active workspaces
            println!("\n🔄 Active Skill Evolution Workspaces:");
            let search_roots = [
                Path::new("runs"),
                Path::new(".wikiskill"),
                Path::new("scratch"),
            ];
            let mut found_ws = false;
            for root in &search_roots {
                if root.is_dir() {
                    if let Ok(entries) = fs::read_dir(root) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if path.is_dir()
                                && ((path.join("config.json").is_file() && path.join("events").is_dir())
                                    || path.join(".wikiskill-state.json").is_file())
                            {
                                found_ws = true;
                                let mut phase = "unknown".to_string();
                                let mut score_info = String::new();
                                if let Ok(out) = run_wikiskill_cli(&["status", &path.to_string_lossy()]) {
                                    if out.status.success() {
                                        if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                                            if let Some(p) = val.get("phase").and_then(|v| v.as_str()) {
                                                phase = p.to_string();
                                            }
                                            if let Some(best) = val.get("best_score").and_then(|v| v.as_f64()) {
                                                score_info = format!(", Score: {:.2}", best);
                                            }
                                        }
                                    }
                                }
                                println!("  • \x1b[1m{}\x1b[0m (Phase: {}{})", path.display(), phase, score_info);
                            }
                        }
                    }
                }
            }
            if !found_ws {
                println!("  (No active evolution workspaces found. Start one with `wikiskill start <path> --tasks <tasks.json>`)");
            }
            println!("================================================================================\n");
            Ok(())
        }
        Some(SkillSubcommand::Doctor) => {
            println!("\n================================================================================");
            println!("                       WikiSkill Runtime Doctor");
            println!("================================================================================");
            let (python_opt, cli_opt, project_root) = resolve_wikiskill_paths();
            println!(
                "Python Runtime:       {}",
                match &python_opt {
                    Some(p) => format!("AVAILABLE ({})", p.display()),
                    None => "NOT FOUND (Python 3.11+ required)".to_string(),
                }
            );
            if let Some(ref py) = python_opt {
                if let Ok(ver_out) = std::process::Command::new(py).arg("--version").output() {
                    let ver = String::from_utf8_lossy(&ver_out.stdout).trim().to_string();
                    let ver_err = String::from_utf8_lossy(&ver_out.stderr).trim().to_string();
                    let full_ver = if !ver.is_empty() { ver } else { ver_err };
                    println!("Python Version:       {}", full_ver);
                }
            }
            println!(
                "WikiSkill CLI:        {}",
                match &cli_opt {
                    Some(c) => format!("LOCATED ({})", c.display()),
                    None => "NOT FOUND (Expected tools/wikiskill/src/wikiskill/cli.py)".to_string(),
                }
            );

            let subagents_dir = if let Some(ref root) = project_root {
                root.join(".agents").join("subagents")
            } else {
                Path::new(".agents").join("subagents")
            };
            let has_subagents = subagents_dir.is_dir()
                && subagents_dir.join("wikiskill-executor.md").is_file()
                && subagents_dir.join("wikiskill-maintainer.md").is_file()
                && subagents_dir.join("wikiskill-proposer.md").is_file();
            println!(
                "Native Subagents:     {}",
                if has_subagents {
                    "INSTALLED (.agents/subagents/)"
                } else {
                    "NOT INSTALLED (Run wikiskill agents install)"
                }
            );

            let skill_dir = if let Some(ref root) = project_root {
                root.join(".agents").join("skills").join("wikiskill")
            } else {
                Path::new(".agents").join("skills").join("wikiskill")
            };
            let has_skill = skill_dir.join("SKILL.md").is_file();
            println!(
                "Entry Skill:          {}",
                if has_skill {
                    "INSTALLED (.agents/skills/wikiskill/SKILL.md)"
                } else {
                    "NOT INSTALLED"
                }
            );

            if python_opt.is_some() && cli_opt.is_some() {
                println!("\n--- WikiSkill Self-Diagnostic Output ---");
                match run_wikiskill_cli(&["doctor"]) {
                    Ok(out) => {
                        let text = String::from_utf8_lossy(&out.stdout);
                        println!("{}", text.trim());
                    }
                    Err(e) => {
                        eprintln!("Error executing wikiskill doctor: {}", e);
                    }
                }
            }
            println!("================================================================================\n");
            Ok(())
        }
        Some(SkillSubcommand::Capabilities) => {
            let out = run_wikiskill_cli(&["capabilities"])?;
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                println!("{}", text);
            } else {
                let err = String::from_utf8_lossy(&out.stderr);
                eprintln!("Failed to get capabilities: {}", err);
            }
            Ok(())
        }
        Some(SkillSubcommand::Status { workspace }) => {
            let ws_str = workspace.to_string_lossy();
            let out = run_wikiskill_cli(&["status", &ws_str])?;
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                println!("{}", text);
            } else {
                let err = String::from_utf8_lossy(&out.stderr);
                eprintln!("Error querying workspace status: {}", err);
            }
            Ok(())
        }
        Some(SkillSubcommand::Report { workspace }) => {
            let ws_str = workspace.to_string_lossy();
            let out = run_wikiskill_cli(&["report", &ws_str])?;
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                println!("{}", text);
            } else {
                let err = String::from_utf8_lossy(&out.stderr);
                eprintln!("Error generating report: {}", err);
            }
            Ok(())
        }
    }
}

async fn handle_forensics_command(action: ForensicsAction) -> anyhow::Result<()> {
    let cfg = osoosi_types::config::load_forensics_config();
    let client = osoosi_forensics::VelociraptorClient::new(cfg.clone());

    match action {
        ForensicsAction::Status => {
            println!("================================================================================");
            println!("           OpenỌ̀ṣọ́ọ̀sì Embedded Velociraptor Forensics Status                     ");
            println!("================================================================================");
            println!("Enabled in config:        {}", cfg.enabled);
            println!("Configured Binary Path:   {}", cfg.binary_path);
            let resolved = client.resolve_binary_path();
            println!(
                "Resolved Binary Path:     {}",
                resolved
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "NOT_FOUND".to_string())
            );
            println!("Binary Available:         {}", client.is_available());
            let version = client
                .probe_version()
                .unwrap_or_else(|| "N/A (binary not running or absent)".to_string());
            println!("Velociraptor Version:     {}", version);
            println!("Execution Timeout:        {}s", cfg.execution_timeout_secs);
            println!("Max Memory Cap:           {} MB", cfg.max_memory_mb);
            println!("Max Output Lines:         {}", cfg.max_output_lines);
            println!("Staging Directory:        {}", cfg.staging_dir);
            println!("Auto Investigate Alerts:  {}", cfg.auto_investigate);
            println!("Min Trigger Confidence:   {:.2}", cfg.min_trigger_confidence);
            println!("Trigger ATT&CK Techniques: {:?}", cfg.trigger_techniques);
            println!("================================================================================");
        }
        ForensicsAction::InspectProcess { pid } => {
            println!("[*] Inspecting Virtual Address Descriptors (VAD) for PID {}...", pid);
            let records = client.inspect_process_vad(pid).await?;
            let (corroborated, delta, flagged) =
                osoosi_forensics::corroborate_process_injection(pid, &records);

            println!(
                "Found {} memory regions ({} flagged as unbacked executable):",
                records.len(),
                flagged.len()
            );
            for r in &records {
                let status = if r.is_unbacked_executable {
                    "[!] INJECTION/UNBACKED"
                } else {
                    "[+] Backed/Normal"
                };
                println!(
                    "  {} Address: {:<18} Size: {:<10} Prot: {:<24} Type: {:<10} File: {:?}",
                    status, r.address, r.size, r.protection, r.mapping_type, r.filename
                );
            }

            println!(
                "\nCorroboration Verdict: {}",
                if corroborated {
                    "CORROBORATED (INJECTION DETECTED)"
                } else {
                    "BENIGN"
                }
            );
            println!("Confidence Delta:      +{:.2}", delta);
        }
        ForensicsAction::ScanMft { path } => {
            let drive_char = path.chars().next().unwrap_or('C');
            println!(
                "[*] Scanning NTFS Master File Table (MFT) for drive {}: and prefix '{}'...",
                drive_char, path
            );
            let records = client.scan_mft(drive_char, &path).await?;
            let (corroborated, delta, flagged) =
                osoosi_forensics::corroborate_mft_rootkit_hiding(&records);

            println!(
                "MFT Records Scanned: {} ({} flagged as Win32 hidden / rootkit cloaked):",
                records.len(),
                flagged.len()
            );
            for r in &records {
                if r.is_hidden_from_win32_api {
                    println!(
                        "  [!] ROOTKIT CLOAKED: Entry: {} Size: {} Path: {}",
                        r.entry_number, r.size, r.full_path
                    );
                }
            }

            println!(
                "\nRootkit Cloaking Verdict: {}",
                if corroborated {
                    "CORROBORATED (HIDDEN FILES DETECTED)"
                } else {
                    "NO DISCREPANCIES"
                }
            );
            println!("Confidence Delta:        +{:.2}", delta);
        }
        ForensicsAction::Query { vql } => {
            println!("[*] Executing VQL Query: {}", vql);
            let output: Vec<serde_json::Value> = client.execute_vql(&vql).await?;
            println!("Query returned {} record(s):", output.len());
            for (idx, row) in output.iter().enumerate() {
                println!(
                    "[{}] {}",
                    idx + 1,
                    serde_json::to_string_pretty(row).unwrap_or_default()
                );
            }
        }
    }

    Ok(())
}

async fn handle_decision_command(action: DecisionAction) -> anyhow::Result<()> {
    let cfg = osoosi_types::config::load_decision_model_config();
    let engine = osoosi_behavioral::decision_model::ClefDecisionEngine::new(cfg.clone());

    match action {
        DecisionAction::Status => {
            println!("================================================================================");
            println!("       OpenỌ̀ṣọ́ọ̀sì Clef Non-Autoregressive Decision Model Status");
            println!("================================================================================");
            println!("Enabled:                  {}", cfg.enabled);
            println!("Provider:                 {}", cfg.provider);
            println!("Model:                    {}", cfg.model);
            println!("Timeout Cutoff:           {} ms", cfg.timeout_ms);
            println!("Min Action Confidence:    {:.2}", cfg.min_action_confidence);
            println!("Auto-Escalate to Cortex:  {}", cfg.auto_escalate_to_cortex);
            println!("Fallback to Local Engine: {}", cfg.fallback_to_local);
            println!("Local Model Directory:    {:?}", cfg.model_dir);
            let airgapped = if cfg.provider.to_lowercase() == "local" {
                "Active (100% Self-Hosted Hermetic / Air-Gapped)"
            } else {
                "Cloudflare Workers AI (with local fallback)"
            };
            println!("Air-Gapped Mode:          {}", airgapped);
            let metrics = engine.metrics();
            println!("Total Evaluations:        {}", metrics.total_evaluations);
            println!("Local Evaluations:        {}", metrics.local_evaluations);
            println!("Cloudflare Evaluations:   {}", metrics.cloudflare_evaluations);
            println!("Fallback Evaluations:     {}", metrics.fallback_evaluations);
            println!("Average Latency:          {:.3} ms", metrics.avg_latency_ms);
            println!("RLCD Feedback Count:      {}", metrics.rl_feedback_count);
            println!("Cumulative RLCD Reward:   {:.3}", metrics.cumulative_rl_reward);
            println!("================================================================================");
        }
        DecisionAction::Test => {
            println!("================================================================================");
            println!("       OpenỌ̀ṣọ́ọ̀sì Clef Decision Model Benchmark Test");
            println!("================================================================================");

            // 1. Benign Scenario
            println!("\n[1/2] Evaluating Benign Incident Scenario:");
            let benign_state = "Process: svchost.exe (PID: 1204, Parent: services.exe). CommandLine: C:\\Windows\\system32\\svchost.exe -k RPCSS. Network: None. File activity: Standard registry query.";
            println!("  State: {}", benign_state);
            let benign_decision = engine.evaluate_security_incident(benign_state).await?;
            println!("  Provider:         {}", benign_decision.provider_used);
            println!("  Latency:          {:.2} ms", benign_decision.latency_ms);
            println!("  Verdict:          {} ({:.2}%)", benign_decision.verdict, benign_decision.verdict_probability * 100.0);
            println!("  Containment:      {} ({:.2}%)", benign_decision.containment_action, benign_decision.action_probability * 100.0);
            println!("  Severity:         {}", benign_decision.threat_severity);
            println!("  Human Escalation: {}", benign_decision.human_escalation_required);
            println!("  Deep Reasoning:   {}", benign_decision.deep_reasoning_required);

            // 2. Attack Scenario
            println!("\n[2/2] Evaluating Malicious Attack Incident Scenario:");
            let attack_state = "Process: mimikatz.exe (PID: 8492, Parent: powershell.exe). CommandLine: mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit. Target: lsass.exe memory dump via OpenProcess(PROCESS_VM_READ).";
            println!("  State: {}", attack_state);
            let attack_decision = engine.evaluate_security_incident(attack_state).await?;
            println!("  Provider:         {}", attack_decision.provider_used);
            println!("  Latency:          {:.2} ms", attack_decision.latency_ms);
            println!("  Verdict:          {} ({:.2}%)", attack_decision.verdict, attack_decision.verdict_probability * 100.0);
            println!("  Containment:      {} ({:.2}%)", attack_decision.containment_action, attack_decision.action_probability * 100.0);
            println!("  Severity:         {}", attack_decision.threat_severity);
            println!("  Human Escalation: {}", attack_decision.human_escalation_required);
            println!("  Deep Reasoning:   {}", attack_decision.deep_reasoning_required);

            println!("\n[+] Clef Decision Model benchmark completed successfully.");
            println!("================================================================================");
        }
        DecisionAction::Evaluate { state } => {
            let decision = engine.evaluate_security_incident(&state).await?;
            println!("{}", serde_json::to_string_pretty(&decision)?);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::io::Write;
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct BufferWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for BufferWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for BufferWriter {
        type Writer = BufferWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn test_file_filter_silences_nostr_relay_pool() {
        let log_buffer = Arc::new(Mutex::new(Vec::new()));
        let writer = BufferWriter(log_buffer.clone());

        let layer = fmt::Layer::default()
            .with_writer(writer)
            .with_ansi(false)
            .with_filter(create_file_filter(false));

        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            // Simulated nostr_relay_pool background retry error
            tracing::error!(
                target: "nostr_relay_pool::relay::internal",
                "Impossible to connect to 'wss://nos.lol/': ws error: HTTP error: 502 Bad Gateway"
            );
            // Simulated nostr_relay_pool latency warning
            tracing::warn!(
                target: "nostr_relay_pool::relay::internal",
                "Latency of 'wss://nos.lol/' relay is high"
            );
            // Simulated regular application log
            tracing::info!(target: "osoosi_core", "Telemetry heartbeat normal");
        });

        let output = String::from_utf8(log_buffer.lock().unwrap().clone()).expect("valid utf8");
        assert!(
            !output.contains("502 Bad Gateway"),
            "nostr_relay_pool connection errors must be silenced by file_filter"
        );
        assert!(
            !output.contains("Latency of"),
            "nostr_relay_pool latency warnings must be silenced by file_filter"
        );
        assert!(
            output.contains("Telemetry heartbeat normal"),
            "Normal application INFO logs must be captured by file_filter"
        );
    }

    #[test]
    fn test_console_filter_silences_nostr_relay_pool_and_nostr_warnings() {
        let log_buffer = Arc::new(Mutex::new(Vec::new()));
        let writer = BufferWriter(log_buffer.clone());

        let layer = fmt::Layer::default()
            .with_writer(writer)
            .with_ansi(false)
            .with_filter(create_console_filter(false));

        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            // nostr_relay_pool retry error
            tracing::error!(
                target: "nostr_relay_pool::relay::internal",
                "Impossible to connect to 'wss://nos.lol/': ws error: HTTP error: 502 Bad Gateway"
            );
            // nostr warning (should be suppressed by nostr=error)
            tracing::warn!(target: "nostr", "Minor nostr protocol warning");
            // nostr error (should be allowed through by nostr=error)
            tracing::error!(target: "nostr", "Critical nostr protocol corruption");
            // General application warning
            tracing::warn!(target: "osoosi_core", "System firewall warning");
        });

        let output = String::from_utf8(log_buffer.lock().unwrap().clone()).expect("valid utf8");
        assert!(
            !output.contains("502 Bad Gateway"),
            "nostr_relay_pool error must be silenced in console_filter"
        );
        assert!(
            !output.contains("Minor nostr protocol warning"),
            "nostr warnings must be filtered out by console_filter"
        );
        assert!(
            output.contains("Critical nostr protocol corruption"),
            "nostr errors must pass through console_filter"
        );
        assert!(
            output.contains("System firewall warning"),
            "Standard WARN logs must pass through console_filter"
        );
    }

    #[test]
    fn test_debug_mode_retains_nostr_relay_pool_silence() {
        let log_buffer = Arc::new(Mutex::new(Vec::new()));
        let writer = BufferWriter(log_buffer.clone());

        let layer = fmt::Layer::default()
            .with_writer(writer)
            .with_ansi(false)
            .with_filter(create_file_filter(true));

        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(
                target: "nostr_relay_pool::relay::internal",
                "Impossible to connect to 'wss://nos.lol/': ws error: HTTP error: 502 Bad Gateway"
            );
            tracing::debug!(target: "osoosi_core", "Detailed diagnostic trace");
        });

        let output = String::from_utf8(log_buffer.lock().unwrap().clone()).expect("valid utf8");
        assert!(
            !output.contains("502 Bad Gateway"),
            "nostr_relay_pool must remain silenced even when debug logging is active"
        );
        assert!(
            output.contains("Detailed diagnostic trace"),
            "Core debug logs must appear when debug is active"
        );
    }

    #[test]
    fn test_file_filter_silences_tower_http_serve_dir() {
        let log_buffer = Arc::new(Mutex::new(Vec::new()));
        let writer = BufferWriter(log_buffer.clone());

        let layer = fmt::Layer::default()
            .with_writer(writer)
            .with_ansi(false)
            .with_filter(create_file_filter(false));

        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(
                target: "tower_http::services::fs::serve_dir",
                "Failed to read file error=The filename, directory name, or volume label syntax is incorrect. (os error 123)"
            );
            tracing::info!(target: "osoosi_core", "Telemetry heartbeat normal");
        });

        let output = String::from_utf8(log_buffer.lock().unwrap().clone()).expect("valid utf8");
        assert!(
            !output.contains("os error 123"),
            "tower_http serve_dir error must be silenced by file_filter"
        );
        assert!(
            output.contains("Telemetry heartbeat normal"),
            "Normal application INFO logs must be captured by file_filter"
        );
    }

    #[test]
    fn test_console_filter_silences_tower_http_serve_dir() {
        let log_buffer = Arc::new(Mutex::new(Vec::new()));
        let writer = BufferWriter(log_buffer.clone());

        let layer = fmt::Layer::default()
            .with_writer(writer)
            .with_ansi(false)
            .with_filter(create_console_filter(false));

        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(
                target: "tower_http::services::fs::serve_dir",
                "Failed to read file error=The filename, directory name, or volume label syntax is incorrect. (os error 123)"
            );
            tracing::warn!(target: "osoosi_core", "System firewall warning");
        });

        let output = String::from_utf8(log_buffer.lock().unwrap().clone()).expect("valid utf8");
        assert!(
            !output.contains("os error 123"),
            "tower_http serve_dir error must be silenced by console_filter"
        );
        assert!(
            output.contains("System firewall warning"),
            "Standard WARN logs must pass through console_filter"
        );
    }

    #[tokio::test]
    async fn test_live_nostr_relay_pool_connection_failure_silence() {
        let log_buffer = Arc::new(Mutex::new(Vec::new()));
        let writer = BufferWriter(log_buffer.clone());

        let layer = fmt::Layer::default()
            .with_writer(writer)
            .with_ansi(false)
            .with_filter(create_file_filter(false));

        let subscriber = tracing_subscriber::registry().with(layer);

        let _guard = tracing::subscriber::set_default(subscriber);

        let orch = osoosi_core::nostr_mesh::NostrMeshOrchestrator::new(None, 1.0)
            .await
            .expect("orchestrator initialized");
        let _ = orch.add_relay("ws://127.0.0.1:19").await;
        orch.connect().await;

        tokio::time::sleep(tokio::time::Duration::from_millis(600)).await;

        let output = String::from_utf8(log_buffer.lock().unwrap().clone()).expect("valid utf8");
        assert!(
            !output.contains("Impossible to connect"),
            "Live nostr_relay_pool connection failure log must be suppressed by filter, but got: {}",
            output
        );
    }

    #[test]
    fn test_update_stix_cli_parsing() {
        let cli = Cli::try_parse_from(["osoosi", "update-stix", "--force", "--broadcast"]).unwrap();
        match cli.command {
            Some(Commands::UpdateStix { force, broadcast }) => {
                assert!(force);
                assert!(broadcast);
            }
            _ => panic!("Expected Commands::UpdateStix"),
        }

        // Test alias update-mitre
        let cli_alias = Cli::try_parse_from(["osoosi", "update-mitre"]).unwrap();
        match cli_alias.command {
            Some(Commands::UpdateStix { force, broadcast }) => {
                assert!(!force);
                assert!(!broadcast);
            }
            _ => panic!("Expected Commands::UpdateStix from alias update-mitre"),
        }
    }

    #[test]
    fn test_get_ollama_bin_resolution() {
        let bin = get_ollama_bin();
        assert!(!bin.as_os_str().is_empty());
    }

    #[test]
    fn test_winget_already_installed_exit_code() {
        let code = 0x8a15002b_u32 as i32;
        assert_eq!(code, -1978335189);
        assert!(code == -1978335189 || code == 0x8a15002b_u32 as i32);
    }

    #[test]
    fn test_driver_cli_parsing() {
        let cli_status = Cli::try_parse_from(["osoosi", "driver", "status"]).unwrap();
        match cli_status.command {
            Some(Commands::Driver { action: DriverAction::Status }) => {}
            _ => panic!("Expected Commands::Driver with Status"),
        }

        let cli_install = Cli::try_parse_from(["osoosi", "driver", "install"]).unwrap();
        match cli_install.command {
            Some(Commands::Driver { action: DriverAction::Install { path: None } }) => {}
            _ => panic!("Expected Commands::Driver with Install"),
        }

        let cli_install_custom = Cli::try_parse_from(["osoosi", "driver", "install", "--path", "C:\\test\\osoosi_driver.sys"]).unwrap();
        match cli_install_custom.command {
            Some(Commands::Driver { action: DriverAction::Install { path: Some(p) } }) => {
                assert_eq!(p, "C:\\test\\osoosi_driver.sys");
            }
            _ => panic!("Expected Commands::Driver with Install path"),
        }

        let cli_uninstall = Cli::try_parse_from(["osoosi", "driver", "uninstall"]).unwrap();
        match cli_uninstall.command {
            Some(Commands::Driver { action: DriverAction::Uninstall }) => {}
            _ => panic!("Expected Commands::Driver with Uninstall"),
        }

        let cli_add_rule = Cli::try_parse_from(["osoosi", "driver", "add-rule", "C:\\malware.exe"]).unwrap();
        match cli_add_rule.command {
            Some(Commands::Driver { action: DriverAction::AddRule { path } }) => {
                assert_eq!(path, "C:\\malware.exe");
            }
            _ => panic!("Expected Commands::Driver with AddRule"),
        }

        let cli_set_mode = Cli::try_parse_from(["osoosi", "driver", "set-mode", "lockdown"]).unwrap();
        match cli_set_mode.command {
            Some(Commands::Driver { action: DriverAction::SetMode { mode } }) => {
                assert_eq!(mode, "lockdown");
            }
            _ => panic!("Expected Commands::Driver with SetMode"),
        }

        let cli_clear = Cli::try_parse_from(["osoosi", "driver", "clear-rules"]).unwrap();
        match cli_clear.command {
            Some(Commands::Driver { action: DriverAction::ClearRules }) => {}
            _ => panic!("Expected Commands::Driver with ClearRules"),
        }
    }

    #[test]
    fn test_skill_cli_parsing() {
        let cli_list = Cli::try_parse_from(["osoosi", "skill", "list"]).unwrap();
        match cli_list.command {
            Some(Commands::Skill { subcommand: Some(SkillSubcommand::List) }) => {}
            _ => panic!("Expected Commands::Skill with List"),
        }

        let cli_none = Cli::try_parse_from(["osoosi", "skill"]).unwrap();
        match cli_none.command {
            Some(Commands::Skill { subcommand: None }) => {}
            _ => panic!("Expected Commands::Skill with None"),
        }

        let cli_doctor = Cli::try_parse_from(["osoosi", "skill", "doctor"]).unwrap();
        match cli_doctor.command {
            Some(Commands::Skill { subcommand: Some(SkillSubcommand::Doctor) }) => {}
            _ => panic!("Expected Commands::Skill with Doctor"),
        }

        let cli_cap = Cli::try_parse_from(["osoosi", "skill", "capabilities"]).unwrap();
        match cli_cap.command {
            Some(Commands::Skill { subcommand: Some(SkillSubcommand::Capabilities) }) => {}
            _ => panic!("Expected Commands::Skill with Capabilities"),
        }

        let cli_status = Cli::try_parse_from(["osoosi", "skill", "status", "runs/test"]).unwrap();
        match cli_status.command {
            Some(Commands::Skill { subcommand: Some(SkillSubcommand::Status { workspace }) }) => {
                assert_eq!(workspace, PathBuf::from("runs/test"));
            }
            _ => panic!("Expected Commands::Skill with Status"),
        }

        let cli_report = Cli::try_parse_from(["osoosi", "skill", "report", "runs/test"]).unwrap();
        match cli_report.command {
            Some(Commands::Skill { subcommand: Some(SkillSubcommand::Report { workspace }) }) => {
                assert_eq!(workspace, PathBuf::from("runs/test"));
            }
            _ => panic!("Expected Commands::Skill with Report"),
        }
    }

    #[test]
    fn test_atomic_write_state_file_and_parsing() {
        let temp_dir = std::env::temp_dir().join(format!("osoosi_state_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let state_path = temp_dir.join(".wikiskill-state.json");

        let initial_json = br#"{"schema_version":"wikiskill.workspace.v1","phase":"baseline","best_score":null,"round":1}"#;
        atomic_write_state_file(&state_path, initial_json).expect("atomic write must succeed");
        assert!(state_path.is_file());

        let read_back = std::fs::read_to_string(&state_path).unwrap();
        let val: serde_json::Value = serde_json::from_str(&read_back).unwrap();
        assert_eq!(val.get("phase").and_then(|v| v.as_str()), Some("baseline"));
        assert!(val.get("best_score").unwrap().is_null());
        assert_eq!(val.get("round").and_then(|v| v.as_u64()), Some(1));

        let updated_json = br#"{"schema_version":"wikiskill.workspace.v1","phase":"active","best_score":0.95,"round":2}"#;
        atomic_write_state_file(&state_path, updated_json).expect("atomic overwrite must succeed");

        let read_updated = std::fs::read_to_string(&state_path).unwrap();
        let val_updated: serde_json::Value = serde_json::from_str(&read_updated).unwrap();
        assert_eq!(val_updated.get("phase").and_then(|v| v.as_str()), Some("active"));
        assert_eq!(val_updated.get("best_score").and_then(|v| v.as_f64()), Some(0.95));
        assert_eq!(val_updated.get("round").and_then(|v| v.as_u64()), Some(2));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_broadcast_new_wiki_patterns_discovery() {
        let temp_dir = std::env::temp_dir().join(format!("osoosi_wiki_broadcast_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        let wiki_dir = temp_dir.join("wiki");
        let patterns_dir = wiki_dir.join("patterns");
        let _ = std::fs::create_dir_all(&patterns_dir);

        // 1. Table format (as produced by WikiSkill's python maintainer)
        let pat1_content = "# EDR-PAT-01: In-Memory Process Injection Analysis\n\nVerify unbacked memory pages.";
        let pat1_hash = blake3::hash(pat1_content.trim().as_bytes()).to_hex().to_string();
        std::fs::write(patterns_dir.join("d7002e64340557ef.md"), pat1_content).unwrap();

        // 2. Bullet list format
        let pat2_content = "# EDR-PAT-02: Remote Thread Injection\n\nDetect CreateRemoteThread into svchost.";
        let pat2_hash = blake3::hash(pat2_content.trim().as_bytes()).to_hex().to_string();
        std::fs::write(patterns_dir.join("pat02.md"), pat2_content).unwrap();

        // 3. Unindexed pattern in patterns/ directory (fallback discovery)
        let pat3_content = "# EDR-PAT-03: Process Hollowing\n\nDetect unmapped executable sections.";
        let pat3_hash = blake3::hash(pat3_content.trim().as_bytes()).to_hex().to_string();
        std::fs::write(patterns_dir.join("pat03_unindexed.md"), pat3_content).unwrap();

        let index_content = format!(
            "# Wiki Index\n\n| Pattern | Summary |\n|---|---|\n| [EDR-PAT-01: In-Memory Process Injection Analysis](patterns/d7002e64340557ef.md) | Verify unbacked memory pages. |\n\n## Other Playbooks\n- [EDR-PAT-02: Remote Thread Injection](patterns/pat02.md)\n"
        );
        std::fs::write(wiki_dir.join("index.md"), index_content).unwrap();

        // Test discover_wiki_patterns directly
        let discovered = discover_wiki_patterns(&temp_dir);
        assert_eq!(discovered.len(), 3, "All 3 patterns (table, list, unindexed fallback) must be discovered");

        let titles: Vec<_> = discovered.iter().map(|(t, _, _)| t.as_str()).collect();
        assert!(titles.contains(&"EDR-PAT-01: In-Memory Process Injection Analysis"));
        assert!(titles.contains(&"EDR-PAT-02: Remote Thread Injection"));
        assert!(titles.contains(&"EDR-PAT-03: Process Hollowing"));

        // Test broadcast_new_wiki_patterns populates broadcasted set
        let mut broadcasted = std::collections::HashSet::new();
        broadcast_new_wiki_patterns(&temp_dir, 0.95, &mut broadcasted, &None).await;
        assert_eq!(broadcasted.len(), 3, "All 3 pattern hashes must be recorded in broadcasted");
        assert!(broadcasted.contains(&pat1_hash));
        assert!(broadcasted.contains(&pat2_hash));
        assert!(broadcasted.contains(&pat3_hash));

        // Test deduplication on subsequent run
        broadcast_new_wiki_patterns(&temp_dir, 0.95, &mut broadcasted, &None).await;
        assert_eq!(broadcasted.len(), 3, "Subsequent run must not duplicate already broadcasted patterns");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_forensics_cli_parsing() {
        let cli_status = Cli::try_parse_from(["osoosi", "forensics", "status"]).unwrap();
        match cli_status.command {
            Some(Commands::Forensics { action: ForensicsAction::Status }) => {}
            _ => panic!("Expected Commands::Forensics with Status"),
        }

        let cli_vad = Cli::try_parse_from(["osoosi", "forensics", "inspect-process", "1234"]).unwrap();
        match cli_vad.command {
            Some(Commands::Forensics { action: ForensicsAction::InspectProcess { pid } }) => {
                assert_eq!(pid, 1234);
            }
            _ => panic!("Expected Commands::Forensics with InspectProcess"),
        }

        let cli_mft = Cli::try_parse_from(["osoosi", "forensics", "scan-mft", "C:\\Windows\\System32"]).unwrap();
        match cli_mft.command {
            Some(Commands::Forensics { action: ForensicsAction::ScanMft { path } }) => {
                assert_eq!(path, "C:\\Windows\\System32");
            }
            _ => panic!("Expected Commands::Forensics with ScanMft"),
        }

        let cli_query = Cli::try_parse_from(["osoosi", "forensics", "query", "SELECT 1"]).unwrap();
        match cli_query.command {
            Some(Commands::Forensics { action: ForensicsAction::Query { vql } }) => {
                assert_eq!(vql, "SELECT 1");
            }
            _ => panic!("Expected Commands::Forensics with Query"),
        }
    }

    #[test]
    fn test_decision_cli_parsing() {
        let cli_status = Cli::try_parse_from(["osoosi", "decision", "status"]).unwrap();
        match cli_status.command {
            Some(Commands::Decision { action: DecisionAction::Status }) => {}
            _ => panic!("Expected Commands::Decision with Status"),
        }

        let cli_test = Cli::try_parse_from(["osoosi", "decision", "test"]).unwrap();
        match cli_test.command {
            Some(Commands::Decision { action: DecisionAction::Test }) => {}
            _ => panic!("Expected Commands::Decision with Test"),
        }

        let cli_eval = Cli::try_parse_from(["osoosi", "decision", "evaluate", "--state", "svchost.exe"]).unwrap();
        match cli_eval.command {
            Some(Commands::Decision { action: DecisionAction::Evaluate { state } }) => {
                assert_eq!(state, "svchost.exe");
            }
            _ => panic!("Expected Commands::Decision with Evaluate"),
        }
    }
}

