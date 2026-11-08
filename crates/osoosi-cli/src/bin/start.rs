//! # `start.exe` - Unified Launcher for OpenỌ̀ṣọ́ọ̀sì Autonomous EDR
//!
//! Enforces launcher browser behavior:
//! - Auto-opens browser to `http://127.0.0.1:3030` by default.
//! - Can be suppressed via `--no-browser` or `--daemon`.
//! - Supports `--service <ACTION>` and subcommand `service <action>`:
//!   `install`, `delete`, `uninstall`, `start`, `stop`, `restart`, `status`, `run`.
//! - Supports `--verify` / `--check` for subsystem self-diagnostics.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser, Debug)]
#[command(name = "start")]
#[command(version)]
#[command(about = "Unified Launcher for OpenỌ̀ṣọ́ọ̀sì Autonomous EDR", long_about = None)]
struct StartCli {
    /// Execute subsystem in-memory self-diagnostics and exit 0
    #[arg(long, alias = "check")]
    verify: bool,

    /// Bind host for local HTTP control server
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    host: String,

    /// Bind port for local HTTP control server
    #[arg(short = 'p', long, default_value_t = 3030)]
    port: u16,

    /// Run in LITE mode: skip massive reasoning models & external browser
    #[arg(long)]
    lite: bool,

    /// Run as native OS background service daemon
    #[arg(long)]
    daemon: bool,

    /// Do not launch web browser on start
    #[arg(long = "no-browser", alias = "nobrowser")]
    no_browser: bool,

    /// Manage native OS background service (install, delete, uninstall, start, stop, restart, status, run)
    #[arg(long, value_name = "ACTION")]
    service: Option<String>,

    /// Internal elevated helper flag for Windows Filtering Platform (WFP) kernel delegation
    #[arg(long, hide = true)]
    wfp_kernel_apply: Option<String>,

    /// Internal marker set after startup UAC elevation relaunch
    #[arg(long, hide = true)]
    elevated_relaunch: bool,

    #[command(subcommand)]
    command: Option<StartSubcommands>,
}

#[derive(Subcommand, Debug)]
enum StartSubcommands {
    /// Manage native OS background service
    Service {
        #[arg(default_value = "status")]
        action: String,
    },
}

fn resolve_osoosi_binary() -> PathBuf {
    if let Ok(cur_exe) = std::env::current_exe() {
        if let Some(parent) = cur_exe.parent() {
            let candidate_exe = parent.join(if cfg!(windows) {
                "osoosi.exe"
            } else {
                "osoosi"
            });
            if candidate_exe.exists() {
                return candidate_exe;
            }
            // Check target/release or target/debug
            for profile in &["release", "debug"] {
                let candidate = parent.join(format!("../target/{}/osoosi.exe", profile));
                if candidate.exists() {
                    return candidate;
                }
            }
        }
    }
    PathBuf::from(if cfg!(windows) {
        "osoosi.exe"
    } else {
        "osoosi"
    })
}

fn run_subsystem_verification() {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!(
                "❌ Failed to initialize async runtime for verification: {}",
                e
            );
            std::process::exit(1);
        }
    };
    match rt.block_on(osoosi_cli::verify::SubsystemVerifier::run_all()) {
        Ok(report) => {
            report.print_summary();
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("❌ Subsystem verification failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = StartCli::parse();

    if cli.verify {
        run_subsystem_verification();
    }

    let osoosi_bin = resolve_osoosi_binary();

    // Check service actions
    if let Some(ref action) = cli.service {
        let mut cmd = Command::new(&osoosi_bin);
        cmd.args(["--service", action]);
        let status = cmd.status()?;
        std::process::exit(status.code().unwrap_or(1));
    }

    if let Some(StartSubcommands::Service { ref action }) = cli.command {
        let mut cmd = Command::new(&osoosi_bin);
        cmd.args(["--service", action]);
        let status = cmd.status()?;
        std::process::exit(status.code().unwrap_or(1));
    }

    // Default start behavior: auto-open browser unless --no-browser or --daemon is passed
    let auto_open_browser = !cli.no_browser && !cli.daemon;

    let mut args: Vec<String> = vec!["start".to_string()];
    if auto_open_browser {
        args.push("--open-browser".to_string());
    } else {
        args.push("--no-browser".to_string());
    }

    if cli.daemon {
        args.push("--detach".to_string());
    }

    if cli.lite {
        args.push("--lite".to_string());
    }

    let mut cmd = Command::new(&osoosi_bin);
    cmd.args(&args);
    cmd.env("OSOOSI_DASHBOARD_PORT", cli.port.to_string());

    let status = cmd.status()?;
    std::process::exit(status.code().unwrap_or(0));
}
