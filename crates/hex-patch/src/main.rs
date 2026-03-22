//! Autonomous hex-patch: cross-OS binary patching with script or dynamic find-replace.
//!
//! Usage:
//!   hex-patch --script patch_logic.rhai target_binary.exe
//!   hex-patch --find-hex "74 0E" --replace-hex "EB 0E" target_binary.exe
//!
//! Install: cargo install --path crates/hex-patch

use clap::Parser;
use std::path::Path;

#[derive(Parser)]
#[command(name = "hex-patch")]
#[command(about = "Cross-OS hex patching with script or dynamic find-replace", long_about = None)]
struct Cli {
    /// Script defining patch logic (patches() or apply())
    #[arg(short, long)]
    script: Option<String>,
    /// Hex pattern to find (dynamic patch; use with --replace-hex)
    #[arg(long)]
    find_hex: Option<String>,
    /// Hex bytes to replace with (dynamic patch; use with --find-hex)
    #[arg(long)]
    replace_hex: Option<String>,
    /// Target binary to patch
    target: String,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let target_path = Path::new(&cli.target);

    if !target_path.exists() {
        anyhow::bail!("Target binary not found: {}", target_path.display());
    }

    // DO NOT use hex patch for system files (User request)
    if osoosi_types::is_system_path(&cli.target) {
        anyhow::bail!("Hex-patch REJECTED for system file: {} (User policy: no hex patches for system files)", cli.target);
    }

    if let (Some(ref fh), Some(ref rh)) = (&cli.find_hex, &cli.replace_hex) {
        if !fh.is_empty() && !rh.is_empty() {
            osoosi_hexpatch::hex_patch_find_replace(target_path, fh, rh)?;
            println!("Patched {} (dynamic find-replace).", target_path.display());
            return Ok(());
        }
    }

    if let Some(ref script_path) = cli.script {
        let script = Path::new(script_path);
        if script.exists() {
            osoosi_hexpatch::hex_patch(script, target_path)?;
            println!("Patched {} successfully.", target_path.display());
            return Ok(());
        }
        anyhow::bail!("Script not found: {}", script.display());
    }

    anyhow::bail!("Provide either --script <path> or --find-hex and --replace-hex");
}
