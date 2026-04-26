use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use otx_taxii::*;
use reqwest::blocking::Client;
use rusqlite::{params, Connection};
use std::env::{self, VarError};

#[derive(Parser)]
#[command(name = "otx-taxii-rs")]
#[command(about = "Rust OTX TAXII 1.1 indicator collector")]
#[command(
    after_help = "Environment:\n  OTX_TAXII_KEY_ENV  Optional. If set, only the variable *named by this value* is read. If it is set but wrong, OTX_API_KEY will NOT be used — unset it.\n  Default search: OTX_API_KEY, OTX_KEY, ALIENVAULT_OTX_API_KEY, X_OTX_API_KEY (first non-empty).\n  OTX_TAXII_DEBUG_ENV=1  Print what this process sees (variable names and value lengths, never the secret).\n  TAXII: Basic auth, username = API key, password = any (this tool uses \"foo\").\n  Open a new terminal after changing user/system env; Explorer may not inherit user env when double-clicking .exe."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Discovery,
    Collections,
    Poll {
        #[arg(short, long)]
        collection: String,
        #[arg(short, long, default_value = "24")]
        hours: i64,
        #[arg(short, long, default_value = "otx_indicators.db")]
        db: String,
    },
}

/// Default names to try, in order.
const OTX_KEY_ENV_NAMES: &[&str] = &[
    "OTX_API_KEY",
    "OTX_KEY",
    "ALIENVAULT_OTX_API_KEY",
    "X_OTX_API_KEY",
];

/// If `OTX_TAXII_KEY_ENV` is set, only that name is used (so your key can live in any single OS variable).
const OTX_KEY_ENV_POINTER: &str = "OTX_TAXII_KEY_ENV";

/// Set to `1` or `true` to print which variables this process sees (names + lengths only, never the secret).
const OTX_TAXII_DEBUG_ENV: &str = "OTX_TAXII_DEBUG_ENV";

/// Trim and strip a leading UTF-8 BOM (common when the value is pasted on Windows).
fn normalize_key_value(s: &str) -> &str {
    s.trim().trim_start_matches('\u{feff}')
}

fn describe_env_var(name: &str) -> String {
    match env::var(name) {
        Ok(s) if normalize_key_value(&s).is_empty() => "present but empty after trim".to_string(),
        Ok(s) => format!(
            "present, value length {} bytes (after trim/BOM strip)",
            normalize_key_value(&s).len()
        ),
        Err(VarError::NotPresent) => "not visible to this process".to_string(),
        Err(VarError::NotUnicode(_)) => {
            "present but not valid UTF-8 (re-paste the key as plain text)".to_string()
        }
    }
}

fn maybe_print_env_debug() {
    let on = match env::var(OTX_TAXII_DEBUG_ENV) {
        Ok(s) => {
            let t = s.trim();
            t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
        }
        Err(_) => false,
    };
    if !on {
        return;
    }
    eprintln!("otx-taxii-rs: {OTX_TAXII_DEBUG_ENV} is on (secret values are never printed):");
    if let Ok(p) = env::var(OTX_KEY_ENV_POINTER) {
        let p = p.trim();
        if p.is_empty() {
            eprintln!("  {OTX_KEY_ENV_POINTER}: set but empty (ignored, using default name list)");
        } else {
            eprintln!(
                "  {OTX_KEY_ENV_POINTER} points to {p:?} -> {}",
                describe_env_var(p)
            );
        }
    } else {
        eprintln!("  {OTX_KEY_ENV_POINTER}: not set");
    }
    for name in OTX_KEY_ENV_NAMES {
        eprintln!("  {name} -> {}", describe_env_var(name));
    }
    eprintln!("  (If System/user env was changed, start a *new* terminal, or run from the same session where you set the variable.)");
}

fn resolve_otx_api_key() -> Result<String, String> {
    if let Ok(override_raw) = env::var(OTX_KEY_ENV_POINTER) {
        let target = override_raw.trim();
        if !target.is_empty() {
            // Pointer mode: only this variable is read. Do not fall back to OTX_API_KEY, etc.
            match env::var(target) {
                Ok(v) => {
                    let n = normalize_key_value(&v);
                    if n.is_empty() {
                        return Err(format!(
                            "{OTX_KEY_ENV_POINTER} is set, so only `{target}` is read, but that value is empty after trim. \
                             Set the key in `{target}` or unset {OTX_KEY_ENV_POINTER} to use OTX_API_KEY / OTX_KEY / ALIENVAULT_OTX_API_KEY."
                        ));
                    }
                    return Ok(n.to_string());
                }
                Err(VarError::NotPresent) => {
                    return Err(format!(
                        "{OTX_KEY_ENV_POINTER} is set to `{target}`, but that variable is not set in *this* process. \
                         Fix the name, set `{target}` in this session, or unset {OTX_KEY_ENV_POINTER} so the default names are tried."
                    ));
                }
                Err(VarError::NotUnicode(_)) => {
                    return Err(format!(
                        "variable `{target}` (from {OTX_KEY_ENV_POINTER}) is not valid UTF-8"
                    ));
                }
            }
        }
    }

    for name in OTX_KEY_ENV_NAMES {
        match env::var(name) {
            Ok(v) => {
                let n = normalize_key_value(&v);
                if !n.is_empty() {
                    return Ok(n.to_string());
                }
            }
            Err(VarError::NotUnicode(_)) => {
                return Err(format!("{name} is set but the value is not valid UTF-8"));
            }
            Err(VarError::NotPresent) => {}
        }
    }

    Err("no OTX API key in any of the default variables".to_string())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    maybe_print_env_debug();
    let api_key = match resolve_otx_api_key() {
        Ok(k) => {
            if let Ok(s) = env::var(OTX_TAXII_DEBUG_ENV) {
                let t = s.trim();
                if t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes") {
                    eprintln!("otx-taxii-rs: using API key length {} bytes", k.len());
                }
            }
            k
        }
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!(
                "Expected one of: {} (or set {} to the *name* of the variable that holds the key).",
                OTX_KEY_ENV_NAMES.join(", "),
                OTX_KEY_ENV_POINTER
            );
            eprintln!(
                "Re-run with {}=1 to see what this process can see (lengths only).",
                OTX_TAXII_DEBUG_ENV
            );
            eprintln!(
                r#"  PowerShell: $env:OTX_API_KEY = "your-key"; $env:OTX_TAXII_DEBUG_ENV = "1"; .\otx-taxii-rs discovery"#
            );
            eprintln!("Get a key: https://otx.alienvault.com/ → Account settings → API Key.");
            std::process::exit(1);
        }
    };

    let client = Client::builder().build()?;

    match cli.command {
        Commands::Discovery => {
            let body = discovery_request();
            let response = post_taxii(&client, OTX_DISCOVERY_URL, &api_key, &body)?;
            println!("{response}");
        }
        Commands::Collections => {
            let body = collections_request();
            let response = post_taxii(&client, OTX_COLLECTIONS_URL, &api_key, &body)?;
            println!("{response}");
        }
        Commands::Poll {
            collection,
            hours,
            db,
        } => {
            let begin = Utc::now() - Duration::hours(hours);
            let body = poll_request(&collection, begin);
            let response = post_taxii(&client, OTX_POLL_URL, &api_key, &body)?;
            let indicators = extract_indicators(&response);

            save_sqlite(&db, &indicators)?;

            println!(
                "Saved {} indicators to SQLite database: {}",
                indicators.len(),
                db
            );
        }
    }

    Ok(())
}

fn save_sqlite(path: &str, indicators: &[Indicator]) -> Result<(), Box<dyn std::error::Error>> {
    let conn = Connection::open(path)?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator_type TEXT NOT NULL,
            value TEXT NOT NULL,
            source TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(indicator_type, value, source)
        )",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_indicator_lookup ON indicators(indicator_type, value)",
        [],
    )?;

    for ind in indicators {
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO indicators (indicator_type, value, source, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(indicator_type, value, source) DO UPDATE SET last_seen = ?5",
            params![ind.indicator_type, ind.value, ind.source, now, now,],
        )?;
    }

    Ok(())
}
