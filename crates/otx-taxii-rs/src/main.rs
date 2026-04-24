use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use otx_taxii::*;
use reqwest::blocking::Client;
use std::env;
use rusqlite::{params, Connection};

#[derive(Parser)]
#[command(name = "otx-taxii-rs")]
#[command(about = "Rust OTX TAXII 1.1 indicator collector")]
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let api_key = env::var("OTX_API_KEY")
        .expect("Missing OTX_API_KEY environment variable.");

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
            params![
                ind.indicator_type,
                ind.value,
                ind.source,
                now,
                now,
            ],
        )?;
    }

    Ok(())
}
