//! Standalone Port 3030 Live Daemon Integration Test Harness
//! Spawns genuine OshoosiClaw dashboard on port 3030 for adversarial and CI integration testing.

use osoosi_dashboard::spawn_dashboard_with_backend;
use std::time::Duration;

#[tokio::test]
async fn run_live_port_3030_daemon() {
    let port: u16 = std::env::var("OSOOSI_DASHBOARD_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3030);

    println!("[*] Spawning live production dashboard on port {}...", port);
    let bound = match spawn_dashboard_with_backend(port, None, None).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "[!] Failed to bind port {}: {}. Trying ephemeral port...",
                port, e
            );
            spawn_dashboard_with_backend(0, None, None)
                .await
                .expect("Failed to bind ephemeral dashboard port")
        }
    };

    println!("[+] OSHOOSI_DASHBOARD_READY_PORT={}", bound);

    // Keep running for up to 600 seconds when invoked as a standalone daemon harness
    // (--nocapture / explicit test filter / OSOOSI_DASHBOARD_PORT), or 1 second during
    // normal `cargo test --workspace` execution.
    let default_duration = if std::env::args()
        .any(|a| a == "--nocapture" || a == "run_live_port_3030_daemon")
        || std::env::var("OSOOSI_DASHBOARD_PORT").is_ok()
        || std::env::var("OSOOSI_DASHBOARD_BIND_ALL").is_ok()
    {
        600
    } else {
        1
    };
    let duration_secs: u64 = std::env::var("OSOOSI_DAEMON_DURATION_SECS")
        .ok()
        .and_then(|d| d.parse().ok())
        .unwrap_or(default_duration);

    tokio::time::sleep(Duration::from_secs(duration_secs)).await;
    println!(
        "[*] Live dashboard test harness finished after {}s.",
        duration_secs
    );
}
