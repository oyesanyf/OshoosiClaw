//! Sleeper Traps (Deceptive Services).
//!
//! Spawns fake listeners to detect and capture unauthorized scans/exploits.

use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn, error};

pub struct SleeperManager;

impl Default for SleeperManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SleeperManager {
    pub fn new() -> Self {
        Self
    }

    /// Spawn a fake service on a given port.
    pub async fn spawn_trap(&self, port: u16, service_name: &str) -> anyhow::Result<()> {
        let addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&addr).await?;
        
        info!("Sleeper Trap active: {} on port {}", service_name, port);
        
        let service_name = service_name.to_string();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut socket, peer)) => {
                        warn!("ALARM: Connection to Sleeper Trap {} from {}", service_name, peer);
                        
                        // Capturing the interaction (Deceptive payload)
                        let mut buf = [0u8; 1024];
                        match socket.read(&mut buf).await {
                            Ok(n) if n > 0 => {
                                let payload = String::from_utf8_lossy(&buf[..n]);
                                warn!("Captured payload from {}: {}", peer, payload);
                                
                                // Send a deceptive response (e.g., a fake banner)
                                let response = format!("220-Osoosi Secure {} Protocol Ready\r\n", service_name);
                                let _ = socket.write_all(response.as_bytes()).await;
                            }
                            _ => {}
                        }
                    }
                    Err(e) => error!("Sleeper Trap error on {}: {}", service_name, e),
                }
            }
        });

        Ok(())
    }
}
