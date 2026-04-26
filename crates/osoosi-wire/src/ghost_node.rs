use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use tracing::{info, warn};

pub struct GhostNodeManager {
    node_id: String,
    mesh_tx: Arc<Mutex<Option<Sender<crate::MeshCommand>>>>,
}

impl GhostNodeManager {
    pub fn new(node_id: String, mesh_tx: Arc<Mutex<Option<Sender<crate::MeshCommand>>>>) -> Self {
        Self { node_id, mesh_tx }
    }

    /// Spin up a "Coy" deception service that alerts the mesh while teasing the attacker.
    pub async fn spawn_ghost_service(&self, port: u16, service_name: &str) {
        let addr = format!("0.0.0.0:{}", port);
        let listener = match TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(_) => return,
        };

        info!(
            "Coy Deception: Ghost service '{}' active on {}",
            service_name, addr
        );

        let service_name = service_name.to_string();
        let node_id = self.node_id.clone();
        let mesh_tx = self.mesh_tx.clone();

        tokio::spawn(async move {
            let dp = osoosi_dp::DifferentialPrivacy::new(osoosi_dp::PrivacyConfig {
                epsilon: 1.0,
                min_samples: 1,
                sensitivity: 1.0,
            });

            loop {
                match listener.accept().await {
                    Ok((mut socket, addr)) => {
                        let jitter = dp.laplace_noise();
                        let noisy_addr = if jitter > 0.5 {
                            addr.to_string()
                        } else {
                            "REDACTED".to_string()
                        };

                        warn!(
                            "DECEPTION ALERT: Interaction from {} on '{}' (Node: {})",
                            noisy_addr, service_name, node_id
                        );

                        // Notify mesh (Tarpit)
                        let tx_guard = mesh_tx.lock().await;
                        if let Some(ref tx) = *tx_guard {
                            let _ = tx.try_send(crate::MeshCommand::BroadcastTarpit(
                                crate::TarpitSignal {
                                    target_ip: addr.ip().to_string(),
                                    confidence: 1.0,
                                    attack_type: format!("Ghost Node (Coy): {}", service_name),
                                },
                            ));
                        }
                        drop(tx_guard);

                        // "Coy" Behavior: Send dynamic, teasing banners
                        let banner: &[u8] = match service_name.as_str() {
                            "SSH" => {
                                if jitter > 0.0 {
                                    b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"
                                } else {
                                    b"SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3\r\n"
                                    // Look older/vulnerable
                                }
                            }
                            "SMB" => {
                                b"\x00\x00\x00\x85\xffSMB\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00"
                            }
                            _ => b"Access Denied. Internal Resource Only.\r\n",
                        };

                        let _ = socket.write_all(banner).await;

                        // Adaptive Tarpitting: wait longer based on noise
                        let sleep_secs = 5 + (jitter.abs() as u64 % 10);
                        tokio::time::sleep(tokio::time::Duration::from_secs(sleep_secs)).await;
                        let _ = socket.shutdown().await;
                    }
                    Err(_) => break,
                }
            }
        });
    }

    pub async fn start_all_deceptions(&self) {
        self.spawn_ghost_service(22, "SSH").await;
        self.spawn_ghost_service(445, "SMB").await;
        self.spawn_ghost_service(3389, "RDP").await;
        self.spawn_ghost_service(80, "HTTP-Admin").await;
    }
}
