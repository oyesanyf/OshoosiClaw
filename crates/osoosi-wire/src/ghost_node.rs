use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

pub struct GhostNodeManager {
    node_id: String,
    mesh_tx: Arc<Mutex<Option<Sender<crate::MeshCommand>>>>,
    active_services: Arc<dashmap::DashMap<String, u16>>,
    total_interactions: Arc<AtomicU64>,
}

impl GhostNodeManager {
    pub fn new(node_id: String, mesh_tx: Arc<Mutex<Option<Sender<crate::MeshCommand>>>>) -> Self {
        Self {
            node_id,
            mesh_tx,
            active_services: Arc::new(dashmap::DashMap::new()),
            total_interactions: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Spin up a "Coy" deception service that alerts the mesh while teasing the attacker.
    pub async fn spawn_ghost_service(&self, port: u16, service_name: &str) {
        let fallback_port = match port {
            22 => 2222,
            80 => 8088,
            445 => 4450,
            3389 => 3390,
            p => p.wrapping_add(10000),
        };

        let (listener, bound_port) = match TcpListener::bind(format!("0.0.0.0:{}", port)).await {
            Ok(l) => (l, port),
            Err(e) => {
                debug!(
                    "Coy Deception: Primary port {} in use by OS for '{}' ({}); binding decoy fallback port {}",
                    port, service_name, e, fallback_port
                );
                match TcpListener::bind(format!("0.0.0.0:{}", fallback_port)).await {
                    Ok(l) => (l, fallback_port),
                    Err(e2) => {
                        warn!(
                            "Coy Deception: Fallback port {} also unavailable for '{}': {}",
                            fallback_port, service_name, e2
                        );
                        return;
                    }
                }
            }
        };

        info!(
            "Coy Deception: Ghost service '{}' active on 0.0.0.0:{}",
            service_name, bound_port
        );
        self.active_services.insert(service_name.to_string(), bound_port);

        let service_name = service_name.to_string();
        let node_id = self.node_id.clone();
        let mesh_tx = self.mesh_tx.clone();
        let total_interactions = self.total_interactions.clone();

        tokio::spawn(async move {
            let dp = osoosi_dp::DifferentialPrivacy::new(osoosi_dp::PrivacyConfig {
                epsilon: 1.0,
                min_samples: 1,
                sensitivity: 1.0,
            });

            loop {
                match listener.accept().await {
                    Ok((mut socket, addr)) => {
                        total_interactions.fetch_add(1, Ordering::Relaxed);
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

    pub fn get_status(&self) -> serde_json::Value {
        let mut services = serde_json::Map::new();
        for item in self.active_services.iter() {
            services.insert(item.key().clone(), serde_json::json!(item.value()));
        }
        serde_json::json!({
            "active_services": services,
            "total_interactions": self.total_interactions.load(Ordering::Relaxed),
        })
    }

    pub async fn start_all_deceptions(&self) {
        self.spawn_ghost_service(22, "SSH").await;
        self.spawn_ghost_service(445, "SMB").await;
        self.spawn_ghost_service(3389, "RDP").await;
        self.spawn_ghost_service(80, "HTTP-Admin").await;
    }
}
