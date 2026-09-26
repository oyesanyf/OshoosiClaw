use std::sync::Arc;
use tokio::sync::RwLock;
use nostr_sdk::prelude::*;
use rand_distr::{Distribution, Exp};
use rand::thread_rng;
use osoosi_types::ThreatSignature;
use tracing::{debug, info};

/// Nostr Event Kinds for OshoosiClaw Mesh
pub const KIND_EDR_ALERT: Kind = Kind::Custom(20001);
pub const KIND_NODE_HEARTBEAT: Kind = Kind::Custom(20002);
pub const KIND_MESH_CONFIG: Kind = Kind::Custom(20003);

/// MalchelaPrivacy: Implements Laplacian noise injection for Differential Privacy.
pub struct MalchelaPrivacy {
    pub epsilon: f64, // Privacy budget (lower = more noise)
}

impl MalchelaPrivacy {
    /// Injects Laplacian noise into a threat score (0.0 to 1.0)
    pub fn inject_noise(&self, score: f64) -> f64 {
        let mut rng = thread_rng();
        // Laplace distribution is the difference of two Exponential distributions
        // For Oshoosi, we use lambda = epsilon to scale noise to the privacy budget.
        if let Ok(exp) = Exp::new(self.epsilon) {
            let noise = exp.sample(&mut rng) - exp.sample(&mut rng);
            (score + noise).clamp(0.0, 1.0)
        } else {
            score // Fallback if epsilon is invalid
        }
    }
}

/// NostrMeshOrchestrator: Handles decentralized relay-based communication.
pub struct NostrMeshOrchestrator {
    client: Arc<RwLock<Client>>,
    keys: Keys,
    privacy: MalchelaPrivacy,
    seen_threats: Arc<dashmap::DashMap<String, std::time::Instant>>,
}

impl NostrMeshOrchestrator {
    /// Initialize a new Nostr mesh node.
    pub async fn new(secret_key_hex: Option<&str>, epsilon: f64) -> anyhow::Result<Self> {
        let keys = match secret_key_hex {
            Some(hex) => Keys::parse(hex)?,
            None => Keys::generate(),
        };

        let client = Client::new(&keys);
        
        info!("Nostr Mesh Node Initialized. PubKey: {}", keys.public_key());

        Ok(Self {
            client: Arc::new(RwLock::new(client)),
            keys,
            privacy: MalchelaPrivacy { epsilon },
            seen_threats: Arc::new(dashmap::DashMap::new()),
        })
    }

    /// Add a new relay to the pool.
    pub async fn add_relay(&self, url: &str) -> anyhow::Result<()> {
        let client = self.client.read().await;
        client.add_relay(url).await?;
        Ok(())
    }

    /// Connect to all configured relays.
    pub async fn connect(&self) {
        let client = self.client.read().await;
        client.connect().await;
    }

    /// Broadcast a privacy-hardened threat signature to the decentralized mesh.
    pub async fn broadcast_threat(&self, mut sig: ThreatSignature) -> anyhow::Result<()> {
        let client = self.client.read().await;

        let relays = client.relays().await;
        if relays.is_empty() {
            debug!("Nostr Mesh: No relays configured; skipping broadcast.");
            return Ok(());
        }
        
        // --- 1. MALCHELA DIFFERENTIAL PRIVACY ---
        // Inject Laplacian noise to prevent relay-side fingerprinting of specific threats.
        sig.confidence = self.privacy.inject_noise(sig.confidence as f64) as f32;

        // --- 2. CRYPTOGRAPHIC IDENTITY & SIGNING ---
        let content = serde_json::to_string(&sig)?;
        
        // Create the signed Nostr event (Kind 20001)
        let event = EventBuilder::new(
            KIND_EDR_ALERT,
            content,
            Vec::<Tag>::new()
        )
        .custom_created_at(Self::randomized_timestamp())
        .to_event(&self.keys)?;

        client.send_event(event).await?;
        
        info!("Privacy-hardened threat broadcasted via Nostr: {}", sig.id);
        
        Ok(())
    }

    /// Listen for incoming threats from the mesh.
    pub async fn start_listening<F>(&self, callback: F)
    where
        F: Fn(ThreatSignature) + Send + Sync + 'static,
    {
        let client = self.client.read().await;
        let filter = Filter::new().kind(KIND_EDR_ALERT);
        let _ = client.subscribe(vec![filter], None).await;

        let client_clone = self.client.clone();
        let seen = self.seen_threats.clone();
        tokio::spawn(async move {
            let mut notifications = {
                let c = client_clone.read().await;
                c.notifications()
            };

            while let Ok(notification) = notifications.recv().await {
                if let RelayPoolNotification::Event { event, .. } = notification {
                    if event.kind == KIND_EDR_ALERT {
                        if let Ok(sig) = serde_json::from_str::<ThreatSignature>(&event.content) {
                            if !Self::check_and_record_threat_map(&seen, &sig.id) {
                                debug!("BitChat: Suppressed duplicate Nostr threat {} from relay pool", sig.id);
                                continue;
                            }
                            info!("Received threat from Nostr mesh: {}", sig.id);
                            callback(sig);
                        }
                    }
                }
            }
        });
    }

    /// Check whether a threat has been recently seen. If new (or seen > 3600s ago),
    /// records the threat and returns true (should process). If seen within 3600s, returns false (suppress).
    /// Uses DashMap entry API to guarantee atomic check-and-insert under multi-threaded concurrency.
    pub fn check_and_record_threat(&self, id: &str) -> bool {
        Self::check_and_record_threat_map(&self.seen_threats, id)
    }

    /// Helper for checking and recording threat against an Arc/shared DashMap instance.
    pub fn check_and_record_threat_map(
        seen: &dashmap::DashMap<String, std::time::Instant>,
        id: &str,
    ) -> bool {
        let now = std::time::Instant::now();
        let mut is_new = false;
        seen.entry(id.to_string())
            .and_modify(|prev| {
                if now.duration_since(*prev).as_secs() >= 3600 {
                    *prev = now;
                    is_new = true;
                }
            })
            .or_insert_with(|| {
                is_new = true;
                now
            });

        if is_new && seen.len() > 1000 {
            seen.retain(|_, time| now.duration_since(*time).as_secs() < 7200);
        }

        is_new
    }

    /// Pulse: Heartbeat for node discovery.
    pub async fn send_heartbeat(&self, node_id: &str) -> anyhow::Result<()> {
        let client = self.client.read().await;
        let relays = client.relays().await;
        if relays.is_empty() {
            debug!("Nostr Mesh: No relays configured; skipping heartbeat.");
            return Ok(());
        }
        let event = EventBuilder::new(
            KIND_NODE_HEARTBEAT,
            format!("Node {} is active", node_id),
            Vec::<Tag>::new()
        ).to_event(&self.keys)?;
        client.send_event(event).await?;
        Ok(())
    }

    /// Randomized timestamp (BitChat style) for privacy.
    /// Returns a timestamp offset by +/- 15 minutes.
    pub fn randomized_timestamp() -> Timestamp {
        use rand::Rng;
        let offset = rand::thread_rng().gen_range(-900..900);
        let now = Timestamp::now().as_u64() as i64;
        Timestamp::from((now + offset) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn test_broadcast_threat_no_relays_returns_ok() {
        let orch = NostrMeshOrchestrator::new(None, 1.0).await.expect("Failed to create orchestrator");
        let sig = ThreatSignature::new("test-node".to_string());
        let res = orch.broadcast_threat(sig).await;
        assert!(res.is_ok(), "broadcast_threat with no relays must return Ok(()) without error");
    }

    #[tokio::test]
    async fn test_send_heartbeat_no_relays_returns_ok() {
        let orch = NostrMeshOrchestrator::new(None, 1.0).await.expect("Failed to create orchestrator");
        let res = orch.send_heartbeat("node-123").await;
        assert!(res.is_ok(), "send_heartbeat with no relays must return Ok(()) without error");
    }

    #[tokio::test]
    async fn test_nostr_threat_deduplication_lifecycle() {
        let orch = NostrMeshOrchestrator::new(None, 1.0).await.expect("Failed to create orchestrator");

        // First occurrence must be accepted
        assert!(orch.check_and_record_threat("threat-uuid-alpha"));

        // Immediate duplicate must be suppressed
        assert!(!orch.check_and_record_threat("threat-uuid-alpha"));

        // Distinct ID must be accepted
        assert!(orch.check_and_record_threat("threat-uuid-beta"));

        // Duplicate of second ID must also be suppressed
        assert!(!orch.check_and_record_threat("threat-uuid-beta"));
    }

    #[tokio::test]
    async fn test_nostr_threat_concurrent_burst_deduplication() {
        let orch = Arc::new(NostrMeshOrchestrator::new(None, 1.0).await.expect("Failed to create orchestrator"));
        let accepted_count = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        // 20 concurrent tasks simulating 4-20 relay sockets pushing the exact same threat 25 times each (500 total)
        for _ in 0..20 {
            let orch_clone = orch.clone();
            let count_clone = accepted_count.clone();
            handles.push(tokio::spawn(async move {
                for _ in 0..25 {
                    if orch_clone.check_and_record_threat("concurrent-nostr-threat-uuid") {
                        count_clone.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // Exactly ONE occurrence across all 500 concurrent attempts must be accepted
        assert_eq!(
            accepted_count.load(Ordering::SeqCst),
            1,
            "Exactly 1 of 500 concurrent events must pass deduplication"
        );
    }
}
