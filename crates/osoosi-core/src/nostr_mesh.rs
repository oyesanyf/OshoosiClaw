use std::sync::Arc;
use tokio::sync::RwLock;
use nostr_sdk::prelude::*;
use rand_distr::{Distribution, Exp};
use rand::thread_rng;
use osoosi_types::ThreatSignature;
use tracing::info;

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
        tokio::spawn(async move {
            let mut notifications = {
                let c = client_clone.read().await;
                c.notifications()
            };

            while let Ok(notification) = notifications.recv().await {
                if let RelayPoolNotification::Event { event, .. } = notification {
                    if event.kind == KIND_EDR_ALERT {
                        if let Ok(sig) = serde_json::from_str::<ThreatSignature>(&event.content) {
                            info!("Received threat from Nostr mesh: {}", sig.id);
                            callback(sig);
                        }
                    }
                }
            }
        });
    }

    /// Pulse: Heartbeat for node discovery.
    pub async fn send_heartbeat(&self, node_id: &str) -> anyhow::Result<()> {
        let client = self.client.read().await;
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
        Timestamp::now().checked_add(offset).unwrap_or_else(Timestamp::now)
    }
}
