//! P2P Mesh Behavior (Gossipsub and mDNS).

use super::join_gate::JoinGate;
use super::MeshCommand;
use futures::StreamExt;
use libp2p::{
    autonat, gossipsub, identify, kad, mdns,
    multiaddr::Protocol,
    noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, upnp, yamux, Multiaddr, PeerId,
};
use osoosi_types::{MalwareSample, PeerAnnounce, PeerRulesConfig, ThreatSignature};
use serde::Serialize;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

// Helper functions removed as they are now in osoosi_types::config

/// Custom network behavior for OpenỌ̀ṣọ́ọ̀sì Mesh.
#[derive(NetworkBehaviour)]
pub struct OsoosiBehavior {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub identify: identify::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub autonat: autonat::Behaviour,
    pub upnp: upnp::tokio::Behaviour,
    pub relay_client: libp2p::relay::client::Behaviour,
    pub relay_server: libp2p::relay::Behaviour,
    pub dcutr: libp2p::dcutr::Behaviour,
}
pub struct MeshNode {
    pub swarm: libp2p::Swarm<OsoosiBehavior>,
    pub threat_topic: gossipsub::IdentTopic,
    pub consensus_topic: gossipsub::IdentTopic,
    pub peer_announce_topic: gossipsub::IdentTopic,
    pub ghost_shard_topic: gossipsub::IdentTopic,
    pub intel_topic: gossipsub::IdentTopic,
    pub malware_sample_topic: gossipsub::IdentTopic,
    pub audit_proof_topic: gossipsub::IdentTopic,
    pub tarpit_topic: gossipsub::IdentTopic,
    pub confidential_topic: gossipsub::IdentTopic,
    pub model_delta_topic: gossipsub::IdentTopic,
    pub tripwire_topic: gossipsub::IdentTopic,
    pub zone: String,
    pub memory: Arc<osoosi_memory::MemoryStore>,
    pub dial_semaphore: Arc<tokio::sync::Semaphore>,
}

impl MeshNode {
    pub async fn new(memory: Arc<osoosi_memory::MemoryStore>) -> anyhow::Result<Self> {
        let mesh_config = osoosi_types::load_mesh_listen_config();
        let zone = mesh_config.zone.clone();

        let mut swarm = libp2p::SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_dns()?
            .with_relay_client(noise::Config::new, yamux::Config::default)?
            .with_behaviour(|key, relay_client| {
                let message_id_fn = |message: &gossipsub::Message| {
                    let mut s = std::collections::hash_map::DefaultHasher::new();
                    std::hash::Hash::hash(&message.data, &mut s);
                    gossipsub::MessageId::from(std::hash::Hasher::finish(&s).to_string())
                };

                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(15)) // Increased interval to reduce gossip noise/chatter
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .message_id_fn(message_id_fn)
                    .duplicate_cache_time(Duration::from_secs(60)) // Cache IDs longer to prevent re-gossip overhead
                    .history_length(10)
                    .history_gossip(6)
                    .mesh_n_low(4) // Lower neighbor requirements for resource-constrained nodes
                    .build()
                    .map_err(std::io::Error::other)?;

                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )?;

                let mdns = mdns::tokio::Behaviour::new(
                    mdns::Config::default(),
                    key.public().to_peer_id(),
                )?;

                let identify = identify::Behaviour::new(identify::Config::new(
                    "/osoosi/1.0.0".into(),
                    key.public(),
                ));

                let kademlia = kad::Behaviour::new(
                    key.public().to_peer_id(),
                    kad::store::MemoryStore::new(key.public().to_peer_id()),
                );

                let autonat = autonat::Behaviour::new(
                    key.public().to_peer_id(),
                    autonat::Config::default(),
                );

                let upnp = upnp::tokio::Behaviour::default();
                
                let dcutr = libp2p::dcutr::Behaviour::new(key.public().to_peer_id());

                // Initialize Relay Server (allows this node to help others behind NAT)
                let relay_server = libp2p::relay::Behaviour::new(
                    key.public().to_peer_id(),
                    libp2p::relay::Config::default(),
                );

                Ok(OsoosiBehavior {
                    gossipsub,
                    mdns,
                    identify,
                    kademlia,
                    autonat,
                    upnp,
                    relay_client,
                    relay_server,
                    dcutr,
                })
            })?
            .with_swarm_config(|c| {
                c.with_idle_connection_timeout(Duration::from_secs(30))
                 .with_dial_concurrency_factor(std::num::NonZeroU8::new(1).unwrap()) // Slow down dials
                 .with_max_negotiating_inbound_streams(16)
            })
            .build();

        let threat_topic = gossipsub::IdentTopic::new(format!("osoosi-threats-{}", zone));
        let consensus_topic = gossipsub::IdentTopic::new(format!("osoosi-consensus-{}", zone));
        let peer_announce_topic =
            gossipsub::IdentTopic::new(format!("osoosi-peer-announce-{}", zone));
        let ghost_shard_topic = gossipsub::IdentTopic::new(format!("osoosi-ghost-shards-{}", zone));
        let intel_topic = gossipsub::IdentTopic::new(format!("osoosi-intel-{}", zone));
        let malware_sample_topic =
            gossipsub::IdentTopic::new(format!("osoosi-malware-samples-{}", zone));
        let audit_proof_topic = gossipsub::IdentTopic::new(format!("osoosi-audit-proofs-{}", zone));
        let tarpit_topic = gossipsub::IdentTopic::new(format!("{}-{}", super::TARPIT_TOPIC, zone));
        let confidential_topic =
            gossipsub::IdentTopic::new(format!("{}-{}", super::CONFIDENTIAL_TOPIC, zone));
        let model_delta_topic = gossipsub::IdentTopic::new(format!("osoosi-model-deltas-{}", zone));
        let tripwire_topic = gossipsub::IdentTopic::new(format!("osoosi-deception-tripwire-{}", zone));

        swarm.behaviour_mut().gossipsub.subscribe(&threat_topic)?;
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&consensus_topic)?;
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&peer_announce_topic)?;
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&ghost_shard_topic)?;
        swarm.behaviour_mut().gossipsub.subscribe(&intel_topic)?;
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&malware_sample_topic)?;
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&audit_proof_topic)?;
        swarm.behaviour_mut().gossipsub.subscribe(&tarpit_topic)?;
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&confidential_topic)?;
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&model_delta_topic)?;
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&tripwire_topic)?;

        let mesh_config = osoosi_types::load_mesh_listen_config();

        for addr in mesh_config.listen_addrs {
            if let Ok(maddr) = addr.parse::<Multiaddr>() {
                let mut current_addr = maddr.clone();
                let mut success = false;
                
                // Try up to 5 ports starting from the configured one
                for i in 0..5 {
                    if i > 0 {
                        let mut new_addr = Multiaddr::empty();
                        for proto in current_addr.iter() {
                            match proto {
                                libp2p::multiaddr::Protocol::Tcp(p) => {
                                    new_addr.push(libp2p::multiaddr::Protocol::Tcp(p + 1));
                                }
                                other => new_addr.push(other),
                            }
                        }
                        current_addr = new_addr;
                    }

                    match swarm.listen_on(current_addr.clone()) {
                        Ok(_) => {
                            info!("Oshoosi Mesh: Listening on {}", current_addr);
                            success = true;
                            break;
                        }
                        Err(e) => {
                            let es = e.to_string();
                            if es.contains("10048") || es.contains("WSAEADDRINUSE") || es.contains("already in use") {
                                warn!("Oshoosi Mesh: Port {} in use, trying next...", current_addr);
                            } else {
                                warn!("Oshoosi Mesh: Failed to listen on {}: {}", current_addr, e);
                                break;
                            }
                        }
                    }
                }
                if !success {
                    error!("Oshoosi Mesh: Could not bind to any port for {}", maddr);
                }
            }
        }

        let local_peer_id = *swarm.local_peer_id();
        for peer_addr in mesh_config.bootstrap_peers {
            if let Ok(maddr) = peer_addr.parse::<Multiaddr>() {
                let mut peer_id_opt = None;
                if let Some(Protocol::P2p(peer_id)) = maddr.iter().last() {
                    if peer_id == local_peer_id {
                        continue;
                    }
                    peer_id_opt = Some(peer_id);
                }

                if let Some(pid) = peer_id_opt {
                    swarm.behaviour_mut().gossipsub.add_explicit_peer(&pid);
                    swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&pid, maddr.clone());
                }
                let _ = swarm.dial(maddr);
                // Backoff Strategy: Add delay between initial dials to prevent socket exhaustion burst
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }

        // Set Kademlia to server mode to help others discover the network
        swarm
            .behaviour_mut()
            .kademlia
            .set_mode(Some(kad::Mode::Server));
        // Start bootstrapping the DHT if we have peers
        let has_peers = swarm.behaviour_mut().kademlia.kbuckets().any(|b| b.num_entries() > 0);
        if has_peers {
            let _ = swarm.behaviour_mut().kademlia.bootstrap();
        }

        Ok(MeshNode {
            swarm,
            threat_topic,
            consensus_topic,
            peer_announce_topic,
            ghost_shard_topic,
            intel_topic,
            malware_sample_topic,
            audit_proof_topic,
            tarpit_topic,
            confidential_topic,
            model_delta_topic,
            tripwire_topic,
            zone,
            memory,
            dial_semaphore: Arc::new(tokio::sync::Semaphore::new(16)),
        })
    }

    /// [NEW] Native Neighbor Discovery: Scrapes the OS ARP/Neighbor cache and
    /// attempts to dial any potential Oshoosi siblings on the local segment.
    /// Uses MAC-aware filtering to prioritize "trusted" hardware (Dell, Apple, Intel)
    /// and avoid IoT noise.
    pub async fn bootstrap_local_neighbors(&mut self) {
        info!("[Mesh] Performing Intelligent Local Bootstrapping via ARP cache...");
        let scraper = osoosi_telemetry::discovery::RouteScraper::new();
        let neighbors = scraper.scrape_arp();
        
        let local_peer_id = *self.swarm.local_peer_id();
        let mut dialed = 0;

        // Example "Trusted" MAC Prefixes (OUI) for Laptops/Servers/VMs
        // - b0:e4:d5, bc:df:58 (Common NICs)
        // - 00:15:5d (Hyper-V / WSL)
        let trusted_ouis = vec!["b0:e4:d5", "bc:df:58", "00:15:5d"];

        for host in neighbors {
            // Basic noise filtering: skip common multicast/broadcast patterns
            if host.ip.starts_with("224.") || host.ip.starts_with("239.") || host.ip.ends_with(".255") {
                continue;
            }

            // Skip gateway if it ends in .1 (heuristic)
            if host.ip.ends_with(".1") {
                continue;
            }

            // MAC Filtering: Only dial if the MAC prefix is in our trusted list
            // If MAC is unknown (None), we still dial to ensure we don't miss peers 
            // on interfaces that don't report MACs in the ARP table.
            if let Some(ref mac) = host.mac {
                if !trusted_ouis.iter().any(|oui| mac.starts_with(oui)) {
                    debug!("[Mesh] Skipping non-trusted neighbor (MAC: {})", mac);
                    continue;
                }
            }

            // Construct Multiaddr for the standard Oshoosi port (4001)
            let maddr_str = format!("/ip4/{}/tcp/4001", host.ip);
            if let Ok(maddr) = maddr_str.parse::<Multiaddr>() {
                if let Some(Protocol::P2p(peer_id)) = maddr.iter().last() {
                    if peer_id == local_peer_id { continue; }
                }

                debug!("[Mesh] Knocking on potential sibling door: {}", maddr);
                let _ = self.swarm.dial(maddr);
                dialed += 1;
                
                if dialed % 5 == 0 {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        
        if dialed > 0 {
            info!("[Mesh] ARP Discovery: Dialed {} trusted potential local siblings.", dialed);
        }
    }

    /// Serialize and publish; never panics (unlike `unwrap()` on `serde_json::to_string`).
    fn publish_gossip_json<T: Serialize>(&mut self, topic: &gossipsub::IdentTopic, value: &T) {
        match serde_json::to_string(value) {
            Ok(j) => {
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic.clone(), j.as_bytes());
            }
            Err(e) => warn!("[mesh] gossip message JSON serialization failed: {}", e),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn run_loop<F, G, H, I, J, K, L, M, N>(
        mut self,
        join_gate: Arc<JoinGate>,
        mut command_rx: mpsc::Receiver<MeshCommand>,
        peer_count: Option<Arc<AtomicU32>>,
        peer_rules: PeerRulesConfig,
        adaptive: Arc<dyn osoosi_types::TelemetryControllerInterface>,
        mut on_threat: F,
        mut on_consensus: G,
        mut on_ghost_shard: H,
        mut on_intel: I,
        mut on_malware_sample: J,
        mut on_tarpit: K,
        mut on_confidential: L,
        mut on_model_delta: M,
        mut on_tripwire: N,
    ) where
        F: FnMut(ThreatSignature) + Send + 'static,
        G: FnMut(osoosi_types::PolicyConsensusMessage) + Send + 'static,
        H: FnMut(osoosi_types::GhostShardData) + Send + 'static,
        I: FnMut(osoosi_types::GlobalIntelligence) + Send + 'static,
        J: FnMut(MalwareSample) + Send + 'static,
        K: FnMut(super::TarpitSignal) + Send + 'static,
        L: FnMut(super::ConfidentialMessage) + Send + 'static,
        M: FnMut(osoosi_types::FederatedModelDelta) + Send + 'static,
        N: FnMut(osoosi_types::MeshTripwireAlert) + Send + 'static,
    {
        let mut quarantined: HashSet<PeerId> = HashSet::new();
        let mut approved: HashSet<PeerId> = HashSet::new();
        // Slow down "excitement": Increased bootstrap interval to 5 minutes
        let mut bootstrap_interval = tokio::time::interval(Duration::from_secs(300));
        // [NEW] Local ARP Discovery Interval: Every 10 minutes
        let mut arp_discovery_interval = tokio::time::interval(Duration::from_secs(600));
        // Dynamic Crawler: Periodic random walk to discover new segments of the global mesh
        let mut crawl_interval = tokio::time::interval(Duration::from_secs(60));
        let mut dial_backoff_secs = 0u64;
        let mut socket_cooldown = tokio::time::interval(Duration::from_secs(30));
        socket_cooldown.tick().await; // skip first tick

        // Initial bootstrapping with a small delay to let the system settle
        tokio::time::sleep(Duration::from_secs(2)).await;
        self.bootstrap_local_neighbors().await;

        loop {
            tokio::select! {
                _ = socket_cooldown.tick() => {
                    if adaptive.is_socket_exhaustion() {
                        debug!("Mesh: Clearing socket exhaustion flag after cooldown.");
                        adaptive.set_socket_exhaustion(false);
                    }
                }
                _ = arp_discovery_interval.tick() => {
                    self.bootstrap_local_neighbors().await;
                }
                _ = bootstrap_interval.tick() => {
                    // Zero-Config Discovery: Periodic DHT Bootstrap
                    // Only trigger if we actually have some peers to bootstrap from, to avoid "No known peers" logs.
                    let has_peers = self.swarm.behaviour_mut().kademlia.kbuckets().any(|b| b.num_entries() > 0);
                    if has_peers {
                        let _ = self.swarm.behaviour_mut().kademlia.bootstrap();
                        debug!("Oshoosi Mesh: Periodic Kademlia bootstrap triggered for autonomous discovery.");
                    } else {
                        debug!("Oshoosi Mesh: Kademlia bootstrap skipped (no known peers yet).");
                    }
                }
                _ = crawl_interval.tick() => {
                    // Generate a random ID to force the DHT to explore new buckets
                    let target_random = PeerId::random();
                    debug!("[Crawler] Actively hunting for nodes near: {:?}", target_random);
                    self.swarm.behaviour_mut().kademlia.get_closest_peers(target_random);
                }
                Some(cmd) = command_rx.recv() => match cmd {
                    MeshCommand::ApprovePeer(pid) => {
                        self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&pid);
                        if approved.insert(pid) {
                            if let Some(ref c) = peer_count { c.fetch_add(1, Ordering::Relaxed); }
                        }
                    }
                    MeshCommand::QuarantinePeer(pid) => {
                        self.swarm.behaviour_mut().gossipsub.remove_explicit_peer(&pid);
                        quarantined.insert(pid);
                        if approved.remove(&pid) {
                            if let Some(ref c) = peer_count {
                                let current = c.load(Ordering::Relaxed);
                                if current > 0 {
                                    c.fetch_sub(1, Ordering::Relaxed);
                                }
                            }
                        }
                        info!("Peer {} quarantined; total mesh peers: {}", pid, peer_count.as_ref().map(|c| c.load(Ordering::Relaxed)).unwrap_or(0));
                    }
                    MeshCommand::ReleasePeer(pid) => {
                        quarantined.remove(&pid);
                    }
                    MeshCommand::Broadcast(sig) => {
                        let topic = self.threat_topic.clone();
                        self.publish_gossip_json(&topic, &sig);
                    }
                    MeshCommand::BroadcastConsensus(msg) => {
                        let topic = self.consensus_topic.clone();
                        self.publish_gossip_json(&topic, &msg);
                    }
                    MeshCommand::PublishPeerAnnounce(ann) => {
                        let topic = self.peer_announce_topic.clone();
                        self.publish_gossip_json(&topic, &ann);
                    }
                    MeshCommand::BroadcastGhostShard(shard) => {
                        let topic = self.ghost_shard_topic.clone();
                        self.publish_gossip_json(&topic, &shard);
                    }
                    MeshCommand::BroadcastGlobalIntel(intel) => {
                        let topic = self.intel_topic.clone();
                        self.publish_gossip_json(&topic, &intel);
                    }
                    MeshCommand::BroadcastMalwareSample(sample) => {
                        let topic = self.malware_sample_topic.clone();
                        self.publish_gossip_json(&topic, &sample);
                    }
                    MeshCommand::BroadcastNoisyThreat(mut sig, dp_conf) => {
                        let dp = osoosi_dp::DifferentialPrivacy::new(dp_conf.clone());
                        sig.confidence = (sig.confidence + dp.laplace_noise()).clamp(0.0, 1.0);
                        sig.epsilon = Some(dp_conf.epsilon);
                        let topic = self.threat_topic.clone();
                        self.publish_gossip_json(&topic, &sig);
                    }
                    MeshCommand::BroadcastAuditProof(proof) => {
                        let _ = self.swarm.behaviour_mut().gossipsub.publish(self.audit_proof_topic.clone(), proof.as_bytes());
                    }
                    MeshCommand::DialPeer(pid, addr) => {
                        if let Ok(maddr) = addr.parse::<Multiaddr>() {
                            let _ = self.swarm.dial(maddr.clone());
                            self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&pid);
                            self.swarm.behaviour_mut().kademlia.add_address(&pid, maddr);
                        }
                    }
                    MeshCommand::BroadcastTarpit(signal) => {
                        let topic = self.tarpit_topic.clone();
                        self.publish_gossip_json(&topic, &signal);
                    }
                    MeshCommand::BroadcastConfidential(msg) => {
                        let topic = self.confidential_topic.clone();
                        self.publish_gossip_json(&topic, &msg);
                    }
                    MeshCommand::BroadcastModelDelta(delta) => {
                        let topic = self.model_delta_topic.clone();
                        self.publish_gossip_json(&topic, &delta);
                    }
                    MeshCommand::BroadcastTripwire(alert) => {
                        let topic = self.tripwire_topic.clone();
                        self.publish_gossip_json(&topic, &alert);
                    }
                },
                event = self.swarm.select_next_some() => match event {
                    SwarmEvent::Behaviour(OsoosiBehaviorEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (pid, addr) in list {
                            if pid != *self.swarm.local_peer_id() && !quarantined.contains(&pid) {
                                self.swarm.behaviour_mut().kademlia.add_address(&pid, addr.clone());
                                let _ = join_gate.on_peer_discovered(pid, Some(addr.to_string()));
                            }
                        }
                    }
                    SwarmEvent::Behaviour(OsoosiBehaviorEvent::Gossipsub(gossipsub::Event::Message { propagation_source, message, .. })) => {
                        if quarantined.contains(&propagation_source) { continue; }

                        // REPUTATION FILTERING: Drop messages from untrusted peers at scale
                        let peer_reputation = self.memory.get_reputation_value(&propagation_source.to_string()).unwrap_or(0.5);
                        if peer_reputation < 0.1 {
                            debug!("Dropping gossip message from low-reputation peer: {}", propagation_source);
                            continue;
                        }
                        if message.topic == self.threat_topic.hash() {
                            if let Ok(sig) = serde_json::from_slice::<ThreatSignature>(&message.data) {
                                if sig.verify() { on_threat(sig); }
                            }
                        } else if message.topic == self.consensus_topic.hash() {
                            if let Ok(m) = serde_json::from_slice::<osoosi_types::PolicyConsensusMessage>(&message.data) {
                                on_consensus(m);
                            }
                        } else if message.topic == self.peer_announce_topic.hash() {
                            if let Ok(a) = serde_json::from_slice::<PeerAnnounce>(&message.data) {
                                let _ = join_gate.on_peer_announce_received(&a, &peer_rules);
                            }
                        } else if message.topic == self.ghost_shard_topic.hash() {
                            if let Ok(s) = serde_json::from_slice::<osoosi_types::GhostShardData>(&message.data) {
                                on_ghost_shard(s);
                            }
                        } else if message.topic == self.intel_topic.hash() {
                            if let Ok(i) = serde_json::from_slice::<osoosi_types::GlobalIntelligence>(&message.data) {
                                on_intel(i);
                            }
                        } else if message.topic == self.malware_sample_topic.hash() {
                            if let Ok(s) = serde_json::from_slice::<MalwareSample>(&message.data) {
                                on_malware_sample(s);
                            }
                        } else if message.topic == self.tarpit_topic.hash() {
                            if let Ok(s) = serde_json::from_slice::<super::TarpitSignal>(&message.data) {
                                on_tarpit(s);
                            }
                        } else if message.topic == self.confidential_topic.hash() {
                            if let Ok(msg) = serde_json::from_slice::<super::ConfidentialMessage>(&message.data) {
                                on_confidential(msg);
                            }
                        } else if message.topic == self.model_delta_topic.hash() {
                            if let Ok(delta) = serde_json::from_slice::<osoosi_types::FederatedModelDelta>(&message.data) {
                                on_model_delta(delta);
                            }
                        } else if message.topic == self.tripwire_topic.hash() {
                            if let Ok(alert) = serde_json::from_slice::<osoosi_types::MeshTripwireAlert>(&message.data) {
                                on_tripwire(alert);
                            }
                        }
                    }
                    SwarmEvent::Behaviour(OsoosiBehaviorEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                        if peer_id == *self.swarm.local_peer_id() { continue; }
                        
                        // THE IDENTIFY FINGERPRINT: Filter for Oshoosi protocol agents
                        if info.agent_version.to_lowercase().contains("osoosi") {
                            info!("[!] DYNAMIC DISCOVERY: Identified Oshoosi Node at {:?}", peer_id);
                            for addr in info.listen_addrs {
                                self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                            }
                        } else {
                            // Stealth: Disconnect from non-Oshoosi nodes to save resources and remain stealthy
                            debug!("Identify: Disconnecting from non-Oshoosi peer {}", peer_id);
                            let _ = self.swarm.disconnect_peer_id(peer_id);
                        }
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        info!("Connection established with {} via {:?}", peer_id, endpoint.get_remote_address());
                    }
                    SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                        debug!("Connection closed with {}: {:?}", peer_id, cause);
                        if let Some(libp2p::swarm::ConnectionError::IO(e)) = cause {
                            if e.kind() == std::io::ErrorKind::TimedOut {
                                debug!("Connection to {} timed out - likely system contention.", peer_id);
                            }
                        }
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!("Local node is listening on {}", address);
                    }
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                        let es = error.to_string();
                        if es.contains("10048") || es.contains("WSAEADDRINUSE") {
                            warn!("Socket exhaustion detected (WSAEADDRINUSE). Applying aggressive discovery backoff.");
                            adaptive.set_socket_exhaustion(true);
                            dial_backoff_secs = (dial_backoff_secs + 60).min(3600);
                            bootstrap_interval = tokio::time::interval(Duration::from_secs(300 + dial_backoff_secs));
                            arp_discovery_interval = tokio::time::interval(Duration::from_secs(600 + dial_backoff_secs));
                            // Reset the intervals
                            let _ = bootstrap_interval.tick().await; 
                            let _ = arp_discovery_interval.tick().await;
                        } else {
                            warn!("Outgoing connection error to {:?}: {}", peer_id, error);
                        }
                        
                        // Autonomous Repair: Remove dead/unreachable peers from DHT to stop retry loops
                        if let Some(pid) = peer_id {
                            let _ = self.swarm.behaviour_mut().kademlia.remove_peer(&pid);
                            debug!("Removed unreachable peer {} from Kademlia routing table.", pid);
                        }
                    }
                    SwarmEvent::Behaviour(OsoosiBehaviorEvent::Kademlia(kad::Event::OutboundQueryProgressed { result, .. })) => {
                        if let kad::QueryResult::GetClosestPeers(Ok(kad::GetClosestPeersOk { peers, .. })) = result {
                            let mut dial_count = 0;
                            for peer_info in peers {
                                if peer_info.peer_id != *self.swarm.local_peer_id() {
                                    let _ = join_gate.on_peer_discovered(peer_info.peer_id, None);
                                    
                                    // SHODAN SCAN: Dial newly discovered peers to fingerprint them
                                    // Limit to 5 dials per crawl cycle to prevent ISP throttling
                                    // And use the global dial_semaphore for adaptive backpressure
                                    if dial_count < 5 {
                                        let sem = self.dial_semaphore.clone();
                                        let permit = sem.try_acquire();
                                        if permit.is_ok() {
                                            let _ = self.swarm.dial(peer_info.peer_id);
                                            dial_count += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    SwarmEvent::Behaviour(OsoosiBehaviorEvent::Kademlia(kad::Event::RoutingUpdated { peer, addresses, .. })) => {
                        if peer != *self.swarm.local_peer_id() {
                            debug!("Kademlia routing updated for peer {}: {:?}", peer, addresses);
                            let addr = addresses.iter().next().map(|a| a.to_string());
                            let _ = join_gate.on_peer_discovered(peer, addr);
                        }
                    }
                    SwarmEvent::Behaviour(OsoosiBehaviorEvent::Autonat(autonat::Event::StatusChanged { old: _old, new })) => {
                        info!("Oshoosi Mesh: NAT status changed to {:?}", new);
                    }
                    SwarmEvent::Behaviour(OsoosiBehaviorEvent::Upnp(upnp::Event::NewExternalAddr(addr))) => {
                        info!("Oshoosi Mesh: UPnP opened external port at {}", addr);
                    }
                    SwarmEvent::Behaviour(OsoosiBehaviorEvent::Upnp(upnp::Event::GatewayNotFound)) => {
                        debug!("Oshoosi Mesh: UPnP gateway not found (manual port forwarding might be needed).");
                    }
                    SwarmEvent::Behaviour(OsoosiBehaviorEvent::Dcutr(ev)) => {
                        debug!("[HolePunch] DCUtR event: {:?}", ev);
                    }
                    SwarmEvent::Behaviour(OsoosiBehaviorEvent::RelayClient(ev)) => {
                        debug!("[Relay] Relay client event: {:?}", ev);
                    }
                    SwarmEvent::Behaviour(OsoosiBehaviorEvent::RelayServer(ev)) => {
                        debug!("[RelayServer] Event: {:?}", ev);
                    }
                    _ => {}
                }
            }
        }
    }
}
