//! P2P Mesh Behavior (Gossipsub and mDNS).

use super::join_gate::JoinGate;
use futures::StreamExt;
use libp2p::{
    gossipsub, mdns, noise, identify, kad,
    multiaddr::Protocol,
    Multiaddr, PeerId,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use super::MeshCommand;
use osoosi_types::{ThreatSignature, PeerAnnounce, PeerRulesConfig, MalwareSample};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{info, warn, debug};

// Helper functions removed as they are now in osoosi_types::config

/// Custom network behavior for OpenỌ̀ṣọ́ọ̀sì Mesh.
#[derive(NetworkBehaviour)]
pub struct OsoosiBehavior {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub identify: identify::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
}

pub struct MeshNode {
    swarm: libp2p::Swarm<OsoosiBehavior>,
    pub threat_topic: gossipsub::IdentTopic,
    pub consensus_topic: gossipsub::IdentTopic,
    pub peer_announce_topic: gossipsub::IdentTopic,
    pub ghost_shard_topic: gossipsub::IdentTopic,
    pub intel_topic: gossipsub::IdentTopic,
    pub name: String,
    pub malware_sample_topic: gossipsub::IdentTopic,
    pub audit_proof_topic: gossipsub::IdentTopic,
    pub tarpit_topic: gossipsub::IdentTopic,
    pub confidential_topic: gossipsub::IdentTopic,
}

impl MeshNode {
    pub async fn new() -> anyhow::Result<Self> {
        let mut swarm = libp2p::SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|key| {
                let message_id_fn = |message: &gossipsub::Message| {
                    let mut s = std::collections::hash_map::DefaultHasher::new();
                    std::hash::Hash::hash(&message.data, &mut s);
                    gossipsub::MessageId::from(std::hash::Hasher::finish(&s).to_string())
                };

                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(10))
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .message_id_fn(message_id_fn)
                    .duplicate_cache_time(Duration::from_secs(1))
                    .build()
                    .map_err(std::io::Error::other)?;

                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )?;

                let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())?;
                
                let identify = identify::Behaviour::new(identify::Config::new(
                    "/osoosi/1.0.0".into(),
                    key.public(),
                ));

                let kademlia = kad::Behaviour::new(
                    key.public().to_peer_id(),
                    kad::store::MemoryStore::new(key.public().to_peer_id()),
                );

                Ok(OsoosiBehavior { gossipsub, mdns, identify, kademlia })
            })?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        let threat_topic = gossipsub::IdentTopic::new("osoosi-threats");
        let consensus_topic = gossipsub::IdentTopic::new("osoosi-consensus");
        let peer_announce_topic = gossipsub::IdentTopic::new("osoosi-peer-announce");
        let ghost_shard_topic = gossipsub::IdentTopic::new("osoosi-ghost-shards");
        let intel_topic = gossipsub::IdentTopic::new("osoosi-intel");
        let malware_sample_topic = gossipsub::IdentTopic::new("osoosi-malware-samples");
        let audit_proof_topic = gossipsub::IdentTopic::new("osoosi-audit-proofs");
        let tarpit_topic = gossipsub::IdentTopic::new(super::TARPIT_TOPIC);
        let confidential_topic = gossipsub::IdentTopic::new(super::CONFIDENTIAL_TOPIC);

        swarm.behaviour_mut().gossipsub.subscribe(&threat_topic)?;
        swarm.behaviour_mut().gossipsub.subscribe(&consensus_topic)?;
        swarm.behaviour_mut().gossipsub.subscribe(&peer_announce_topic)?;
        swarm.behaviour_mut().gossipsub.subscribe(&ghost_shard_topic)?;
        swarm.behaviour_mut().gossipsub.subscribe(&intel_topic)?;
        swarm.behaviour_mut().gossipsub.subscribe(&malware_sample_topic)?;
        swarm.behaviour_mut().gossipsub.subscribe(&audit_proof_topic)?;
        swarm.behaviour_mut().gossipsub.subscribe(&tarpit_topic)?;
        swarm.behaviour_mut().gossipsub.subscribe(&confidential_topic)?;

        let mesh_config = osoosi_types::load_mesh_listen_config();

        for addr in mesh_config.listen_addrs {
            if let Ok(maddr) = addr.parse::<Multiaddr>() {
                if let Err(e) = swarm.listen_on(maddr.clone()) {
                    warn!("Failed to listen on {}: {}", maddr, e);
                }
            }
        }

        for peer_addr in mesh_config.bootstrap_peers {
            if let Ok(maddr) = peer_addr.parse::<Multiaddr>() {
                if let Some(Protocol::P2p(peer_id)) = maddr.iter().last() {
                    swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    swarm.behaviour_mut().kademlia.add_address(&peer_id, maddr.clone());
                }
                let _ = swarm.dial(maddr);
            }
        }

        // Set Kademlia to server mode to help others discover the network
        swarm.behaviour_mut().kademlia.set_mode(Some(kad::Mode::Server));
        // Start bootstrapping the DHT
        let _ = swarm.behaviour_mut().kademlia.bootstrap();

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
            name: String::new(), // placeholder
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn run_loop<F, G, H, I, J, K, L>(
        mut self,
        join_gate: Arc<JoinGate>,
        mut command_rx: mpsc::Receiver<MeshCommand>,
        peer_count: Option<Arc<AtomicU32>>,
        peer_rules: PeerRulesConfig,
        mut on_threat: F,
        mut on_consensus: G,
        mut on_ghost_shard: H,
        mut on_intel: I,
        mut on_malware_sample: J,
        mut on_tarpit: K,
        mut on_confidential: L,
    ) where
        F: FnMut(ThreatSignature) + Send + 'static,
        G: FnMut(osoosi_types::PolicyConsensusMessage) + Send + 'static,
        H: FnMut(osoosi_types::GhostShardData) + Send + 'static,
        I: FnMut(osoosi_types::GlobalIntelligence) + Send + 'static,
        J: FnMut(MalwareSample) + Send + 'static,
        K: FnMut(super::TarpitSignal) + Send + 'static,
        L: FnMut(super::ConfidentialMessage) + Send + 'static,
    {
        let mut quarantined: HashSet<PeerId> = HashSet::new();
        let mut approved: HashSet<PeerId> = HashSet::new();
        loop {
            tokio::select! {
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
                         let j = serde_json::to_string(&sig).unwrap();
                         let _ = self.swarm.behaviour_mut().gossipsub.publish(self.threat_topic.clone(), j.as_bytes());
                    }
                    MeshCommand::BroadcastConsensus(msg) => {
                        let j = serde_json::to_string(&msg).unwrap();
                        let _ = self.swarm.behaviour_mut().gossipsub.publish(self.consensus_topic.clone(), j.as_bytes());
                    }
                    MeshCommand::PublishPeerAnnounce(ann) => {
                        let j = serde_json::to_string(&ann).unwrap();
                        let _ = self.swarm.behaviour_mut().gossipsub.publish(self.peer_announce_topic.clone(), j.as_bytes());
                    }
                    MeshCommand::BroadcastGhostShard(shard) => {
                        let j = serde_json::to_string(&shard).unwrap();
                        let _ = self.swarm.behaviour_mut().gossipsub.publish(self.ghost_shard_topic.clone(), j.as_bytes());
                    }
                    MeshCommand::BroadcastGlobalIntel(intel) => {
                        let j = serde_json::to_string(&intel).unwrap();
                        let _ = self.swarm.behaviour_mut().gossipsub.publish(self.intel_topic.clone(), j.as_bytes());
                    }
                    MeshCommand::BroadcastMalwareSample(sample) => {
                        let j = serde_json::to_string(&sample).unwrap();
                        let _ = self.swarm.behaviour_mut().gossipsub.publish(self.malware_sample_topic.clone(), j.as_bytes());
                    }
                    MeshCommand::BroadcastNoisyThreat(mut sig, dp_conf) => {
                        let dp = osoosi_dp::DifferentialPrivacy::new(dp_conf.clone());
                        sig.confidence = (sig.confidence + dp.laplace_noise()).clamp(0.0, 1.0);
                        sig.epsilon = Some(dp_conf.epsilon);
                        let j = serde_json::to_string(&sig).unwrap();
                        let _ = self.swarm.behaviour_mut().gossipsub.publish(self.threat_topic.clone(), j.as_bytes());
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
                        if let Ok(j) = serde_json::to_string(&signal) {
                            let _ = self.swarm.behaviour_mut().gossipsub.publish(self.tarpit_topic.clone(), j.as_bytes());
                        }
                    }
                    MeshCommand::BroadcastConfidential(msg) => {
                        if let Ok(j) = serde_json::to_string(&msg) {
                            let _ = self.swarm.behaviour_mut().gossipsub.publish(self.confidential_topic.clone(), j.as_bytes());
                        }
                    }
                },
                event = self.swarm.select_next_some() => match event {
                    SwarmEvent::Behaviour(OsoosiBehaviorEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (pid, addr) in list {
                            if !quarantined.contains(&pid) {
                                self.swarm.behaviour_mut().kademlia.add_address(&pid, addr.clone());
                                let _ = join_gate.on_peer_discovered(pid, Some(addr.to_string()));
                            }
                        }
                    }
                    SwarmEvent::Behaviour(OsoosiBehaviorEvent::Gossipsub(gossipsub::Event::Message { propagation_source, message, .. })) => {
                        if quarantined.contains(&propagation_source) { continue; }
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
                        }
                    }
                    SwarmEvent::Behaviour(OsoosiBehaviorEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                        debug!("Identify: discovered {} from {:?}", peer_id, info.listen_addrs);
                        self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        for addr in info.listen_addrs {
                            self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                        }
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        info!("Connection established with {} via {:?}", peer_id, endpoint.get_remote_address());
                    }
                    SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                        warn!("Connection closed with {}: {:?}", peer_id, cause);
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!("Local node is listening on {}", address);
                    }
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                        warn!("Outgoing connection error to {:?}: {}", peer_id, error);
                    }
                    SwarmEvent::Behaviour(OsoosiBehaviorEvent::Kademlia(kad::Event::OutboundQueryProgressed { result, .. })) => {
                        if let kad::QueryResult::GetClosestPeers(Ok(kad::GetClosestPeersOk { peers, .. })) = result {
                            for peer_info in peers {
                                let _ = join_gate.on_peer_discovered(peer_info.peer_id, None);
                            }
                        }
                    }
                    SwarmEvent::Behaviour(OsoosiBehaviorEvent::Kademlia(kad::Event::RoutingUpdated { peer, addresses, .. })) => {
                        debug!("Kademlia routing updated for peer {}: {:?}", peer, addresses);
                        let addr = addresses.iter().next().map(|a| a.to_string());
                        let _ = join_gate.on_peer_discovered(peer, addr);
                    }
                    _ => {}
                }
            }
        }
    }
}
