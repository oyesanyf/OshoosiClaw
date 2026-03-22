//! Test Peer — Simulates a peer trying to join the OpenỌ̀ṣọ́ọ̀sì mesh.
//!
//! This standalone binary connects to the same gossipsub mesh as the main agent,
//! announces itself, and listens for threat intelligence broadcasts.
//!
//! Usage:
//!   cargo run --release -p test-peer [-- --bootstrap /ip4/127.0.0.1/tcp/9000/p2p/<PEER_ID>]
//!
//! What this test does:
//! 1. Creates a new libp2p identity
//! 2. Listens on a random port
//! 3. Discovers the main agent via mDNS (or bootstrap address)
//! 4. Publishes a PeerAnnounce on the "osoosi-peer-announce" topic
//! 5. Subscribes to all gossipsub topics
//! 6. Prints all received messages (threats, consensus, intel, etc.)

use chrono::Utc;
use futures::StreamExt;
use libp2p::{
    gossipsub, mdns, noise, identify, kad,
    multiaddr::Protocol,
    Multiaddr, PeerId,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;

/// Re-define PeerAnnounce locally so we don't need to depend on osoosi-types.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PeerAnnounce {
    source_node: String,
    is_patched: bool,
    os_name: String,
    os_version: String,
    os_supported: bool,
    timestamp: chrono::DateTime<Utc>,
    #[serde(default)]
    membership_proof: Option<String>,
}

#[derive(NetworkBehaviour)]
struct TestPeerBehavior {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
    identify: identify::Behaviour,
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .init();

    let args: Vec<String> = std::env::args().collect();
    let bootstrap_addr = args.iter().position(|a| a == "--bootstrap")
        .and_then(|i| args.get(i + 1))
        .cloned();

    println!("╔══════════════════════════════════════════════════╗");
    println!("║  OpenỌ̀ṣọ́ọ̀sì Test Peer — Mesh Join Simulator  ║");
    println!("╠══════════════════════════════════════════════════╣");
    println!("║  This peer will:                                ║");
    println!("║  1. Discover the agent via mDNS                 ║");
    println!("║  2. Send a PeerAnnounce                         ║");
    println!("║  3. Listen for threat broadcasts                ║");
    println!("╚══════════════════════════════════════════════════╝");
    println!();

    // Build the libp2p swarm
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

            Ok(TestPeerBehavior { gossipsub, mdns, identify, kademlia })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    // Subscribe to all osoosi topics
    let threat_topic = gossipsub::IdentTopic::new("osoosi-threats");
    let consensus_topic = gossipsub::IdentTopic::new("osoosi-consensus");
    let peer_announce_topic = gossipsub::IdentTopic::new("osoosi-peer-announce");
    let ghost_shard_topic = gossipsub::IdentTopic::new("osoosi-ghost-shards");
    let intel_topic = gossipsub::IdentTopic::new("osoosi-intel");
    let malware_topic = gossipsub::IdentTopic::new("osoosi-malware-samples");

    swarm.behaviour_mut().gossipsub.subscribe(&threat_topic)?;
    swarm.behaviour_mut().gossipsub.subscribe(&consensus_topic)?;
    swarm.behaviour_mut().gossipsub.subscribe(&peer_announce_topic)?;
    swarm.behaviour_mut().gossipsub.subscribe(&ghost_shard_topic)?;
    swarm.behaviour_mut().gossipsub.subscribe(&intel_topic)?;
    swarm.behaviour_mut().gossipsub.subscribe(&malware_topic)?;

    // Listen on TCP (random port to avoid conflicts with the main agent)
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    let our_peer_id = *swarm.local_peer_id();
    println!("🆔 Our Peer ID: {}", our_peer_id);

    // Bootstrap if address provided
    if let Some(ref addr) = bootstrap_addr {
        println!("🔗 Bootstrapping to: {}", addr);
        if let Ok(maddr) = addr.parse::<Multiaddr>() {
            if let Some(Protocol::P2p(peer_id)) = maddr.iter().last() {
                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                swarm.behaviour_mut().kademlia.add_address(&peer_id, maddr.clone());
            }
            swarm.dial(maddr)?;
        }
    } else {
        println!("📡 Waiting for mDNS discovery (no bootstrap address specified)...");
        println!("   Tip: Run with --bootstrap /ip4/127.0.0.1/tcp/9000/p2p/<AGENT_PEER_ID>");
    }

    // Track state
    let mut discovered_peers: HashSet<PeerId> = HashSet::new();
    let mut announced = false;
    let mut messages_received: u32 = 0;

    // Periodic announcement timer
    let mut announce_interval = tokio::time::interval(Duration::from_secs(15));

    println!("\n⏳ Starting event loop...\n");

    loop {
        tokio::select! {
            _ = announce_interval.tick() => {
                if !discovered_peers.is_empty() {
                    // Publish our PeerAnnounce
                    let announce = PeerAnnounce {
                        source_node: our_peer_id.to_string(),
                        is_patched: true,
                        os_name: std::env::consts::OS.to_string(),
                        os_version: "10.0".to_string(),
                        os_supported: true,
                        timestamp: Utc::now(),
                        membership_proof: None,
                    };

                    let json = serde_json::to_string(&announce).unwrap();
                    match swarm.behaviour_mut().gossipsub.publish(
                        peer_announce_topic.clone(),
                        json.as_bytes(),
                    ) {
                        Ok(_) => {
                            if !announced {
                                println!("📢 PeerAnnounce published! (is_patched=true, os_supported=true)");
                                println!("   The main agent should now see us in pending joins.");
                                announced = true;
                            } else {
                                println!("📢 PeerAnnounce refreshed (heartbeat)");
                            }
                        }
                        Err(e) => {
                            println!("⚠️  Failed to publish PeerAnnounce: {}", e);
                        }
                    }
                }
            }

            event = swarm.select_next_some() => match event {
                // === mDNS Discovery ===
                SwarmEvent::Behaviour(TestPeerBehaviorEvent::Mdns(mdns::Event::Discovered(list))) => {
                    for (peer_id, addr) in list {
                        if discovered_peers.insert(peer_id) {
                            println!("🔍 mDNS: Discovered peer {} at {}", peer_id, addr);
                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                        }
                    }
                }

                SwarmEvent::Behaviour(TestPeerBehaviorEvent::Mdns(mdns::Event::Expired(list))) => {
                    for (peer_id, _) in list {
                        println!("💤 mDNS: Peer expired: {}", peer_id);
                    }
                }

                // === Gossipsub Messages ===
                SwarmEvent::Behaviour(TestPeerBehaviorEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source,
                    message,
                    ..
                })) => {
                    messages_received += 1;
                    let topic = &message.topic;
                    let data = String::from_utf8_lossy(&message.data);

                    if *topic == threat_topic.hash() {
                        println!("🚨 THREAT received from {}: {}", propagation_source, truncate(&data, 200));
                    } else if *topic == consensus_topic.hash() {
                        println!("🗳️  CONSENSUS message from {}: {}", propagation_source, truncate(&data, 200));
                    } else if *topic == peer_announce_topic.hash() {
                        println!("👋 PEER ANNOUNCE from {}: {}", propagation_source, truncate(&data, 200));
                    } else if *topic == ghost_shard_topic.hash() {
                        println!("👻 GHOST SHARD from {}: {}", propagation_source, truncate(&data, 100));
                    } else if *topic == intel_topic.hash() {
                        println!("🧠 INTEL from {}: {}", propagation_source, truncate(&data, 200));
                    } else if *topic == malware_topic.hash() {
                        println!("🦠 MALWARE SAMPLE from {}: {}", propagation_source, truncate(&data, 100));
                    } else {
                        println!("❓ Unknown topic message from {}", propagation_source);
                    }

                    println!("   📊 Total messages received: {}", messages_received);
                }

                SwarmEvent::Behaviour(TestPeerBehaviorEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic })) => {
                    println!("📬 Peer {} subscribed to {}", peer_id, topic);
                }

                // === Identify ===
                SwarmEvent::Behaviour(TestPeerBehaviorEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                    println!("🔎 Identify: {} agent={} addrs={:?}", peer_id, info.agent_version, info.listen_addrs);
                    swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    for addr in info.listen_addrs {
                        swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                    }
                }

                // === Connection Events ===
                SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                    println!("✅ Connected to {} via {}", peer_id, endpoint.get_remote_address());
                }

                SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                    println!("❌ Disconnected from {}: {:?}", peer_id, cause);
                }

                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("👂 Listening on: {}/p2p/{}", address, our_peer_id);
                }

                SwarmEvent::IncomingConnectionError { local_addr, send_back_addr, error, .. } => {
                    println!("⚠️  Incoming error from {}: {} (local: {})", send_back_addr, error, local_addr);
                }

                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                    println!("⚠️  Outgoing error to {:?}: {}", peer_id, error);
                }

                // === Kademlia ===
                SwarmEvent::Behaviour(TestPeerBehaviorEvent::Kademlia(kad::Event::RoutingUpdated { peer, .. })) => {
                    println!("🗺️  Kademlia routing updated for: {}", peer);
                }

                _ => {}
            }
        }
    }
}

fn truncate(s: &str, max_len: usize) -> &str {
    if s.len() > max_len {
        &s[..max_len]
    } else {
        s
    }
}
