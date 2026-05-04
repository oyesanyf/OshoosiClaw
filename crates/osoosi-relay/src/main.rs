use libp2p::{
    identify, relay, PeerId, SwarmBuilder,
};
use std::error::Error;
use futures::StreamExt;
use tracing::{info, Level};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    // 1. Generate keys
    let local_key = libp2p::identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    info!("Starting Oshoosi Relay Node: {}", local_peer_id);

    // 2. Build Swarm
    let mut swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|key| {
            Behaviour {
                relay: relay::Behaviour::new(local_peer_id, Default::default()),
                identify: identify::Behaviour::new(identify::Config::new(
                    "/osoosi/relay/1.0.0".to_string(),
                    key.public(),
                )),
            }
        })?
        .build();

    // 3. Listen on all interfaces
    swarm.listen_on("/ip4/0.0.0.0/tcp/4001".parse()?)?;

    info!("Relay is listening on Port 4001 and ready for anchored mesh peers.");

    while let Some(event) = swarm.next().await {
        match event {
            libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                info!("Local node is listening on {}", address);
            }
            libp2p::swarm::SwarmEvent::Behaviour(event) => {
                info!("Behaviour Event: {:?}", event);
            }
            _ => {}
        }
    }

    Ok(())
}

#[derive(libp2p::swarm::NetworkBehaviour)]
#[behaviour(out_event = "BehaviourEvent")]
struct Behaviour {
    relay: relay::Behaviour,
    identify: identify::Behaviour,
}

#[derive(Debug)]
enum BehaviourEvent {
    Relay(relay::Event),
    Identify(identify::Event),
}

impl From<relay::Event> for BehaviourEvent {
    fn from(event: relay::Event) -> Self {
        BehaviourEvent::Relay(event)
    }
}

impl From<identify::Event> for BehaviourEvent {
    fn from(event: identify::Event) -> Self {
        BehaviourEvent::Identify(event)
    }
}
