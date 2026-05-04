use libp2p::{
    core::upgrade,
    identify, noise, relay, tcp, yamux,
    Multiaddr, PeerId, Swarm, SwarmBuilder, Transport,
};
use libp2p_webrtc as _; // Just for completeness if needed later
use std::error::Error;
use std::time::Duration;
use futures::StreamExt;
use tracing::{info, Level};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    // 1. Create a fixed PeerId (or generate one)
    let local_key = libp2p::identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    info!("Starting Oshoosi Relay Node: {}", local_peer_id);

    // 2. Build the transport (TCP + WebSockets + Noise + Yamux)
    let transport = tcp::tokio::Transport::default()
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise::Config::new(&local_key)?)
        .multiplex(yamux::Config::default())
        .boxed();

    // 3. Define the Network Behaviour
    #[derive(libp2p::swarm::NetworkBehaviour)]
    struct Behaviour {
        relay: relay::Behaviour,
        identify: identify::Behaviour,
    }

    let behaviour = Behaviour {
        relay: relay::Behaviour::new(local_peer_id, Default::default()),
        identify: identify::Behaviour::new(identify::Config::new(
            "/osoosi/relay/1.0.0".to_string(),
            local_key.public(),
        )),
    };

    // 4. Create the Swarm
    let mut swarm = SwarmBuilder::with_tokio_executor(transport, behaviour, local_peer_id).build();

    // 5. Listen on all interfaces (TCP 4001 for peers, 443/8080 for WS)
    swarm.listen_on("/ip4/0.0.0.0/tcp/4001".parse()?)?;
    // WS support would usually be handled via a proxy or libp2p-websocket
    // In this tiny version, we focus on the core relay capability.

    info!("Relay is listening and ready for anchored mesh peers.");

    loop {
        match swarm.select_next_some().await {
            libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                info!("Local node is listening on {}", address);
            }
            libp2p::swarm::SwarmEvent::Behaviour(BehaviourEvent::Relay(e)) => {
                info!("Relay Event: {:?}", e);
            }
            _ => {}
        }
    }
}
