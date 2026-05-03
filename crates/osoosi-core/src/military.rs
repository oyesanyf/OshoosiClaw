use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};
use osoosi_types::{SysmonEvent, SysmonEventId, ResponseAction, ThreatSignature};
use tracing::warn;

/// MilitaryGuard: Tactical detection for asymmetric warfare patterns.
pub struct MilitaryGuard {
    /// P2P Whispering: Maps Source PID -> Set of internal unique Peer IPs
    peer_whispers: Arc<RwLock<HashMap<u32, HashSet<IpAddr>>>>,
    /// Loitering: Maps PID -> Process Start Time
    process_launch_times: Arc<RwLock<HashMap<u32, DateTime<Utc>>>>,
    /// Decoy Detection: Maps PID -> (Destination Count, Last Payload Hash, Similarity Score)
    decoy_trackers: Arc<RwLock<HashMap<u32, DecoyTracker>>>,
}

#[derive(Default)]
struct DecoyTracker {
    destinations: HashSet<IpAddr>,
    last_payload_hash: String,
    similarity_hits: u64,
}

impl MilitaryGuard {
    pub fn new() -> Self {
        Self {
            peer_whispers: Arc::new(RwLock::new(HashMap::new())),
            process_launch_times: Arc::new(RwLock::new(HashMap::new())),
            decoy_trackers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Analyze an event for tactical military-grade patterns.
    pub async fn analyze_event(&self, event: &SysmonEvent) -> Option<ThreatSignature> {
        match event.event_id {
            SysmonEventId::ProcessCreate => {
                let pid = event.process_id()?;
                self.process_launch_times.write().await.insert(pid, Utc::now());
                None
            }
            SysmonEventId::NetworkConnect => self.analyze_network_tactics(event).await,
            SysmonEventId::FileCreate | SysmonEventId::FileDeleteLogged => self.analyze_loitering_strike(event).await,
            _ => None,
        }
    }

    /// Tactical Network Analysis: Mesh Whispering and Decoy/Chaff detection.
    async fn analyze_network_tactics(&self, event: &SysmonEvent) -> Option<ThreatSignature> {
        let pid = event.process_id()?;
        let dest_ip_str = event.data.get("DestinationIp")?.as_str()?;
        let dest_ip: IpAddr = dest_ip_str.parse().ok()?;

        // 1. MESH WHISPERING DETECTION (MIL-SPEC)
        if dest_ip.is_loopback() || is_private_ip(dest_ip) {
            let mut whispers = self.peer_whispers.write().await;
            let peers = whispers.entry(pid).or_insert(HashSet::new());
            peers.insert(dest_ip);

            if peers.len() > 15 {
                return Some(ThreatSignature {
                    id: format!("MIL-MESH-{}", pid),
                    confidence: 0.9,
                    reason: Some(format!("Phantom Mesh Detected: Process (PID {}) is whispering to {} unique internal peers. Possible unauthorized P2P lateral movement.", pid, peers.len())),
                    recommended_action: ResponseAction::Isolate,
                    ..ThreatSignature::new("military".to_string())
                });
            }
        }

        // 2. ANTI-CHAFF / DECOY DETECTION (MIL-SPEC)
        let mut decoys = self.decoy_trackers.write().await;
        let tracker = decoys.entry(pid).or_insert(DecoyTracker::default());
        tracker.destinations.insert(dest_ip);
        
        // In a real EDR we would hash the actual packet payload. 
        // Here we use the DestinationPort as a proxy for 'pattern similarity'.
        let port = event.data.get("DestinationPort").and_then(|v| v.as_str()).unwrap_or("");
        if port == tracker.last_payload_hash {
            tracker.similarity_hits += 1;
        } else {
            tracker.last_payload_hash = port.to_string();
            tracker.similarity_hits = 0;
        }

        if tracker.destinations.len() > 100 && tracker.similarity_hits > 50 {
            return Some(ThreatSignature {
                id: format!("MIL-DECOY-{}", pid),
                confidence: 0.95,
                reason: Some(format!("Anti-Chaff Alert: Process (PID {}) is generating high-similarity traffic across {} destinations. Evasion/Blinding attempt detected.", pid, tracker.destinations.len())),
                recommended_action: ResponseAction::Isolate,
                ..ThreatSignature::new("military".to_string())
            });
        }

        None
    }

    /// Tactical Temporal Analysis: Sleeper-Strike (Loitering) detection.
    async fn analyze_loitering_strike(&self, event: &SysmonEvent) -> Option<ThreatSignature> {
        let pid = event.process_id()?;
        let launch_times = self.process_launch_times.read().await;
        
        if let Some(launch_time) = launch_times.get(&pid) {
            let duration = Utc::now() - *launch_time;
            
            // If the process has been 'loitering' for more than 4 hours and suddenly strikes
            if duration > Duration::hours(4) {
                let target = event.data.get("TargetFilename").and_then(|v| v.as_str()).unwrap_or("unknown");
                
                // Sensitive target detection
                if is_sensitive_target(target) {
                    return Some(ThreatSignature {
                        id: format!("MIL-LOITER-{}", pid),
                        confidence: 0.92,
                        reason: Some(format!("Sleeper-Strike Detected: Process (PID {}) loitered for {}h before attempting an Alpha Strike on sensitive target: {}.", pid, duration.num_hours(), target)),
                        recommended_action: ResponseAction::Isolate,
                        ..ThreatSignature::new("military".to_string())
                    });
                }
            }
        }
        None
    }
}

// --- Tactical Helpers ---

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => ipv4.is_private(),
        IpAddr::V6(_ipv6) => false, // Simplified for MIL-SPEC baseline
    }
}

fn is_sensitive_target(path: &str) -> bool {
    let p = path.to_lowercase();
    p.contains("\\windows\\system32\\config\\") || // Registry hives
    p.contains("\\lsass.exe") ||
    p.contains("\\etc\\shadow") ||
    p.contains(".ssh\\id_") ||
    p.contains("wallet.dat") ||
    p.contains("credentials")
}
