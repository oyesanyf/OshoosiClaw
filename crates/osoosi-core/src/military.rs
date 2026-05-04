use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};
use osoosi_types::{SysmonEvent, SysmonEventId, ResponseAction, ThreatSignature};

/// MilitaryGuard: Tactical detection for asymmetric warfare patterns.
/// 
/// Translates drone concepts (Geran-2E) into EDR heuristics:
/// - Mesh Networking: Detecting workstation-to-workstation P2P whispers.
/// - Loitering: Detecting idle processes that perform "Alpha Strikes".
/// - Decoy Detection: Detecting masqueraded system processes (Windows/Linux/macOS).
pub struct MilitaryGuard {
    /// P2P Whispering: Maps Source PID -> Set of internal unique Peer IPs
    peer_map: Arc<RwLock<HashMap<u32, HashSet<String>>>>,
    /// Loitering: Maps PID -> Process Start Time
    process_start_times: Arc<RwLock<HashMap<u32, DateTime<Utc>>>>,
    /// Decoy Detection: Maps PID -> Tracker for high-entropy chaff traffic
    decoy_trackers: Arc<RwLock<HashMap<u32, DecoyTracker>>>,
}

#[derive(Default)]
struct DecoyTracker {
    destinations: HashSet<String>,
    similarity_hits: u64,
}

impl MilitaryGuard {
    pub fn new() -> Self {
        Self {
            peer_map: Arc::new(RwLock::new(HashMap::new())),
            process_start_times: Arc::new(RwLock::new(HashMap::new())),
            decoy_trackers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Main entry point for tactical analysis of a telemetry event.
    pub async fn analyze_event(&self, event: &SysmonEvent) -> Option<ThreatSignature> {
        match event.event_id {
            SysmonEventId::NetworkConnect => self.analyze_network_tactics(event).await,
            SysmonEventId::FileCreate | SysmonEventId::FileDeleteLogged => self.analyze_loitering_strike(event).await,
            SysmonEventId::ProcessCreate => {
                let pid = event.process_id().unwrap_or(0);
                if pid != 0 {
                    self.process_start_times.write().await.insert(pid, Utc::now());
                }
                self.analyze_process_legitimacy(event).await
            },
            _ => None,
        }
    }

    /// 1. Mesh Networking: Detecting P2P "Whispering"
    async fn analyze_network_tactics(&self, event: &SysmonEvent) -> Option<ThreatSignature> {
        let pid = event.process_id()?;
        let dest_ip = event.data.get("DestinationIp")?.as_str()?;
        let dest_port = event.data.get("DestinationPort").and_then(|v| v.as_u64()).unwrap_or(0);

        // --- MESH DETECTION (P2P Whispering) ---
        if is_private_ip(dest_ip) {
            let mut peer_map = self.peer_map.write().await;
            let peers = peer_map.entry(pid).or_insert_with(HashSet::new);
            peers.insert(dest_ip.to_string());

            // Threshold: Workstation talking to > 10 internal neighbors (mesh behavior)
            if peers.len() > 10 {
                return Some(ThreatSignature {
                    id: format!("MIL-MESH-{}", pid),
                    confidence: 0.95,
                    reason: Some(format!("Phantom Mesh Detected: Process (PID {}) is whispering to {} unique internal peers. Possible P2P lateral movement.", pid, peers.len())),
                    recommended_action: ResponseAction::Isolate,
                    ..ThreatSignature::new("military".to_string())
                });
            }
        }

        // --- DECOY DETECTION (Chaff/Noise Evasion) ---
        let mut decoy_trackers = self.decoy_trackers.write().await;
        let tracker = decoy_trackers.entry(pid).or_insert_with(DecoyTracker::default);
        tracker.destinations.insert(dest_ip.to_string());
        
        // High-similarity traffic on standard ports (C2 masking as HTTPS)
        if dest_port == 443 || dest_port == 80 {
             tracker.similarity_hits += 1;
        }

        if tracker.destinations.len() > 100 && tracker.similarity_hits > 200 {
            return Some(ThreatSignature {
                id: format!("MIL-CHAFF-{}", pid),
                confidence: 0.90,
                reason: Some(format!("Anti-Chaff Alert: Process (PID {}) generating high-volume decoy traffic ({} destinations). Blinding attempt detected.", pid, tracker.destinations.len())),
                recommended_action: ResponseAction::Isolate,
                ..ThreatSignature::new("military".to_string())
            });
        }

        None
    }

    /// 2. Loitering: Behavioral Anomaly Detection (LotL)
    async fn analyze_loitering_strike(&self, event: &SysmonEvent) -> Option<ThreatSignature> {
        let pid = event.process_id()?;
        let target = event.data.get("TargetFilename")?.as_str()?;

        let loiter_map = self.process_start_times.read().await;
        if let Some(start_time) = loiter_map.get(&pid) {
            let duration = Utc::now() - *start_time;

            // Threshold: Process idle for > 1 hour then strikes sensitive files (LotL persistence)
            if duration > Duration::hours(1) && is_sensitive_target(target) {
                return Some(ThreatSignature {
                    id: format!("MIL-LOITER-{}", pid),
                    confidence: 0.92,
                    reason: Some(format!("Sleeper-Strike: Process (PID {}) loitered for {}h before attempting an Alpha Strike on sensitive target: {}.", pid, duration.num_hours(), target)),
                    recommended_action: ResponseAction::Isolate,
                    ..ThreatSignature::new("military".to_string())
                });
            }
        }

        None
    }

    /// 3. Decoys: Detecting "Phantom" Processes (Windows/Linux/macOS)
    async fn analyze_process_legitimacy(&self, event: &SysmonEvent) -> Option<ThreatSignature> {
        let pid = event.process_id()?;
        let image_path = event.data.get("Image")?.as_str()?.to_lowercase();
        let process_name = image_path.split('\\').last()?.split('/').last()?.to_lowercase();

        // --- WINDOWS: Phantom System Process Detection ---
        #[cfg(target_os = "windows")]
        {
            let critical_procs = ["svchost.exe", "lsass.exe", "wininit.exe", "services.exe", "csrss.exe"];
            if critical_procs.contains(&process_name.as_str()) {
                if !image_path.contains("system32") && !image_path.contains("syswow64") {
                    return Some(ThreatSignature {
                        id: format!("MIL-DECOY-PROC-{}", pid),
                        confidence: 1.0,
                        reason: Some(format!("Decoy Detected: System process '{}' running from unauthorized location: {}. Tactical masquerading attempt.", process_name, image_path)),
                        recommended_action: ResponseAction::Isolate,
                        ..ThreatSignature::new("military".to_string())
                    });
                }
            }
        }

        // --- LINUX/macOS: Hidden/Stealthy Execution ---
        #[cfg(not(target_os = "windows"))]
        {
            if process_name.starts_with('.') || image_path.contains("/tmp/") || image_path.contains("/dev/shm/") {
                return Some(ThreatSignature {
                    id: format!("MIL-STEALTH-PROC-{}", pid),
                    confidence: 0.85,
                    reason: Some(format!("Tactical Evasion: Process '{}' executing from stealthy memory-backed or hidden path: {}.", process_name, image_path)),
                    recommended_action: ResponseAction::Isolate,
                    ..ThreatSignature::new("military".to_string())
                });
            }
        }

        None
    }
}

/// Helper: Identify sensitive targets for loitering detection
fn is_sensitive_target(path: &str) -> bool {
    let p = path.to_lowercase();
    p.contains("lsass") || 
    p.contains("config\\sam") || 
    p.contains(".ssh\\") || 
    p.contains("/etc/shadow") || 
    p.contains("ntds.dit") || 
    p.contains("wallet")
}

/// Helper: Identify private IP ranges for mesh detection
fn is_private_ip(ip: &str) -> bool {
    ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("172.16.") || ip == "127.0.0.1" || ip == "::1"
}
