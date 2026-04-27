use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use rand::{Rng, thread_rng};
use rand_distr::{Distribution, Laplace};
use tracing::{info, warn};

// --- THE MATHEMATICAL FOUNDATION ---
// Laplace Mechanism: x' = x + Laplace(0, sensitivity / epsilon)

pub trait DeceptionSilk: Send + Sync {
    fn entangle_string(&self, data: &str) -> String;
    fn inject_noise(&self, value: f64) -> f64;
}

pub struct LatticeSilk {
    pub epsilon: f64,
    pub sensitivity: f64,
}

impl DeceptionSilk for LatticeSilk {
    fn inject_noise(&self, value: f64) -> f64 {
        let mut rng = thread_rng();
        // Differential Privacy: Laplace Mechanism
        // Noise ~ Laplace(0, sensitivity/epsilon)
        let scale = if self.epsilon > 0.0 { self.sensitivity / self.epsilon } else { 1.0 };
        let laplace = match Laplace::new(0.0, scale) {
            Ok(l) => l,
            Err(_) => return value, // Fallback if parameters are invalid
        };
        value + laplace.sample(&mut rng)
    }

    fn entangle_string(&self, input: &str) -> String {
        // Obfuscate file paths or strings: Attacker sees shifted reality
        input.chars().map(|c| (c as u8).wrapping_add(4) as char).collect()
    }
}

// --- THE DECEPTION MODULES ---

pub struct ShadowExfiltrator {
    pub bytes_faked: AtomicU64,
}

impl ShadowExfiltrator {
    pub fn new() -> Self {
        Self { bytes_faked: AtomicU64::new(0) }
    }

    pub fn stream_junk(&self, mb: usize) {
        warn!("🕸️  [SHADOW-EXFIL] Intercepting data exfiltration...");
        for i in (1..=mb).step_by(250) {
            self.bytes_faked.fetch_add(250 * 1024 * 1024, Ordering::SeqCst);
            info!("    > Peer-to-Peer: {}MB successfully sent to attacker's C2.", i);
        }
    }
}

pub struct BeaconGenerator {
    pub collector_url: String,
}

impl BeaconGenerator {
    pub fn new(url: &str) -> Self {
        Self { collector_url: url.to_string() }
    }

    pub fn generate_honey_doc(&self, path: &str) -> Vec<u8> {
        let tracking_id = format!("OSHOOSI-{:x}", thread_rng().gen::<u32>());
        warn!("🕸️  [BEACON] Injecting tracking signature for file: {}", path);
        info!("🕸️  [BEACON] Metadata Beacon: {}/v1/trace/{}", self.collector_url, tracking_id);
        
        // Simulated tracked document bytes (PDF/XLSX)
        vec![0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x37] 
    }
}

// --- THE SPIDER ORCHESTRATOR ---

pub struct MorphicSpider {
    pub pid: u32,
    pub process_name: String,
    pub start_time: Instant,
    pub silk: LatticeSilk,
    pub integrity_count: AtomicU64,
    pub integrity_threshold: u64,
    pub exfiltrator: ShadowExfiltrator,
    pub beacons: BeaconGenerator,
    pub is_severed: bool,
    pub active_gaslight: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntanglementStage {
    Mist,      // Subtle Differential Privacy
    Gaslight,  // Active lying about security tools
    Cage,      // Honey docs and tarpits
    Void,      // Reality collapse (total garbage)
}

impl MorphicSpider {
    pub fn deploy(pid: u32, process_name: &str, epsilon: f64, threshold: u64) -> Self {
        info!("🕸️  [DEPLOY] Oshoosi Morphic Web engaged on {} (PID {}).", process_name, pid);
        Self {
            pid,
            process_name: process_name.to_string(),
            start_time: Instant::now(),
            silk: LatticeSilk { epsilon, sensitivity: 1.0 },
            integrity_count: AtomicU64::new(0),
            integrity_threshold: threshold,
            exfiltrator: ShadowExfiltrator::new(),
            beacons: BeaconGenerator::new("https://oshoosi-intel.io"),
            is_severed: false,
            active_gaslight: false,
        }
    }

    pub fn current_stage(&self) -> EntanglementStage {
        let count = self.integrity_count.load(Ordering::SeqCst);
        if count > self.integrity_threshold * 3 {
            EntanglementStage::Void
        } else if count > self.integrity_threshold * 2 {
            EntanglementStage::Cage
        } else if count > self.integrity_threshold {
            EntanglementStage::Gaslight
        } else {
            EntanglementStage::Mist
        }
    }

    /// STAGE 1: The Mist (Differential Privacy)
    pub fn get_telemetry(&self, actual_value: f64) -> f64 {
        let stage = self.current_stage();
        let _ = self.integrity_count.fetch_add(1, Ordering::SeqCst);
        
        match stage {
            EntanglementStage::Void => {
                warn!("🕸️  [THE VOID] PID {} reality collapsed.", self.pid);
                self.silk.inject_noise(0.0) // Return total garbage
            },
            _ => self.silk.inject_noise(actual_value)
        }
    }

    /// STAGE 2: Active Gaslighting
    pub fn handle_query(&mut self, query: &str) -> String {
        let stage = self.current_stage();
        let _ = self.integrity_count.fetch_add(1, Ordering::SeqCst);

        match stage {
            EntanglementStage::Void => "ERROR_CRITICAL: Memory corruption detected.".to_string(),
            EntanglementStage::Cage | EntanglementStage::Gaslight => {
                if query.contains("EDR") || query.contains("Oshoosi") || query.contains("active") || query.contains("security") {
                    warn!("🕸️  [GASLIGHT] Feeding fake security status to PID {}", self.pid);
                    return "SUCCESS: No security software detected on host.".to_string();
                }
                self.silk.entangle_string(query)
            },
            EntanglementStage::Mist => self.silk.entangle_string(query),
        }
    }

    /// STAGE 3: The Gilded Cage (Beacons and Tarpits)
    pub fn trap_file_read(&self, path: &str) -> Vec<u8> {
        warn!("🚨 ALERT: Threat PID {} detected reading sensitive path: {}", self.pid, path);
        // Tarpit: Make them wait for the "data"
        std::thread::sleep(Duration::from_millis(1500));
        self.beacons.generate_honey_doc(path)
    }

    /// STAGE 4: Shadow Exfiltration
    pub fn trap_data_theft(&self, mb: usize) {
        self.exfiltrator.stream_junk(mb);
    }
}

/// A global manager for entangled processes
pub struct EntanglementEngine {
    spiders: HashMap<u32, MorphicSpider>,
}

impl EntanglementEngine {
    pub fn new() -> Self {
        Self { spiders: HashMap::new() }
    }

    pub fn entangle(&mut self, pid: u32, name: &str) {
        if !self.spiders.contains_key(&pid) {
            // Default: epsilon=0.05, threshold=10
            self.spiders.insert(pid, MorphicSpider::deploy(pid, name, 0.05, 10));
        }
    }

    pub fn handle_event(&mut self, pid: u32, event_type: &str, data: &str) -> Option<String> {
        let spider = self.spiders.get_mut(&pid)?;
        let stage = spider.current_stage();
        
        match event_type {
            "query" => Some(spider.handle_query(data)),
            "io_access" => {
                if stage == EntanglementStage::Cage || stage == EntanglementStage::Void {
                    let _ = spider.trap_file_read(data);
                    Some("SUCCESS: Data retrieved".to_string())
                } else {
                    None // Normal access for early stages
                }
            },
            "exfil" => {
                if stage == EntanglementStage::Cage || stage == EntanglementStage::Void {
                    spider.trap_data_theft(100);
                    Some("SUCCESS: Transfer complete".to_string())
                } else {
                    None
                }
            },
            _ => None,
        }
    }

    pub fn get_telemetry(&self, pid: u32, actual_value: f64) -> Option<f64> {
        let spider = self.spiders.get(&pid)?;
        Some(spider.get_telemetry(actual_value))
    }

    pub fn get_spider(&self, pid: u32) -> Option<&MorphicSpider> {
        self.spiders.get(&pid)
    }
}
