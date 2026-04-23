use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use osoosi_types::SysmonEvent;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    pub pid: u32,
    pub parent_pid: u32,
    pub image: String,
    pub command_line: String,
    pub start_time: DateTime<Utc>,
    pub score: f32,
    pub events: Vec<String>,
}

pub struct CausalEngine {
    /// PID -> ProcessNode
    processes: Arc<RwLock<HashMap<u32, ProcessNode>>>,
    /// Track lineage chains for high-risk processes
    #[allow(dead_code)]
    lineage_cache: Arc<RwLock<HashMap<u32, Vec<u32>>>>,
}

impl CausalEngine {
    pub fn new() -> Self {
        Self {
            processes: Arc::new(RwLock::new(HashMap::new())),
            lineage_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn ingest_event(&self, event: &SysmonEvent) {
        let mut processes = self.processes.write().unwrap();
        
        use osoosi_types::SysmonEventId::*;
        match event.event_id {
            ProcessCreate => {
                let pid = event.data.get("ProcessId").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
                let ppid = event.data.get("ParentProcessId").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
                let image = event.data.get("Image").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let cmd = event.data.get("CommandLine").and_then(|v| v.as_str()).unwrap_or("").to_string();
                
                processes.insert(pid, ProcessNode {
                    pid,
                    parent_pid: ppid,
                    image,
                    command_line: cmd,
                    start_time: Utc::now(),
                    score: 0.0,
                    events: Vec::new(),
                });
            }
            FileCreateTimeChange => {
                let pid = event.data.get("ProcessId").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
                if let Some(node) = processes.get_mut(&pid) {
                    node.events.push("Timestomping detected (FileCreateTimeChange)".to_string());
                    node.score += 0.4;
                }
            }
            NetworkConnect => {
                let pid = event.data.get("ProcessId").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
                if let Some(node) = processes.get_mut(&pid) {
                    node.events.push(format!("Network: {}", event.data.get("DestinationIp").and_then(|v| v.as_str()).unwrap_or("?")));
                    node.score += 0.15;
                }
            }
            SysmonServiceState => {} // Audit only
            ProcessTerminate => {
                let pid = event.data.get("ProcessId").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
                processes.remove(&pid);
            }
            DriverLoad => {
                let pid = event.data.get("ProcessId").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
                if let Some(node) = processes.get_mut(&pid) {
                    node.events.push(format!("Driver Loaded: {}", event.data.get("ImageLoaded").and_then(|v| v.as_str()).unwrap_or("?")));
                    node.score += 0.8;
                }
            }
            ImageLoad => {
                let pid = event.data.get("ProcessId").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
                if let Some(node) = processes.get_mut(&pid) {
                    node.score += 0.02; // Small increment for DLL loads
                }
            }
            CreateRemoteThread => {
                let pid = event.data.get("SourceProcessId").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
                if let Some(node) = processes.get_mut(&pid) {
                    node.events.push("CRITICAL: CreateRemoteThread (Injection)".to_string());
                    node.score += 1.5;
                }
            }
            RawAccessRead => {
                let pid = event.data.get("ProcessId").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
                if let Some(node) = processes.get_mut(&pid) {
                    node.events.push("CRITICAL: RawAccessRead (Disk Bypass)".to_string());
                    node.score += 1.2;
                }
            }
            ProcessAccess => {
                let pid = event.data.get("SourceProcessId").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
                if let Some(node) = processes.get_mut(&pid) {
                    node.score += 0.3;
                }
            }
            FileCreate => {
                let pid = event.data.get("ProcessId").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
                if let Some(node) = processes.get_mut(&pid) {
                    node.events.push(format!("File Create: {}", event.data.get("TargetFilename").and_then(|v| v.as_str()).unwrap_or("?")));
                    node.score += 0.05;
                }
            }
            RegistryAddDelete | RegistryValueSet | RegistryRename => {
                let pid = event.data.get("ProcessId").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
                if let Some(node) = processes.get_mut(&pid) {
                    node.events.push(format!("Registry Modify: {}", event.data.get("TargetObject").and_then(|v| v.as_str()).unwrap_or("?")));
                    node.score += 0.2;
                }
            }
            FileCreateStreamHash => {
                let pid = event.data.get("ProcessId").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
                if let Some(node) = processes.get_mut(&pid) {
                    node.events.push("ADS Created (FileCreateStreamHash)".to_string());
                    node.score += 0.4;
                }
            }
            SysmonConfigChange => {
                 let pid = event.data.get("ProcessId").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
                if let Some(node) = processes.get_mut(&pid) {
                    node.events.push("Sysmon Config Tamper Detected".to_string());
                    node.score += 1.0;
                }
            }
            PipeCreated | PipeConnected => {
                let pid = event.data.get("ProcessId").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
                if let Some(node) = processes.get_mut(&pid) {
                    node.score += 0.15;
                }
            }
            WmiEventFilter | WmiEventConsumer | WmiConsumerBinding => {
                let pid = event.data.get("ProcessId").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
                if let Some(node) = processes.get_mut(&pid) {
                    node.events.push("WMI Persistence Activity".to_string());
                    node.score += 0.7;
                }
            }
            DnsQuery => {
                let pid = event.data.get("ProcessId").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
                if let Some(node) = processes.get_mut(&pid) {
                    node.events.push(format!("DNS Query: {}", event.data.get("QueryName").and_then(|v| v.as_str()).unwrap_or("?")));
                    node.score += 0.1;
                }
            }
            FileDeleteArchived => {
                let pid = event.data.get("ProcessId").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
                if let Some(node) = processes.get_mut(&pid) {
                    node.score += 0.2;
                }
            }
            ClipboardChange => {
                let pid = event.data.get("ProcessId").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
                if let Some(node) = processes.get_mut(&pid) {
                    node.events.push("Clipboard Sniffing Detected".to_string());
                    node.score += 0.5;
                }
            }
            ProcessTampering => {
                let pid = event.data.get("ProcessId").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
                if let Some(node) = processes.get_mut(&pid) {
                    node.events.push("CRITICAL: Process Tampering (Hollowing/Herpaderping)".to_string());
                    node.score += 2.0;
                }
            }
            FileDeleteLogged => {}
            FileBlockExecutable | FileBlockShredding => {
                let pid = event.data.get("ProcessId").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
                if let Some(node) = processes.get_mut(&pid) {
                    node.score += 0.1;
                }
            }
            FileExecutableDetected => {
                let pid = event.data.get("ProcessId").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
                if let Some(node) = processes.get_mut(&pid) {
                    node.events.push("New Executable Detected".to_string());
                    node.score += 0.3;
                }
            }
            SysmonError => {}
            Generic => {}
        }
    }

    /// Returns the full ancestry of a process
    pub fn get_ancestry(&self, pid: u32) -> Vec<ProcessNode> {
        let processes = self.processes.read().unwrap();
        let mut ancestry = Vec::new();
        let mut current_pid = pid;

        while let Some(node) = processes.get(&current_pid) {
            ancestry.push(node.clone());
            if current_pid == node.parent_pid || node.parent_pid == 0 {
                break;
            }
            current_pid = node.parent_pid;
            if ancestry.len() > 10 { break; } // Safety break
        }
        ancestry
    }

    /// Predict the "Next Step" based on current chain
    pub fn predict_next_step(&self, pid: u32) -> Option<String> {
        let ancestry = self.get_ancestry(pid);
        if ancestry.is_empty() { return None; }

        let chain: Vec<String> = ancestry.iter().map(|n| {
            std::path::Path::new(&n.image)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(&n.image)
                .to_lowercase()
        }).collect();

        // 10/10 Logic: Causal Prediction Patterns
        if chain.contains(&"powershell.exe".to_string()) && chain.contains(&"excel.exe".to_string()) {
            return Some("Credential Dumping / Ransomware Deployment".to_string());
        }
        if chain.contains(&"certutil.exe".to_string()) && chain.contains(&"cmd.exe".to_string()) {
            return Some("Stage 2 Payload Download".to_string());
        }
        if chain.contains(&"wsmprovhost.exe".to_string()) {
            return Some("Lateral Movement via WinRM".to_string());
        }

        None
    }

    /// Calculate a "Causal Risk Score"
    pub fn calculate_risk_score(&self, pid: u32) -> f32 {
        let ancestry = self.get_ancestry(pid);
        let mut total_score = 0.0;
        
        for node in &ancestry {
            total_score += node.score;
            
            // Heuristic multipliers
            if node.image.to_lowercase().contains("powershell") { total_score += 0.5; }
            if node.image.to_lowercase().contains("mimikatz") { total_score += 2.0; }
            if node.command_line.contains("-enc") { total_score += 0.3; }
        }

        total_score
    }
}
