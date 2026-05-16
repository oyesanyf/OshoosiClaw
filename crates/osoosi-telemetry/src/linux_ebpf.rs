#[cfg(target_os = "linux")]
use aya::maps::{MapData, RingBuf};
#[cfg(target_os = "linux")]
use aya::programs::{TracePoint, KProbe};
#[cfg(target_os = "linux")]
use aya::Ebpf;
use osoosi_types::HostSecurityEvent;
use tokio::sync::mpsc;
#[cfg(target_os = "linux")]
use osoosi_types::HostEventSource;
#[cfg(target_os = "linux")]
use tracing::{error, info, warn};
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use chrono::Utc;

#[cfg(target_os = "linux")]
pub struct EbpfTelemetryEngine {
    tx: mpsc::Sender<HostSecurityEvent>,
    shutdown: Arc<AtomicBool>,
}

#[cfg(target_os = "linux")]
impl EbpfTelemetryEngine {
    pub fn new(tx: mpsc::Sender<HostSecurityEvent>) -> Self {
        Self {
            tx,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        info!("🚀 [LINUX-EBPF] Starting Oshoosi eBPF Telemetry Engine...");

        // In a real implementation, we would use aya::include_bytes_aligned! 
        // with the compiled eBPF object from rustinel.
        // For now, we assume the user will provide the .o file or we stub it.
        
        let ebpf_path = std::env::var("OSOOSI_EBPF_OBJECT").unwrap_or_else(|_| "osoosi-ebpf.o".to_string());
        let bytes = match std::fs::read(&ebpf_path) {
            Ok(b) => b,
            Err(_) => {
                warn!("eBPF object not found at {}. Linux eBPF telemetry disabled.", ebpf_path);
                return Ok(());
            }
        };

        let mut bpf = Ebpf::load(&bytes)?;

        // Attach tracepoints (adapted from Rustinel)
        self.attach_tracepoint(&mut bpf, "handle_exec", "sched", "sched_process_exec")?;
        self.attach_tracepoint(&mut bpf, "handle_exit", "sched", "sched_process_exit")?;
        self.attach_tracepoint(&mut bpf, "handle_connect", "syscalls", "sys_enter_connect")?;

        let process_ring: RingBuf<MapData> = RingBuf::try_from(bpf.take_map("PROCESS_RING").unwrap())?;
        let network_ring: RingBuf<MapData> = RingBuf::try_from(bpf.take_map("NETWORK_RING").unwrap())?;

        let tx = self.tx.clone();
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            let _bpf = bpf; // Keep alive
            let mut process_fd = tokio::io::unix::AsyncFd::new(process_ring).unwrap();
            let mut network_fd = tokio::io::unix::AsyncFd::new(network_ring).unwrap();

            loop {
                if shutdown.load(Ordering::Relaxed) { break; }

                tokio::select! {
                    Ok(mut guard) = process_fd.readable_mut() => {
                        let rb = guard.get_inner_mut();
                        while let Some(item) = rb.next() {
                            if let Some(ev) = parse_process_event(&item) {
                                let _ = tx.send(ev).await;
                            }
                        }
                        guard.clear_ready();
                    }
                    Ok(mut guard) = network_fd.readable_mut() => {
                        let rb = guard.get_inner_mut();
                        while let Some(item) = rb.next() {
                            if let Some(ev) = parse_network_event(&item) {
                                let _ = tx.send(ev).await;
                            }
                        }
                        guard.clear_ready();
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
                }
            }
        });

        Ok(())
    }

    fn attach_tracepoint(&self, bpf: &mut Ebpf, prog_name: &str, category: &str, name: &str) -> anyhow::Result<()> {
        let prog: &mut TracePoint = bpf.program_mut(prog_name).unwrap().try_into()?;
        prog.load()?;
        prog.attach(category, name)?;
        Ok(())
    }
}

// Minimal event parsing (adapted from Rustinel's events.rs)
#[cfg(target_os = "linux")]
fn parse_process_event(bytes: &[u8]) -> Option<HostSecurityEvent> {
    if bytes.len() < 16 + 128 + 16 { return None; }
    
    // Simplification: Rustinel uses fixed layouts.
    // In production, we'd use the exact structs from ebpf/src/events.rs
    let kind = u32::from_ne_bytes(bytes[0..4].try_into().ok()?);
    let pid = u32::from_ne_bytes(bytes[4..8].try_into().ok()?);
    let uid = u32::from_ne_bytes(bytes[8..12].try_into().ok()?);
    
    let comm_bytes = &bytes[16..32];
    let image_bytes = &bytes[32..160];
    
    let comm = String::from_utf8_lossy(comm_bytes).trim_matches('\0').to_string();
    let image = String::from_utf8_lossy(image_bytes).trim_matches('\0').to_string();

    let mut data = serde_json::Map::new();
    data.insert("ProcessId".to_string(), serde_json::json!(pid));
    data.insert("Image".to_string(), serde_json::json!(image));
    data.insert("User".to_string(), serde_json::json!(uid));
    data.insert("CommandLine".to_string(), serde_json::json!(comm));

    Some(HostSecurityEvent {
        source: HostEventSource::Ebpf,
        event_id: if kind == 1 { 1 } else { 5 },
        timestamp: Utc::now(),
        computer: "localhost".to_string(), // In production, resolve host
        data: serde_json::Value::Object(data),
        causal_parent: None,
    })
}

#[cfg(target_os = "linux")]
fn parse_network_event(bytes: &[u8]) -> Option<HostSecurityEvent> {
    // Similar to above, adapt the NetworkEvent struct
    None
}

// Stub for non-linux to allow compilation
#[cfg(not(target_os = "linux"))]
pub struct EbpfTelemetryEngine;

#[cfg(not(target_os = "linux"))]
impl EbpfTelemetryEngine {
    pub fn new(_tx: mpsc::Sender<HostSecurityEvent>) -> Self { Self }
    pub async fn run(&self) -> anyhow::Result<()> { Ok(()) }
}
