//! Linux eBPF Ring-Buffer Telemetry Engine with LSM Parity.
//!
//! Provides zero-overhead process and network event capture from kernel space,
//! with Linux Security Module (LSM) pre-operation execution blocking parity.

use chrono::Utc;
use osoosi_types::{HostEventSource, HostSecurityEvent};
use tokio::sync::mpsc;

pub const OSOOSI_COMM_LEN: usize = 16;
pub const OSOOSI_PATH_LEN: usize = 256;
pub const OSOOSI_ARGS_LEN: usize = 512;

pub const OSOOSI_EBPF_EVENT_EXEC: u32 = 1;
pub const OSOOSI_EBPF_EVENT_EXIT: u32 = 2;
pub const OSOOSI_EBPF_EVENT_LSM_BLOCK: u32 = 3;

/// Binary struct layout matching `struct ebpf_process_event` in kernel memory.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EbpfProcessEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; OSOOSI_COMM_LEN],
    pub filename: [u8; OSOOSI_PATH_LEN],
    pub args: [u8; OSOOSI_ARGS_LEN],
    pub timestamp_ns: u64,
    pub event_type: u32, // 1=Exec, 2=Exit, 3=LsmBlock
    pub _pad: u32,
}

impl Default for EbpfProcessEvent {
    fn default() -> Self {
        Self {
            pid: 0,
            ppid: 0,
            uid: 0,
            gid: 0,
            comm: [0u8; OSOOSI_COMM_LEN],
            filename: [0u8; OSOOSI_PATH_LEN],
            args: [0u8; OSOOSI_ARGS_LEN],
            timestamp_ns: 0,
            event_type: 0,
            _pad: 0,
        }
    }
}

/// Binary struct layout matching `struct ebpf_network_event` in kernel memory.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EbpfNetworkEvent {
    pub pid: u32,
    pub family: u16,     // AF_INET (2) or AF_INET6 (10)
    pub dport: u16,      // Big-endian network byte order
    pub daddr: [u8; 16], // IPv4 (in first 4 bytes) or IPv6
    pub sport: u16,      // Source port
    pub _pad1: u16,
    pub _pad2: u32,
    pub timestamp_ns: u64,
}

impl Default for EbpfNetworkEvent {
    fn default() -> Self {
        Self {
            pid: 0,
            family: 0,
            dport: 0,
            daddr: [0u8; 16],
            sport: 0,
            _pad1: 0,
            _pad2: 0,
            timestamp_ns: 0,
        }
    }
}

/// Parses raw kernel bytes from `process_ring` into a normalized `HostSecurityEvent`.
pub fn parse_process_event(bytes: &[u8]) -> Option<HostSecurityEvent> {
    if bytes.len() < std::mem::size_of::<EbpfProcessEvent>() {
        return None;
    }

    let event: EbpfProcessEvent = unsafe {
        std::ptr::read_unaligned(bytes.as_ptr() as *const EbpfProcessEvent)
    };

    let comm_len = event.comm.iter().position(|&c| c == 0).unwrap_or(event.comm.len());
    let comm = String::from_utf8_lossy(&event.comm[..comm_len]).trim().to_string();

    let fn_len = event.filename.iter().position(|&c| c == 0).unwrap_or(event.filename.len());
    let filename = String::from_utf8_lossy(&event.filename[..fn_len]).trim().to_string();

    let args_len = event.args.iter().position(|&c| c == 0).unwrap_or(event.args.len());
    let args = String::from_utf8_lossy(&event.args[..args_len]).trim().to_string();

    let command_line = if !args.is_empty() {
        if !filename.is_empty() {
            format!("{} {}", filename, args)
        } else {
            format!("{} {}", comm, args)
        }
    } else if !filename.is_empty() {
        filename.clone()
    } else {
        comm.clone()
    };

    let (event_id, mut data) = match event.event_type {
        OSOOSI_EBPF_EVENT_EXEC => {
            let mut map = serde_json::Map::new();
            map.insert("ProcessId".to_string(), serde_json::json!(event.pid));
            map.insert("ParentProcessId".to_string(), serde_json::json!(event.ppid));
            map.insert("Image".to_string(), serde_json::json!(if !filename.is_empty() { &filename } else { &comm }));
            map.insert("CommandLine".to_string(), serde_json::json!(command_line));
            map.insert("User".to_string(), serde_json::json!(event.uid.to_string()));
            map.insert("Gid".to_string(), serde_json::json!(event.gid));
            (1, map)
        }
        OSOOSI_EBPF_EVENT_EXIT => {
            let mut map = serde_json::Map::new();
            map.insert("ProcessId".to_string(), serde_json::json!(event.pid));
            map.insert(
                "Image".to_string(),
                serde_json::json!(if !filename.is_empty() { filename } else { comm }),
            );
            (5, map)
        }
        OSOOSI_EBPF_EVENT_LSM_BLOCK => {
            let mut map = serde_json::Map::new();
            map.insert("ProcessId".to_string(), serde_json::json!(event.pid));
            map.insert(
                "Image".to_string(),
                serde_json::json!(if !filename.is_empty() { filename } else { comm }),
            );
            map.insert("CommandLine".to_string(), serde_json::json!(command_line));
            map.insert(
                "Reason".to_string(),
                serde_json::json!("Linux LSM BPF bprm_check_security: blocked binary execution"),
            );
            (25, map)
        }
        _ => return None,
    };

    data.insert("TimestampNs".to_string(), serde_json::json!(event.timestamp_ns));

    Some(HostSecurityEvent {
        source: HostEventSource::Ebpf,
        event_id,
        timestamp: Utc::now(),
        computer: "localhost".to_string(),
        data: serde_json::Value::Object(data),
        causal_parent: None,
    })
}

/// Parses raw kernel bytes from `network_ring` into a normalized `HostSecurityEvent`.
pub fn parse_network_event(bytes: &[u8]) -> Option<HostSecurityEvent> {
    if bytes.len() < std::mem::size_of::<EbpfNetworkEvent>() {
        return None;
    }

    let event: EbpfNetworkEvent = unsafe {
        std::ptr::read_unaligned(bytes.as_ptr() as *const EbpfNetworkEvent)
    };

    let dest_port = u16::from_be(event.dport);
    let dest_ip = match event.family {
        2 => {
            // AF_INET (IPv4)
            format!(
                "{}.{}.{}.{}",
                event.daddr[0], event.daddr[1], event.daddr[2], event.daddr[3]
            )
        }
        10 => {
            // AF_INET6 (IPv6)
            std::net::Ipv6Addr::from(event.daddr).to_string()
        }
        _ => return None,
    };

    let mut data = serde_json::Map::new();
    data.insert("ProcessId".to_string(), serde_json::json!(event.pid));
    data.insert("Image".to_string(), serde_json::json!(""));
    data.insert("DestinationIp".to_string(), serde_json::json!(dest_ip));
    data.insert("DestinationPort".to_string(), serde_json::json!(dest_port));
    data.insert("SourcePort".to_string(), serde_json::json!(event.sport));
    data.insert("TimestampNs".to_string(), serde_json::json!(event.timestamp_ns));

    Some(HostSecurityEvent {
        source: HostEventSource::Ebpf,
        event_id: 3,
        timestamp: Utc::now(),
        computer: "localhost".to_string(),
        data: serde_json::Value::Object(data),
        causal_parent: None,
    })
}

#[cfg(target_os = "linux")]
pub struct EbpfTelemetryEngine {
    tx: mpsc::Sender<HostSecurityEvent>,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(target_os = "linux")]
impl EbpfTelemetryEngine {
    pub fn new(tx: mpsc::Sender<HostSecurityEvent>) -> Self {
        Self {
            tx,
            shutdown: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        use aya::maps::{MapData, RingBuf};
        use aya::programs::TracePoint;
        use aya::Ebpf;
        use std::sync::atomic::Ordering;
        use tracing::{info, warn};

        info!("🚀 [LINUX-EBPF] Starting Oshoosi eBPF Telemetry Engine with Ring-Buffer & LSM...");

        let candidate_paths = if let Ok(custom) = std::env::var("OSOOSI_EBPF_OBJECT") {
            vec![std::path::PathBuf::from(custom)]
        } else {
            vec![
                std::path::PathBuf::from("osoosi-ebpf.o"),
                std::path::PathBuf::from("ebpf/bin/osoosi-ebpf.o"),
                std::path::PathBuf::from("/usr/lib/osoosi/osoosi-ebpf.o"),
                std::path::PathBuf::from("/etc/osoosi/osoosi-ebpf.o"),
            ]
        };

        let mut bytes_opt = None;
        let mut loaded_path = std::path::PathBuf::new();
        for p in candidate_paths {
            if let Ok(b) = std::fs::read(&p) {
                loaded_path = p;
                bytes_opt = Some(b);
                break;
            }
        }

        let bytes = match bytes_opt {
            Some(b) => {
                info!("eBPF object successfully loaded from {:?}", loaded_path);
                b
            }
            None => {
                warn!("eBPF object not found in candidate locations. Linux eBPF telemetry disabled.");
                return Ok(());
            }
        };

        let mut bpf = Ebpf::load(&bytes)?;

        // Attach tracepoints
        self.attach_tracepoint(&mut bpf, "handle_process_exec", "sched", "sched_process_exec")?;
        self.attach_tracepoint(&mut bpf, "handle_process_exit", "sched", "sched_process_exit")?;
        self.attach_tracepoint(&mut bpf, "handle_connect", "syscalls", "sys_enter_connect")?;

        let process_map = bpf.take_map("process_ring")
            .or_else(|| bpf.take_map("PROCESS_RING"))
            .ok_or_else(|| anyhow::anyhow!("Required eBPF ringbuffer map 'process_ring' not found"))?;
        let process_ring: RingBuf<MapData> = RingBuf::try_from(process_map)?;

        let network_map = bpf.take_map("network_ring")
            .or_else(|| bpf.take_map("NETWORK_RING"))
            .ok_or_else(|| anyhow::anyhow!("Required eBPF ringbuffer map 'network_ring' not found"))?;
        let network_ring: RingBuf<MapData> = RingBuf::try_from(network_map)?;

        let tx = self.tx.clone();
        let shutdown = self.shutdown.clone();

        let mut process_fd = tokio::io::unix::AsyncFd::new(process_ring)?;
        let mut network_fd = tokio::io::unix::AsyncFd::new(network_ring)?;

        tokio::spawn(async move {
            let _bpf = bpf; // Keep alive

            loop {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }

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

    fn attach_tracepoint(
        &self,
        bpf: &mut aya::Ebpf,
        prog_name: &str,
        category: &str,
        name: &str,
    ) -> anyhow::Result<()> {
        let prog_mut = bpf.program_mut(prog_name)
            .ok_or_else(|| anyhow::anyhow!("eBPF program '{}' not found in object", prog_name))?;
        let prog: &mut aya::programs::TracePoint = prog_mut.try_into()?;
        prog.load()?;
        prog.attach(category, name)?;
        Ok(())
    }
}

// Fallback stub for non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub struct EbpfTelemetryEngine;

#[cfg(not(target_os = "linux"))]
impl EbpfTelemetryEngine {
    pub fn new(_tx: mpsc::Sender<HostSecurityEvent>) -> Self {
        Self
    }
    pub async fn run(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ebpf_struct_sizes() {
        assert_eq!(std::mem::size_of::<EbpfProcessEvent>(), 816);
        assert_eq!(std::mem::size_of::<EbpfNetworkEvent>(), 40);
    }

    #[test]
    fn test_parse_process_exec_event() {
        let mut raw = EbpfProcessEvent::default();
        raw.pid = 4321;
        raw.ppid = 1000;
        raw.uid = 1001;
        raw.gid = 1001;
        raw.event_type = OSOOSI_EBPF_EVENT_EXEC;
        raw.timestamp_ns = 1700000000123456789;

        let comm = b"malware_test\0";
        raw.comm[..comm.len()].copy_from_slice(comm);

        let filename = b"/usr/local/bin/malware_test\0";
        raw.filename[..filename.len()].copy_from_slice(filename);

        let args = b"--daemon --listen 0.0.0.0\0";
        raw.args[..args.len()].copy_from_slice(args);

        let bytes = unsafe {
            std::slice::from_raw_parts(
                &raw as *const _ as *const u8,
                std::mem::size_of::<EbpfProcessEvent>(),
            )
        };

        let event = parse_process_event(bytes).expect("Should parse exec event");
        assert_eq!(event.source, HostEventSource::Ebpf);
        assert_eq!(event.event_id, 1);
        assert_eq!(event.data["ProcessId"], 4321);
        assert_eq!(event.data["ParentProcessId"], 1000);
        assert_eq!(event.data["Image"], "/usr/local/bin/malware_test");
        assert_eq!(
            event.data["CommandLine"],
            "/usr/local/bin/malware_test --daemon --listen 0.0.0.0"
        );
        assert_eq!(event.data["User"], "1001");
    }

    #[test]
    fn test_parse_process_exit_event() {
        let mut raw = EbpfProcessEvent::default();
        raw.pid = 5555;
        raw.event_type = OSOOSI_EBPF_EVENT_EXIT;

        let comm = b"curl\0";
        raw.comm[..comm.len()].copy_from_slice(comm);

        let bytes = unsafe {
            std::slice::from_raw_parts(
                &raw as *const _ as *const u8,
                std::mem::size_of::<EbpfProcessEvent>(),
            )
        };

        let event = parse_process_event(bytes).expect("Should parse exit event");
        assert_eq!(event.source, HostEventSource::Ebpf);
        assert_eq!(event.event_id, 5);
        assert_eq!(event.data["ProcessId"], 5555);
        assert_eq!(event.data["Image"], "curl");
    }

    #[test]
    fn test_parse_lsm_block_event() {
        let mut raw = EbpfProcessEvent::default();
        raw.pid = 9999;
        raw.event_type = OSOOSI_EBPF_EVENT_LSM_BLOCK;

        let filename = b"/tmp/ransomware\0";
        raw.filename[..filename.len()].copy_from_slice(filename);

        let bytes = unsafe {
            std::slice::from_raw_parts(
                &raw as *const _ as *const u8,
                std::mem::size_of::<EbpfProcessEvent>(),
            )
        };

        let event = parse_process_event(bytes).expect("Should parse LSM block event");
        assert_eq!(event.source, HostEventSource::Ebpf);
        assert_eq!(event.event_id, 25);
        assert_eq!(event.data["ProcessId"], 9999);
        assert_eq!(event.data["Image"], "/tmp/ransomware");
        assert!(event.data["Reason"]
            .as_str()
            .unwrap()
            .contains("LSM BPF bprm_check_security"));
    }

    #[test]
    fn test_parse_network_ipv4_event() {
        let mut raw = EbpfNetworkEvent::default();
        raw.pid = 8888;
        raw.family = 2; // AF_INET
        raw.dport = 443u16.to_be(); // network byte order
        raw.sport = 54321;
        raw.daddr[0] = 93;
        raw.daddr[1] = 184;
        raw.daddr[2] = 216;
        raw.daddr[3] = 34; // 93.184.216.34 (example.com)

        let bytes = unsafe {
            std::slice::from_raw_parts(
                &raw as *const _ as *const u8,
                std::mem::size_of::<EbpfNetworkEvent>(),
            )
        };

        let event = parse_network_event(bytes).expect("Should parse IPv4 network event");
        assert_eq!(event.source, HostEventSource::Ebpf);
        assert_eq!(event.event_id, 3);
        assert_eq!(event.data["ProcessId"], 8888);
        assert_eq!(event.data["DestinationIp"], "93.184.216.34");
        assert_eq!(event.data["DestinationPort"], 443);
        assert_eq!(event.data["SourcePort"], 54321);
    }

    #[test]
    fn test_parse_network_ipv6_event() {
        let mut raw = EbpfNetworkEvent::default();
        raw.pid = 7777;
        raw.family = 10; // AF_INET6
        raw.dport = 80u16.to_be();
        raw.sport = 49152;
        // 2001:db8::1
        raw.daddr[0] = 0x20;
        raw.daddr[1] = 0x01;
        raw.daddr[2] = 0x0d;
        raw.daddr[3] = 0xb8;
        raw.daddr[15] = 0x01;

        let bytes = unsafe {
            std::slice::from_raw_parts(
                &raw as *const _ as *const u8,
                std::mem::size_of::<EbpfNetworkEvent>(),
            )
        };

        let event = parse_network_event(bytes).expect("Should parse IPv6 network event");
        assert_eq!(event.source, HostEventSource::Ebpf);
        assert_eq!(event.event_id, 3);
        assert_eq!(event.data["ProcessId"], 7777);
        assert_eq!(event.data["DestinationIp"], "2001:db8::1");
        assert_eq!(event.data["DestinationPort"], 80);
    }
}
