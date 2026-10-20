//! Linux eBPF Ring-Buffer Telemetry & Inline `BPF_PROG_TYPE_LSM` Containment Engine.
//!
//! Provides zero-overhead process and network event capture from kernel space,
//! with full inline Linux Security Module (`BPF_PROG_TYPE_LSM`) kernel-enforced
//! containment across:
//! 1. `lsm/bprm_check_security` (`osoosi_bprm_check`) — Pre-execution binary blocking (`-EPERM`)
//! 2. `lsm/file_open` (`osoosi_file_open`) — Self-defense & `/etc/shadow` credential vault guard (`-EPERM`)
//! 3. `lsm/socket_connect` (`osoosi_socket_connect`) — Inline C2 IPv4/IPv6/port & Kill-Chain lockdown (`-EPERM`)

use chrono::Utc;
use osoosi_types::{HostEventSource, HostSecurityEvent};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};
use tokio::sync::mpsc;

pub const OSOOSI_COMM_LEN: usize = 16;
pub const OSOOSI_PATH_LEN: usize = 256;
pub const OSOOSI_ARGS_LEN: usize = 512;

pub const OSOOSI_EBPF_EVENT_EXEC: u32 = 1;
pub const OSOOSI_EBPF_EVENT_EXIT: u32 = 2;
pub const OSOOSI_EBPF_EVENT_LSM_BLOCK: u32 = 3;
pub const OSOOSI_EBPF_EVENT_MPROTECT_WX: u32 = 4;
pub const OSOOSI_EBPF_EVENT_PTRACE_TAMPER: u32 = 5;
pub const OSOOSI_EBPF_EVENT_LSM_FILE_BLOCK: u32 = 6;
pub const OSOOSI_EBPF_EVENT_LSM_NET_BLOCK: u32 = 7;

static LSM_HOOKS_ATTACHED: AtomicU32 = AtomicU32::new(0);
static LSM_BLOCK_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Shared user-to-BPF control state synchronized into kernel BPF maps (`blocked_paths`,
/// `protected_sensor_pids`, `blocked_ipv4`, `blocked_ipv6`, `blocked_ports`, `lsm_autonomy_mode`).
#[derive(Debug, Clone)]
pub struct EbpfLsmSharedState {
    pub mode: u32,
    pub blocked_paths: Vec<String>,
    pub protected_pids: Vec<u32>,
    pub blocked_ipv4: Vec<[u8; 4]>,
    pub blocked_ipv6: Vec<[u8; 16]>,
    pub blocked_ports: Vec<u16>,
    pub dirty: bool,
}

impl Default for EbpfLsmSharedState {
    fn default() -> Self {
        Self {
            mode: 1, // Active enforcement by default
            blocked_paths: Vec::new(),
            protected_pids: vec![std::process::id()],
            blocked_ipv4: Vec::new(),
            blocked_ipv6: Vec::new(),
            blocked_ports: Vec::new(),
            dirty: true,
        }
    }
}

static GLOBAL_EBPF_LSM_STATE: OnceLock<RwLock<EbpfLsmSharedState>> = OnceLock::new();

pub fn get_ebpf_lsm_state() -> &'static RwLock<EbpfLsmSharedState> {
    GLOBAL_EBPF_LSM_STATE.get_or_init(|| RwLock::new(EbpfLsmSharedState::default()))
}

pub fn sync_ebpf_lsm_mode(mode: u32) {
    let mut guard = get_ebpf_lsm_state()
        .write()
        .unwrap_or_else(|e| e.into_inner());
    guard.mode = mode;
    guard.dirty = true;
}

pub fn sync_ebpf_lsm_add_blocked_path(path: &str) {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return;
    }
    let mut guard = get_ebpf_lsm_state()
        .write()
        .unwrap_or_else(|e| e.into_inner());
    if !guard.blocked_paths.iter().any(|p| p == trimmed) {
        guard.blocked_paths.push(trimmed.to_string());
        guard.dirty = true;
    }
}

pub fn sync_ebpf_lsm_add_protected_pid(pid: u32) {
    if pid == 0 {
        return;
    }
    let mut guard = get_ebpf_lsm_state()
        .write()
        .unwrap_or_else(|e| e.into_inner());
    if !guard.protected_pids.contains(&pid) {
        guard.protected_pids.push(pid);
        guard.dirty = true;
    }
}

pub fn sync_ebpf_lsm_add_blocked_ipv4(ip: [u8; 4]) {
    let mut guard = get_ebpf_lsm_state()
        .write()
        .unwrap_or_else(|e| e.into_inner());
    if !guard.blocked_ipv4.contains(&ip) {
        guard.blocked_ipv4.push(ip);
        guard.dirty = true;
    }
}

pub fn sync_ebpf_lsm_add_blocked_ipv6(ip: [u8; 16]) {
    let mut guard = get_ebpf_lsm_state()
        .write()
        .unwrap_or_else(|e| e.into_inner());
    if !guard.blocked_ipv6.contains(&ip) {
        guard.blocked_ipv6.push(ip);
        guard.dirty = true;
    }
}

pub fn sync_ebpf_lsm_add_blocked_port(port: u16) {
    if port == 0 {
        return;
    }
    let mut guard = get_ebpf_lsm_state()
        .write()
        .unwrap_or_else(|e| e.into_inner());
    if !guard.blocked_ports.contains(&port) {
        guard.blocked_ports.push(port);
        guard.dirty = true;
    }
}

pub fn sync_ebpf_lsm_clear_rules() {
    let mut guard = get_ebpf_lsm_state()
        .write()
        .unwrap_or_else(|e| e.into_inner());
    guard.blocked_paths.clear();
    guard.blocked_ipv4.clear();
    guard.blocked_ipv6.clear();
    guard.blocked_ports.clear();
    guard.dirty = true;
}

pub fn get_ebpf_lsm_stats() -> (u32, u64) {
    (
        LSM_HOOKS_ATTACHED.load(Ordering::Relaxed),
        LSM_BLOCK_COUNTER.load(Ordering::Relaxed),
    )
}

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
    pub event_type: u32, // 1=Exec, 2=Exit, 3=LsmBlock, 4=MprotectWx, 5=PtraceTamper, 6=LsmFileBlock, 7=LsmNetBlock
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
#[derive(Debug, Clone, Copy, Default)]
pub struct EbpfNetworkEvent {
    pub pid: u32,
    pub family: u16,     // AF_INET (2) or AF_INET6 (10)
    pub dport: u16,      // Big-endian network byte order
    pub daddr: [u8; 16], // IPv4 (in first 4 bytes) or IPv6
    pub sport: u16,      // Source port
    pub _pad1: u16,
    pub event_type: u32, // 0=Connect, 7=OSOOSI_EBPF_EVENT_LSM_NET_BLOCK
    pub timestamp_ns: u64,
}

/// Parses raw kernel bytes from `process_ring` into a normalized `HostSecurityEvent`.
pub fn parse_process_event(bytes: &[u8]) -> Option<HostSecurityEvent> {
    if bytes.len() < std::mem::size_of::<EbpfProcessEvent>() {
        return None;
    }

    let event: EbpfProcessEvent =
        unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const EbpfProcessEvent) };

    let comm_len = event
        .comm
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(event.comm.len());
    let comm = String::from_utf8_lossy(&event.comm[..comm_len])
        .trim()
        .to_string();

    let fn_len = event
        .filename
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(event.filename.len());
    let filename = String::from_utf8_lossy(&event.filename[..fn_len])
        .trim()
        .to_string();

    let args_len = event
        .args
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(event.args.len());
    let args = String::from_utf8_lossy(&event.args[..args_len])
        .trim()
        .to_string();

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
            map.insert(
                "Image".to_string(),
                serde_json::json!(if !filename.is_empty() {
                    &filename
                } else {
                    &comm
                }),
            );
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
            LSM_BLOCK_COUNTER.fetch_add(1, Ordering::Relaxed);
            let mut map = serde_json::Map::new();
            map.insert("ProcessId".to_string(), serde_json::json!(event.pid));
            map.insert(
                "Image".to_string(),
                serde_json::json!(if !filename.is_empty() { filename } else { comm }),
            );
            map.insert("CommandLine".to_string(), serde_json::json!(command_line));
            map.insert("Action".to_string(), serde_json::json!("Blocked"));
            map.insert(
                "Reason".to_string(),
                serde_json::json!("Linux LSM BPF bprm_check_security: blocked binary execution (-EPERM)"),
            );
            (25, map)
        }
        OSOOSI_EBPF_EVENT_LSM_FILE_BLOCK => {
            LSM_BLOCK_COUNTER.fetch_add(1, Ordering::Relaxed);
            let mut map = serde_json::Map::new();
            map.insert("ProcessId".to_string(), serde_json::json!(event.pid));
            map.insert(
                "Image".to_string(),
                serde_json::json!(if !filename.is_empty() { filename } else { comm }),
            );
            map.insert("TargetFilename".to_string(), serde_json::json!(command_line));
            map.insert("Action".to_string(), serde_json::json!("Blocked"));
            map.insert(
                "Reason".to_string(),
                serde_json::json!("Linux LSM BPF file_open: blocked unauthorized file tampering or credential vault access (-EPERM)"),
            );
            (25, map)
        }
        OSOOSI_EBPF_EVENT_MPROTECT_WX => {
            let mut map = serde_json::Map::new();
            map.insert("ProcessId".to_string(), serde_json::json!(event.pid));
            map.insert(
                "Image".to_string(),
                serde_json::json!(if !filename.is_empty() { filename } else { comm }),
            );
            map.insert("CommandLine".to_string(), serde_json::json!(command_line));
            map.insert(
                "Reason".to_string(),
                serde_json::json!("Linux sys_enter_mprotect: memory protection set to WRITABLE and EXECUTABLE (W^X violation)"),
            );
            (25, map)
        }
        OSOOSI_EBPF_EVENT_PTRACE_TAMPER => {
            let mut map = serde_json::Map::new();
            map.insert("ProcessId".to_string(), serde_json::json!(event.pid));
            map.insert(
                "Image".to_string(),
                serde_json::json!(if !filename.is_empty() { filename } else { comm }),
            );
            map.insert("CommandLine".to_string(), serde_json::json!(command_line));
            map.insert(
                "Reason".to_string(),
                serde_json::json!("Linux sys_enter_ptrace: memory tampering or remote process injection attempted"),
            );
            (8, map)
        }
        _ => return None,
    };

    data.insert(
        "TimestampNs".to_string(),
        serde_json::json!(event.timestamp_ns),
    );

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

    let event: EbpfNetworkEvent =
        unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const EbpfNetworkEvent) };

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
    data.insert(
        "TimestampNs".to_string(),
        serde_json::json!(event.timestamp_ns),
    );

    if event.event_type == OSOOSI_EBPF_EVENT_LSM_NET_BLOCK {
        LSM_BLOCK_COUNTER.fetch_add(1, Ordering::Relaxed);
        data.insert("Action".to_string(), serde_json::json!("Blocked"));
        data.insert(
            "Reason".to_string(),
            serde_json::json!(
                "Linux LSM BPF socket_connect: blocked outbound C2 or lockdown connection (-EPERM)"
            ),
        );
    }

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
        use aya::maps::{Array, HashMap as BpfHashMap, MapData, RingBuf};
        use aya::{Btf, Ebpf};
        use tracing::{info, warn};

        info!("🚀 [LINUX-EBPF] Starting Oshoosi eBPF Telemetry Engine with Ring-Buffer & Inline BPF_PROG_TYPE_LSM...");

        let candidate_paths = if let Ok(custom) = std::env::var("OSOOSI_EBPF_OBJECT") {
            vec![std::path::PathBuf::from(custom)]
        } else {
            vec![
                std::path::PathBuf::from("ebpf/osoosi_probe.bpf.o"),
                std::path::PathBuf::from("osoosi_probe.bpf.o"),
                std::path::PathBuf::from("/usr/lib/oshoosiclaw/osoosi_probe.bpf.o"),
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
                warn!(
                    "eBPF object not found in candidate locations. Linux eBPF telemetry disabled."
                );
                return Ok(());
            }
        };

        let mut bpf = Ebpf::load(&bytes)?;

        // 1. Attach Tracepoints
        self.attach_tracepoint(
            &mut bpf,
            "handle_process_exec",
            "sched",
            "sched_process_exec",
        )?;
        self.attach_tracepoint(
            &mut bpf,
            "handle_process_exit",
            "sched",
            "sched_process_exit",
        )?;
        self.attach_tracepoint(&mut bpf, "handle_connect", "syscalls", "sys_enter_connect")?;
        let _ = self.attach_tracepoint(
            &mut bpf,
            "handle_mprotect",
            "syscalls",
            "sys_enter_mprotect",
        );
        let _ = self.attach_tracepoint(&mut bpf, "handle_ptrace", "syscalls", "sys_enter_ptrace");

        // 2. Attach Inline BPF_PROG_TYPE_LSM Hooks (bprm_check_security, file_open, socket_connect)
        let mut attached_lsm = 0u32;
        match Btf::from_sys_fs() {
            Ok(btf) => {
                for (prog_name, hook_name) in [
                    ("osoosi_bprm_check", "bprm_check_security"),
                    ("osoosi_file_open", "file_open"),
                    ("osoosi_socket_connect", "socket_connect"),
                ] {
                    match self.attach_lsm_program(&mut bpf, &btf, prog_name, hook_name) {
                        Ok(()) => {
                            attached_lsm += 1;
                            info!(
                                "✅ [LINUX-LSM] Attached inline BPF_PROG_TYPE_LSM hook: {} -> {}",
                                prog_name, hook_name
                            );
                        }
                        Err(e) => {
                            warn!(
                                "⚠️ [LINUX-LSM] Could not attach LSM hook '{}' ({}): {}. Ensure 'bpf' is in /sys/kernel/security/lsm.",
                                prog_name, hook_name, e
                            );
                        }
                    }
                }
            }
            Err(e) => {
                warn!(
                    "⚠️ [LINUX-LSM] Could not load kernel BTF from /sys/kernel/btf/vmlinux ({}); continuing with tracepoint ring buffers.",
                    e
                );
            }
        }
        LSM_HOOKS_ATTACHED.store(attached_lsm, Ordering::Relaxed);

        // Register current sensor PID for self-defense
        sync_ebpf_lsm_add_protected_pid(std::process::id());

        let process_map = bpf
            .take_map("process_ring")
            .or_else(|| bpf.take_map("PROCESS_RING"))
            .ok_or_else(|| {
                anyhow::anyhow!("Required eBPF ringbuffer map 'process_ring' not found")
            })?;
        let process_ring: RingBuf<MapData> = RingBuf::try_from(process_map)?;

        let network_map = bpf
            .take_map("network_ring")
            .or_else(|| bpf.take_map("NETWORK_RING"))
            .ok_or_else(|| {
                anyhow::anyhow!("Required eBPF ringbuffer map 'network_ring' not found")
            })?;
        let network_ring: RingBuf<MapData> = RingBuf::try_from(network_map)?;

        let tx = self.tx.clone();
        let shutdown = self.shutdown.clone();

        #[allow(deprecated)]
        let mut process_fd = tokio::io::unix::AsyncFd::new(process_ring)?;
        #[allow(deprecated)]
        let mut network_fd = tokio::io::unix::AsyncFd::new(network_ring)?;

        tokio::spawn(async move {
            let mut bpf = bpf; // Keep alive and sync maps dynamically

            loop {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }

                // Synchronize user-mode LSM policy maps into kernel BPF maps when updated
                {
                    let snapshot = {
                        let mut st = get_ebpf_lsm_state()
                            .write()
                            .unwrap_or_else(|e| e.into_inner());
                        if st.dirty {
                            st.dirty = false;
                            Some(st.clone())
                        } else {
                            None
                        }
                    };
                    if let Some(cfg) = snapshot {
                        if let Some(map) = bpf.map_mut("lsm_autonomy_mode") {
                            if let Ok(mut arr) = Array::<_, u32>::try_from(map) {
                                let _ = arr.set(0, cfg.mode, 0);
                            }
                        }
                        if let Some(map) = bpf.map_mut("protected_sensor_pids") {
                            if let Ok(mut hm) = BpfHashMap::<_, u32, u8>::try_from(map) {
                                for pid in &cfg.protected_pids {
                                    let _ = hm.insert(pid, &1u8, 0);
                                }
                            }
                        }
                        if let Some(map) = bpf.map_mut("blocked_paths") {
                            if let Ok(mut hm) =
                                BpfHashMap::<_, [u8; OSOOSI_PATH_LEN], u8>::try_from(map)
                            {
                                for path in &cfg.blocked_paths {
                                    let mut key = [0u8; OSOOSI_PATH_LEN];
                                    let bytes = path.as_bytes();
                                    let len = bytes.len().min(OSOOSI_PATH_LEN - 1);
                                    key[..len].copy_from_slice(&bytes[..len]);
                                    let _ = hm.insert(&key, &1u8, 0);
                                }
                            }
                        }
                        if let Some(map) = bpf.map_mut("blocked_ipv4") {
                            if let Ok(mut hm) = BpfHashMap::<_, u32, u8>::try_from(map) {
                                for ip in &cfg.blocked_ipv4 {
                                    let addr_u32 = u32::from_ne_bytes(*ip);
                                    let _ = hm.insert(&addr_u32, &1u8, 0);
                                }
                            }
                        }
                        if let Some(map) = bpf.map_mut("blocked_ipv6") {
                            if let Ok(mut hm) = BpfHashMap::<_, [u8; 16], u8>::try_from(map) {
                                for ip6 in &cfg.blocked_ipv6 {
                                    let _ = hm.insert(ip6, &1u8, 0);
                                }
                            }
                        }
                        if let Some(map) = bpf.map_mut("blocked_ports") {
                            if let Ok(mut hm) = BpfHashMap::<_, u16, u8>::try_from(map) {
                                for port in &cfg.blocked_ports {
                                    let _ = hm.insert(port, &1u8, 0);
                                }
                            }
                        }
                    }
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
        let prog_mut = bpf
            .program_mut(prog_name)
            .ok_or_else(|| anyhow::anyhow!("eBPF program '{}' not found in object", prog_name))?;
        let prog: &mut aya::programs::TracePoint = prog_mut.try_into()?;
        prog.load()?;
        prog.attach(category, name)?;
        Ok(())
    }

    fn attach_lsm_program(
        &self,
        bpf: &mut aya::Ebpf,
        btf: &aya::Btf,
        prog_name: &str,
        hook_name: &str,
    ) -> anyhow::Result<()> {
        let prog_mut = bpf
            .program_mut(prog_name)
            .ok_or_else(|| anyhow::anyhow!("LSM program '{}' not found in object", prog_name))?;
        let prog: &mut aya::programs::Lsm = prog_mut.try_into()?;
        prog.load(hook_name, btf)?;
        prog.attach()?;
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
#[allow(clippy::field_reassign_with_default)]
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
        assert_eq!(event.data["Action"], "Blocked");
        assert!(event.data["Reason"]
            .as_str()
            .unwrap()
            .contains("LSM BPF bprm_check_security"));
    }

    #[test]
    fn test_parse_lsm_file_block_event() {
        let mut raw = EbpfProcessEvent::default();
        raw.pid = 4242;
        raw.event_type = OSOOSI_EBPF_EVENT_LSM_FILE_BLOCK;

        let comm = b"tamper_tool\0";
        raw.comm[..comm.len()].copy_from_slice(comm);

        let filename = b"osoosi.toml\0";
        raw.filename[..filename.len()].copy_from_slice(filename);

        let bytes = unsafe {
            std::slice::from_raw_parts(
                &raw as *const _ as *const u8,
                std::mem::size_of::<EbpfProcessEvent>(),
            )
        };

        let event = parse_process_event(bytes).expect("Should parse LSM file_open block event");
        assert_eq!(event.source, HostEventSource::Ebpf);
        assert_eq!(event.event_id, 25);
        assert_eq!(event.data["ProcessId"], 4242);
        assert_eq!(event.data["Action"], "Blocked");
        assert!(event.data["Reason"]
            .as_str()
            .unwrap()
            .contains("LSM BPF file_open"));
    }

    #[test]
    fn test_parse_lsm_net_block_event() {
        let mut raw = EbpfNetworkEvent::default();
        raw.pid = 31337;
        raw.family = 2; // AF_INET
        raw.dport = 4444u16.to_be();
        raw.sport = 51234;
        raw.daddr[0] = 198;
        raw.daddr[1] = 51;
        raw.daddr[2] = 100;
        raw.daddr[3] = 42;
        raw.event_type = OSOOSI_EBPF_EVENT_LSM_NET_BLOCK;

        let bytes = unsafe {
            std::slice::from_raw_parts(
                &raw as *const _ as *const u8,
                std::mem::size_of::<EbpfNetworkEvent>(),
            )
        };

        let event = parse_network_event(bytes).expect("Should parse LSM socket_connect block event");
        assert_eq!(event.source, HostEventSource::Ebpf);
        assert_eq!(event.event_id, 3);
        assert_eq!(event.data["ProcessId"], 31337);
        assert_eq!(event.data["DestinationIp"], "198.51.100.42");
        assert_eq!(event.data["DestinationPort"], 4444);
        assert_eq!(event.data["Action"], "Blocked");
        assert!(event.data["Reason"]
            .as_str()
            .unwrap()
            .contains("LSM BPF socket_connect"));
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

    #[test]
    fn test_parse_mprotect_wx_event() {
        let mut raw = EbpfProcessEvent::default();
        raw.pid = 6666;
        raw.event_type = OSOOSI_EBPF_EVENT_MPROTECT_WX;

        let comm = b"exploit_jit\0";
        raw.comm[..comm.len()].copy_from_slice(comm);

        let bytes = unsafe {
            std::slice::from_raw_parts(
                &raw as *const _ as *const u8,
                std::mem::size_of::<EbpfProcessEvent>(),
            )
        };

        let event = parse_process_event(bytes).expect("Should parse mprotect W^X event");
        assert_eq!(event.source, HostEventSource::Ebpf);
        assert_eq!(event.event_id, 25);
        assert_eq!(event.data["ProcessId"], 6666);
        assert_eq!(event.data["Image"], "exploit_jit");
        assert!(event.data["Reason"]
            .as_str()
            .unwrap()
            .contains("W^X violation"));
    }

    #[test]
    fn test_parse_ptrace_tamper_event() {
        let mut raw = EbpfProcessEvent::default();
        raw.pid = 7777;
        raw.event_type = OSOOSI_EBPF_EVENT_PTRACE_TAMPER;

        let comm = b"ptrace_injector\0";
        raw.comm[..comm.len()].copy_from_slice(comm);

        let bytes = unsafe {
            std::slice::from_raw_parts(
                &raw as *const _ as *const u8,
                std::mem::size_of::<EbpfProcessEvent>(),
            )
        };

        let event = parse_process_event(bytes).expect("Should parse ptrace tamper event");
        assert_eq!(event.source, HostEventSource::Ebpf);
        assert_eq!(event.event_id, 8);
        assert_eq!(event.data["ProcessId"], 7777);
        assert_eq!(event.data["Image"], "ptrace_injector");
        assert!(event.data["Reason"]
            .as_str()
            .unwrap()
            .contains("ptrace: memory tampering or remote process injection"));
    }

    #[test]
    fn test_ebpf_lsm_shared_state_sync() {
        sync_ebpf_lsm_clear_rules();
        sync_ebpf_lsm_mode(2);
        sync_ebpf_lsm_add_blocked_path("/tmp/malicious_dropper");
        sync_ebpf_lsm_add_protected_pid(12345);
        sync_ebpf_lsm_add_blocked_ipv4([203, 0, 113, 9]);
        sync_ebpf_lsm_add_blocked_port(4444);

        let st = get_ebpf_lsm_state()
            .read()
            .unwrap_or_else(|e| e.into_inner());
        assert_eq!(st.mode, 2);
        assert!(st.blocked_paths.contains(&"/tmp/malicious_dropper".to_string()));
        assert!(st.protected_pids.contains(&12345));
        assert!(st.blocked_ipv4.contains(&[203, 0, 113, 9]));
        assert!(st.blocked_ports.contains(&4444));
        assert!(st.dirty);
    }
}
