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

pub const OSOOSI_PID_ROLE_PROTECTED_SENSOR: u32 = 1;
pub const OSOOSI_PID_ROLE_QUARANTINED: u32 = 2;

static LSM_HOOKS_ATTACHED: AtomicU32 = AtomicU32::new(0);
static LSM_BLOCK_COUNTER: AtomicU64 = AtomicU64::new(0);

/// 24-byte kernel quarantine directive matching `struct quarantine_directive` in `osoosi_ebpf_types.h`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct QuarantineDirective {
    pub triggered_ts_ns: u64,
    pub target_pid: u32,
    pub sigma_x100: u32,
    pub status: u32,
    pub _pad: u32,
}

#[cfg(target_os = "linux")]
unsafe impl aya::Pod for QuarantineDirective {}

/// Shared user-to-BPF control state synchronized into kernel BPF maps (`blocked_paths`,
/// `protected_sensor_pids`, `quarantine_targets`, `blocked_ipv4`, `blocked_ipv6`, `blocked_ports`, `lsm_autonomy_mode`).
#[derive(Debug, Clone)]
pub struct EbpfLsmSharedState {
    pub mode: u32,
    pub blocked_paths: Vec<String>,
    pub protected_pids: Vec<u32>,
    pub quarantined_pids: Vec<u32>,
    pub quarantine_directives: Vec<(u32, QuarantineDirective)>,
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
            quarantined_pids: Vec::new(),
            quarantine_directives: Vec::new(),
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

pub fn sync_ebpf_lsm_add_quarantined_pid(pid: u32) {
    if pid <= 4 || pid == std::process::id() {
        return;
    }
    let mut guard = get_ebpf_lsm_state()
        .write()
        .unwrap_or_else(|e| e.into_inner());
    if guard.protected_pids.contains(&pid) {
        return;
    }
    if !guard.quarantined_pids.contains(&pid) {
        guard.quarantined_pids.push(pid);
        guard.dirty = true;
    }
}

pub fn sync_ebpf_quarantine_directive(tgid: u32, directive: QuarantineDirective) {
    if tgid <= 4 || tgid == std::process::id() {
        return;
    }
    let mut guard = get_ebpf_lsm_state()
        .write()
        .unwrap_or_else(|e| e.into_inner());
    if guard.protected_pids.contains(&tgid) {
        return;
    }
    if let Some(existing) = guard
        .quarantine_directives
        .iter_mut()
        .find(|(id, _)| *id == tgid)
    {
        existing.1 = directive;
    } else {
        guard.quarantine_directives.push((tgid, directive));
    }
    guard.dirty = true;
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
    guard.quarantined_pids.clear();
    guard.quarantine_directives.clear();
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

/// Dual-Stage 5-Sigma Kernel `SIGSTOP` + Pre-Armed Cgroup v2 Freezer Responder.
pub struct QuarantineResponder {
    pub cgroup_base_path: std::path::PathBuf,
    pub cgroup_procs_file: Option<std::fs::File>,
    pub cgroup_freeze_file: Option<std::fs::File>,
    pub frozen_history: Vec<(u32, QuarantineDirective)>,
}

impl QuarantineResponder {
    /// Creates `cgroup_base_path`, pre-opens `cgroup.procs` and `cgroup.freeze` with write
    /// permissions, and pre-arms `cgroup.freeze` with `"1\n"` so any TGID migrated into
    /// `cgroup.procs` enters the kernel refrigerator immediately upon arrival.
    pub fn new(cgroup_base_path: &str) -> Self {
        use std::io::Write;
        let base_path = std::path::PathBuf::from(cgroup_base_path);
        let _ = std::fs::create_dir_all(&base_path);

        let procs_path = base_path.join("cgroup.procs");
        let freeze_path = base_path.join("cgroup.freeze");

        let open_rw = |p: &std::path::Path| -> Option<std::fs::File> {
            std::fs::OpenOptions::new()
                .write(true)
                .append(true)
                .open(p)
                .or_else(|_| {
                    std::fs::OpenOptions::new()
                        .create(true)
                        .write(true)
                        .append(true)
                        .open(p)
                })
                .ok()
        };

        let cgroup_procs_file = open_rw(&procs_path);
        let mut cgroup_freeze_file = std::fs::OpenOptions::new()
            .write(true)
            .open(&freeze_path)
            .or_else(|_| {
                std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&freeze_path)
            })
            .ok();

        if let Some(ref mut f) = cgroup_freeze_file {
            let _ = f.write_all(b"1\n");
            let _ = f.flush();
        }

        Self {
            cgroup_base_path: base_path,
            cgroup_procs_file,
            cgroup_freeze_file,
            frozen_history: Vec::with_capacity(64),
        }
    }

    /// Zero-allocation ASCII integer formatter appending `'\n'` into a 16-byte stack buffer.
    #[inline]
    pub fn format_u32_newline(mut val: u32, buf: &mut [u8; 16]) -> usize {
        if val == 0 {
            buf[0] = b'0';
            buf[1] = b'\n';
            return 2;
        }
        let mut tmp = [0u8; 10];
        let mut i = 10usize;
        while val > 0 {
            i -= 1;
            tmp[i] = b'0' + (val % 10) as u8;
            val /= 10;
        }
        let digits_len = 10 - i;
        buf[..digits_len].copy_from_slice(&tmp[i..10]);
        buf[digits_len] = b'\n';
        digits_len + 1
    }

    /// Enforces Dual-Stage 5-Sigma Quarantine (Stage 1: Kernel `quarantine_targets` BPF map +
    /// Stage 2: Pre-Armed Cgroup v2 `cgroup.procs` + `cgroup.freeze`), strictly subject to the
    /// Host OS & Developer Immunity Veto.
    pub fn isolate_5_sigma_threat(
        &mut self,
        tgid: u32,
        pid: u32,
        comm_or_image: &str,
        sigma_z: f64,
    ) -> Result<QuarantineDirective, String> {
        use std::io::{Seek, SeekFrom, Write};

        if tgid <= 4 {
            return Err(format!(
                "Host OS Immunity Veto: Refusing to freeze kernel/init TGID {}",
                tgid
            ));
        }
        if tgid == std::process::id() || pid == std::process::id() {
            return Err(format!(
                "Self-Defense Veto: Refusing to freeze active OshoosiClaw sensor PID {}",
                tgid
            ));
        }
        if osoosi_types::is_critical_system_process(comm_or_image) {
            return Err(format!(
                "Host OS & Developer Immunity Veto: Refusing to freeze protected process '{}' (TGID {})",
                comm_or_image, tgid
            ));
        }
        {
            let st = get_ebpf_lsm_state()
                .read()
                .unwrap_or_else(|e| e.into_inner());
            let is_protected = st.protected_pids.contains(&tgid);
            std::mem::drop(st);
            if is_protected {
                return Err(format!(
                    "Protected Sensor PID Veto: TGID {} is registered in protected_pids",
                    tgid
                ));
            }
        }
        if sigma_z < 5.0 {
            return Err(format!(
                "Significance below 5-sigma quarantine threshold: {:.2} < 5.00",
                sigma_z
            ));
        }

        let triggered_ts_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        let directive = QuarantineDirective {
            triggered_ts_ns,
            target_pid: pid,
            sigma_x100: (sigma_z * 100.0).round() as u32,
            status: 1, // 1 = Armed for kernel SIGSTOP injection
            _pad: 0,
        };

        // Stage 1: Synchronize into kernel BPF maps (quarantine_targets + protected_sensor_pids role=2)
        sync_ebpf_quarantine_directive(tgid, directive);
        sync_ebpf_lsm_add_quarantined_pid(tgid);

        // Stage 2: Write TGID to pre-opened cgroup.procs and re-assert cgroup.freeze = "1\n"
        let mut buf = [0u8; 16];
        let n = Self::format_u32_newline(tgid, &mut buf);
        if let Some(ref mut procs_f) = self.cgroup_procs_file {
            let _ = procs_f.write_all(&buf[..n]);
            let _ = procs_f.flush();
        }
        if let Some(ref mut freeze_f) = self.cgroup_freeze_file {
            let _ = freeze_f.seek(SeekFrom::Start(0));
            let _ = freeze_f.write_all(b"1\n");
            let _ = freeze_f.flush();
        }

        if self.frozen_history.len() >= 64 {
            let drain_count = self.frozen_history.len() - 63;
            self.frozen_history.drain(0..drain_count);
            self.frozen_history.shrink_to(64);
        }
        self.frozen_history.push((tgid, directive));
        Ok(directive)
    }
}

impl Drop for QuarantineResponder {
    fn drop(&mut self) {
        use std::io::Write;
        if let Some(mut procs_f) = self.cgroup_procs_file.take() {
            let _ = procs_f.flush();
            std::mem::drop(procs_f);
        }
        if let Some(mut freeze_f) = self.cgroup_freeze_file.take() {
            let _ = freeze_f.flush();
            std::mem::drop(freeze_f);
        }
        self.frozen_history.clear();
        self.frozen_history.shrink_to_fit();
    }
}

/// Haloscope 5-Sigma Statistical Scorer for Linux eBPF Ring-Buffer Events.
#[derive(Debug, Default, Clone)]
pub struct HaloscopeFiveSigmaScorer {
    accumulated_z: std::collections::HashMap<u32, f64>,
}

impl HaloscopeFiveSigmaScorer {
    pub fn new() -> Self {
        Self {
            accumulated_z: std::collections::HashMap::with_capacity(128),
        }
    }

    /// Evaluates an `EbpfProcessEvent` and returns `(sigma_z, coincidence_veto_fp)`.
    pub fn evaluate_process_event(&mut self, ev: &EbpfProcessEvent) -> (f64, bool) {
        let comm_len = ev
            .comm
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(ev.comm.len());
        let comm = String::from_utf8_lossy(&ev.comm[..comm_len])
            .trim()
            .to_string();

        let fn_len = ev
            .filename
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(ev.filename.len());
        let filename = String::from_utf8_lossy(&ev.filename[..fn_len])
            .trim()
            .to_string();

        let args_len = ev
            .args
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(ev.args.len());
        let args = String::from_utf8_lossy(&ev.args[..args_len])
            .trim()
            .to_string();

        let image_or_comm = if !filename.is_empty() {
            if !args.is_empty() {
                format!("{} {}", filename, args)
            } else {
                filename.clone()
            }
        } else if !args.is_empty() {
            format!("{} {}", comm, args)
        } else {
            comm.clone()
        };

        let coincidence_veto_fp = ev.pid <= 4
            || ev.pid == std::process::id()
            || osoosi_types::is_critical_system_process(&image_or_comm)
            || (!filename.is_empty() && osoosi_types::is_critical_system_process(&filename))
            || (!comm.is_empty()
                && args.is_empty()
                && osoosi_types::is_critical_system_process(&comm));

        if ev.event_type == OSOOSI_EBPF_EVENT_EXIT {
            self.accumulated_z.remove(&ev.pid);
            if self.accumulated_z.capacity() > 128 && self.accumulated_z.len() <= 64 {
                self.accumulated_z.shrink_to(128);
            }
            return (0.0, coincidence_veto_fp);
        }

        let instant_z = match ev.event_type {
            OSOOSI_EBPF_EVENT_MPROTECT_WX => 5.35,
            OSOOSI_EBPF_EVENT_PTRACE_TAMPER => 5.50,
            OSOOSI_EBPF_EVENT_LSM_BLOCK => 5.60,
            OSOOSI_EBPF_EVENT_LSM_FILE_BLOCK => 5.25,
            OSOOSI_EBPF_EVENT_LSM_NET_BLOCK => 5.15,
            OSOOSI_EBPF_EVENT_EXEC => {
                let lower = image_or_comm.to_ascii_lowercase();
                if lower.starts_with("/dev/shm/")
                    || lower.starts_with("/tmp/")
                    || lower.starts_with("/var/tmp/")
                    || lower.contains("memfd:")
                    || lower.contains("/proc/self/fd/")
                {
                    5.20
                } else {
                    0.85
                }
            }
            _ => 0.50,
        };

        if self.accumulated_z.len() >= 512 && !self.accumulated_z.contains_key(&ev.pid) {
            self.accumulated_z.retain(|_, z| *z >= 2.5);
            self.accumulated_z.shrink_to(128);
        }

        let prev = self.accumulated_z.get(&ev.pid).copied().unwrap_or(0.0);
        let combined = (prev * 0.85 + instant_z).max(instant_z).min(12.0);
        self.accumulated_z.insert(ev.pid, combined);

        (combined, coincidence_veto_fp)
    }
}

/// Unbacked / anonymous executable VMA parsed from `/proc/<tgid>/maps`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AnonymousExecRegion {
    pub start_addr: u64,
    pub end_addr: u64,
    pub permissions: String,
    pub offset: u64,
    pub pathname: String,
}

/// Kernel syscall register snapshot parsed from `/proc/<pid>/syscall`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FrozenSyscallState {
    pub syscall_nr: i64,
    pub args: [u64; 6],
    pub rsp: u64,
    pub rip: u64,
}

/// Complete forensic snapshot extracted from a frozen 5-sigma process before termination.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FrozenProcessForensicSnapshot {
    pub tgid: u32,
    pub pid: u32,
    pub sigma_z: f64,
    pub anonymous_exec_regions: Vec<AnonymousExecRegion>,
    pub extracted_payload_hex: String,
    pub extracted_payload_len: usize,
    pub payload_blake3: String,
    pub payload_sha256: String,
    pub syscall_state: Option<FrozenSyscallState>,
    pub ioc_digest_blake3: String,
    pub mesh_ioc_signature: String,
}

/// Post-Freeze Forensic Collector that inspects intact `mm_struct` anonymous `VM_EXEC` pages
/// (`/proc/<tgid>/maps` + `/proc/<tgid>/mem`) and kernel syscall registers (`/proc/<pid>/syscall`)
/// while the process is held in Cgroup v2 freezer / `SIGSTOP`.
pub struct FrozenProcessForensicCollector;

impl FrozenProcessForensicCollector {
    pub const MAX_EXTRACT_BYTES: usize = 64 * 1024;

    /// Parses `/proc/<tgid>/maps` to find executable (`r-xp` or `rwxp`) regions that are
    /// anonymous or unbacked (empty pathname, `[anon*`, `[heap]`, `[stack]`, `/memfd:`, or `(deleted)`).
    pub fn parse_proc_maps_anonymous_exec(maps_content: &str) -> Vec<AnonymousExecRegion> {
        let mut regions = Vec::new();
        for raw_line in maps_content.lines() {
            let line = raw_line.trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(range_str) = parts.next() else {
                continue;
            };
            let Some(perms) = parts.next() else {
                continue;
            };
            let offset_str = parts.next().unwrap_or("0");
            let _dev = parts.next();
            let _inode = parts.next();
            let pathname: String = parts.collect::<Vec<&str>>().join(" ");

            if !perms.contains('x') {
                continue;
            }

            let is_anonymous_or_unbacked = pathname.is_empty()
                || pathname.starts_with("[anon")
                || pathname == "[heap]"
                || pathname.starts_with("[stack")
                || pathname.starts_with("/memfd:")
                || pathname.starts_with("memfd:")
                || pathname.contains("(deleted)");

            if !is_anonymous_or_unbacked {
                continue;
            }

            let Some((start_hex, end_hex)) = range_str.split_once('-') else {
                continue;
            };
            let Ok(start_addr) = u64::from_str_radix(start_hex.trim(), 16) else {
                continue;
            };
            let Ok(end_addr) = u64::from_str_radix(end_hex.trim(), 16) else {
                continue;
            };
            if end_addr <= start_addr {
                continue;
            }
            let offset = u64::from_str_radix(offset_str.trim(), 16).unwrap_or(0);

            regions.push(AnonymousExecRegion {
                start_addr,
                end_addr,
                permissions: perms.to_string(),
                offset,
                pathname,
            });
        }
        regions
    }

    /// Parses `/proc/<pid>/syscall` (`syscall_nr arg0 arg1 arg2 arg3 arg4 arg5 sp ip`)
    /// into structured register fields.
    pub fn parse_proc_syscall_registers(syscall_content: &str) -> Option<FrozenSyscallState> {
        let line = syscall_content.lines().next()?.trim();
        if line.is_empty() {
            return None;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() {
            return None;
        }
        if tokens[0].eq_ignore_ascii_case("running") {
            return Some(FrozenSyscallState {
                syscall_nr: -1,
                args: [0; 6],
                rsp: 0,
                rip: 0,
            });
        }

        let syscall_nr = tokens[0].parse::<i64>().ok()?;
        let parse_hex_u64 = |s: &str| -> u64 {
            let clean = s
                .trim()
                .strip_prefix("0x")
                .or_else(|| s.trim().strip_prefix("0X"))
                .unwrap_or(s.trim());
            u64::from_str_radix(clean, 16).unwrap_or(0)
        };

        let mut args = [0u64; 6];
        for i in 0..6 {
            if let Some(tok) = tokens.get(1 + i) {
                args[i] = parse_hex_u64(tok);
            }
        }
        let rsp = tokens.get(7).map(|t| parse_hex_u64(t)).unwrap_or(0);
        let rip = tokens.get(8).map(|t| parse_hex_u64(t)).unwrap_or(0);

        Some(FrozenSyscallState {
            syscall_nr,
            args,
            rsp,
            rip,
        })
    }

    /// Collects a complete forensic snapshot from `<proc_root>/<tgid>/{maps,mem}` and
    /// `<proc_root>/<pid>/syscall`.
    pub fn collect_from_proc_root(
        proc_root: &std::path::Path,
        tgid: u32,
        pid: u32,
        sigma_z: f64,
    ) -> FrozenProcessForensicSnapshot {
        use sha2::{Digest, Sha256};
        use std::io::{Read, Seek, SeekFrom};

        let tgid_dir = proc_root.join(tgid.to_string());
        let pid_dir = proc_root.join(pid.to_string());

        let maps_content = std::fs::read_to_string(tgid_dir.join("maps")).unwrap_or_default();
        let anonymous_exec_regions = Self::parse_proc_maps_anonymous_exec(&maps_content);
        std::mem::drop(maps_content);

        let mut extracted_payload = Vec::new();
        if let Ok(mut mem_file) = std::fs::File::open(tgid_dir.join("mem")) {
            let mut chunk = Vec::new();
            for region in &anonymous_exec_regions {
                let region_size = (region.end_addr.saturating_sub(region.start_addr) as usize)
                    .min(Self::MAX_EXTRACT_BYTES.saturating_sub(extracted_payload.len()));
                if region_size == 0 {
                    break;
                }
                if mem_file.seek(SeekFrom::Start(region.start_addr)).is_ok() {
                    chunk.resize(region_size, 0u8);
                    if let Ok(n) = mem_file.read(&mut chunk) {
                        if n > 0 {
                            extracted_payload.extend_from_slice(&chunk[..n]);
                        }
                    }
                }
                if extracted_payload.len() >= Self::MAX_EXTRACT_BYTES {
                    break;
                }
            }
            std::mem::drop(chunk);
            std::mem::drop(mem_file);
        }
        extracted_payload.shrink_to_fit();

        let payload_blake3 = blake3::hash(&extracted_payload).to_hex().to_string();
        let mut sha256_hasher = Sha256::new();
        sha256_hasher.update(&extracted_payload);
        let payload_sha256 = hex::encode(sha256_hasher.finalize());
        let extracted_payload_hex = hex::encode(&extracted_payload);
        let extracted_payload_len = extracted_payload.len();
        std::mem::drop(extracted_payload);

        let syscall_content = std::fs::read_to_string(pid_dir.join("syscall"))
            .or_else(|_| std::fs::read_to_string(tgid_dir.join("syscall")))
            .unwrap_or_default();
        let syscall_state = Self::parse_proc_syscall_registers(&syscall_content);
        std::mem::drop(syscall_content);

        let mut ioc_hasher = blake3::Hasher::new();
        ioc_hasher.update(b"OSOOSI_5SIGMA_FROZEN_SNAPSHOT_V1:");
        ioc_hasher.update(&tgid.to_le_bytes());
        ioc_hasher.update(&pid.to_le_bytes());
        ioc_hasher.update(&((sigma_z * 100.0).round() as u32).to_le_bytes());
        ioc_hasher.update(payload_blake3.as_bytes());
        if let Some(ref sc) = syscall_state {
            ioc_hasher.update(&sc.syscall_nr.to_le_bytes());
            ioc_hasher.update(&sc.rip.to_le_bytes());
            ioc_hasher.update(&sc.rsp.to_le_bytes());
        }
        let ioc_digest_blake3 = ioc_hasher.finalize().to_hex().to_string();

        let mesh_key: [u8; 32] = *b"OSOOSI_5SIGMA_FROZEN_IOC_MESH_V1";
        let mesh_ioc_signature =
            blake3::keyed_hash(&mesh_key, ioc_digest_blake3.as_bytes())
                .to_hex()
                .to_string();

        FrozenProcessForensicSnapshot {
            tgid,
            pid,
            sigma_z,
            anonymous_exec_regions,
            extracted_payload_hex,
            extracted_payload_len,
            payload_blake3,
            payload_sha256,
            syscall_state,
            ioc_digest_blake3,
            mesh_ioc_signature,
        }
    }

    /// Collects a forensic snapshot from `/proc` on a live Linux host.
    pub fn collect_forensic_snapshot(
        tgid: u32,
        pid: u32,
        sigma_z: f64,
    ) -> FrozenProcessForensicSnapshot {
        Self::collect_from_proc_root(std::path::Path::new("/proc"), tgid, pid, sigma_z)
    }
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
            let mut responder = QuarantineResponder::new("/sys/fs/cgroup/osoosi_quarantine");
            let mut scorer = HaloscopeFiveSigmaScorer::new();

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
                            if let Ok(mut hm) = BpfHashMap::<_, u32, u32>::try_from(&mut *map) {
                                for pid in &cfg.protected_pids {
                                    let _ = hm.insert(pid, &OSOOSI_PID_ROLE_PROTECTED_SENSOR, 0);
                                }
                                for pid in &cfg.quarantined_pids {
                                    let _ = hm.insert(pid, &OSOOSI_PID_ROLE_QUARANTINED, 0);
                                }
                            } else if let Ok(mut hm) = BpfHashMap::<_, u32, u8>::try_from(map) {
                                for pid in &cfg.protected_pids {
                                    let _ = hm.insert(pid, &1u8, 0);
                                }
                                for pid in &cfg.quarantined_pids {
                                    let _ = hm.insert(pid, &2u8, 0);
                                }
                            }
                        }
                        if let Some(map) = bpf.map_mut("quarantine_targets") {
                            if let Ok(mut hm) =
                                BpfHashMap::<_, u32, QuarantineDirective>::try_from(map)
                            {
                                for (tgid, directive) in &cfg.quarantine_directives {
                                    let _ = hm.insert(tgid, directive, 0);
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
                            let mut sigma_eval = None;
                            if item.len() >= std::mem::size_of::<EbpfProcessEvent>() {
                                let raw_ev: EbpfProcessEvent = unsafe {
                                    std::ptr::read_unaligned(item.as_ptr() as *const EbpfProcessEvent)
                                };
                                let (sigma_z, veto_fp) = scorer.evaluate_process_event(&raw_ev);
                                sigma_eval = Some((raw_ev, sigma_z, veto_fp));
                            }

                            if let Some(mut ev) = parse_process_event(&item) {
                                if let Some((raw_ev, sigma_z, veto_fp)) = sigma_eval {
                                    if let Some(obj) = ev.data.as_object_mut() {
                                        obj.insert("SigmaZ".to_string(), serde_json::json!(sigma_z));
                                        obj.insert("CoincidenceVetoFp".to_string(), serde_json::json!(veto_fp));
                                    }

                                    if sigma_z >= 5.0 && !veto_fp {
                                        let comm_or_fn = ev
                                            .data
                                            .get("CommandLine")
                                            .or_else(|| ev.data.get("Image"))
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("")
                                            .to_string();

                                        if let Ok(directive) = responder.isolate_5_sigma_threat(
                                            raw_ev.pid,
                                            raw_ev.pid,
                                            &comm_or_fn,
                                            sigma_z,
                                        ) {
                                            if let Some(map) = bpf.map_mut("quarantine_targets") {
                                                if let Ok(mut hm) =
                                                    BpfHashMap::<_, u32, QuarantineDirective>::try_from(map)
                                                {
                                                    let _ = hm.insert(&raw_ev.pid, &directive, 0);
                                                }
                                            }
                                            let forensic_snapshot =
                                                FrozenProcessForensicCollector::collect_forensic_snapshot(
                                                    raw_ev.pid,
                                                    raw_ev.pid,
                                                    sigma_z,
                                                );
                                            if let Some(obj) = ev.data.as_object_mut() {
                                                obj.insert(
                                                    "QuarantineDirective".to_string(),
                                                    serde_json::to_value(directive).unwrap_or_default(),
                                                );
                                                obj.insert(
                                                    "Frozen5SigmaForensicSnapshot".to_string(),
                                                    serde_json::to_value(forensic_snapshot)
                                                        .unwrap_or_default(),
                                                );
                                            }
                                        }
                                    }
                                }
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
        assert_eq!(std::mem::size_of::<QuarantineDirective>(), 24);
    }

    #[test]
    fn test_quarantine_directive_layout_and_format_u32_newline() {
        assert_eq!(std::mem::size_of::<QuarantineDirective>(), 24);
        assert_eq!(std::mem::align_of::<QuarantineDirective>(), 8);

        let mut buf = [0u8; 16];
        let n0 = QuarantineResponder::format_u32_newline(0, &mut buf);
        assert_eq!(&buf[..n0], b"0\n");

        let n4242 = QuarantineResponder::format_u32_newline(4242, &mut buf);
        assert_eq!(&buf[..n4242], b"4242\n");

        let n_max = QuarantineResponder::format_u32_newline(u32::MAX, &mut buf);
        assert_eq!(&buf[..n_max], b"4294967295\n");
    }

    #[test]
    fn test_quarantine_responder_5_sigma_cgroup_freezer_and_os_immunity() {
        sync_ebpf_lsm_clear_rules();

        let temp_dir = std::env::temp_dir().join(format!(
            "osoosi_cgroup_test_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let cgroup_str = temp_dir.to_string_lossy().to_string();
        let mut responder = QuarantineResponder::new(&cgroup_str);

        // Verify cgroup.freeze was pre-armed with "1\n"
        let freeze_content =
            std::fs::read_to_string(temp_dir.join("cgroup.freeze")).expect("cgroup.freeze exists");
        assert_eq!(freeze_content, "1\n");

        // 1. Verify critical OS & developer processes are strictly vetoed and never written to cgroup.procs
        for protected_proc in ["systemd", "sshd", "explorer.exe", "cargo"] {
            let res = responder.isolate_5_sigma_threat(9001, 9001, protected_proc, 6.25);
            assert!(
                res.is_err(),
                "Protected process '{}' must be vetoed by Host OS & Developer Immunity",
                protected_proc
            );
        }
        assert!(responder
            .isolate_5_sigma_threat(1, 1, "/tmp/rogue", 6.0)
            .is_err());
        assert!(responder
            .isolate_5_sigma_threat(std::process::id(), std::process::id(), "/tmp/rogue", 6.0)
            .is_err());

        let procs_after_vetoes =
            std::fs::read_to_string(temp_dir.join("cgroup.procs")).unwrap_or_default();
        assert!(
            procs_after_vetoes.is_empty(),
            "Vetoed processes must never be written to cgroup.procs"
        );

        // 2. Verify a genuine >= 5.0 sigma rogue process is isolated in both Stage 1 (BPF state) and Stage 2 (cgroup.procs)
        let directive = responder
            .isolate_5_sigma_threat(42420, 42421, "/tmp/memfd_shellcode_loader", 5.45)
            .expect("Rogue 5.45-sigma threat should be isolated");
        assert_eq!(directive.target_pid, 42421);
        assert_eq!(directive.sigma_x100, 545);
        assert_eq!(directive.status, 1);

        let procs_content =
            std::fs::read_to_string(temp_dir.join("cgroup.procs")).expect("cgroup.procs readable");
        assert_eq!(procs_content, "42420\n");

        let st = get_ebpf_lsm_state()
            .read()
            .unwrap_or_else(|e| e.into_inner());
        assert!(st.quarantined_pids.contains(&42420));
        assert!(st
            .quarantine_directives
            .iter()
            .any(|(tgid, d)| *tgid == 42420 && d.sigma_x100 == 545 && d.status == 1));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_frozen_process_forensic_collector_maps_mem_and_syscall() {
        use std::io::{Seek, SeekFrom, Write};

        let proc_root = std::env::temp_dir().join(format!(
            "osoosi_proc_forensic_test_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let tgid = 31337u32;
        let tgid_dir = proc_root.join(tgid.to_string());
        std::fs::create_dir_all(&tgid_dir).expect("create fake proc/<tgid>");

        // Create /proc/<tgid>/maps with a normal backed libc mapping and an unbacked rwxp shellcode mapping at 0x4000..0x4020
        let maps_text = "\
00001000-00002000 r-xp 00000000 08:01 123456 /usr/lib/libc.so.6\n\
00004000-00004020 rwxp 00000000 00:00 0 [anon:shellcode]\n\
00008000-00009000 rw-p 00000000 00:00 0 [heap]\n";
        std::fs::write(tgid_dir.join("maps"), maps_text).expect("write maps");

        // Create /proc/<tgid>/mem with shellcode bytes at offset 0x4000
        let shellcode: [u8; 32] = [
            0x48, 0x31, 0xc0, 0x48, 0x89, 0xc2, 0x48, 0x89, 0xc6, 0x48, 0x8d, 0x3d, 0x04, 0x00,
            0x00, 0x00, 0x04, 0x3b, 0x0f, 0x05, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00,
            0x90, 0x90, 0x90, 0xcc,
        ];
        {
            let mut mem_f = std::fs::File::create(tgid_dir.join("mem")).expect("create mem");
            mem_f.seek(SeekFrom::Start(0x4000)).expect("seek to 0x4000");
            mem_f.write_all(&shellcode).expect("write shellcode");
            mem_f.flush().expect("flush mem");
        }

        // Create /proc/<pid>/syscall
        let syscall_text =
            "10 0x4000 0x1000 0x7 0x0 0x0 0x0 0x7ffd90001120 0x4014\n";
        std::fs::write(tgid_dir.join("syscall"), syscall_text).expect("write syscall");

        let snapshot =
            FrozenProcessForensicCollector::collect_from_proc_root(&proc_root, tgid, tgid, 5.55);

        assert_eq!(snapshot.tgid, tgid);
        assert_eq!(snapshot.anonymous_exec_regions.len(), 1);
        assert_eq!(snapshot.anonymous_exec_regions[0].start_addr, 0x4000);
        assert_eq!(snapshot.anonymous_exec_regions[0].end_addr, 0x4020);
        assert_eq!(snapshot.anonymous_exec_regions[0].permissions, "rwxp");
        assert_eq!(snapshot.extracted_payload_len, 32);
        assert_eq!(snapshot.extracted_payload_hex, hex::encode(shellcode));
        assert_eq!(
            snapshot.payload_blake3,
            blake3::hash(&shellcode).to_hex().to_string()
        );

        let sc = snapshot.syscall_state.expect("syscall state parsed");
        assert_eq!(sc.syscall_nr, 10); // sys_mprotect
        assert_eq!(sc.args[0], 0x4000);
        assert_eq!(sc.args[1], 0x1000);
        assert_eq!(sc.args[2], 0x7);
        assert_eq!(sc.rsp, 0x7ffd90001120);
        assert_eq!(sc.rip, 0x4014);

        assert!(!snapshot.ioc_digest_blake3.is_empty());
        assert!(!snapshot.mesh_ioc_signature.is_empty());

        let _ = std::fs::remove_dir_all(&proc_root);
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

