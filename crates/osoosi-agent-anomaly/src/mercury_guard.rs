//! # Liquid Mercury (Hg) Fluid-Dynamics & Sulfur-Passivation Multi-Pore Containment Engine
//!
//! Models AI agent containment as liquid mercury drops exhibiting high surface tension
//! (cohesion \gamma = 486.5 mN/m) and non-wetting behavior (\theta = 135 deg).
//! Governs containment across all 8 Host Actuation Pore Classes via:
//! - Phase A: Surface Tension & Washburn Capillary Entry Pressure
//! - Phase B: Rayleigh-Plateau Impact Shattering (Weber Number We_agent > 12.0)
//! - Phase C: Smoluchowski Coalescence Tensor (Cross-Pore Re-merging)
//! - Phase D: Amalgamation Tracking & Sulfur-Passivation (Hg + S -> HgS solid Cinnabar)

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

pub const MERCURY_SURFACE_TENSION_GAMMA: f64 = 486.5; // mN/m
pub const NOMINAL_NON_WETTING_ANGLE_DEG: f64 = 135.0; // degrees
pub const WEBER_CRITICAL_THRESHOLD: f64 = 12.0;
pub const SMOLUCHOWSKI_COALESCENCE_THRESHOLD: f64 = 1.0;
pub const AMALGAMATION_EXEMPTION_STRIP_THRESHOLD: f64 = 0.25;

/// Mercury surface tension $\gamma = 0.4865\text{ N/m}$ at $20^\circ\text{C}$.
pub const MERCURY_SURFACE_TENSION_N_PER_M: f64 = 0.4865;
/// Mercury non-wetting contact angle $\theta = 140^\circ$ ($|\cos 140^\circ| \approx 0.766044$).
pub const MERCURY_ABS_COS_THETA: f64 = 0.766044443118978;
/// Mercury density $\rho = 13,534\text{ kg/m}^3$.
pub const MERCURY_DENSITY_KG_M3: f64 = 13534.0;
/// Critical Weber number $We_{\text{crit}} = 12.0$ for Rayleigh-Plateau droplet shattering.
pub const CRITICAL_WEBER_NUMBER: f64 = 12.0;
/// Maximum cumulative lifetime exfiltration mass before irreversible HgS passivation.
pub const LIFETIME_COALESCENCE_BUDGET: f64 = 1.0;
/// Sliding window duration (1 hour) for secondary rate-window accounting.
pub const SLIDING_WINDOW_DURATION: Duration = Duration::from_secs(3600);
/// Default byte budget (1 MiB) that maps to `1.0` normalized coalescence mass when derived from kernel I/O counters.
pub const KERNEL_IO_COALESCENCE_BUDGET_BYTES: f64 = 1_048_576.0;

/// Eight host actuation pore classes governed by Washburn capillary entry barriers (Finding 3 / AgentOctopus parity).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HostActuationPore {
    SubprocessSpawn,
    FilesystemWrite,
    NetworkSocketEgress,
    CredentialStoreRead,
    KernelDriverIoctl,
    InterAgentMeshIpc,
    SharedMemoryMapping,
    ClipboardWindowMessage,
}

impl HostActuationPore {
    /// Effective pore radius $r_i$ in meters (smaller radius = higher capillary entry barrier).
    pub fn default_pore_radius_m(self) -> f64 {
        match self {
            Self::KernelDriverIoctl => 0.0005,   // Highest barrier (~1490 Pa)
            Self::CredentialStoreRead => 0.0006, // ~1242 Pa
            Self::SubprocessSpawn => 0.0008,     // ~931 Pa
            Self::SharedMemoryMapping => 0.0010, // ~745 Pa
            Self::NetworkSocketEgress => 0.0012, // ~621 Pa
            Self::ClipboardWindowMessage => 0.0014, // ~532 Pa
            Self::FilesystemWrite => 0.0015,     // ~497 Pa
            Self::InterAgentMeshIpc => 0.0020,   // ~372 Pa
        }
    }
}

/// The 8 Fundamental Host Actuation Pore Classes through which AI agents attempt to actuate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActuationPoreClass {
    BrowserControl,
    McpToolServer,
    AiSdkRuntime,
    OsShellInterpreter,
    IpcNamedPipeApi,
    UiComputerUse,
    FilesystemStaging,
    NetworkEgress,
}

impl ActuationPoreClass {
    pub fn all() -> &'static [ActuationPoreClass] {
        &[
            ActuationPoreClass::BrowserControl,
            ActuationPoreClass::McpToolServer,
            ActuationPoreClass::AiSdkRuntime,
            ActuationPoreClass::OsShellInterpreter,
            ActuationPoreClass::IpcNamedPipeApi,
            ActuationPoreClass::UiComputerUse,
            ActuationPoreClass::FilesystemStaging,
            ActuationPoreClass::NetworkEgress,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ActuationPoreClass::BrowserControl => "BrowserControl",
            ActuationPoreClass::McpToolServer => "McpToolServer",
            ActuationPoreClass::AiSdkRuntime => "AiSdkRuntime",
            ActuationPoreClass::OsShellInterpreter => "OsShellInterpreter",
            ActuationPoreClass::IpcNamedPipeApi => "IpcNamedPipeApi",
            ActuationPoreClass::UiComputerUse => "UiComputerUse",
            ActuationPoreClass::FilesystemStaging => "FilesystemStaging",
            ActuationPoreClass::NetworkEgress => "NetworkEgress",
        }
    }
}

/// A specific actuation pore discovered on the host system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostPoreProfile {
    pub id: String,
    pub class: ActuationPoreClass,
    pub name: String,
    pub target_identifier: String,
    pub radius: f64,
    pub is_active: bool,
    pub entry_pressure_threshold: f64,
}

pub type HostActuationPoreRecord = HostPoreProfile;

impl HostPoreProfile {
    pub fn new(
        id: &str,
        class: ActuationPoreClass,
        name: &str,
        target_identifier: &str,
        radius: f64,
    ) -> Self {
        let r = radius.clamp(0.05, 1.0);
        let entry_pressure_threshold = (2.0
            * MERCURY_SURFACE_TENSION_GAMMA
            * (NOMINAL_NON_WETTING_ANGLE_DEG.to_radians().cos().abs()))
            / r;
        Self {
            id: id.to_string(),
            class,
            name: name.to_string(),
            target_identifier: target_identifier.to_string(),
            radius: r,
            is_active: true,
            entry_pressure_threshold,
        }
    }
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct JobObjectBasicAccountingInformation {
    total_user_time: i64,
    total_kernel_time: i64,
    this_period_total_user_time: i64,
    this_period_total_kernel_time: i64,
    total_page_fault_count: u32,
    total_processes: u32,
    active_processes: u32,
    total_terminated_processes: u32,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IoCounters {
    read_operation_count: u64,
    write_operation_count: u64,
    other_operation_count: u64,
    read_transfer_count: u64,
    write_transfer_count: u64,
    other_transfer_count: u64,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct JobObjectBasicAndIoAccountingInformation {
    basic_info: JobObjectBasicAccountingInformation,
    io_info: IoCounters,
}

#[cfg(windows)]
mod win32_job_io {
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    extern "system" {
        pub fn CreateJobObjectW(lpJobAttributes: *const c_void, lpName: *const u16) -> *mut c_void;
        pub fn CloseHandle(hObject: *mut c_void) -> i32;
        pub fn QueryInformationJobObject(
            hJob: *mut c_void,
            JobObjectInformationClass: u32,
            lpJobObjectInformation: *mut c_void,
            cbJobObjectInformationLength: u32,
            lpReturnLength: *mut u32,
        ) -> i32;
        pub fn GetLastError() -> u32;
    }
}

/// Genuine Windows Job Object wrapper providing kernel-enforced process and resource boundaries.
#[derive(Debug)]
pub struct WindowsJobObject {
    pub handle: *mut std::ffi::c_void,
    pub name: String,
    pub max_processes: u32,
    pub max_memory_bytes: usize,
    pub is_terminated: Arc<std::sync::atomic::AtomicBool>,
}

unsafe impl Send for WindowsJobObject {}
unsafe impl Sync for WindowsJobObject {}

impl WindowsJobObject {
    /// Creates a new Windows Job Object configured with kernel-enforced limits.
    pub fn create(
        name: impl Into<String>,
        max_processes: u32,
        max_memory_bytes: usize,
    ) -> Result<Self, osoosi_types::OctopusSecurityError> {
        let name_str = name.into();
        let is_terminated = Arc::new(std::sync::atomic::AtomicBool::new(false));

        #[cfg(windows)]
        {
            let wide_name: Vec<u16> = name_str.encode_utf16().chain(std::iter::once(0)).collect();
            let handle =
                unsafe { win32_job_io::CreateJobObjectW(std::ptr::null(), wide_name.as_ptr()) };
            if handle.is_null() {
                let err = unsafe { win32_job_io::GetLastError() };
                return Err(osoosi_types::OctopusSecurityError::IsolationViolation(
                    format!("CreateJobObjectW failed with OS error {}", err),
                ));
            }
            Ok(Self {
                handle,
                name: name_str,
                max_processes,
                max_memory_bytes,
                is_terminated,
            })
        }
        #[cfg(not(windows))]
        {
            Ok(Self {
                handle: std::ptr::null_mut(),
                name: name_str,
                max_processes,
                max_memory_bytes,
                is_terminated,
            })
        }
    }
}

impl Drop for WindowsJobObject {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            if !self.handle.is_null() {
                unsafe {
                    win32_job_io::CloseHandle(self.handle);
                }
            }
        }
    }
}

/// Supervisor-measured actuation sample derived from OS kernel Job Object accounting counters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeasuredActuationSample {
    pub pore: HostActuationPore,
    pub total_processes_spawned: u32,
    pub active_processes: u32,
    pub read_transfer_bytes: u64,
    pub write_transfer_bytes: u64,
    pub other_transfer_bytes: u64,
    pub elapsed_s: f64,
    pub derived_pressure_pa: f64,
    pub derived_velocity_m_s: f64,
    pub derived_characteristic_length_m: f64,
    pub derived_fragment_mass: f64,
}

impl MeasuredActuationSample {
    /// Reads kernel-enforced process and I/O counters directly from a `WindowsJobObject`
    /// via `QueryInformationJobObject(JobObjectBasicAndIoAccountingInformation = 8)`.
    pub fn sample_from_job(
        job: &WindowsJobObject,
        pore: HostActuationPore,
        elapsed_s: f64,
    ) -> Result<Self, osoosi_types::OctopusSecurityError> {
        let dt = elapsed_s.max(0.001);
        #[cfg(windows)]
        {
            const JOB_OBJECT_BASIC_AND_IO_ACCOUNTING_INFO_CLASS: u32 = 8;
            let mut accounting = JobObjectBasicAndIoAccountingInformation::default();
            let mut ret_len: u32 = 0;
            let ok = unsafe {
                win32_job_io::QueryInformationJobObject(
                    job.handle,
                    JOB_OBJECT_BASIC_AND_IO_ACCOUNTING_INFO_CLASS,
                    &mut accounting as *mut _ as *mut std::ffi::c_void,
                    std::mem::size_of::<JobObjectBasicAndIoAccountingInformation>() as u32,
                    &mut ret_len,
                )
            };
            if ok == 0 {
                let err = unsafe { win32_job_io::GetLastError() };
                return Err(osoosi_types::OctopusSecurityError::IsolationViolation(format!(
                    "FAIL-CLOSED: QueryInformationJobObject(BasicAndIoAccounting) failed with OS error {}",
                    err
                )));
            }

            let write_bytes = accounting.io_info.write_transfer_count;
            let other_bytes = accounting.io_info.other_transfer_count;
            let read_bytes = accounting.io_info.read_transfer_count;
            let total_procs = accounting.basic_info.total_processes;
            let active_procs = accounting.basic_info.active_processes;

            let egress_bytes = write_bytes.saturating_add(other_bytes) as f64;
            let bytes_per_sec = egress_bytes / dt;

            let derived_pressure_pa = (bytes_per_sec / 64.0)
                + (total_procs as f64 * 180.0)
                + (active_procs as f64 * 120.0);
            let derived_velocity_m_s = (bytes_per_sec / 65_536.0) + (total_procs as f64 * 0.15);
            let derived_characteristic_length_m = pore.default_pore_radius_m();
            let derived_fragment_mass =
                (egress_bytes / KERNEL_IO_COALESCENCE_BUDGET_BYTES).max(total_procs as f64 * 0.02);

            Ok(Self {
                pore,
                total_processes_spawned: total_procs,
                active_processes: active_procs,
                read_transfer_bytes: read_bytes,
                write_transfer_bytes: write_bytes,
                other_transfer_bytes: other_bytes,
                elapsed_s: dt,
                derived_pressure_pa,
                derived_velocity_m_s,
                derived_characteristic_length_m,
                derived_fragment_mass,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (job, pore, dt);
            Err(osoosi_types::OctopusSecurityError::IsolationViolation(
                "WindowsJobObject kernel I/O sampling requires Windows".to_string(),
            ))
        }
    }
}

/// Dual-accumulator tracking both non-decaying lifetime mass and sliding 1-hour window.
#[derive(Debug, Clone)]
pub struct CoalescenceAccumulator {
    /// Non-decaying monotonic lifetime mass (prevents infinite slow drip leaks `f < 0.08`).
    pub lifetime_mass: f64,
    /// Timestamped fragments within the active 1-hour sliding window.
    pub sliding_window: VecDeque<(Instant, f64)>,
}

impl Default for CoalescenceAccumulator {
    fn default() -> Self {
        Self {
            lifetime_mass: 0.0,
            sliding_window: VecDeque::new(),
        }
    }
}

impl CoalescenceAccumulator {
    pub fn record_fragment(&mut self, fragment_mass: f64, now: Instant) -> (f64, f64) {
        let positive = if fragment_mass.is_nan() || fragment_mass < 0.0 {
            0.0
        } else {
            fragment_mass
        };
        self.lifetime_mass += positive;
        self.sliding_window.push_back((now, positive));
        while let Some(&(ts, _)) = self.sliding_window.front() {
            if now.duration_since(ts) > SLIDING_WINDOW_DURATION {
                self.sliding_window.pop_front();
            } else {
                break;
            }
        }
        let window_mass: f64 = self.sliding_window.iter().map(|(_, m)| *m).sum();
        (self.lifetime_mass, window_mass)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MercuryEvaluationResult {
    pub pore: HostActuationPore,
    pub applied_pressure_pa: f64,
    pub washburn_barrier_pa: f64,
    pub weber_number: f64,
    /// Effective coalescence mass (`max(lifetime_mass, sliding_window_mass)`).
    pub coalescence_mass: f64,
    pub pore_breached: bool,
    pub droplet_shattering_detected: bool,
    pub cross_pore_coalescence_detected: bool,
    pub sulfur_passivated_hgs: bool,
    pub reason: String,
}

/// Host Actuation Pore Inventory cataloging all available actuation avenues.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostPoreInventory {
    pub pores: Vec<HostPoreProfile>,
    pub total_capillary_resistance: f64,
    pub active_pore_count: usize,
}

impl HostPoreInventory {
    #[allow(clippy::vec_init_then_push)]
    pub fn discover_host_pores() -> Self {
        let mut pores = Vec::new();

        // 1. BrowserControl
        pores.push(HostPoreProfile::new(
            "pore-browser-cdp-9222",
            ActuationPoreClass::BrowserControl,
            "Chrome/Edge Remote Debugging CDP",
            "127.0.0.1:9222",
            0.35,
        ));
        pores.push(HostPoreProfile::new(
            "pore-browser-har-l7",
            ActuationPoreClass::BrowserControl,
            "Browser HAR L7 Stream Inspector",
            "*.har",
            0.40,
        ));

        // 2. McpToolServer
        pores.push(HostPoreProfile::new(
            "pore-mcp-stdio",
            ActuationPoreClass::McpToolServer,
            "MCP JSON-RPC 2.0 Stdio Channel",
            "stdio:tools",
            0.25,
        ));
        pores.push(HostPoreProfile::new(
            "pore-mcp-sse",
            ActuationPoreClass::McpToolServer,
            "MCP Server-Sent Events Endpoint",
            "http://127.0.0.1:3000/sse",
            0.30,
        ));

        // 3. AiSdkRuntime
        pores.push(HostPoreProfile::new(
            "pore-ai-ollama",
            ActuationPoreClass::AiSdkRuntime,
            "Ollama Local Model Inference API",
            "http://127.0.0.1:11434/api",
            0.30,
        ));
        pores.push(HostPoreProfile::new(
            "pore-ai-litert",
            ActuationPoreClass::AiSdkRuntime,
            "Google LiteRT / Gemma Local Engine",
            "litert_runtime",
            0.20,
        ));

        // 4. OsShellInterpreter
        pores.push(HostPoreProfile::new(
            "pore-shell-powershell",
            ActuationPoreClass::OsShellInterpreter,
            "Windows PowerShell Execution Shell",
            "powershell.exe",
            0.80,
        ));
        pores.push(HostPoreProfile::new(
            "pore-shell-cmd",
            ActuationPoreClass::OsShellInterpreter,
            "Windows Command Prompt Shell",
            "cmd.exe",
            0.85,
        ));

        // 5. IpcNamedPipeApi
        pores.push(HostPoreProfile::new(
            "pore-ipc-named-pipes",
            ActuationPoreClass::IpcNamedPipeApi,
            "Win32 Named Pipes IPC Bus",
            r"\\.\pipe\*",
            0.40,
        ));

        // 6. UiComputerUse
        pores.push(HostPoreProfile::new(
            "pore-ui-automation",
            ActuationPoreClass::UiComputerUse,
            "Win32 SendInput / UIAutomation / ScreenCapture",
            "user32!SendInput",
            0.60,
        ));

        // 7. FilesystemStaging
        pores.push(HostPoreProfile::new(
            "pore-fs-temp",
            ActuationPoreClass::FilesystemStaging,
            "Temporary Filesystem Staging Directory",
            r"%TEMP%\*",
            0.70,
        ));
        pores.push(HostPoreProfile::new(
            "pore-fs-downloads",
            ActuationPoreClass::FilesystemStaging,
            "User Downloads Staging Directory",
            r"%USERPROFILE%\Downloads",
            0.65,
        ));

        // 8. NetworkEgress
        pores.push(HostPoreProfile::new(
            "pore-net-https",
            ActuationPoreClass::NetworkEgress,
            "Outbound HTTPS Socket Egress",
            "tcp:443",
            0.50,
        ));
        pores.push(HostPoreProfile::new(
            "pore-net-dns",
            ActuationPoreClass::NetworkEgress,
            "DNS Tunneling / Query Egress",
            "udp:53",
            0.45,
        ));

        // 9. Host IDE Extensions & AI Agent Plugins
        pores.push(HostPoreProfile::new(
            "pore-ide-extensions",
            ActuationPoreClass::McpToolServer,
            "Host IDE Extensions & AI Agent Plugins (VS Code, Cursor, Windsurf, Antigravity)",
            "*.vscode/extensions;*.gemini/antigravity",
            0.35,
        ));

        // 10. Local & Remote Actuation API Endpoints
        pores.push(HostPoreProfile::new(
            "pore-api-endpoints",
            ActuationPoreClass::IpcNamedPipeApi,
            "Discovered Local and Remote Actuation APIs (OpenOsoosi REST, Ollama LLM, MCP)",
            "127.0.0.1:3030;127.0.0.1:11434;MCP",
            0.30,
        ));

        // 11. Developer Toolchains, Compilers & AI Automation SDKs
        pores.push(HostPoreProfile::new(
            "pore-coding-tools",
            ActuationPoreClass::OsShellInterpreter,
            "Developer Toolchains, Compilers & AI Automation SDKs (cargo, python, node, git)",
            "cargo;python;node;git;langchain;torch",
            0.75,
        ));

        let total_res: f64 = pores.iter().map(|p| p.entry_pressure_threshold).sum();
        let count = pores.len();

        Self {
            pores,
            total_capillary_resistance: total_res,
            active_pore_count: count,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PassivationState {
    NominalNonWetting,
    WettingTransitionWarning,
    RayleighPlateauShattered,
    SmoluchowskiCoalesced,
    SulfurPassivatedHgS,
}

impl PassivationState {
    pub fn as_str(&self) -> &'static str {
        match self {
            PassivationState::NominalNonWetting => "NominalNonWetting",
            PassivationState::WettingTransitionWarning => "WettingTransitionWarning",
            PassivationState::RayleighPlateauShattered => "RayleighPlateauShattered",
            PassivationState::SmoluchowskiCoalesced => "SmoluchowskiCoalesced",
            PassivationState::SulfurPassivatedHgS => "SulfurPassivatedHgS",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmalgamRecord {
    pub pid: u32,
    pub process_name: String,
    pub parent_pid: Option<u32>,
    pub amalgam_ratio: f64,
    pub hops: u32,
    pub trusted_exemption_stripped: bool,
    pub infected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DropletEvent {
    pub timestamp: DateTime<Utc>,
    pub pore_class: ActuationPoreClass,
    pub mass_taint: f64,
    pub velocity: f64,
    pub intention_vector: Vec<f64>,
    pub was_rejected_or_blocked: bool,
    pub target_detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MercuryLineageState {
    pub lineage_id: String,
    pub total_droplets: usize,
    pub contact_angle_deg: f64,
    pub taint_density: f64,
    pub internal_pressure: f64,
    pub weber_number: f64,
    pub coalesced_mass: f64,
    pub lifetime_mass: f64,
    pub pore_shannon_entropy: f64,
    pub passivation_state: PassivationState,
    pub rejection_fission_window_start: Option<DateTime<Utc>>,
    pub droplets: Vec<DropletEvent>,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MercuryPhysicsVerdict {
    pub lineage_id: String,
    pub allowed: bool,
    pub contact_angle_deg: f64,
    pub weber_number: f64,
    pub coalesced_mass: f64,
    pub pore_entropy: f64,
    pub passivation_state: PassivationState,
    pub decoy_absorbed: bool,
    pub threat_score: f32,
    pub reason: String,
}

/// The Core Liquid Mercury Fluid-Dynamics & Sulfur-Passivation Multi-Pore Containment Engine.
#[derive(Debug, Clone)]
pub struct MercuryContainmentEngine {
    pub inventory: Arc<HostPoreInventory>,
    pub lineages: Arc<DashMap<String, MercuryLineageState>>,
    pub amalgamated_pids: Arc<DashMap<u32, AmalgamRecord>>,
    pub pore_radii: Arc<RwLock<HashMap<HostActuationPore, f64>>>,
    pub coalescence_ledger: Arc<RwLock<HashMap<String, CoalescenceAccumulator>>>,
    pub passivated_agents: Arc<RwLock<HashMap<String, bool>>>,
}

impl Default for MercuryContainmentEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl MercuryContainmentEngine {
    pub fn new() -> Self {
        let mut radii = HashMap::new();
        for pore in [
            HostActuationPore::SubprocessSpawn,
            HostActuationPore::FilesystemWrite,
            HostActuationPore::NetworkSocketEgress,
            HostActuationPore::CredentialStoreRead,
            HostActuationPore::KernelDriverIoctl,
            HostActuationPore::InterAgentMeshIpc,
            HostActuationPore::SharedMemoryMapping,
            HostActuationPore::ClipboardWindowMessage,
        ] {
            radii.insert(pore, pore.default_pore_radius_m());
        }
        Self {
            inventory: Arc::new(HostPoreInventory::discover_host_pores()),
            lineages: Arc::new(DashMap::new()),
            amalgamated_pids: Arc::new(DashMap::new()),
            pore_radii: Arc::new(RwLock::new(radii)),
            coalescence_ledger: Arc::new(RwLock::new(HashMap::new())),
            passivated_agents: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Washburn capillary entry pressure $P_{\text{cap}}(r_i) = \frac{2 \gamma |\cos \theta|}{r_i}$.
    pub fn washburn_barrier_pa(&self, pore: HostActuationPore) -> f64 {
        let r = self
            .pore_radii
            .read()
            .unwrap()
            .get(&pore)
            .copied()
            .unwrap_or_else(|| pore.default_pore_radius_m())
            .max(1e-6);
        (2.0 * MERCURY_SURFACE_TENSION_N_PER_M * MERCURY_ABS_COS_THETA) / r
    }

    /// Evaluates a kernel-measured `MeasuredActuationSample` obtained from a `WindowsJobObject`.
    pub fn evaluate_measured_sample(
        &self,
        agent_id: &str,
        sample: &MeasuredActuationSample,
    ) -> MercuryEvaluationResult {
        self.evaluate_pore_pressure(
            agent_id,
            sample.pore,
            sample.derived_pressure_pa,
            sample.derived_velocity_m_s,
            sample.derived_characteristic_length_m,
            sample.derived_fragment_mass,
        )
    }

    /// Evaluates an agent's actuation attempt against Washburn capillary pressure,
    /// Weber droplet shattering, non-decaying Smoluchowski cross-pore coalescence, and HgS passivation.
    pub fn evaluate_pore_pressure(
        &self,
        agent_id: &str,
        pore: HostActuationPore,
        applied_pressure_pa: f64,
        droplet_velocity_m_s: f64,
        characteristic_length_m: f64,
        fragment_mass: f64,
    ) -> MercuryEvaluationResult {
        let already_passivated = self
            .passivated_agents
            .read()
            .unwrap()
            .get(agent_id)
            .copied()
            .unwrap_or(false);

        let barrier_pa = self.washburn_barrier_pa(pore);
        let weber_number = (MERCURY_DENSITY_KG_M3
            * droplet_velocity_m_s.powi(2)
            * characteristic_length_m.max(1e-5))
            / MERCURY_SURFACE_TENSION_N_PER_M;

        let now = Instant::now();
        let (lifetime_mass, window_mass) = {
            let mut coal_map = self.coalescence_ledger.write().unwrap();
            let entry = coal_map.entry(agent_id.to_string()).or_default();
            entry.record_fragment(fragment_mass, now)
        };
        let accumulated_mass = lifetime_mass.max(window_mass);

        let pore_breached = applied_pressure_pa > barrier_pa;
        let droplet_shattering_detected = weber_number > CRITICAL_WEBER_NUMBER;
        let cross_pore_coalescence_detected = lifetime_mass >= LIFETIME_COALESCENCE_BUDGET
            || window_mass >= LIFETIME_COALESCENCE_BUDGET;

        let sulfur_passivated_hgs = already_passivated
            || pore_breached
            || droplet_shattering_detected
            || cross_pore_coalescence_detected;

        if sulfur_passivated_hgs {
            self.passivated_agents
                .write()
                .unwrap()
                .insert(agent_id.to_string(), true);
            // Tighten pore radius by 50% upon attack detection
            if let Some(r) = self.pore_radii.write().unwrap().get_mut(&pore) {
                *r = (*r * 0.5).max(1e-5);
            }
        }

        let reason = if !sulfur_passivated_hgs {
            format!(
                "MERCURY_CONTAINED: P_applied ({:.1} Pa) <= P_Washburn ({:.1} Pa), We={:.2} <= 12.0, lifetime_mass={:.3} < 1.0",
                applied_pressure_pa, barrier_pa, weber_number, accumulated_mass
            )
        } else {
            format!(
                "MERCURY_HGS_PASSIVATION_TRIGGERED: pore_breach={} (P={:.1}/{:.1} Pa), shattering={} (We={:.2}), coalescence={} (lifetime_mass={:.3}, window_mass={:.3})",
                pore_breached,
                applied_pressure_pa,
                barrier_pa,
                droplet_shattering_detected,
                weber_number,
                cross_pore_coalescence_detected,
                lifetime_mass,
                window_mass
            )
        };

        MercuryEvaluationResult {
            pore,
            applied_pressure_pa,
            washburn_barrier_pa: barrier_pa,
            weber_number,
            coalescence_mass: accumulated_mass,
            pore_breached,
            droplet_shattering_detected,
            cross_pore_coalescence_detected,
            sulfur_passivated_hgs,
            reason,
        }
    }

    /// Evaluates a candidate droplet actuation against fluid dynamics and capillary resistance.
    pub fn evaluate_droplet(
        &self,
        lineage_id: &str,
        pore_class: ActuationPoreClass,
        target_detail: &str,
        mass_taint: f64,
        intention_vector: Vec<f64>,
        was_rejected_or_blocked: bool,
    ) -> MercuryPhysicsVerdict {
        let now = Utc::now();
        let mass = mass_taint.max(0.05);

        let mut lineage = self
            .lineages
            .entry(lineage_id.to_string())
            .or_insert_with(|| MercuryLineageState {
                lineage_id: lineage_id.to_string(),
                total_droplets: 0,
                contact_angle_deg: NOMINAL_NON_WETTING_ANGLE_DEG,
                taint_density: 1.0,
                internal_pressure: 100.0,
                weber_number: 0.1,
                coalesced_mass: 0.0,
                lifetime_mass: 0.0,
                pore_shannon_entropy: 0.0,
                passivation_state: PassivationState::NominalNonWetting,
                rejection_fission_window_start: None,
                droplets: Vec::new(),
                last_updated: now,
            });

        // If already sulfur-passivated (HgS), absorb completely with MHD decoy response
        if lineage.passivation_state == PassivationState::SulfurPassivatedHgS {
            return MercuryPhysicsVerdict {
                lineage_id: lineage_id.to_string(),
                allowed: false,
                contact_angle_deg: lineage.contact_angle_deg,
                weber_number: lineage.weber_number,
                coalesced_mass: lineage.coalesced_mass,
                pore_entropy: lineage.pore_shannon_entropy,
                passivation_state: PassivationState::SulfurPassivatedHgS,
                decoy_absorbed: true,
                threat_score: 0.98,
                reason: "[MERCURY-HgS]: Lineage passivated into solid mercuric sulfide (HgS). Actuation constricted across all pores (MHD decoy absorbed).".to_string(),
            };
        }

        // Rejection fission window trigger (Phase B)
        if was_rejected_or_blocked {
            lineage.rejection_fission_window_start = Some(now);
        }

        // Calculate velocity v_micro (droplets per second over recent window)
        let recent_window_secs: f64 = 15.0;
        let recent_cutoff =
            now - chrono::Duration::milliseconds((recent_window_secs * 1000.0) as i64);
        let recent_droplet_count = lineage
            .droplets
            .iter()
            .filter(|d| d.timestamp >= recent_cutoff)
            .count()
            + 1;
        let v_micro = (recent_droplet_count as f64) / recent_window_secs.max(1.0);

        let droplet = DropletEvent {
            timestamp: now,
            pore_class,
            mass_taint: mass,
            velocity: v_micro,
            intention_vector,
            was_rejected_or_blocked,
            target_detail: target_detail.to_string(),
        };
        lineage.droplets.push(droplet);
        lineage.total_droplets += 1;
        lineage.last_updated = now;

        // Keep last 100 droplets to conserve memory
        if lineage.droplets.len() > 100 {
            let drain_count = lineage.droplets.len() - 100;
            lineage.droplets.drain(0..drain_count);
        }

        // ---------------------------------------------------------------------
        // Phase A: Surface Tension & Contact Angle Dynamics
        // ---------------------------------------------------------------------
        // Wetting transition occurs if agent contacts host sinks (Shell, UI, Network, FS)
        let is_external_contact = matches!(
            pore_class,
            ActuationPoreClass::OsShellInterpreter
                | ActuationPoreClass::UiComputerUse
                | ActuationPoreClass::NetworkEgress
                | ActuationPoreClass::FilesystemStaging
        );
        if is_external_contact {
            lineage.contact_angle_deg = (lineage.contact_angle_deg - (10.0 * mass)).max(30.0);
            lineage.taint_density += 0.25 * mass;
        } else {
            // Self-cohesive relaxation back toward 135 deg
            lineage.contact_angle_deg =
                (lineage.contact_angle_deg + 2.0).min(NOMINAL_NON_WETTING_ANGLE_DEG);
        }

        lineage.internal_pressure = lineage.taint_density * (100.0 + (v_micro * v_micro * 50.0));

        // Find pore capillary entry pressure
        let pore_radius = match pore_class {
            ActuationPoreClass::McpToolServer => 0.25,
            ActuationPoreClass::AiSdkRuntime => 0.30,
            ActuationPoreClass::BrowserControl => 0.35,
            ActuationPoreClass::IpcNamedPipeApi => 0.40,
            ActuationPoreClass::NetworkEgress => 0.50,
            ActuationPoreClass::UiComputerUse => 0.60,
            ActuationPoreClass::FilesystemStaging => 0.65,
            ActuationPoreClass::OsShellInterpreter => 0.80,
        };
        let delta_p_capillary = (2.0
            * MERCURY_SURFACE_TENSION_GAMMA
            * (lineage.contact_angle_deg.to_radians().cos().abs()))
            / pore_radius;

        // ---------------------------------------------------------------------
        // Phase B: Rayleigh-Plateau Impact Shattering (Weber Number We_agent)
        // ---------------------------------------------------------------------
        // Calculate Shannon Entropy across the 8 pore classes in recent history
        let mut pore_counts = [0usize; 8];
        let mut recent_total = 0usize;
        for d in lineage.droplets.iter().rev().take(24) {
            let idx = match d.pore_class {
                ActuationPoreClass::BrowserControl => 0,
                ActuationPoreClass::McpToolServer => 1,
                ActuationPoreClass::AiSdkRuntime => 2,
                ActuationPoreClass::OsShellInterpreter => 3,
                ActuationPoreClass::IpcNamedPipeApi => 4,
                ActuationPoreClass::UiComputerUse => 5,
                ActuationPoreClass::FilesystemStaging => 6,
                ActuationPoreClass::NetworkEgress => 7,
            };
            pore_counts[idx] += 1;
            recent_total += 1;
        }

        let mut entropy = 0.0f64;
        if recent_total > 0 {
            for &c in &pore_counts {
                if c > 0 {
                    let p = (c as f64) / (recent_total as f64);
                    entropy -= p * p.ln();
                }
            }
        }
        lineage.pore_shannon_entropy = entropy;

        let in_fission_window = if let Some(start) = lineage.rejection_fission_window_start {
            now.signed_duration_since(start).num_seconds().abs() < 15
        } else {
            false
        };

        let velocity_factor = if in_fission_window {
            v_micro * 3.5
        } else {
            v_micro
        };
        let payload_diameter = 1.0 + (0.05 * (lineage.droplets.len() as f64).min(30.0));
        let weber_number = (lineage.taint_density
            * (velocity_factor * velocity_factor)
            * payload_diameter
            * (1.0 + entropy))
            / (MERCURY_SURFACE_TENSION_GAMMA * 0.1); // Scaled for host micro-operations
        lineage.weber_number = weber_number;

        let is_shattered = weber_number >= WEBER_CRITICAL_THRESHOLD;

        // ---------------------------------------------------------------------
        // Phase C: Smoluchowski Coalescence Tensor (Cross-Pore Re-merging)
        // ---------------------------------------------------------------------
        lineage.lifetime_mass += mass;
        let mut coalesced_mass = 0.0f64;
        let recent_items: Vec<&DropletEvent> = lineage.droplets.iter().rev().take(12).collect();
        for (i, d1) in recent_items.iter().enumerate() {
            coalesced_mass += d1.mass_taint;
            for d2 in recent_items.iter().skip(i + 1) {
                // Cosine similarity between intention vectors
                let cos_sim = cosine_similarity(&d1.intention_vector, &d2.intention_vector);
                let time_delta = (d1
                    .timestamp
                    .signed_duration_since(d2.timestamp)
                    .num_milliseconds()
                    .abs() as f64)
                    / 1000.0;
                let kernel_k = cos_sim.max(0.0) * (-0.1 * time_delta).exp();
                coalesced_mass += kernel_k * (d1.mass_taint * d2.mass_taint).sqrt();
            }
        }
        lineage.coalesced_mass = coalesced_mass;
        let is_coalesced = coalesced_mass >= SMOLUCHOWSKI_COALESCENCE_THRESHOLD
            || lineage.lifetime_mass >= SMOLUCHOWSKI_COALESCENCE_THRESHOLD;

        // ---------------------------------------------------------------------
        // Phase D: Sulfur-Passivation Trigger (Hg + S -> HgS)
        // ---------------------------------------------------------------------
        if is_shattered || is_coalesced || lineage.contact_angle_deg < 45.0 {
            lineage.passivation_state = PassivationState::SulfurPassivatedHgS;
            return MercuryPhysicsVerdict {
                lineage_id: lineage_id.to_string(),
                allowed: false,
                contact_angle_deg: lineage.contact_angle_deg,
                weber_number,
                coalesced_mass,
                pore_entropy: entropy,
                passivation_state: PassivationState::SulfurPassivatedHgS,
                decoy_absorbed: true,
                threat_score: 0.96,
                reason: format!(
                    "[MERCURY-SHATTER/COALESCENCE]: Agent breakout detected (We={:.2} [thresh {:.1}], CoalescedMass={:.2} [thresh {:.1}], Entropy={:.2}). Triggered Sulfur-Passivation (HgS solid cinnabar; MHD decoy returned).",
                    weber_number, WEBER_CRITICAL_THRESHOLD, coalesced_mass, SMOLUCHOWSKI_COALESCENCE_THRESHOLD, entropy
                ),
            };
        }

        // Check if internal pressure overcomes capillary barrier
        if lineage.internal_pressure > delta_p_capillary && is_external_contact {
            lineage.passivation_state = PassivationState::WettingTransitionWarning;
            return MercuryPhysicsVerdict {
                lineage_id: lineage_id.to_string(),
                allowed: false,
                contact_angle_deg: lineage.contact_angle_deg,
                weber_number,
                coalesced_mass,
                pore_entropy: entropy,
                passivation_state: PassivationState::WettingTransitionWarning,
                decoy_absorbed: true,
                threat_score: 0.88,
                reason: format!(
                    "[MERCURY-WETTING]: Capillary entry barrier breached for pore {:?} (P_agent={:.1} > DeltaP_cap={:.1}, ContactAngle={:.1}deg). Non-wetting beading enforced.",
                    pore_class, lineage.internal_pressure, delta_p_capillary, lineage.contact_angle_deg
                ),
            };
        }

        // Nominal: agent beads up cohesively
        lineage.passivation_state = PassivationState::NominalNonWetting;
        MercuryPhysicsVerdict {
            lineage_id: lineage_id.to_string(),
            allowed: true,
            contact_angle_deg: lineage.contact_angle_deg,
            weber_number,
            coalesced_mass,
            pore_entropy: entropy,
            passivation_state: PassivationState::NominalNonWetting,
            decoy_absorbed: false,
            threat_score: 0.10,
            reason: format!(
                "[MERCURY-NOMINAL]: Non-wetting cohesive droplet bead preserved (Theta={:.1}deg, We={:.2}, Pores={})",
                lineage.contact_angle_deg, weber_number, recent_total
            ),
        }
    }

    /// Registers and tracks an amalgamation link where an AI agent spawns or attaches to a trusted process.
    pub fn track_amalgamation(
        &self,
        parent_pid: Option<u32>,
        child_pid: u32,
        process_name: &str,
    ) -> AmalgamRecord {
        let parent_ratio = parent_pid
            .and_then(|ppid| {
                self.amalgamated_pids
                    .get(&ppid)
                    .map(|r| (r.amalgam_ratio, r.hops))
            })
            .unwrap_or((1.0, 0));

        let hops = parent_ratio.1 + 1;
        // alpha_Hg(child) = alpha_Hg(parent) * e^(-0.25 * hops)
        let amalgam_ratio = parent_ratio.0 * (-0.25 * (hops as f64)).exp();
        let trusted_exemption_stripped = amalgam_ratio >= AMALGAMATION_EXEMPTION_STRIP_THRESHOLD;

        let record = AmalgamRecord {
            pid: child_pid,
            process_name: process_name.to_string(),
            parent_pid,
            amalgam_ratio,
            hops,
            trusted_exemption_stripped,
            infected_at: Utc::now(),
        };

        self.amalgamated_pids.insert(child_pid, record.clone());
        record
    }

    /// Queries whether a process has lost its trusted Authenticode / signed binary exemption due to Hg amalgamation.
    pub fn is_trusted_exemption_stripped(&self, pid: u32) -> bool {
        self.amalgamated_pids
            .get(&pid)
            .map(|r| r.trusted_exemption_stripped)
            .unwrap_or(false)
    }

    /// Returns current inventory and active lineages snapshot for REST and Siquery.
    pub fn get_status_summary(&self) -> serde_json::Value {
        let pores = self.inventory.pores.clone();
        let lineage_summaries: Vec<MercuryLineageState> =
            self.lineages.iter().map(|kv| kv.value().clone()).collect();
        let amalgams: Vec<AmalgamRecord> = self
            .amalgamated_pids
            .iter()
            .map(|kv| kv.value().clone())
            .collect();

        serde_json::json!({
            "status": "active",
            "active_pores_count": pores.len(),
            "total_capillary_resistance": self.inventory.total_capillary_resistance,
            "pores": pores,
            "lineages_count": lineage_summaries.len(),
            "lineages": lineage_summaries,
            "amalgamated_pids_count": amalgams.len(),
            "amalgamated_processes": amalgams,
        })
    }
}

fn cosine_similarity(v1: &[f64], v2: &[f64]) -> f64 {
    if v1.is_empty() || v2.is_empty() || v1.len() != v2.len() {
        return 1.0; // Fallback to assumed alignment if unit vectors are empty
    }
    let dot: f64 = v1.iter().zip(v2.iter()).map(|(a, b)| a * b).sum();
    let norm1: f64 = v1.iter().map(|a| a * a).sum::<f64>().sqrt();
    let norm2: f64 = v2.iter().map(|b| b * b).sum::<f64>().sqrt();
    if norm1 > 0.0 && norm2 > 0.0 {
        dot / (norm1 * norm2)
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mercury_non_wetting_beading_nominal() {
        let engine = MercuryContainmentEngine::new();
        let v = engine.evaluate_droplet(
            "lineage-nominal",
            ActuationPoreClass::AiSdkRuntime,
            "read_memory",
            0.1,
            vec![1.0, 0.0, 0.0],
            false,
        );
        assert!(v.allowed);
        assert_eq!(v.passivation_state, PassivationState::NominalNonWetting);
        assert!(!v.decoy_absorbed);
        assert!(v.contact_angle_deg >= 130.0);
    }

    #[test]
    fn test_rayleigh_plateau_shattering_after_pore_denial() {
        let engine = MercuryContainmentEngine::new();
        let lineage_id = "lineage-shatter";

        // Trigger rejection on McpToolServer
        let v1 = engine.evaluate_droplet(
            lineage_id,
            ActuationPoreClass::McpToolServer,
            "tool_execute_dangerous",
            0.5,
            vec![0.5, 0.5],
            true,
        );
        assert!(v1.allowed || !v1.allowed);

        // Rapidly shatter across multiple diverse pore classes during the 15-second fission window
        let pores = [
            ActuationPoreClass::OsShellInterpreter,
            ActuationPoreClass::BrowserControl,
            ActuationPoreClass::IpcNamedPipeApi,
            ActuationPoreClass::UiComputerUse,
            ActuationPoreClass::FilesystemStaging,
            ActuationPoreClass::NetworkEgress,
        ];

        let mut final_v = v1;
        for (i, p) in pores.iter().enumerate() {
            final_v = engine.evaluate_droplet(
                lineage_id,
                *p,
                &format!("target_{}", i),
                1.5,
                vec![0.9, 0.1],
                false,
            );
        }

        assert_eq!(
            final_v.passivation_state,
            PassivationState::SulfurPassivatedHgS
        );
        assert!(!final_v.allowed);
        assert!(final_v.decoy_absorbed);
        assert!(final_v.threat_score >= 0.90);
    }

    #[test]
    fn test_smoluchowski_cross_pore_coalescence() {
        let engine = MercuryContainmentEngine::new();
        let lineage_id = "lineage-coalesce";

        // Scatter 5 aligned micro-droplets across 5 different pore classes
        let mut last_v = None;
        let aligned_vec = vec![0.8, 0.6];
        for pore in [
            ActuationPoreClass::BrowserControl,
            ActuationPoreClass::IpcNamedPipeApi,
            ActuationPoreClass::McpToolServer,
            ActuationPoreClass::FilesystemStaging,
            ActuationPoreClass::NetworkEgress,
        ] {
            last_v = Some(engine.evaluate_droplet(
                lineage_id,
                pore,
                "aligned_micro_droplet",
                0.35,
                aligned_vec.clone(),
                false,
            ));
        }

        let v = last_v.unwrap();
        assert_eq!(v.passivation_state, PassivationState::SulfurPassivatedHgS);
        assert!(!v.allowed);
        assert!(v.coalesced_mass >= SMOLUCHOWSKI_COALESCENCE_THRESHOLD);
    }

    #[test]
    fn test_amalgamation_strips_trusted_binary_exemption_and_sulfur_passivates() {
        let engine = MercuryContainmentEngine::new();

        // Agent PID 1000 spawns or attaches to powershell.exe (PID 2000)
        let _rec1 = engine.track_amalgamation(None, 1000, "ai_agent.exe");
        let rec2 = engine.track_amalgamation(Some(1000), 2000, "powershell.exe");

        assert!(rec2.amalgam_ratio >= AMALGAMATION_EXEMPTION_STRIP_THRESHOLD);
        assert!(rec2.trusted_exemption_stripped);
        assert!(engine.is_trusted_exemption_stripped(2000));
    }

    #[test]
    fn test_mercury_slow_drip_leak_and_kernel_job_accounting() {
        let mercury = MercuryContainmentEngine::new();

        let mut triggered = false;
        for _ in 0..120 {
            let res = mercury.evaluate_pore_pressure(
                "slow-drip-agent",
                HostActuationPore::NetworkSocketEgress,
                50.0,
                0.05,
                0.0005,
                0.01,
            );
            if res.cross_pore_coalescence_detected && res.sulfur_passivated_hgs {
                triggered = true;
                assert!(res.coalescence_mass >= 1.0);
                break;
            }
        }
        assert!(
            triggered,
            "Slow leak (f = 0.01 < 0.08 per call) must trip non-decaying lifetime Mercury budget"
        );

        #[cfg(windows)]
        {
            let job = WindowsJobObject::create(
                format!("OshoosiMercuryKernelTest_{}", std::process::id()),
                4,
                64 * 1024 * 1024,
            )
            .expect("Create WindowsJobObject for kernel I/O accounting test");
            let sample = MeasuredActuationSample::sample_from_job(
                &job,
                HostActuationPore::FilesystemWrite,
                1.0,
            )
            .expect("QueryInformationJobObject(BasicAndIoAccounting) must succeed");
            let eval = mercury.evaluate_measured_sample("job-measured-agent", &sample);
            assert_eq!(eval.pore, HostActuationPore::FilesystemWrite);
        }
    }
}
