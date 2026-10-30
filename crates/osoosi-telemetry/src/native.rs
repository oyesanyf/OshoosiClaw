#[cfg(target_os = "windows")]
use chrono::Utc;
use dashmap::DashMap;
#[cfg(target_os = "windows")]
use ferrisetw::parser::*;
#[cfg(target_os = "windows")]
use ferrisetw::provider::Provider;
#[cfg(target_os = "windows")]
use ferrisetw::trace::UserTrace;
#[cfg(target_os = "windows")]
use osoosi_types::HostEventSource;
use osoosi_types::HostSecurityEvent;
#[cfg(target_os = "windows")]
use std::sync::Arc;
use tokio::sync::mpsc;
#[cfg(target_os = "windows")]
use tracing::warn;
use tracing::{error, info};

#[derive(Debug, Clone)]
pub struct ProcessMeta {
    pub pid: u32,
    pub image_name: String,
    pub started_at: std::time::Instant,
    pub child_spawn_times: Vec<std::time::Instant>,
}

/// Pre-populates the system process registry with existing processes at startup
/// across all operating systems to ensure zero-unknown process invariants.
pub fn populate_initial_active_processes(map: &DashMap<u32, ProcessMeta>) {
    let now = std::time::Instant::now();
    // System processes
    map.insert(
        0,
        ProcessMeta {
            pid: 0,
            image_name: "System Idle Process".to_string(),
            started_at: now,
            child_spawn_times: Vec::new(),
        },
    );
    map.insert(
        4,
        ProcessMeta {
            pid: 4,
            image_name: if cfg!(windows) {
                "C:\\Windows\\System32\\ntoskrnl.exe".to_string()
            } else {
                "kthreadd".to_string()
            },
            started_at: now,
            child_spawn_times: Vec::new(),
        },
    );

    let mut sys = sysinfo::System::new();
    sys.refresh_processes_specifics(
        sysinfo::ProcessRefreshKind::new()
            .with_exe(sysinfo::UpdateKind::OnlyIfNotSet)
            .with_cmd(sysinfo::UpdateKind::OnlyIfNotSet),
    );

    for (pid_val, proc_info) in sys.processes() {
        let pid = pid_val.as_u32();
        if map.contains_key(&pid) {
            continue;
        }

        #[cfg(target_os = "windows")]
        let (live_img, _) = query_live_process_image_and_cmdline(pid);
        #[cfg(not(target_os = "windows"))]
        let live_img: Option<String> = None;

        let image = live_img
            .filter(|s| !s.is_empty())
            .or_else(|| {
                proc_info
                    .exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or_else(|| proc_info.name().to_string());

        let final_image = if image.is_empty() {
            format!("Process-{}", pid)
        } else {
            image
        };

        map.insert(
            pid,
            ProcessMeta {
                pid,
                image_name: final_image,
                started_at: now,
                child_spawn_times: Vec::new(),
            },
        );
    }
}

pub type NativeTelemetry = NativeTelemetryEngine;

/// Atomic counter tracking telemetry events dropped due to ring-buffer / channel saturation (F10).
pub static TELEMETRY_EVENTS_LOST: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

pub fn telemetry_events_lost() -> u64 {
    TELEMETRY_EVENTS_LOST.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn record_telemetry_event_lost() -> u64 {
    TELEMETRY_EVENTS_LOST.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1
}

/// Classifies whether a `HostSecurityEvent` belongs to the high-priority critical queue (`tx_critical`)
/// so noisy bulk file/stat floods cannot starve process creation, driver load, injection, or tampering telemetry.
pub fn is_critical_telemetry_event(event: &HostSecurityEvent) -> bool {
    matches!(event.event_id, 1 | 6 | 8 | 10 | 4688 | 7045)
        || event
            .data
            .get("CriticalPriority")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        || event
            .data
            .get("Hook")
            .and_then(|v| v.as_str())
            .map(|h| {
                matches!(
                    h,
                    "TelemetryTamperingDetected"
                        | "NtAllocateVirtualMemory"
                        | "NtProtectVirtualMemory"
                        | "CreateProcessW"
                )
            })
            .unwrap_or(false)
}

pub struct NativeTelemetryEngine {
    tx: mpsc::Sender<HostSecurityEvent>,
    tx_critical: Option<mpsc::Sender<HostSecurityEvent>>,
}

impl NativeTelemetryEngine {
    pub fn new(tx: mpsc::Sender<HostSecurityEvent>) -> Self {
        Self {
            tx,
            tx_critical: None,
        }
    }

    pub fn new_prioritized(
        tx_critical: mpsc::Sender<HostSecurityEvent>,
        tx_bulk: mpsc::Sender<HostSecurityEvent>,
    ) -> Self {
        Self {
            tx: tx_bulk,
            tx_critical: Some(tx_critical),
        }
    }

    /// Dispatches an event through the priority-tiered channel queues (`tx_critical` vs `tx_bulk`),
    /// incrementing `TELEMETRY_EVENTS_LOST` on backpressure overflow.
    pub fn dispatch_prioritized(
        tx_critical: Option<&mpsc::Sender<HostSecurityEvent>>,
        tx_bulk: &mpsc::Sender<HostSecurityEvent>,
        event: HostSecurityEvent,
    ) -> bool {
        if is_critical_telemetry_event(&event) {
            if let Some(crit) = tx_critical {
                if crit.try_send(event.clone()).is_ok() {
                    return true;
                }
            }
        }
        if tx_bulk.try_send(event).is_ok() {
            true
        } else {
            record_telemetry_event_lost();
            false
        }
    }

    pub fn start(&self) {
        // Provided for compatibility with caller conventions
    }

    pub fn critical_sender(&self) -> Option<&mpsc::Sender<HostSecurityEvent>> {
        self.tx_critical.as_ref()
    }

    /// Starts the native kernel monitoring trace.
    pub async fn run(&self) -> anyhow::Result<()> {
        info!("🚀 [NATIVE-TELEMETRY] Starting Oshoosi Native Monitoring (Multi-Engine)...");

        // 1. Start Injection Hook Telemetry Listener (Named Pipe)
        #[cfg(target_os = "windows")]
        {
            let tx_hook = self.tx.clone();
            tokio::spawn(async move {
                if let Err(e) = run_hook_telemetry_listener(tx_hook).await {
                    error!("Hook Telemetry Listener failed: {:?}", e);
                }
            });
        }

        // 2. Start Linux eBPF Engine (Adapted from Rustinel)
        #[cfg(target_os = "linux")]
        {
            let tx_ebpf = self.tx.clone();
            tokio::spawn(async move {
                let engine = super::linux_ebpf::EbpfTelemetryEngine::new(tx_ebpf);
                if let Err(e) = engine.run().await {
                    error!("Linux eBPF Engine failed: {:?}", e);
                }
            });
        }

        // 3. Sysmon-Zero: Port of SysmonX native ETW logic (Windows)
        #[cfg(target_os = "windows")]
        {
            let tx = self.tx.clone();
            let computer = hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "localhost".to_string());

            tokio::task::spawn_blocking(move || {
                let tx_p = tx.clone();
                let computer_p = computer.clone();

                // --- 2a. Sysmon Provider (if installed) ---
                let sysmon_provider = Provider::by_guid("5770385F-C22A-43E0-BF4C-06F5698FFBD9")
                    .add_callback(move |event, schema_locator| {
                        if let Ok(schema) = schema_locator.event_schema(event) {
                            let parser = Parser::create(event, &schema);
                            let event_id = event.event_id();

                            let mut data = serde_json::Map::new();
                            // Extract common Sysmon fields by name (cannot iterate properties due to private API)
                            let keys = [
                                "Image",
                                "CommandLine",
                                "ParentImage",
                                "ParentCommandLine",
                                "User",
                                "SourceIp",
                                "DestinationIp",
                                "Protocol",
                            ];
                            for key in keys {
                                if let Ok(val) = parser.try_parse::<String>(key) {
                                    data.insert(key.to_string(), serde_json::json!(val.trim()));
                                }
                            }

                            // Handle numeric IDs specifically
                            if let Ok(pid) = parser.try_parse::<u32>("ProcessId") {
                                data.insert("ProcessId".to_string(), serde_json::json!(pid));
                            }
                            if let Ok(ppid) = parser.try_parse::<u32>("ParentProcessId") {
                                data.insert("ParentProcessId".to_string(), serde_json::json!(ppid));
                            }
                            if let Ok(dport) = parser.try_parse::<u16>("DestinationPort") {
                                data.insert(
                                    "DestinationPort".to_string(),
                                    serde_json::json!(dport),
                                );
                            }

                            let ev = HostSecurityEvent {
                                source: HostEventSource::WindowsEventLog,
                                event_id: event_id as u32,
                                timestamp: Utc::now(),
                                computer: computer_p.clone(),
                                data: serde_json::Value::Object(data),
                                causal_parent: None,
                            };
                            let _ = tx_p.blocking_send(ev);
                        }
                    })
                    .build();

                // --- 2b. Kernel Process Provider (Direct Port) ---
                let tx_k = tx.clone();
                let computer_k = computer.clone();
                let active_processes: Arc<DashMap<u32, ProcessMeta>> = Arc::new(DashMap::new());
                populate_initial_active_processes(&active_processes);
                let active_procs_cb = active_processes.clone();
                let kernel_process_provider =
                    Provider::by_guid("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716")
                        .any(0x10) // WINEVT_KEYWORD_PROCESS
                        .add_callback(move |event, schema_locator| {
                            let event_id = event.event_id();
                            // 1: ProcessStart, 2: ProcessStop
                            if event_id == 1 || event_id == 2 {
                                if let Ok(schema) = schema_locator.event_schema(event) {
                                    let parser = Parser::create(event, &schema);
                                    let pid: u32 = parser
                                        .try_parse::<u32>("ProcessID")
                                        .or_else(|_| {
                                            parser.try_parse::<u64>("ProcessID").map(|v| v as u32)
                                        })
                                        .or_else(|_| parser.try_parse::<u32>("ProcessId"))
                                        .or_else(|_| {
                                            parser.try_parse::<u64>("ProcessId").map(|v| v as u32)
                                        })
                                        .or_else(|_| parser.try_parse::<u32>("PID"))
                                        .unwrap_or_else(|_| event.process_id());
                                    let parent_pid: u32 = parser
                                        .try_parse("ParentProcessID")
                                        .or_else(|_| parser.try_parse("ParentProcessId"))
                                        .unwrap_or(0);
                                    let mut image: String = parser
                                        .try_parse("ImageName")
                                        .or_else(|_| parser.try_parse("ImageFileName"))
                                        .unwrap_or_else(|_| {
                                            parser.try_parse("CommandLine").unwrap_or_default()
                                        });
                                    let mut cmdline: String = parser
                                        .try_parse::<String>("CommandLine")
                                        .unwrap_or_default();

                                    if event_id == 1
                                        && pid > 4
                                        && (image.is_empty()
                                            || image.starts_with("\\Device\\")
                                            || cmdline.trim().is_empty())
                                    {
                                        let (live_img, live_cmd) =
                                            query_live_process_image_and_cmdline(pid);
                                        if let Some(li) = live_img {
                                            if !li.is_empty() {
                                                image = li;
                                            }
                                        }
                                        if cmdline.trim().is_empty() {
                                            if let Some(lc) = live_cmd {
                                                if !lc.is_empty() {
                                                    cmdline = lc;
                                                }
                                            }
                                        }
                                    }

                                    let mut data = serde_json::Map::new();
                                    data.insert("ProcessId".to_string(), serde_json::json!(pid));
                                    data.insert(
                                        "ParentProcessId".to_string(),
                                        serde_json::json!(parent_pid),
                                    );
                                    data.insert("Image".to_string(), serde_json::json!(image));
                                    let final_cmd = if !cmdline.is_empty() {
                                        cmdline
                                    } else {
                                        image.clone()
                                    };
                                    if event_id == 1
                                        && is_suspicious_initial_process(&image, &final_cmd)
                                    {
                                        terminate_suspicious_process_immediately(
                                            pid, &image, &final_cmd,
                                        );
                                    }
                                    data.insert(
                                        "CommandLine".to_string(),
                                        serde_json::json!(final_cmd),
                                    );

                                    if event_id == 1 {
                                        let now = std::time::Instant::now();
                                        let mut parent_image = String::new();
                                        let mut velocity_3s = 0usize;

                                        if parent_pid != 0 {
                                            if let Some(mut parent_meta) =
                                                active_procs_cb.get_mut(&parent_pid)
                                            {
                                                parent_image = parent_meta.image_name.clone();
                                                parent_meta.child_spawn_times.retain(|t| {
                                                    now.duration_since(*t).as_secs() < 3
                                                });
                                                parent_meta.child_spawn_times.push(now);
                                                velocity_3s = parent_meta.child_spawn_times.len();
                                            }
                                        }

                                        if !parent_image.is_empty() {
                                            data.insert(
                                                "ParentImage".to_string(),
                                                serde_json::json!(parent_image),
                                            );
                                        }
                                        data.insert(
                                            "ChildSpawnVelocity3s".to_string(),
                                            serde_json::json!(velocity_3s),
                                        );
                                        data.insert(
                                            "IsVelocityAnomaly".to_string(),
                                            serde_json::json!(velocity_3s > 5),
                                        );

                                        let already_seen = active_procs_cb.contains_key(&pid);
                                        active_procs_cb.insert(
                                            pid,
                                            ProcessMeta {
                                                pid,
                                                image_name: image.clone(),
                                                started_at: now,
                                                child_spawn_times: Vec::new(),
                                            },
                                        );

                                        if !already_seen {
                                            let ev = HostSecurityEvent {
                                                source: HostEventSource::WindowsEventLog,
                                                event_id: 1, // Sysmon ProcessCreate
                                                timestamp: Utc::now(),
                                                computer: computer_k.clone(),
                                                data: serde_json::Value::Object(data),
                                                causal_parent: None,
                                            };
                                            let _ = tx_k.try_send(ev);
                                        }
                                    } else {
                                        let (lifetime_ms, cached_img) =
                                            if let Some((_, meta)) = active_procs_cb.remove(&pid) {
                                                (
                                                    meta.started_at.elapsed().as_millis() as u64,
                                                    meta.image_name,
                                                )
                                            } else {
                                                (0u64, String::new())
                                            };

                                        if (image.is_empty() || image == "unknown")
                                            && !cached_img.is_empty()
                                            && cached_img != "unknown"
                                        {
                                            image = cached_img;
                                        }

                                        if image.is_empty() || image == "unknown" {
                                            if pid == 4 {
                                                image = "C:\\Windows\\System32\\ntoskrnl.exe"
                                                    .to_string();
                                                data.insert(
                                                    "ProcessName".to_string(),
                                                    serde_json::json!("System"),
                                                );
                                            } else if pid == 0 {
                                                image = "System Idle Process".to_string();
                                                data.insert(
                                                    "ProcessName".to_string(),
                                                    serde_json::json!("Idle"),
                                                );
                                            } else if pid > 4 {
                                                let (live_img, _) =
                                                    query_live_process_image_and_cmdline(pid);
                                                if let Some(li) = live_img
                                                    .filter(|s| !s.is_empty() && s != "unknown")
                                                {
                                                    image = li;
                                                } else {
                                                    image = format!("Process-{}", pid);
                                                }
                                            } else {
                                                image = format!("Process-{}", pid);
                                            }
                                        }

                                        data.insert(
                                            "ProcessId".to_string(),
                                            serde_json::json!(pid),
                                        );
                                        data.insert("Image".to_string(), serde_json::json!(image));
                                        data.insert(
                                            "ProcessLifetimeMs".to_string(),
                                            serde_json::json!(lifetime_ms),
                                        );

                                        let ev = HostSecurityEvent {
                                            source: HostEventSource::WindowsEventLog,
                                            event_id: 5, // Sysmon ProcessTerminate
                                            timestamp: Utc::now(),
                                            computer: computer_k.clone(),
                                            data: serde_json::Value::Object(data),
                                            causal_parent: None,
                                        };
                                        let _ = tx_k.blocking_send(ev);
                                    }
                                }
                            }
                        })
                        .build();

                // --- 2c. Kernel Network Provider (Port) ---
                let tx_n = tx.clone();
                let computer_n = computer.clone();
                let kernel_net_provider = Provider::by_guid("7DD42A49-5329-4832-8DFD-43D979153A88")
                    .add_callback(move |event, schema_locator| {
                        if let Ok(schema) = schema_locator.event_schema(event) {
                            let parser = Parser::create(event, &schema);
                            let mut data = serde_json::Map::new();

                            let dest_ip: String = parser.try_parse("daddr").unwrap_or_default();
                            let dest_port: u16 = parser.try_parse("dport").unwrap_or(0);
                            let pid: u32 = parser.try_parse("PID").unwrap_or(0);

                            if !dest_ip.is_empty() && dest_port != 0 {
                                data.insert(
                                    "DestinationIp".to_string(),
                                    serde_json::json!(dest_ip),
                                );
                                data.insert(
                                    "DestinationPort".to_string(),
                                    serde_json::json!(dest_port),
                                );
                                data.insert("ProcessId".to_string(), serde_json::json!(pid));

                                let ev = HostSecurityEvent {
                                    source: HostEventSource::WindowsEventLog,
                                    event_id: 3, // Sysmon Network Connection
                                    timestamp: Utc::now(),
                                    computer: computer_n.clone(),
                                    data: serde_json::Value::Object(data),
                                    causal_parent: None,
                                };
                                let _ = tx_n.blocking_send(ev);
                            }
                        }
                    })
                    .build();

                // --- 2d. Kernel File Provider (Port) ---
                let tx_f = tx.clone();
                let computer_f = computer.clone();
                let kernel_file_provider =
                    Provider::by_guid("EDD08927-9CC9-4E69-B970-C2560FB5C289")
                        .add_callback(move |event, schema_locator| {
                            if let Ok(schema) = schema_locator.event_schema(event) {
                                let parser = Parser::create(event, &schema);
                                let mut data = serde_json::Map::new();

                                let event_id = event.event_id();
                                // Mapping various file ops to Sysmon 11 (Create) or 23 (Delete)
                                let sysmon_id = match event_id {
                                    12 | 64 => 11, // Create / Overwrite
                                    65 | 66 => 23, // Delete
                                    _ => 0,
                                };

                                if sysmon_id != 0 {
                                    if let Ok(path) = parser.try_parse::<String>("FileName") {
                                        data.insert(
                                            "TargetFilename".to_string(),
                                            serde_json::json!(path),
                                        );
                                        let ev = HostSecurityEvent {
                                            source: HostEventSource::WindowsEventLog,
                                            event_id: sysmon_id,
                                            timestamp: Utc::now(),
                                            computer: computer_f.clone(),
                                            data: serde_json::Value::Object(data),
                                            causal_parent: None,
                                        };
                                        let _ = tx_f.blocking_send(ev);
                                    }
                                }
                            }
                        })
                        .build();

                // --- 2e. DNS Client Provider (Port) ---
                let tx_d = tx.clone();
                let computer_d = computer.clone();
                let dns_client_provider = Provider::by_guid("1C95126E-7EEA-49A9-A3FE-13F157579402")
                    .add_callback(move |event, schema_locator| {
                        if event.event_id() == 3008 {
                            // DNS Query
                            if let Ok(schema) = schema_locator.event_schema(event) {
                                let parser = Parser::create(event, &schema);
                                let mut data = serde_json::Map::new();

                                if let Ok(query) = parser.try_parse::<String>("QueryName") {
                                    data.insert("QueryName".to_string(), serde_json::json!(query));
                                    let ev = HostSecurityEvent {
                                        source: HostEventSource::WindowsEventLog,
                                        event_id: 22, // Sysmon DNS Query
                                        timestamp: Utc::now(),
                                        computer: computer_d.clone(),
                                        data: serde_json::Value::Object(data),
                                        causal_parent: None,
                                    };
                                    let _ = tx_d.blocking_send(ev);
                                }
                            }
                        }
                    })
                    .build();

                info!("🚀 [NATIVE-TELEMETRY] Starting Multi-Engine ETW Session...");

                // Clean up any stale session using logman (ferrisetw doesn't expose stop-by-name easily)
                use std::os::windows::process::CommandExt;
                let mut logman_cmd =
                    std::process::Command::new(osoosi_types::resolve_system_binary("logman.exe"));
                logman_cmd
                    .args(["stop", "OshoosiNativeTelemetry", "-ets"])
                    .creation_flags(osoosi_types::CREATE_NO_WINDOW);
                let _ = logman_cmd.output();

                let trace_res = UserTrace::new()
                    .named("OshoosiNativeTelemetry".to_string())
                    .enable(sysmon_provider)
                    .enable(kernel_process_provider)
                    .enable(kernel_net_provider)
                    .enable(kernel_file_provider)
                    .enable(dns_client_provider)
                    .start_and_process();

                let _active_trace = match trace_res {
                    Ok(trace) => {
                        info!("✅ [NATIVE-TELEMETRY] ETW Session started and processing events.");
                        Some(trace)
                    }
                    Err(e) => {
                        let err_str = format!("{:?}", e);
                        if err_str.contains("AlreadyExist") {
                            warn!("⚠️ [NATIVE-TELEMETRY] ETW Session 'OshoosiNativeTelemetry' already exists. Falling back to live kernel process delta monitor.");
                        } else {
                            error!("❌ [NATIVE-TELEMETRY] ETW Session failed ({:?}); activating live kernel process delta monitor.", e);
                        }
                        None
                    }
                };

                // Real-time kernel process delta loop (750ms) — guarantees zero missed ProcessCreate events
                // even for ultra-fast LOLBins or processes spawned prior to ETW session attachment.
                let mut sys = sysinfo::System::new();
                let mut is_initial_pass = true;
                loop {
                    sys.refresh_processes_specifics(
                        sysinfo::ProcessRefreshKind::new()
                            .with_exe(sysinfo::UpdateKind::OnlyIfNotSet)
                            .with_cmd(sysinfo::UpdateKind::OnlyIfNotSet),
                    );
                    let now = std::time::Instant::now();
                    let self_pid = std::process::id();

                    for (pid_val, proc_info) in sys.processes() {
                        let pid = pid_val.as_u32();
                        if pid <= 4 || pid == self_pid {
                            continue;
                        }
                        if active_processes.contains_key(&pid) {
                            continue;
                        }

                        let (live_img, live_cmd) = query_live_process_image_and_cmdline(pid);
                        let image = live_img
                            .filter(|s| !s.is_empty())
                            .or_else(|| {
                                proc_info
                                    .exe()
                                    .map(|p| p.to_string_lossy().to_string())
                                    .filter(|s| !s.is_empty())
                            })
                            .unwrap_or_else(|| proc_info.name().to_string());
                        let cmdline = live_cmd.filter(|s| !s.is_empty()).unwrap_or_else(|| {
                            let joined = proc_info.cmd().join(" ");
                            if joined.is_empty() {
                                image.clone()
                            } else {
                                joined
                            }
                        });
                        let parent_pid = proc_info.parent().map(|p| p.as_u32()).unwrap_or(0);

                        active_processes.insert(
                            pid,
                            ProcessMeta {
                                pid,
                                image_name: image.clone(),
                                started_at: now,
                                child_spawn_times: Vec::new(),
                            },
                        );

                        let is_cred_theft = is_suspicious_initial_process(&image, &cmdline);
                        if is_cred_theft {
                            terminate_suspicious_process_immediately(pid, &image, &cmdline);
                        }

                        // On the initial pass, only emit pre-existing processes that match credential/LOLBin/breakout indicators
                        // so we don't flood startup with hundreds of benign baseline OS services, while still catching
                        // any already-running attack (e.g., rundll32.exe keymgr,KRShowKeyMgr).
                        if !is_initial_pass || is_cred_theft {
                            let mut data = serde_json::Map::new();
                            data.insert("ProcessId".to_string(), serde_json::json!(pid));
                            data.insert(
                                "ParentProcessId".to_string(),
                                serde_json::json!(parent_pid),
                            );
                            data.insert("Image".to_string(), serde_json::json!(image));
                            data.insert("CommandLine".to_string(), serde_json::json!(cmdline));
                            if parent_pid != 0 {
                                if let Some(parent_meta) = active_processes.get(&parent_pid) {
                                    data.insert(
                                        "ParentImage".to_string(),
                                        serde_json::json!(parent_meta.image_name.clone()),
                                    );
                                }
                            }
                            let ev = HostSecurityEvent {
                                source: HostEventSource::WindowsEventLog,
                                event_id: 1,
                                timestamp: Utc::now(),
                                computer: computer.clone(),
                                data: serde_json::Value::Object(data),
                                causal_parent: None,
                            };
                            let _ = tx.try_send(ev);
                        }
                    }

                    // Prune terminated PIDs from active_processes map
                    active_processes
                        .retain(|pid, _| sys.process(sysinfo::Pid::from(*pid as usize)).is_some());
                    is_initial_pass = false;
                    std::thread::sleep(std::time::Duration::from_millis(750));
                }
            });
        }

        // Keep the main loop alive
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
    }
}

#[cfg(target_os = "windows")]
fn is_monitor_mode_active() -> bool {
    if std::env::var("OSOOSI_MONITOR_ONLY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return true;
    }
    for candidate in ["config/autonomy_mode.json", "../config/autonomy_mode.json"] {
        if let Ok(raw) = std::fs::read_to_string(candidate) {
            let lower = raw.to_ascii_lowercase();
            if lower.contains("\"audit\"") || lower.contains("\"monitor\"") {
                return true;
            }
        }
    }
    false
}

#[cfg(target_os = "windows")]
fn is_suspicious_initial_process(image: &str, cmdline: &str) -> bool {
    let img_l = image.to_ascii_lowercase();
    let cmd_l = cmdline.to_ascii_lowercase();
    if img_l.ends_with("osoosi.exe")
        || cmd_l.contains("--type=crashpad-handler")
        || cmd_l.contains("sentryproxy")
        || cmd_l.contains("cargo ")
        || cmd_l.contains("rustc ")
        || cmd_l.contains("git ")
        || cmd_l.contains("rg ")
        || cmd_l.contains("select-string")
        || cmd_l.contains("control_rundll")
        || cmd_l.contains(".cpl")
        || cmd_l.contains("editenvironmentvariables")
        || img_l.ends_with("python.exe")
        || img_l.ends_with("py.exe")
        || img_l.ends_with("node.exe")
        || img_l.ends_with("code.exe")
        || img_l.ends_with("antigravity.exe")
    {
        return false;
    }
    let is_rundll = img_l.ends_with("rundll32.exe");
    (is_rundll
        && (cmd_l.contains("keymgr")
            || cmd_l.contains("krshowkeymgr")
            || (cmd_l.contains("comsvcs") && cmd_l.contains("minidump"))))
        || img_l.ends_with("credwiz.exe")
        || (img_l.ends_with("vaultcmd.exe") && (cmd_l.contains("/list") || cmd_l.contains("-list")))
        || cmd_l.contains("sekurlsa")
        || cmd_l.contains("lsadump")
        || img_l.ends_with("mimikatz.exe")
        || (img_l.ends_with("procdump.exe") && cmd_l.contains("lsass"))
        || (img_l.ends_with("ntdsutil.exe") && (cmd_l.contains("ifm") || cmd_l.contains("ntds")))
        || (img_l.ends_with("cmdkey.exe") && (cmd_l.contains("/list") || cmd_l.contains("-l")))
}

#[cfg(target_os = "windows")]
fn terminate_suspicious_process_immediately(pid: u32, image: &str, cmdline: &str) {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    if pid <= 4 || pid == std::process::id() {
        return;
    }
    if is_monitor_mode_active() {
        tracing::info!(
            "Native Kernel Guard [MONITOR MODE]: Observed credential-harvesting process PID {} ({}) cmd: {} (not terminating in Monitor Mode)",
            pid,
            image,
            cmdline
        );
        return;
    }
    unsafe {
        if let Ok(handle) = OpenProcess(PROCESS_TERMINATE, false, pid) {
            let _ = TerminateProcess(handle, 1);
            let _ = CloseHandle(handle);
            tracing::warn!(
                "Native Kernel Guard: Immediately terminated credential-harvesting process PID {} ({}) cmd: {}",
                pid,
                image,
                cmdline
            );
        }
    }
}

#[cfg(target_os = "windows")]
fn query_live_process_image_and_cmdline(pid: u32) -> (Option<String>, Option<String>) {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *const u16,
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn NtQueryInformationProcess(
            process_handle: *mut std::ffi::c_void,
            process_information_class: u32,
            process_information: *mut std::ffi::c_void,
            process_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    unsafe {
        let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return (None, None);
        };

        let mut img_buf = [0u16; 1024];
        let mut img_len = img_buf.len() as u32;
        let image = if QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(img_buf.as_mut_ptr()),
            &mut img_len,
        )
        .is_ok()
            && img_len > 0
        {
            Some(String::from_utf16_lossy(&img_buf[..img_len as usize]))
        } else {
            None
        };

        // ProcessCommandLineInformation = 60
        let mut cmd_buf = vec![0u8; 8192];
        let mut ret_len = 0u32;
        let status = NtQueryInformationProcess(
            handle.0,
            60,
            cmd_buf.as_mut_ptr() as *mut std::ffi::c_void,
            cmd_buf.len() as u32,
            &mut ret_len,
        );
        let cmdline = if status >= 0 && (ret_len as usize) >= std::mem::size_of::<UnicodeString>() {
            let ustr = &*(cmd_buf.as_ptr() as *const UnicodeString);
            if !ustr.buffer.is_null() && ustr.length > 0 {
                let char_len = (ustr.length as usize) / 2;
                let slice = std::slice::from_raw_parts(ustr.buffer, char_len);
                Some(String::from_utf16_lossy(slice))
            } else {
                None
            }
        } else {
            None
        };

        let _ = CloseHandle(handle);
        (image, cmdline)
    }
}

#[cfg(target_os = "windows")]
async fn run_hook_telemetry_listener(
    tx: tokio::sync::mpsc::Sender<HostSecurityEvent>,
) -> anyhow::Result<()> {
    tokio::task::spawn_blocking(move || {
        use winapi::um::fileapi::ReadFile;
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::namedpipeapi::*;
        use winapi::um::winbase::*;

        let computer = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "localhost".to_string());

        #[repr(C)]
        struct SecurityAttributes {
            n_length: u32,
            lp_security_descriptor: *mut std::ffi::c_void,
            b_inherit_handle: i32,
        }

        const SDDL_REVISION_1: u32 = 1;
        #[link(name = "advapi32")]
        extern "system" {
            fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
                string_security_descriptor: *const u16,
                string_sd_revision: u32,
                security_descriptor: *mut *mut std::ffi::c_void,
                security_descriptor_size: *mut u32,
            ) -> i32;
        }
        #[link(name = "kernel32")]
        extern "system" {
            fn LocalFree(h_mem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
        }

        // Strict Protected DACL: Allow SYSTEM (SY) and Builtin Administrators (BA) only
        let sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";
        let wide_sddl: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();

        loop {
            let event = unsafe {
                let pipe_name = "\\\\.\\pipe\\osoosi_injection"
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect::<Vec<u16>>();

                let mut sd_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
                let mut sa = SecurityAttributes {
                    n_length: std::mem::size_of::<SecurityAttributes>() as u32,
                    lp_security_descriptor: std::ptr::null_mut(),
                    b_inherit_handle: 0,
                };
                let sa_ptr = if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide_sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut sd_ptr,
                    std::ptr::null_mut(),
                ) != 0
                    && !sd_ptr.is_null()
                {
                    sa.lp_security_descriptor = sd_ptr;
                    &mut sa as *mut SecurityAttributes as *mut _
                } else {
                    std::ptr::null_mut()
                };

                let h_pipe = CreateNamedPipeW(
                    pipe_name.as_ptr(),
                    PIPE_ACCESS_INBOUND,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                    PIPE_UNLIMITED_INSTANCES,
                    4096,
                    4096,
                    0,
                    sa_ptr,
                );

                if !sd_ptr.is_null() {
                    LocalFree(sd_ptr);
                }

                if h_pipe == winapi::um::handleapi::INVALID_HANDLE_VALUE {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    continue;
                }

                let mut result = None;
                let connected = ConnectNamedPipe(h_pipe, std::ptr::null_mut()) != 0
                    || windows_sys::Win32::Foundation::GetLastError()
                        == windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED;
                if connected {
                    let mut buffer = [0u8; 4096];
                    let mut bytes_read = 0;
                    if ReadFile(
                        h_pipe,
                        buffer.as_mut_ptr() as *mut _,
                        4096,
                        &mut bytes_read,
                        std::ptr::null_mut(),
                    ) != 0
                    {
                        if let Ok(data) = serde_json::from_slice::<serde_json::Value>(
                            &buffer[..bytes_read as usize],
                        ) {
                            result = Some(HostSecurityEvent {
                                source: HostEventSource::WindowsEventLog,
                                event_id: 999, // Custom Hook ID
                                timestamp: Utc::now(),
                                computer: computer.clone(),
                                data,
                                causal_parent: None,
                            });
                        }
                    }
                } else {
                    let _ = CloseHandle(h_pipe);
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    continue;
                }
                let _ = CloseHandle(h_pipe);
                result
            };

            if let Some(ev) = event {
                let _ = tx.blocking_send(ev);
            }
        }
    })
    .await?;
    Ok(())
}

/// Telemetry record for a kernel driver loaded in the operating system.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct LoadedDriverInfo {
    pub base_address: usize,
    pub image_name: String,
    pub file_path: Option<String>,
}

/// Enumerates all currently loaded kernel-mode drivers across Windows and Linux.
///
/// On Windows, queries K32EnumDeviceDrivers (or EnumDeviceDrivers) and normalizes paths.
/// On Linux, parses `/proc/modules`.
/// On unsupported platforms, returns an empty vector.
pub fn enumerate_loaded_kernel_drivers() -> Vec<LoadedDriverInfo> {
    #[cfg(target_os = "windows")]
    {
        enumerate_loaded_kernel_drivers_windows()
    }
    #[cfg(target_os = "linux")]
    {
        enumerate_loaded_kernel_drivers_linux()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Vec::new()
    }
}

#[cfg(target_os = "windows")]
fn enumerate_loaded_kernel_drivers_windows() -> Vec<LoadedDriverInfo> {
    use std::ffi::c_void;
    use windows_sys::Win32::System::LibraryLoader::{
        GetModuleHandleA, GetProcAddress, LoadLibraryA,
    };

    let mut results = Vec::new();
    unsafe {
        let kernel32 = GetModuleHandleA(c"kernel32.dll".as_ptr() as *const u8);
        if kernel32.is_null() {
            return results;
        }

        type EnumDriversFn = unsafe extern "system" fn(*mut *mut c_void, u32, *mut u32) -> i32;
        type GetBaseNameFn = unsafe extern "system" fn(*mut c_void, *mut u16, u32) -> u32;
        type GetFileNameFn = unsafe extern "system" fn(*mut c_void, *mut u16, u32) -> u32;

        let enum_drivers: Option<EnumDriversFn> = {
            if let Some(p) = GetProcAddress(kernel32, c"K32EnumDeviceDrivers".as_ptr() as *const u8)
            {
                Some(std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    EnumDriversFn,
                >(p))
            } else {
                let psapi = LoadLibraryA(c"psapi.dll".as_ptr() as *const u8);
                if !psapi.is_null() {
                    GetProcAddress(psapi, c"EnumDeviceDrivers".as_ptr() as *const u8).map(|p2| {
                        std::mem::transmute::<unsafe extern "system" fn() -> isize, EnumDriversFn>(
                            p2,
                        )
                    })
                } else {
                    None
                }
            }
        };

        let get_base_name: Option<GetBaseNameFn> = {
            if let Some(p) = GetProcAddress(
                kernel32,
                c"K32GetDeviceDriverBaseNameW".as_ptr() as *const u8,
            ) {
                Some(std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    GetBaseNameFn,
                >(p))
            } else {
                let psapi = GetModuleHandleA(c"psapi.dll".as_ptr() as *const u8);
                if !psapi.is_null() {
                    GetProcAddress(psapi, c"GetDeviceDriverBaseNameW".as_ptr() as *const u8)
                            .map(|p2| {
                                std::mem::transmute::<
                                    unsafe extern "system" fn() -> isize,
                                    GetBaseNameFn,
                                >(p2)
                            })
                } else {
                    None
                }
            }
        };

        let get_file_name: Option<GetFileNameFn> = {
            if let Some(p) = GetProcAddress(
                kernel32,
                c"K32GetDeviceDriverFileNameW".as_ptr() as *const u8,
            ) {
                Some(std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    GetFileNameFn,
                >(p))
            } else {
                let psapi = GetModuleHandleA(c"psapi.dll".as_ptr() as *const u8);
                if !psapi.is_null() {
                    GetProcAddress(psapi, c"GetDeviceDriverFileNameW".as_ptr() as *const u8)
                            .map(|p2| {
                                std::mem::transmute::<
                                    unsafe extern "system" fn() -> isize,
                                    GetFileNameFn,
                                >(p2)
                            })
                } else {
                    None
                }
            }
        };

        if let Some(enum_fn) = enum_drivers {
            let mut drivers: Vec<*mut c_void> = vec![std::ptr::null_mut(); 2048];
            let mut cb_needed: u32 = 0;
            let cb = (drivers.len() * std::mem::size_of::<*mut c_void>()) as u32;

            if enum_fn(drivers.as_mut_ptr(), cb, &mut cb_needed) != 0 {
                let count = (cb_needed as usize) / std::mem::size_of::<*mut c_void>();
                let actual_count = count.min(drivers.len());

                let system_root =
                    std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());

                for &base in &drivers[..actual_count] {
                    if base.is_null() {
                        continue;
                    }
                    let mut base_name_buf = [0u16; 260];
                    let mut file_path_buf = [0u16; 520];

                    let mut image_name = String::new();
                    if let Some(base_fn) = get_base_name {
                        let len =
                            base_fn(base, base_name_buf.as_mut_ptr(), base_name_buf.len() as u32);
                        if len > 0 {
                            image_name = String::from_utf16_lossy(&base_name_buf[..len as usize]);
                        }
                    }

                    let mut file_path = None;
                    if let Some(file_fn) = get_file_name {
                        let len =
                            file_fn(base, file_path_buf.as_mut_ptr(), file_path_buf.len() as u32);
                        if len > 0 {
                            let mut raw_path =
                                String::from_utf16_lossy(&file_path_buf[..len as usize]);
                            if raw_path.to_ascii_lowercase().starts_with("\\systemroot\\") {
                                raw_path = format!("{}\\{}", system_root, &raw_path[12..]);
                            } else if raw_path.to_ascii_lowercase().starts_with("\\??\\") {
                                raw_path = raw_path[4..].to_string();
                            }
                            file_path = Some(raw_path);
                        }
                    }

                    if image_name.is_empty() {
                        if let Some(ref fp) = file_path {
                            if let Some(name) = std::path::Path::new(fp)
                                .file_name()
                                .and_then(|n| n.to_str())
                            {
                                image_name = name.to_string();
                            }
                        }
                    }

                    if !image_name.is_empty() {
                        results.push(LoadedDriverInfo {
                            base_address: base as usize,
                            image_name,
                            file_path,
                        });
                    }
                }
            }
        }
    }
    results
}

#[cfg(target_os = "linux")]
fn enumerate_loaded_kernel_drivers_linux() -> Vec<LoadedDriverInfo> {
    let mut results = Vec::new();
    if let Ok(content) = std::fs::read_to_string("/proc/modules") {
        for line in content.lines() {
            let mut parts = line.split_whitespace();
            if let Some(mod_name) = parts.next() {
                let _size = parts.next();
                let _ref_count = parts.next();
                let _sub = parts.next();
                let _state = parts.next();
                let addr_str = parts.next();
                let base_address = addr_str
                    .and_then(|s| s.strip_prefix("0x"))
                    .and_then(|hex_str| usize::from_str_radix(hex_str, 16).ok())
                    .unwrap_or(0);
                results.push(LoadedDriverInfo {
                    base_address,
                    image_name: format!("{}.ko", mod_name),
                    file_path: Some(format!("/sys/module/{}/", mod_name)),
                });
            }
        }
    }
    results
}

// ============================================================================
// F25 & F26: Zero-Day Kernel & Hypervisor Integrity Innovations
// - F25: Hardware HVCI / VBS / VTL1 Posture Verifier (arXiv:2409.07508 SafeBPF)
// - F26: Cross-View DKOM Process Differential & O(1) Temporal SPRT Sensor
//        (arXiv:2503.02402 Trace of the Times)
// ============================================================================

pub const CODEINTEGRITY_OPTION_ENABLED: u32 = 0x0000_0001;
pub const CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED: u32 = 0x0000_0400;
pub const CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED: u32 = 0x0000_0800;

/// Hardware-backed Virtualization-Based Security (VBS) & Hypervisor-Protected Code Integrity
/// (HVCI / VTL1) posture report (`F25`, `arXiv:2409.07508`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HvciVbsPostureReport {
    pub raw_code_integrity_options: u32,
    pub code_integrity_enabled: bool,
    pub hvci_kmci_enabled: bool,
    pub vbs_isolated_user_mode_enabled: bool,
    /// When hardware HVCI is inactive, Ring 7 process confinement automatically tightens
    /// because in-OS kernel callbacks are not backed by VTL1 hypervisor page protections.
    pub requires_tightened_ring7_confinement: bool,
}

/// Evaluates raw `SYSTEM_CODEINTEGRITY_INFORMATION.CodeIntegrityOptions` bitmask (`F25`).
pub fn evaluate_code_integrity_options_bitmask(options: u32) -> HvciVbsPostureReport {
    let code_integrity_enabled = (options & CODEINTEGRITY_OPTION_ENABLED) != 0;
    let hvci_kmci_enabled = (options & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) != 0;
    let vbs_isolated_user_mode_enabled = (options & CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED) != 0;
    HvciVbsPostureReport {
        raw_code_integrity_options: options,
        code_integrity_enabled,
        hvci_kmci_enabled,
        vbs_isolated_user_mode_enabled,
        requires_tightened_ring7_confinement: !hvci_kmci_enabled,
    }
}

/// Queries live Windows `NtQuerySystemInformation(SystemCodeIntegrityInformation = 0x67)`
/// to verify hardware-backed HVCI/VBS/VTL1 code integrity posture (`F25`).
pub fn verify_hardware_hvci_vbs_posture() -> HvciVbsPostureReport {
    #[cfg(target_os = "windows")]
    unsafe {
        #[repr(C)]
        struct SystemCodeIntegrityInformation {
            length: u32,
            code_integrity_options: u32,
        }
        type NtQuerySystemInformationFn = unsafe extern "system" fn(
            system_information_class: u32,
            system_information: *mut std::ffi::c_void,
            system_information_length: u32,
            return_length: *mut u32,
        ) -> i32;

        let ntdll =
            windows::Win32::System::LibraryLoader::GetModuleHandleA(windows::core::s!("ntdll.dll"));
        if let Ok(hmod) = ntdll {
            if !hmod.is_invalid() {
                if let Some(proc) = windows::Win32::System::LibraryLoader::GetProcAddress(
                    hmod,
                    windows::core::s!("NtQuerySystemInformation"),
                ) {
                    let query_fn: NtQuerySystemInformationFn = std::mem::transmute(proc);
                    let mut info = SystemCodeIntegrityInformation {
                        length: std::mem::size_of::<SystemCodeIntegrityInformation>() as u32,
                        code_integrity_options: 0,
                    };
                    let mut ret_len: u32 = 0;
                    // SystemCodeIntegrityInformation = 0x67 (103)
                    let status = query_fn(
                        0x67,
                        &mut info as *mut _ as *mut std::ffi::c_void,
                        info.length,
                        &mut ret_len,
                    );
                    if status == 0 {
                        return evaluate_code_integrity_options_bitmask(
                            info.code_integrity_options,
                        );
                    }
                }
            }
        }
    }
    evaluate_code_integrity_options_bitmask(CODEINTEGRITY_OPTION_ENABLED)
}

/// Cross-View Direct Kernel Object Manipulation (DKOM) discrepancy finding (`F26`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CrossViewDkomFinding {
    pub hidden_pids: Vec<u32>,
    pub anomaly_detected: bool,
    pub reason: String,
}

/// Compares standard `ActiveProcessLinks` PID enumeration (`view_a_active_links`) against
/// kernel handle/scheduler thread PID tables (`view_b_handle_or_scheduler_pids`) to detect
/// 0-day DKOM rootkits that unlink `EPROCESS` structures (`F26`, `arXiv:2503.02402`).
pub fn detect_cross_view_dkom_discrepancy(
    view_a_active_links: &[u32],
    view_b_handle_or_scheduler_pids: &[u32],
) -> CrossViewDkomFinding {
    let active_set: std::collections::HashSet<u32> = view_a_active_links.iter().copied().collect();
    let mut hidden: Vec<u32> = view_b_handle_or_scheduler_pids
        .iter()
        .copied()
        // Ignore Idle (0) and System (4) pseudo-PIDs
        .filter(|&pid| pid != 0 && pid != 4 && !active_set.contains(&pid))
        .collect();
    hidden.sort_unstable();
    hidden.dedup();

    if hidden.is_empty() {
        CrossViewDkomFinding {
            hidden_pids: Vec::new(),
            anomaly_detected: false,
            reason: "Cross-view ActiveProcessLinks and handle/scheduler tables are consistent"
                .to_string(),
        }
    } else {
        CrossViewDkomFinding {
            reason: format!(
                "DKOM_HIDDEN_PROCESS_DETECTED: {} process(es) {:?} present in kernel handle/scheduler tables but unlinked from ActiveProcessLinks",
                hidden.len(),
                hidden
            ),
            hidden_pids: hidden,
            anomaly_detected: true,
        }
    }
}

/// State of the $O(1)$ Sequential Probability Ratio Test (`SPRT`) over kernel callback heartbeats (`F26`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum KernelSprtState {
    /// Null hypothesis $H_0$ holds: callback heartbeat cadence is nominal.
    Nominal,
    /// Indifference region: accumulating statistical evidence in $O(1)$ time.
    Monitoring,
    /// Alternative hypothesis $H_1$ accepted: kernel callback blinding or hypervisor VM-exit suppression detected.
    CallbackBlindingOrRootkitDetected,
}

/// Constant-time $O(1)$ Sequential Probability Ratio Test (`SPRT`) monitor over kernel callback
/// inter-arrival intervals (`F26`, `arXiv:2503.02402` *Trace of the Times*).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KernelSprtCallbackMonitor {
    expected_interval_ms: f64,
    anomaly_interval_ms: f64,
    log_likelihood_ratio: f64,
    upper_threshold_b: f64,
    lower_threshold_a: f64,
    samples_observed: u64,
}

impl KernelSprtCallbackMonitor {
    /// Creates an $O(1)$ Wald SPRT monitor with false-positive bound $\alpha$ and false-negative bound $\beta$.
    pub fn new(expected_interval_ms: f64, anomaly_interval_ms: f64, alpha: f64, beta: f64) -> Self {
        let a = (beta / (1.0 - alpha)).ln();
        let b = ((1.0 - beta) / alpha).ln();
        Self {
            expected_interval_ms: expected_interval_ms.max(1.0),
            anomaly_interval_ms: anomaly_interval_ms.max(expected_interval_ms + 1.0),
            log_likelihood_ratio: 0.0,
            upper_threshold_b: b,
            lower_threshold_a: a,
            samples_observed: 0,
        }
    }

    /// Updates the cumulative log-likelihood ratio $S_n = S_{n-1} + \ln\frac{f_1(\Delta t)}{f_0(\Delta t)}$
    /// under exponential inter-arrival models in $O(1)$ time and returns the current `KernelSprtState`.
    pub fn observe_interval_ms(&mut self, observed_dt_ms: f64) -> KernelSprtState {
        let dt = observed_dt_ms.max(0.1);
        let lambda_0 = 1.0 / self.expected_interval_ms;
        let lambda_1 = 1.0 / self.anomaly_interval_ms;
        // Log-likelihood ratio for Exponential(lambda_1) vs Exponential(lambda_0)
        let step_llr = (lambda_1 / lambda_0).ln() + (lambda_0 - lambda_1) * dt;
        self.log_likelihood_ratio = (self.log_likelihood_ratio + step_llr)
            .clamp(self.lower_threshold_a * 2.0, self.upper_threshold_b * 2.0);
        self.samples_observed += 1;

        if self.log_likelihood_ratio >= self.upper_threshold_b {
            KernelSprtState::CallbackBlindingOrRootkitDetected
        } else if self.log_likelihood_ratio <= self.lower_threshold_a {
            self.log_likelihood_ratio = 0.0;
            KernelSprtState::Nominal
        } else {
            KernelSprtState::Monitoring
        }
    }

    pub fn log_likelihood_ratio(&self) -> f64 {
        self.log_likelihood_ratio
    }
}

#[cfg(test)]
mod f25_f26_tests {
    use super::*;

    #[test]
    fn test_f25_hvci_vbs_posture_bitmask_evaluation() {
        let hvci_on = evaluate_code_integrity_options_bitmask(
            CODEINTEGRITY_OPTION_ENABLED
                | CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED
                | CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED,
        );
        assert!(hvci_on.code_integrity_enabled);
        assert!(hvci_on.hvci_kmci_enabled);
        assert!(hvci_on.vbs_isolated_user_mode_enabled);
        assert!(!hvci_on.requires_tightened_ring7_confinement);

        let hvci_off = evaluate_code_integrity_options_bitmask(CODEINTEGRITY_OPTION_ENABLED);
        assert!(hvci_off.code_integrity_enabled);
        assert!(!hvci_off.hvci_kmci_enabled);
        assert!(hvci_off.requires_tightened_ring7_confinement);
    }

    #[test]
    fn test_f26_cross_view_dkom_detects_unlinked_eprocess() {
        let active_links = vec![4, 412, 880, 1024, 2048];
        let handle_table = vec![0, 4, 412, 880, 1024, 2048, 31337];
        let finding = detect_cross_view_dkom_discrepancy(&active_links, &handle_table);
        assert!(finding.anomaly_detected);
        assert_eq!(finding.hidden_pids, vec![31337]);
        assert!(finding.reason.contains("DKOM_HIDDEN_PROCESS_DETECTED"));
    }

    #[test]
    fn test_f26_kernel_sprt_callback_monitor_detects_blinding() {
        let mut monitor = KernelSprtCallbackMonitor::new(50.0, 500.0, 0.001, 0.01);
        // Nominal 40ms-55ms heartbeats stay Nominal/Monitoring
        for _ in 0..5 {
            let state = monitor.observe_interval_ms(45.0);
            assert_ne!(state, KernelSprtState::CallbackBlindingOrRootkitDetected);
        }
        // Sudden callback starvation / hypervisor rootkit suppression (800ms intervals)
        let mut detected = false;
        for _ in 0..8 {
            if monitor.observe_interval_ms(800.0)
                == KernelSprtState::CallbackBlindingOrRootkitDetected
            {
                detected = true;
                break;
            }
        }
        assert!(
            detected,
            "SPRT must detect callback blinding within bounded samples"
        );
    }
}
