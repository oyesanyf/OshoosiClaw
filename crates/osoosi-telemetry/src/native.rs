use ferrisetw::provider::Provider;
use ferrisetw::trace::UserTrace;
use ferrisetw::parser::*;
use osoosi_types::{HostSecurityEvent, HostEventSource};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use chrono::Utc;

pub struct NativeTelemetryEngine {
    tx: mpsc::Sender<HostSecurityEvent>,
}

impl NativeTelemetryEngine {
    pub fn new(tx: mpsc::Sender<HostSecurityEvent>) -> Self {
        Self { tx }
    }

    /// Starts the native kernel monitoring trace.
    pub async fn run(&self) -> anyhow::Result<()> {
        info!("🚀 [NATIVE-TELEMETRY] Starting Oshoosi Native Monitoring (Multi-Engine)...");

        // 1. Start Injection Hook Telemetry Listener (Named Pipe)
        let tx_hook = self.tx.clone();
        tokio::spawn(async move {
            if let Err(e) = run_hook_telemetry_listener(tx_hook).await {
                error!("Hook Telemetry Listener failed: {:?}", e);
            }
        });

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

        let tx = self.tx.clone();
        let computer = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "localhost".to_string());

        // 2. Sysmon-Zero: Port of SysmonX native ETW logic
        // We listen to the official Sysmon provider IF present, or kernel providers as fallback.
        
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
                        let keys = ["Image", "CommandLine", "ParentImage", "ParentCommandLine", 
                                   "User", "SourceIp", "DestinationIp", "Protocol"];
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
                            data.insert("DestinationPort".to_string(), serde_json::json!(dport));
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
            let kernel_process_provider = Provider::by_guid("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716")
                .add_callback(move |event, schema_locator| {
                    let event_id = event.event_id();
                    // 1: ProcessStart, 2: ProcessStop
                    if event_id == 1 || event_id == 2 {
                        if let Ok(schema) = schema_locator.event_schema(event) {
                            let parser = Parser::create(event, &schema);
                            let pid: u32 = parser.try_parse("ProcessID").unwrap_or(0);
                            let parent_pid: u32 = parser.try_parse("ParentProcessID").unwrap_or(0);
                            let image: String = parser.try_parse("ImageName").unwrap_or_else(|_| parser.try_parse("CommandLine").unwrap_or_default());
                            
                            let sysmon_id = if event_id == 1 { 1 } else { 5 };
                            
                            let mut data = serde_json::Map::new();
                            data.insert("ProcessId".to_string(), serde_json::json!(pid));
                            data.insert("ParentProcessId".to_string(), serde_json::json!(parent_pid));
                            data.insert("Image".to_string(), serde_json::json!(image));
                            if let Ok(cmd) = parser.try_parse::<String>("CommandLine") {
                                data.insert("CommandLine".to_string(), serde_json::json!(cmd));
                            }
                            
                            let ev = HostSecurityEvent {
                                source: HostEventSource::WindowsEventLog,
                                event_id: sysmon_id,
                                timestamp: Utc::now(),
                                computer: computer_k.clone(),
                                data: serde_json::Value::Object(data),
                                causal_parent: None,
                            };
                            let _ = tx_k.blocking_send(ev);
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
                            data.insert("DestinationIp".to_string(), serde_json::json!(dest_ip));
                            data.insert("DestinationPort".to_string(), serde_json::json!(dest_port));
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
            let kernel_file_provider = Provider::by_guid("EDD08927-9CC9-4E69-B970-C2560FB5C289")
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
                                data.insert("TargetFilename".to_string(), serde_json::json!(path));
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
                    if event.event_id() == 3008 { // DNS Query
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
            let _ = std::process::Command::new("logman")
                .args(&["stop", "OshoosiNativeTelemetry", "-ets"])
                .output();
            
            let trace_res = UserTrace::new()
                .named("OshoosiNativeTelemetry".to_string())
                .enable(sysmon_provider)
                .enable(kernel_process_provider)
                .enable(kernel_net_provider)
                .enable(kernel_file_provider)
                .enable(dns_client_provider)
                .start();
            
            match trace_res {
                Ok(_) => info!("✅ [NATIVE-TELEMETRY] ETW Session started successfully."),
                Err(e) => {
                    let err_str = format!("{:?}", e);
                    if err_str.contains("AlreadyExist") {
                        warn!("⚠️ [NATIVE-TELEMETRY] ETW Session 'OshoosiNativeTelemetry' already exists. This usually means a previous instance is still running.");
                    } else {
                        error!("❌ [NATIVE-TELEMETRY] ETW Session failed: {:?}", e);
                    }
                }
            }
            
            // Loop while trace is active (blocks the spawn_blocking thread)
            loop {
                std::thread::sleep(std::time::Duration::from_secs(10));
            }
        });
        
        // Keep the main loop alive
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
    }
}

async fn run_hook_telemetry_listener(tx: tokio::sync::mpsc::Sender<HostSecurityEvent>) -> anyhow::Result<()> {
    use winapi::um::namedpipeapi::*;
    use winapi::um::fileapi::ReadFile;
    use winapi::um::winbase::*;
    use winapi::um::handleapi::CloseHandle;

    let computer = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "localhost".to_string());

    info!("🚀 [HOOK-LISTENER] Starting Oshoosi Injection Telemetry Listener (Named Pipe)...");

    loop {
        let event = unsafe {
            let pipe_name = "\\\\.\\pipe\\osoosi_injection".encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
            let h_pipe = CreateNamedPipeW(
                pipe_name.as_ptr(),
                PIPE_ACCESS_INBOUND,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                4096,
                4096,
                0,
                std::ptr::null_mut(),
            );

            if h_pipe != winapi::um::handleapi::INVALID_HANDLE_VALUE {
                let mut result = None;
                if ConnectNamedPipe(h_pipe, std::ptr::null_mut()) != 0 {
                    let mut buffer = [0u8; 4096];
                    let mut bytes_read = 0;
                    if ReadFile(h_pipe, buffer.as_mut_ptr() as *mut _, 4096, &mut bytes_read, std::ptr::null_mut()) != 0 {
                        if let Ok(data) = serde_json::from_slice::<serde_json::Value>(&buffer[..bytes_read as usize]) {
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
                }
                let _ = CloseHandle(h_pipe);
                result
            } else {
                None
            }
        };

        if let Some(ev) = event {
            let _ = tx.send(ev).await;
        }
        tokio::task::yield_now().await;
    }
}
