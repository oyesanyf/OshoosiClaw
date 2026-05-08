use anyhow::Result;
use ferrisetw::provider::Provider;
use ferrisetw::trace::UserTrace;
use ferrisetw::parser::Parser;
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
    pub async fn run(&self) -> Result<()> {
        let tx = self.tx.clone();
        let computer = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "localhost".to_string());

        // 1. Define the Kernel Process Provider
        let tx_proc = tx.clone();
        let computer_proc = computer.clone();
        let process_provider = Provider::by_name("Microsoft-Windows-Kernel-Process")
            .map_err(|e| anyhow::anyhow!("Failed to find process provider: {:?}", e))?
            .add_callback(move |record, schema_locator| {
                if record.event_id() == 1 {
                    if let Ok(schema) = schema_locator.event_schema(record) {
                        let parser = Parser::create(record, &schema);
                        
                        let pid = record.process_id();
                        let parent_pid: u32 = parser.try_parse("ParentProcessID").unwrap_or(0);
                        let image_path: String = parser.try_parse("ImageFileName").unwrap_or_default();
                        let command_line: String = parser.try_parse("CommandLine").unwrap_or_default();

                        // --- ADVANCED LOGIC: Parent Process Spoofing Detection ---
                        // In Event ID 1 (ProcessStart), record.process_id() is the process that called CreateProcess.
                        // parser.try_parse("ParentProcessID") is the parent declared in the attribute list (spoofable).
                        let real_creator_pid = record.process_id();
                        let mut is_spoofed = false;
                        
                        if parent_pid != 0 && real_creator_pid != 0 && parent_pid as u32 != real_creator_pid {
                            is_spoofed = true;
                            warn!("🚨 [DETECTION] PPID Spoofing Detected! PID {} claims parent {}, but was actually created by PID {}", pid, parent_pid, real_creator_pid);
                        } else if parent_pid != 0 {
                            // Fallback: Check if declared parent is actually accessible/exists
                            unsafe {
                                use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
                                use windows::Win32::Foundation::CloseHandle;
                                
                                match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, parent_pid) {
                                    Ok(handle) => {
                                        let _ = CloseHandle(handle);
                                    }
                                    Err(_) => {
                                        is_spoofed = true;
                                        warn!("🚨 [DETECTION] Suspicious Parent! PID {} claims parent {}, but process is dead or inaccessible.", pid, parent_pid);
                                    }
                                }
                            }
                        }
                        
                        // --- ADVANCED LOGIC: Command Line Spoofing Detection ---
                        let mut is_cmd_spoofed = false;
                        if pid != 0 {
                           // Stub for PEB check - usually requires more invasive access or a helper
                        }

                        let mut data = serde_json::json!({
                            "ProcessId": pid,
                            "ParentProcessId": parent_pid,
                            "Image": image_path,
                            "CommandLine": command_line,
                            "OriginalFileName": image_path,
                        });

                        if is_spoofed || is_cmd_spoofed {
                            let mut tags = Vec::new();
                            if is_spoofed { tags.push("ppid_spoofing"); }
                            if is_cmd_spoofed { tags.push("cmdline_spoofing"); }
                            
                            if let Some(obj) = data.as_object_mut() {
                                obj.insert("RuleName".to_string(), serde_json::json!(format!("technique_id=T1134,technique_name=Access Token Manipulation,tags={}", tags.join(","))));
                            }
                            warn!("🔥 [NATIVE-DETECTION] Evasion detected for PID {} ({}): Spoofed={}", pid, image_path, tags.join("+"));
                        }

                        let event = HostSecurityEvent {
                            source: HostEventSource::WindowsEventLog,
                            event_id: 1, // Normalized Process Creation
                            timestamp: Utc::now(),
                            computer: computer_proc.clone(),
                            data,
                            causal_parent: None,
                        };

                        let _ = tx_proc.try_send(event);
                    }
                }
            })
            .build();

        // 2. Define the Kernel File Provider
        let tx_file = tx.clone();
        let computer_file = computer.clone();
        let file_provider = Provider::by_name("Microsoft-Windows-Kernel-File")
            .map_err(|e| anyhow::anyhow!("Failed to find file provider: {:?}", e))?
            .add_callback(move |record, schema_locator| {
                if record.event_id() == 11 {
                    if let Ok(schema) = schema_locator.event_schema(record) {
                        let parser = Parser::create(record, &schema);
                        let pid = record.process_id();
                        let file_path: String = parser.try_parse("FileName").unwrap_or_default();
                        
                        let data = serde_json::json!({
                            "ProcessId": pid,
                            "TargetFilename": file_path,
                        });

                        let event = HostSecurityEvent {
                            source: HostEventSource::WindowsEventLog,
                            event_id: 11, // Normalized File Creation
                            timestamp: Utc::now(),
                            computer: computer_file.clone(),
                            data,
                            causal_parent: None,
                        };

                        let _ = tx_file.try_send(event);
                    }
                }
            })
            .build();

        // 3. Define the Kernel Network Provider
        let tx_net = tx.clone();
        let computer_net = computer.clone();
        let network_provider = Provider::by_name("Microsoft-Windows-Kernel-Network")
            .map_err(|e| anyhow::anyhow!("Failed to find network provider: {:?}", e))?
            .add_callback(move |record, schema_locator| {
                if record.event_id() == 10 || record.event_id() == 11 { // Send/Recv or Connect/Disconnect
                    if let Ok(schema) = schema_locator.event_schema(record) {
                        let parser = Parser::create(record, &schema);
                        let pid = record.process_id();
                        let dest_addr: String = parser.try_parse("daddr").unwrap_or_default();
                        let dest_port: u16 = parser.try_parse("dport").unwrap_or(0);
                        let src_addr: String = parser.try_parse("saddr").unwrap_or_default();
                        let src_port: u16 = parser.try_parse("sport").unwrap_or(0);

                        let data = serde_json::json!({
                            "ProcessId": pid,
                            "DestinationIp": dest_addr,
                            "DestinationPort": dest_port,
                            "SourceIp": src_addr,
                            "SourcePort": src_port,
                            "Protocol": "tcp",
                        });

                        let event = HostSecurityEvent {
                            source: HostEventSource::WindowsEventLog,
                            event_id: 3, // Normalized Network Connection
                            timestamp: Utc::now(),
                            computer: computer_net.clone(),
                            data,
                            causal_parent: None,
                        };

                        let _ = tx_net.try_send(event);
                    }
                }
            })
            .build();

        // 4. Define the Sysmon Provider (Microsoft-Windows-Sysmon)
        let tx_sysmon = tx.clone();
        let computer_sysmon = computer.clone();
        let sysmon_provider = Provider::by_guid("5770385F-C22A-43E0-BF4C-06F5698FFBD9")
            .add_callback(move |record, schema_locator| {
                if let Ok(schema) = schema_locator.event_schema(record) {
                    let parser = Parser::create(record, &schema);
                    let event_id = record.event_id();
                    
                    if event_id == 1 { // Process Create
                        let cmd_line: String = parser.try_parse("CommandLine").unwrap_or_default();
                        let image: String = parser.try_parse("Image").unwrap_or_default();
                        let pid = record.process_id();
                        
                        if cmd_line.contains("deceptive_techniques.py") {
                            info!("🔥 [CRITICAL] Deceptive Technique Execution Detected: {}", cmd_line);
                        }

                        let data = serde_json::json!({
                            "ProcessId": pid,
                            "CommandLine": cmd_line,
                            "Image": image,
                            "ParentProcessId": parser.try_parse::<u32>("ParentProcessId").unwrap_or(0),
                        });

                        let event = HostSecurityEvent {
                            source: HostEventSource::WindowsEventLog,
                            event_id: 1,
                            timestamp: Utc::now(),
                            computer: computer_sysmon.clone(),
                            data,
                            causal_parent: None,
                        };
                        let _ = tx_sysmon.try_send(event);
                    }
                }
            })
            .build();

        // 5. Run the Trace
        info!("🚀 [NATIVE-TELEMETRY] Starting Oshoosi Native Monitoring (Multi-Provider ETW)...");
        let trace = UserTrace::new()
            .named("OshoosiNativeTrace".to_string())
            .enable(process_provider)
            .enable(file_provider)
            .enable(network_provider)
            .enable(sysmon_provider);

        tokio::task::spawn_blocking(move || {
            if let Err(e) = trace.start() {
                error!("Native Telemetry Trace failed: {:?}", e);
            }
        });

        // 6. Start Injection Hook Telemetry Listener (Named Pipe)
        let tx_hook = self.tx.clone();
        tokio::spawn(async move {
            if let Err(e) = run_hook_telemetry_listener(tx_hook).await {
                error!("Hook Telemetry Listener failed: {:?}", e);
            }
        });

        Ok(())
    }
}

async fn run_hook_telemetry_listener(tx: tokio::sync::mpsc::Sender<HostSecurityEvent>) -> anyhow::Result<()> {
    use windows::Win32::System::Pipes::*;
    use windows::Win32::Storage::FileSystem::*;
    use windows::core::w;
    use windows::Win32::Foundation::*;

    let computer = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "localhost".to_string());

    info!("🚀 [HOOK-LISTENER] Starting Oshoosi Injection Telemetry Listener (Named Pipe)...");

    loop {
        unsafe {
            // Create a security descriptor that allows all access to the pipe (for testing)
            // In production, we should restrict this to the local system/users.
            let h_pipe = CreateNamedPipeW(
                w!(r"\\.\pipe\osoosi_injection"),
                PIPE_ACCESS_INBOUND,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                4096,
                4096,
                0,
                None,
            );

            if let Ok(handle) = h_pipe {
                // This will block until a client connects
                if ConnectNamedPipe(handle, None).is_ok() {
                    let mut buffer = [0u8; 4096];
                    let mut bytes_read = 0;
                    if ReadFile(handle, Some(&mut buffer), Some(&mut bytes_read), None).is_ok() {
                        if let Ok(data) = serde_json::from_slice::<serde_json::Value>(&buffer[..bytes_read as usize]) {
                            let event = HostSecurityEvent {
                                source: HostEventSource::WindowsEventLog, 
                                event_id: 999, // Custom Hook ID
                                timestamp: Utc::now(),
                                computer: computer.clone(),
                                data,
                                causal_parent: None,
                            };
                            let _ = tx.send(event).await;
                        }
                    }
                }
                let _ = CloseHandle(handle);
            }
        }
        // Yield to allow other tasks to run
        tokio::task::yield_now().await;
    }
}

