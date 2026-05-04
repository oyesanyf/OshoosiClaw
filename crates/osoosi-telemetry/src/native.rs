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
                        let mut is_spoofed = false;
                        if parent_pid != 0 {
                            unsafe {
                                use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
                                use windows::Win32::Foundation::CloseHandle;
                                
                                match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, parent_pid) {
                                    Ok(handle) => {
                                        let _ = CloseHandle(handle);
                                    }
                                    Err(_) => {
                                        is_spoofed = true;
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

        // 4. Run the Trace
        info!("🚀 [NATIVE-TELEMETRY] Starting Oshoosi Native Monitoring (Zero-Process ETW)...");
        let trace = UserTrace::new()
            .named("OshoosiNativeTrace".to_string())
            .enable(process_provider)
            .enable(file_provider)
            .enable(network_provider);

        tokio::task::spawn_blocking(move || {
            if let Err(e) = trace.start() {
                error!("Native Telemetry Trace failed: {:?}", e);
            }
        }).await?;

        Ok(())
    }
}

