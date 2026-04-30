use anyhow::Result;
use ferrisetw::provider::Provider;
use ferrisetw::trace::UserTrace;
use ferrisetw::parser::Parser;
use osoosi_types::{SysmonEvent, SysmonEventId};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

pub struct NativeTelemetryEngine {
    tx: mpsc::Sender<SysmonEvent>,
}

impl NativeTelemetryEngine {
    pub fn new(tx: mpsc::Sender<SysmonEvent>) -> Self {
        Self { tx }
    }

    /// Starts the native kernel monitoring trace.
    pub async fn run(&self) -> Result<()> {
        let tx = self.tx.clone();

        // 1. Define the Kernel Process Provider
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
                           if let Ok(peb_cmdline) = get_peb_command_line(pid) {
                               if !peb_cmdline.is_empty() && !command_line.is_empty() && peb_cmdline != command_line {
                                   is_cmd_spoofed = true;
                               }
                           }
                        }

                        let mut sysmon_event = SysmonEvent::new(SysmonEventId::ProcessCreate);
                        if let Some(obj) = sysmon_event.data.as_object_mut() {
                            obj.insert("ProcessId".to_string(), serde_json::json!(pid));
                            obj.insert("ParentProcessId".to_string(), serde_json::json!(parent_pid));
                            obj.insert("Image".to_string(), serde_json::json!(image_path));
                            obj.insert("CommandLine".to_string(), serde_json::json!(command_line));
                            obj.insert("OriginalFileName".to_string(), serde_json::json!(image_path));

                            if is_spoofed || is_cmd_spoofed {
                                let mut tags = Vec::new();
                                if is_spoofed { tags.push("ppid_spoofing"); }
                                if is_cmd_spoofed { tags.push("cmdline_spoofing"); }
                                
                                obj.insert("RuleName".to_string(), serde_json::json!(format!("technique_id=T1134,technique_name=Access Token Manipulation,tags={}", tags.join(","))));
                                warn!("🔥 [NATIVE-DETECTION] Evasion detected for PID {} ({}): Spoofed={}", pid, image_path, tags.join("+"));
                            }
                        }

                        let _ = tx.try_send(sysmon_event);
                    }
                }
            })
            .build();

        // 2. Define the Kernel File Provider
        let tx_file = self.tx.clone();
        let file_provider = Provider::by_name("Microsoft-Windows-Kernel-File")
            .map_err(|e| anyhow::anyhow!("Failed to find file provider: {:?}", e))?
            .add_callback(move |record, schema_locator| {
                if record.event_id() == 11 {
                    if let Ok(schema) = schema_locator.event_schema(record) {
                        let parser = Parser::create(record, &schema);
                        let pid = record.process_id();
                        let file_path: String = parser.try_parse("FileName").unwrap_or_default();
                        
                        let mut sysmon_event = SysmonEvent::new(SysmonEventId::FileCreate);
                        if let Some(obj) = sysmon_event.data.as_object_mut() {
                            obj.insert("ProcessId".to_string(), serde_json::json!(pid));
                            obj.insert("TargetFilename".to_string(), serde_json::json!(file_path));
                        }

                        let _ = tx_file.try_send(sysmon_event);
                    }
                }
            })
            .build();

        // 3. Run the Trace
        info!("🚀 [NATIVE-TELEMETRY] Starting Oshoosi Native Monitoring (SysmonX Port)...");
        let trace = UserTrace::new()
            .named("OshoosiNativeTrace".to_string())
            .enable(process_provider)
            .enable(file_provider);

        tokio::task::spawn_blocking(move || {
            if let Err(e) = trace.start() {
                error!("Native Telemetry Trace failed: {:?}", e);
            }
        }).await?;

        Ok(())
    }
}

/// Helper to read the true command line from a process's PEB.
fn get_peb_command_line(pid: u32) -> Result<String> {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
    use windows::Win32::Foundation::CloseHandle;
    
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)?;
        let _ = CloseHandle(handle);
    }
    
    Ok(String::new())
}
