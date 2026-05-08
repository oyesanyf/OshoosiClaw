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

        info!("⚠️  [NATIVE-TELEMETRY] Kernel ETW Monitoring temporarily disabled for stability.");
        
        // Keep the thread alive
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
