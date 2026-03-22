//! WASM Sandboxing with Dual-Metering (Fuel + Epoch).
//!
//! Provides isolated execution of untrusted code with:
//! - Fuel tracking (CPU instruction budget)
//! - Epoch interruption (wall-clock timeout)
//! - Workspace isolation (filesystem confinement)
//! - Capability-based tool access
//! - Taint-aware security gates
//! - Kill-switch process management
//! - SSRF protection
//! - Merkle-audited decision logging

use wasmtime::*;
use osoosi_audit::AuditTrail;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::time::{Duration, Instant};
use osoosi_memory::MemoryStore;
use osoosi_model::MalwareScanner;

pub mod host_interface;
pub mod native_host;
pub mod memory_limiter;
pub mod kill_switch;
pub mod security;

pub use security::SandboxSecurityConfig;

/// Configuration for a sandbox execution.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub max_fuel: u64,
    pub memory_limit_bytes: usize,
    pub wall_clock_timeout: Duration,
    pub workspace_dir: PathBuf,
    pub allowed_capabilities: Vec<Capability>,
    /// Security model: hash verification, allowlists, rate limiting.
    #[allow(clippy::module_name_repetitions)]
    pub security_config: SandboxSecurityConfig,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            max_fuel: 500_000,
            memory_limit_bytes: 8 * 1024 * 1024,
            wall_clock_timeout: Duration::from_secs(30),
            workspace_dir: PathBuf::from("."),
            allowed_capabilities: Vec::new(),
            security_config: SandboxSecurityConfig::default(),
        }
    }
}

/// Capability tokens that grant specific permissions to WASM modules.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Capability {
    FileRead(String),
    FileWrite(String),
    NetworkOut(String),
    ExecuteTool(String),
}

/// Internal state for a WASM Store.
///
/// Uses `WasiP1Ctx` which wraps both `WasiCtx` and `ResourceTable` and
/// implements `WasiView` automatically. Our custom security state is stored
/// alongside it.
pub struct SandboxStore {
    /// The WASIp1 context
    pub wasi: wasmtime_wasi::p1::WasiP1Ctx,
    pub fuel_consumed: u64,
    pub capabilities: Vec<Capability>,
    pub pending_approvals: Vec<ApprovalRequest>,
    pub triage_queue: Vec<String>,
    pub forensic_story: Vec<String>,
    pub taint_labels: std::collections::HashSet<osoosi_types::TaintLabel>,
    pub syscall_sequence: Vec<String>,
    pub native_host: Arc<native_host::NativeHost>,
    pub security_config: SandboxSecurityConfig,
}

/// A pending human-in-the-loop approval request.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApprovalRequest {
    pub id: String,
    pub action: String,
    pub description: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Result of a sandbox execution.
pub struct SandboxResult {
    pub output: String,
    pub pending_approvals: Vec<ApprovalRequest>,
    pub forensic_story: String,
    pub triage_level: String,
    pub fuel_used: u64,
    pub duration_ms: u128,
    pub syscall_count: usize,
    pub suspicious_sequence: bool,
}

/// The main WASM execution engine.
pub struct SandboxExecutor {
    engine: Engine,
    audit: Arc<AuditTrail>,
    native_host: Arc<native_host::NativeHost>,
}

impl SandboxExecutor {
    pub fn new(audit: Arc<AuditTrail>, memory: Arc<MemoryStore>, malware_scanner: Arc<MalwareScanner>) -> anyhow::Result<Self> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);
        config.async_support(true);

        let engine = Engine::new(&config)?;
        let native_host = Arc::new(native_host::NativeHost::new(audit.clone(), memory, malware_scanner));

        Ok(Self { engine, audit, native_host })
    }

    pub async fn run_script(
        &self,
        wasm_bytes: &[u8],
        config: SandboxConfig,
        taint_labels: std::collections::HashSet<osoosi_types::TaintLabel>,
    ) -> anyhow::Result<SandboxResult> {
        // 1. WASM provenance verification
        config.security_config.verify_wasm_hash(wasm_bytes).map_err(|e| anyhow::anyhow!("{}", e))?;

        let mut linker: Linker<SandboxStore> = Linker::new(&self.engine);

        // Add all WASI Preview 1 imports.
        // The closure projects from our SandboxStore to the WasiP1Ctx field.
        wasmtime_wasi::p1::add_to_linker_async(&mut linker, |s: &mut SandboxStore| &mut s.wasi)?;

        // --- The Syscall Boundary (oso_brain module) ---

        // host_scan_file(bytes_ptr, bytes_len) -> response_id (JSON)
        linker.func_wrap_async("oso_brain", "host_scan_file", |mut caller: Caller<'_, SandboxStore>, (ptr, len): (u32, u32)| {
            Box::new(async move {
                let memory = caller.get_export("memory").and_then(|e: Extern| e.into_memory())
                    .ok_or_else(|| wasmtime::Error::msg("Missing memory export"))?;
                let data = memory.data(&caller);
                let bytes = data.get(ptr as usize..(ptr + len) as usize)
                    .ok_or_else(|| wasmtime::Error::msg("Out of bounds memory access"))?
                    .to_vec();
                let fuel = caller.get_fuel().unwrap_or(0);

                let store = caller.data_mut();
                if store.security_config.is_rate_limited(store.syscall_sequence.len()) {
                    return Err(wasmtime::Error::msg("Rate limit: max host calls exceeded"));
                }
                store.syscall_sequence.push("host_scan_file".to_string());
                
                let call = host_interface::HostCall::ScanFile { bytes };
                let envelope = host_interface::HostCallEnvelope {
                    call_id: uuid::Uuid::new_v4().to_string(),
                    caller_module: "wasm_brain".to_string(),
                    call,
                    fuel_remaining: fuel,
                    taint_labels: store.taint_labels.iter().map(|l| format!("{:?}", l)).collect(),
                    timestamp: chrono::Utc::now(),
                };
                
                let _response = store.native_host.dispatch(envelope).await;
                Ok(0u32)
            }) as Box<dyn std::future::Future<Output = Result<u32, wasmtime::Error>> + Send + '_>
        })?;

        // host_fetch_url(url_ptr, url_len) -> response_id (JSON)
        linker.func_wrap_async("oso_brain", "host_fetch_url", |mut caller: Caller<'_, SandboxStore>, (ptr, len): (u32, u32)| {
            Box::new(async move {
                let memory = caller.get_export("memory").and_then(|e: Extern| e.into_memory())
                    .ok_or_else(|| wasmtime::Error::msg("Missing memory export"))?;
                let data = memory.data(&caller);
                let url = std::str::from_utf8(&data[ptr as usize..(ptr + len) as usize])
                    .map_err(|_| wasmtime::Error::msg("Invalid UTF-8 in URL"))?
                    .to_string();
                let fuel = caller.get_fuel().unwrap_or(0);

                let store = caller.data_mut();
                if store.security_config.is_rate_limited(store.syscall_sequence.len()) {
                    return Err(wasmtime::Error::msg("Rate limit: max host calls exceeded"));
                }
                if !store.security_config.is_url_allowed(&url) {
                    return Err(wasmtime::Error::msg("URL not in allowlist"));
                }
                store.syscall_sequence.push(format!("host_fetch_url:{}", url));
                
                let call = host_interface::HostCall::FetchUrl { 
                    url, 
                    method: "GET".to_string(), 
                    headers: Vec::new() 
                };
                let envelope = host_interface::HostCallEnvelope {
                    call_id: uuid::Uuid::new_v4().to_string(),
                    caller_module: "wasm_brain".to_string(),
                    call,
                    fuel_remaining: fuel,
                    taint_labels: store.taint_labels.iter().map(|l| format!("{:?}", l)).collect(),
                    timestamp: chrono::Utc::now(),
                };
                
                let _response = store.native_host.dispatch(envelope).await;
                Ok(0u32)
            }) as Box<dyn std::future::Future<Output = Result<u32, wasmtime::Error>> + Send + '_>
        })?;

        // host_exec_command(cmd_ptr, cmd_len) -> response_id (JSON)
        linker.func_wrap_async("oso_brain", "host_exec_command", |mut caller: Caller<'_, SandboxStore>, (ptr, len): (u32, u32)| {
            Box::new(async move {
                let memory = caller.get_export("memory").and_then(|e: Extern| e.into_memory())
                    .ok_or_else(|| wasmtime::Error::msg("Missing memory export"))?;
                let data = memory.data(&caller);
                let cmd = std::str::from_utf8(&data[ptr as usize..(ptr + len) as usize])
                    .map_err(|_| wasmtime::Error::msg("Invalid UTF-8 in command"))?
                    .to_string();
                let fuel = caller.get_fuel().unwrap_or(0);

                let program = cmd.split_whitespace().next().unwrap_or(&cmd).to_string();
                let args = cmd.split_whitespace().skip(1).map(String::from).collect();

                let store = caller.data_mut();
                if store.security_config.is_rate_limited(store.syscall_sequence.len()) {
                    return Err(wasmtime::Error::msg("Rate limit: max host calls exceeded"));
                }
                if !store.security_config.is_command_allowed(&program) {
                    return Err(wasmtime::Error::msg("Command not in whitelist"));
                }
                store.syscall_sequence.push(format!("host_exec_command:{}", cmd));
                
                let call = host_interface::HostCall::ExecCommand { 
                    program, 
                    args, 
                    requires_approval: true // Default to requiring approval for WASM brain commands
                };
                let envelope = host_interface::HostCallEnvelope {
                    call_id: uuid::Uuid::new_v4().to_string(),
                    caller_module: "wasm_brain".to_string(),
                    call,
                    fuel_remaining: fuel,
                    taint_labels: store.taint_labels.iter().map(|l| format!("{:?}", l)).collect(),
                    timestamp: chrono::Utc::now(),
                };
                
                let _response = store.native_host.dispatch(envelope).await;
                Ok(0u32)
            }) as Box<dyn std::future::Future<Output = Result<u32, wasmtime::Error>> + Send + '_>
        })?;

        // host_read_db(query_ptr, query_len) -> response_id
        linker.func_wrap_async("oso_brain", "host_read_db", |mut caller: Caller<'_, SandboxStore>, (ptr, len): (u32, u32)| {
            Box::new(async move {
                let memory = caller.get_export("memory").and_then(|e: Extern| e.into_memory())
                    .ok_or_else(|| wasmtime::Error::msg("Missing memory export"))?;
                let data = memory.data(&caller);
                let query = std::str::from_utf8(&data[ptr as usize..(ptr + len) as usize])
                    .map_err(|_| wasmtime::Error::msg("Invalid UTF-8 in query"))?
                    .to_string();
                let fuel = caller.get_fuel().unwrap_or(0);

                let store = caller.data_mut();
                if store.security_config.is_rate_limited(store.syscall_sequence.len()) {
                    return Err(wasmtime::Error::msg("Rate limit: max host calls exceeded"));
                }
                if !store.security_config.is_query_allowed(&query) {
                    return Err(wasmtime::Error::msg("Query references disallowed table"));
                }
                store.syscall_sequence.push(format!("host_read_db:{}", query));
                
                let call = host_interface::HostCall::ReadDb { 
                    query, 
                    params: Vec::new() 
                };
                let envelope = host_interface::HostCallEnvelope {
                    call_id: uuid::Uuid::new_v4().to_string(),
                    caller_module: "wasm_brain".to_string(),
                    call,
                    fuel_remaining: fuel,
                    taint_labels: store.taint_labels.iter().map(|l| format!("{:?}", l)).collect(),
                    timestamp: chrono::Utc::now(),
                };
                
                let _response = store.native_host.dispatch(envelope).await;
                Ok(0u32)
            }) as Box<dyn std::future::Future<Output = Result<u32, wasmtime::Error>> + Send + '_>
        })?;

        // host_send_mesh(topic_ptr, topic_len, data_ptr, data_len) -> hash_id
        linker.func_wrap_async("oso_brain", "host_send_mesh", |mut caller: Caller<'_, SandboxStore>, (t_ptr, t_len, d_ptr, d_len): (u32, u32, u32, u32)| {
            Box::new(async move {
                let memory = caller.get_export("memory").and_then(|e: Extern| e.into_memory())
                    .ok_or_else(|| wasmtime::Error::msg("Missing memory export"))?;
                let data = memory.data(&caller);
                let topic = std::str::from_utf8(&data[t_ptr as usize..(t_ptr + t_len) as usize])
                    .map_err(|_| wasmtime::Error::msg("Invalid UTF-8 in topic"))?
                    .to_string();
                let bytes = data.get(d_ptr as usize..(d_ptr + d_len) as usize)
                    .ok_or_else(|| wasmtime::Error::msg("Out of bounds memory access"))?
                    .to_vec();
                let fuel = caller.get_fuel().unwrap_or(0);

                let store = caller.data_mut();
                if store.security_config.is_rate_limited(store.syscall_sequence.len()) {
                    return Err(wasmtime::Error::msg("Rate limit: max host calls exceeded"));
                }
                store.syscall_sequence.push(format!("host_send_mesh:{}", topic));
                
                let call = host_interface::HostCall::SendMesh { 
                    topic, 
                    data: bytes 
                };
                let envelope = host_interface::HostCallEnvelope {
                    call_id: uuid::Uuid::new_v4().to_string(),
                    caller_module: "wasm_brain".to_string(),
                    call,
                    fuel_remaining: fuel,
                    taint_labels: store.taint_labels.iter().map(|l| format!("{:?}", l)).collect(),
                    timestamp: chrono::Utc::now(),
                };
                
                let _response = store.native_host.dispatch(envelope).await;
                Ok(0u32)
            }) as Box<dyn std::future::Future<Output = Result<u32, wasmtime::Error>> + Send + '_>
        })?;

        // host_write_audit(entry_ptr, entry_len) -> hash_id
        linker.func_wrap_async("oso_brain", "host_write_audit", |mut caller: Caller<'_, SandboxStore>, (ptr, len): (u32, u32)| {
            Box::new(async move {
                let memory = caller.get_export("memory").and_then(|e: Extern| e.into_memory())
                    .ok_or_else(|| wasmtime::Error::msg("Missing memory export"))?;
                let data = memory.data(&caller);
                let entry_str = std::str::from_utf8(&data[ptr as usize..(ptr + len) as usize])
                    .map_err(|_| wasmtime::Error::msg("Invalid UTF-8 in audit entry"))?
                    .to_string();
                let entry: serde_json::Value = serde_json::from_str(&entry_str)
                    .map_err(|_| wasmtime::Error::msg("Invalid JSON in audit entry"))?;
                let fuel = caller.get_fuel().unwrap_or(0);

                let store = caller.data_mut();
                if store.security_config.is_rate_limited(store.syscall_sequence.len()) {
                    return Err(wasmtime::Error::msg("Rate limit: max host calls exceeded"));
                }
                store.syscall_sequence.push(format!("host_write_audit:{}", entry_str));
                
                let call = host_interface::HostCall::WriteAudit { entry };
                let envelope = host_interface::HostCallEnvelope {
                    call_id: uuid::Uuid::new_v4().to_string(),
                    caller_module: "wasm_brain".to_string(),
                    call,
                    fuel_remaining: fuel,
                    taint_labels: store.taint_labels.iter().map(|l| format!("{:?}", l)).collect(),
                    timestamp: chrono::Utc::now(),
                };
                
                let _response = store.native_host.dispatch(envelope).await;
                Ok(0u32)
            }) as Box<dyn std::future::Future<Output = Result<u32, wasmtime::Error>> + Send + '_>
        })?;

        // --- Build the Tightened WASIp1 Context ---

        // Security Benefit: No host filesystem access, no inherited env, no stdout/stderr.
        // The WASM brain can ONLY talk to the host via the 'oso_brain' syscalls.
        let wasi_p1 = wasmtime_wasi::WasiCtxBuilder::new()
            .build_p1();

        let mut store = Store::new(
            &self.engine,
            SandboxStore {
                wasi: wasi_p1,
                fuel_consumed: 0,
                capabilities: config.allowed_capabilities.clone(),
                pending_approvals: Vec::new(),
                triage_queue: Vec::new(),
                forensic_story: Vec::new(),
                taint_labels,
                syscall_sequence: Vec::new(),
                native_host: self.native_host.clone(),
                security_config: config.security_config.clone(),
            },
        );

        // --- Set Resource Limits ---
        store.set_fuel(config.max_fuel)?;
        store.epoch_deadline_async_yield_and_update(1);

        // --- Compile and Instantiate ---
        let module = Module::from_binary(&self.engine, wasm_bytes)?;
        let instance = linker.instantiate_async(&mut store, &module).await?;
        let func = instance.get_typed_func::<(), ()>(&mut store, "_start")?;

        let start_time = Instant::now();

        // Epoch-based timeout: spawn a task to increment epoch after timeout
        let engine_clone = self.engine.clone();
        let timeout = config.wall_clock_timeout;
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            engine_clone.increment_epoch();
        });

        // --- Execute ---
        match func.call_async(&mut store, ()).await {
            Ok(_) => {
                let fuel_used = config.max_fuel - store.get_fuel()?;
                let syscall_count = store.data().syscall_sequence.len();
                let is_suspicious = analyze_syscall_sequence(&store.data().syscall_sequence);
                let duration_ms = start_time.elapsed().as_millis();

                self.audit.log("sandbox_execution_success", serde_json::json!({
                    "fuel_used": fuel_used,
                    "duration_ms": duration_ms,
                    "syscall_count": syscall_count,
                    "suspicious_sequence": is_suspicious,
                    "pending_approvals": store.data().pending_approvals.len(),
                    "taint_labels": store.data().taint_labels,
                }));

                Ok(SandboxResult {
                    output: "Execution successful".to_string(),
                    pending_approvals: store.data().pending_approvals.clone(),
                    forensic_story: format!("Agent executed {} syscalls", syscall_count),
                    triage_level: if is_suspicious { "CRITICAL".to_string() } else { "INFO".to_string() },
                    fuel_used,
                    duration_ms,
                    syscall_count,
                    suspicious_sequence: is_suspicious,
                })
            }
            Err(e) => {
                let fuel_used = config.max_fuel - store.get_fuel().unwrap_or(0);
                self.audit.log("sandbox_execution_failure", serde_json::json!({
                    "error": e.to_string(),
                    "fuel_used": fuel_used,
                    "duration_ms": start_time.elapsed().as_millis(),
                }));
                Err(e)
            }
        }
    }
}

/// Detect suspicious syscall sequences (e.g., db enumeration → network exfil).
fn analyze_syscall_sequence(sequence: &[String]) -> bool {
    let mut has_db_read = false;

    for call in sequence {
        if call.contains("host_read_db") {
            has_db_read = true;
        }
        if call.contains("host_fetch_url") && has_db_read {
            return true; // Suspicious: potentially stealing data via DB read → network exfil
        }
        if call.contains("host_exec_command") && has_db_read {
            return true; // Suspicious: DB read → command execution (potential lateral movement)
        }
    }
    false
}
