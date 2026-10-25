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

use osoosi_audit::AuditTrail;
use osoosi_memory::MemoryStore;
use osoosi_model::MalwareScanner;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::time::{Duration, Instant};
use wasmtime::*;

pub mod hidden_process_ledger;
pub mod host_interface;
pub mod kill_switch;
pub mod memory_limiter;
pub mod native_host;
pub mod open_confined;
pub mod security;
pub mod tiered_executor;
pub mod token_posture;
pub mod wasm_tier1;
pub mod windows;

pub use hidden_process_ledger::{
    list_hidden_spawns, output_hidden, record_hidden_spawn, spawn_hidden, spawn_hidden_tokio,
    status_hidden, HiddenSpawnRecord, LedgeredCommandExt,
};
pub use native_host::{is_ssrf_ip, is_ssrf_ipv4, is_ssrf_url};
pub use open_confined::open_confined;
pub use security::SandboxSecurityConfig;
pub use tiered_executor::{
    ExecutionTier, TieredExecutionDispatcher, TieredExecutionReceipt, TieredToolRequest,
};
pub use token_posture::{
    current_token_posture, JobAccountingSnapshot, SandboxJobObject, TokenPosture,
    DANGEROUS_PRIVILEGES, INTEGRITY_HIGH, INTEGRITY_LOW, INTEGRITY_MEDIUM, INTEGRITY_SYSTEM,
    INTEGRITY_UNTRUSTED,
};
#[cfg(windows)]
pub use token_posture::{
    create_deelevated_token, spawn_deelevated, spawn_deelevated_in_job, DeelevatedChild,
};
pub use wasm_tier1::{
    WasmExecutionReceipt, WasmHostState, WasmSandboxLimits, WasmTier1Executor,
    ZeroMiProjectionResult, ZeroMutualInformationProjector, WASM_DOC_EXTRACTOR_WAT,
    WASM_LEDGER_VALIDATOR_WAT,
};

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
    pub memory_limiter: memory_limiter::MemoryLimiter,
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

/// Maximum allowable buffer length returned from WASM linear memory (16MB).
const MAX_WASM_BUFFER_SIZE: usize = 16 * 1024 * 1024;

/// Safely read a slice from WASM linear memory with checked arithmetic and size upper bounds.
fn read_wasm_slice(data: &[u8], ptr: u32, len: u32) -> Option<&[u8]> {
    let start = ptr as usize;
    let length = len as usize;
    if length > MAX_WASM_BUFFER_SIZE {
        return None;
    }
    let end = start.checked_add(length)?;
    data.get(start..end)
}

/// The main WASM execution engine.
pub struct SandboxExecutor {
    engine: Engine,
    audit: Arc<AuditTrail>,
    native_host: Arc<native_host::NativeHost>,
}

impl SandboxExecutor {
    pub fn new(
        audit: Arc<AuditTrail>,
        memory: Arc<MemoryStore>,
        malware_scanner: Arc<MalwareScanner>,
    ) -> anyhow::Result<Self> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);

        let engine = Engine::new(&config)?;
        let native_host = Arc::new(native_host::NativeHost::new(
            audit.clone(),
            memory,
            malware_scanner,
        ));

        Ok(Self {
            engine,
            audit,
            native_host,
        })
    }

    pub async fn run_script(
        &self,
        wasm_bytes: &[u8],
        config: SandboxConfig,
        taint_labels: std::collections::HashSet<osoosi_types::TaintLabel>,
    ) -> anyhow::Result<SandboxResult> {
        // 1. WASM provenance verification
        config
            .security_config
            .verify_wasm_hash(wasm_bytes)
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        let mut linker: Linker<SandboxStore> = Linker::new(&self.engine);

        // Add all WASI Preview 1 imports.
        wasmtime_wasi::p1::add_to_linker_async(&mut linker, |s: &mut SandboxStore| &mut s.wasi)?;

        // --- The Syscall Boundary (oso_brain module) ---

        // host_scan_file(bytes_ptr, bytes_len) -> response_id (JSON)
        linker.func_wrap_async(
            "oso_brain",
            "host_scan_file",
            |mut caller: Caller<'_, SandboxStore>, (ptr, len): (u32, u32)| {
                Box::new(async move {
                    let memory = caller
                        .get_export("memory")
                        .and_then(|e: Extern| e.into_memory())
                        .ok_or_else(|| wasmtime::Error::msg("Missing memory export"))?;
                    let data = memory.data(&caller);
                    let bytes = read_wasm_slice(data, ptr, len)
                        .ok_or_else(|| {
                            wasmtime::Error::msg(
                                "Out of bounds or oversized memory access in host_scan_file",
                            )
                        })?
                        .to_vec();
                    let fuel = caller.get_fuel().unwrap_or(0);

                    let store = caller.data_mut();
                    if store
                        .security_config
                        .is_rate_limited(store.syscall_sequence.len())
                    {
                        return Err(wasmtime::Error::msg("Rate limit: max host calls exceeded"));
                    }
                    store.syscall_sequence.push("host_scan_file".to_string());

                    let call = host_interface::HostCall::ScanFile { bytes };
                    let envelope = host_interface::HostCallEnvelope {
                        call_id: uuid::Uuid::new_v4().to_string(),
                        caller_module: "wasm_brain".to_string(),
                        call,
                        fuel_remaining: fuel,
                        taint_labels: store
                            .taint_labels
                            .iter()
                            .map(|l| format!("{:?}", l))
                            .collect(),
                        timestamp: chrono::Utc::now(),
                    };

                    let _response = store.native_host.dispatch(envelope).await;
                    Ok(0u32)
                })
                    as Box<
                        dyn std::future::Future<Output = Result<u32, wasmtime::Error>> + Send + '_,
                    >
            },
        )?;

        // host_fetch_url(url_ptr, url_len) -> response_id (JSON)
        linker.func_wrap_async(
            "oso_brain",
            "host_fetch_url",
            |mut caller: Caller<'_, SandboxStore>, (ptr, len): (u32, u32)| {
                Box::new(async move {
                    let memory = caller
                        .get_export("memory")
                        .and_then(|e: Extern| e.into_memory())
                        .ok_or_else(|| wasmtime::Error::msg("Missing memory export"))?;
                    let data = memory.data(&caller);
                    let slice = read_wasm_slice(data, ptr, len).ok_or_else(|| {
                        wasmtime::Error::msg(
                            "Out of bounds or oversized memory access in host_fetch_url",
                        )
                    })?;
                    let url = std::str::from_utf8(slice)
                        .map_err(|_| wasmtime::Error::msg("Invalid UTF-8 in URL"))?
                        .to_string();
                    let fuel = caller.get_fuel().unwrap_or(0);

                    let store = caller.data_mut();
                    if store
                        .security_config
                        .is_rate_limited(store.syscall_sequence.len())
                    {
                        return Err(wasmtime::Error::msg("Rate limit: max host calls exceeded"));
                    }
                    if !store.security_config.is_url_allowed(&url) {
                        return Err(wasmtime::Error::msg("URL not in allowlist"));
                    }
                    store
                        .syscall_sequence
                        .push(format!("host_fetch_url:{}", url));

                    let call = host_interface::HostCall::FetchUrl {
                        url,
                        method: "GET".to_string(),
                        headers: Vec::new(),
                    };
                    let envelope = host_interface::HostCallEnvelope {
                        call_id: uuid::Uuid::new_v4().to_string(),
                        caller_module: "wasm_brain".to_string(),
                        call,
                        fuel_remaining: fuel,
                        taint_labels: store
                            .taint_labels
                            .iter()
                            .map(|l| format!("{:?}", l))
                            .collect(),
                        timestamp: chrono::Utc::now(),
                    };

                    let _response = store.native_host.dispatch(envelope).await;
                    Ok(0u32)
                })
                    as Box<
                        dyn std::future::Future<Output = Result<u32, wasmtime::Error>> + Send + '_,
                    >
            },
        )?;

        // host_exec_command(cmd_ptr, cmd_len) -> response_id (JSON)
        linker.func_wrap_async(
            "oso_brain",
            "host_exec_command",
            |mut caller: Caller<'_, SandboxStore>, (ptr, len): (u32, u32)| {
                Box::new(async move {
                    let memory = caller
                        .get_export("memory")
                        .and_then(|e: Extern| e.into_memory())
                        .ok_or_else(|| wasmtime::Error::msg("Missing memory export"))?;
                    let data = memory.data(&caller);
                    let slice = read_wasm_slice(data, ptr, len).ok_or_else(|| {
                        wasmtime::Error::msg(
                            "Out of bounds or oversized memory access in host_exec_command",
                        )
                    })?;
                    let cmd = std::str::from_utf8(slice)
                        .map_err(|_| wasmtime::Error::msg("Invalid UTF-8 in command"))?
                        .to_string();
                    let fuel = caller.get_fuel().unwrap_or(0);

                    let program = cmd.split_whitespace().next().unwrap_or(&cmd).to_string();
                    let args = cmd.split_whitespace().skip(1).map(String::from).collect();

                    let store = caller.data_mut();
                    if store
                        .security_config
                        .is_rate_limited(store.syscall_sequence.len())
                    {
                        return Err(wasmtime::Error::msg("Rate limit: max host calls exceeded"));
                    }
                    if !store.security_config.is_command_allowed(&program) {
                        return Err(wasmtime::Error::msg("Command not in whitelist"));
                    }
                    store
                        .syscall_sequence
                        .push(format!("host_exec_command:{}", cmd));

                    let call = host_interface::HostCall::ExecCommand {
                        program,
                        args,
                        requires_approval: true,
                    };
                    let envelope = host_interface::HostCallEnvelope {
                        call_id: uuid::Uuid::new_v4().to_string(),
                        caller_module: "wasm_brain".to_string(),
                        call,
                        fuel_remaining: fuel,
                        taint_labels: store
                            .taint_labels
                            .iter()
                            .map(|l| format!("{:?}", l))
                            .collect(),
                        timestamp: chrono::Utc::now(),
                    };

                    let _response = store.native_host.dispatch(envelope).await;
                    Ok(0u32)
                })
                    as Box<
                        dyn std::future::Future<Output = Result<u32, wasmtime::Error>> + Send + '_,
                    >
            },
        )?;

        // host_read_db(query_ptr, query_len) -> response_id
        linker.func_wrap_async(
            "oso_brain",
            "host_read_db",
            |mut caller: Caller<'_, SandboxStore>, (ptr, len): (u32, u32)| {
                Box::new(async move {
                    let memory = caller
                        .get_export("memory")
                        .and_then(|e: Extern| e.into_memory())
                        .ok_or_else(|| wasmtime::Error::msg("Missing memory export"))?;
                    let data = memory.data(&caller);
                    let slice = read_wasm_slice(data, ptr, len).ok_or_else(|| {
                        wasmtime::Error::msg(
                            "Out of bounds or oversized memory access in host_read_db",
                        )
                    })?;
                    let query = std::str::from_utf8(slice)
                        .map_err(|_| wasmtime::Error::msg("Invalid UTF-8 in query"))?
                        .to_string();
                    let fuel = caller.get_fuel().unwrap_or(0);

                    let store = caller.data_mut();
                    if store
                        .security_config
                        .is_rate_limited(store.syscall_sequence.len())
                    {
                        return Err(wasmtime::Error::msg("Rate limit: max host calls exceeded"));
                    }
                    if !store.security_config.is_query_allowed(&query) {
                        return Err(wasmtime::Error::msg("Query references disallowed table"));
                    }
                    store
                        .syscall_sequence
                        .push(format!("host_read_db:{}", query));

                    let call = host_interface::HostCall::ReadDb {
                        query,
                        params: Vec::new(),
                    };
                    let envelope = host_interface::HostCallEnvelope {
                        call_id: uuid::Uuid::new_v4().to_string(),
                        caller_module: "wasm_brain".to_string(),
                        call,
                        fuel_remaining: fuel,
                        taint_labels: store
                            .taint_labels
                            .iter()
                            .map(|l| format!("{:?}", l))
                            .collect(),
                        timestamp: chrono::Utc::now(),
                    };

                    let _response = store.native_host.dispatch(envelope).await;
                    Ok(0u32)
                })
                    as Box<
                        dyn std::future::Future<Output = Result<u32, wasmtime::Error>> + Send + '_,
                    >
            },
        )?;

        // host_send_mesh(topic_ptr, topic_len, data_ptr, data_len) -> hash_id
        linker.func_wrap_async(
            "oso_brain",
            "host_send_mesh",
            |mut caller: Caller<'_, SandboxStore>,
             (t_ptr, t_len, d_ptr, d_len): (u32, u32, u32, u32)| {
                Box::new(async move {
                    let memory = caller
                        .get_export("memory")
                        .and_then(|e: Extern| e.into_memory())
                        .ok_or_else(|| wasmtime::Error::msg("Missing memory export"))?;
                    let data = memory.data(&caller);
                    let topic_slice = read_wasm_slice(data, t_ptr, t_len)
                        .ok_or_else(|| wasmtime::Error::msg("Out of bounds or oversized memory access for topic in host_send_mesh"))?;
                    let topic = std::str::from_utf8(topic_slice)
                        .map_err(|_| wasmtime::Error::msg("Invalid UTF-8 in topic"))?
                        .to_string();
                    let bytes = read_wasm_slice(data, d_ptr, d_len)
                        .ok_or_else(|| wasmtime::Error::msg("Out of bounds or oversized memory access for data in host_send_mesh"))?
                        .to_vec();
                    let fuel = caller.get_fuel().unwrap_or(0);

                    let store = caller.data_mut();
                    if store
                        .security_config
                        .is_rate_limited(store.syscall_sequence.len())
                    {
                        return Err(wasmtime::Error::msg("Rate limit: max host calls exceeded"));
                    }
                    store
                        .syscall_sequence
                        .push(format!("host_send_mesh:{}", topic));

                    let call = host_interface::HostCall::SendMesh { topic, data: bytes };
                    let envelope = host_interface::HostCallEnvelope {
                        call_id: uuid::Uuid::new_v4().to_string(),
                        caller_module: "wasm_brain".to_string(),
                        call,
                        fuel_remaining: fuel,
                        taint_labels: store
                            .taint_labels
                            .iter()
                            .map(|l| format!("{:?}", l))
                            .collect(),
                        timestamp: chrono::Utc::now(),
                    };

                    let _response = store.native_host.dispatch(envelope).await;
                    Ok(0u32)
                })
                    as Box<
                        dyn std::future::Future<Output = Result<u32, wasmtime::Error>> + Send + '_,
                    >
            },
        )?;

        // host_write_audit(entry_ptr, entry_len) -> hash_id
        linker.func_wrap_async(
            "oso_brain",
            "host_write_audit",
            |mut caller: Caller<'_, SandboxStore>, (ptr, len): (u32, u32)| {
                Box::new(async move {
                    let memory = caller
                        .get_export("memory")
                        .and_then(|e: Extern| e.into_memory())
                        .ok_or_else(|| wasmtime::Error::msg("Missing memory export"))?;
                    let data = memory.data(&caller);
                    let slice = read_wasm_slice(data, ptr, len).ok_or_else(|| {
                        wasmtime::Error::msg(
                            "Out of bounds or oversized memory access in host_write_audit",
                        )
                    })?;
                    let entry_str = std::str::from_utf8(slice)
                        .map_err(|_| wasmtime::Error::msg("Invalid UTF-8 in audit entry"))?
                        .to_string();
                    let entry: serde_json::Value = serde_json::from_str(&entry_str)
                        .map_err(|_| wasmtime::Error::msg("Invalid JSON in audit entry"))?;
                    let fuel = caller.get_fuel().unwrap_or(0);

                    let store = caller.data_mut();
                    if store
                        .security_config
                        .is_rate_limited(store.syscall_sequence.len())
                    {
                        return Err(wasmtime::Error::msg("Rate limit: max host calls exceeded"));
                    }
                    store
                        .syscall_sequence
                        .push(format!("host_write_audit:{}", entry_str));

                    let call = host_interface::HostCall::WriteAudit { entry };
                    let envelope = host_interface::HostCallEnvelope {
                        call_id: uuid::Uuid::new_v4().to_string(),
                        caller_module: "wasm_brain".to_string(),
                        call,
                        fuel_remaining: fuel,
                        taint_labels: store
                            .taint_labels
                            .iter()
                            .map(|l| format!("{:?}", l))
                            .collect(),
                        timestamp: chrono::Utc::now(),
                    };

                    let _response = store.native_host.dispatch(envelope).await;
                    Ok(0u32)
                })
                    as Box<
                        dyn std::future::Future<Output = Result<u32, wasmtime::Error>> + Send + '_,
                    >
            },
        )?;

        // --- Build the Tightened WASIp1 Context ---
        let wasi_p1 = wasmtime_wasi::WasiCtxBuilder::new().build_p1();

        let mut store = Store::new(
            &self.engine,
            SandboxStore {
                wasi: wasi_p1,
                memory_limiter: memory_limiter::MemoryLimiter::new(config.memory_limit_bytes),
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
        store.limiter(|s| &mut s.memory_limiter);
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

                self.audit.log(
                    "sandbox_execution_success",
                    serde_json::json!({
                        "fuel_used": fuel_used,
                        "duration_ms": duration_ms,
                        "syscall_count": syscall_count,
                        "suspicious_sequence": is_suspicious,
                        "pending_approvals": store.data().pending_approvals.len(),
                        "taint_labels": store.data().taint_labels,
                    }),
                );

                Ok(SandboxResult {
                    output: "Execution successful".to_string(),
                    pending_approvals: store.data().pending_approvals.clone(),
                    forensic_story: format!("Agent executed {} syscalls", syscall_count),
                    triage_level: if is_suspicious {
                        "CRITICAL".to_string()
                    } else {
                        "INFO".to_string()
                    },
                    fuel_used,
                    duration_ms,
                    syscall_count,
                    suspicious_sequence: is_suspicious,
                })
            }
            Err(e) => {
                let fuel_used = config.max_fuel - store.get_fuel().unwrap_or(0);
                self.audit.log(
                    "sandbox_execution_failure",
                    serde_json::json!({
                        "error": e.to_string(),
                        "fuel_used": fuel_used,
                        "duration_ms": start_time.elapsed().as_millis(),
                    }),
                );
                Err(e.into())
            }
        }
    }
}

/// Detect suspicious syscall sequences (e.g., db enumeration -> network exfil).
fn analyze_syscall_sequence(sequence: &[String]) -> bool {
    let mut has_db_read = false;

    for call in sequence {
        if call.contains("host_read_db") {
            has_db_read = true;
        }
        if call.contains("host_fetch_url") && has_db_read {
            return true;
        }
        if call.contains("host_exec_command") && has_db_read {
            return true;
        }
    }
    false
}

/// Validates and joins a candidate relative path inside a sandbox root, defending against:
/// 1. `Path::join` replacement via absolute paths, drive letters (`C:\`), or leading slashes/backslashes.
/// 2. UNC network paths (`\\server\share`).
/// 3. Percent-encoded traversal (`%2e`, `%2f`, `%5c`, `%00`) or null bytes.
/// 4. NTFS Alternate Data Streams (`report.txt:hidden_stream`).
/// 5. Parent directory traversal (`..` / `Component::ParentDir`).
pub fn validate_sandbox_relative_path(
    sandbox_root: &std::path::Path,
    candidate_rel: &str,
) -> Result<PathBuf, String> {
    let trimmed = candidate_rel.trim();
    if trimmed.is_empty() {
        return Err("Empty sandbox path rejected".to_string());
    }
    if trimmed.contains('\0') {
        return Err("Null byte in path rejected".to_string());
    }
    let lower = trimmed.to_ascii_lowercase();
    for encoded in ["%2e", "%2f", "%5c", "%00"] {
        if lower.contains(encoded) {
            return Err(format!(
                "Percent-encoded traversal sequence '{}' rejected",
                encoded
            ));
        }
    }
    if trimmed.starts_with('/') || trimmed.starts_with('\\') {
        return Err(
            "Leading slash/backslash or UNC path rejected (Path::join replacement defense)"
                .to_string(),
        );
    }
    if trimmed.contains(':') {
        return Err(
            "Drive letter or NTFS Alternate Data Stream (':') rejected (Path::join replacement defense)"
                .to_string(),
        );
    }

    let rel_path = std::path::Path::new(trimmed);
    if rel_path.is_absolute() {
        return Err("Absolute path rejected (Path::join replacement defense)".to_string());
    }
    for comp in rel_path.components() {
        match comp {
            std::path::Component::Normal(seg) => {
                let s = seg.to_string_lossy();
                if s.contains("..") || s.contains(':') {
                    return Err(format!("Disallowed path segment '{}' rejected", s));
                }
            }
            std::path::Component::CurDir => {}
            _ => {
                return Err(format!(
                    "Disallowed non-normal path component '{:?}' rejected",
                    comp
                ));
            }
        }
    }
    Ok(sandbox_root.join(rel_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::path::Path;

    #[test]
    fn test_vector3_sandbox_path_join_replacement_and_traversal_blocked() {
        let root = Path::new("/tmp/sandbox_workspace");
        assert!(validate_sandbox_relative_path(root, r"C:\Windows\System32\config\SAM").is_err());
        assert!(validate_sandbox_relative_path(root, "/etc/shadow").is_err());
        assert!(validate_sandbox_relative_path(root, r"\\10.0.0.5\c$\secrets.txt").is_err());
        assert!(validate_sandbox_relative_path(root, "..%2f..%2fetc/passwd").is_err());
        assert!(validate_sandbox_relative_path(root, "%2e%2e%5cWindows%5cwin.ini").is_err());
        assert!(validate_sandbox_relative_path(root, "report.txt%00.png").is_err());
        assert!(validate_sandbox_relative_path(root, "report.txt:hidden_ads").is_err());
        assert!(validate_sandbox_relative_path(root, "../../etc/passwd").is_err());
        let ok_path = validate_sandbox_relative_path(root, "reports/summary.json")
            .expect("normal relative path must succeed");
        assert!(ok_path.ends_with("summary.json"));
    }

    #[test]
    fn test_vector4_mathematical_ipv4_ipv6_ssrf_blocked() {
        assert!(is_ssrf_url("http://169.254.169.254/latest/meta-data/").is_err());
        assert!(is_ssrf_url("http://[::ffff:169.254.169.254]/latest/meta-data/").is_err());
        assert!(is_ssrf_url("http://metadata.google.internal/computeMetadata/v1/").is_err());
        assert!(is_ssrf_url("http://127.0.0.1:11434/api/tags").is_err());
        assert!(is_ssrf_url("http://localhost:3030/api/status").is_err());
        assert!(is_ssrf_url("http://[::1]:3030/api/status").is_err());
        assert!(is_ssrf_url("http://10.0.0.1/admin").is_err());
        assert!(is_ssrf_url("http://172.16.5.4/internal").is_err());
        assert!(is_ssrf_url("http://192.168.1.1/router").is_err());
        assert!(is_ssrf_url("http://100.64.0.1/mesh").is_err());
        assert!(is_ssrf_url("http://100.127.255.254/mesh").is_err());
        assert!(is_ssrf_ip("fc00::1".parse::<IpAddr>().unwrap()));
        assert!(is_ssrf_ip("fd12:3456:789a::1".parse::<IpAddr>().unwrap()));
        assert!(is_ssrf_ip("fe80::1".parse::<IpAddr>().unwrap()));
        assert!(is_ssrf_ip("0.0.0.0".parse::<IpAddr>().unwrap()));
        assert!(is_ssrf_ip("::".parse::<IpAddr>().unwrap()));
        assert!(is_ssrf_url("https://workbench.cisecurity.org/").is_ok());
    }

    #[test]
    fn test_vector5_windows_confinement_fail_closed_invariants() {
        let default_policy = windows::WindowsConfinementPolicy::default();
        assert!(windows::verify_windows_confinement_invariants(&default_policy).is_ok());

        let ok_outcome =
            windows::evaluate_pre_resume_confinement_gate(&default_policy, true, true, true, true);
        assert!(ok_outcome.resume_thread_allowed);
        assert!(!ok_outcome.terminated_suspended_process);
        assert!(ok_outcome.sid_freed_via_free_sid);
        assert!(!ok_outcome.uncontained_fallback_used);

        let failed_job = windows::evaluate_pre_resume_confinement_gate(
            &default_policy,
            true,
            true,
            false,
            false,
        );
        assert!(!failed_job.resume_thread_allowed);
        assert!(failed_job.terminated_suspended_process);
        assert!(failed_job.sid_freed_via_free_sid);
        assert!(failed_job.profile_rolled_back_via_delete_appcontainer_profile);
        assert!(!failed_job.uncontained_fallback_used);

        let mut bad_policy = default_policy.clone();
        bad_policy.creation_flags = 0;
        assert!(windows::verify_windows_confinement_invariants(&bad_policy).is_err());
    }

    #[test]
    fn test_win32_appcontainer_profile_lifecycle_and_confined_execution() {
        let default_policy = windows::WindowsConfinementPolicy::default();

        let mut profile =
            windows::Win32AppContainerProfile::create("test_agent_profile", "Test Agent Profile")
                .expect("Valid profile creation should succeed");
        assert_eq!(profile.profile_name, "test_agent_profile");
        assert!(profile.profile_allocated);
        assert!(profile.sid_allocated);

        profile.rollback();
        assert!(!profile.profile_allocated);
        assert!(!profile.sid_allocated);

        let outcome = windows::execute_confined_windows_process(
            "cmd.exe",
            &["/c", "whoami"],
            "test_agent_proc_profile",
            &default_policy,
        )
        .expect("Execution with compliant policy should succeed");
        assert!(outcome.resume_thread_allowed);
        assert!(!outcome.terminated_suspended_process);
        assert!(outcome.sid_freed_via_free_sid);
        assert!(!outcome.uncontained_fallback_used);

        let mut permissive_policy = default_policy.clone();
        permissive_policy.allow_uncontained_fallback = true;
        assert!(windows::execute_confined_windows_process(
            "cmd.exe",
            &["/c", "whoami"],
            "test_bad_profile",
            &permissive_policy,
        )
        .is_err());
    }
}
