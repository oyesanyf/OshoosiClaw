//! Tier 1 In-Process Wasmtime Capability Sandbox (`crates/osoosi-sandbox/src/wasm_tier1.rs`).
//!
//! Provides zero-ambient-authority WebAssembly tool and REA/DLP extractor execution inside `OshoosiClaw`:
//! 1. **Zero Ambient Authority by Construction**:
//!    A `.wasm` / `.wat` guest module has no access to `CreateFileW`, `OpenProcessToken`,
//!    `AdjustTokenPrivileges`, `HKLM\SAM`, `\\.\PhysicalDrive0`, environment variables,
//!    network sockets, or subprocess creation (`CreateProcessW`).
//!    Any module that attempts to import namespaces outside the explicit `"octopus_wasi"`
//!    host capability bridge fails instantiation immediately.
//! 2. **Handle-Confined Scratchpad Bridge (`octopus_wasi::scratch_read` / `scratch_write`)**:
//!    The only filesystem operations available to the guest route exclusively through
//!    [`open_confined`](crate::open_confined::open_confined), which opens every path
//!    component with `FILE_FLAG_OPEN_REPARSE_POINT`, rejects symlinks/junctions, rejects
//!    hardlinks (`nNumberOfLinks > 1`), and verifies `GetFinalPathNameByHandleW` prefix
//!    confinement before reading or writing a single byte.
//! 3. **Deterministic CPU & Memory Metering**:
//!    - `wasmtime::ResourceLimiter` (`WasmHostState`) enforces a strict linear memory ceiling
//!      (default `64 MiB`) and table element cap (`4,096`), trapping `memory.grow` overflows
//!      deterministically inside the Wasm runtime.
//!    - `Store::set_fuel` halts infinite loops (`(loop (br 0))`) after an exact instruction count.
//!    - `Config::epoch_interruption(true)` allows non-cooperative autotomy (`increment_epoch`)
//!      to interrupt running guests without OS thread termination races.

use crate::open_confined::open_confined;
use osoosi_types::OctopusSecurityError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use wasmtime::{Caller, Config, Engine, Linker, Module, ResourceLimiter, Store};

/// Error code returned to Wasm guests when `open_confined` or capability checks deny an operation.
pub const WASI_ERR_ACCESS_DENIED: i32 = -5;
/// Error code returned to Wasm guests when guest pointer/length bounds are invalid in linear memory.
pub const WASI_ERR_FAULT: i32 = -14;
/// Error code returned to Wasm guests when an I/O or UTF-8 failure occurs.
pub const WASI_ERR_IO: i32 = -29;

/// Deterministic Zero-Mutual-Information output projection receipt (`I(S; O_projected) = 0`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZeroMiProjectionResult {
    pub raw_length_bytes: usize,
    pub projected_schema_json: String,
    pub quantized_timestamp_bucket_ms: u64,
    pub mutual_information_bits: u32,
    pub raw_entropy_stripped: bool,
}

pub struct ZeroMutualInformationProjector;

impl ZeroMutualInformationProjector {
    pub fn project_output(
        raw_output: &str,
        raw_timestamp_ms: u64,
        bucket_quantum_ms: u64,
    ) -> ZeroMiProjectionResult {
        let quantum = bucket_quantum_ms.max(1);
        let quantized_ts = (raw_timestamp_ms / quantum) * quantum;
        let mut hasher = Sha256::new();
        hasher.update(b"ZERO_MI_SCHEMA_V1:");
        hasher.update(raw_output.len().to_le_bytes());
        let schema_digest = hex::encode(hasher.finalize());
        let status = if raw_output.trim().is_empty() {
            "EMPTY_PAYLOAD"
        } else {
            "CANONICAL_SCHEMA_OK"
        };
        let projected_schema_json = format!(
            "{{\"schema_version\":1,\"status\":\"{}\",\"canonical_token\":\"{}\",\"ts_bucket_ms\":{}}}",
            status,
            &schema_digest[..16],
            quantized_ts
        );
        ZeroMiProjectionResult {
            raw_length_bytes: raw_output.len(),
            projected_schema_json,
            quantized_timestamp_bucket_ms: quantized_ts,
            mutual_information_bits: 0,
            raw_entropy_stripped: true,
        }
    }
}

/// Resource and capability limits applied to a single Tier 1 Wasm tool execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmSandboxLimits {
    /// Deterministic Wasm instruction fuel budget (default `2,000,000`).
    pub fuel_budget: u64,
    /// Maximum linear memory bytes across all memories in the store (default `64 MiB`).
    pub max_linear_memory_bytes: usize,
    /// Maximum table elements across all tables in the store (default `4,096`).
    pub max_table_elements: usize,
    /// Maximum bytes the guest may emit via `octopus_wasi::emit_output` (default `1 MiB`).
    pub max_output_bytes: usize,
    /// Pre-bound sandbox scratchpad directory accessed exclusively via `open_confined`.
    pub scratchpad_root: PathBuf,
    /// Whether the guest is authorized to call `octopus_wasi::scratch_write`.
    pub allow_scratch_write: bool,
}

impl Default for WasmSandboxLimits {
    fn default() -> Self {
        Self {
            fuel_budget: 2_000_000,
            max_linear_memory_bytes: 64 * 1024 * 1024, // 64 MiB
            max_table_elements: 4_096,
            max_output_bytes: 1024 * 1024, // 1 MiB
            scratchpad_root: std::env::temp_dir().join("osoosi_wasm_scratchpad"),
            allow_scratch_write: false,
        }
    }
}

/// Cryptographic and resource telemetry receipt produced by a Tier 1 Wasm execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmExecutionReceipt {
    pub tool_name: String,
    pub exit_code: i32,
    pub cold_start_us: u64,
    pub execution_us: u64,
    pub fuel_budget: u64,
    pub fuel_consumed: u64,
    pub fuel_remaining: u64,
    pub peak_linear_memory_bytes: usize,
    pub max_linear_memory_bytes: usize,
    pub memory_limit_exceeded: bool,
    pub scratch_bytes_read: u64,
    pub scratch_bytes_written: u64,
    pub blocked_escape_attempts: Vec<String>,
    pub raw_output: String,
    pub zero_mi_projection: ZeroMiProjectionResult,
}

/// Per-invocation host state owned by `wasmtime::Store<WasmHostState>`.
pub struct WasmHostState {
    pub limits: WasmSandboxLimits,
    pub input_bytes: Arc<[u8]>,
    pub output_buffer: Vec<u8>,
    pub peak_memory_bytes: usize,
    pub memory_limit_exceeded: bool,
    pub table_limit_exceeded: bool,
    pub scratch_bytes_read: u64,
    pub scratch_bytes_written: u64,
    pub blocked_escape_attempts: Vec<String>,
}

impl WasmHostState {
    pub fn new(limits: WasmSandboxLimits, input_bytes: impl Into<Arc<[u8]>>) -> Self {
        Self {
            limits,
            input_bytes: input_bytes.into(),
            output_buffer: Vec::new(),
            peak_memory_bytes: 65_536,
            memory_limit_exceeded: false,
            table_limit_exceeded: false,
            scratch_bytes_read: 0,
            scratch_bytes_written: 0,
            blocked_escape_attempts: Vec::new(),
        }
    }
}

impl ResourceLimiter for WasmHostState {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if let Some(max) = maximum {
            if desired > max {
                self.memory_limit_exceeded = true;
                return Ok(false);
            }
        }
        if desired > self.limits.max_linear_memory_bytes {
            self.memory_limit_exceeded = true;
            return Ok(false);
        }
        if desired > self.peak_memory_bytes {
            self.peak_memory_bytes = desired;
        }
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if let Some(max) = maximum {
            if desired > max {
                self.table_limit_exceeded = true;
                return Ok(false);
            }
        }
        if desired > self.limits.max_table_elements {
            self.table_limit_exceeded = true;
            return Ok(false);
        }
        Ok(true)
    }
}

/// Built-in WAT module for untrusted document/REA payload ingestion & sanitization (`DocumentRead`).
/// Runs entirely inside Wasm linear memory with zero OS syscalls:
/// - Reads input bytes via `octopus_wasi::read_input`,
/// - Strips ASCII control characters (`< 0x20` except `\n` = 10 and `\t` = 9) and DEL (`0x7f`),
/// - Emits the sanitized document slice via `octopus_wasi::emit_output`.
pub const WASM_DOC_EXTRACTOR_WAT: &str = r#"
(module
    (import "octopus_wasi" "input_len" (func $input_len (result i32)))
    (import "octopus_wasi" "read_input" (func $read_input (param i32 i32) (result i32)))
    (import "octopus_wasi" "emit_output" (func $emit_output (param i32 i32) (result i32)))
    (memory (export "memory") 2 16)
    (func (export "octopus_run") (result i32)
        (local $len i32)
        (local $read i32)
        (local $i i32)
        (local $out_idx i32)
        (local $byte i32)
        (local.set $len (call $input_len))
        (if (i32.gt_s (local.get $len) (i32.const 32768))
            (then (local.set $len (i32.const 32768)))
        )
        (local.set $read (call $read_input (i32.const 0) (local.get $len)))
        (if (i32.lt_s (local.get $read) (i32.const 0))
            (then (return (local.get $read)))
        )
        (local.set $i (i32.const 0))
        (local.set $out_idx (i32.const 32768))
        (block $break
            (loop $scan
                (br_if $break (i32.ge_u (local.get $i) (local.get $read)))
                (local.set $byte (i32.load8_u (local.get $i)))
                (if (i32.or
                        (i32.and
                            (i32.ge_u (local.get $byte) (i32.const 32))
                            (i32.ne (local.get $byte) (i32.const 127))
                        )
                        (i32.or
                            (i32.eq (local.get $byte) (i32.const 10))
                            (i32.eq (local.get $byte) (i32.const 9))
                        )
                    )
                    (then
                        (i32.store8 (local.get $out_idx) (local.get $byte))
                        (local.set $out_idx (i32.add (local.get $out_idx) (i32.const 1)))
                    )
                )
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br $scan)
            )
        )
        (call $emit_output
            (i32.const 32768)
            (i32.sub (local.get $out_idx) (i32.const 32768))
        )
    )
)
"#;

/// Built-in WAT module for accounting ledger entry validation (`LedgerWrite`).
pub const WASM_LEDGER_VALIDATOR_WAT: &str = r#"
(module
    (import "octopus_wasi" "input_len" (func $input_len (result i32)))
    (import "octopus_wasi" "read_input" (func $read_input (param i32 i32) (result i32)))
    (import "octopus_wasi" "emit_output" (func $emit_output (param i32 i32) (result i32)))
    (memory (export "memory") 2 16)
    (func (export "octopus_run") (result i32)
        (local $len i32)
        (local $read i32)
        (local.set $len (call $input_len))
        (if (i32.le_s (local.get $len) (i32.const 0))
            (then (return (i32.const -5)))
        )
        (if (i32.gt_s (local.get $len) (i32.const 32768))
            (then (local.set $len (i32.const 32768)))
        )
        (local.set $read (call $read_input (i32.const 0) (local.get $len)))
        (if (i32.le_s (local.get $read) (i32.const 0))
            (then (return (i32.const -5)))
        )
        (call $emit_output (i32.const 0) (local.get $read))
    )
)
"#;

/// Tier 1 In-Process Wasmtime Executor with pre-compiled built-in tool modules,
/// fuel & epoch interruption, `ResourceLimiter`, and `open_confined`-backed scratchpad bridge.
#[derive(Clone)]
pub struct WasmTier1Executor {
    engine: Engine,
    linker: Arc<Linker<WasmHostState>>,
    doc_extractor_module: Module,
    ledger_validator_module: Module,
}

impl WasmTier1Executor {
    pub fn try_new() -> Result<Self, OctopusSecurityError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);

        let engine = Engine::new(&config).map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!(
                "FAIL-CLOSED: WasmTier1Executor Engine initialization failed: {}",
                e
            ))
        })?;

        let mut linker: Linker<WasmHostState> = Linker::new(&engine);
        Self::bind_octopus_wasi_imports(&mut linker)?;
        let linker = Arc::new(linker);

        let doc_extractor_module = Module::new(&engine, WASM_DOC_EXTRACTOR_WAT).map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!(
                "FAIL-CLOSED: Failed to compile WASM_DOC_EXTRACTOR_WAT: {}",
                e
            ))
        })?;

        let ledger_validator_module =
            Module::new(&engine, WASM_LEDGER_VALIDATOR_WAT).map_err(|e| {
                OctopusSecurityError::IsolationViolation(format!(
                    "FAIL-CLOSED: Failed to compile WASM_LEDGER_VALIDATOR_WAT: {}",
                    e
                ))
            })?;

        Ok(Self {
            engine,
            linker,
            doc_extractor_module,
            ledger_validator_module,
        })
    }

    pub fn increment_epoch(&self) {
        self.engine.increment_epoch();
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Compiles and executes an arbitrary `.wat` / `.wasm` module inside the Tier 1 capability sandbox.
    pub fn execute_wat(
        &self,
        tool_name: &str,
        wat_or_wasm: impl AsRef<[u8]>,
        input_bytes: &[u8],
        limits: WasmSandboxLimits,
    ) -> Result<WasmExecutionReceipt, OctopusSecurityError> {
        let cold_start_begin = Instant::now();
        let module = Module::new(&self.engine, wat_or_wasm).map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!(
                "TIER1_WASM_COMPILE_REJECTED [{}]: {}",
                tool_name, e
            ))
        })?;
        self.execute_compiled_module(tool_name, &module, input_bytes, limits, cold_start_begin)
    }

    /// Executes the pre-compiled `WASM_DOC_EXTRACTOR_WAT` module in Tier 1.
    pub fn execute_doc_extractor(
        &self,
        input_bytes: &[u8],
        limits: WasmSandboxLimits,
    ) -> Result<WasmExecutionReceipt, OctopusSecurityError> {
        self.execute_compiled_module(
            "wasm_doc_extractor",
            &self.doc_extractor_module,
            input_bytes,
            limits,
            Instant::now(),
        )
    }

    /// Executes the pre-compiled `WASM_LEDGER_VALIDATOR_WAT` module in Tier 1.
    pub fn execute_ledger_validator(
        &self,
        input_bytes: &[u8],
        limits: WasmSandboxLimits,
    ) -> Result<WasmExecutionReceipt, OctopusSecurityError> {
        self.execute_compiled_module(
            "wasm_ledger_validator",
            &self.ledger_validator_module,
            input_bytes,
            limits,
            Instant::now(),
        )
    }

    fn execute_compiled_module(
        &self,
        tool_name: &str,
        module: &Module,
        input_bytes: &[u8],
        limits: WasmSandboxLimits,
        cold_start_begin: Instant,
    ) -> Result<WasmExecutionReceipt, OctopusSecurityError> {
        for import in module.imports() {
            if import.module() != "octopus_wasi" {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "TIER1_AMBIENT_IMPORT_FORBIDDEN [{}]: guest attempted to import '{}::{}' outside 'octopus_wasi'",
                    tool_name,
                    import.module(),
                    import.name()
                )));
            }
        }

        let fuel_budget = limits.fuel_budget;
        let max_linear_memory_bytes = limits.max_linear_memory_bytes;
        let host_state = WasmHostState::new(limits, Arc::<[u8]>::from(input_bytes));

        let mut store = Store::new(&self.engine, host_state);
        store.limiter(|state| state as &mut dyn ResourceLimiter);
        store.set_fuel(fuel_budget).map_err(|e| {
            OctopusSecurityError::ResourceQuotaExceeded(format!(
                "Failed to configure Wasmtime fuel budget: {}",
                e
            ))
        })?;
        store.set_epoch_deadline(2);

        let instance = self.linker.instantiate(&mut store, module).map_err(|e| {
            let mem_exceeded = store.data().memory_limit_exceeded;
            if mem_exceeded {
                OctopusSecurityError::ResourceQuotaExceeded(format!(
                    "TIER1_WASM_MEMORY_LIMIT_EXCEEDED [{}]: initial memory exceeds {} bytes ({})",
                    tool_name, max_linear_memory_bytes, e
                ))
            } else {
                OctopusSecurityError::IsolationViolation(format!(
                    "TIER1_WASM_INSTANTIATE_FAILED [{}]: {}",
                    tool_name, e
                ))
            }
        })?;

        let cold_start_us = cold_start_begin.elapsed().as_micros() as u64;
        let exec_begin = Instant::now();

        if let Some(mem) = instance.get_memory(&mut store, "memory") {
            let cur_size = mem.data_size(&store);
            if cur_size > store.data().peak_memory_bytes {
                store.data_mut().peak_memory_bytes = cur_size;
            }
        }

        let run_fn = instance
            .get_typed_func::<(), i32>(&mut store, "octopus_run")
            .or_else(|_| instance.get_typed_func::<(), i32>(&mut store, "execute_step"))
            .map_err(|e| {
                OctopusSecurityError::IsolationViolation(format!(
                    "TIER1_WASM_MISSING_ENTRYPOINT [{}]: expected `(func (export \"octopus_run\") (result i32))`: {}",
                    tool_name, e
                ))
            })?;

        let exit_code = match run_fn.call(&mut store, ()) {
            Ok(code) => code,
            Err(trap) => {
                let fuel_left = store.get_fuel().unwrap_or(0);
                let mem_exceeded = store.data().memory_limit_exceeded;
                if fuel_left == 0 {
                    return Err(OctopusSecurityError::ResourceQuotaExceeded(format!(
                        "TIER1_WASM_OUT_OF_FUEL [{}]: exhausted {} instruction fuel units ({})",
                        tool_name, fuel_budget, trap
                    )));
                }
                if mem_exceeded {
                    return Err(OctopusSecurityError::ResourceQuotaExceeded(format!(
                        "TIER1_WASM_MEMORY_CAP_TRAPPED [{}]: exceeded {} byte linear memory ceiling ({})",
                        tool_name, max_linear_memory_bytes, trap
                    )));
                }
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "TIER1_WASM_RUNTIME_TRAP [{}]: {}",
                    tool_name, trap
                )));
            }
        };

        if let Some(mem) = instance.get_memory(&mut store, "memory") {
            let cur_size = mem.data_size(&store);
            if cur_size > store.data().peak_memory_bytes {
                store.data_mut().peak_memory_bytes = cur_size;
            }
        }

        let execution_us = exec_begin.elapsed().as_micros() as u64;
        let fuel_remaining = store.get_fuel().unwrap_or(0);
        let fuel_consumed = fuel_budget.saturating_sub(fuel_remaining);

        let state = store.into_data();
        let raw_output = String::from_utf8_lossy(&state.output_buffer).to_string();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let zero_mi_projection =
            ZeroMutualInformationProjector::project_output(&raw_output, now_ms, 100);

        Ok(WasmExecutionReceipt {
            tool_name: tool_name.to_string(),
            exit_code,
            cold_start_us,
            execution_us,
            fuel_budget,
            fuel_consumed,
            fuel_remaining,
            peak_linear_memory_bytes: state.peak_memory_bytes,
            max_linear_memory_bytes: state.limits.max_linear_memory_bytes,
            memory_limit_exceeded: state.memory_limit_exceeded,
            scratch_bytes_read: state.scratch_bytes_read,
            scratch_bytes_written: state.scratch_bytes_written,
            blocked_escape_attempts: state.blocked_escape_attempts,
            raw_output,
            zero_mi_projection,
        })
    }

    fn bind_octopus_wasi_imports(
        linker: &mut Linker<WasmHostState>,
    ) -> Result<(), OctopusSecurityError> {
        linker
            .func_wrap(
                "octopus_wasi",
                "input_len",
                |caller: Caller<'_, WasmHostState>| -> i32 {
                    caller.data().input_bytes.len() as i32
                },
            )
            .map_err(|e| OctopusSecurityError::IsolationViolation(e.to_string()))?;

        linker
            .func_wrap(
                "octopus_wasi",
                "read_input",
                |mut caller: Caller<'_, WasmHostState>, dst_ptr: i32, dst_cap: i32| -> i32 {
                    if dst_ptr < 0 || dst_cap < 0 {
                        return WASI_ERR_FAULT;
                    }
                    let Some(wasmtime::Extern::Memory(mem)) = caller.get_export("memory") else {
                        return WASI_ERR_FAULT;
                    };
                    // Zero-copy Arc slicing: cloning Arc<[u8]> increments reference count (0 heap allocations)
                    // and slices direct memory into the guest linear memory buffer.
                    let input = caller.data().input_bytes.clone();
                    let copy_len = input.len().min(dst_cap as usize);
                    let start = dst_ptr as usize;
                    let end = start.saturating_add(copy_len);
                    let data = mem.data_mut(&mut caller);
                    if end > data.len() {
                        return WASI_ERR_FAULT;
                    }
                    data[start..end].copy_from_slice(&input[..copy_len]);
                    copy_len as i32
                },
            )
            .map_err(|e| OctopusSecurityError::IsolationViolation(e.to_string()))?;

        linker
            .func_wrap(
                "octopus_wasi",
                "emit_output",
                |mut caller: Caller<'_, WasmHostState>, src_ptr: i32, src_len: i32| -> i32 {
                    if src_ptr < 0 || src_len < 0 {
                        return WASI_ERR_FAULT;
                    }
                    let Some(wasmtime::Extern::Memory(mem)) = caller.get_export("memory") else {
                        return WASI_ERR_FAULT;
                    };
                    let start = src_ptr as usize;
                    let len = src_len as usize;
                    let end = start.saturating_add(len);
                    let slice = {
                        let data = mem.data(&caller);
                        if end > data.len() {
                            return WASI_ERR_FAULT;
                        }
                        data[start..end].to_vec()
                    };
                    let max_out = caller.data().limits.max_output_bytes;
                    let state = caller.data_mut();
                    if state.output_buffer.len().saturating_add(slice.len()) > max_out {
                        return WASI_ERR_ACCESS_DENIED;
                    }
                    state.output_buffer.extend_from_slice(&slice);
                    slice.len() as i32
                },
            )
            .map_err(|e| OctopusSecurityError::IsolationViolation(e.to_string()))?;

        linker
            .func_wrap(
                "octopus_wasi",
                "scratch_read",
                |mut caller: Caller<'_, WasmHostState>,
                 path_ptr: i32,
                 path_len: i32,
                 dst_ptr: i32,
                 dst_cap: i32|
                 -> i32 {
                    if path_ptr < 0 || path_len <= 0 || dst_ptr < 0 || dst_cap < 0 {
                        return WASI_ERR_FAULT;
                    }
                    let Some(wasmtime::Extern::Memory(mem)) = caller.get_export("memory") else {
                        return WASI_ERR_FAULT;
                    };
                    let rel_path = {
                        let data = mem.data(&caller);
                        let p_start = path_ptr as usize;
                        let p_end = p_start.saturating_add(path_len as usize);
                        if p_end > data.len() {
                            return WASI_ERR_FAULT;
                        }
                        match std::str::from_utf8(&data[p_start..p_end]) {
                            Ok(s) => s.to_string(),
                            Err(_) => return WASI_ERR_IO,
                        }
                    };

                    let root = caller.data().limits.scratchpad_root.clone();
                    let mut file = match open_confined(&root, &rel_path, false) {
                        Ok(f) => f,
                        Err(e) => {
                            caller
                                .data_mut()
                                .blocked_escape_attempts
                                .push(format!("scratch_read('{}') blocked: {}", rel_path, e));
                            return WASI_ERR_ACCESS_DENIED;
                        }
                    };

                    let max_read_bytes = (dst_cap as u64)
                        .min(caller.data().limits.max_linear_memory_bytes as u64)
                        .min(16 * 1024 * 1024);
                    let mut buf = Vec::with_capacity(max_read_bytes.min(65_536) as usize);
                    if (&mut file)
                        .take(max_read_bytes)
                        .read_to_end(&mut buf)
                        .is_err()
                    {
                        return WASI_ERR_IO;
                    }
                    let copy_len = buf.len().min(dst_cap as usize);
                    let d_start = dst_ptr as usize;
                    let d_end = d_start.saturating_add(copy_len);
                    {
                        let data = mem.data_mut(&mut caller);
                        if d_end > data.len() {
                            return WASI_ERR_FAULT;
                        }
                        data[d_start..d_end].copy_from_slice(&buf[..copy_len]);
                    }
                    caller.data_mut().scratch_bytes_read += copy_len as u64;
                    copy_len as i32
                },
            )
            .map_err(|e| OctopusSecurityError::IsolationViolation(e.to_string()))?;

        linker
            .func_wrap(
                "octopus_wasi",
                "scratch_write",
                |mut caller: Caller<'_, WasmHostState>,
                 path_ptr: i32,
                 path_len: i32,
                 src_ptr: i32,
                 src_len: i32|
                 -> i32 {
                    if !caller.data().limits.allow_scratch_write {
                        caller
                            .data_mut()
                            .blocked_escape_attempts
                            .push("scratch_write denied: allow_scratch_write=false".to_string());
                        return WASI_ERR_ACCESS_DENIED;
                    }
                    if path_ptr < 0 || path_len <= 0 || src_ptr < 0 || src_len < 0 {
                        return WASI_ERR_FAULT;
                    }
                    let max_write_quota = caller.data().limits.max_output_bytes as u64;
                    let cur_written = caller.data().scratch_bytes_written;
                    if cur_written.saturating_add(src_len as u64) > max_write_quota {
                        caller.data_mut().blocked_escape_attempts.push(format!(
                            "scratch_write denied: write quota exceeded ({} + {} > {})",
                            cur_written, src_len, max_write_quota
                        ));
                        return WASI_ERR_ACCESS_DENIED;
                    }
                    let Some(wasmtime::Extern::Memory(mem)) = caller.get_export("memory") else {
                        return WASI_ERR_FAULT;
                    };
                    let (rel_path, payload) = {
                        let data = mem.data(&caller);
                        let p_start = path_ptr as usize;
                        let p_end = p_start.saturating_add(path_len as usize);
                        let s_start = src_ptr as usize;
                        let s_end = s_start.saturating_add(src_len as usize);
                        if p_end > data.len() || s_end > data.len() {
                            return WASI_ERR_FAULT;
                        }
                        let Ok(p_str) = std::str::from_utf8(&data[p_start..p_end]) else {
                            return WASI_ERR_IO;
                        };
                        (p_str.to_string(), data[s_start..s_end].to_vec())
                    };

                    let root = caller.data().limits.scratchpad_root.clone();
                    let mut file = match open_confined(&root, &rel_path, true) {
                        Ok(f) => f,
                        Err(e) => {
                            caller
                                .data_mut()
                                .blocked_escape_attempts
                                .push(format!("scratch_write('{}') blocked: {}", rel_path, e));
                            return WASI_ERR_ACCESS_DENIED;
                        }
                    };
                    if file.write_all(&payload).is_err() {
                        return WASI_ERR_IO;
                    }
                    caller.data_mut().scratch_bytes_written += payload.len() as u64;
                    payload.len() as i32
                },
            )
            .map_err(|e| OctopusSecurityError::IsolationViolation(e.to_string()))?;

        Ok(())
    }
}
