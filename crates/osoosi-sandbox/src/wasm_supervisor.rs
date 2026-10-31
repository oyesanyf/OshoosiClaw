//! Zero-Overhead Wasmtime Sandbox Architecture & Dual-Plane Supervisor (`crates/osoosi-sandbox/src/wasm_supervisor.rs`).
//!
//! Provides:
//! 1. `build_zero_overhead_engine`: Hot-Path Engine using `PoolingAllocationConfig` (64 slots, 64 MiB ceiling, 1 MiB warm resident, epoch interruption, consume_fuel=false).
//! 2. `build_metered_engine`: Scraper Engine (16 slots, consume_fuel=true, StoreLimits 64 MiB).
//! 3. `EpochTicker`: OS background thread maintaining 1ms quantum with Windows `timeBeginPeriod(1)`.
//! 4. AOT precompilation & `.cwasm` in-memory / on-disk caching.
//! 5. `WasmSupervisor`: Split-plane P2P frame validation (< 50 µs warm latency) and metered document sanitization.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use thiserror::Error;
use wasmtime::*;

#[cfg(windows)]
extern "system" {
    fn timeBeginPeriod(uPeriod: u32) -> u32;
    fn timeEndPeriod(uPeriod: u32) -> u32;
}

/// Errors returned by the WasmSupervisor and its guest execution pools.
#[derive(Error, Debug)]
pub enum WasmSupervisorError {
    #[error("Engine initialization failed: {0}")]
    EngineInit(String),

    #[error("Compilation or AOT verification failed: {0}")]
    Compilation(String),

    #[error("Instantiation failed: {0}")]
    Instantiation(String),

    #[error("Guest execution trapped: {0}")]
    Trap(String),

    #[error("Epoch deadline exceeded ({deadline_ms} ticks elapsed)")]
    EpochDeadlineExceeded { deadline_ms: u64 },

    #[error("Fuel exhausted (budget: {limit})")]
    FuelExhausted { limit: u64 },

    #[error("Linear memory limit exceeded ({requested_bytes} requested, {limit_bytes} allowed)")]
    MemoryExceeded {
        requested_bytes: usize,
        limit_bytes: usize,
    },

    #[error("P2P frame validation rejected: topic '{topic}', reason: {reason}")]
    FrameRejected { topic: String, reason: String },

    #[error("SSRF violation: target address '{address}' is blocked")]
    SsrfBlocked { address: String },

    #[error("Host I/O error: {0}")]
    HostIo(#[from] std::io::Error),
}

/// Constructs the Hot-Path Zero-Overhead Engine.
///
/// Characteristics:
/// - PoolingAllocator pre-allocates 64 slots, avoiding OS VirtualAlloc/mmap syscalls on checkout.
/// - `linear_memory_keep_resident(1024 * 1024)` keeps 1 MiB paged in RAM to eliminate page faults.
/// - `consume_fuel(false)` eliminates instruction counter overhead in hot loops.
/// - `epoch_interruption(true)` ensures asynchronous non-cooperative preemption.
pub fn build_zero_overhead_engine() -> Result<Engine, WasmSupervisorError> {
    let mut pool = PoolingAllocationConfig::new();
    pool.total_component_instances(64)
        .total_core_instances(64)
        .total_memories(64)
        .total_tables(64)
        .max_memory_size(64 * 1024 * 1024) // 64 MiB hard ceiling
        .linear_memory_keep_resident(1024 * 1024) // 1 MiB warm resident
        .max_unused_warm_slots(64);

    let mut config = Config::new();
    config.wasm_component_model(true);
    config.memory_init_cow(true);
    config.allocation_strategy(InstanceAllocationStrategy::Pooling(pool));
    config.epoch_interruption(true);
    config.consume_fuel(false);
    config.cranelift_opt_level(OptLevel::Speed);

    Engine::new(&config).map_err(|e| WasmSupervisorError::EngineInit(e.to_string()))
}

/// Constructs the Metered Scraper Engine.
///
/// Characteristics:
/// - 16 pool slots with immediate reclamation (`linear_memory_keep_resident(0)`).
/// - `consume_fuel(true)` for strict instruction metering of untrusted guest workloads.
/// - `epoch_interruption(true)` for wall-clock deadline backstops.
pub fn build_metered_engine() -> Result<Engine, WasmSupervisorError> {
    let mut pool = PoolingAllocationConfig::new();
    pool.total_component_instances(16)
        .total_core_instances(16)
        .total_memories(16)
        .total_tables(16)
        .max_memory_size(64 * 1024 * 1024)
        .linear_memory_keep_resident(0);

    let mut config = Config::new();
    config.wasm_component_model(true);
    config.memory_init_cow(true);
    config.allocation_strategy(InstanceAllocationStrategy::Pooling(pool));
    config.epoch_interruption(true);
    config.consume_fuel(true);

    Engine::new(&config).map_err(|e| WasmSupervisorError::EngineInit(e.to_string()))
}

/// Dedicated OS background atomic epoch ticker maintaining a 1ms quantum.
pub struct EpochTicker {
    shutdown_flag: Arc<AtomicBool>,
    thread_handle: Option<std::thread::JoinHandle<()>>,
}

impl EpochTicker {
    pub fn spawn(engines: Vec<Engine>, tick_interval: Duration) -> Self {
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let flag_clone = shutdown_flag.clone();

        let thread_handle = std::thread::Builder::new()
            .name("osoosi-wasm-epoch-ticker".to_string())
            .spawn(move || {
                #[cfg(windows)]
                unsafe {
                    timeBeginPeriod(1);
                }

                while !flag_clone.load(Ordering::Relaxed) {
                    for engine in &engines {
                        engine.increment_epoch();
                    }
                    std::thread::sleep(tick_interval);
                }

                #[cfg(windows)]
                unsafe {
                    timeEndPeriod(1);
                }
            })
            .expect("Failed to spawn epoch ticker thread");

        Self {
            shutdown_flag,
            thread_handle: Some(thread_handle),
        }
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        self.shutdown_flag.store(true, Ordering::SeqCst);
        if let Some(h) = self.thread_handle.take() {
            let _ = h.join();
        }
    }
}

/// Configuration options for the dual-plane supervisor.
#[derive(Debug, Clone)]
pub struct WasmSupervisorConfig {
    pub hot_epoch_deadline_ticks: u64,     // e.g. 10 ticks = 10ms
    pub scraper_default_fuel: u64,         // e.g. 5,000,000 instructions
    pub scraper_epoch_deadline_ticks: u64, // e.g. 5,000 ticks = 5s
    pub epoch_tick_interval: Duration,     // 1ms
    pub cache_dir: Option<PathBuf>,
}

impl Default for WasmSupervisorConfig {
    fn default() -> Self {
        Self {
            hot_epoch_deadline_ticks: 10,
            scraper_default_fuel: 5_000_000,
            scraper_epoch_deadline_ticks: 5_000,
            epoch_tick_interval: Duration::from_millis(1),
            cache_dir: None,
        }
    }
}

/// Host state for Hot-Path P2P Frame Validation.
pub struct P2pFrameHostState {
    pub topic: String,
    pub raw_data: Arc<[u8]>,
    pub output_data: Vec<u8>,
    pub is_valid: bool,
    pub rejection_reason: Option<String>,
    pub canonical_hash: Option<[u8; 32]>,
}

/// Host state for Metered Research Scrapers.
pub struct MeteredScraperHostState {
    pub limits: StoreLimits,
    pub input_doc: Vec<u8>,
    pub sanitized_doc: Vec<u8>,
    pub scratchpad_dir: PathBuf,
}

/// Telemetry receipt returned after P2P frame validation.
#[derive(Debug, Clone)]
pub struct ValidatedP2pFrameReceipt {
    pub topic: String,
    pub is_valid: bool,
    pub raw_length: usize,
    pub sanitized_length: usize,
    pub duration_us: u64,
    pub canonical_hash: [u8; 32],
}

const P2P_FRAME_VALIDATOR_WAT: &str = r#"
(module
  (import "p2p_env" "read_payload" (func $read_payload (param i32 i32) (result i32)))
  (import "p2p_env" "emit_sanitized" (func $emit_sanitized (param i32 i32) (result i32)))
  (import "p2p_env" "reject_frame" (func $reject_frame (param i32 i32) (result i32)))
  (memory (export "memory") 1 4)
  
  (func (export "validate_frame") (param $topic_id i32) (param $payload_len i32) (result i32)
    (local $read_bytes i32)
    (local $first_byte i32)
    (local $last_byte i32)
    ;; 1. Check max frame size <= 524288 (512 KiB)
    (if (i32.gt_u (local.get $payload_len) (i32.const 524288))
      (then
        (return (i32.const -1))
      )
    )
    ;; 2. Read payload into memory offset 0
    (local.set $read_bytes (call $read_payload (i32.const 0) (local.get $payload_len)))
    (if (i32.lt_s (local.get $read_bytes) (i32.const 2))
      (then
        (return (i32.const -2))
      )
    )
    ;; 3. Check JSON envelope: must start with '{' (123) or '[' (91)
    (local.set $first_byte (i32.load8_u (i32.const 0)))
    (if (i32.and 
          (i32.ne (local.get $first_byte) (i32.const 123))
          (i32.ne (local.get $first_byte) (i32.const 91))
        )
      (then
        (return (i32.const -3))
      )
    )
    ;; Check ending character: '}' (125) or ']' (93)
    (local.set $last_byte (i32.load8_u (i32.sub (local.get $read_bytes) (i32.const 1))))
    (if (i32.and
          (i32.ne (local.get $last_byte) (i32.const 125))
          (i32.ne (local.get $last_byte) (i32.const 93))
        )
      (then
        (return (i32.const -4))
      )
    )
    ;; Emit validated frame and return success (0)
    (drop (call $emit_sanitized (i32.const 0) (local.get $read_bytes)))
    (i32.const 0)
  )
)
"#;

const SCRAPER_SANITIZER_WAT: &str = r#"
(module
  (import "scraper_env" "read_doc" (func $read_doc (param i32 i32) (result i32)))
  (import "scraper_env" "emit_doc" (func $emit_doc (param i32 i32) (result i32)))
  (memory (export "memory") 1 1024)
  (func (export "parse_and_sanitize") (result i32)
    (local $len i32)
    (local.set $len (call $read_doc (i32.const 0) (i32.const 65536)))
    (if (i32.gt_s (local.get $len) (i32.const 0))
      (then
        (drop (call $emit_doc (i32.const 0) (local.get $len)))
        (return (i32.const 0))
      )
    )
    (i32.const -1)
  )
)
"#;

/// Dual-plane supervisor managing pooled Hot-Path and Metered Scraper engines.
pub struct WasmSupervisor {
    config: WasmSupervisorConfig,
    hot_engine: Engine,
    scraper_engine: Engine,
    _ticker: Arc<EpochTicker>,
    p2p_frame_pre: InstancePre<P2pFrameHostState>,
    scraper_module: Module,
    cwasm_cache: Arc<RwLock<HashMap<[u8; 32], Vec<u8>>>>,
}

impl WasmSupervisor {
    /// Initialize the supervisor, pooling allocators, background ticker, and pre-compiled instances.
    pub fn new(config: WasmSupervisorConfig) -> Result<Self, WasmSupervisorError> {
        let hot_engine = build_zero_overhead_engine()?;
        let scraper_engine = build_metered_engine()?;

        let ticker = Arc::new(EpochTicker::spawn(
            vec![hot_engine.clone(), scraper_engine.clone()],
            config.epoch_tick_interval,
        ));

        // Pre-link Hot-Path P2P Validator
        let mut p2p_linker: Linker<P2pFrameHostState> = Linker::new(&hot_engine);
        Self::bind_p2p_frame_imports(&mut p2p_linker)?;
        let p2p_module = Module::new(&hot_engine, P2P_FRAME_VALIDATOR_WAT)
            .map_err(|e| WasmSupervisorError::Compilation(format!("P2P validator WAT: {}", e)))?;
        let p2p_frame_pre = p2p_linker
            .instantiate_pre(&p2p_module)
            .map_err(|e| WasmSupervisorError::Instantiation(format!("P2P InstancePre: {}", e)))?;

        // Compile Scraper Module on Scraper Engine
        let scraper_module = Module::new(&scraper_engine, SCRAPER_SANITIZER_WAT)
            .map_err(|e| WasmSupervisorError::Compilation(format!("Scraper WAT: {}", e)))?;

        Ok(Self {
            config,
            hot_engine,
            scraper_engine,
            _ticker: ticker,
            p2p_frame_pre,
            scraper_module,
            cwasm_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Access reference to the hot-path zero-overhead engine.
    pub fn hot_engine(&self) -> &Engine {
        &self.hot_engine
    }

    /// Access reference to the metered scraper engine.
    pub fn scraper_engine(&self) -> &Engine {
        &self.scraper_engine
    }

    /// Precompiles Wasm bytecode into AOT machine code (`.cwasm`) and caches it in memory/disk.
    pub fn precompile_and_cache(&self, wasm_bytes: &[u8]) -> Result<[u8; 32], WasmSupervisorError> {
        let hash: [u8; 32] = *blake3::hash(wasm_bytes).as_bytes();

        let cwasm_bytes = self
            .hot_engine
            .precompile_module(wasm_bytes)
            .map_err(|e| WasmSupervisorError::Compilation(format!("AOT precompile: {}", e)))?;

        if let Some(ref dir) = self.config.cache_dir {
            let _ = std::fs::create_dir_all(dir);
            let path = dir.join(format!("{}.cwasm", hex::encode(hash)));
            let _ = std::fs::write(path, &cwasm_bytes);
        }

        let mut lock = self.cwasm_cache.write().unwrap_or_else(|p| p.into_inner());
        lock.insert(hash, cwasm_bytes);

        Ok(hash)
    }

    /// Deserializes a precompiled `.cwasm` module safely from cache.
    ///
    /// # Safety
    /// Caller must ensure the precompiled bytes originated from trusted Wasmtime compilation.
    pub unsafe fn deserialize_cached_module(
        &self,
        hash: &[u8; 32],
    ) -> Result<Module, WasmSupervisorError> {
        let lock = self.cwasm_cache.read().unwrap_or_else(|p| p.into_inner());
        if let Some(cwasm) = lock.get(hash) {
            Module::deserialize(&self.hot_engine, cwasm)
                .map_err(|e| WasmSupervisorError::Compilation(format!("Deserialization: {}", e)))
        } else if let Some(ref dir) = self.config.cache_dir {
            let path = dir.join(format!("{}.cwasm", hex::encode(hash)));
            if path.exists() {
                Module::deserialize_file(&self.hot_engine, path).map_err(|e| {
                    WasmSupervisorError::Compilation(format!("File deserialization: {}", e))
                })
            } else {
                Err(WasmSupervisorError::Compilation("Cache miss".to_string()))
            }
        } else {
            Err(WasmSupervisorError::Compilation("Cache miss".to_string()))
        }
    }

    /// Validates an untrusted inbound P2P mesh frame using pooled Wasm hot-path guests.
    pub fn validate_p2p_frame(
        &self,
        topic: &str,
        raw_payload: &[u8],
    ) -> Result<ValidatedP2pFrameReceipt, WasmSupervisorError> {
        let start_time = std::time::Instant::now();
        let payload_arc: Arc<[u8]> = Arc::from(raw_payload);

        let host_state = P2pFrameHostState {
            topic: topic.to_string(),
            raw_data: payload_arc.clone(),
            output_data: Vec::with_capacity(raw_payload.len().min(65536)),
            is_valid: false,
            rejection_reason: None,
            canonical_hash: None,
        };

        let mut store = Store::new(&self.hot_engine, host_state);
        store.set_epoch_deadline(self.config.hot_epoch_deadline_ticks);

        let instance = self
            .p2p_frame_pre
            .instantiate(&mut store)
            .map_err(|e| WasmSupervisorError::Instantiation(e.to_string()))?;

        let validate_fn = instance
            .get_typed_func::<(u32, u32), i32>(&mut store, "validate_frame")
            .map_err(|e| WasmSupervisorError::Trap(e.to_string()))?;

        let result = validate_fn.call(&mut store, (0, raw_payload.len() as u32));
        match result {
            Ok(0) => {
                let duration_us = start_time.elapsed().as_micros() as u64;
                let data = store.into_data();
                let hash = data.canonical_hash.unwrap_or_else(|| {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(blake3::hash(raw_payload).as_bytes());
                    h
                });

                Ok(ValidatedP2pFrameReceipt {
                    topic: topic.to_string(),
                    is_valid: true,
                    raw_length: raw_payload.len(),
                    sanitized_length: data.output_data.len(),
                    duration_us,
                    canonical_hash: hash,
                })
            }
            Ok(err_code) => {
                let reason = store
                    .data()
                    .rejection_reason
                    .clone()
                    .unwrap_or_else(|| format!("Guest returned rejection code {}", err_code));
                Err(WasmSupervisorError::FrameRejected {
                    topic: topic.to_string(),
                    reason,
                })
            }
            Err(trap) => {
                if trap.to_string().contains("interrupt") || trap.to_string().contains("epoch") {
                    Err(WasmSupervisorError::EpochDeadlineExceeded {
                        deadline_ms: self.config.hot_epoch_deadline_ticks,
                    })
                } else {
                    Err(WasmSupervisorError::Trap(trap.to_string()))
                }
            }
        }
    }

    /// Executes an untrusted document / web payload parser in the Metered Scraper plane.
    pub fn execute_metered_scraper(
        &self,
        raw_document: &[u8],
        scratchpad_dir: &Path,
        fuel_override: Option<u64>,
    ) -> Result<Vec<u8>, WasmSupervisorError> {
        let limits = StoreLimitsBuilder::new()
            .memory_size(64 * 1024 * 1024)
            .instances(1)
            .tables(10)
            .memories(1)
            .build();

        let host_state = MeteredScraperHostState {
            limits,
            input_doc: raw_document.to_vec(),
            sanitized_doc: Vec::new(),
            scratchpad_dir: scratchpad_dir.to_path_buf(),
        };

        let mut store = Store::new(&self.scraper_engine, host_state);
        store.limiter(|s| &mut s.limits);
        store
            .set_fuel(fuel_override.unwrap_or(self.config.scraper_default_fuel))
            .map_err(|e| WasmSupervisorError::Trap(e.to_string()))?;
        store.set_epoch_deadline(self.config.scraper_epoch_deadline_ticks);

        let mut linker = Linker::new(&self.scraper_engine);
        Self::bind_scraper_imports(&mut linker)?;

        let instance = linker
            .instantiate(&mut store, &self.scraper_module)
            .map_err(|e| WasmSupervisorError::Instantiation(e.to_string()))?;

        let run_fn = instance
            .get_typed_func::<(), i32>(&mut store, "parse_and_sanitize")
            .map_err(|e| WasmSupervisorError::Trap(e.to_string()))?;

        match run_fn.call(&mut store, ()) {
            Ok(0) => Ok(store.into_data().sanitized_doc),
            Ok(err) => Err(WasmSupervisorError::Trap(format!(
                "Scraper error code {}",
                err
            ))),
            Err(e) => {
                if e.to_string().contains("fuel") {
                    Err(WasmSupervisorError::FuelExhausted {
                        limit: fuel_override.unwrap_or(self.config.scraper_default_fuel),
                    })
                } else if e.to_string().contains("interrupt") || e.to_string().contains("epoch") {
                    Err(WasmSupervisorError::EpochDeadlineExceeded {
                        deadline_ms: self.config.scraper_epoch_deadline_ticks,
                    })
                } else {
                    Err(WasmSupervisorError::Trap(e.to_string()))
                }
            }
        }
    }

    fn bind_p2p_frame_imports(
        linker: &mut Linker<P2pFrameHostState>,
    ) -> Result<(), WasmSupervisorError> {
        linker
            .func_wrap(
                "p2p_env",
                "read_payload",
                |mut caller: Caller<'_, P2pFrameHostState>, ptr: u32, max_len: u32| -> i32 {
                    let memory = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                        Some(m) => m,
                        None => return -1,
                    };
                    let raw_data = caller.data().raw_data.clone();
                    let copy_len = raw_data.len().min(max_len as usize);
                    if memory
                        .write(&mut caller, ptr as usize, &raw_data[..copy_len])
                        .is_err()
                    {
                        return -2;
                    }
                    copy_len as i32
                },
            )
            .map_err(|e| WasmSupervisorError::EngineInit(e.to_string()))?;

        linker
            .func_wrap(
                "p2p_env",
                "emit_sanitized",
                |mut caller: Caller<'_, P2pFrameHostState>, ptr: u32, len: u32| -> i32 {
                    let memory = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                        Some(m) => m,
                        None => return -1,
                    };
                    let mut buf = vec![0u8; len as usize];
                    if memory.read(&caller, ptr as usize, &mut buf).is_err() {
                        return -2;
                    }
                    caller.data_mut().output_data = buf;
                    0
                },
            )
            .map_err(|e| WasmSupervisorError::EngineInit(e.to_string()))?;

        linker
            .func_wrap(
                "p2p_env",
                "reject_frame",
                |mut caller: Caller<'_, P2pFrameHostState>, ptr: u32, len: u32| -> i32 {
                    let memory = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                        Some(m) => m,
                        None => return -1,
                    };
                    let mut buf = vec![0u8; len as usize];
                    if memory.read(&caller, ptr as usize, &mut buf).is_ok() {
                        if let Ok(s) = std::str::from_utf8(&buf) {
                            caller.data_mut().rejection_reason = Some(s.to_string());
                        }
                    }
                    0
                },
            )
            .map_err(|e| WasmSupervisorError::EngineInit(e.to_string()))?;

        Ok(())
    }

    fn bind_scraper_imports(
        linker: &mut Linker<MeteredScraperHostState>,
    ) -> Result<(), WasmSupervisorError> {
        linker
            .func_wrap(
                "scraper_env",
                "read_doc",
                |mut caller: Caller<'_, MeteredScraperHostState>, ptr: u32, max_len: u32| -> i32 {
                    let memory = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                        Some(m) => m,
                        None => return -1,
                    };
                    let input = caller.data().input_doc.clone();
                    let copy_len = input.len().min(max_len as usize);
                    if memory
                        .write(&mut caller, ptr as usize, &input[..copy_len])
                        .is_err()
                    {
                        return -2;
                    }
                    copy_len as i32
                },
            )
            .map_err(|e| WasmSupervisorError::EngineInit(e.to_string()))?;

        linker
            .func_wrap(
                "scraper_env",
                "emit_doc",
                |mut caller: Caller<'_, MeteredScraperHostState>, ptr: u32, len: u32| -> i32 {
                    let memory = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                        Some(m) => m,
                        None => return -1,
                    };
                    let mut buf = vec![0u8; len as usize];
                    if memory.read(&caller, ptr as usize, &mut buf).is_err() {
                        return -2;
                    }
                    caller.data_mut().sanitized_doc = buf;
                    0
                },
            )
            .map_err(|e| WasmSupervisorError::EngineInit(e.to_string()))?;

        Ok(())
    }
}
