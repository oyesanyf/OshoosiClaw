//! Hierarchical Concurrency Controller (`SafeAgentsConcurrencyController`)
//!
//! Enforces bounded concurrency across the 3-stage inspection pipeline and execution tiers:
//! - Gateway Semaphore: 64 permits (overall HTTP admission control; returns 429 when saturated)
//! - AtifScan Semaphore: 16 permits (CPU-bound RegexSet / AhoCorasick scanning across worker pool)
//! - OllamaJudge Semaphore: 2 permits (serializes local Ollama LLM queries, avoiding GPU/CPU OOM)
//! - WasmSandbox Semaphore: 16 permits (limits concurrent Wasmtime instances / AppContainers)

use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Debug, Error)]
pub enum ConcurrencyError {
    #[error("Admission saturated: 429 Too Many Requests")]
    GatewaySaturated,
    #[error("ATIF scan worker pool exhausted")]
    AtifScanSaturated,
    #[error("Judge inference capacity exhausted")]
    JudgeSaturated,
    #[error("Sandbox worker pool exhausted")]
    SandboxSaturated,
}

#[derive(Clone)]
pub struct SafeAgentsConcurrencyController {
    gateway_sem: Arc<Semaphore>,
    atif_scan_sem: Arc<Semaphore>,
    judge_sem: Arc<Semaphore>,
    wasm_sandbox_sem: Arc<Semaphore>,
}

impl Default for SafeAgentsConcurrencyController {
    fn default() -> Self {
        Self {
            gateway_sem: Arc::new(Semaphore::new(64)),
            atif_scan_sem: Arc::new(Semaphore::new(16)),
            judge_sem: Arc::new(Semaphore::new(2)),
            wasm_sandbox_sem: Arc::new(Semaphore::new(16)),
        }
    }
}

impl SafeAgentsConcurrencyController {
    pub fn new(gateway: usize, atif: usize, judge: usize, wasm: usize) -> Self {
        Self {
            gateway_sem: Arc::new(Semaphore::new(gateway)),
            atif_scan_sem: Arc::new(Semaphore::new(atif)),
            judge_sem: Arc::new(Semaphore::new(judge)),
            wasm_sandbox_sem: Arc::new(Semaphore::new(wasm)),
        }
    }

    /// Acquires a Gateway permit (non-blocking try_acquire). Returns 429 error if saturated.
    pub fn try_acquire_gateway(&self) -> Result<OwnedSemaphorePermit, ConcurrencyError> {
        self.gateway_sem
            .clone()
            .try_acquire_owned()
            .map_err(|_| ConcurrencyError::GatewaySaturated)
    }

    /// Acquires an ATIF Scan worker permit.
    pub async fn acquire_atif_scan(&self) -> OwnedSemaphorePermit {
        self.atif_scan_sem
            .clone()
            .acquire_owned()
            .await
            .expect("atif_scan semaphore closed")
    }

    /// Try to acquire an ATIF Scan worker permit without blocking.
    pub fn try_acquire_atif_scan(&self) -> Result<OwnedSemaphorePermit, ConcurrencyError> {
        self.atif_scan_sem
            .clone()
            .try_acquire_owned()
            .map_err(|_| ConcurrencyError::AtifScanSaturated)
    }

    /// Acquires an Isolated Judge permit (strictly serialized to 2 concurrent queries).
    pub async fn acquire_judge(&self) -> OwnedSemaphorePermit {
        self.judge_sem
            .clone()
            .acquire_owned()
            .await
            .expect("judge semaphore closed")
    }

    /// Try to acquire an Isolated Judge permit without blocking.
    pub fn try_acquire_judge(&self) -> Result<OwnedSemaphorePermit, ConcurrencyError> {
        self.judge_sem
            .clone()
            .try_acquire_owned()
            .map_err(|_| ConcurrencyError::JudgeSaturated)
    }

    /// Acquires a Wasm Sandbox permit.
    pub async fn acquire_sandbox(&self) -> OwnedSemaphorePermit {
        self.wasm_sandbox_sem
            .clone()
            .acquire_owned()
            .await
            .expect("wasm_sandbox semaphore closed")
    }

    /// Try to acquire a Wasm Sandbox permit without blocking.
    pub fn try_acquire_sandbox(&self) -> Result<OwnedSemaphorePermit, ConcurrencyError> {
        self.wasm_sandbox_sem
            .clone()
            .try_acquire_owned()
            .map_err(|_| ConcurrencyError::SandboxSaturated)
    }

    /// Returns available permits across all semaphores.
    pub fn available_permits(&self) -> (usize, usize, usize, usize) {
        (
            self.gateway_sem.available_permits(),
            self.atif_scan_sem.available_permits(),
            self.judge_sem.available_permits(),
            self.wasm_sandbox_sem.available_permits(),
        )
    }
}
