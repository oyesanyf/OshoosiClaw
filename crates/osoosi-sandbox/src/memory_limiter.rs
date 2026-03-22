//! Resource Limiter for WASM Memory.
//!
//! Implements Wasmtime's ResourceLimiter trait to enforce hard memory caps
//! on WASM modules. This is the "Memory Meter" half of the dual-metering system.

/// Memory limits for a WASM instance.
pub struct MemoryLimiter {
    /// Maximum total bytes of WASM linear memory.
    pub max_memory_bytes: usize,
    /// Current allocated bytes.
    pub current_bytes: usize,
    /// Maximum number of table elements.
    pub max_table_elements: u32,
}

impl MemoryLimiter {
    pub fn new(max_memory_bytes: usize) -> Self {
        Self {
            max_memory_bytes,
            current_bytes: 0,
            max_table_elements: 10_000,
        }
    }
}

impl wasmtime::ResourceLimiter for MemoryLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        self.current_bytes = desired;
        if desired > self.max_memory_bytes {
            tracing::warn!(
                "WASM memory growth DENIED: requested {} bytes, limit is {} bytes",
                desired,
                self.max_memory_bytes
            );
            Ok(false)
        } else {
            Ok(true)
        }
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        Ok(desired <= self.max_table_elements as usize)
    }
}
