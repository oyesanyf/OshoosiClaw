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
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > self.max_memory_bytes {
            tracing::warn!(
                "WASM memory growth DENIED: requested {} bytes exceeds limit of {} bytes (current: {} bytes)",
                desired,
                self.max_memory_bytes,
                current
            );
            Ok(false)
        } else {
            self.current_bytes = desired;
            Ok(true)
        }
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= self.max_table_elements as usize)
    }

    fn instances(&self) -> usize {
        1
    }

    fn tables(&self) -> usize {
        1
    }

    fn memories(&self) -> usize {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasmtime::ResourceLimiter;

    #[test]
    fn test_memory_limiter_enforces_64mib_cap() {
        let limit_64mib = 64 * 1024 * 1024;
        let mut limiter = MemoryLimiter::new(limit_64mib);

        assert_eq!(limiter.current_bytes, 0);

        // 32 MiB growth permitted
        assert!(limiter.memory_growing(0, 32 * 1024 * 1024, None).unwrap());
        assert_eq!(limiter.current_bytes, 32 * 1024 * 1024);

        // Exactly 64 MiB permitted
        assert!(limiter
            .memory_growing(32 * 1024 * 1024, 64 * 1024 * 1024, None)
            .unwrap());
        assert_eq!(limiter.current_bytes, 64 * 1024 * 1024);

        // 65 MiB (> 64 MiB cap) DENIED
        assert!(!limiter
            .memory_growing(64 * 1024 * 1024, 65 * 1024 * 1024, None)
            .unwrap());
        // current_bytes remains at 64 MiB
        assert_eq!(limiter.current_bytes, 64 * 1024 * 1024);
    }
}
