//! # Crate 3: Solid-State Side-Channel & Anti-Tamper (`silicon-shield`)
//!
//! Protects the EDR sensor and agent containment ring against user-mode inline hook patching
//! (`NtTraceEvent` / eBPF ring buffer tampering) and timing/power side-channel leakage using
//! `SeqCst` hardware memory fences, `subtle::ConstantTimeEq` BLAKE3 code-slice verification,
//! and volatile `constant_time_scrub` secret zeroization.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{compiler_fence, fence, Ordering};
use subtle::{Choice, ConstantTimeEq};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiliconIntegrityGuard {
    expected_text_hash: [u8; 32],
    expected_node_token: [u8; 32],
}

impl SiliconIntegrityGuard {
    /// Initializes the guard by hashing the in-memory executable `.text` segment of the EDR sensor
    /// and storing the cryptographic node capability token.
    pub fn initialize(executable_code_slice: &[u8], node_token: [u8; 32]) -> Self {
        compiler_fence(Ordering::SeqCst);
        let digest = blake3::hash(executable_code_slice);
        fence(Ordering::SeqCst);

        Self {
            expected_text_hash: *digest.as_bytes(),
            expected_node_token: node_token,
        }
    }

    /// Performs a branchless, constant-time attestation of both the runtime memory image
    /// (defeating inline hook patching like `ret` injection) and the agent's capability token.
    #[inline(never)]
    pub fn attest_runtime_state(
        &self,
        live_executable_slice: &[u8],
        presented_token: &[u8; 32],
    ) -> bool {
        // Prevent speculative execution reordering across the integrity boundary
        compiler_fence(Ordering::SeqCst);
        fence(Ordering::SeqCst);

        let live_digest = blake3::hash(live_executable_slice);
        let live_bytes = live_digest.as_bytes();

        // Constant-time bitwise comparison: execution time is strictly independent of where bytes differ
        let memory_intact: Choice = self.expected_text_hash.ct_eq(live_bytes);
        let token_valid: Choice = self.expected_node_token.ct_eq(presented_token);

        let combined_valid: Choice = memory_intact & token_valid;

        fence(Ordering::SeqCst);
        compiler_fence(Ordering::SeqCst);

        combined_valid.unwrap_u8() == 1
    }

    /// Constant-time memory scrubbing to zeroize sensitive agent keys if a breakout is detected,
    /// ensuring the compiler does not optimize away the dead store.
    pub fn constant_time_scrub(secret_buffer: &mut [u8]) {
        compiler_fence(Ordering::SeqCst);
        for byte in secret_buffer.iter_mut() {
            unsafe {
                std::ptr::write_volatile(byte, 0x00);
            }
        }
        fence(Ordering::SeqCst);
        compiler_fence(Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_attestation_and_scrub() {
        let code_slice = b"\x48\x89\x5c\x24\x08\x57\x48\x83\xec\x20";
        let token = [0xAAu8; 32];
        let guard = SiliconIntegrityGuard::initialize(code_slice, token);

        assert!(guard.attest_runtime_state(code_slice, &token));

        // Simulate inline `ret` (0xC3) hook patch at entry point
        let patched_code = b"\xc3\x89\x5c\x24\x08\x57\x48\x83\xec\x20";
        assert!(!guard.attest_runtime_state(patched_code, &token));

        let mut secret = [0x42u8; 32];
        SiliconIntegrityGuard::constant_time_scrub(&mut secret);
        assert_eq!(secret, [0u8; 32]);
    }
}
