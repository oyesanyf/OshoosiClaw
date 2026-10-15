//! JIT Memory Mitigations and WASM Pre-flight Checks.
//!
//! Intercepts high-risk system calls and uses the WASM sandbox to
//! determine if they should be blocked or allowed.

use osoosi_sandbox::{SandboxConfig, SandboxExecutor, SandboxSecurityConfig};
use osoosi_types::TaintLabel;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{info, warn};

pub struct MitigationEngine {
    sandbox: Arc<SandboxExecutor>,
    config: SandboxConfig,
}

impl MitigationEngine {
    pub fn new(sandbox: Arc<SandboxExecutor>) -> Self {
        let config = SandboxConfig {
            max_fuel: 100_000,
            security_config: SandboxSecurityConfig::default(),
            ..Default::default()
        };
        Self { sandbox, config }
    }

    /// Perform a 'pre-flight' check on a system call.
    /// Returns true if the call is allowed, false if it should be blocked.
    pub async fn check_syscall(&self, pid: u32, syscall_name: &str, _args: &[String]) -> bool {
        info!(
            "Mitigation: Checking syscall {} for PID {}",
            syscall_name, pid
        );

        // Load the mitigation policy WASM (this would come from a signed policy file)
        let wasm_policy: &[u8] = b"\xff\xfem\x00o\x00d\x00u\x00l\x00e\x00\r\x00\n\x00";

        let mut labels = HashSet::new();
        labels.insert(TaintLabel::UntrustedScript);

        let result = self
            .sandbox
            .run_script(wasm_policy, self.config.clone(), labels)
            .await;

        match result {
            Ok(res) => {
                info!(
                    "Mitigation Result: {} - Triage: {}",
                    res.output, res.triage_level
                );
                res.triage_level != "CRITICAL"
            }
            Err(e) => {
                warn!(
                    "Mitigation Engine Error: {}. Defensive posture: Blocking syscall.",
                    e
                );
                false // Fail closed
            }
        }
    }
}
