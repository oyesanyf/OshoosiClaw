//! Error types for Osoosi.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum OsoosiError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Policy evaluation failed: {0}")]
    Policy(String),

    #[error("Telemetry error: {0}")]
    Telemetry(String),

    #[error("Audit error: {0}")]
    Audit(String),

    #[error("Runtime error: {0}")]
    Runtime(String),

    #[error("Wire error: {0}")]
    Wire(String),

    #[error("Exporter error: {0}")]
    Exporter(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

pub type OsoosiResult<T> = Result<T, OsoosiError>;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OctopusSecurityError {
    #[error("Breakout attempt detected: {0}")]
    BreakoutDetected(String),

    #[error("Input payload violated strict enclave boundaries: {0}")]
    EnclaveViolation(String),

    #[error("Limb execution deadline exceeded (timeout)")]
    ExecutionTimeout,

    #[error("Arm communication channel severed")]
    ChannelSevered,

    #[error("Limb terminated by supervisory autotomy circuit breaker")]
    LimbKilled,

    #[error("High entropy payload anomaly detected: {entropy:.2} bits/byte exceeds threshold")]
    HighEntropyDetected { entropy: u32 },

    #[error("Prohibited outbound target (SSRF/Pivot blocked): {0}")]
    SsrfBlocked(String),

    #[error("Cryptographic Merkle tamper detected: {0}")]
    MerkleTamperDetected(String),

    #[error("Deterministic layer violation: {0}")]
    DeterministicLayerViolation(String),

    #[error("Illegal FSM state transition: cannot transition from '{from}' to '{to}'")]
    IllegalStateTransition { from: String, to: String },

    #[error("Zero-trust capability authorization failure: {0}")]
    CapabilityDenied(String),

    #[error("Delegation authority violation: delegation chain exceeds permitted scope: {0}")]
    DelegationScopeViolation(String),

    #[error("Cryptographic agent identity spoofing detected: {0}")]
    IdentitySpoofingDetected(String),

    #[error("Operating system / process sandbox confinement violation: {0}")]
    IsolationViolation(String),

    #[error("Resource quota exceeded or exhaustion attempt blocked: {0}")]
    ResourceQuotaExceeded(String),
}
