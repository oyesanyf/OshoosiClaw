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
