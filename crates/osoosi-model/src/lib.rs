//! Local threat model trained on data from self and peers.
//!
//! Uses aggregated threat signatures and telemetry to train a lightweight
//! feature-weight model. Model is stored in the `models/` folder.
//!
//! Also provides a malware detection system (PE analysis + ML + signatures).

mod train;
pub mod malware;
pub mod nsrl;
pub mod malconv;

pub use train::{ThreatModel, ModelConfig};
pub use malware::{MalwareScanner, MalwareScanResult, MalwareScannerStats};
pub use malconv::{MalConv, preprocess_binary, preprocess_bytes};
