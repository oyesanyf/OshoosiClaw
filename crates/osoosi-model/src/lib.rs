//! Local threat model trained on data from self and peers.
//!
//! Uses aggregated threat signatures and telemetry to train a lightweight
//! feature-weight model. Model is stored in the `models/` folder.
//!
//! Also provides a malware detection system (PE analysis + ML + signatures).

pub mod malconv;
pub mod malconv_train;
pub mod malware;
pub mod nsrl;
pub mod sorel_ffnn;
pub mod sorel_train;
mod train;

pub use malconv::{preprocess_binary, preprocess_bytes, MalConv};
pub use malware::{MalwareScanResult, MalwareScanner, MalwareScannerStats};
pub use sorel_ffnn::SorelFFNN;
pub use train::{ModelConfig, ThreatModel};
