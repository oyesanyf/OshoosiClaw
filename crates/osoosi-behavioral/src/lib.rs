//! Behavioral detection from system and application logs.
//!
//! First detection layer: streams Windows Event Log (System, Application, Security),
//! Linux journald/syslog, and macOS unified log into behavioral sentences for
//! SecureBERT-style classification. Supports continual training via labeled feedback.

mod log_reader;
mod sentence;
mod classifier;
pub mod feedback;
mod colog;
mod reasoning;
mod analyzer;
mod gemma;
mod process_tree;
pub mod forensics;

pub use log_reader::{BehavioralLogReader, LogEvent};
pub use sentence::event_to_behavioral_sentence;
pub use classifier::{BehavioralClassifier, BehavioralResult};
pub use feedback::{FeedbackStore, LabeledSample};
pub use analyzer::{BehavioralAnalyzer, AnalysisMode, InvestigativePrompt};
pub use process_tree::{ProcessTreeEmbedder, ProcessRelationship};
pub use forensics::{PacketForensics, TriageResult};
