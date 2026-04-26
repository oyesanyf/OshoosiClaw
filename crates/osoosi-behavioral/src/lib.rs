//! Behavioral detection from system and application logs.
//!
//! First detection layer: streams Windows Event Log (System, Application, Security),
//! Linux journald/syslog, and macOS unified log into behavioral sentences for
//! SecureBERT-style classification. Supports continual training via labeled feedback.

mod analyzer;
mod classifier;
mod colog;
pub mod ebpf_monitor;
pub mod feedback;
pub mod forensics;
pub mod llm_engine;
mod log_reader;
mod process_tree;
mod reasoning;
mod sentence;
pub mod privacy_voter;
pub mod yara_analyzer;


pub use analyzer::{AnalysisMode, BehavioralAnalyzer, InvestigativePrompt};
pub use classifier::{BehavioralClassifier, BehavioralResult};
pub use ebpf_monitor::EbpfMonitor;
pub use feedback::{FeedbackStore, LabeledSample};
pub use forensics::{PacketForensics, TriageResult};
pub use llm_engine::{Gemma4Analyzer, SmolLMAnalyzer};
pub use log_reader::{BehavioralLogReader, LogEvent};
pub use process_tree::{ProcessRelationship, ProcessTreeEmbedder};
pub use sentence::event_to_behavioral_sentence;
pub use privacy_voter::PrivacyVoter;
pub use yara_analyzer::YaraAnalyzer;

