//! # Zero-Hardcode Dynamic AI Agent Classifier & Osquery Relational Discovery
//!
//! Provides dynamic behavioral, protocol, and relational AI agent classification
//! without relying on static executable name lists:
//! 1. Protocol Provenance (LLM inference API endpoints, MCP JSON-RPC framing, model tensor mmap)
//! 2. Actuation Cadence & Pipe Topology (Inference-wait -> Non-interactive stdio tool burst)
//! 3. EmbeddingGemma 2 (128-dim MRL) Semantic Lineage Vectors
//! 4. Osquery Relational Host Discovery (`OsqueryAgentDetector` via live `osqueryi` and embedded engine)
//! 5. Adrian Runtime Boundary & Arize Phoenix (`openinference` / `gen_ai.*`) OpenTelemetry span inspection
//! 6. Elastic Pass-Through: Human processes ($P < 0.75$) bypass containment completely (Zero Disruption).

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use osoosi_behavioral::{EmbeddingGemma2Engine, MatryoshkaDim};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Dynamic signals that provide Bayesian evidence of an autonomous AI agent process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentEvidenceSignal {
    /// Outbound communication with an LLM inference REST/gRPC/SSE endpoint
    InferenceProtocolTraffic {
        endpoint_pattern: String,
        is_streaming: bool,
    },
    /// Model Context Protocol (MCP) JSON-RPC 2.0 framing on stdio or loopback socket
    McpJsonRpcFraming {
        method: String,
    },
    /// Memory-mapped weights/tensor file
    ModelTensorMemoryMapped {
        format: String,
    },
    /// OpenTelemetry GenAI or OpenInference semantic convention span attributes
    OpenTelemetryGenAiSpan {
        attribute_key: String,
    },
    /// Autonomous pipe-driven child process spawn burst following network inference wait
    PipeDrivenToolBurst {
        child_count_10s: usize,
        non_interactive_stdio: bool,
        post_network_wait_ms: u64,
    },
    /// High-velocity child spawn burst (e.g. > 5 children in 3 seconds from ETW)
    ChildSpawnVelocityBurst {
        count_3s: usize,
    },
    /// EmbeddingGemma 2 cosine similarity to canonical agent tool loop manifolds
    SemanticLineageSimilarity {
        cosine_score: f32,
    },
    /// Interactive human console (e.g. ConPTY keyboard input with human stroke variance)
    InteractiveHumanConsole {
        has_conpty_keyboard_input: bool,
    },
    /// Adrian tool-call boundary intent or Arize Phoenix reasoning path drift
    AdrianRuntimeBoundary {
        boundary_event: String,
        is_tool_call: bool,
    },
}

impl AgentEvidenceSignal {
    /// Returns the Bayesian log-odds update for this evidence signal.
    pub fn log_odds_delta(&self) -> f64 {
        match self {
            Self::InferenceProtocolTraffic { .. } => 2.4,
            Self::McpJsonRpcFraming { .. } => 2.8,
            Self::ModelTensorMemoryMapped { .. } => 2.2,
            Self::OpenTelemetryGenAiSpan { .. } => 2.6,
            Self::PipeDrivenToolBurst { child_count_10s, non_interactive_stdio, .. } => {
                if *non_interactive_stdio && *child_count_10s >= 2 {
                    1.6
                } else {
                    0.5
                }
            }
            Self::ChildSpawnVelocityBurst { count_3s } => {
                if *count_3s > 5 {
                    1.5
                } else {
                    0.2
                }
            }
            Self::SemanticLineageSimilarity { cosine_score } => {
                if *cosine_score >= 0.78 {
                    1.4
                } else if *cosine_score >= 0.55 {
                    0.4
                } else {
                    -0.5
                }
            }
            Self::AdrianRuntimeBoundary { is_tool_call, .. } => {
                if *is_tool_call {
                    2.0
                } else {
                    1.0
                }
            }
            Self::InteractiveHumanConsole { has_conpty_keyboard_input } => {
                if *has_conpty_keyboard_input {
                    // Strong negative evidence: interactive human terminal!
                    -3.0
                } else {
                    0.0
                }
            }
        }
    }

    /// Descriptive summary tag for audit logging.
    pub fn description(&self) -> String {
        match self {
            Self::InferenceProtocolTraffic { endpoint_pattern, .. } => {
                format!("InferenceProtocol({})", endpoint_pattern)
            }
            Self::McpJsonRpcFraming { method } => format!("McpFraming({})", method),
            Self::ModelTensorMemoryMapped { format } => format!("TensorMap({})", format),
            Self::OpenTelemetryGenAiSpan { attribute_key } => format!("OTelGenAI({})", attribute_key),
            Self::PipeDrivenToolBurst { child_count_10s, .. } => {
                format!("PipeBurst(children={})", child_count_10s)
            }
            Self::ChildSpawnVelocityBurst { count_3s } => {
                format!("VelocityBurst(3s={})", count_3s)
            }
            Self::SemanticLineageSimilarity { cosine_score } => {
                format!("EmbeddingGemma2(cos={:.2})", cosine_score)
            }
            Self::AdrianRuntimeBoundary { boundary_event, .. } => {
                format!("AdrianBoundary({})", boundary_event)
            }
            Self::InteractiveHumanConsole { .. } => "HumanConsole(ConPTY)".to_string(),
        }
    }
}

/// Dynamic classification and state record for a monitored subject (PID or session ID).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentClassificationRecord {
    pub subject_id: String,
    pub parent_id: Option<String>,
    pub log_odds: f64,
    pub posterior_probability: f32,
    pub is_verified_agent: bool,
    pub inferred_workspace_root: Option<String>,
    pub observed_signals: Vec<String>,
    pub generation_epoch: u64,
    pub last_updated: DateTime<Utc>,
}

/// 100% Native Rust In-Process Relational Host Discovery Engine.
pub use crate::siquery::SiqueryEngine;
pub type OsqueryAgentDetector = SiqueryEngine;
pub type SiqueryAgentDetector = SiqueryEngine;

/// Dynamic Bayesian Classifier discovering AI agents without hardcoded executable names.
pub struct DynamicAgentClassifier {
    pub records: DashMap<String, AgentClassificationRecord>,
    embedding_engine: Arc<EmbeddingGemma2Engine>,
    pub osquery_detector: Arc<OsqueryAgentDetector>,
    verification_threshold: f32,
}

impl Default for DynamicAgentClassifier {
    fn default() -> Self {
        Self::new()
    }
}

impl DynamicAgentClassifier {
    pub fn new() -> Self {
        Self {
            records: DashMap::new(),
            embedding_engine: Arc::new(EmbeddingGemma2Engine::new(MatryoshkaDim::Dim128)),
            osquery_detector: Arc::new(OsqueryAgentDetector::new()),
            verification_threshold: 0.75,
        }
    }

    /// Records Bayesian evidence for a subject (PID or session ID).
    /// If `parent_id` is already a verified AI agent, the child inherits parent's context and baseline probability!
    pub fn record_signal(
        &self,
        subject_id: &str,
        parent_id: Option<&str>,
        workspace_hint: Option<&str>,
        signal: AgentEvidenceSignal,
    ) -> AgentClassificationRecord {
        let now = Utc::now();

        let mut record = self
            .records
            .entry(subject_id.to_string())
            .or_insert_with(|| {
                // Initial prior log-odds = -1.5 (corresponding to P ≈ 0.18 for an unknown process)
                let mut initial_log_odds = -1.5;
                let mut inherited_ws = workspace_hint.map(|s| s.to_string());
                let mut initial_epoch = 1;

                // Process tree lineage inheritance:
                if let Some(pid_str) = parent_id {
                    if let Some(parent_rec) = self.records.get(pid_str) {
                        if parent_rec.is_verified_agent {
                            // Inherit 90% of parent's verified log-odds and inferred workspace
                            initial_log_odds = parent_rec.log_odds * 0.9;
                            if inherited_ws.is_none() {
                                inherited_ws = parent_rec.inferred_workspace_root.clone();
                            }
                            initial_epoch = parent_rec.generation_epoch;
                        }
                    }
                }

                let p = (1.0 / (1.0 + (-initial_log_odds).exp())) as f32;
                AgentClassificationRecord {
                    subject_id: subject_id.to_string(),
                    parent_id: parent_id.map(|s| s.to_string()),
                    log_odds: initial_log_odds,
                    posterior_probability: p,
                    is_verified_agent: p >= self.verification_threshold,
                    inferred_workspace_root: inherited_ws,
                    observed_signals: Vec::new(),
                    generation_epoch: initial_epoch,
                    last_updated: now,
                }
            });

        // Update workspace if hint provided
        if record.inferred_workspace_root.is_none() && workspace_hint.is_some() {
            record.inferred_workspace_root = workspace_hint.map(|s| s.to_string());
        }

        // Apply Bayesian log-odds update
        let delta = signal.log_odds_delta();
        record.log_odds = (record.log_odds + delta).clamp(-6.0, 8.0);
        let post = (1.0 / (1.0 + (-record.log_odds).exp())) as f32;
        record.posterior_probability = post;
        record.is_verified_agent = post >= self.verification_threshold;
        record.observed_signals.push(signal.description());
        record.last_updated = now;

        record.clone()
    }

    /// Inspects an arbitrary command line, URL, or JSON-RPC context for structural AI agent indicators.
    /// Does NOT hardcode binary names!
    pub fn inspect_command_and_context(
        &self,
        subject_id: &str,
        parent_id: Option<&str>,
        cmd_or_payload: &str,
        workspace_hint: Option<&str>,
    ) -> AgentClassificationRecord {
        let lower = cmd_or_payload.to_ascii_lowercase();

        // 1. LLM API Endpoint Provenance
        if lower.contains("/v1/chat/completions")
            || lower.contains("/v1/messages")
            || lower.contains(":generatecontent")
            || lower.contains("/api/chat")
            || lower.contains("/api/generate")
            || lower.contains("/v1/embeddings")
        {
            let is_streaming = lower.contains("stream=true") || lower.contains("text/event-stream");
            self.record_signal(
                subject_id,
                parent_id,
                workspace_hint,
                AgentEvidenceSignal::InferenceProtocolTraffic {
                    endpoint_pattern: "llm_inference_api".to_string(),
                    is_streaming,
                },
            );
        }

        // 2. Model Context Protocol (MCP) JSON-RPC framing
        if lower.contains("tools/call")
            || lower.contains("tools/list")
            || lower.contains("resources/read")
            || lower.contains("prompts/get")
            || (lower.contains("jsonrpc") && lower.contains("method"))
            || lower.contains("mcpservers")
            || lower.contains("--mcp")
        {
            self.record_signal(
                subject_id,
                parent_id,
                workspace_hint,
                AgentEvidenceSignal::McpJsonRpcFraming {
                    method: "mcp_json_rpc".to_string(),
                },
            );
        }

        // 3. Model Tensor Memory Mappings
        if lower.contains(".gguf") || lower.contains(".safetensors") || lower.contains(".onnx") {
            let format = if lower.contains(".gguf") {
                "gguf"
            } else if lower.contains(".safetensors") {
                "safetensors"
            } else {
                "onnx"
            };
            self.record_signal(
                subject_id,
                parent_id,
                workspace_hint,
                AgentEvidenceSignal::ModelTensorMemoryMapped {
                    format: format.to_string(),
                },
            );
        }

        // 4. OpenTelemetry GenAI / OpenInference Spans & Adrian Runtime Boundaries
        if lower.contains("gen_ai.")
            || lower.contains("openinference.")
            || lower.contains("llm.input_messages")
            || lower.contains("adrian_tool_intent")
        {
            self.record_signal(
                subject_id,
                parent_id,
                workspace_hint,
                AgentEvidenceSignal::OpenTelemetryGenAiSpan {
                    attribute_key: "gen_ai_trace".to_string(),
                },
            );
        }

        // 5. Semantic Lineage Similarity via EmbeddingGemma 2 (128-dim MRL)
        let vec_input = self.embedding_engine.embed_text(cmd_or_payload);
        let ref_prompt_inj = self.embedding_engine.embed_text("tool_call: send_message (content: agentic tool call loop)");
        let cos = EmbeddingGemma2Engine::cosine_similarity(&vec_input, &ref_prompt_inj);
        if cos >= 0.78 {
            self.record_signal(
                subject_id,
                parent_id,
                workspace_hint,
                AgentEvidenceSignal::SemanticLineageSimilarity { cosine_score: cos },
            );
        }

        // Ensure record exists even if no signals fired (prior P < 0.20)
        self.records
            .entry(subject_id.to_string())
            .or_insert_with(|| {
                AgentClassificationRecord {
                    subject_id: subject_id.to_string(),
                    parent_id: parent_id.map(|s| s.to_string()),
                    log_odds: -1.5,
                    posterior_probability: 0.18,
                    is_verified_agent: false,
                    inferred_workspace_root: workspace_hint.map(|s| s.to_string()),
                    observed_signals: Vec::new(),
                    generation_epoch: 1,
                    last_updated: Utc::now(),
                }
            })
            .clone()
    }

    /// Classifies structured tool call telemetry.
    /// Structured tool calls from agents immediately record MCP + OpenTelemetry signals.
    pub fn classify_telemetry(&self, telemetry: &crate::types::ToolCallTelemetry) -> AgentClassificationRecord {
        let subject_id = &telemetry.session_id;

        self.record_signal(
            subject_id,
            Some(&telemetry.agent_id),
            None,
            AgentEvidenceSignal::McpJsonRpcFraming {
                method: telemetry.tool_name.clone(),
            },
        );

        self.record_signal(
            subject_id,
            Some(&telemetry.agent_id),
            None,
            AgentEvidenceSignal::OpenTelemetryGenAiSpan {
                attribute_key: "gen_ai.agent.tool_call".to_string(),
            },
        )
    }

    /// Runs a continuous Siquery/Osquery relational query and updates discovered agent processes.
    pub fn run_osquery_host_scan(&self) -> Vec<AgentClassificationRecord> {
        let sql = "SELECT p.pid, p.name, p.path, p.cmdline, p.parent FROM processes p JOIN process_open_sockets s ON p.pid = s.pid WHERE s.remote_port IN (11434, 1234, 8000, 8080, 5000) OR (s.remote_port = 443 AND (p.cmdline LIKE '%mcp%' OR p.cmdline LIKE '%jsonrpc%'));";
        let mut discovered = Vec::new();

        if let Ok(rows) = self.osquery_detector.execute_query(sql) {
            for row in rows {
                let pid_str = row
                    .get("pid")
                    .and_then(|v| v.as_str().map(|s| s.to_string()).or_else(|| v.as_i64().map(|n| n.to_string())))
                    .unwrap_or_default();
                let cmdline = row.get("cmdline").and_then(|v| v.as_str()).unwrap_or("");
                let parent_str = row
                    .get("parent")
                    .and_then(|v| v.as_str().map(|s| s.to_string()).or_else(|| v.as_i64().map(|n| n.to_string())));

                if !pid_str.is_empty() {
                    let rec = self.inspect_command_and_context(&pid_str, parent_str.as_deref(), cmdline, None);
                    discovered.push(rec);
                }
            }
        }

        discovered
    }

    /// Alias for `run_osquery_host_scan` using the native Rust in-process `siquery` engine.
    pub fn run_siquery_host_scan(&self) -> Vec<AgentClassificationRecord> {
        self.run_osquery_host_scan()
    }

    pub fn get_record(&self, subject_id: &str) -> Option<AgentClassificationRecord> {
        self.records.get(subject_id).map(|r| r.clone())
    }

    pub fn list_verified_agents(&self) -> Vec<AgentClassificationRecord> {
        self.records
            .iter()
            .filter(|r| r.is_verified_agent)
            .map(|r| r.clone())
            .collect()
    }

    pub fn advance_epoch(&self, subject_id: &str) -> u64 {
        if let Some(mut rec) = self.records.get_mut(subject_id) {
            rec.generation_epoch += 1;
            rec.generation_epoch
        } else {
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_human_developer_command_receives_passthrough() {
        let classifier = DynamicAgentClassifier::new();

        // Normal developer command: `cargo build` in an interactive console
        let dev_pid = "pid_4120";
        classifier.record_signal(
            dev_pid,
            None,
            Some("D:\\harfile\\OshoosiClaw"),
            AgentEvidenceSignal::InteractiveHumanConsole {
                has_conpty_keyboard_input: true,
            },
        );

        let rec = classifier.get_record(dev_pid).unwrap();
        // Posterior probability must be low (< 0.20), not verified as AI agent!
        assert!(rec.posterior_probability < 0.20, "Human console must score low probability, got {}", rec.posterior_probability);
        assert!(!rec.is_verified_agent);
    }

    #[test]
    fn test_arbitrary_binary_name_discovered_via_protocol_provenance() {
        let classifier = DynamicAgentClassifier::new();

        // Arbitrarily named custom binary: `C:\CustomAi\autonomous_worker_xyz.exe`
        let agent_pid = "pid_9844";
        let payload = r#"C:\CustomAi\autonomous_worker_xyz.exe --mcp --endpoint https://api.openai.com/v1/chat/completions --model mistral.gguf"#;

        let rec = classifier.inspect_command_and_context(agent_pid, None, payload, Some("C:\\CustomAi"));
        // Multiple protocol signals (LLM API + MCP + .gguf) must drive probability >= 0.75!
        assert!(rec.posterior_probability >= 0.75, "Custom binary with inference/MCP signals must be verified, got {}", rec.posterior_probability);
        assert!(rec.is_verified_agent);
        assert_eq!(rec.inferred_workspace_root.as_deref(), Some("C:\\CustomAi"));
    }

    #[test]
    fn test_lineage_inheritance() {
        let classifier = DynamicAgentClassifier::new();
        let parent_pid = "parent_ai_88";
        let child_pid = "child_tool_89";

        // Step 1: Parent process is verified as an AI agent via MCP framing
        classifier.record_signal(
            parent_pid,
            None,
            Some("C:\\AgentWorkspace"),
            AgentEvidenceSignal::McpJsonRpcFraming { method: "tools/call".to_string() },
        );
        classifier.record_signal(
            parent_pid,
            None,
            None,
            AgentEvidenceSignal::InferenceProtocolTraffic {
                endpoint_pattern: "/v1/chat/completions".to_string(),
                is_streaming: true,
            },
        );

        let parent_rec = classifier.get_record(parent_pid).unwrap();
        assert!(parent_rec.is_verified_agent);

        // Step 2: Child tool process spawned by verified parent
        // Automatically inherits parent's verified status and workspace!
        let child_rec = classifier.record_signal(
            child_pid,
            Some(parent_pid),
            None,
            AgentEvidenceSignal::PipeDrivenToolBurst {
                child_count_10s: 3,
                non_interactive_stdio: true,
                post_network_wait_ms: 150,
            },
        );

        assert!(child_rec.is_verified_agent);
        assert_eq!(child_rec.inferred_workspace_root.as_deref(), Some("C:\\AgentWorkspace"));
    }

    #[test]
    fn test_osquery_relational_scan_execution() {
        let detector = OsqueryAgentDetector::new();
        // Should execute cleanly using either osqueryi or embedded engine
        let res = detector.execute_query("SELECT count(*) as count FROM processes;");
        assert!(res.is_ok(), "Osquery query execution must succeed: {:?}", res.err());
    }

    #[test]
    fn test_adrian_and_opentelemetry_signal_scoring() {
        let classifier = DynamicAgentClassifier::new();
        let subject_id = "adrian_test_proc";

        classifier.record_signal(
            subject_id,
            None,
            None,
            AgentEvidenceSignal::AdrianRuntimeBoundary {
                boundary_event: "adrian_tool_call_enter".to_string(),
                is_tool_call: true,
            },
        );
        classifier.record_signal(
            subject_id,
            None,
            None,
            AgentEvidenceSignal::OpenTelemetryGenAiSpan {
                attribute_key: "openinference.span.kind".to_string(),
            },
        );

        let rec = classifier.get_record(subject_id).unwrap();
        assert!(rec.posterior_probability >= 0.75);
        assert!(rec.is_verified_agent);
    }
}
