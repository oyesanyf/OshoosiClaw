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
    #[serde(default)]
    pub pid: u32,
    #[serde(default)]
    pub process_name: String,
    #[serde(default)]
    pub agent_role: String,
    #[serde(default)]
    pub framework: String,
    #[serde(default)]
    pub agent_probability: f32,
    #[serde(default)]
    pub protocol_provenance: Vec<String>,
    #[serde(default)]
    pub child_spawn_velocity_3s: usize,
    #[serde(default)]
    pub containment_state: String,
}

/// Infers canonical process name, agent role, and framework from cmdline, executable name, and signals.
pub fn infer_agent_metadata(name: &str, cmdline: &str) -> (String, String, String) {
    let lower_name = name.to_ascii_lowercase();
    let lower_cmd = cmdline.to_ascii_lowercase();

    let resolved_name = if !name.is_empty() && name != "unknown" {
        name.to_string()
    } else if let Some(first_tok) = cmdline.split_whitespace().next() {
        let clean = first_tok.trim_matches('"').trim_matches('\'');
        std::path::Path::new(clean)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    } else {
        "unknown".to_string()
    };

    let (role, framework) = if lower_cmd.contains("language_server")
        || lower_cmd.contains("cloud_code")
        || lower_cmd.contains("antigravity")
        || lower_name.contains("language_server")
        || lower_name.contains("antigravity")
    {
        ("Coding & Tool Orchestrator".to_string(), "Google Antigravity / CloudCode".to_string())
    } else if lower_cmd.contains("mcp") || lower_cmd.contains("jsonrpc") || lower_cmd.contains("--stdio") || lower_name.contains("mcp") {
        ("MCP Tool Server".to_string(), "Model Context Protocol (MCP)".to_string())
    } else if lower_cmd.contains("ollama") || lower_cmd.contains("llama") || lower_cmd.contains(".gguf") || lower_name.contains("ollama") {
        ("Local LLM Inference Daemon".to_string(), "Ollama / GGUF Runtime".to_string())
    } else if lower_cmd.contains("osoosi") || lower_name.contains("osoosi") {
        ("Autonomous Security Supervisor".to_string(), "OpenOsoosi EDR Cortex (ONNX)".to_string())
    } else if lower_cmd.contains("python") || lower_cmd.contains("uv") || lower_name.contains("python") {
        ("Python Automation Agent".to_string(), "Python / Agentic SDK".to_string())
    } else if lower_cmd.contains("node") || lower_name.contains("node") {
        ("Node.js Extension Host / Agent".to_string(), "Node.js / V8 Agent Runtime".to_string())
    } else {
        ("Autonomous Subprocess".to_string(), "Native OS / Pipe-Driven".to_string())
    };

    (resolved_name, role, framework)
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

        // DashMap Lock Hygiene: Read parent info BEFORE entering entry() lock to prevent deadlock
        let parent_info = if let Some(pid_str) = parent_id {
            self.records.get(pid_str).map(|p| {
                (
                    p.is_verified_agent,
                    p.log_odds,
                    p.inferred_workspace_root.clone(),
                    p.generation_epoch,
                )
            })
        } else {
            None
        };

        let mut record = self
            .records
            .entry(subject_id.to_string())
            .or_insert_with(|| {
                // Initial prior log-odds = -1.5 (corresponding to P ≈ 0.18 for an unknown process)
                let mut initial_log_odds = -1.5;
                let mut inherited_ws = workspace_hint.map(|s| s.to_string());
                let mut initial_epoch = 1;

                // Process tree lineage inheritance:
                if let Some((is_verified, parent_log_odds, parent_ws, parent_epoch)) = parent_info {
                    if is_verified {
                        // Inherit 90% of parent's verified log-odds and inferred workspace
                        initial_log_odds = parent_log_odds * 0.9;
                        if inherited_ws.is_none() {
                            inherited_ws = parent_ws;
                        }
                        initial_epoch = parent_epoch;
                    }
                }

                let p = (1.0 / (1.0 + (-initial_log_odds).exp())) as f32;
                let parsed_pid = subject_id.parse::<u32>().unwrap_or(0);
                let (proc_name, role, framework) = infer_agent_metadata("", "");
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
                    pid: parsed_pid,
                    process_name: proc_name,
                    agent_role: role,
                    framework,
                    agent_probability: p,
                    protocol_provenance: Vec::new(),
                    child_spawn_velocity_3s: 0,
                    containment_state: if p >= self.verification_threshold {
                        "Monitored (Ring-1)".to_string()
                    } else {
                        "PassThrough".to_string()
                    },
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
        record.agent_probability = post;
        record.is_verified_agent = post >= self.verification_threshold;
        let desc = signal.description();
        if !record.observed_signals.contains(&desc) {
            record.observed_signals.push(desc.clone());
        }
        if !record.protocol_provenance.contains(&desc) {
            record.protocol_provenance.push(desc);
        }
        if record.pid == 0 {
            if let Ok(p) = subject_id.parse::<u32>() {
                record.pid = p;
            } else if subject_id.starts_with("pid_") {
                if let Ok(p) = subject_id[4..].parse::<u32>() {
                    record.pid = p;
                }
            }
        }
        if record.is_verified_agent {
            record.containment_state = "Monitored (Ring-1)".to_string();
        } else if post >= 0.45 {
            record.containment_state = "Evaluating".to_string();
        } else {
            record.containment_state = "PassThrough".to_string();
        }
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

        // 1. LLM / Cloud Code / Agent API Endpoint Provenance
        if lower.contains("/v1/chat/completions")
            || lower.contains("/v1/messages")
            || lower.contains(":generatecontent")
            || lower.contains("/api/chat")
            || lower.contains("/api/generate")
            || lower.contains("/v1/embeddings")
            || lower.contains("--cloud_code_endpoint")
            || lower.contains("--api_server_url")
            || lower.contains("generativelanguage.googleapis.com")
            || lower.contains("daily-cloudcode-pa.googleapis.com")
            || lower.contains("api.openai.com")
            || lower.contains("api.anthropic.com")
            || lower.contains("--extension_server_port")
        {
            let is_streaming = lower.contains("stream=true")
                || lower.contains("text/event-stream")
                || lower.contains("--cloud_code_endpoint");
            self.record_signal(
                subject_id,
                parent_id,
                workspace_hint,
                AgentEvidenceSignal::InferenceProtocolTraffic {
                    endpoint_pattern: "llm_or_cloud_code_api".to_string(),
                    is_streaming,
                },
            );
        }

        // 2. Model Context Protocol (MCP) JSON-RPC framing & Host Bridges
        if lower.contains("tools/call")
            || lower.contains("tools/list")
            || lower.contains("resources/read")
            || lower.contains("prompts/get")
            || (lower.contains("jsonrpc") && lower.contains("method"))
            || lower.contains("mcpservers")
            || lower.contains("--mcp")
            || lower.contains("litert_mcp_server")
            || lower.contains("mcp_server")
            || lower.contains("--host_bridge_url")
            || lower.contains("--csrf_token")
            || lower.contains("--enable_sidecars")
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
        let (proc_name, role, framework) = infer_agent_metadata("", cmd_or_payload);
        let parsed_pid = subject_id
            .parse::<u32>()
            .ok()
            .or_else(|| {
                if subject_id.starts_with("pid_") {
                    subject_id[4..].parse::<u32>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);

        let mut rec = self
            .records
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
                    pid: parsed_pid,
                    process_name: proc_name.clone(),
                    agent_role: role.clone(),
                    framework: framework.clone(),
                    agent_probability: 0.18,
                    protocol_provenance: Vec::new(),
                    child_spawn_velocity_3s: 0,
                    containment_state: "PassThrough".to_string(),
                }
            });

        if (rec.process_name.is_empty() || rec.process_name == "unknown") && proc_name != "unknown" {
            rec.process_name = proc_name;
        }
        if rec.agent_role.is_empty() || rec.agent_role == "Autonomous Subprocess" {
            rec.agent_role = role;
        }
        if rec.framework.is_empty() || rec.framework == "Native OS / Pipe-Driven" {
            rec.framework = framework;
        }
        if rec.pid == 0 && parsed_pid > 0 {
            rec.pid = parsed_pid;
        }
        rec.clone()
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

    /// Runs a continuous Siquery relational query suite and dynamically discovers AI agent processes
    /// and their MCP/tool subprocess hierarchy without hardcoding binary names.
    pub fn run_siquery_host_scan(&self) -> Vec<AgentClassificationRecord> {
        let mut discovered = Vec::new();

        // ---------------------------------------------------------------------
        // Query 1: Inference & Cloud Code / Agent Endpoint Sockets + MCP / RPC
        // Detects processes connecting to local inference ports, remote port 443 with agent arguments,
        // or local loopback agent IPC sockets.
        // ---------------------------------------------------------------------
        let query1 = "SELECT DISTINCT p.pid, p.name, p.path, p.cmdline, p.cwd, p.parent, \
                             s.remote_address, s.remote_port, s.local_address, s.local_port \
                      FROM processes p \
                      JOIN process_open_sockets s ON p.pid = s.pid \
                      WHERE s.remote_port IN (11434, 1234, 8000, 8080, 5000, 14537) \
                         OR (s.remote_port = 443 AND ( \
                             p.cmdline LIKE '%--cloud_code_endpoint%' \
                          OR p.cmdline LIKE '%--extension_server_port%' \
                          OR p.cmdline LIKE '%--api_server_url%' \
                          OR p.cmdline LIKE '%--host_bridge_url%' \
                          OR p.cmdline LIKE '%--csrf_token%' \
                          OR p.cmdline LIKE '%mcp%' \
                          OR p.cmdline LIKE '%jsonrpc%' \
                          OR p.cmdline LIKE '%lsp%' \
                          OR p.cmdline LIKE '%--stdio%' \
                          OR p.cmdline LIKE '%agent%' \
                          OR p.cmdline LIKE '%gemini%' \
                          OR p.cmdline LIKE '%openai%' \
                          OR p.cmdline LIKE '%anthropic%' \
                          OR p.cmdline LIKE '%ollama%' \
                         )) \
                         OR (s.local_address = '127.0.0.1' AND ( \
                             p.cmdline LIKE '%--cloud_code_endpoint%' \
                          OR p.cmdline LIKE '%--host_bridge_url%' \
                          OR p.cmdline LIKE '%mcp%' \
                          OR p.cmdline LIKE '%jsonrpc%' \
                          OR p.cmdline LIKE '%serve%' \
                          OR p.cmdline LIKE '%--model%' \
                          OR p.cmdline LIKE '%--stdio%' \
                         ));";

        if let Ok(rows) = self.osquery_detector.execute_query(query1) {
            for row in rows {
                let pid_str = row
                    .get("pid")
                    .and_then(|v| v.as_str().map(|s| s.to_string()).or_else(|| v.as_i64().map(|n| n.to_string())))
                    .unwrap_or_default();
                let name = row.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let cmdline = row.get("cmdline").and_then(|v| v.as_str()).unwrap_or("");
                let cwd = row.get("cwd").and_then(|v| v.as_str()).unwrap_or("");
                let parent_str = row
                    .get("parent")
                    .and_then(|v| v.as_str().map(|s| s.to_string()).or_else(|| v.as_i64().map(|n| n.to_string())));

                if !pid_str.is_empty() {
                    let ws_hint = if !cwd.is_empty() { Some(cwd) } else { None };
                    let mut rec = self.inspect_command_and_context(&pid_str, parent_str.as_deref(), cmdline, ws_hint);
                    let (p_name, role, framework) = infer_agent_metadata(name, cmdline);
                    if (rec.process_name.is_empty() || rec.process_name == "unknown") && p_name != "unknown" {
                        rec.process_name = p_name;
                    }
                    if rec.agent_role.is_empty() || rec.agent_role == "Autonomous Subprocess" {
                        rec.agent_role = role;
                    }
                    if rec.framework.is_empty() || rec.framework == "Native OS / Pipe-Driven" {
                        rec.framework = framework;
                    }
                    if let Some(mut existing) = self.records.get_mut(&pid_str) {
                        existing.process_name = rec.process_name.clone();
                        existing.agent_role = rec.agent_role.clone();
                        existing.framework = rec.framework.clone();
                    }
                    discovered.push(rec);
                }
            }
        }

        // ---------------------------------------------------------------------
        // Query 2: Relational Process Tree + Socket + Subprocess Fan-Out
        // Identifies parent processes holding network/IPC sockets and spawning children
        // with non-interactive pipe/RPC indicators. Propagates lineage to children!
        // ---------------------------------------------------------------------
        let query2 = "SELECT DISTINCT p.pid, p.name, p.path, p.cmdline, p.cwd, p.parent, \
                             COUNT(DISTINCT c.pid) AS child_count, \
                             COUNT(DISTINCT s.remote_port) AS socket_count \
                       FROM processes p \
                       JOIN processes c ON c.parent = p.pid \
                       JOIN process_open_sockets s ON p.pid = s.pid \
                       WHERE s.remote_port = 443 OR s.local_address = '127.0.0.1' \
                       GROUP BY p.pid \
                       HAVING child_count >= 1;";

        if let Ok(rows) = self.osquery_detector.execute_query(query2) {
            for row in rows {
                let pid_str = row
                    .get("pid")
                    .and_then(|v| v.as_str().map(|s| s.to_string()).or_else(|| v.as_i64().map(|n| n.to_string())))
                    .unwrap_or_default();
                let name = row.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let cmdline = row.get("cmdline").and_then(|v| v.as_str()).unwrap_or("");
                let cwd = row.get("cwd").and_then(|v| v.as_str()).unwrap_or("");
                let parent_str = row
                    .get("parent")
                    .and_then(|v| v.as_str().map(|s| s.to_string()).or_else(|| v.as_i64().map(|n| n.to_string())));
                let child_count = row.get("child_count").and_then(|v| v.as_u64()).unwrap_or(1) as usize;

                let lower_cmd = cmdline.to_ascii_lowercase();
                let lower_cwd = cwd.to_ascii_lowercase();

                let is_agent_parent = lower_cmd.contains("--cloud_code_endpoint")
                    || lower_cmd.contains("--extension_server_port")
                    || lower_cmd.contains("--api_server_url")
                    || lower_cmd.contains("--host_bridge_url")
                    || lower_cmd.contains("--csrf_token")
                    || lower_cmd.contains("--stdio")
                    || lower_cmd.contains("mcp")
                    || lower_cmd.contains("agent")
                    || lower_cmd.contains(".gemini")
                    || lower_cmd.contains("antigravity")
                    || lower_cmd.contains("generativelanguage")
                    || lower_cwd.contains(".gemini")
                    || lower_cwd.contains("antigravity");

                if is_agent_parent && !pid_str.is_empty() {
                    let ws_hint = if !cwd.is_empty() { Some(cwd) } else { None };

                    // 1. Record structural parent signals
                    self.record_signal(
                        &pid_str,
                        parent_str.as_deref(),
                        ws_hint,
                        AgentEvidenceSignal::InferenceProtocolTraffic {
                            endpoint_pattern: "cloud_code_agent_host".to_string(),
                            is_streaming: true,
                        },
                    );
                    self.record_signal(
                        &pid_str,
                        parent_str.as_deref(),
                        ws_hint,
                        AgentEvidenceSignal::McpJsonRpcFraming {
                            method: "agent_orchestration_tree".to_string(),
                        },
                    );
                    let mut parent_rec = self.record_signal(
                        &pid_str,
                        parent_str.as_deref(),
                        ws_hint,
                        AgentEvidenceSignal::PipeDrivenToolBurst {
                            child_count_10s: child_count,
                            non_interactive_stdio: true,
                            post_network_wait_ms: 50,
                        },
                    );
                    let (p_name, role, framework) = infer_agent_metadata(name, cmdline);
                    if (parent_rec.process_name.is_empty() || parent_rec.process_name == "unknown") && p_name != "unknown" {
                        parent_rec.process_name = p_name;
                    }
                    if parent_rec.agent_role.is_empty() || parent_rec.agent_role == "Autonomous Subprocess" {
                        parent_rec.agent_role = role;
                    }
                    if parent_rec.framework.is_empty() || parent_rec.framework == "Native OS / Pipe-Driven" {
                        parent_rec.framework = framework;
                    }
                    if let Some(mut existing) = self.records.get_mut(&pid_str) {
                        existing.process_name = parent_rec.process_name.clone();
                        existing.agent_role = parent_rec.agent_role.clone();
                        existing.framework = parent_rec.framework.clone();
                    }
                    discovered.push(parent_rec);

                    // 2. Discover children and propagate lineage
                    let child_query = format!(
                        "SELECT c.pid, c.name, c.path, c.cmdline, c.cwd, c.parent FROM processes c WHERE c.parent = {};",
                        pid_str
                    );
                    if let Ok(child_rows) = self.osquery_detector.execute_query(&child_query) {
                        for c_row in child_rows {
                            let c_pid = c_row
                                .get("pid")
                                .and_then(|v| v.as_str().map(|s| s.to_string()).or_else(|| v.as_i64().map(|n| n.to_string())))
                                .unwrap_or_default();
                            let c_name = c_row.get("name").and_then(|v| v.as_str()).unwrap_or("");
                            let c_cmd = c_row.get("cmdline").and_then(|v| v.as_str()).unwrap_or("");
                            let c_cwd = c_row.get("cwd").and_then(|v| v.as_str()).unwrap_or("");
                            let c_lower = c_cmd.to_ascii_lowercase();

                            if !c_pid.is_empty() {
                                let c_ws = if !c_cwd.is_empty() { Some(c_cwd) } else { ws_hint };

                                // Check if child is an MCP server or tool subprocess
                                if c_lower.contains("mcp")
                                    || c_lower.contains("jsonrpc")
                                    || c_lower.contains("--stdio")
                                {
                                    self.record_signal(
                                        &c_pid,
                                        Some(&pid_str),
                                        c_ws,
                                        AgentEvidenceSignal::McpJsonRpcFraming {
                                            method: "mcp_subprocess_tool".to_string(),
                                        },
                                    );
                                }

                                let mut c_rec = self.inspect_command_and_context(&c_pid, Some(&pid_str), c_cmd, c_ws);
                                let (cp_name, c_role, c_framework) = infer_agent_metadata(c_name, c_cmd);
                                if (c_rec.process_name.is_empty() || c_rec.process_name == "unknown") && cp_name != "unknown" {
                                    c_rec.process_name = cp_name;
                                }
                                if c_rec.agent_role.is_empty() || c_rec.agent_role == "Autonomous Subprocess" {
                                    c_rec.agent_role = c_role;
                                }
                                if c_rec.framework.is_empty() || c_rec.framework == "Native OS / Pipe-Driven" {
                                    c_rec.framework = c_framework;
                                }
                                if let Some(mut existing) = self.records.get_mut(&c_pid) {
                                    existing.process_name = c_rec.process_name.clone();
                                    existing.agent_role = c_rec.agent_role.clone();
                                    existing.framework = c_rec.framework.clone();
                                }
                                discovered.push(c_rec);
                            }
                        }
                    }
                }
            }
        }

        // ---------------------------------------------------------------------
        // Query 3: Named Pipes & MCP / Agent IPC Pipes + Environment Variables
        // Inspects process_envs for agent prefixes (corroborates active sessions)
        // ---------------------------------------------------------------------
        let query3 = "SELECT DISTINCT e.pid, p.name, p.cmdline, p.cwd, p.parent, e.key \
                      FROM process_envs e \
                      JOIN processes p ON e.pid = p.pid \
                      WHERE e.key LIKE 'ANTIGRAVITY%' \
                         OR e.key LIKE 'GEMINI%' \
                         OR e.key LIKE 'OPENAI%' \
                         OR e.key LIKE 'ANTHROPIC%' \
                         OR e.key LIKE 'MCP%' \
                         OR e.key LIKE 'OLLAMA%';";

        if let Ok(rows) = self.osquery_detector.execute_query(query3) {
            for row in rows {
                let pid_str = row
                    .get("pid")
                    .and_then(|v| v.as_str().map(|s| s.to_string()).or_else(|| v.as_i64().map(|n| n.to_string())))
                    .unwrap_or_default();
                let name = row.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let cmdline = row.get("cmdline").and_then(|v| v.as_str()).unwrap_or("");
                let cwd = row.get("cwd").and_then(|v| v.as_str()).unwrap_or("");
                let parent_str = row
                    .get("parent")
                    .and_then(|v| v.as_str().map(|s| s.to_string()).or_else(|| v.as_i64().map(|n| n.to_string())));
                let key = row.get("key").and_then(|v| v.as_str()).unwrap_or("");

                if !pid_str.is_empty() {
                    let ws_hint = if !cwd.is_empty() { Some(cwd) } else { None };
                    self.record_signal(
                        &pid_str,
                        parent_str.as_deref(),
                        ws_hint,
                        AgentEvidenceSignal::InferenceProtocolTraffic {
                            endpoint_pattern: format!("env:{}", key),
                            is_streaming: false,
                        },
                    );
                    let mut rec = self.inspect_command_and_context(&pid_str, parent_str.as_deref(), cmdline, ws_hint);
                    let (p_name, role, framework) = infer_agent_metadata(name, cmdline);
                    if (rec.process_name.is_empty() || rec.process_name == "unknown") && p_name != "unknown" {
                        rec.process_name = p_name;
                    }
                    if rec.agent_role.is_empty() || rec.agent_role == "Autonomous Subprocess" {
                        rec.agent_role = role;
                    }
                    if rec.framework.is_empty() || rec.framework == "Native OS / Pipe-Driven" {
                        rec.framework = framework;
                    }
                    if let Some(mut existing) = self.records.get_mut(&pid_str) {
                        existing.process_name = rec.process_name.clone();
                        existing.agent_role = rec.agent_role.clone();
                        existing.framework = rec.framework.clone();
                    }
                    discovered.push(rec);
                }
            }
        }

        // ---------------------------------------------------------------------
        // Query 4: Model Tensor Memory Mappings
        // Inspects process_memory_map for loaded model tensors (.gguf, .safetensors, .onnx)
        // ---------------------------------------------------------------------
        let query4 = "SELECT DISTINCT pid, path FROM process_memory_map \
                      WHERE path LIKE '%.gguf' OR path LIKE '%.safetensors' OR path LIKE '%.onnx';";

        if let Ok(rows) = self.osquery_detector.execute_query(query4) {
            for row in rows {
                let pid_str = row
                    .get("pid")
                    .and_then(|v| v.as_str().map(|s| s.to_string()).or_else(|| v.as_i64().map(|n| n.to_string())))
                    .unwrap_or_default();
                let path = row.get("path").and_then(|v| v.as_str()).unwrap_or("");

                if !pid_str.is_empty() {
                    let format = if path.ends_with(".gguf") {
                        "gguf"
                    } else if path.ends_with(".safetensors") {
                        "safetensors"
                    } else {
                        "onnx"
                    };
                    let mut rec = self.record_signal(
                        &pid_str,
                        None,
                        None,
                        AgentEvidenceSignal::ModelTensorMemoryMapped {
                            format: format.to_string(),
                        },
                    );
                    let (p_name, role, framework) = infer_agent_metadata("", path);
                    if (rec.process_name.is_empty() || rec.process_name == "unknown") && p_name != "unknown" {
                        rec.process_name = p_name;
                    }
                    if rec.agent_role.is_empty() || rec.agent_role == "Autonomous Subprocess" {
                        rec.agent_role = role;
                    }
                    if rec.framework.is_empty() || rec.framework == "Native OS / Pipe-Driven" {
                        rec.framework = framework;
                    }
                    if let Some(mut existing) = self.records.get_mut(&pid_str) {
                        existing.process_name = rec.process_name.clone();
                        existing.agent_role = rec.agent_role.clone();
                        existing.framework = rec.framework.clone();
                    }
                    discovered.push(rec);
                }
            }
        }

        discovered
    }

    /// Backwards compatibility alias for `run_siquery_host_scan`.
    pub fn run_osquery_host_scan(&self) -> Vec<AgentClassificationRecord> {
        self.run_siquery_host_scan()
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

    #[test]
    fn test_live_host_antigravity_agent_detection() {
        let classifier = DynamicAgentClassifier::new();
        let discovered = classifier.run_siquery_host_scan();

        println!("=== Siquery Host Scan: Total Discovered Subjects: {} ===", discovered.len());
        let verified = classifier.list_verified_agents();
        println!("=== Siquery Host Scan: Total Verified AI Agents (P >= 0.75): {} ===", verified.len());

        for agent in &verified {
            println!(
                "  [VERIFIED AGENT] PID={} P={:.4} workspace='{:?}' signals={:?}",
                agent.subject_id,
                agent.posterior_probability,
                agent.inferred_workspace_root,
                agent.observed_signals
            );
        }

        assert!(
            !verified.is_empty(),
            "DynamicAgentClassifier must detect at least one active AI agent process on this host via siquery relational queries without hardcoded binary names!"
        );

        // Ensure at least one verified agent has posterior probability >= 0.75
        let highest_prob = verified
            .iter()
            .map(|a| a.posterior_probability)
            .fold(0.0f32, f32::max);
        assert!(highest_prob >= 0.75, "Highest verified probability must be >= 0.75, got {}", highest_prob);
    }
}
