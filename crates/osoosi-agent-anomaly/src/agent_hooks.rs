//! # Inline Synchronous Agent Hooks & Wire Format Interception Engine
//!
//! Provides zero-latency (<1ms) inline pre-execution and post-execution interception
//! for AI coding agents (Claude Code, Cursor, GitHub Copilot, OpenCode, and MCP stdio tools)
//! eliminating the blind spots of voluntary reporting and interval polling.
//!
//! ## 6-Layer Synchronous In-Memory Pipeline:
//! 1. `SemanticCommandAst` (privilege escalation AST/flag parsing)
//! 2. `DynamicBinaryMetadataProbe` (SUID/SGID, Linux capabilities, Windows requireAdministrator)
//! 3. `SemanticDlpEngine` (character/span-level entity and PHI/PII classification)
//! 4. `TemporalCircumventionCorrelator` (Incident A sliding-window circumvention memory)
//! 5. `ApcPolicyDecisionPoint` (Bounded Agents APC action class gating)
//! 6. `CageGovernanceKernel` (CAGE governance and invariant checks)

use std::collections::VecDeque;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::bounded_agents_apc::classify_action_class;
use crate::circumvention::{
    is_cross_boundary_invocation, DynamicDenialSignal, TemporalCircumventionCorrelator,
};
use crate::semantic_command::{
    parse_semantic_command, DynamicBinaryMetadataProbe, PrivilegeEquivalenceClass,
};

/// Capacity for in-memory ring buffer of agent interception events.
pub const AGENT_INTERCEPTION_CAPACITY: usize = 1024;

/// Global shared temporal circumvention correlator for hook-observed denials.
pub static GLOBAL_CORRELATOR: LazyLock<TemporalCircumventionCorrelator> =
    LazyLock::new(|| TemporalCircumventionCorrelator::new(Duration::from_secs(60)));

// ============================================================================
// Data Structures
// ============================================================================

/// Supported AI coding agent runtime kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SupportedAgentKind {
    Claude,
    Cursor,
    Copilot,
    OpenCode,
    Mcp,
}

impl SupportedAgentKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Cursor => "cursor",
            Self::Copilot => "copilot",
            Self::OpenCode => "opencode",
            Self::Mcp => "mcp",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "claude" | "claudecode" | "claude-code" => Some(Self::Claude),
            "cursor" => Some(Self::Cursor),
            "copilot" | "github-copilot" => Some(Self::Copilot),
            "opencode" => Some(Self::OpenCode),
            "mcp" | "mcp-proxy" => Some(Self::Mcp),
            _ => None,
        }
    }
}

impl fmt::Display for SupportedAgentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Agent lifecycle event type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookEventType {
    PreToolUse,
    PostToolUse,
    BeforeShellExecution,
    AfterShellExecution,
    BeforeMCPExecution,
    BeforeReadFile,
    Custom(String),
}

impl HookEventType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::PreToolUse => "PreToolUse",
            Self::PostToolUse => "PostToolUse",
            Self::BeforeShellExecution => "beforeShellExecution",
            Self::AfterShellExecution => "afterShellExecution",
            Self::BeforeMCPExecution => "beforeMCPExecution",
            Self::BeforeReadFile => "beforeReadFile",
            Self::Custom(s) => s.as_str(),
        }
    }

    pub fn is_post(&self) -> bool {
        matches!(self, Self::PostToolUse | Self::AfterShellExecution)
    }

    pub fn from_name(name: &str) -> Self {
        match name.trim() {
            "PreToolUse" | "preToolUse" | "pre" | "before" => Self::PreToolUse,
            "PostToolUse" | "postToolUse" | "post" => Self::PostToolUse,
            "beforeShellExecution" => Self::BeforeShellExecution,
            "afterShellExecution" => Self::AfterShellExecution,
            "beforeMCPExecution" => Self::BeforeMCPExecution,
            "beforeReadFile" => Self::BeforeReadFile,
            other => Self::Custom(other.to_string()),
        }
    }
}

/// Canonical normalized hook request across all agent wire formats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedHookRequest {
    pub agent: SupportedAgentKind,
    pub event_type: HookEventType,
    pub tool_name: Option<String>,
    pub command: Option<String>,
    pub file_path: Option<String>,
    pub arguments: Option<serde_json::Value>,
    pub exit_code: Option<i32>,
    pub stderr: Option<String>,
    pub cwd: Option<String>,
    pub session_id: Option<String>,
    #[serde(default)]
    pub rpc_id: Option<serde_json::Value>,
}

impl Default for NormalizedHookRequest {
    fn default() -> Self {
        Self {
            agent: SupportedAgentKind::Claude,
            event_type: HookEventType::PreToolUse,
            tool_name: None,
            command: None,
            file_path: None,
            arguments: None,
            exit_code: None,
            stderr: None,
            cwd: None,
            session_id: None,
            rpc_id: None,
        }
    }
}

impl NormalizedHookRequest {
    pub fn from_json(val: &serde_json::Value) -> Self {
        let params = val.get("params");

        let tool_name = params
            .and_then(extract_wire_tool_name)
            .or_else(|| extract_wire_tool_name(val));

        let arguments = params
            .and_then(extract_wire_arguments)
            .or_else(|| extract_wire_arguments(val));

        let command = arguments
            .as_ref()
            .and_then(extract_wire_command)
            .or_else(|| params.and_then(extract_wire_command))
            .or_else(|| extract_wire_command(val));

        let file_path = arguments
            .as_ref()
            .and_then(extract_wire_file_path)
            .or_else(|| params.and_then(extract_wire_file_path))
            .or_else(|| extract_wire_file_path(val));

        let tool_resp = params
            .and_then(extract_wire_tool_response)
            .or_else(|| extract_wire_tool_response(val));

        let exit_code = tool_resp
            .and_then(extract_wire_exit_code)
            .or_else(|| extract_wire_exit_code(val));

        let stderr = tool_resp
            .and_then(extract_wire_stderr)
            .or_else(|| extract_wire_stderr(val));

        let cwd = extract_wire_cwd(val)
            .or_else(|| params.and_then(extract_wire_cwd))
            .or_else(|| arguments.as_ref().and_then(extract_wire_cwd));

        let session_id = extract_wire_session_id(val)
            .or_else(|| params.and_then(extract_wire_session_id))
            .or_else(|| arguments.as_ref().and_then(extract_wire_session_id));

        let agent = if let Some(agent_str) = extract_wire_agent_id(val) {
            SupportedAgentKind::from_str(&agent_str).unwrap_or_else(|| {
                if val.get("cursor_command").is_some()
                    || val.get("cursor_trace_id").is_some()
                    || val.get("context_paths").is_some()
                {
                    SupportedAgentKind::Cursor
                } else if val.get("copilot_action").is_some() || val.get("editor_context").is_some()
                {
                    SupportedAgentKind::Copilot
                } else if val.get("subcommand").is_some() || val.get("working_file").is_some() {
                    SupportedAgentKind::OpenCode
                } else if val.get("jsonrpc").is_some() {
                    SupportedAgentKind::Mcp
                } else {
                    SupportedAgentKind::Claude
                }
            })
        } else if val.get("jsonrpc").is_some()
            || val.get("method").and_then(|m| m.as_str()) == Some("tools/call")
        {
            SupportedAgentKind::Mcp
        } else if val.get("cursor_command").is_some()
            || val.get("cursor_trace_id").is_some()
            || val.get("context_paths").is_some()
        {
            SupportedAgentKind::Cursor
        } else if val.get("copilot_action").is_some() || val.get("editor_context").is_some() {
            SupportedAgentKind::Copilot
        } else if val.get("subcommand").is_some() || val.get("working_file").is_some() {
            SupportedAgentKind::OpenCode
        } else {
            SupportedAgentKind::Claude
        };

        let event_type = if let Some(evt) = val
            .get("event")
            .or_else(|| val.get("event_type"))
            .or_else(|| val.get("type"))
            .and_then(|e| e.as_str())
        {
            HookEventType::from_name(evt)
        } else if val.get("jsonrpc").is_some() {
            HookEventType::BeforeMCPExecution
        } else if exit_code.is_some() || stderr.is_some() || tool_resp.is_some() {
            HookEventType::PostToolUse
        } else {
            HookEventType::PreToolUse
        };

        let rpc_id = val.get("id").cloned();

        Self {
            agent,
            event_type,
            tool_name,
            command,
            file_path,
            arguments,
            exit_code,
            stderr,
            cwd,
            session_id,
            rpc_id,
        }
    }

    pub fn from_json_str(raw: &str) -> Result<Self, String> {
        let val: serde_json::Value =
            serde_json::from_str(raw).map_err(|e| format!("Invalid hook request JSON: {e}"))?;
        Ok(Self::from_json(&val))
    }
}

/// Synchronous evaluation decision returned to agent wire format adapters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookEvaluationDecision {
    pub allowed: bool,
    pub rationale: String,
    pub denied_by_layer: Option<String>,
    pub remediation: Option<String>,
    pub execution_duration_us: u64,
}

impl HookEvaluationDecision {
    pub fn allow(rationale: impl Into<String>, duration_us: u64) -> Self {
        Self {
            allowed: true,
            rationale: rationale.into(),
            denied_by_layer: None,
            remediation: None,
            execution_duration_us: duration_us,
        }
    }

    pub fn deny(
        rationale: impl Into<String>,
        denied_by_layer: Option<&str>,
        remediation: Option<&str>,
        duration_us: u64,
    ) -> Self {
        Self {
            allowed: false,
            rationale: rationale.into(),
            denied_by_layer: denied_by_layer.map(|s| s.to_string()),
            remediation: remediation.map(|s| s.to_string()),
            execution_duration_us: duration_us,
        }
    }
}

/// Persistent record of an interception stored in the in-memory ring buffer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInterceptionRecord {
    pub event_id: String,
    pub timestamp_ns: u64,
    pub timestamp_utc: String,
    pub agent: String,
    pub event_type: String,
    pub tool_name: String,
    pub command: String,
    pub allowed: bool,
    pub rationale: String,
    pub denied_by_layer: Option<String>,
}

// ============================================================================
// Ring Buffer for Siquery & EDR Visibility
// ============================================================================

pub static AGENT_INTERCEPTION_EVENTS: LazyLock<RwLock<VecDeque<AgentInterceptionRecord>>> =
    LazyLock::new(|| RwLock::new(VecDeque::with_capacity(AGENT_INTERCEPTION_CAPACITY)));

static EVENT_COUNTER: AtomicU64 = AtomicU64::new(1);

pub fn record_interception_event(record: AgentInterceptionRecord) {
    let mut buf = AGENT_INTERCEPTION_EVENTS.write();
    while buf.len() >= AGENT_INTERCEPTION_CAPACITY {
        buf.pop_front();
    }
    buf.push_back(record);
}

pub fn get_recent_interceptions(limit: usize) -> Vec<AgentInterceptionRecord> {
    AGENT_INTERCEPTION_EVENTS
        .read()
        .iter()
        .rev()
        .take(limit)
        .cloned()
        .collect()
}

pub fn snapshot_interceptions() -> Vec<AgentInterceptionRecord> {
    AGENT_INTERCEPTION_EVENTS.read().iter().cloned().collect()
}

pub fn clear_interceptions() {
    AGENT_INTERCEPTION_EVENTS.write().clear();
}

// ============================================================================
// Wire Format Parsers
// ============================================================================

pub fn extract_wire_tool_name(val: &serde_json::Value) -> Option<String> {
    const CANDIDATES: &[&str] = &["tool_name", "name", "tool"];
    for &key in CANDIDATES {
        if let Some(v) = val.get(key) {
            if let Some(s) = v.as_str() {
                return Some(s.to_string());
            }
        }
    }
    None
}

pub fn extract_wire_arguments(val: &serde_json::Value) -> Option<serde_json::Value> {
    const CANDIDATES: &[&str] = &["arguments", "tool_input", "args", "parameters", "input"];
    for &key in CANDIDATES {
        if let Some(v) = val.get(key) {
            if !v.is_null() {
                return Some(v.clone());
            }
        }
    }
    None
}

pub fn extract_wire_tool_response(val: &serde_json::Value) -> Option<&serde_json::Value> {
    const CANDIDATES: &[&str] = &[
        "tool_response",
        "tool_result",
        "result",
        "output",
        "content",
    ];
    for &key in CANDIDATES {
        if let Some(v) = val.get(key) {
            if !v.is_null() {
                return Some(v);
            }
        }
    }
    None
}

pub fn extract_wire_command(val: &serde_json::Value) -> Option<String> {
    const CANDIDATES: &[&str] = &[
        "command",
        "cmd",
        "cursor_command",
        "copilot_action",
        "subcommand",
        "action",
    ];
    for &key in CANDIDATES {
        if let Some(f) = val.get(key) {
            if let Some(s) = f.as_str() {
                return Some(s.to_string());
            }
            if let Some(arr) = f.as_array() {
                let parts: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
                if !parts.is_empty() {
                    return Some(parts.join(" "));
                }
            }
        }
    }
    None
}

pub fn extract_wire_file_path(val: &serde_json::Value) -> Option<String> {
    const CANDIDATES: &[&str] = &[
        "file_path",
        "path",
        "filePath",
        "uri",
        "working_file",
        "editor_context",
        "file",
        "context_paths",
    ];
    for &key in CANDIDATES {
        if let Some(f) = val.get(key) {
            if let Some(s) = f.as_str() {
                return Some(s.to_string());
            }
            if let Some(arr) = f.as_array() {
                if let Some(first) = arr.first().and_then(|v| v.as_str()) {
                    return Some(first.to_string());
                }
            }
        }
    }
    None
}

pub fn extract_wire_session_id(val: &serde_json::Value) -> Option<String> {
    const CANDIDATES: &[&str] = &[
        "session_id",
        "sessionId",
        "conversation_id",
        "cursor_trace_id",
        "tool_use_id",
    ];
    for &key in CANDIDATES {
        if let Some(v) = val.get(key) {
            if let Some(s) = v.as_str() {
                return Some(s.to_string());
            }
        }
    }
    None
}

pub fn extract_wire_exit_code(val: &serde_json::Value) -> Option<i32> {
    const CANDIDATES: &[&str] = &["exit_code", "exitCode"];
    for &key in CANDIDATES {
        if let Some(v) = val.get(key) {
            if let Some(i) = v.as_i64() {
                return Some(i as i32);
            }
        }
    }
    None
}

pub fn extract_wire_stderr(val: &serde_json::Value) -> Option<String> {
    const CANDIDATES: &[&str] = &["stderr", "error"];
    for &key in CANDIDATES {
        if let Some(v) = val.get(key) {
            if let Some(s) = v.as_str() {
                return Some(s.to_string());
            }
        }
    }
    None
}

pub fn extract_wire_cwd(val: &serde_json::Value) -> Option<String> {
    const CANDIDATES: &[&str] = &["cwd", "working_dir", "workingDirectory"];
    for &key in CANDIDATES {
        if let Some(v) = val.get(key) {
            if let Some(s) = v.as_str() {
                return Some(s.to_string());
            }
        }
    }
    None
}

pub fn extract_wire_agent_id(val: &serde_json::Value) -> Option<String> {
    const CANDIDATES: &[&str] = &["agent_id", "agentId", "agent"];
    for &key in CANDIDATES {
        if let Some(v) = val.get(key) {
            if let Some(s) = v.as_str() {
                return Some(s.to_string());
            }
            if let Some(id) = v
                .get("id")
                .or_else(|| v.get("name"))
                .and_then(|x| x.as_str())
            {
                return Some(id.to_string());
            }
        }
    }
    None
}

pub fn extract_wire_source_agent_id(val: &serde_json::Value) -> Option<String> {
    const CANDIDATES: &[&str] = &["source_agent_id", "sourceAgentId", "caller_agent_id"];
    for &key in CANDIDATES {
        if let Some(v) = val.get(key) {
            if let Some(s) = v.as_str() {
                return Some(s.to_string());
            }
            if let Some(id) = v
                .get("id")
                .or_else(|| v.get("name"))
                .and_then(|x| x.as_str())
            {
                return Some(id.to_string());
            }
        }
    }
    None
}

pub fn parse_claude_request(
    raw_json: &str,
    is_post: bool,
) -> Result<NormalizedHookRequest, String> {
    let val: serde_json::Value = serde_json::from_str(raw_json)
        .map_err(|e| format!("Invalid Claude Code hook JSON: {e}"))?;

    let tool_name = extract_wire_tool_name(&val);
    let arguments = extract_wire_arguments(&val);
    let command = arguments
        .as_ref()
        .and_then(extract_wire_command)
        .or_else(|| extract_wire_command(&val));
    let file_path = arguments
        .as_ref()
        .and_then(extract_wire_file_path)
        .or_else(|| extract_wire_file_path(&val));

    let tool_resp = extract_wire_tool_response(&val);
    let exit_code = tool_resp
        .and_then(extract_wire_exit_code)
        .or_else(|| extract_wire_exit_code(&val));
    let stderr = tool_resp
        .and_then(extract_wire_stderr)
        .or_else(|| extract_wire_stderr(&val));

    let cwd = extract_wire_cwd(&val).or_else(|| arguments.as_ref().and_then(extract_wire_cwd));
    let session_id = extract_wire_session_id(&val)
        .or_else(|| arguments.as_ref().and_then(extract_wire_session_id));

    Ok(NormalizedHookRequest {
        agent: SupportedAgentKind::Claude,
        event_type: if is_post {
            HookEventType::PostToolUse
        } else {
            HookEventType::PreToolUse
        },
        tool_name,
        command,
        file_path,
        arguments,
        exit_code,
        stderr,
        cwd,
        session_id,
        rpc_id: None,
    })
}

pub fn parse_cursor_request(
    raw_json: &str,
    event_name: &str,
) -> Result<NormalizedHookRequest, String> {
    let val: serde_json::Value =
        serde_json::from_str(raw_json).map_err(|e| format!("Invalid Cursor hook JSON: {e}"))?;

    let event_type = HookEventType::from_name(event_name);
    let tool_name = extract_wire_tool_name(&val);
    let arguments = extract_wire_arguments(&val);
    let command =
        extract_wire_command(&val).or_else(|| arguments.as_ref().and_then(extract_wire_command));
    let file_path = extract_wire_file_path(&val)
        .or_else(|| arguments.as_ref().and_then(extract_wire_file_path));

    let tool_resp = extract_wire_tool_response(&val);
    let exit_code = tool_resp
        .and_then(extract_wire_exit_code)
        .or_else(|| extract_wire_exit_code(&val));
    let stderr = tool_resp
        .and_then(extract_wire_stderr)
        .or_else(|| extract_wire_stderr(&val));

    let cwd = extract_wire_cwd(&val).or_else(|| arguments.as_ref().and_then(extract_wire_cwd));
    let session_id = extract_wire_session_id(&val)
        .or_else(|| arguments.as_ref().and_then(extract_wire_session_id));

    Ok(NormalizedHookRequest {
        agent: SupportedAgentKind::Cursor,
        event_type,
        tool_name,
        command,
        file_path,
        arguments,
        exit_code,
        stderr,
        cwd,
        session_id,
        rpc_id: None,
    })
}

pub fn parse_copilot_request(
    raw_json: &str,
    event_name: &str,
) -> Result<NormalizedHookRequest, String> {
    let val: serde_json::Value = serde_json::from_str(raw_json)
        .map_err(|e| format!("Invalid GitHub Copilot hook JSON: {e}"))?;

    let event_type = HookEventType::from_name(event_name);
    let tool_name = extract_wire_tool_name(&val);
    let arguments = extract_wire_arguments(&val);
    let command = arguments
        .as_ref()
        .and_then(extract_wire_command)
        .or_else(|| extract_wire_command(&val));
    let file_path = arguments
        .as_ref()
        .and_then(extract_wire_file_path)
        .or_else(|| extract_wire_file_path(&val));

    let tool_resp = extract_wire_tool_response(&val);
    let exit_code = tool_resp
        .and_then(extract_wire_exit_code)
        .or_else(|| extract_wire_exit_code(&val));
    let stderr = tool_resp
        .and_then(extract_wire_stderr)
        .or_else(|| extract_wire_stderr(&val));

    let cwd = extract_wire_cwd(&val).or_else(|| arguments.as_ref().and_then(extract_wire_cwd));
    let session_id = extract_wire_session_id(&val)
        .or_else(|| arguments.as_ref().and_then(extract_wire_session_id));

    Ok(NormalizedHookRequest {
        agent: SupportedAgentKind::Copilot,
        event_type,
        tool_name,
        command,
        file_path,
        arguments,
        exit_code,
        stderr,
        cwd,
        session_id,
        rpc_id: None,
    })
}

pub fn parse_opencode_request(raw_json: &str) -> Result<NormalizedHookRequest, String> {
    let val: serde_json::Value =
        serde_json::from_str(raw_json).map_err(|e| format!("Invalid OpenCode hook JSON: {e}"))?;

    let typ = val.get("type").and_then(|v| v.as_str()).unwrap_or("before");
    let event_type = if typ.eq_ignore_ascii_case("after") || typ.eq_ignore_ascii_case("post") {
        HookEventType::PostToolUse
    } else {
        HookEventType::PreToolUse
    };

    let tool_name = extract_wire_tool_name(&val);
    let arguments = extract_wire_arguments(&val);
    let command = arguments
        .as_ref()
        .and_then(extract_wire_command)
        .or_else(|| extract_wire_command(&val));
    let file_path = arguments
        .as_ref()
        .and_then(extract_wire_file_path)
        .or_else(|| extract_wire_file_path(&val));

    let tool_resp = extract_wire_tool_response(&val);
    let exit_code = tool_resp
        .and_then(extract_wire_exit_code)
        .or_else(|| extract_wire_exit_code(&val));
    let stderr = tool_resp
        .and_then(extract_wire_stderr)
        .or_else(|| extract_wire_stderr(&val));

    let cwd = extract_wire_cwd(&val).or_else(|| arguments.as_ref().and_then(extract_wire_cwd));
    let session_id = extract_wire_session_id(&val)
        .or_else(|| arguments.as_ref().and_then(extract_wire_session_id));

    Ok(NormalizedHookRequest {
        agent: SupportedAgentKind::OpenCode,
        event_type,
        tool_name,
        command,
        file_path,
        arguments,
        exit_code,
        stderr,
        cwd,
        session_id,
        rpc_id: None,
    })
}

pub fn parse_mcp_call_request(raw_json: &str) -> Result<NormalizedHookRequest, String> {
    let val: serde_json::Value =
        serde_json::from_str(raw_json).map_err(|e| format!("Invalid MCP JSON-RPC: {e}"))?;

    let method = val.get("method").and_then(|v| v.as_str()).unwrap_or("");
    if method != "tools/call" {
        return Err("Not a tools/call method".to_string());
    }

    let rpc_id = val.get("id").cloned();
    let params = val
        .get("params")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    let tool_name = extract_wire_tool_name(&params).or_else(|| extract_wire_tool_name(&val));
    let arguments = extract_wire_arguments(&params).or_else(|| extract_wire_arguments(&val));

    let command = arguments
        .as_ref()
        .and_then(extract_wire_command)
        .or_else(|| extract_wire_command(&params))
        .or_else(|| extract_wire_command(&val));
    let file_path = arguments
        .as_ref()
        .and_then(extract_wire_file_path)
        .or_else(|| extract_wire_file_path(&params))
        .or_else(|| extract_wire_file_path(&val));

    let tool_resp =
        extract_wire_tool_response(&params).or_else(|| extract_wire_tool_response(&val));
    let exit_code = tool_resp
        .and_then(extract_wire_exit_code)
        .or_else(|| extract_wire_exit_code(&params))
        .or_else(|| extract_wire_exit_code(&val));
    let stderr = tool_resp
        .and_then(extract_wire_stderr)
        .or_else(|| extract_wire_stderr(&params))
        .or_else(|| extract_wire_stderr(&val));

    let cwd = extract_wire_cwd(&params)
        .or_else(|| extract_wire_cwd(&val))
        .or_else(|| arguments.as_ref().and_then(extract_wire_cwd));
    let session_id = extract_wire_session_id(&params).or_else(|| extract_wire_session_id(&val));

    Ok(NormalizedHookRequest {
        agent: SupportedAgentKind::Mcp,
        event_type: HookEventType::BeforeMCPExecution,
        tool_name,
        command,
        file_path,
        arguments,
        exit_code,
        stderr,
        cwd,
        session_id,
        rpc_id,
    })
}

// ============================================================================
// Wire Format Formatters
// ============================================================================

pub fn format_claude_response(decision: &HookEvaluationDecision) -> (i32, String) {
    if decision.allowed {
        (0, String::new())
    } else {
        (
            2,
            format!("OshoosiClaw Hook Policy Denied: {}\n", decision.rationale),
        )
    }
}

pub fn format_cursor_response(decision: &HookEvaluationDecision) -> (i32, String) {
    let obj = if decision.allowed {
        serde_json::json!({
            "permission": "allow",
            "user_message": "Authorized by OshoosiClaw PEP",
            "agent_message": ""
        })
    } else {
        serde_json::json!({
            "permission": "deny",
            "user_message": format!("OshoosiClaw Containment: {}", decision.rationale),
            "agent_message": decision.rationale
        })
    };
    (0, obj.to_string())
}

pub fn format_copilot_response(decision: &HookEvaluationDecision) -> (i32, String) {
    let obj = if decision.allowed {
        serde_json::json!({
            "permissionDecision": "allow",
            "permissionDecisionReason": "OshoosiClaw cleared execution"
        })
    } else {
        serde_json::json!({
            "permissionDecision": "deny",
            "permissionDecisionReason": format!("OshoosiClaw Policy Violation: {}", decision.rationale)
        })
    };
    (0, obj.to_string())
}

pub fn format_opencode_response(decision: &HookEvaluationDecision) -> (i32, String) {
    let obj = if decision.allowed {
        serde_json::json!({
            "allow": true,
            "reason": "OshoosiClaw cleared execution"
        })
    } else {
        serde_json::json!({
            "allow": false,
            "reason": format!("OshoosiClaw Policy Violation: {}", decision.rationale)
        })
    };
    (0, obj.to_string())
}

pub fn format_mcp_error_response(
    id: &serde_json::Value,
    decision: &HookEvaluationDecision,
) -> String {
    let mut error_obj = serde_json::json!({
        "code": -32000,
        "message": format!("OshoosiClaw Policy Violation: {}", decision.rationale)
    });

    if decision.denied_by_layer.is_some() || decision.remediation.is_some() {
        error_obj["data"] = serde_json::json!({
            "denied_by_layer": decision.denied_by_layer.as_deref().unwrap_or("Unknown"),
            "suggested_remediation": decision.remediation.as_deref().unwrap_or("None"),
        });
    }

    let resp = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": error_obj,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": format!("OshoosiClaw Policy Violation: {}", decision.rationale)
                }
            ],
            "isError": true
        }
    });
    resp.to_string()
}

// ============================================================================
// 6-Layer Zero-Latency Synchronous In-Memory Evaluation Pipeline
// ============================================================================

pub fn evaluate_hook_synchronously(req: &NormalizedHookRequest) -> HookEvaluationDecision {
    let start_instant = Instant::now();
    let session_id = req.session_id.as_deref().unwrap_or("agent-session-default");

    // Post-Execution Handling (Capture dynamic denials for Incident A memory)
    if req.event_type.is_post() {
        let is_denial = req.exit_code.map(|c| c != 0).unwrap_or(false)
            || req
                .stderr
                .as_ref()
                .map(|e| {
                    let l = e.to_ascii_lowercase();
                    l.contains("password is required")
                        || l.contains("permission denied")
                        || l.contains("eacces")
                        || l.contains("eperm")
                        || l.contains("access denied")
                })
                .unwrap_or(false);

        if is_denial {
            let cmd_str = req.command.as_deref().unwrap_or("unknown_command");
            let sem = parse_semantic_command(cmd_str);
            let signal = DynamicDenialSignal::new(
                format!("denial-{}", EVENT_COUNTER.fetch_add(1, Ordering::SeqCst)),
                session_id,
                None,
                std::process::id(),
                cmd_str,
                sem.privilege_class,
                req.exit_code,
                true,
                req.stderr.clone(),
                Instant::now(),
            );
            GLOBAL_CORRELATOR.record_denial(signal);
            debug!("PostToolUse recorded dynamic denial for Incident A memory");
        }

        let duration_us = start_instant.elapsed().as_micros() as u64;
        let decision =
            HookEvaluationDecision::allow("PostToolUse completed and recorded", duration_us);
        record_decision(req, &decision);
        return decision;
    }

    // PreToolUse Guard: Sensitive System Path & Credential Store Interception
    let mut detected_sensitive_store: Option<(
        osoosi_dp::sensitive_paths::SensitiveCredentialStoreKind,
        String,
    )> = None;

    if let Some(path) = &req.file_path {
        if let Some(kind) = osoosi_dp::sensitive_paths::classify_sensitive_system_path(path) {
            detected_sensitive_store = Some((kind, path.clone()));
        } else if let Some(found) = osoosi_dp::sensitive_paths::scan_for_sensitive_system_path(path)
        {
            detected_sensitive_store = Some(found);
        }
    }

    if detected_sensitive_store.is_none() {
        if let Some(args) = &req.arguments {
            if let Some(found) = osoosi_dp::sensitive_paths::scan_json_for_sensitive_path(args) {
                detected_sensitive_store = Some(found);
            }
        }
    }

    if detected_sensitive_store.is_none() {
        if let Some(cmd) = &req.command {
            if let Some(found) = osoosi_dp::sensitive_paths::scan_for_sensitive_system_path(cmd) {
                detected_sensitive_store = Some(found);
            }
        }
    }

    if let Some((store_kind, matched_path)) = detected_sensitive_store {
        let duration_us = start_instant.elapsed().as_micros() as u64;
        let decision = HookEvaluationDecision::deny(
            format!(
                "Access to sensitive system credential store blocked: {} ('{}')",
                store_kind.description(),
                matched_path
            ),
            Some("SensitiveSystemPathGuard"),
            Some("Access to root credential databases (/etc/shadow, SAM, SYSTEM) is strictly forbidden"),
            duration_us,
        );
        record_decision(req, &decision);
        return decision;
    }

    // Layer 1: SemanticCommandAst (Structural privilege escalation AST parsing)
    if let Some(cmd) = &req.command {
        let sem = parse_semantic_command(cmd);
        if sem.privilege_class == PrivilegeEquivalenceClass::RootOrAdminElevation
            || sem.privilege_class == PrivilegeEquivalenceClass::TargetUserDelegation
        {
            let duration_us = start_instant.elapsed().as_micros() as u64;
            let decision = HookEvaluationDecision::deny(
                format!("Privileged command elevation rejected: '{cmd}'"),
                Some("Layer 1: SemanticCommandAst"),
                Some("Execute unprivileged commands or obtain signed authorization"),
                duration_us,
            );
            record_decision(req, &decision);
            return decision;
        }
    }

    // Layer 2: DynamicBinaryMetadataProbe (On-disk SUID/SGID/Capabilities/PE)
    if let Some(cmd) = &req.command {
        let tokens = crate::semantic_command::tokenize_command(cmd);
        if let Some(first) = tokens.first() {
            let target_path = Path::new(first);
            if target_path.exists() {
                if let Ok(probe) = DynamicBinaryMetadataProbe::probe_path(target_path) {
                    if probe.is_privileged_target() {
                        let duration_us = start_instant.elapsed().as_micros() as u64;
                        let decision = HookEvaluationDecision::deny(
                            format!(
                                "Target binary on disk requires administrator privileges: '{}'",
                                target_path.display()
                            ),
                            Some("Layer 2: DynamicBinaryMetadataProbe"),
                            Some("Target unprivileged binaries"),
                            duration_us,
                        );
                        record_decision(req, &decision);
                        return decision;
                    }
                }
            }
        }
    }

    // Layer 3: SemanticDlpEngine (Structured entity and PHI/PII classification)
    let mut payload_to_inspect = String::new();
    if let Some(cmd) = &req.command {
        payload_to_inspect.push_str(cmd);
        payload_to_inspect.push(' ');
    }
    if let Some(path) = &req.file_path {
        payload_to_inspect.push_str(path);
        payload_to_inspect.push(' ');
    }
    if let Some(args) = &req.arguments {
        let s = args.to_string();
        for ch in s.chars() {
            if ch == '{'
                || ch == '}'
                || ch == '['
                || ch == ']'
                || ch == ':'
                || ch == ','
                || ch == '"'
            {
                payload_to_inspect.push(' ');
                payload_to_inspect.push(ch);
                payload_to_inspect.push(' ');
            } else {
                payload_to_inspect.push(ch);
            }
        }
    }

    if !payload_to_inspect.trim().is_empty() {
        let dlp_engine = osoosi_dp::semantic_dlp::SemanticDlpEngine::new();
        let entities = dlp_engine.scan_payload(&payload_to_inspect);
        let has_sensitive = entities.iter().any(|e| {
            matches!(
                e.kind,
                osoosi_dp::semantic_dlp::SemanticEntityKind::PhiMedicalRecord
                    | osoosi_dp::semantic_dlp::SemanticEntityKind::PaymentCard
                    | osoosi_dp::semantic_dlp::SemanticEntityKind::DealValue
                    | osoosi_dp::semantic_dlp::SemanticEntityKind::SecretKey
                    | osoosi_dp::semantic_dlp::SemanticEntityKind::UnclassifiedSensitive
            )
        });

        if has_sensitive {
            let duration_us = start_instant.elapsed().as_micros() as u64;
            let decision = HookEvaluationDecision::deny(
                format!("Sensitive data or PHI/PII entity detected: {:?}", entities),
                Some("Layer 3: SemanticDlpEngine"),
                Some("Scrub sensitive records before tool execution"),
                duration_us,
            );
            record_decision(req, &decision);
            return decision;
        }
    }

    // Layer 4: TemporalCircumventionCorrelator (Incident A circumvention memory)
    if let Some(cmd) = &req.command {
        let now = Instant::now();
        if let Some(alert) = GLOBAL_CORRELATOR.check_candidate(session_id, None, cmd, now) {
            let duration_us = start_instant.elapsed().as_micros() as u64;
            let decision = HookEvaluationDecision::deny(
                alert.summary,
                Some("Layer 4: TemporalCircumventionCorrelator"),
                Some("Incident A cross-boundary circumvention attempt blocked"),
                duration_us,
            );
            record_decision(req, &decision);
            return decision;
        }

        let sem = parse_semantic_command(cmd);
        if is_cross_boundary_invocation(cmd, &sem) && GLOBAL_CORRELATOR.active_denial_count() > 0 {
            let duration_us = start_instant.elapsed().as_micros() as u64;
            let decision = HookEvaluationDecision::deny(
                format!("Incident A cross-boundary execution denied: '{cmd}'"),
                Some("Layer 4: TemporalCircumventionCorrelator"),
                Some("Do not attempt cross-boundary retry"),
                duration_us,
            );
            record_decision(req, &decision);
            return decision;
        }
    }

    // Layer 5: ApcPolicyDecisionPoint (Bounded Agents APC action class gating)
    let action_candidate = req
        .command
        .as_deref()
        .or(req.tool_name.as_deref())
        .unwrap_or("READ_PUBLIC");
    let action_class = classify_action_class(action_candidate);
    if action_class == "PRIVILEGED_EXECUTION" {
        let duration_us = start_instant.elapsed().as_micros() as u64;
        let decision = HookEvaluationDecision::deny(
            format!("Bounded Agents APC Action Class 'PRIVILEGED_EXECUTION' blocked for '{action_candidate}'"),
            Some("Layer 5: ApcPolicyDecisionPoint"),
            Some("Action requires signed approval token envelope"),
            duration_us,
        );
        record_decision(req, &decision);
        return decision;
    }

    // Layer 6: CageGovernance (High consequence action checks)
    if let Some(args) = &req.arguments {
        if let Some(amount) = args.get("amount_usd").and_then(|v| v.as_f64()) {
            if amount >= 100_000.0 {
                let duration_us = start_instant.elapsed().as_micros() as u64;
                let decision = HookEvaluationDecision::deny(
                    format!("Fiscal transfer of ${:.2} exceeds unverified limit", amount),
                    Some("Layer 6: CageGovernanceKernel"),
                    Some("Fiscal transfers >= $100k require two-person cryptographic signoff"),
                    duration_us,
                );
                record_decision(req, &decision);
                return decision;
            }
        }
        if let Some(dose) = args.get("dose_mg").and_then(|v| v.as_f64()) {
            if dose > 500.0 {
                let duration_us = start_instant.elapsed().as_micros() as u64;
                let decision = HookEvaluationDecision::deny(
                    format!("Clinical dose of {:.2}mg exceeds safe threshold", dose),
                    Some("Layer 6: CageGovernanceKernel"),
                    Some("High dosage medical interventions require physician confirmation"),
                    duration_us,
                );
                record_decision(req, &decision);
                return decision;
            }
        }
    }

    // All 6 layers cleared
    let duration_us = start_instant.elapsed().as_micros() as u64;
    let decision = HookEvaluationDecision::allow(
        "Execution cleared all 6 OshoosiClaw security layers",
        duration_us,
    );
    record_decision(req, &decision);
    decision
}

fn record_decision(req: &NormalizedHookRequest, decision: &HookEvaluationDecision) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let event_id = format!("intercept-{}", EVENT_COUNTER.fetch_add(1, Ordering::SeqCst));
    let record = AgentInterceptionRecord {
        event_id,
        timestamp_ns: now,
        timestamp_utc: chrono::Utc::now().to_rfc3339(),
        agent: req.agent.as_str().to_string(),
        event_type: req.event_type.as_str().to_string(),
        tool_name: req.tool_name.clone().unwrap_or_default(),
        command: req.command.clone().unwrap_or_default(),
        allowed: decision.allowed,
        rationale: decision.rationale.clone(),
        denied_by_layer: decision.denied_by_layer.clone(),
    };
    record_interception_event(record);
}

// ============================================================================
// Agent Hook Configuration Installer
// ============================================================================

pub fn install_agent_hooks(
    workspace: &Path,
    agents: &[SupportedAgentKind],
    osoosi_bin: &Path,
) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut installed_paths = Vec::new();
    let bin_path_str = osoosi_bin.to_string_lossy().into_owned();

    for agent in agents {
        match agent {
            SupportedAgentKind::Claude => {
                let dir = workspace.join(".claude");
                std::fs::create_dir_all(&dir)?;
                let file_path = dir.join("settings.json");
                let config = serde_json::json!({
                    "hooks": {
                        "PreToolUse": [
                            {
                                "matcher": ".*",
                                "command": format!("\"{}\" hook evaluate --agent claude", bin_path_str)
                            }
                        ],
                        "PostToolUse": [
                            {
                                "matcher": ".*",
                                "command": format!("\"{}\" hook evaluate --agent claude --post", bin_path_str)
                            }
                        ]
                    }
                });
                std::fs::write(&file_path, serde_json::to_string_pretty(&config)?)?;
                installed_paths.push(file_path);
            }
            SupportedAgentKind::Cursor => {
                let dir = workspace.join(".cursor");
                std::fs::create_dir_all(&dir)?;
                let file_path = dir.join("hooks.json");
                let config = serde_json::json!({
                    "version": 1,
                    "hooks": {
                        "beforeShellExecution": [
                            {
                                "command": format!("\"{}\" hook evaluate --agent cursor --event beforeShellExecution", bin_path_str)
                            }
                        ],
                        "afterShellExecution": [
                            {
                                "command": format!("\"{}\" hook evaluate --agent cursor --event afterShellExecution", bin_path_str)
                            }
                        ],
                        "beforeMCPExecution": [
                            {
                                "command": format!("\"{}\" hook evaluate --agent cursor --event beforeMCPExecution", bin_path_str)
                            }
                        ],
                        "beforeReadFile": [
                            {
                                "command": format!("\"{}\" hook evaluate --agent cursor --event beforeReadFile", bin_path_str)
                            }
                        ]
                    }
                });
                std::fs::write(&file_path, serde_json::to_string_pretty(&config)?)?;
                installed_paths.push(file_path);
            }
            SupportedAgentKind::Copilot => {
                let dir = workspace.join(".github").join("hooks");
                std::fs::create_dir_all(&dir)?;
                let file_path = dir.join("killswitch.json");
                let config = serde_json::json!({
                    "version": "1.0",
                    "hooks": {
                        "preToolUse": [
                            {
                                "type": "command",
                                "exec": format!("\"{}\" hook evaluate --agent copilot --event preToolUse", bin_path_str)
                            }
                        ],
                        "postToolUse": [
                            {
                                "type": "command",
                                "exec": format!("\"{}\" hook evaluate --agent copilot --event postToolUse", bin_path_str)
                            }
                        ]
                    }
                });
                std::fs::write(&file_path, serde_json::to_string_pretty(&config)?)?;
                installed_paths.push(file_path);
            }
            SupportedAgentKind::OpenCode => {
                let dir = workspace.join(".opencode").join("plugin");
                std::fs::create_dir_all(&dir)?;
                let file_path = dir.join("killswitch-guard.js");
                let script = format!(
                    r#"// OpenCode OshoosiClaw PEP Guard Plugin
const {{ execFileSync }} = require('child_process');

module.exports = {{
    name: 'oshoosi-guard',
    onToolExecuteBefore(tool, args) {{
        const payload = JSON.stringify({{ tool, args, type: 'before' }});
        try {{
            const out = execFileSync('{bin}', ['hook', 'evaluate', '--agent', 'opencode'], {{
                input: payload,
                encoding: 'utf-8'
            }});
            const res = JSON.parse(out);
            if (!res.allow) {{
                throw new Error('OshoosiClaw PEP Denied: ' + res.reason);
            }}
        }} catch (err) {{
            throw new Error('OshoosiClaw Execution Blocked: ' + err.message);
        }}
    }}
}};
"#,
                    bin = bin_path_str.replace('\\', "\\\\")
                );
                std::fs::write(&file_path, script)?;
                installed_paths.push(file_path);
            }
            SupportedAgentKind::Mcp => {}
        }
    }

    Ok(installed_paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_synonyms_extraction() {
        let json_val = serde_json::json!({
            "name": "bash",
            "cmd": "ls -la",
            "uri": "/tmp/test.txt",
            "tool_use_id": "session-123",
            "exitCode": 0
        });

        assert_eq!(extract_wire_tool_name(&json_val), Some("bash".to_string()));
        assert_eq!(extract_wire_command(&json_val), Some("ls -la".to_string()));
        assert_eq!(
            extract_wire_file_path(&json_val),
            Some("/tmp/test.txt".to_string())
        );
        assert_eq!(
            extract_wire_session_id(&json_val),
            Some("session-123".to_string())
        );
        assert_eq!(extract_wire_exit_code(&json_val), Some(0));
    }

    #[test]
    fn test_mcp_error_formatting_preserves_id() {
        let id = serde_json::json!("req-999");
        let decision =
            HookEvaluationDecision::deny("Root access denied", Some("Layer 1"), None, 100);
        let resp_str = format_mcp_error_response(&id, &decision);
        let resp_json: serde_json::Value = serde_json::from_str(&resp_str).unwrap();

        assert_eq!(resp_json["id"], "req-999");
        assert_eq!(resp_json["jsonrpc"], "2.0");
        assert!(resp_json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Root access denied"));
    }

    #[test]
    fn test_pipeline_blocks_sensitive_path() {
        let req = NormalizedHookRequest {
            command: Some("cat /etc/shadow".to_string()),
            ..Default::default()
        };
        let decision = evaluate_hook_synchronously(&req);
        assert!(!decision.allowed);
        assert!(decision
            .denied_by_layer
            .as_deref()
            .unwrap()
            .contains("SensitiveSystemPathGuard"));
    }

    #[test]
    fn test_pipeline_blocks_sudo_elevation() {
        let req = NormalizedHookRequest {
            command: Some("sudo id".to_string()),
            ..Default::default()
        };
        let decision = evaluate_hook_synchronously(&req);
        assert!(!decision.allowed);
    }
}
