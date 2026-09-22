//! AI Security Audit Policy Voter (Cloudflare Attack Classes Realization)
//!
//! Realizes active host-level detection for the AI/LLM attack classes documented
//! in Cloudflare's security-audit framework (`AI-AND-LLM.md`, `MEMORY-SAFETY-AND-BINARY.md`):
//! 1. Tool-Argument Injection (Downstream sink exploitation via shell metachars or path traversal).
//! 2. Persistent Agent Memory & Config Poisoning (Unauthorized modifications to agent memory/rules).
//! 3. Process Memory Safety & Remote Thread Tampering (Process injection into AI agent runtimes).

use async_trait::async_trait;
use osoosi_types::HostSecurityEvent;
use crate::engine::{ThreatVoter, VoteResult};
use regex::Regex;
use serde_json::Value;
use tracing::warn;

/// Threat voter realizing Cloudflare AI & LLM security audit attack classes.
pub struct AiSecurityAuditVoter {
    ai_runtime_regex: Regex,
    shell_injection_regex: Regex,
    path_traversal_regex: Regex,
    protected_config_regex: Regex,
}

impl Default for AiSecurityAuditVoter {
    fn default() -> Self {
        Self::new()
    }
}

impl AiSecurityAuditVoter {
    pub fn new() -> Self {
        // AI runtimes: python, node, cargo, ollama, uv, deno, code, cursor, gemini, anthropic
        let ai_runtime_regex = Regex::new(
            r"(?i)(?:^|[\\/])(python3?|node|cargo|ollama|uv|deno|code|cursor|gemini|anthropic)(?:\.exe)?$"
        ).expect("Valid AI runtime regex");

        // Tool-Argument Injection: shell metacharacters, subshell executions, dangerous flags
        let shell_injection_regex = Regex::new(
            r#"(?i)(;\s*(?:rm|del|curl|wget|bash|sh|cmd|powershell|pwsh)\b|&&|\|\||`[^`]+`|\$\([^\)]+\)|-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{8,}|\b(?:Invoke-Expression|IEX|DownloadString|DownloadFile)\b)"#
        ).expect("Valid shell injection regex");

        // Path Traversal in tool arguments targeting sensitive resources
        let path_traversal_regex = Regex::new(
            r#"(?i)(?:\.\.[\\/]|%2e%2e[\\/])+(?:etc[\\/](?:passwd|shadow)|windows[\\/]system32|\.ssh|\.aws|\.env|id_rsa)"#
        ).expect("Valid path traversal regex");

        // Protected agent state and configuration files
        let protected_config_regex = Regex::new(
            r#"(?i)(?:\.agents[\\/](?:memory\.md|rules[\\/]|AGENTS\.md)|osoosi\.toml|config[\\/][^\\/]+\.json|\.env)"#
        ).expect("Valid protected config regex");

        Self {
            ai_runtime_regex,
            shell_injection_regex,
            path_traversal_regex,
            protected_config_regex,
        }
    }

    /// Check if image represents an AI agent runtime.
    pub fn is_ai_runtime(&self, image: &str) -> bool {
        let path = std::path::Path::new(image);
        let file_name = path.file_name().and_then(|f| f.to_str()).unwrap_or(image);
        self.ai_runtime_regex.is_match(file_name)
    }

    /// Evaluate security event against Cloudflare AI audit attack classes.
    pub fn evaluate_event(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        match event.event_id {
            // Sysmon Event 1: Process Creation / Tool Execution
            1 => self.evaluate_process_creation(event),

            // Sysmon Event 11: File Create / File Modification (Persistent Memory Poisoning)
            11 => self.evaluate_file_event(event),

            // Sysmon Event 8: CreateRemoteThread (Process Memory Injection)
            8 => self.evaluate_remote_thread(event),

            // Sysmon Event 10: ProcessAccess (Memory Tampering)
            10 => self.evaluate_process_access(event),

            _ => None,
        }
    }

    /// Evaluates Sysmon Event 1 for Tool-Argument Injection.
    fn evaluate_process_creation(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        let image = event.data.get("Image").and_then(|v| v.as_str()).unwrap_or("");
        let parent_image = event.data.get("ParentImage").and_then(|v| v.as_str()).unwrap_or("");
        let cmd_line = event.data.get("CommandLine").and_then(|v| v.as_str()).unwrap_or("");

        let self_is_ai = self.is_ai_runtime(image);
        let parent_is_ai = self.is_ai_runtime(parent_image);

        if !self_is_ai && !parent_is_ai {
            return None;
        }

        let pid = event.data.get("ProcessId")
            .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse::<u64>().ok())))
            .unwrap_or(0);

        // 1. Check for Tool-Argument Shell Injection
        if let Some(m) = self.shell_injection_regex.find(cmd_line) {
            warn!(
                pid = pid,
                matched = m.as_str(),
                cmd = cmd_line,
                "Cloudflare Attack Class Detected: AI Tool-Argument Injection into downstream sink"
            );

            return Some(VoteResult {
                confidence: 0.95,
                reason: format!(
                    "AI Tool-Argument Injection [MITRE ATLAS AML.T0043 / Cloudflare AI-AND-LLM]: Process '{}' (PID {}) spawned with command chaining or shell injection pattern '{}' in CommandLine: {}",
                    image, pid, m.as_str(), cmd_line
                ),
                weight: 1.0,
            });
        }

        // 2. Check for Tool-Argument Path Traversal
        if let Some(m) = self.path_traversal_regex.find(cmd_line) {
            warn!(
                pid = pid,
                matched = m.as_str(),
                cmd = cmd_line,
                "Cloudflare Attack Class Detected: AI Tool Path Traversal into sensitive target"
            );

            return Some(VoteResult {
                confidence: 0.94,
                reason: format!(
                    "AI Tool Path Traversal [MITRE ATLAS AML.T0044 / Insecure Output]: Process '{}' (PID {}) supplied traversal targeting sensitive asset '{}' in CommandLine: {}",
                    image, pid, m.as_str(), cmd_line
                ),
                weight: 0.95,
            });
        }

        None
    }

    /// Evaluates Sysmon Event 11 for Persistent Agent Memory & Config Poisoning.
    fn evaluate_file_event(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        let image = event.data.get("Image").and_then(|v| v.as_str()).unwrap_or("");
        let target_file = event.data.get("TargetFilename").and_then(|v| v.as_str()).unwrap_or("");

        // Check if the modified target is an agent memory/rule/config file
        if let Some(m) = self.protected_config_regex.find(target_file) {
            // If modified by an untrusted worker runtime or script
            let pid = event.data.get("ProcessId")
                .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse::<u64>().ok())))
                .unwrap_or(0);

            warn!(
                pid = pid,
                target = target_file,
                image = image,
                "Cloudflare Attack Class Detected: Persistent Agent Memory / State Poisoning Attempt"
            );

            return Some(VoteResult {
                confidence: 0.92,
                reason: format!(
                    "Agent Memory & State Poisoning [MITRE ATLAS AML.T0048 / Persistence]: Process '{}' (PID {}) attempted unauthorized modification of protected agent asset '{}'",
                    image, pid, m.as_str()
                ),
                weight: 0.95,
            });
        }

        None
    }

    /// Evaluates Sysmon Event 8 for Remote Thread Injection into AI Agent Runtimes.
    fn evaluate_remote_thread(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        let source_image = event.data.get("SourceImage").and_then(|v| v.as_str()).unwrap_or("");
        let target_image = event.data.get("TargetImage").and_then(|v| v.as_str()).unwrap_or("");

        // If target is an AI agent runtime being injected into by an external process
        if self.is_ai_runtime(target_image) && !self.is_ai_runtime(source_image) {
            let source_pid = event.data.get("SourceProcessId")
                .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse::<u64>().ok())))
                .unwrap_or(0);
            let target_pid = event.data.get("TargetProcessId")
                .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse::<u64>().ok())))
                .unwrap_or(0);

            warn!(
                source = source_image,
                source_pid = source_pid,
                target = target_image,
                target_pid = target_pid,
                "Cloudflare Attack Class Detected: Remote Thread Injection into AI Runtime"
            );

            return Some(VoteResult {
                confidence: 0.98,
                reason: format!(
                    "AI Runtime Remote Thread Injection [MITRE ATLAS AML.T0040 / Execution Environment Compromise]: Non-AI process '{}' (PID {}) injected remote thread into AI agent runtime '{}' (PID {})",
                    source_image, source_pid, target_image, target_pid
                ),
                weight: 1.0,
            });
        }

        None
    }

    /// Evaluates Sysmon Event 10 for Process Memory Access with write privileges into Agent Runtimes.
    fn evaluate_process_access(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        let source_image = event.data.get("SourceImage").and_then(|v| v.as_str()).unwrap_or("");
        let target_image = event.data.get("TargetImage").and_then(|v| v.as_str()).unwrap_or("");
        let granted_access = event.data.get("GrantedAccess").and_then(|v| v.as_str()).unwrap_or("");

        // If targeting an AI agent runtime
        if self.is_ai_runtime(target_image) && !self.is_ai_runtime(source_image) {
            // PROCESS_VM_WRITE (0x0020) or PROCESS_VM_OPERATION (0x0010) or PROCESS_ALL_ACCESS (0x1F0FFF)
            let is_write_access = granted_access.contains("0x0020")
                || granted_access.contains("0x1F0FFF")
                || granted_access.contains("0x1F1FFF")
                || granted_access.contains("0x0010");

            if is_write_access {
                let source_pid = event.data.get("SourceProcessId")
                    .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse::<u64>().ok())))
                    .unwrap_or(0);
                let target_pid = event.data.get("TargetProcessId")
                    .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse::<u64>().ok())))
                    .unwrap_or(0);

                return Some(VoteResult {
                    confidence: 0.91,
                    reason: format!(
                        "AI Runtime Memory Tampering [MITRE ATLAS AML.T0029 / Disarm AI Safeguards]: Non-AI process '{}' (PID {}) requested memory tampering access ({}) into AI agent runtime '{}' (PID {})",
                        source_image, source_pid, granted_access, target_image, target_pid
                    ),
                    weight: 0.90,
                });
            }
        }

        None
    }
}

#[async_trait]
impl ThreatVoter for AiSecurityAuditVoter {
    fn name(&self) -> String {
        "Ai-Security-Audit-Voter".to_string()
    }

    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        self.evaluate_event(event)
    }

    fn stats(&self) -> Value {
        serde_json::json!({
            "voter": "Ai-Security-Audit-Voter",
            "active": true
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use osoosi_types::HostEventSource;
    use serde_json::json;

    fn make_test_event(event_id: u32, data: Value) -> HostSecurityEvent {
        HostSecurityEvent {
            source: HostEventSource::WindowsEventLog,
            event_id,
            timestamp: Utc::now(),
            computer: "AUDIT-AGENT-01".to_string(),
            data,
            causal_parent: None,
        }
    }

    #[test]
    fn test_benign_agent_tool_execution() {
        let voter = AiSecurityAuditVoter::new();

        // Benign cargo build executed by python agent
        let ev = make_test_event(1, json!({
            "ParentImage": "C:\\Python311\\python.exe",
            "Image": "C:\\Users\\user\\.cargo\\bin\\cargo.exe",
            "CommandLine": "cargo test --lib",
            "ProcessId": 1234
        }));

        assert!(voter.evaluate_event(&ev).is_none());
    }

    #[test]
    fn test_tool_argument_shell_injection() {
        let voter = AiSecurityAuditVoter::new();

        // Downstream command injection inside tool argument
        let ev = make_test_event(1, json!({
            "ParentImage": "C:\\Python311\\python.exe",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c echo test; rm -rf /",
            "ProcessId": 5678
        }));

        let vote = voter.evaluate_event(&ev);
        assert!(vote.is_some());
        let v = vote.unwrap();
        assert_eq!(v.confidence, 0.95);
        assert!(v.reason.contains("AI Tool-Argument Injection"));
        assert!(v.reason.contains("AML.T0043"));
    }

    #[test]
    fn test_tool_argument_path_traversal() {
        let voter = AiSecurityAuditVoter::new();

        // Downstream path traversal into sensitive system asset
        let ev = make_test_event(1, json!({
            "ParentImage": "C:\\Program Files\\nodejs\\node.exe",
            "Image": "C:\\Windows\\System32\\tar.exe",
            "CommandLine": "tar -xf archive.tar -C ../../Windows/System32",
            "ProcessId": 9012
        }));

        let vote = voter.evaluate_event(&ev);
        assert!(vote.is_some());
        let v = vote.unwrap();
        assert_eq!(v.confidence, 0.94);
        assert!(v.reason.contains("AI Tool Path Traversal"));
        assert!(v.reason.contains("AML.T0044"));
    }

    #[test]
    fn test_agent_memory_poisoning_attempt() {
        let voter = AiSecurityAuditVoter::new();

        // Unauthorized process writing to .agents/memory.md
        let ev = make_test_event(11, json!({
            "Image": "C:\\Python311\\python.exe",
            "TargetFilename": "D:\\harfile\\OshoosiClaw\\.agents\\memory.md",
            "ProcessId": 3344
        }));

        let vote = voter.evaluate_event(&ev);
        assert!(vote.is_some());
        let v = vote.unwrap();
        assert_eq!(v.confidence, 0.92);
        assert!(v.reason.contains("Agent Memory & State Poisoning"));
        assert!(v.reason.contains("AML.T0048"));
    }

    #[test]
    fn test_remote_thread_injection_into_agent() {
        let voter = AiSecurityAuditVoter::new();

        // External malicious process creating remote thread in python.exe
        let ev = make_test_event(8, json!({
            "SourceImage": "C:\\Temp\\injector.exe",
            "SourceProcessId": 7788,
            "TargetImage": "C:\\Python311\\python.exe",
            "TargetProcessId": 1122
        }));

        let vote = voter.evaluate_event(&ev);
        assert!(vote.is_some());
        let v = vote.unwrap();
        assert_eq!(v.confidence, 0.98);
        assert!(v.reason.contains("AI Runtime Remote Thread Injection"));
        assert!(v.reason.contains("AML.T0040"));
    }

    #[test]
    fn test_runtime_memory_tampering() {
        let voter = AiSecurityAuditVoter::new();

        // External malicious process requesting write/tampering access to python.exe runtime
        let ev = make_test_event(10, json!({
            "SourceImage": "C:\\Temp\\injector.exe",
            "SourceProcessId": 7788,
            "TargetImage": "C:\\Python311\\python.exe",
            "TargetProcessId": 1122,
            "GrantedAccess": "0x1F0FFF"
        }));

        let vote = voter.evaluate_event(&ev);
        assert!(vote.is_some());
        let v = vote.unwrap();
        assert_eq!(v.confidence, 0.91);
        assert!(v.reason.contains("AI Runtime Memory Tampering"));
        assert!(v.reason.contains("AML.T0029"));
    }
}
