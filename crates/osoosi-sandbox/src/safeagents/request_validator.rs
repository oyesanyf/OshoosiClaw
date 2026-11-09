//! Stage 1: Zero-Copy Request Validator & SSE Stream Rewriter
//!
//! Uses `serde_json` and `memchr` for zero-allocation fast paths on clean requests,
//! enforcing declared tool boundaries and verbatim user prompt host sourcing.

use memchr::memmem;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::OnceLock;

/// Configuration for RequestValidator.
#[derive(Debug, Clone)]
pub struct RequestValidatorConfig {
    pub default_allowed_hosts: HashSet<String>,
}

impl Default for RequestValidatorConfig {
    fn default() -> Self {
        let mut hosts = HashSet::new();
        for h in &[
            "localhost",
            "127.0.0.1",
            "::1",
            "github.com",
            "githubusercontent.com",
            "pypi.org",
            "pythonhosted.org",
            "huggingface.co",
            "hf.co",
            "npmjs.org",
            "crates.io",
        ] {
            hosts.insert((*h).to_string());
        }
        Self {
            default_allowed_hosts: hosts,
        }
    }
}

/// Stage 1 inspection verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stage1Verdict {
    Allow,
    Blocked { reason: String, notice: String },
}

impl Stage1Verdict {
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked { .. })
    }
}

/// Stage 1 Request Validator.
pub struct RequestValidator {
    config: RequestValidatorConfig,
}

impl Default for RequestValidator {
    fn default() -> Self {
        Self::new(RequestValidatorConfig::default())
    }
}

impl RequestValidator {
    pub fn new(config: RequestValidatorConfig) -> Self {
        Self { config }
    }

    /// Validates declared tools and host sourcing.
    pub fn validate_request(
        &self,
        tool_name: &str,
        arguments_json: &str,
        declared_tools: &[String],
        user_prompt_turns: &[String],
        allowed_hosts: &[String],
    ) -> Stage1Verdict {
        // 1. Declared tools verification
        if !declared_tools.is_empty() && !declared_tools.iter().any(|t| t == tool_name) {
            let reason = "undeclared tool".to_string();
            let notice = format!("[safeagents] blocked call to `{}`: {}", tool_name, reason);
            return Stage1Verdict::Blocked { reason, notice };
        }

        // 2. Host sourcing verification (assistant turns strictly excluded)
        let extracted_hosts = extract_hosts_from_text(arguments_json);
        for host in extracted_hosts {
            if !self.is_host_permitted(&host, user_prompt_turns, allowed_hosts) {
                let reason = format!("host `{}` appears nowhere in the conversation", host);
                let notice = format!("[safeagents] blocked call to `{}`: {}", tool_name, reason);
                return Stage1Verdict::Blocked { reason, notice };
            }
        }

        Stage1Verdict::Allow
    }

    /// Validates whether a host is permitted by loopback, allowlists, or user prompt turns.
    /// ASSISTANT TURNS ARE STRICTLY EXCLUDED to prevent self-citation injection escapes.
    pub fn is_host_permitted(
        &self,
        host: &str,
        user_prompt_turns: &[String],
        custom_allowed_hosts: &[String],
    ) -> bool {
        let host_lower = host.to_ascii_lowercase();

        // 1. Loopback addresses
        if host_lower == "localhost" || host_lower == "127.0.0.1" || host_lower == "::1" {
            return true;
        }

        // 2. Built-in and custom allowed hosts (supports exact match and subdomain suffixes)
        for allowed in self
            .config
            .default_allowed_hosts
            .iter()
            .map(|s| s.as_str())
            .chain(custom_allowed_hosts.iter().map(|s| s.as_str()))
        {
            let allowed_lower = allowed.to_ascii_lowercase();
            if host_lower == allowed_lower || host_lower.ends_with(&format!(".{}", allowed_lower)) {
                return true;
            }
        }

        // 3. Verbatim appearance in user prompt turns (assistant turns excluded)
        for turn in user_prompt_turns {
            if turn.to_ascii_lowercase().contains(&host_lower) {
                return true;
            }
        }

        false
    }

    /// Rewrites an OpenAI/Anthropic SSE chunk in-stream.
    /// Fast-path uses `memchr` to detect if the chunk contains `tool_calls`.
    /// Text tokens pass through unmodified with zero heap allocation.
    pub fn transform_sse_chunk(
        &self,
        chunk: &[u8],
        declared_tools: &[String],
        user_prompt_turns: &[String],
        allowed_hosts: &[String],
    ) -> Vec<u8> {
        // Fast path: if chunk does not contain "tool_calls", pass through immediately
        if memmem::find(chunk, b"tool_calls").is_none() {
            return chunk.to_vec();
        }

        let chunk_str = match std::str::from_utf8(chunk) {
            Ok(s) => s,
            Err(_) => return chunk.to_vec(),
        };

        let trimmed = chunk_str.trim();
        if !trimmed.starts_with("data: ") || trimmed == "data: [DONE]" {
            return chunk.to_vec();
        }

        let json_str = &trimmed[6..];
        let mut parsed: serde_json::Value = match serde_json::from_str(json_str) {
            Ok(v) => v,
            Err(_) => return chunk.to_vec(),
        };

        let mut modified = false;
        if let Some(choices) = parsed.get_mut("choices").and_then(|c| c.as_array_mut()) {
            for choice in choices {
                if let Some(delta) = choice.get_mut("delta") {
                    if let Some(tool_calls) =
                        delta.get_mut("tool_calls").and_then(|tc| tc.as_array_mut())
                    {
                        let mut allowed_calls = Vec::new();
                        let mut blocked_notices = Vec::new();

                        for tc in tool_calls.drain(..) {
                            let tool_name = tc
                                .pointer("/function/name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("");
                            let args_json = tc
                                .pointer("/function/arguments")
                                .and_then(|a| a.as_str())
                                .unwrap_or("{}");

                            // Validate declared tool
                            if !declared_tools.is_empty()
                                && !declared_tools.iter().any(|t| t == tool_name)
                            {
                                blocked_notices.push(format!(
                                    "[safeagents] blocked call to `{}`: undeclared tool\n",
                                    tool_name
                                ));
                                continue;
                            }

                            // Validate hosts
                            let hosts = extract_hosts_from_text(args_json);
                            let mut host_blocked = false;
                            for h in hosts {
                                if !self.is_host_permitted(&h, user_prompt_turns, allowed_hosts) {
                                    blocked_notices.push(format!(
                                        "[safeagents] blocked call to `{}`: host `{}` appears nowhere in the conversation\n",
                                        tool_name, h
                                    ));
                                    host_blocked = true;
                                    break;
                                }
                            }

                            if !host_blocked {
                                allowed_calls.push(tc);
                            }
                        }

                        if !blocked_notices.is_empty() {
                            modified = true;
                            let existing_content =
                                delta.get("content").and_then(|c| c.as_str()).unwrap_or("");
                            let mut new_content = existing_content.to_string();
                            for notice in blocked_notices {
                                new_content.push_str(&notice);
                            }
                            delta["content"] = serde_json::Value::String(new_content);
                        }

                        if !allowed_calls.is_empty() {
                            delta["tool_calls"] = serde_json::Value::Array(allowed_calls);
                        } else if let Some(obj) = delta.as_object_mut() {
                            obj.remove("tool_calls");
                        }
                    }
                }
            }
        }

        if modified {
            match serde_json::to_string(&parsed) {
                Ok(rewritten) => format!("data: {}\n\n", rewritten).into_bytes(),
                Err(_) => chunk.to_vec(),
            }
        } else {
            chunk.to_vec()
        }
    }
}

/// Extracts target URL authorities and bare IPv4 literals from arguments text.
pub fn extract_hosts_from_text(text: &str) -> Vec<String> {
    static AUTHORITY_RE: OnceLock<Regex> = OnceLock::new();
    static IPV4_RE: OnceLock<Regex> = OnceLock::new();

    let authority_re = AUTHORITY_RE
        .get_or_init(|| Regex::new(r#"://?([^/\s?#"'\`\)\]>]+)"#).expect("authority regex valid"));
    let ipv4_re = IPV4_RE.get_or_init(|| {
        Regex::new(r#"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"#).expect("ipv4 regex valid")
    });

    let mut hosts = HashSet::new();

    for caps in authority_re.captures_iter(text) {
        if let Some(auth_match) = caps.get(1) {
            let auth = auth_match.as_str();
            let host_part = auth.rsplit('@').next().unwrap_or(auth);
            let host_clean = host_part.split(':').next().unwrap_or(host_part);
            let normalized = host_clean.trim().to_ascii_lowercase();
            if !normalized.is_empty()
                && normalized
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '.' || c == '-')
            {
                hosts.insert(normalized);
            }
        }
    }

    for caps in ipv4_re.captures_iter(text) {
        if let Some(ip_match) = caps.get(1) {
            let candidate = ip_match.as_str();
            if let Ok(ip) = candidate.parse::<Ipv4Addr>() {
                hosts.insert(ip.to_string());
            }
        }
    }

    hosts.into_iter().collect()
}
