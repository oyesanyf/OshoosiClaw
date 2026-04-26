//! WASM Sandbox Security Model.
//!
//! Implements defense-in-depth:
//! - WASM provenance verification (hash allowlist)
//! - URL allowlist (deny-by-default)
//! - Command whitelist (deny-by-default)
//! - Query table restrictions
//! - Per-session rate limiting

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Security configuration for the WASM sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSecurityConfig {
    /// Allowed WASM module hashes (blake3 hex). Empty = allow all (insecure).
    pub allowed_wasm_hashes: HashSet<String>,
    /// Require WASM hash to be in allowlist. If true and allowlist empty, reject all.
    pub wasm_hash_required: bool,
    /// Allowed URL host patterns (e.g. "api.example.com", "*.trusted.org"). Empty = deny all outbound.
    pub url_allowlist: Vec<String>,
    /// If true, use allowlist; if false, use blocklist only (legacy).
    pub url_allowlist_mode: bool,
    /// Allowed programs for exec (e.g. "clamscan", "whoami"). Empty = deny all.
    pub command_whitelist: Vec<String>,
    /// If true, use whitelist; if false, use blocklist only (legacy).
    pub command_whitelist_mode: bool,
    /// Allowed table names in SELECT (e.g. "threats", "kev"). Empty = allow all tables.
    pub query_allowed_tables: Vec<String>,
    /// If true, restrict SELECT to allowed_tables only.
    pub query_restrict_tables: bool,
    /// Max host calls per WASM session. 0 = unlimited.
    pub max_host_calls_per_session: usize,
}

impl Default for SandboxSecurityConfig {
    fn default() -> Self {
        Self {
            allowed_wasm_hashes: HashSet::new(),
            wasm_hash_required: false,
            url_allowlist: Vec::new(),
            url_allowlist_mode: false, // blocklist-only by default
            command_whitelist: Vec::new(),
            command_whitelist_mode: false,
            query_allowed_tables: Vec::new(),
            query_restrict_tables: false,
            max_host_calls_per_session: 256,
        }
    }
}

impl SandboxSecurityConfig {
    /// Strict mode: hash required, allowlist-only for URL and command.
    pub fn strict() -> Self {
        Self {
            wasm_hash_required: true,
            url_allowlist_mode: true,
            command_whitelist_mode: true,
            query_restrict_tables: true,
            max_host_calls_per_session: 64,
            ..Default::default()
        }
    }

    /// Verify WASM module hash against allowlist.
    pub fn verify_wasm_hash(&self, wasm_bytes: &[u8]) -> Result<(), String> {
        let hash = hex::encode(Hasher::new().update(wasm_bytes).finalize().as_bytes());
        if self.wasm_hash_required && self.allowed_wasm_hashes.is_empty() {
            return Err("WASM hash required but no hashes in allowlist".to_string());
        }
        if self.wasm_hash_required || !self.allowed_wasm_hashes.is_empty() {
            if !self.allowed_wasm_hashes.contains(&hash) {
                return Err(format!(
                    "WASM module hash {} not in allowlist",
                    &hash[..hash.len().min(16)]
                ));
            }
        }
        Ok(())
    }

    /// Check if URL is allowed.
    pub fn is_url_allowed(&self, url: &str) -> bool {
        if self.url_allowlist_mode {
            if self.url_allowlist.is_empty() {
                return false;
            }
            let host = extract_host_from_url(url);
            for pattern in &self.url_allowlist {
                if pattern.starts_with("*.") {
                    let suffix = &pattern[1..];
                    if host.ends_with(suffix) || host == &suffix[2..] {
                        return true;
                    }
                } else if host == pattern.as_str() || host.ends_with(&format!(".{}", pattern)) {
                    return true;
                }
            }
            false
        } else {
            true // blocklist mode: NativeHost handles SSRF blocklist
        }
    }

    /// Check if command is allowed.
    pub fn is_command_allowed(&self, program: &str) -> bool {
        if self.command_whitelist_mode {
            if self.command_whitelist.is_empty() {
                return false;
            }
            let prog = to_ascii_lower(program.trim());
            let basename = std::path::Path::new(&prog)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&prog);
            for allowed in &self.command_whitelist {
                let a = to_ascii_lower(allowed.trim());
                if basename == a
                    || prog.ends_with(&format!("\\{}", a))
                    || prog.ends_with(&format!("/{}", a))
                {
                    return true;
                }
            }
            false
        } else {
            true // blocklist mode: NativeHost handles dangerous commands
        }
    }

    /// Check if SELECT query is allowed (table restriction).
    pub fn is_query_allowed(&self, query: &str) -> bool {
        if !self.query_restrict_tables || self.query_allowed_tables.is_empty() {
            return true;
        }
        let q = query.trim().to_uppercase();
        if !q.starts_with("SELECT") {
            return false;
        }
        for table in &self.query_allowed_tables {
            let t = table.to_uppercase();
            if q.contains(&format!("FROM {}", t)) || q.contains(&format!("FROM {} ", t)) {
                return true;
            }
        }
        false
    }

    /// Check if session has exceeded host call limit.
    pub fn is_rate_limited(&self, call_count: usize) -> bool {
        if self.max_host_calls_per_session == 0 {
            return false;
        }
        call_count >= self.max_host_calls_per_session
    }
}

fn extract_host_from_url(url: &str) -> String {
    let url = url.trim();
    let rest = if let Some(r) = url.strip_prefix("https://") {
        r
    } else if let Some(r) = url.strip_prefix("http://") {
        r
    } else {
        return String::new();
    };
    to_ascii_lower(
        rest.split('/')
            .next()
            .unwrap_or(rest)
            .split(':')
            .next()
            .unwrap_or(rest),
    )
}

fn to_ascii_lower(s: &str) -> String {
    s.to_lowercase()
}

impl From<osoosi_types::SandboxSecurityConfigPartial> for SandboxSecurityConfig {
    fn from(p: osoosi_types::SandboxSecurityConfigPartial) -> Self {
        Self {
            allowed_wasm_hashes: p.allowed_wasm_hashes.into_iter().collect(),
            wasm_hash_required: p.wasm_hash_required,
            url_allowlist: p.url_allowlist,
            url_allowlist_mode: p.url_allowlist_mode,
            command_whitelist: p.command_whitelist,
            command_whitelist_mode: p.command_whitelist_mode,
            query_allowed_tables: p.query_allowed_tables,
            query_restrict_tables: p.query_restrict_tables,
            max_host_calls_per_session: p.max_host_calls_per_session,
        }
    }
}
