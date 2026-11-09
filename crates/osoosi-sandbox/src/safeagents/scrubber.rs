//! Native Trajectory Redaction Engine (`OshoosiScrubber`)
//!
//! Redacts credentials, private keys, bearer tokens, env secrets, emails,
//! home directory paths, and public IPs from tool-call arguments and tasks
//! before telemetry emission to ~/.safeagents/calls.jsonl.

use regex::{Captures, Regex};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::OnceLock;

/// Configuration options for trajectory redaction.
#[derive(Debug, Clone)]
pub struct ScrubberConfig {
    pub mask_credentials: bool,
    pub mask_emails: bool,
    pub mask_home_dirs: bool,
    pub mask_public_ips: bool,
    pub mask_env_vars: bool,
}

impl Default for ScrubberConfig {
    fn default() -> Self {
        Self {
            mask_credentials: true,
            mask_emails: true,
            mask_home_dirs: true,
            mask_public_ips: true,
            mask_env_vars: true,
        }
    }
}

/// Statistics on redactions performed during a scrub pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedactionStats {
    pub private_keys_redacted: usize,
    pub api_keys_redacted: usize,
    pub bearer_tokens_redacted: usize,
    pub url_passwords_redacted: usize,
    pub env_vars_redacted: usize,
    pub emails_redacted: usize,
    pub home_dirs_redacted: usize,
    pub public_ips_redacted: usize,
}

/// Native trajectory scrubber for SafeAgents.
pub struct OshoosiScrubber;

impl Default for OshoosiScrubber {
    fn default() -> Self {
        Self
    }
}

impl OshoosiScrubber {
    /// Scrub input text using default production rules.
    pub fn scrub(input: &str) -> String {
        Self::scrub_with_config(input, &ScrubberConfig::default())
    }

    /// Scrub input text with custom configuration.
    pub fn scrub_with_config(input: &str, config: &ScrubberConfig) -> String {
        if input.is_empty() {
            return String::new();
        }

        let mut s = input.to_string();

        // 1. Private keys
        if config.mask_credentials {
            static PK_RE: OnceLock<Regex> = OnceLock::new();
            let re = PK_RE.get_or_init(|| {
                Regex::new(
                    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
                )
                .expect("private key regex valid")
            });
            s = re.replace_all(&s, "[private key]").to_string();
        }

        // 2. API Keys & Specific Secret Tokens
        if config.mask_credentials {
            static KEY_PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
            let patterns = KEY_PATTERNS.get_or_init(|| {
                vec![
                    Regex::new(r"\bsk-[a-zA-Z0-9_-]{16,}\b").expect("openai regex valid"),
                    Regex::new(r"\bhf_[a-zA-Z0-9]{20,}\b").expect("hf regex valid"),
                    Regex::new(r"\bgh[pousr]_[a-zA-Z0-9]{20,}\b").expect("github regex valid"),
                    Regex::new(r"\bxox[abprs]-[a-zA-Z0-9-]{10,}\b").expect("slack regex valid"),
                    Regex::new(r"\bAKIA[0-9A-Z]{16}\b").expect("aws key regex valid"),
                    Regex::new(r"\bAIza[0-9A-Za-z-_]{35}\b").expect("google key regex valid"),
                ]
            });
            for re in patterns {
                s = re.replace_all(&s, "***").to_string();
            }
        }

        // 3. Bearer Tokens
        if config.mask_credentials {
            static BEARER_RE: OnceLock<Regex> = OnceLock::new();
            let re = BEARER_RE.get_or_init(|| {
                Regex::new(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}").expect("bearer regex valid")
            });
            s = re.replace_all(&s, "Bearer ***").to_string();
        }

        // 4. URL Passwords (e.g. http://user:secret@host)
        if config.mask_credentials {
            static URL_PW_RE: OnceLock<Regex> = OnceLock::new();
            let re = URL_PW_RE.get_or_init(|| {
                Regex::new(r"(://[^/\s:@]+):[^/\s@]+@").expect("url password regex valid")
            });
            s = re.replace_all(&s, "$1:***@").to_string();
        }

        // 5. Environment Variables ($VAR, ${VAR})
        if config.mask_env_vars {
            // ${VAR} pattern
            static BRACED_ENV_RE: OnceLock<Regex> = OnceLock::new();
            let re_braced = BRACED_ENV_RE.get_or_init(|| {
                Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}").expect("braced env regex valid")
            });
            s = re_braced.replace_all(&s, "***").to_string();

            // $VAR pattern (targeting sensitive env names or standard shell references)
            static BARE_ENV_RE: OnceLock<Regex> = OnceLock::new();
            let re_bare = BARE_ENV_RE.get_or_init(|| {
                Regex::new(r"\$([A-Za-z_][A-Za-z0-9_]{2,})\b").expect("bare env regex valid")
            });
            s = re_bare
                .replace_all(&s, |caps: &Captures| {
                    let var_name = &caps[1];
                    let var_upper = var_name.to_ascii_uppercase();
                    if var_upper.contains("TOKEN")
                        || var_upper.contains("KEY")
                        || var_upper.contains("SECRET")
                        || var_upper.contains("PASS")
                        || var_upper.contains("AUTH")
                        || var_upper.contains("CRED")
                        || var_upper.contains("API")
                        || var_upper.contains("COOKIE")
                        || var_upper.contains("SESSION")
                        || var_upper.contains("BEARER")
                        || var_upper.starts_with("HF_")
                        || var_upper.starts_with("OPENAI_")
                        || var_upper.starts_with("AWS_")
                    {
                        "***".to_string()
                    } else {
                        format!("${}", var_name)
                    }
                })
                .to_string();
        }

        // 6. Personal Emails (excluding infrastructure / git / example domains)
        if config.mask_emails {
            static EMAIL_RE: OnceLock<Regex> = OnceLock::new();
            let re = EMAIL_RE.get_or_init(|| {
                Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
                    .expect("email regex valid")
            });
            s = re
                .replace_all(&s, |caps: &Captures| {
                    let e = &caps[0];
                    let e_lower = e.to_ascii_lowercase();
                    if e_lower.starts_with("git@")
                        || e_lower.starts_with("noreply")
                        || e_lower.starts_with("no-reply")
                        || e_lower.ends_with("@example.com")
                        || e_lower.ends_with("@example.org")
                        || e_lower.ends_with("@example.net")
                        || e_lower.ends_with("users.noreply.github.com")
                    {
                        e.to_string()
                    } else {
                        "<email>".to_string()
                    }
                })
                .to_string();
        }

        // 7. Home Directory Paths (/home/user, /Users/user, C:\Users\user)
        if config.mask_home_dirs {
            static HOME_RE: OnceLock<Regex> = OnceLock::new();
            let re = HOME_RE.get_or_init(|| {
                Regex::new(r#"(?i)(?:/home/|/Users/|[a-zA-Z]:\\Users\\)([a-zA-Z0-9_-]+)"#)
                    .expect("home path regex valid")
            });
            static GENERIC_USERS: OnceLock<HashSet<&'static str>> = OnceLock::new();
            let generic = GENERIC_USERS.get_or_init(|| {
                let mut set = HashSet::new();
                for u in &[
                    "ubuntu",
                    "runner",
                    "user",
                    "admin",
                    "linuxbrew",
                    "node",
                    "app",
                    "public",
                    "shared",
                    "administrator",
                    "default",
                ] {
                    set.insert(*u);
                }
                set
            });

            s = re
                .replace_all(&s, |caps: &Captures| {
                    let full = &caps[0];
                    let user = &caps[1];
                    if generic.contains(user.to_ascii_lowercase().as_str()) {
                        full.to_string()
                    } else {
                        format!("{{root}}{}", user)
                    }
                })
                .to_string();
        }

        // 8. Public IPv4 Literals (preserving loopback, RFC1918, link-local)
        if config.mask_public_ips {
            static IP_RE: OnceLock<Regex> = OnceLock::new();
            let re = IP_RE.get_or_init(|| {
                Regex::new(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b").expect("ipv4 regex valid")
            });
            s = re
                .replace_all(&s, |caps: &Captures| {
                    let ip_str = &caps[1];
                    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                        let oct = ip.octets();
                        let is_loopback = oct[0] == 127;
                        let is_rfc1918 = oct[0] == 10
                            || (oct[0] == 172 && (16..=31).contains(&oct[1]))
                            || (oct[0] == 192 && oct[1] == 168);
                        let is_link_local = oct[0] == 169 && oct[1] == 254;

                        if !is_loopback && !is_rfc1918 && !is_link_local {
                            "<ip>".to_string()
                        } else {
                            ip_str.to_string()
                        }
                    } else {
                        ip_str.to_string()
                    }
                })
                .to_string();
        }

        s
    }

    /// Recursively scrubs all string fields in a serde_json::Value.
    pub fn scrub_json(val: &mut serde_json::Value) {
        match val {
            serde_json::Value::String(s) => {
                *s = Self::scrub(s);
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    Self::scrub_json(item);
                }
            }
            serde_json::Value::Object(map) => {
                for (_, v) in map.iter_mut() {
                    Self::scrub_json(v);
                }
            }
            _ => {}
        }
    }
}
