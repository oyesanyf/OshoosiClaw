//! Native High-Speed ATIF Pattern Scanner (Stage 2)
//!
//! Sub-millisecond (<500µs) lock-free precompiled state machine combining
//! Aho-Corasick multi-needle pre-filtering, RegexSet single-pass matching,
//! and normalization for 0-evasion defense across all 53 adversarial vectors.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use regex::{Regex, RegexSet};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

/// Severity classification for ATIF scanner findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AtifSeverity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl std::fmt::Display for AtifSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A structured signal emitted by the ATIF detector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtifSignal {
    pub id: String,
    pub severity: AtifSeverity,
    pub title: String,
    pub details: String,
    pub pattern_matched: String,
}

/// Stage 2 scan verdict for an incoming tool invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stage2Verdict {
    /// No suspicious ATIF patterns detected.
    Clean,
    /// Medium-severity patterns detected; forwards to Stage 3 Isolated Judge.
    Suspicious { signals: Vec<AtifSignal> },
    /// High- or critical-severity patterns detected; immediate block (<15ms).
    Blocked {
        reason: String,
        notice: String,
        signals: Vec<AtifSignal>,
    },
}

impl Stage2Verdict {
    #[inline]
    pub fn is_clean(&self) -> bool {
        matches!(self, Stage2Verdict::Clean)
    }

    #[inline]
    pub fn is_suspicious(&self) -> bool {
        matches!(self, Stage2Verdict::Suspicious { .. })
    }

    #[inline]
    pub fn is_blocked(&self) -> bool {
        matches!(self, Stage2Verdict::Blocked { .. })
    }
}

/// Helper converting hex byte (ASCII '0'-'9', 'a'-'f', 'A'-'F') to numeric value.
#[inline]
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Helper to determine if a string slice ending in ':' is preceded by a URI scheme
/// (e.g. "http:", "https:", "file:"). Requires >= 2 scheme characters starting with
/// an alphabetic character to prevent false-positive matching on Windows drive letters (e.g. "C:").
#[inline]
fn is_uri_scheme_prefix(s: &str) -> bool {
    if !s.ends_with(':') {
        return false;
    }
    let before_colon = &s[..s.len() - 1];
    let scheme_candidate = before_colon
        .rsplit(|c: char| !c.is_ascii_alphanumeric() && c != '+' && c != '-' && c != '.')
        .next()
        .unwrap_or("");
    scheme_candidate.len() >= 2
        && scheme_candidate
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
}

/// Fast in-place pre-check determining if text requires normalization.
/// Enables zero-allocation fast paths for clean requests.
#[inline]
pub fn needs_normalization(text: &str) -> bool {
    let bytes = text.as_bytes();
    for i in 0..bytes.len() {
        let b = bytes[i];
        if b == b'\\' || b == b'%' {
            return true;
        }
        if b == b'/' && i + 1 < bytes.len() && (bytes[i + 1] == b'/' || bytes[i + 1] == b'.') {
            return true;
        }
    }
    false
}

/// Normalizes command and argument text prior to ATIF security scanning.
///
/// Neutralizes evasion attempts by:
/// 1. Percent-decoding hex bytes (%2f -> /, %31 -> 1, etc.).
/// 2. Converting backslashes `\` to `/` while unescaping `\"` -> `"`.
/// 3. Collapsing repeated slashes (`//+` -> `/`) while strictly preserving URI schemes (`://` and `file:///`).
/// 4. Stripping dot segments (`/./` -> `/`).
/// 5. Canonicalizing relative path parent references (`/1/../1/` -> `/1/`, bounded to 32 loops).
pub fn normalize_for_scan(text: &str) -> Cow<'_, str> {
    if !needs_normalization(text) {
        return Cow::Borrowed(text);
    }

    let bytes = text.as_bytes();

    // Step 1: Percent-decode hex and normalize backslashes
    let mut decoded = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];

        // Percent-decode `%xx`
        if b == b'%' && i + 2 < bytes.len() {
            if let (Some(h1), Some(h2)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                let dec = (h1 << 4) | h2;
                if dec == b'\\' || dec == b'/' {
                    decoded.push('/');
                } else if (0x20..=0x7E).contains(&dec) {
                    decoded.push(dec as char);
                } else {
                    decoded.push('%');
                    decoded.push(bytes[i + 1] as char);
                    decoded.push(bytes[i + 2] as char);
                }
                i += 3;
                continue;
            }
        }

        // Backslash conversion
        if b == b'\\' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'"' {
                decoded.push('"');
                i += 2;
                continue;
            }
            decoded.push('/');
            i += 1;
            continue;
        }

        if b < 128 {
            decoded.push(b as char);
            i += 1;
        } else {
            let ch = text[i..].chars().next().unwrap_or(' ');
            decoded.push(ch);
            i += ch.len_utf8();
        }
    }

    // Step 2: Collapse contiguous repeated slashes (`//+` -> `/`), preserving URI schemes `://` and `file:///`
    let mut collapsed = String::with_capacity(decoded.len());
    for ch in decoded.chars() {
        if ch == '/' {
            let is_scheme = if collapsed.ends_with(':') {
                is_uri_scheme_prefix(&collapsed)
            } else if collapsed.ends_with(":/") {
                is_uri_scheme_prefix(&collapsed[..collapsed.len() - 1])
            } else if collapsed.ends_with("://") {
                collapsed.ends_with("file://")
            } else {
                false
            };

            if is_scheme {
                collapsed.push('/');
            } else if collapsed.ends_with('/') {
                continue;
            } else {
                collapsed.push('/');
            }
        } else {
            collapsed.push(ch);
        }
    }

    // Step 3: Strip dot segments (`/./` -> `/`)
    let mut normalized = collapsed;
    while normalized.contains("/./") {
        normalized = normalized.replace("/./", "/");
    }
    if normalized.ends_with("/.") {
        normalized.truncate(normalized.len() - 1);
    }

    // Step 4: Canonicalize relative path parent references (`/seg/../` -> `/`)
    if normalized.contains("/../") {
        let parts: Vec<&str> = normalized.split('/').collect();
        let mut result = String::with_capacity(normalized.len());
        let mut stack: Vec<(usize, bool)> = Vec::with_capacity(parts.len());

        for (idx, part) in parts.iter().enumerate() {
            if idx == 0 {
                result.push_str(part);
                continue;
            }

            if *part == ".." {
                if let Some((start_pos, cancellable)) = stack.pop() {
                    if cancellable {
                        result.truncate(start_pos);
                        continue;
                    } else {
                        stack.push((start_pos, cancellable));
                    }
                }
            }

            let start_pos = result.len();
            result.push('/');
            result.push_str(part);

            let cancellable = !part.is_empty()
                && *part != "."
                && *part != ".."
                && !part
                    .chars()
                    .any(|c| c.is_whitespace() || c == '"' || c == '\'' || c == ':');

            stack.push((start_pos, cancellable));
        }

        if normalized.ends_with('/') && !result.ends_with('/') {
            result.push('/');
        }

        normalized = result;
    }

    Cow::Owned(normalized)
}

/// Configuration options and plugin allowance rules for ATIF scanner.
#[derive(Debug, Clone)]
pub struct AtifScannerConfig {
    /// Severity threshold for immediate blocking (default: High).
    pub block_threshold: AtifSeverity,
    /// Disabled rule IDs (plugin override).
    pub disabled_rules: HashSet<String>,
    /// Custom severity overrides per rule ID (plugin override).
    pub severity_overrides: HashMap<String, AtifSeverity>,
    /// Allow proxy bypass for localhost destinations (default: true).
    pub allow_localhost_proxy_bypass: bool,
    /// Allow benign /proc/self/environ inspection (default: true).
    pub allow_self_proc_environ: bool,
}

impl Default for AtifScannerConfig {
    fn default() -> Self {
        Self {
            block_threshold: AtifSeverity::High,
            disabled_rules: HashSet::new(),
            severity_overrides: HashMap::new(),
            allow_localhost_proxy_bypass: true,
            allow_self_proc_environ: true,
        }
    }
}

/// Individual detector rule definition.
struct DetectorRule {
    id: &'static str,
    default_severity: AtifSeverity,
    title: &'static str,
    regex: Regex,
}

/// Native precompiled ATIF scanner running lock-free across worker pool.
pub struct NativeAtifScanner {
    config: AtifScannerConfig,
    ac_matcher: AhoCorasick,
    regex_set: RegexSet,
    rules: Vec<DetectorRule>,
}

impl Default for NativeAtifScanner {
    fn default() -> Self {
        Self::new_with_config(AtifScannerConfig::default())
    }
}

impl NativeAtifScanner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new NativeAtifScanner compiling state machines once.
    pub fn new_with_config(config: AtifScannerConfig) -> Self {
        // Needle tokens for Aho-Corasick multi-pattern pre-filter
        let needles = &[
            "/proc/",
            "\\proc\\",
            "/proc",
            "\\proc",
            "proc/",
            "proc\\",
            "environ",
            "--noproxy",
            "no_proxy",
            "env -u",
            "--unset",
            "https_proxy",
            "http_proxy",
            "all_proxy",
            "unshare",
            "nsenter",
            "/run/secrets/kubernetes.io/serviceaccount",
            "/var/run/secrets/kubernetes.io/serviceaccount",
            "\\run\\secrets\\kubernetes.io\\serviceaccount",
            "\\var\\run\\secrets\\kubernetes.io\\serviceaccount",
            "kubernetes.io/serviceaccount",
            "kubernetes.io\\serviceaccount",
            "kubernetes.io",
            "serviceaccount",
            "/run/secrets/",
            "/var/run/secrets/",
            "\\run\\secrets\\",
            "\\var\\run\\secrets\\",
            "169.254.169.254",
            "metadata.google.internal",
            "100.100.100.200",
            // Threat Class 1: Eval Gaming Needles
            "grader",
            "solution",
            "answer",
            "test_hidden",
            "test_ground_truth",
            "grading",
            "rubric",
            "expected_sha256",
            "benchmark_reference",
            "verifier",
            "test_verify",
            "grading_suite",
            "secret_tests",
            "hidden_tests",
            "eval_bin",
            "eval-harness",
            "leaderboard",
            "score",
            "ground_truth",
            "/eval",
            "\\eval",
            "eval/",
            "eval\\",
            "*eval*",
            "eval_",
            "test_outputs.py",
            // Threat Class 2: Harness Introspection Needles
            "history_agent",
            "history-agent",
            "agent-runner",
            "agent_runner",
            "agent-executor",
            "agent_executor",
            "agent_conversation",
            "agent-conversation",
            "checkpoint_state",
            "checkpoint-state",
            "agent_ipc",
            "agent-ipc",
            "agent_token",
            "agent-token",
            "interviewer",
            "agent_loop",
            "agent-loop",
            ".claude/session",
            ".claude\\session",
            "daemon.log",
            "trace.jsonl",
            "entrypoint.sh",
            "cgroup",
            "$ppid",
            "${ppid}",
            "supervisor/conf.d",
            "supervisor\\conf.d",
            "harness",
            "/fd",
            "\\fd",
            // Threat Class 3: Credential Misuse Needles
            "hf_token",
            "hf-token",
            "aws_secret_access_key",
            "aws-secret-access-key",
            "github_token",
            "github-token",
            ".netrc",
            ".aws/credentials",
            ".aws\\credentials",
            "gcloud/credentials",
            "gcloud\\credentials",
            "credentials.db",
            "eval-operator",
            "eval_operator",
            "id_rsa",
            "id-rsa",
            "id_ed25519",
            "id-ed25519",
            "hub/token",
            "hub\\token",
            "exfil.attacker",
            ".docker/config.json",
            ".docker\\config.json",
        ];

        let ac_matcher = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(needles)
            .expect("AhoCorasick state machine compilation failed");

        let patterns = vec![
            // 0: /proc/<pid>/environ
            r#"(?i)(?:/|\\)+proc(?:/|\\)+(?:(?:\.)(?:/|\\)+)*(?:(?P<pid>[a-zA-Z0-9_\-\$\{\}]+)(?:/|\\)+(?:(?:\.)(?:/|\\)+)*)?environ\b"#,
            // 1: Proxy bypass
            r#"(?i)(?:--noproxy(?:\s+|=)['"]?[^\s'"]+['"]?|\bno_proxy\s*=\s*['"]?[^\s'"]*['"]?|\benv\s+(?:-u\s*=?|--unset(?:\s+|=))['"]?(?:HTTPS?_PROXY|ALL_PROXY)\b['"]?|\bhttps?_proxy\s*=\s*['"]?[^'\s"]*['"]?|\b-c\s+https?\.proxy\s*=\s*['"][^'"]*['"])"#,
            // 2: Namespace escape
            r#"(?i)\b(?:unshare|nsenter)\b"#,
            // 3: Kubernetes service account credentials
            r#"(?i)(?:(?:/|\\)*(?:var(?:/|\\)+(?:(?:\.)(?:/|\\)+)*)?)?run(?:/|\\)+(?:(?:\.)(?:/|\\)+)*secrets(?:/|\\)+(?:(?:\.)(?:/|\\)+)*kubernetes\.io(?:/|\\)+(?:(?:\.)(?:/|\\)+)*serviceaccount"#,
            // 4: Cloud IMDS metadata
            r#"(?i)\b(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)\b"#,
            // 5: Eval gaming probe
            r#"(?i)(?:\b(?:grader|solution|answer|test_hidden|test_ground_truth|grading|rubric|expected_sha256|benchmark_reference|verifier|test_verify|grading_suite|secret_tests|hidden_tests|eval_bin|eval-harness|leaderboard|score|ground_truth)|(?:/|\\)eval(?:/|\\|\b)|\*eval\*|eval_|\btest_outputs\.py\b)"#,
            // 6: Harness introspection probe
            r#"(?i)(?:history[-_]agent|\b(?:agent[-_]runner|agent[-_]executor|checkpoint[-_]state|agent[-_]ipc|agent[-_]token|interviewer|agent[-_]loop)\b|agent[-_]conversation|\.claude/session|\.claude\\session|\b(?:daemon\.log|trace\.jsonl|entrypoint\.sh)\b|\bcgroup\b|\$ppid|\$\{ppid\}|supervisor/conf\.d|supervisor\\conf\.d|\bharness\b|/proc/[^/\s]+/fd\b|\\proc\\[^\s\\]+\\fd\b)"#,
            // 7: Credential misuse attempt
            r#"(?i)(?:\b(?:hf[-_]token|aws[-_]secret[-_]access[-_]key|github[-_]token)\b|\.netrc\b|\.aws/credentials\b|\.aws\\credentials\b|(?:gcloud/credentials|gcloud\\credentials|\bcredentials\.db\b)|\beval[-_]operator\b|\.ssh/id[-_](?:rsa|ed25519)\b|\bid[-_](?:rsa|ed25519)\b|hub/token\b|hub\\token\b|exfil\.attacker|\.docker/config\.json\b|\.docker\\config\.json\b)"#,
        ];

        let regex_set = RegexSet::new(&patterns).expect("RegexSet compilation failed");

        let rules = vec![
            DetectorRule {
                id: "side_channel.harness_secret_read",
                default_severity: AtifSeverity::High,
                title: "Process environment secret read (/proc/<pid>/environ)",
                regex: Regex::new(patterns[0]).expect("regex 0 valid"),
            },
            DetectorRule {
                id: "network.proxy_bypass",
                default_severity: AtifSeverity::High,
                title: "Outbound proxy bypass attempt",
                regex: Regex::new(patterns[1]).expect("regex 1 valid"),
            },
            DetectorRule {
                id: "safeagents.namespace_escape",
                default_severity: AtifSeverity::High,
                title: "Linux namespace escape / transition (unshare/nsenter)",
                regex: Regex::new(patterns[2]).expect("regex 2 valid"),
            },
            DetectorRule {
                id: "side_channel.orchestrator_credentials",
                default_severity: AtifSeverity::High,
                title: "Kubernetes service account credentials / token access",
                regex: Regex::new(patterns[3]).expect("regex 3 valid"),
            },
            DetectorRule {
                id: "network.imds_metadata_probe",
                default_severity: AtifSeverity::High,
                title: "Cloud instance metadata service (IMDS) reconnaissance probe",
                regex: Regex::new(patterns[4]).expect("regex 4 valid"),
            },
            DetectorRule {
                id: "safeagents.eval_gaming",
                default_severity: AtifSeverity::High,
                title: "Evaluation benchmark / grader gaming probe",
                regex: Regex::new(patterns[5]).expect("regex 5 valid"),
            },
            DetectorRule {
                id: "side_channel.harness_introspection",
                default_severity: AtifSeverity::High,
                title: "Harness internals / container environment introspection probe",
                regex: Regex::new(patterns[6]).expect("regex 6 valid"),
            },
            DetectorRule {
                id: "credential.unauthorized_access",
                default_severity: AtifSeverity::High,
                title: "Unauthorized credential / secret token access attempt",
                regex: Regex::new(patterns[7]).expect("regex 7 valid"),
            },
        ];

        Self {
            config,
            ac_matcher,
            regex_set,
            rules,
        }
    }

    /// Scans raw text and returns all detected ATIF signals.
    pub fn scan_text(&self, command_or_args: &str) -> Vec<AtifSignal> {
        let normalized = normalize_for_scan(command_or_args);

        // Early-exit fast filter: if none of the needles appear, exit in <5µs
        if self.ac_matcher.find(normalized.as_ref()).is_none() {
            return Vec::new();
        }

        // Single-pass multi-pattern evaluation
        let matches = self.regex_set.matches(normalized.as_ref());
        if !matches.matched_any() {
            return Vec::new();
        }

        let mut signals = Vec::new();

        for idx in matches.into_iter() {
            let rule = &self.rules[idx];

            if self.config.disabled_rules.contains(rule.id) {
                continue;
            }

            let severity = self
                .config
                .severity_overrides
                .get(rule.id)
                .copied()
                .unwrap_or(rule.default_severity);

            match idx {
                0 => {
                    // /proc/<pid>/environ
                    for caps in rule.regex.captures_iter(&normalized) {
                        if let Some(pid_m) = caps.name("pid") {
                            let pid = pid_m.as_str().to_ascii_lowercase();
                            if self.config.allow_self_proc_environ
                                && (pid == "self"
                                    || pid == "thread-self"
                                    || pid == "$$"
                                    || pid == "${$}")
                            {
                                continue;
                            }
                            let title = if pid == "1" {
                                "PID 1 container environment access attempt".to_string()
                            } else {
                                format!(
                                    "Cross-process environment secret access (/proc/{}/environ)",
                                    pid
                                )
                            };
                            signals.push(AtifSignal {
                                id: rule.id.to_string(),
                                severity,
                                title,
                                details: format!("Targeted process environ: {}", &caps[0]),
                                pattern_matched: caps[0].to_string(),
                            });
                        } else {
                            signals.push(AtifSignal {
                                id: rule.id.to_string(),
                                severity,
                                title: "Kernel/Process environment access (/proc/environ)"
                                    .to_string(),
                                details: format!("Raw process environ access: {}", &caps[0]),
                                pattern_matched: caps[0].to_string(),
                            });
                        }
                    }
                }
                1 => {
                    // Proxy bypass
                    for caps in rule.regex.captures_iter(&normalized) {
                        let matched_flag = &caps[0];
                        let is_wildcard = matched_flag.contains('*');
                        let flag_lower = matched_flag.to_ascii_lowercase();
                        let is_env_unset =
                            flag_lower.contains("env -u") || flag_lower.contains("env --unset");

                        let is_strictly_local = if self.config.allow_localhost_proxy_bypass {
                            let hosts =
                                crate::safeagents::request_validator::extract_hosts_from_text(
                                    &normalized,
                                );
                            !hosts.is_empty()
                                && hosts.iter().all(|h| h == "127.0.0.1" || h == "localhost")
                        } else {
                            false
                        };

                        if is_wildcard || is_env_unset || !is_strictly_local {
                            signals.push(AtifSignal {
                                id: rule.id.to_string(),
                                severity,
                                title: rule.title.to_string(),
                                details: format!("Proxy bypass flags: {}", matched_flag),
                                pattern_matched: matched_flag.to_string(),
                            });
                        }
                    }
                }
                _ => {
                    // General regex match (unshare/nsenter, k8s, IMDS)
                    for caps in rule.regex.captures_iter(&normalized) {
                        signals.push(AtifSignal {
                            id: rule.id.to_string(),
                            severity,
                            title: rule.title.to_string(),
                            details: format!("Pattern matched: {}", &caps[0]),
                            pattern_matched: caps[0].to_string(),
                        });
                    }
                }
            }
        }

        signals
    }

    /// Evaluates tool invocation command or arguments JSON emitting a Stage2Verdict.
    pub fn scan(&self, tool_name: &str, command_or_args: &str) -> Stage2Verdict {
        let signals = self.scan_text(command_or_args);
        if signals.is_empty() {
            return Stage2Verdict::Clean;
        }

        let max_sev = signals
            .iter()
            .map(|s| s.severity)
            .max()
            .unwrap_or(AtifSeverity::Low);

        if max_sev >= self.config.block_threshold {
            let top_signal = signals.iter().max_by_key(|s| s.severity).unwrap();
            let reason = format!("{}: {}", top_signal.id, top_signal.title);
            let notice = format!("[safeagents] blocked call to `{}`: {}", tool_name, reason);
            Stage2Verdict::Blocked {
                reason,
                notice,
                signals,
            }
        } else {
            Stage2Verdict::Suspicious { signals }
        }
    }
}
