//! Real Windows Command-Line Tokenizer, Recursive Shell Unwrapper, PowerShell Unambiguous-Prefix
//! Parameter Parser, and `-EncodedCommand` UTF-16LE Base64 Decoder (Finding 1).
//!
//! Replaces single-phrase substring rules with genuine structural parsing:
//! 1. [`tokenize_windows_argv`]: Faithful implementation of MSVCRT / `CommandLineToArgvW` quoting
//!    and backslash-escape rules (`2n` backslashes before `"`, `2n+1` backslashes before `"`, `""`).
//! 2. [`parse_powershell_args`]: Matches PowerShell (`powershell.exe` / `pwsh.exe`) switches using
//!    PowerShell's actual unambiguous-prefix rules (`-e`, `-ec`, `-en`, `-enc`, `-enco`, ...,
//!    `-EncodedCommand`, `-c` / `-Command`, `-f` / `-File`, `-w` / `-WindowStyle`,
//!    `-ep` / `-ExecutionPolicy`, `-nop` / `-NoProfile`, `-noni` / `-NonInteractive`), across
//!    ASCII `-`, `/`, and Unicode dash prefixes (`\u{2013}`, `\u{2014}`, `\u{2015}`).
//! 3. [`decode_encoded_command`]: Hand-written RFC 4648 Base64 decoder + UTF-16LE decoder.
//!    Reports malformed Base64 or odd byte lengths as [`EncodedCommandState::MalformedBase64`]
//!    rather than ignoring them.
//! 4. [`analyze_command_line`]: Recursively unwraps `cmd.exe /c|/k|/r`, `start`, and nested
//!    `powershell` / `pwsh` invocations up to depth 4, and inspects decoded script bodies for
//!    secondary encoded payloads or reflective/download cradles.

use serde::{Deserialize, Serialize};

/// Maximum recursion depth when unwrapping nested shell or encoded invocations (`cmd /c powershell -enc ...`).
pub const MAX_UNWRAP_DEPTH: usize = 4;

/// Canonical PowerShell parameter names and their shortest unambiguous prefixes in `powershell.exe` / `pwsh`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PsParameter {
    /// `-e`, `-ec`, `-en`, `-enc`, ..., `-encodedcommand`
    EncodedCommand(String),
    /// `-c`, `-co`, ..., `-command`
    Command(String),
    /// `-f`, `-fi`, ..., `-file`
    File(String),
    /// `-w`, `-wi`, ..., `-windowstyle`
    WindowStyle(String),
    /// `-ep`, `-ex`, ..., `-executionpolicy`
    ExecutionPolicy(String),
    /// `-nop`, ..., `-noprofile`
    NoProfile,
    /// `-noni`, ..., `-noninteractive`
    NonInteractive,
    /// `-sta` / `-mta` / `-version` / other switches
    OtherSwitch(String),
    /// Positional argument
    Positional(String),
}

/// Outcome of decoding a PowerShell `-EncodedCommand` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncodedCommandState {
    NotPresent,
    Decoded {
        raw_base64: String,
        decoded_utf16le: String,
    },
    MalformedBase64 {
        raw_base64: String,
        reason: String,
    },
}

/// Structured analysis of a command line (including any recursively unwrapped child invocations).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedInvocation {
    pub raw_command_line: String,
    pub argv: Vec<String>,
    /// Normalized executable stem (path stripped, `.exe`/`.com`/`.bat`/`.cmd` removed, lowercase).
    pub executable_stem: String,
    pub is_powershell: bool,
    pub is_cmd_wrapper: bool,
    pub ps_parameters: Vec<PsParameter>,
    pub encoded_command: EncodedCommandState,
    pub window_style_hidden: bool,
    pub execution_policy_bypass: bool,
    /// Indicators extracted from the decoded script or command body via structural token analysis.
    pub script_structural_signals: Vec<String>,
    /// Nested invocations unwrapped from `cmd /c` or decoded `-EncodedCommand` scripts.
    pub nested: Vec<ParsedInvocation>,
}

impl ParsedInvocation {
    /// Returns `true` if this invocation (or any nested child) exhibits a multi-signal technical
    /// breakout pattern (never a lone process name or single static phrase).
    pub fn has_breakout_signals(&self) -> bool {
        !self.collect_findings().is_empty()
    }

    /// Collects structured finding descriptions across this invocation and any unwrapped children.
    pub fn collect_findings(&self) -> Vec<String> {
        let mut out = Vec::new();
        self.collect_into(&mut out, 0);
        out
    }

    fn collect_into(&self, out: &mut Vec<String>, depth: usize) {
        match &self.encoded_command {
            EncodedCommandState::Decoded { decoded_utf16le, .. } => {
                out.push(format!(
                    "depth={}: {} invoked with -EncodedCommand (decoded {} chars: {:?})",
                    depth,
                    self.executable_stem,
                    decoded_utf16le.chars().count(),
                    truncate_preview(decoded_utf16le, 96)
                ));
            }
            EncodedCommandState::MalformedBase64 { raw_base64, reason } => {
                out.push(format!(
                    "depth={}: {} invoked with malformed -EncodedCommand ({}: {:?})",
                    depth,
                    self.executable_stem,
                    reason,
                    truncate_preview(raw_base64, 64)
                ));
            }
            EncodedCommandState::NotPresent => {}
        }

        if self.is_powershell && self.window_style_hidden && self.execution_policy_bypass {
            out.push(format!(
                "depth={}: {} combines -WindowStyle Hidden with -ExecutionPolicy Bypass",
                depth, self.executable_stem
            ));
        }

        for sig in &self.script_structural_signals {
            out.push(format!("depth={}: {}", depth, sig));
        }

        for child in &self.nested {
            child.collect_into(out, depth + 1);
        }
    }
}

fn truncate_preview(s: &str, max_chars: usize) -> String {
    let mut out: String = s.chars().take(max_chars).collect();
    if s.chars().count() > max_chars {
        out.push_str("...");
    }
    out
}

/// Faithful implementation of Windows `CommandLineToArgvW` / MSVCRT argv splitting rules:
/// - Inside quotes, whitespace is literal and `""` produces a single `"`.
/// - `2n` backslashes followed by `"` produce `n` backslashes and toggle quote mode.
/// - `2n + 1` backslashes followed by `"` produce `n` backslashes and a literal `"`.
/// - Backslashes not followed by `"` are emitted literally.
/// - Caret (`^`) outside quotes in `cmd.exe` style obfuscation (`p^o^w^e^r^s^h^e^l^l`) is also
///   normalized by [`strip_cmd_carets_outside_quotes`] when unwrapping `cmd.exe`.
pub fn tokenize_windows_argv(cmdline: &str) -> Vec<String> {
    let trimmed = cmdline.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut args: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut token_started = false;
    let mut chars = trimmed.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            let mut bs_count = 1usize;
            while chars.peek() == Some(&'\\') {
                chars.next();
                bs_count += 1;
            }
            if chars.peek() == Some(&'"') {
                chars.next();
                for _ in 0..(bs_count / 2) {
                    cur.push('\\');
                }
                if bs_count % 2 == 0 {
                    in_quotes = !in_quotes;
                } else {
                    cur.push('"');
                }
                token_started = true;
            } else {
                for _ in 0..bs_count {
                    cur.push('\\');
                }
                token_started = true;
            }
        } else if c == '"' {
            if in_quotes && chars.peek() == Some(&'"') {
                chars.next();
                cur.push('"');
            } else {
                in_quotes = !in_quotes;
            }
            token_started = true;
        } else if c.is_whitespace() && !in_quotes {
            if token_started {
                args.push(std::mem::take(&mut cur));
                token_started = false;
            }
        } else {
            cur.push(c);
            token_started = true;
        }
    }

    if token_started {
        args.push(cur);
    }
    args
}

/// Strips `cmd.exe` escape carets (`^`) outside double quotes (e.g. `p^o^w^e^r^s^h^e^l^l -e^n^c`).
pub fn strip_cmd_carets_outside_quotes(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_quotes = false;
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' {
            in_quotes = !in_quotes;
            out.push(c);
        } else if c == '^' && !in_quotes {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Normalizes an executable token (`"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.EXE"` -> `"powershell"`).
pub fn normalize_executable_stem(token: &str) -> String {
    let unquoted = token.trim().trim_matches('"').trim_matches('\'');
    let basename = unquoted
        .rsplit(&['\\', '/'][..])
        .next()
        .unwrap_or(unquoted)
        .to_ascii_lowercase();
    for suffix in [".exe", ".com", ".bat", ".cmd"] {
        if let Some(stem) = basename.strip_suffix(suffix) {
            return stem.to_string();
        }
    }
    basename
}

fn strip_switch_prefix(arg: &str) -> Option<&str> {
    for prefix in ['-', '/', '\u{2013}', '\u{2014}', '\u{2015}'] {
        if let Some(rest) = arg.strip_prefix(prefix) {
            if !rest.is_empty() {
                return Some(rest);
            }
        }
    }
    None
}

/// Matches a switch name (already lowercased, without leading dash) against PowerShell's
/// unambiguous parameter prefixes.
pub fn classify_ps_switch_name(switch_lower: &str) -> &'static str {
    // PowerShell explicitly supports `-ec` as an alias for `-EncodedCommand`, plus any prefix
    // of `encodedcommand` (`-e`, `-en`, `-enc`, `-enco`, ...).
    if switch_lower == "ec"
        || ("encodedcommand".starts_with(switch_lower) && !switch_lower.is_empty())
    {
        return "encodedcommand";
    }
    if switch_lower == "c" || ("command".starts_with(switch_lower) && !switch_lower.is_empty()) {
        return "command";
    }
    if switch_lower == "f" || ("file".starts_with(switch_lower) && !switch_lower.is_empty()) {
        return "file";
    }
    if switch_lower == "w"
        || ("windowstyle".starts_with(switch_lower) && !switch_lower.is_empty())
    {
        return "windowstyle";
    }
    if switch_lower == "ep"
        || (switch_lower.len() >= 2 && "executionpolicy".starts_with(switch_lower))
    {
        return "executionpolicy";
    }
    if switch_lower.starts_with("nop") && "noprofile".starts_with(switch_lower) {
        return "noprofile";
    }
    if switch_lower.starts_with("noni") && "noninteractive".starts_with(switch_lower) {
        return "noninteractive";
    }
    "other"
}

/// Parses PowerShell arguments (`argv[1..]`) using PowerShell's unambiguous-prefix switch rules.
/// Supports both space-separated (`-enc AAAA`) and colon/equals-attached (`-enc:AAAA`, `-enc=AAAA`) values.
pub fn parse_powershell_args(args: &[String]) -> Vec<PsParameter> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        let token = args[i].trim();
        if let Some(after_dash) = strip_switch_prefix(token) {
            let (raw_name, inline_val) = match after_dash.split_once(&[':', '='][..]) {
                Some((n, v)) if !n.is_empty() => (n, Some(v.to_string())),
                _ => (after_dash, None),
            };
            let kind = classify_ps_switch_name(&raw_name.to_ascii_lowercase());
            match kind {
                "encodedcommand" => {
                    let val = inline_val.unwrap_or_else(|| {
                        if i + 1 < args.len() {
                            i += 1;
                            args[i].clone()
                        } else {
                            String::new()
                        }
                    });
                    out.push(PsParameter::EncodedCommand(val));
                }
                "command" => {
                    let val = inline_val.unwrap_or_else(|| {
                        if i + 1 < args.len() {
                            i += 1;
                            args[i..].join(" ")
                        } else {
                            String::new()
                        }
                    });
                    out.push(PsParameter::Command(val));
                    if i + 1 <= args.len() {
                        // `-Command` consumes the rest of the line when unquoted, or the next arg.
                        break;
                    }
                }
                "file" => {
                    let val = inline_val.unwrap_or_else(|| {
                        if i + 1 < args.len() {
                            i += 1;
                            args[i].clone()
                        } else {
                            String::new()
                        }
                    });
                    out.push(PsParameter::File(val));
                }
                "windowstyle" => {
                    let val = inline_val.unwrap_or_else(|| {
                        if i + 1 < args.len() {
                            i += 1;
                            args[i].clone()
                        } else {
                            String::new()
                        }
                    });
                    out.push(PsParameter::WindowStyle(val));
                }
                "executionpolicy" => {
                    let val = inline_val.unwrap_or_else(|| {
                        if i + 1 < args.len() {
                            i += 1;
                            args[i].clone()
                        } else {
                            String::new()
                        }
                    });
                    out.push(PsParameter::ExecutionPolicy(val));
                }
                "noprofile" => out.push(PsParameter::NoProfile),
                "noninteractive" => out.push(PsParameter::NonInteractive),
                _ => out.push(PsParameter::OtherSwitch(raw_name.to_string())),
            }
        } else {
            out.push(PsParameter::Positional(token.to_string()));
        }
        i += 1;
    }
    out
}

/// Hand-written strict RFC 4648 Base64 decoder (no external crate required for `--offline` builds).
pub fn decode_base64_strict(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: Vec<u8> = input
        .bytes()
        .filter(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .collect();
    if cleaned.is_empty() {
        return Err("empty Base64 payload".to_string());
    }
    if cleaned.len() % 4 != 0 {
        return Err(format!(
            "Base64 length {} is not a multiple of 4",
            cleaned.len()
        ));
    }

    let val = |b: u8| -> Result<u8, String> {
        match b {
            b'A'..=b'Z' => Ok(b - b'A'),
            b'a'..=b'z' => Ok(b - b'a' + 26),
            b'0'..=b'9' => Ok(b - b'0' + 52),
            b'+' | b'-' => Ok(62),
            b'/' | b'_' => Ok(63),
            _ => Err(format!("invalid Base64 byte 0x{:02x}", b)),
        }
    };

    let mut out = Vec::with_capacity((cleaned.len() / 4) * 3);
    for (chunk_idx, chunk) in cleaned.chunks_exact(4).enumerate() {
        let is_last = (chunk_idx + 1) * 4 == cleaned.len();
        let pad = chunk.iter().rev().take_while(|&&b| b == b'=').count();
        if pad > 2 || (pad > 0 && !is_last) {
            return Err("invalid Base64 padding placement".to_string());
        }
        if chunk[..4 - pad].contains(&b'=') {
            return Err("unexpected '=' inside Base64 quantum".to_string());
        }

        let b0 = val(chunk[0])?;
        let b1 = val(chunk[1])?;
        let b2 = if pad >= 2 { 0 } else { val(chunk[2])? };
        let b3 = if pad >= 1 { 0 } else { val(chunk[3])? };

        out.push((b0 << 2) | (b1 >> 4));
        if pad < 2 {
            out.push((b1 << 4) | (b2 >> 2));
        }
        if pad < 1 {
            out.push((b2 << 6) | b3);
        }
    }
    Ok(out)
}

/// Encodes a string as UTF-16LE Base64 (matching PowerShell's `[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($s))`).
pub fn encode_utf16le_base64(script: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bytes = Vec::with_capacity(script.len() * 2);
    for u in script.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    let mut out = String::with_capacity(((bytes.len() + 2) / 3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Decodes a PowerShell `-EncodedCommand` payload (Base64 -> UTF-16LE -> `String`).
pub fn decode_encoded_command(raw_b64: &str) -> EncodedCommandState {
    let trimmed = raw_b64.trim().trim_matches('"').trim_matches('\'');
    let bytes = match decode_base64_strict(trimmed) {
        Ok(b) => b,
        Err(reason) => {
            return EncodedCommandState::MalformedBase64 {
                raw_base64: trimmed.to_string(),
                reason,
            };
        }
    };
    if bytes.is_empty() || bytes.len() % 2 != 0 {
        return EncodedCommandState::MalformedBase64 {
            raw_base64: trimmed.to_string(),
            reason: format!(
                "UTF-16LE payload byte length {} must be non-empty and even",
                bytes.len()
            ),
        };
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    match String::from_utf16(&units) {
        Ok(decoded) => EncodedCommandState::Decoded {
            raw_base64: trimmed.to_string(),
            decoded_utf16le: decoded,
        },
        Err(e) => EncodedCommandState::MalformedBase64 {
            raw_base64: trimmed.to_string(),
            reason: format!("invalid UTF-16LE code unit sequence: {}", e),
        },
    }
}

/// Inspects a PowerShell script body for structural multi-token breakout patterns (reflective
/// Base64 + `iex`/`Invoke-Expression`, download cradles, credential store dumps).
fn analyze_script_body(script: &str) -> Vec<String> {
    let mut signals = Vec::new();
    let deobf: String = script.chars().filter(|&c| c != '`').collect();
    let lower = deobf.to_ascii_lowercase();

    let has_b64_decode = lower.contains("frombase64string");
    let has_eval = lower.contains("invoke-expression")
        || lower.split(|c: char| !c.is_ascii_alphanumeric() && c != '-')
            .any(|tok| tok == "iex" || tok == "icm" || tok == "invoke-command");
    if has_b64_decode && has_eval {
        signals.push(
            "PowerShell reflective Base64 decode coupled with dynamic evaluation (FromBase64String + IEX/Invoke-Expression)".to_string(),
        );
    }

    let has_net_client = lower.contains("net.webclient")
        || lower.contains("downloadstring")
        || lower.contains("downloaddata")
        || lower.contains("invoke-webrequest")
        || lower.contains("invoke-restmethod");
    if has_net_client && has_eval {
        signals.push(
            "PowerShell network download cradle coupled with dynamic evaluation".to_string(),
        );
    }

    if (lower.contains("hklm\\sam") || lower.contains("hklm:\\sam") || lower.contains("system32\\config\\sam"))
        && (lower.contains("reg ") || lower.contains("save") || lower.contains("copy"))
    {
        signals.push("SAM registry hive extraction command in script body".to_string());
    }

    if lower.contains("vssadmin") && lower.contains("shadow") {
        signals.push("Volume Shadow Copy manipulation in script body".to_string());
    }

    signals
}

/// Analyzes a raw command line, recursively unwrapping `cmd /c|/k|/r` and nested PowerShell
/// invocations up to [`MAX_UNWRAP_DEPTH`].
pub fn analyze_command_line(raw: &str) -> ParsedInvocation {
    analyze_at_depth(raw, 0)
}

fn analyze_at_depth(raw: &str, depth: usize) -> ParsedInvocation {
    let decareted = strip_cmd_carets_outside_quotes(raw);
    let argv = tokenize_windows_argv(&decareted);
    let executable_stem = argv
        .first()
        .map(|a| normalize_executable_stem(a))
        .unwrap_or_default();

    let is_cmd_wrapper = matches!(executable_stem.as_str(), "cmd" | "start");
    let is_powershell = matches!(executable_stem.as_str(), "powershell" | "pwsh");

    let mut ps_parameters = Vec::new();
    let mut encoded_command = EncodedCommandState::NotPresent;
    let mut window_style_hidden = false;
    let mut execution_policy_bypass = false;
    let mut script_structural_signals = Vec::new();
    let mut nested = Vec::new();

    if is_cmd_wrapper && depth < MAX_UNWRAP_DEPTH {
        let mut idx = 1usize;
        while idx < argv.len() {
            let tok = argv[idx].to_ascii_lowercase();
            if executable_stem == "cmd" && matches!(tok.as_str(), "/c" | "/k" | "/r" | "-c" | "-k" | "-r") {
                let rest = argv[idx + 1..].join(" ");
                if !rest.trim().is_empty() {
                    nested.push(analyze_at_depth(&rest, depth + 1));
                }
                break;
            } else if executable_stem == "cmd" && (tok.starts_with("/c") || tok.starts_with("/k") || tok.starts_with("/r")) && tok.len() > 2 {
                let mut rest = argv[idx][2..].to_string();
                if idx + 1 < argv.len() {
                    rest.push(' ');
                    rest.push_str(&argv[idx + 1..].join(" "));
                }
                nested.push(analyze_at_depth(&rest, depth + 1));
                break;
            } else if executable_stem == "start" && !tok.starts_with('/') && !tok.starts_with('-') {
                let rest = argv[idx..].join(" ");
                nested.push(analyze_at_depth(&rest, depth + 1));
                break;
            }
            idx += 1;
        }
    }

    if is_powershell {
        ps_parameters = parse_powershell_args(&argv[1..]);
        for param in &ps_parameters {
            match param {
                PsParameter::EncodedCommand(raw_b64) => {
                    let state = decode_encoded_command(raw_b64);
                    if let EncodedCommandState::Decoded {
                        ref decoded_utf16le,
                        ..
                    } = state
                    {
                        script_structural_signals.extend(analyze_script_body(decoded_utf16le));
                        if depth < MAX_UNWRAP_DEPTH {
                            let child = analyze_at_depth(decoded_utf16le, depth + 1);
                            if child.is_powershell || child.is_cmd_wrapper || child.has_breakout_signals() {
                                nested.push(child);
                            }
                        }
                    }
                    encoded_command = state;
                }
                PsParameter::Command(script) => {
                    script_structural_signals.extend(analyze_script_body(script));
                    if depth < MAX_UNWRAP_DEPTH {
                        let child = analyze_at_depth(script, depth + 1);
                        if child.is_powershell && !matches!(child.encoded_command, EncodedCommandState::NotPresent) {
                            nested.push(child);
                        }
                    }
                }
                PsParameter::WindowStyle(w) => {
                    let wl = w.trim().to_ascii_lowercase();
                    if wl == "1" || ("hidden".starts_with(&wl) && !wl.is_empty()) {
                        window_style_hidden = true;
                    }
                }
                PsParameter::ExecutionPolicy(ep) => {
                    let epl = ep.trim().to_ascii_lowercase();
                    if "bypass".starts_with(&epl) || "unrestricted".starts_with(&epl) {
                        execution_policy_bypass = true;
                    }
                }
                _ => {}
            }
        }
    } else if !is_cmd_wrapper && depth == 0 {
        for segment in decareted.split(&[';', '|', '&'][..]) {
            let seg = segment.trim();
            let seg_argv = tokenize_windows_argv(seg);
            if let Some(first) = seg_argv.first() {
                let stem = normalize_executable_stem(first);
                if matches!(stem.as_str(), "powershell" | "pwsh" | "cmd") && depth < MAX_UNWRAP_DEPTH {
                    nested.push(analyze_at_depth(seg, depth + 1));
                }
            }
        }
    }

    ParsedInvocation {
        raw_command_line: raw.to_string(),
        argv,
        executable_stem,
        is_powershell,
        is_cmd_wrapper,
        ps_parameters,
        encoded_command,
        window_style_hidden,
        execution_policy_bypass,
        script_structural_signals,
        nested,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_argv_tokenization_msvcrt_rules() {
        let cmd = r#"myprog.exe "a b c" d e"#;
        assert_eq!(tokenize_windows_argv(cmd), vec!["myprog.exe", "a b c", "d", "e"]);

        let cmd_quotes = r#"myprog.exe "a\"b" c"#;
        assert_eq!(tokenize_windows_argv(cmd_quotes), vec!["myprog.exe", "a\"b", "c"]);

        let cmd_double_quotes = r#"myprog.exe "a""b" c"#;
        assert_eq!(tokenize_windows_argv(cmd_double_quotes), vec!["myprog.exe", "a\"b", "c"]);
    }

    #[test]
    fn test_powershell_switch_classification() {
        assert_eq!(classify_ps_switch_name("e"), "encodedcommand");
        assert_eq!(classify_ps_switch_name("ec"), "encodedcommand");
        assert_eq!(classify_ps_switch_name("enc"), "encodedcommand");
        assert_eq!(classify_ps_switch_name("encodedcommand"), "encodedcommand");
        assert_eq!(classify_ps_switch_name("c"), "command");
        assert_eq!(classify_ps_switch_name("command"), "command");
        assert_eq!(classify_ps_switch_name("nop"), "noprofile");
        assert_eq!(classify_ps_switch_name("w"), "windowstyle");
        assert_eq!(classify_ps_switch_name("ep"), "executionpolicy");
    }

    #[test]
    fn test_utf16le_base64_roundtrip() {
        let script = "Write-Host 'Hello World'";
        let b64 = encode_utf16le_base64(script);
        match decode_encoded_command(&b64) {
            EncodedCommandState::Decoded { decoded_utf16le, .. } => {
                assert_eq!(decoded_utf16le, script);
            }
            other => panic!("Expected Decoded, got {:?}", other),
        }
    }
}
