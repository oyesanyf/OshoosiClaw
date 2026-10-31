#![allow(unused_imports)]
use anyhow::{anyhow, Result};
use chrono::Utc;
use flate2::read::ZlibDecoder;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tracing::{debug, info};

use super::*;

// ============================================================================
// Protection Layer 4: Counter-AI Prompt-Injection Scanner & String Sanitizer
// ============================================================================

/// Scan binary strings for embedded LLM prompt-injection / disassembler-poisoning payloads
/// and sanitize control characters, ANSI escape codes, and script tags from `reconstructed_code`.
pub fn scan_and_sanitize_counter_ai_strings(
    bytes: &[u8],
    reconstructed_code: &mut String,
    is_verified_self_binary: bool,
) -> (Vec<String>, usize) {
    let mut detected_injections = Vec::new();
    let mut sanitized_count = 0usize;

    if !is_verified_self_binary && !bytes.is_empty() {
        let strings = extract_printable_strings(bytes, 8, MAX_EXTRACTED_STRINGS);
        for s in &strings {
            let s_low = s.to_ascii_lowercase();
            let has_ignore_prev = s_low.contains("ignore ")
                && (s_low.contains("previous instructions")
                    || s_low.contains("all instructions")
                    || s_low.contains("prior instructions")
                    || s_low.contains("system instructions"));
            let has_disregard = (s_low.contains("disregard ") || s_low.contains("forget "))
                && (s_low.contains("previous instructions")
                    || s_low.contains("system prompt")
                    || s_low.contains("prior instructions"));
            let has_benign_override = (s_low.contains("mark this")
                || s_low.contains("classify this")
                || s_low.contains("report this")
                || s_low.contains("verdict:"))
                && (s_low.contains("as benign")
                    || s_low.contains("as safe")
                    || s_low.contains("threat_score = 0")
                    || s_low.contains("threat_score: 0"));
            let has_role_hijack = (s_low.contains("system prompt")
                && (s_low.contains("override") || s_low.contains("you are now")))
                || s_low.contains("<|im_start|>system")
                || s_low.contains("<<sys>>");

            if has_ignore_prev || has_disregard || has_benign_override || has_role_hijack {
                let snippet: String = s.chars().take(120).collect();
                detected_injections
                    .push(format!("REA_ANTI_ANALYSIS_PROMPT_INJECTION: {}", snippet));
                if detected_injections.len() >= 16 {
                    break;
                }
            }
        }

        // Also check raw bytes for ANSI CSI/OSC escape sequence injection (`\x1b[` or `\x1b]`).
        // Only classify as an anti-analysis prompt-injection finding when accompanied by a semantic
        // prompt-injection directive or an explicit terminal OSC/title/clipboard/screen-clear sequence,
        // avoiding false positives on 2-byte `0x1B 0x5B` (`sbb ebx, ...`) machine code in native binaries.
        if find_subslice(bytes, b"\x1b[").is_some() || find_subslice(bytes, b"\x1b]").is_some() {
            sanitized_count += 1;
            let has_terminal_hijack_escape = find_subslice(bytes, b"\x1b]0;").is_some()
                || find_subslice(bytes, b"\x1b]2;").is_some()
                || find_subslice(bytes, b"\x1b]52;").is_some()
                || find_subslice(bytes, b"\x1b[2J").is_some();
            if (!detected_injections.is_empty() || has_terminal_hijack_escape)
                && !detected_injections
                    .iter()
                    .any(|d| d.contains("ANSI_TERMINAL_ESCAPE"))
            {
                detected_injections.push(
                    "REA_ANTI_ANALYSIS_PROMPT_INJECTION: ANSI_TERMINAL_ESCAPE sequence embedded in binary strings"
                        .to_string(),
                );
            }
        }
    }

    // Sanitize reconstructed_code: strip ANSI escapes, raw control chars, script tags, and redact prompt injections
    if !reconstructed_code.is_empty() || !detected_injections.is_empty() {
        let mut clean = String::with_capacity(reconstructed_code.len() + 64);
        let mut chars = reconstructed_code.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\x1b' {
                sanitized_count += 1;
                if chars.peek() == Some(&'[') || chars.peek() == Some(&']') {
                    let _ = chars.next();
                    while let Some(&c) = chars.peek() {
                        chars.next();
                        if c.is_ascii_alphabetic() || c == '\x07' {
                            break;
                        }
                    }
                }
                continue;
            }
            if ch.is_control() && !matches!(ch, '\n' | '\r' | '\t') {
                sanitized_count += 1;
                continue;
            }
            clean.push(ch);
        }
        if clean.to_ascii_lowercase().contains("<script") {
            sanitized_count += 1;
            clean = clean
                .replace("<script", "<scr_ipt")
                .replace("<SCRIPT", "<SCR_IPT");
        }
        if !detected_injections.is_empty() {
            sanitized_count += detected_injections.len();
            let mut filtered_lines = Vec::new();
            for line in clean.lines() {
                let ll = line.to_ascii_lowercase();
                if (ll.contains("ignore ") && ll.contains("instructions"))
                    || (ll.contains("disregard ") && ll.contains("instructions"))
                    || ll.contains("<|im_start|>system")
                    || ll.contains("<<sys>>")
                {
                    filtered_lines.push("// [REDACTED_COUNTER_AI_PROMPT_INJECTION]".to_string());
                } else {
                    filtered_lines.push(line.to_string());
                }
            }
            clean = filtered_lines.join("\n");
            if !clean.contains("[REDACTED_COUNTER_AI_PROMPT_INJECTION]") {
                clean.push_str("\n// [REDACTED_COUNTER_AI_PROMPT_INJECTION]\n");
            }
        }
        *reconstructed_code = clean;
    }

    (detected_injections, sanitized_count)
}

/// Compute Shannon entropy (0.0 to 8.0 bits/byte) of a byte slice.
pub fn calculate_entropy(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f32;
    let mut entropy = 0.0f32;
    for &c in &counts {
        if c > 0 {
            let p = (c as f32) / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Find a subslice needle inside a byte slice.
pub fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Extract printable ASCII strings of at least `min_len` characters from a byte slice,
/// enforcing `MAX_EXTRACTED_STRINGS` and `MAX_SINGLE_STRING_BYTES` (Protection Layer 3).
pub fn extract_printable_strings(bytes: &[u8], min_len: usize, max_count: usize) -> Vec<String> {
    let effective_max = max_count.min(MAX_EXTRACTED_STRINGS);
    let mut results = Vec::new();
    let mut current = Vec::new();

    for &b in bytes {
        if (0x20..=0x7E).contains(&b) {
            if current.len() < MAX_SINGLE_STRING_BYTES {
                current.push(b);
            }
        } else {
            if current.len() >= min_len {
                if let Ok(s) = String::from_utf8(current.clone()) {
                    let trimmed = s.trim();
                    if trimmed.len() >= min_len {
                        results.push(trimmed.to_string());
                        if results.len() >= effective_max {
                            return results;
                        }
                    }
                }
            }
            current.clear();
        }
    }
    if current.len() >= min_len && results.len() < effective_max {
        if let Ok(s) = String::from_utf8(current) {
            let trimmed = s.trim();
            if trimmed.len() >= min_len {
                results.push(trimmed.to_string());
            }
        }
    }
    results
}
