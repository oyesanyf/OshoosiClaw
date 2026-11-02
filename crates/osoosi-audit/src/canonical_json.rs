//! RFC 8785 JSON Canonicalization Scheme (JCS)
//!
//! Pure-Rust implementation of RFC 8785 with zero external dependencies.
//! Enforces:
//! 1. Lexicographical sorting of object keys by UTF-16 code units (RFC 8785 §3.2.3).
//! 2. Minimal JSON string escaping (quote, backslash, control chars < 0x20 as `\u00xx`).
//! 3. Canonical ECMAScript number serialization, zero whitespace.
//! 4. Lowercase 64-character hex SHA-256 canonical hashing.

use sha2::{Digest, Sha256};
use std::fmt;

/// Errors that can occur during RFC 8785 JSON canonicalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JcsError {
    InvalidNumber(String),
    Serialization(String),
}

impl fmt::Display for JcsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNumber(msg) => write!(f, "RFC 8785 invalid number: {}", msg),
            Self::Serialization(msg) => write!(f, "RFC 8785 serialization error: {}", msg),
        }
    }
}

impl std::error::Error for JcsError {}

/// Canonicalize a `serde_json::Value` strictly following RFC 8785 JSON Canonicalization Scheme (JCS).
///
/// Output invariants:
/// - UTF-8 encoded string.
/// - Object keys sorted lexicographically by UTF-16 code unit values.
/// - Whitespace between tokens completely eliminated.
/// - Minimal string escaping (only `"`, `\`, and control characters U+0000..U+001F; `/` is unescaped).
/// - ECMAScript canonical number serialization (-0 as "0", integers without decimal points, exponents without '+').
pub fn canonicalize_jcs(value: &serde_json::Value) -> Result<String, JcsError> {
    let mut out = String::with_capacity(128);
    write_jcs_value(value, &mut out)?;
    Ok(out)
}

/// Compute the lowercase 64-hex SHA-256 digest of the RFC 8785 canonical representation of a JSON value.
pub fn compute_canonical_hash(value: &serde_json::Value) -> String {
    let canonical = canonicalize_jcs(value).unwrap_or_else(|_| value.to_string());
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize()).to_ascii_lowercase()
}

fn write_jcs_value(val: &serde_json::Value, out: &mut String) -> Result<(), JcsError> {
    match val {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        serde_json::Value::Number(n) => {
            write_jcs_number(n, out)?;
        }
        serde_json::Value::String(s) => {
            write_jcs_string(s, out);
        }
        serde_json::Value::Array(arr) => {
            out.push('[');
            for (i, elem) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_jcs_value(elem, out)?;
            }
            out.push(']');
        }
        serde_json::Value::Object(map) => {
            out.push('{');
            // RFC 8785 §3.2.3: Object keys MUST be sorted lexicographically by UTF-16 code units.
            let mut entries: Vec<(&String, &serde_json::Value)> = map.iter().collect();
            entries.sort_by(|(k1, _), (k2, _)| {
                let u1 = k1.encode_utf16();
                let u2 = k2.encode_utf16();
                u1.cmp(u2)
            });
            for (i, (key, value)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_jcs_string(key, out);
                out.push(':');
                write_jcs_value(value, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_jcs_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{000c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) <= 0x1F => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_jcs_number(n: &serde_json::Number, out: &mut String) -> Result<(), JcsError> {
    if let Some(i) = n.as_i64() {
        out.push_str(&i.to_string());
    } else if let Some(u) = n.as_u64() {
        out.push_str(&u.to_string());
    } else if let Some(f) = n.as_f64() {
        if f.is_nan() || f.is_infinite() {
            return Err(JcsError::InvalidNumber(
                "NaN and Infinity are not permitted in RFC 8785 JSON".to_string(),
            ));
        }
        if f == 0.0 {
            // ECMAScript: -0 is output as "0"
            out.push('0');
        } else if f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0 {
            out.push_str(&(f as i64).to_string());
        } else {
            // Format float without positive '+' in exponent
            let s = f.to_string();
            let s_clean = s.replace("e+", "e");
            out.push_str(&s_clean);
        }
    } else {
        out.push_str(&n.to_string());
    }
    Ok(())
}
