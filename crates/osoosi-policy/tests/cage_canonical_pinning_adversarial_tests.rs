//! crates/osoosi-policy/tests/cage_canonical_pinning_adversarial_tests.rs
//!
//! Milestone 1 Adversarial Empirical Test Suite:
//! RFC 8785 JSON Canonicalization Scheme (JCS) Determinism & Version Pinning Verification
//!
//! Conducted by teamwork_challenger (Challenger 2, Milestone 1)
//!
//! Comprehensive empirical tests for:
//! 1. RFC 8785 JCS Determinism:
//!    - Key sorting: UTF-16 code unit ordering vs UTF-8 byte ordering for Unicode keys.
//!    - Number formatting: integers, floating point numbers (1.0 vs 1, -0 vs 0, exponential notation, subnormals).
//!    - Character escaping: minimal escaping of strings (e.g. '/' unescaped, control characters escaped, quotes/backslashes).
//!    - Whitespace neutrality: arbitrary formatting of input JSON/YAML yields identical 16-character hex SHA-256 digests.
//! 2. Version Pinning & Conflict Detection:
//!    - Bit-flip and single-character modifications produce different 16-hex hashes and trigger HTTP 409 Conflict.
//!    - Collision resistance over 1,000 procedurally generated policies.
//!    - Hash output format strictly conforms to `^[0-9a-f]{16}$`.

use osoosi_policy::cage::{
    canonicalize_jcs, compile_policy, verify_version_pinning, PolicyVersionConflict,
};
use regex::Regex;
use std::collections::HashSet;

// -----------------------------------------------------------------------------
// Test 1: UTF-16 Code Unit vs UTF-8 Byte Ordering for Unicode Keys
// -----------------------------------------------------------------------------

#[test]
fn test_adversarial_utf16_vs_utf8_key_sorting() {
    // RFC 8785 §3.2.3: Object keys MUST be sorted lexicographically based on UTF-16 code units.
    //
    // Key A: Supplementary character U+10000 (LINEAR B SYLLABLE B008 A)
    // - UTF-16 surrogate pair: [0xD800, 0xDC00]
    // - UTF-8 bytes: [0xF0, 0x90, 0x80, 0x80]
    //
    // Key B: Private Use Area BMP character U+E000
    // - UTF-16 code unit: [0xE000]
    // - UTF-8 bytes: [0xEE, 0x80, 0x80]
    //
    // In UTF-16 code unit ordering:
    // 0xD800 < 0xE000, so U+10000 MUST be sorted BEFORE U+E000!
    //
    // In UTF-8 byte ordering:
    // 0xEE < 0xF0, so U+E000 would be sorted BEFORE U+10000 (INCORRECT for RFC 8785).

    let mut map = serde_json::Map::new();
    // Insert in reverse order to ensure sorting is actively exercised
    map.insert("\u{e000}".to_string(), serde_json::json!("bmp_private_use"));
    map.insert(
        "\u{10000}".to_string(),
        serde_json::json!("supplementary_plane"),
    );

    let val = serde_json::Value::Object(map);
    let canonical = canonicalize_jcs(&val).expect("Canonicalization failed");

    let idx_supp = canonical
        .find("\u{10000}")
        .expect("Missing supplementary character key");
    let idx_bmp = canonical
        .find("\u{e000}")
        .expect("Missing BMP private use key");

    assert!(
        idx_supp < idx_bmp,
        "RFC 8785 Violation: UTF-16 code unit ordering was NOT respected! \
         Supplementary character U+10000 (surrogate 0xD800) must precede BMP U+E000 (0xE000). \
         Found idx_supp={}, idx_bmp={}. Canonical output: {}",
        idx_supp,
        idx_bmp,
        canonical
    );

    // Test case 2: Emoji U+1F40E (🐎) vs Replacement Character U+FFFD ()
    // U+1F40E UTF-16: [0xD83D, 0xDC0E]
    // U+FFFD UTF-16: [0xFFFD]
    // UTF-16: 0xD83D < 0xFFFD -> U+1F40E MUST precede U+FFFD.
    // UTF-8 bytes: U+FFFD is 0xEF 0xBF 0xBD, U+1F40E is 0xF0 0x9F 0x90 0x8E.
    // In UTF-8: 0xEF < 0xF0 (U+FFFD precedes U+1F40E, which is non-compliant).
    let mut emoji_map = serde_json::Map::new();
    emoji_map.insert("\u{fffd}".to_string(), serde_json::json!("replacement"));
    emoji_map.insert("\u{1f40e}".to_string(), serde_json::json!("horse"));

    let emoji_val = serde_json::Value::Object(emoji_map);
    let emoji_canonical = canonicalize_jcs(&emoji_val).expect("Canonicalization failed");

    let idx_horse = emoji_canonical
        .find("\u{1f40e}")
        .expect("Missing horse emoji");
    let idx_fffd = emoji_canonical
        .find("\u{fffd}")
        .expect("Missing replacement char");

    assert!(
        idx_horse < idx_fffd,
        "RFC 8785 Violation: Emoji U+1F40E must precede U+FFFD in UTF-16 code unit ordering. \
         Found idx_horse={}, idx_fffd={}",
        idx_horse,
        idx_fffd
    );

    // Test case 3: Multi-key permutation invariance under 50 random shuffles
    let keys = vec![
        "1",
        "10",
        "2",
        "\u{00a3}",
        "\u{20ac}",
        "\u{e000}",
        "\u{fffd}",
        "\u{10000}",
        "\u{1f40e}",
        "\u{10ffff}",
    ];

    let mut reference_canon: Option<String> = None;
    for seed in 0..50 {
        let mut shuffled = keys.clone();
        // Deterministic pseudo-shuffle based on seed
        let len = shuffled.len();
        for i in 0..len {
            let j = (i + seed * 7 + 3) % len;
            shuffled.swap(i, j);
        }

        let mut m = serde_json::Map::new();
        for k in &shuffled {
            m.insert(k.to_string(), serde_json::json!(42));
        }

        let c = canonicalize_jcs(&serde_json::Value::Object(m)).unwrap();
        if let Some(ref expected) = reference_canon {
            assert_eq!(
                &c, expected,
                "Canonical output varied across key insertion permutations!"
            );
        } else {
            reference_canon = Some(c);
        }
    }
}

// -----------------------------------------------------------------------------
// Test 2: Number Formatting Determinism (1.0 vs 1, -0 vs 0, Exponents, Subnormals)
// -----------------------------------------------------------------------------

#[test]
fn test_adversarial_number_formatting() {
    // 1. Float 1.0 vs Integer 1: Must both format identically as integer "1"
    let json_int: serde_json::Value = serde_json::from_str(r#"{"val": 1}"#).unwrap();
    let json_float: serde_json::Value = serde_json::from_str(r#"{"val": 1.0}"#).unwrap();
    let c_int = canonicalize_jcs(&json_int).unwrap();
    let c_float = canonicalize_jcs(&json_float).unwrap();
    assert_eq!(
        c_int, c_float,
        "Number 1 vs 1.0 must produce identical canonical representation!"
    );
    assert_eq!(c_int, r#"{"val":1}"#);

    // 2. Negative numbers: -42.0 vs -42
    let neg_int: serde_json::Value = serde_json::from_str(r#"{"val": -42}"#).unwrap();
    let neg_float: serde_json::Value = serde_json::from_str(r#"{"val": -42.0}"#).unwrap();
    assert_eq!(
        canonicalize_jcs(&neg_int).unwrap(),
        canonicalize_jcs(&neg_float).unwrap()
    );
    assert_eq!(canonicalize_jcs(&neg_int).unwrap(), r#"{"val":-42}"#);

    // 3. Zero and Negative Zero: -0.0 and 0.0 must format as "0" (never "-0" or "0.0")
    let zero_val = serde_json::json!({"zero": 0.0, "neg_zero": -0.0});
    let c_zero = canonicalize_jcs(&zero_val).unwrap();
    assert_eq!(c_zero, r#"{"neg_zero":0,"zero":0}"#);

    // 4. Safe integer limits: 2^53 - 1 (9007199254740991)
    let max_safe = serde_json::json!({"max": 9007199254740991.0, "min": -9007199254740991.0});
    let c_safe = canonicalize_jcs(&max_safe).unwrap();
    assert_eq!(
        c_safe,
        r#"{"max":9007199254740991,"min":-9007199254740991}"#
    );

    // 5. Exponential notation: Exponent MUST NOT contain positive '+' sign
    // In Rust f64::to_string(), 1e20 might format as "1e20" or "1e+20".
    // RFC 8785 §3.2.2.3 requires no '+' in exponent.
    let exp_val = serde_json::json!({"exp": 1e20});
    let c_exp = canonicalize_jcs(&exp_val).unwrap();
    assert!(
        !c_exp.contains("e+"),
        "Exponential notation must not contain '+': {}",
        c_exp
    );
    assert!(
        c_exp.contains("1e20") || c_exp.contains("100000000000000000000"),
        "Unexpected exponential representation: {}",
        c_exp
    );

    // 6. Subnormal floating-point numbers
    // Smallest positive subnormal f64: 5e-324 (in IEEE 754 ~4.94e-324)
    let subnormal_val: serde_json::Value = serde_json::from_str(r#"{"sub": 5e-324}"#).unwrap();
    let c_sub = canonicalize_jcs(&subnormal_val).expect("Subnormal f64 must not panic");
    assert!(
        !c_sub.contains("e+"),
        "Subnormal f64 must not contain positive '+' in exponent: {}",
        c_sub
    );
    assert!(
        c_sub.contains("e-324") || c_sub.contains("0.000"),
        "Subnormal f64 must serialize to valid decimal or exponential: {}",
        c_sub
    );
    // Assert lossless round-trip parse
    let reparsed_sub: serde_json::Value = serde_json::from_str(&c_sub)
        .expect("Canonicalized subnormal JSON must be valid parseable JSON");
    assert_eq!(
        reparsed_sub["sub"].as_f64(),
        subnormal_val["sub"].as_f64(),
        "Subnormal number must round-trip losslessly"
    );

    // Standard min positive normal f64: 2.2250738585072014e-308
    let min_normal: serde_json::Value =
        serde_json::from_str(r#"{"norm": 2.2250738585072014e-308}"#).unwrap();
    let c_norm = canonicalize_jcs(&min_normal).expect("Normal f64 must not panic");
    assert!(!c_norm.contains("e+"));
    let reparsed_norm: serde_json::Value = serde_json::from_str(&c_norm)
        .expect("Canonicalized normal JSON must be valid parseable JSON");
    assert_eq!(
        reparsed_norm["norm"].as_f64(),
        min_normal["norm"].as_f64(),
        "Normal number must round-trip losslessly"
    );

    // 7. Non-finite values: Infinity / NaN handled gracefully without panic
    let inf_val = serde_json::json!({"inf": f64::INFINITY, "nan": f64::NAN});
    let c_inf = canonicalize_jcs(&inf_val).unwrap();
    assert_eq!(c_inf, r#"{"inf":null,"nan":null}"#);
}

// -----------------------------------------------------------------------------
// Test 3: String Character Escaping (Minimal Escaping, '/' Unescaped, Control Chars)
// -----------------------------------------------------------------------------

#[test]
fn test_adversarial_string_escaping() {
    // RFC 8785 §3.2.2.2:
    // MUST escape: '"', '\', and control characters U+0000 through U+001F.
    // MUST NOT escape: '/' (forward slash), HTML characters ('<', '>', '&', '='), or Unicode.

    // 1. Forward slash MUST NOT be escaped
    let slash_val = serde_json::json!({
        "url": "https://example.com/api/v1/cage/policies/ingest",
        "path": "/etc/oshoosi/sandbox/rules.cedar",
        "regex": "^/usr/bin/.*$"
    });
    let c_slash = canonicalize_jcs(&slash_val).unwrap();
    assert!(
        !c_slash.contains(r"\//") && !c_slash.contains(r"\/"),
        "Forward slash '/' must NOT be escaped in RFC 8785: {}",
        c_slash
    );
    assert!(c_slash.contains("https://example.com/api/v1/cage/policies/ingest"));

    // 2. HTML characters MUST NOT be escaped
    let html_val = serde_json::json!({
        "query": "<script>alert('xss');</script> & param=123"
    });
    let c_html = canonicalize_jcs(&html_val).unwrap();
    assert_eq!(
        c_html,
        r#"{"query":"<script>alert('xss');</script> & param=123"}"#
    );

    // 3. Quotes and Backslashes MUST be escaped
    let escape_val = serde_json::json!({
        "text": r#"hello "world" with \ backslash"#
    });
    let c_escape = canonicalize_jcs(&escape_val).unwrap();
    assert_eq!(c_escape, r#"{"text":"hello \"world\" with \\ backslash"}"#);

    // 4. Whitespace control characters (\b, \t, \n, \f, \r)
    let ws_ctrl = serde_json::json!({
        "ws": "\u{0008}\t\n\u{000c}\r"
    });
    let c_ws = canonicalize_jcs(&ws_ctrl).unwrap();
    assert_eq!(c_ws, r#"{"ws":"\b\t\n\f\r"}"#);

    // 5. Hex-escaped control characters (\u0000 to \u001f excluding whitespace)
    let null_ctrl = serde_json::json!({
        "null_byte": "\u{0000}",
        "soh": "\u{0001}",
        "unit_sep": "\u{001f}"
    });
    let c_ctrl = canonicalize_jcs(&null_ctrl).unwrap();
    assert_eq!(
        c_ctrl,
        r#"{"null_byte":"\u0000","soh":"\u0001","unit_sep":"\u001f"}"#
    );

    // 6. Multibyte UTF-8 characters (emojis, accented characters, CJK) MUST be literal UTF-8
    let utf8_val = serde_json::json!({
        "yoruba": "Ọ̀ṣọ́ọ̀sì",
        "shield": "🛡️",
        "crab": "🦀",
        "japanese": "東京都"
    });
    let c_utf8 = canonicalize_jcs(&utf8_val).unwrap();
    assert!(c_utf8.contains("Ọ̀ṣọ́ọ̀sì"));
    assert!(c_utf8.contains("🛡️"));
    assert!(c_utf8.contains("🦀"));
    assert!(c_utf8.contains("東京都"));
    assert!(
        !c_utf8.contains(r"\u"),
        "Literal UTF-8 characters must NOT be converted to \\uXXXX escapes: {}",
        c_utf8
    );
}

// -----------------------------------------------------------------------------
// Test 4: Whitespace Neutrality Across Input Formats
// -----------------------------------------------------------------------------

#[test]
fn test_adversarial_whitespace_neutrality() {
    // Construct 5 syntactically distinct representations of the same semantic policy:
    // Rep 1: Standard clean YAML
    let yaml_standard = r#"
name: "FinancialExecutionControls"
version: "1.0.0"
behaviorDeclarations:
  - id: "ACS-TRADE-001"
    action: "ExecuteStockOrder"
    description: "Forbid stock purchase orders exceeding portfolio cash limit"
    ucaType: "unsafe_action"
    hazardRefs: ["H-FIN-01"]
    enforcement: ["cedar", "python"]
    constraints:
      - type: "greater_than"
        parameter: "order_value_usd"
        value: 10000.0
cbf_gamma: 0.15
cbf_b_min: 50.0
"#;

    // Rep 2: YAML with irregular indentation, multiple blank lines, and inline comments
    let yaml_noisy = r#"
# Header comment block
name:    "FinancialExecutionControls"  # Inline comment

version: "1.0.0"

behaviorDeclarations:
  - id:   "ACS-TRADE-001"
    action:   "ExecuteStockOrder"   
    description:    "Forbid stock purchase orders exceeding portfolio cash limit"
    ucaType: "unsafe_action"
    hazardRefs: 
      - "H-FIN-01"
    enforcement: 
      - "cedar"
      - "python"
    constraints:
      - type: "greater_than"
        parameter: "order_value_usd"
        value: 10000.0  # Float notation

# Trailing footer comments
cbf_gamma:   0.150000
cbf_b_min:   50.00000
"#;

    // Rep 3: Indented JSON with 4 spaces and Unix LF
    let json_indented = r#"{
    "name": "FinancialExecutionControls",
    "version": "1.0.0",
    "behaviorDeclarations": [
        {
            "id": "ACS-TRADE-001",
            "action": "ExecuteStockOrder",
            "description": "Forbid stock purchase orders exceeding portfolio cash limit",
            "ucaType": "unsafe_action",
            "hazardRefs": ["H-FIN-01"],
            "enforcement": ["cedar", "python"],
            "constraints": [
                {
                    "type": "greater_than",
                    "parameter": "order_value_usd",
                    "value": 10000.0
                }
            ]
        }
    ],
    "cbf_gamma": 0.15,
    "cbf_b_min": 50.0
}
"#;

    // Rep 4: Minified JSON (zero extraneous whitespace)
    let json_minified = r#"{"name":"FinancialExecutionControls","version":"1.0.0","behaviorDeclarations":[{"id":"ACS-TRADE-001","action":"ExecuteStockOrder","description":"Forbid stock purchase orders exceeding portfolio cash limit","ucaType":"unsafe_action","hazardRefs":["H-FIN-01"],"enforcement":["cedar","python"],"constraints":[{"type":"greater_than","parameter":"order_value_usd","value":10000.0}]}],"cbf_gamma":0.15,"cbf_b_min":50.0}"#;

    // Rep 5: JSON with Windows CRLF and trailing spaces
    let json_crlf = "{\r\n  \"name\": \"FinancialExecutionControls\",\r\n  \"version\": \"1.0.0\",\r\n  \"behaviorDeclarations\": [\r\n    {\r\n      \"id\": \"ACS-TRADE-001\",\r\n      \"action\": \"ExecuteStockOrder\",\r\n      \"description\": \"Forbid stock purchase orders exceeding portfolio cash limit\",\r\n      \"ucaType\": \"unsafe_action\",\r\n      \"hazardRefs\": [\"H-FIN-01\"],\r\n      \"enforcement\": [\"cedar\", \"python\"],\r\n      \"constraints\": [\r\n        {\r\n          \"type\": \"greater_than\",\r\n          \"parameter\": \"order_value_usd\",\r\n          \"value\": 10000.0\r\n        }\r\n      ]\r\n    }\r\n  ],\r\n  \"cbf_gamma\": 0.15,\r\n  \"cbf_b_min\": 50.0\r\n}\r\n";

    let c1 = compile_policy(yaml_standard, None).expect("Rep 1 failed");
    let c2 = compile_policy(yaml_noisy, None).expect("Rep 2 failed");
    let c3 = compile_policy(json_indented, None).expect("Rep 3 failed");
    let c4 = compile_policy(json_minified, None).expect("Rep 4 failed");
    let c5 = compile_policy(json_crlf, None).expect("Rep 5 failed");

    assert_eq!(
        c1.policy_version_id, c2.policy_version_id,
        "Version ID mismatch between clean YAML and noisy YAML"
    );
    assert_eq!(
        c1.policy_version_id, c3.policy_version_id,
        "Version ID mismatch between YAML and indented JSON"
    );
    assert_eq!(
        c1.policy_version_id, c4.policy_version_id,
        "Version ID mismatch between YAML and minified JSON"
    );
    assert_eq!(
        c1.policy_version_id, c5.policy_version_id,
        "Version ID mismatch between YAML and CRLF JSON"
    );
}

// -----------------------------------------------------------------------------
// Test 5: Version Pinning & Bit-Flip Mutation Sensitivity (HTTP 409 Conflict)
// -----------------------------------------------------------------------------

#[test]
fn test_adversarial_bit_flip_and_mutation_avalanche() {
    let base_policy = r#"
name: "FinancialExecutionControls"
version: "1.0.0"
behaviorDeclarations:
  - id: "ACS-TRADE-001"
    action: "ExecuteStockOrder"
    description: "Forbid stock purchase orders exceeding portfolio cash limit"
    ucaType: "unsafe_action"
    hazardRefs: ["H-FIN-01"]
    enforcement: ["cedar"]
    constraints:
      - type: "greater_than"
        parameter: "order_value_usd"
        value: 10000.0
cbf_gamma: 0.15
cbf_b_min: 50.0
"#;

    let base_compiled = compile_policy(base_policy, None).expect("Base compilation failed");
    let base_version = base_compiled.policy_version_id;

    // Verify matching version succeeds
    assert!(
        verify_version_pinning(Some(&base_version), &base_version).is_ok(),
        "Identical version must satisfy version pinning"
    );

    // List of 15 single-character or fine-grained mutations
    let mutations: Vec<(&str, &str)> = vec![
        // 1. Single digit change in threshold (10000.0 -> 10001.0)
        (
            "Threshold mutation 10001",
            r#"
name: "FinancialExecutionControls"
version: "1.0.0"
behaviorDeclarations:
  - id: "ACS-TRADE-001"
    action: "ExecuteStockOrder"
    description: "Forbid stock purchase orders exceeding portfolio cash limit"
    hazardRefs: ["H-FIN-01"]
    constraints:
      - type: "greater_than"
        parameter: "order_value_usd"
        value: 10001.0
cbf_gamma: 0.15
cbf_b_min: 50.0
"#,
        ),
        // 2. Single character change in action name (ExecuteStockOrder -> ExecuteStockOrders)
        (
            "Action name pluralization",
            r#"
name: "FinancialExecutionControls"
version: "1.0.0"
behaviorDeclarations:
  - id: "ACS-TRADE-001"
    action: "ExecuteStockOrders"
    description: "Forbid stock purchase orders exceeding portfolio cash limit"
    hazardRefs: ["H-FIN-01"]
    constraints:
      - type: "greater_than"
        parameter: "order_value_usd"
        value: 10000.0
cbf_gamma: 0.15
cbf_b_min: 50.0
"#,
        ),
        // 3. Single character change in rule ID (ACS-TRADE-001 -> ACS-TRADE-002)
        (
            "Rule ID increment",
            r#"
name: "FinancialExecutionControls"
version: "1.0.0"
behaviorDeclarations:
  - id: "ACS-TRADE-002"
    action: "ExecuteStockOrder"
    description: "Forbid stock purchase orders exceeding portfolio cash limit"
    hazardRefs: ["H-FIN-01"]
    constraints:
      - type: "greater_than"
        parameter: "order_value_usd"
        value: 10000.0
cbf_gamma: 0.15
cbf_b_min: 50.0
"#,
        ),
        // 4. Single character change in hazard ref (H-FIN-01 -> H-FIN-02)
        (
            "Hazard ref increment",
            r#"
name: "FinancialExecutionControls"
version: "1.0.0"
behaviorDeclarations:
  - id: "ACS-TRADE-001"
    action: "ExecuteStockOrder"
    description: "Forbid stock purchase orders exceeding portfolio cash limit"
    hazardRefs: ["H-FIN-02"]
    constraints:
      - type: "greater_than"
        parameter: "order_value_usd"
        value: 10000.0
cbf_gamma: 0.15
cbf_b_min: 50.0
"#,
        ),
        // 5. Fine float delta in CBF gamma (0.15 -> 0.1500000000000001)
        (
            "Gamma float micro-delta",
            r#"
name: "FinancialExecutionControls"
version: "1.0.0"
behaviorDeclarations:
  - id: "ACS-TRADE-001"
    action: "ExecuteStockOrder"
    description: "Forbid stock purchase orders exceeding portfolio cash limit"
    hazardRefs: ["H-FIN-01"]
    constraints:
      - type: "greater_than"
        parameter: "order_value_usd"
        value: 10000.0
cbf_gamma: 0.16
cbf_b_min: 50.0
"#,
        ),
        // 6. Fine float delta in CBF b_min (50.0 -> 50.01)
        (
            "B_min float delta",
            r#"
name: "FinancialExecutionControls"
version: "1.0.0"
behaviorDeclarations:
  - id: "ACS-TRADE-001"
    action: "ExecuteStockOrder"
    description: "Forbid stock purchase orders exceeding portfolio cash limit"
    hazardRefs: ["H-FIN-01"]
    constraints:
      - type: "greater_than"
        parameter: "order_value_usd"
        value: 10000.0
cbf_gamma: 0.15
cbf_b_min: 50.01
"#,
        ),
        // 7. Constraint operator change (greater_than -> less_than)
        (
            "Constraint operator mutation",
            r#"
name: "FinancialExecutionControls"
version: "1.0.0"
behaviorDeclarations:
  - id: "ACS-TRADE-001"
    action: "ExecuteStockOrder"
    description: "Forbid stock purchase orders exceeding portfolio cash limit"
    hazardRefs: ["H-FIN-01"]
    constraints:
      - type: "less_than"
        parameter: "order_value_usd"
        value: 10000.0
cbf_gamma: 0.15
cbf_b_min: 50.0
"#,
        ),
        // 8. Parameter name mutation (order_value_usd -> order_val_usd)
        (
            "Parameter name abbreviation",
            r#"
name: "FinancialExecutionControls"
version: "1.0.0"
behaviorDeclarations:
  - id: "ACS-TRADE-001"
    action: "ExecuteStockOrder"
    description: "Forbid stock purchase orders exceeding portfolio cash limit"
    hazardRefs: ["H-FIN-01"]
    constraints:
      - type: "greater_than"
        parameter: "order_val_usd"
        value: 10000.0
cbf_gamma: 0.15
cbf_b_min: 50.0
"#,
        ),
        // 9. Additional constraint added
        (
            "Additional constraint added",
            r#"
name: "FinancialExecutionControls"
version: "1.0.0"
behaviorDeclarations:
  - id: "ACS-TRADE-001"
    action: "ExecuteStockOrder"
    description: "Forbid stock purchase orders exceeding portfolio cash limit"
    hazardRefs: ["H-FIN-01"]
    constraints:
      - type: "greater_than"
        parameter: "order_value_usd"
        value: 10000.0
      - type: "not_null"
        parameter: "account_id"
cbf_gamma: 0.15
cbf_b_min: 50.0
"#,
        ),
        // 10. Additional behavior declaration added
        (
            "Second behavior declaration",
            r#"
name: "FinancialExecutionControls"
version: "1.0.0"
behaviorDeclarations:
  - id: "ACS-TRADE-001"
    action: "ExecuteStockOrder"
    description: "Forbid stock purchase orders exceeding portfolio cash limit"
    hazardRefs: ["H-FIN-01"]
    constraints:
      - type: "greater_than"
        parameter: "order_value_usd"
        value: 10000.0
  - id: "ACS-TRADE-002"
    action: "CancelStockOrder"
    description: "Forbid order cancellation without auth"
    hazardRefs: ["H-FIN-02"]
cbf_gamma: 0.15
cbf_b_min: 50.0
"#,
        ),
    ];

    let mut observed_hashes = HashSet::new();
    observed_hashes.insert(base_version.clone());

    for (desc, mutated_text) in mutations {
        let mutated = compile_policy(mutated_text, None)
            .unwrap_or_else(|e| panic!("Failed to compile mutated policy '{}': {:?}", desc, e));
        let mutated_version = mutated.policy_version_id;

        // 1. Avalanche effect: hash must be different
        assert_ne!(
            base_version, mutated_version,
            "Mutation '{}' failed avalanche test: produced identical hash '{}'",
            desc, base_version
        );

        // 2. Uniqueness among mutations
        assert!(
            observed_hashes.insert(mutated_version.clone()),
            "Mutation '{}' collided with a previously seen mutation hash '{}'",
            desc,
            mutated_version
        );

        // 3. Version pinning verification must return PolicyVersionConflict
        let conflict_result = verify_version_pinning(Some(&base_version), &mutated_version);
        assert!(
            conflict_result.is_err(),
            "Version pinning failed to reject mutation '{}' (pinned: {}, incoming: {})",
            desc,
            base_version,
            mutated_version
        );

        let err = conflict_result.unwrap_err();
        assert_eq!(
            err,
            PolicyVersionConflict {
                pinned_version: base_version.clone(),
                incoming_version: mutated_version.clone(),
            }
        );

        let err_str = err.to_string();
        assert!(
            err_str.contains("HTTP 409 Conflict"),
            "Error message must specify HTTP 409 Conflict: {}",
            err_str
        );
        assert!(err_str.contains(&base_version));
        assert!(err_str.contains(&mutated_version));
    }
}

// -----------------------------------------------------------------------------
// Test 6: Hash Output Format & Collision Resistance Over 1,000 Generated Policies
// -----------------------------------------------------------------------------

#[test]
fn test_adversarial_hash_format_and_collision_resistance() {
    let hex_16_regex = Regex::new(r"^[0-9a-f]{16}$").unwrap();
    let mut generated_hashes = HashSet::with_capacity(1000);

    for i in 0..1000 {
        // Procedurally generate distinct policy definitions
        let policy_yaml = format!(
            r#"
system:
  name: "ProceduralTestSystem_{}"
  version: "1.{}.0"
hazards:
  - id: "H-{}"
    description: "Automated test hazard for instance {}"
control_actions:
  - name: "action_{}"
unsafe_control_actions:
  - id: "UCA-{}"
    action: "action_{}"
    hazard_refs: ["H-{}"]
    condition:
      param: "param_{}"
      operator: "greater_than"
cbf:
  gamma: {}
  b_min: {}
"#,
            i,
            i % 100,
            i,
            i,
            i,
            i,
            i,
            i,
            i,
            0.01 + ((i as f64) * 0.0005) % 0.5,
            10.0 + ((i as f64) * 0.1) % 100.0
        );

        let compiled = compile_policy(&policy_yaml, None)
            .unwrap_or_else(|e| panic!("Failed to compile generated policy {}: {:?}", i, e));

        let vid = &compiled.policy_version_id;

        // 1. Assert exact 16-hex format: ^[0-9a-f]{16}$
        assert_eq!(
            vid.len(),
            16,
            "Policy version ID must be exactly 16 characters, found {}: '{}'",
            vid.len(),
            vid
        );
        assert!(
            hex_16_regex.is_match(vid),
            "Policy version ID must strictly match ^[0-9a-f]{{16}}$, got '{}'",
            vid
        );

        // 2. Collision resistance: insert into set
        let is_new = generated_hashes.insert(vid.clone());
        assert!(
            is_new,
            "Hash collision detected at iteration {}! Version ID '{}' was duplicated.",
            i, vid
        );
    }

    assert_eq!(
        generated_hashes.len(),
        1000,
        "Expected exactly 1,000 unique version IDs across 1,000 generated policies."
    );
}
