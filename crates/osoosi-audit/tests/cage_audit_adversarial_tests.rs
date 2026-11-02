//! Adversarial Stress Test Suite for `osoosi-audit` (CAGE Governance Substrate)
//!
//! Empirical validation of:
//! 1. RFC 8785 UTF-16 code unit ordering vs UTF-8 byte ordering (Supplementary vs BMP, surrogate pairs).
//! 2. IEEE 754 float edge cases (-0.0 normalization to "0", boundaries near 2^53 - 1, exponent formatting).
//! 3. Complex nested JSON object permutations with 100+ keys asserting identical SHA-256 hashes.
//! 4. Deeply nested structures (arrays of maps, maps of arrays) asserting whitespace stripping and formatting invariance.
//! 5. MerkleAuditTree spine folding under high volume (1,000+ entries) verifying incremental root matches full rebuild root.

use osoosi_audit::{
    canonicalize_jcs, compute_canonical_hash, verify_trace_chain, CageTraceRecord, MerkleAuditTree,
    GENESIS_PREV_HASH,
};
use serde_json::{json, Value};

// =============================================================================
// Helper Functions
// =============================================================================

/// Deterministic pseudo-random number generator (LCG) for reproducible adversarial shuffles.
struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u32(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        (self.state >> 32) as u32
    }

    fn shuffle<T>(&mut self, slice: &mut [T]) {
        for i in (1..slice.len()).rev() {
            let j = (self.next_u32() as usize) % (i + 1);
            slice.swap(i, j);
        }
    }
}

// =============================================================================
// 1. RFC 8785 UTF-16 Code Unit Ordering vs UTF-8 Byte Ordering Tests
// =============================================================================

#[test]
fn test_rfc8785_utf16_code_unit_vs_utf8_byte_ordering_adversarial() {
    // RFC 8785 §3.2.3 requires sorting keys by UTF-16 code units.
    // In UTF-8, BMP 3-byte characters (U+0800..U+FFFF) start with 0xE0..0xEF.
    // Supplementary 4-byte characters (U+10000..U+10FFFF) start with 0xF0..0xF4.
    // In naive UTF-8 byte ordering: ALL 3-byte characters come BEFORE 4-byte characters!
    // But in UTF-16: Supplementary characters are encoded with surrogate pairs (0xD800..0xDBFF)!
    // High surrogates (0xD800..0xDBFF) are LESS THAN BMP code units 0xE000..0xFFFF!
    //
    // Therefore: For any character in U+E000..U+FFFF and any character in U+10000..U+10FFFF,
    // UTF-8 byte order and UTF-16 code unit order are STRICTLY OPPOSITE.

    // Case 1: Replacement Character (U+FFFD) vs First Supplementary Character (U+10000)
    // U+FFFD:  UTF-16 = [0xFFFD],           UTF-8 = [0xEF, 0xBF, 0xBD]
    // U+10000: UTF-16 = [0xD800, 0xDC00],   UTF-8 = [0xF0, 0x90, 0x80, 0x80]
    let k_bmp_fffd = "\u{FFFD}";
    let k_supp_10000 = "\u{10000}";

    // Verify raw UTF-8 byte ordering places U+FFFD FIRST
    assert!(
        k_bmp_fffd.as_bytes() < k_supp_10000.as_bytes(),
        "UTF-8 byte order assertion"
    );
    // Verify UTF-16 code unit ordering places U+10000 FIRST
    let u16_bmp: Vec<u16> = k_bmp_fffd.encode_utf16().collect();
    let u16_supp: Vec<u16> = k_supp_10000.encode_utf16().collect();
    assert!(u16_supp < u16_bmp, "UTF-16 code unit order assertion");

    // Construct JSON object with both keys inserted in reverse UTF-16 order
    let mut map = serde_json::Map::new();
    map.insert(k_bmp_fffd.to_string(), json!(1));
    map.insert(k_supp_10000.to_string(), json!(2));
    let val = Value::Object(map);

    let canonical = canonicalize_jcs(&val).expect("Canonicalization must succeed");
    // RFC 8785 MUST place U+10000 BEFORE U+FFFD
    let expected = format!("{{\"{}\":2,\"{}\":1}}", k_supp_10000, k_bmp_fffd);
    assert_eq!(
        canonical, expected,
        "RFC 8785 UTF-16 code unit ordering violated!"
    );

    // Case 2: Classic RFC 8785 Triad: Euro (€), Musical G Clef (𝄞), Small Ligature fi (ﬁ)
    // Euro (€, U+20AC):     UTF-16 = [0x20AC],           UTF-8 = [0xE2, 0x82, 0xAC]
    // G Clef (𝄞, U+1D11E):   UTF-16 = [0xD834, 0xDD1E],   UTF-8 = [0xF0, 0x9D, 0x84, 0x9E]
    // fi ligature (ﬁ, U+FB01): UTF-16 = [0xFB01],         UTF-8 = [0xEF, 0xAC, 0x81]
    //
    // UTF-8 byte order:
    // 0xE2 (Euro) < 0xEF (fi) < 0xF0 (G clef) -> Euro < fi < G clef
    //
    // UTF-16 code unit order:
    // 0x20AC (Euro) < 0xD834 (G clef) < 0xFB01 (fi) -> Euro < G clef < fi
    let k_euro = "\u{20AC}";
    let k_gclef = "\u{1D11E}";
    let k_fi = "\u{FB01}";

    // Verify UTF-8 byte ordering
    let mut utf8_triad = vec![k_euro, k_gclef, k_fi];
    utf8_triad.sort();
    assert_eq!(
        utf8_triad,
        vec![k_euro, k_fi, k_gclef],
        "UTF-8 byte order must place G clef LAST"
    );

    let mut triad_map = serde_json::Map::new();
    triad_map.insert(k_fi.to_string(), json!("ligature"));
    triad_map.insert(k_euro.to_string(), json!("currency"));
    triad_map.insert(k_gclef.to_string(), json!("music"));
    let val_triad = Value::Object(triad_map);

    let canonical_triad = canonicalize_jcs(&val_triad).expect("Canonicalization must succeed");
    let expected_triad = format!(
        r#"{{"{}":"currency","{}":"music","{}":"ligature"}}"#,
        k_euro, k_gclef, k_fi
    );
    assert_eq!(
        canonical_triad, expected_triad,
        "G clef must be in the MIDDLE between Euro and fi under RFC 8785!"
    );

    // Case 3: Character pair \u{00E9} vs \u{0100}
    // \u{00E9} (é): UTF-16 = [0x00E9], UTF-8 = [0xC3, 0xA9]
    // \u{0100} (Ā): UTF-16 = [0x0100], UTF-8 = [0xC4, 0x80]
    let k_e_acute = "\u{00E9}";
    let k_a_macron = "\u{0100}";
    let mut e_map = serde_json::Map::new();
    e_map.insert(k_a_macron.to_string(), json!("macron"));
    e_map.insert(k_e_acute.to_string(), json!("acute"));
    let val_e = Value::Object(e_map);
    let canonical_e = canonicalize_jcs(&val_e).unwrap();
    let expected_e = format!(r#"{{"{}":"acute","{}":"macron"}}"#, k_e_acute, k_a_macron);
    assert_eq!(canonical_e, expected_e);

    // Case 4: Multi-character strings with common prefixes
    // "prefix\u{FFFF}" vs "prefix\u{10000}"
    let k_p_bmp = "prefix\u{FFFF}";
    let k_p_supp = "prefix\u{10000}";
    let mut p_map = serde_json::Map::new();
    p_map.insert(k_p_bmp.to_string(), json!("bmp"));
    p_map.insert(k_p_supp.to_string(), json!("supp"));
    let canonical_p = canonicalize_jcs(&Value::Object(p_map)).unwrap();
    let expected_p = format!(r#"{{"{}":"supp","{}":"bmp"}}"#, k_p_supp, k_p_bmp);
    assert_eq!(
        canonical_p, expected_p,
        "Prefixed strings must sort by UTF-16 code units"
    );
}

// =============================================================================
// 2. IEEE 754 Float Edge Cases Tests
// =============================================================================

#[test]
fn test_ieee754_float_edge_cases_and_normalization() {
    // 1. Negative Zero Normalization (-0.0 -> "0")
    let neg_zero_float = -0.0f64;
    let pos_zero_float = 0.0f64;

    let v_neg = json!({"value": neg_zero_float});
    let v_pos = json!({"value": pos_zero_float});
    let v_int = json!({"value": 0});

    let c_neg = canonicalize_jcs(&v_neg).unwrap();
    let c_pos = canonicalize_jcs(&v_pos).unwrap();
    let c_int = canonicalize_jcs(&v_int).unwrap();

    assert_eq!(c_neg, r#"{"value":0}"#, "-0.0 must normalize to 0");
    assert_eq!(c_pos, r#"{"value":0}"#, "0.0 must normalize to 0");
    assert_eq!(c_int, r#"{"value":0}"#, "0 must normalize to 0");

    assert_eq!(
        compute_canonical_hash(&v_neg),
        compute_canonical_hash(&v_pos),
        "Hash of -0.0 and +0.0 must be identical"
    );
    assert_eq!(
        compute_canonical_hash(&v_neg),
        compute_canonical_hash(&v_int),
        "Hash of -0.0 and integer 0 must be identical"
    );

    // Array with mixed zeros
    let v_zeros_arr = json!([-0.0, 0.0, 0, -0.0]);
    assert_eq!(canonicalize_jcs(&v_zeros_arr).unwrap(), "[0,0,0,0]");

    // 2. Boundaries Near 2^53 - 1 (Safe Integers: 9,007,199,254,740,991)
    let max_safe = 9007199254740991.0f64;
    let min_safe = -9007199254740991.0f64;
    let safe_minus_one = 9007199254740990.0f64;
    let neg_safe_plus_one = -9007199254740990.0f64;

    let boundary_obj = json!({
        "max_safe": max_safe,
        "min_safe": min_safe,
        "sub_max": safe_minus_one,
        "sub_min": neg_safe_plus_one
    });
    let c_bound = canonicalize_jcs(&boundary_obj).unwrap();
    assert_eq!(
        c_bound,
        r#"{"max_safe":9007199254740991,"min_safe":-9007199254740991,"sub_max":9007199254740990,"sub_min":-9007199254740990}"#
    );

    // Integers within safe range formatted without decimals
    let integer_floats = json!({
        "one": 1.0,
        "neg_one": -1.0,
        "thousand": 1000.0,
        "million": 1000000.0
    });
    assert_eq!(
        canonicalize_jcs(&integer_floats).unwrap(),
        r#"{"million":1000000,"neg_one":-1,"one":1,"thousand":1000}"#
    );

    // 3. Exponent Formatting (RFC 8785 / ECMAScript: No '+' in exponent, lowercase 'e')
    let exponents = json!({
        "e_pos_large": 1e20,
        "e_pos_huge": 1e30,
        "e_neg_small": 1e-12,
        "e_fraction": 1.2345e-8
    });
    let c_exp = canonicalize_jcs(&exponents).unwrap();
    assert!(
        !c_exp.contains("e+"),
        "Canonical JSON exponent must never contain 'e+'"
    );
    assert!(
        !c_exp.contains("E"),
        "Canonical JSON exponent must use lowercase 'e'"
    );

    // 4. Fractional Floats with Non-Zero Fractions
    let fractions = json!({
        "half": 0.5,
        "neg_half": -0.5,
        "eighth": 0.125,
        "compound": 123.456
    });
    assert_eq!(
        canonicalize_jcs(&fractions).unwrap(),
        r#"{"compound":123.456,"eighth":0.125,"half":0.5,"neg_half":-0.5}"#
    );
}

// =============================================================================
// 3. Complex Nested JSON Object Permutations with 100+ Keys Tests
// =============================================================================

#[test]
fn test_complex_nested_100_plus_keys_permutation_determinism() {
    // Generate 120 unique keys spanning ASCII, unicode, surrogate pairs, symbols
    let mut key_pool = Vec::new();

    // 40 standard ASCII keys
    for i in 0..40 {
        key_pool.push(format!("field_{:03}", i));
    }
    // 20 symbols and punctuation
    for i in 0..20 {
        key_pool.push(format!("sym_#_{:02}", i));
    }
    // 20 Latin-1 and Greek unicode keys
    for c in [
        'α', 'β', 'γ', 'δ', 'ε', 'ζ', 'η', 'θ', 'λ', 'μ', 'π', 'σ', 'τ', 'φ', 'ψ', 'ω', 'é', 'è',
        'à', 'ç',
    ] {
        key_pool.push(format!("uni_{}", c));
    }
    // 20 CJK and mathematical keys
    for c in [
        '漢', '字', '日', '本', '語', '中', '文', '★', '⚡', '♾', '∑', '∏', '√', '∫', '≈', '≠',
        '≤', '≥', '∂', '∇',
    ] {
        key_pool.push(format!("sym_{}", c));
    }
    // 20 Supplementary characters (emojis and historic scripts, surrogate pairs)
    for c in [
        '😀', '🛡', '🔒', '🔑', '🚀', '🦀', '🔥', '✨', '⚡', '🏆', '🎯', '⚙', '🧪', '🧬', '🔬',
        '📡', '🛰', '🛸', '🪐', '🌌',
    ] {
        key_pool.push(format!("emoji_{}", c));
    }

    assert_eq!(key_pool.len(), 120);

    // Build master key-value pairs with varied nested data types
    let mut master_pairs: Vec<(String, Value)> = Vec::with_capacity(120);
    for (idx, key) in key_pool.iter().enumerate() {
        let val = match idx % 8 {
            0 => json!(idx as i64 * 42),
            1 => json!((idx as f64) * std::f64::consts::PI),
            2 => json!(idx % 2 == 0),
            3 => json!(null),
            4 => json!(format!("string_value_{}_{}", key, idx)),
            5 => json!([idx, idx + 1, { "nested_inner": idx * 10 }]),
            6 => json!({
                "sub_k1": "sub_v1",
                "sub_k2": idx as f64,
                "sub_k3": [true, false, null]
            }),
            _ => json!(-0.0f64), // Negative zero
        };
        master_pairs.push((key.clone(), val));
    }

    // Build 8 distinct permutations of the 120-key object
    let mut permutations: Vec<Value> = Vec::new();

    // Permutation 0: Natural insertion order
    let mut p0 = serde_json::Map::new();
    for (k, v) in &master_pairs {
        p0.insert(k.clone(), v.clone());
    }
    permutations.push(Value::Object(p0));

    // Permutation 1: Reverse insertion order
    let mut p1 = serde_json::Map::new();
    for (k, v) in master_pairs.iter().rev() {
        p1.insert(k.clone(), v.clone());
    }
    permutations.push(Value::Object(p1));

    // Permutations 2, 3, 4: Pseudo-random shuffles with distinct seeds
    for seed in [42u64, 1337u64, 999999u64] {
        let mut rng = DeterministicRng::new(seed);
        let mut shuffled = master_pairs.clone();
        rng.shuffle(&mut shuffled);

        let mut p = serde_json::Map::new();
        for (k, v) in shuffled {
            p.insert(k, v);
        }
        permutations.push(Value::Object(p));
    }

    // Permutation 5: Even keys first, then odd keys
    let mut p5 = serde_json::Map::new();
    for (k, v) in master_pairs.iter().step_by(2) {
        p5.insert(k.clone(), v.clone());
    }
    for (k, v) in master_pairs.iter().skip(1).step_by(2) {
        p5.insert(k.clone(), v.clone());
    }
    permutations.push(Value::Object(p5));

    // Permutation 6: Odd keys first, then even keys
    let mut p6 = serde_json::Map::new();
    for (k, v) in master_pairs.iter().skip(1).step_by(2) {
        p6.insert(k.clone(), v.clone());
    }
    for (k, v) in master_pairs.iter().step_by(2) {
        p6.insert(k.clone(), v.clone());
    }
    permutations.push(Value::Object(p6));

    // Permutation 7: Shuffled outer keys AND shuffled inner nested object keys
    let mut rng7 = DeterministicRng::new(777);
    let mut shuffled7 = master_pairs.clone();
    rng7.shuffle(&mut shuffled7);
    let mut p7 = serde_json::Map::new();
    for (k, mut v) in shuffled7 {
        if let Value::Object(ref mut inner_map) = v {
            let mut inner_pairs: Vec<(String, Value)> =
                std::mem::take(inner_map).into_iter().collect();
            rng7.shuffle(&mut inner_pairs);
            for (ik, iv) in inner_pairs {
                inner_map.insert(ik, iv);
            }
        }
        p7.insert(k, v);
    }
    permutations.push(Value::Object(p7));

    assert_eq!(permutations.len(), 8);

    // Compute baseline canonical string and hash from Permutation 0
    let baseline_canonical = canonicalize_jcs(&permutations[0]).expect("Baseline canonicalize");
    let baseline_hash = compute_canonical_hash(&permutations[0]);

    assert_eq!(baseline_hash.len(), 64);
    assert!(baseline_hash
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

    // Verify all 7 other permutations produce the EXACT SAME canonical string and SHA-256 hash
    for (idx, perm) in permutations.iter().enumerate().skip(1) {
        let canonical = canonicalize_jcs(perm)
            .unwrap_or_else(|e| panic!("Permutation {} failed: {:?}", idx, e));
        assert_eq!(
            canonical, baseline_canonical,
            "Permutation {} canonical string diverged from baseline!",
            idx
        );

        let hash = compute_canonical_hash(perm);
        assert_eq!(
            hash, baseline_hash,
            "Permutation {} SHA-256 canonical hash diverged from baseline!",
            idx
        );
    }
}

// =============================================================================
// 4. Deeply Nested Structures Whitespace Stripping & Formatting Invariance Tests
// =============================================================================

fn inject_adversarial_whitespace(json_str: &str) -> String {
    let mut out = String::new();
    let mut in_string = false;
    let mut escape = false;
    for c in json_str.chars() {
        if in_string {
            out.push(c);
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_string = false;
            }
        } else {
            match c {
                '"' => {
                    in_string = true;
                    out.push(c);
                }
                '{' => out.push_str("  \n\t{  \r\n  "),
                '}' => out.push_str("  \n  }  \t  "),
                '[' => out.push_str("  \r\n\t[  "),
                ']' => out.push_str("  \t\n  ]  "),
                ':' => out.push_str("   :   "),
                ',' => out.push_str("  ,\n\t  "),
                ' ' | '\t' | '\r' | '\n' => {
                    // ignore existing non-string whitespace
                }
                _ => out.push(c),
            }
        }
    }
    out
}

#[test]
fn test_deeply_nested_whitespace_stripping_and_formatting_invariance() {
    // Construct depth-20 nested structure: Object -> Array -> Object -> Array ...
    let depth = 20;

    // Representation A: Compact programmatic construction with multiple keys per object
    let mut current_val = json!({
        "z_leaf_data": "governance_audit_token_safe",
        "a_cbf_barrier": 42.0,
        "m_is_active": true
    });
    for level in (0..depth).rev() {
        if level % 2 == 0 {
            current_val = json!({
                "z_tag": "even_level",
                format!("level_{:02}", level): [current_val, level],
                "a_flag": true
            });
        } else {
            current_val = json!([
                {
                    "z_odd_tag": "odd_level",
                    format!("level_{:02}", level): current_val,
                    "a_odd_flag": null
                },
                null
            ]);
        }
    }

    // Representation B: Serialize to string and inject adversarial whitespace (spaces, tabs, newlines, CRLF)
    let compact_json_str = serde_json::to_string(&current_val).expect("Compact JSON serialization");
    let chaotic_whitespace_json = inject_adversarial_whitespace(&compact_json_str);

    // Verify chaotic JSON has extensive whitespace injected outside strings
    assert!(chaotic_whitespace_json.contains("\r\n"));
    assert!(chaotic_whitespace_json.contains("\t"));
    assert!(chaotic_whitespace_json.contains("   :   "));
    assert!(chaotic_whitespace_json.contains("  ,\n\t  "));

    // Parse the chaotic JSON back into a serde_json::Value
    let val_b: Value = serde_json::from_str(&chaotic_whitespace_json)
        .expect("Chaotic whitespace JSON must parse into valid serde_json Value");

    // Representation C: Pretty-printed JSON (standard 2-space indentation)
    let pretty_json_str =
        serde_json::to_string_pretty(&current_val).expect("Pretty JSON serialization");
    let val_c: Value = serde_json::from_str(&pretty_json_str)
        .expect("Pretty JSON must parse into valid serde_json Value");

    // Canonicalize all three representations
    let canonical_a = canonicalize_jcs(&current_val).expect("Canonicalize val_a");
    let canonical_b = canonicalize_jcs(&val_b).expect("Canonicalize val_b");
    let canonical_c = canonicalize_jcs(&val_c).expect("Canonicalize val_c");

    // All three MUST produce byte-for-byte identical canonical representations
    assert_eq!(
        canonical_a, canonical_b,
        "Deeply nested structure whitespace canonicalization diverged between compact and chaotic!"
    );
    assert_eq!(
        canonical_a, canonical_c,
        "Deeply nested structure whitespace canonicalization diverged between compact and pretty!"
    );

    // All three MUST produce identical 64-hex SHA-256 canonical hashes
    let hash_a = compute_canonical_hash(&current_val);
    let hash_b = compute_canonical_hash(&val_b);
    let hash_c = compute_canonical_hash(&val_c);

    assert_eq!(hash_a, hash_b);
    assert_eq!(hash_a, hash_c);
    assert_eq!(hash_a.len(), 64);

    // Verify whitespace outside strings is completely eliminated
    assert!(!canonical_a.contains(" :"));
    assert!(!canonical_a.contains(": "));
    assert!(!canonical_a.contains(", "));
    assert!(!canonical_a.contains(" ,"));
    assert!(!canonical_a.contains("\n"));
    assert!(!canonical_a.contains("\r"));
    assert!(!canonical_a.contains("\t"));

    // String whitespace preservation test
    let string_whitespace_obj = json!({
        "padded_string": "   hello   world   \t\n   ",
        "nested": {
            "inner_spaces": "  preserve   me  "
        }
    });
    let c_str = canonicalize_jcs(&string_whitespace_obj).unwrap();
    // Inner string whitespace MUST be preserved exactly
    assert!(c_str.contains("\"padded_string\":\"   hello   world   \\t\\n   \""));
    assert!(c_str.contains("\"inner_spaces\":\"  preserve   me  \""));
}

// =============================================================================
// 5. MerkleAuditTree Spine Folding Under High Volume (1,000+ Entries) Tests
// =============================================================================

#[test]
fn test_merkle_audit_tree_high_volume_spine_folding_1000_plus() {
    let tree = MerkleAuditTree::new();

    // Volume: 1,024 entries (power of 2) + 476 additional entries = 1,500 total entries
    let count = 1500;
    let mut generated_traces = Vec::with_capacity(count);
    let mut leaf_hashes = Vec::with_capacity(count);
    let mut incremental_roots = Vec::with_capacity(count);

    for i in 0..count {
        let trace = json!({
            "trace_id": format!("cage-trace-{:05}", i),
            "sequence_number": i,
            "action_name": format!("ActuationAction_{}", i % 17),
            "verdict": if i % 7 == 0 { "DENY" } else { "ALLOW" },
            "cbf_h_value": 100.0 - (i as f64 * 0.05),
            "fuel_consumed": (i as f64) * 0.125,
            "policy_version_id": "pol-v1-cafebeef",
            "metadata": {
                "epoch": i / 100,
                "step": i % 100,
                "tags": ["governance", "stpa", "cbf"]
            }
        });

        let (leaf_hash, root_hash) = tree.log_cage_governance_trace(&trace);
        assert_eq!(leaf_hash.len(), 64);
        assert_eq!(root_hash.len(), 64);

        generated_traces.push(trace);
        leaf_hashes.push(leaf_hash);
        incremental_roots.push(root_hash);
    }

    assert_eq!(tree.entries().len(), count);
    assert_eq!(leaf_hashes.len(), count);

    // 1. Invariant: Tree self-verification must be valid across all 1,500 entries
    assert!(
        tree.verify(),
        "Incremental MerkleAuditTree must pass self-verification"
    );

    // 2. Power-of-Two Rebuild Verification (N = 1024)
    // For exact powers of 2, the incremental spine root MUST match static Merkle tree compute_root
    let static_root_1024 = MerkleAuditTree::compute_root_from_leaves(&leaf_hashes[..1024]);
    let incremental_root_1024 = &incremental_roots[1023]; // 0-indexed: index 1023 is entry 1024
    assert_eq!(
        &static_root_1024, incremental_root_1024,
        "Incremental spine folding root at N=1024 must match static complete binary tree root!"
    );

    // 3. Full Rebuild Verification (N = 1500)
    // Create an independent second tree and replay all 1,500 traces sequentially
    let rebuild_tree = MerkleAuditTree::new();
    for (i, trace) in generated_traces.iter().enumerate() {
        let (rebuilt_leaf, rebuilt_root) = rebuild_tree.log_cage_governance_trace(trace);
        assert_eq!(rebuilt_leaf, leaf_hashes[i]);
        assert_eq!(rebuilt_root, incremental_roots[i]);
    }
    assert_eq!(
        rebuild_tree.root(),
        tree.root(),
        "Full rebuild tree root must match incremental tree root at 1,500 entries!"
    );
    assert!(rebuild_tree.verify());

    // 4. Adversarial Tamper Detection at Scale (Tampering with entry 750 of 1500)
    let tamper_idx = 750;
    let mut tampered_traces = generated_traces.clone();
    tampered_traces[tamper_idx] = json!({
        "trace_id": format!("cage-trace-{:05}", tamper_idx),
        "sequence_number": tamper_idx,
        "action_name": "TamperedMaliciousAction", // Tampered field
        "verdict": "ALLOW",
        "cbf_h_value": -999.0,
        "fuel_consumed": 0.0,
        "policy_version_id": "pol-v1-cafebeef"
    });

    let tampered_tree = MerkleAuditTree::new();
    for trace in &tampered_traces {
        tampered_tree.log_cage_governance_trace(trace);
    }
    assert_ne!(
        tampered_tree.root(),
        tree.root(),
        "Tampering with entry 750 out of 1500 MUST produce a distinct Merkle root!"
    );

    // 5. Large Chain Verification with `verify_trace_chain` (1,000 records)
    let chain_size = 1000;
    let mut chain = Vec::with_capacity(chain_size);
    let mut prev_hash = GENESIS_PREV_HASH.to_string();

    for (i, root) in incremental_roots.iter().take(chain_size).enumerate() {
        let payload = json!({
            "step": i,
            "cost": 1.0,
            "actor": "governance_subsystem"
        });
        let mut record = CageTraceRecord::new(
            format!("trace-{}", i),
            i as u64,
            &prev_hash,
            "ExecuteGovernorStep",
            "ALLOW",
            Some(100.0 - (i as f64 * 0.05)),
            Some(1.0),
            "pol-v1-abcdef01",
            "",
            root,
            payload,
            "2026-11-02T01:00:00Z",
        );
        let leaf = record.compute_canonical_leaf_hash();
        record.merkle_leaf_hash = leaf.clone();
        prev_hash = leaf;
        chain.push(record);
    }

    assert_eq!(chain.len(), chain_size);
    assert!(
        verify_trace_chain(&chain).is_ok(),
        "1,000-record cryptographic hash chain must verify cleanly"
    );

    // Tamper with record #427 in the chain
    let mut tampered_chain = chain.clone();
    tampered_chain[427].verdict = "DENY".to_string();
    let tamper_res = verify_trace_chain(&tampered_chain);
    assert!(
        tamper_res.is_err(),
        "Chain with tampered record 427 must be rejected!"
    );
    assert!(tamper_res.unwrap_err().contains("Tampered leaf hash"));
}
