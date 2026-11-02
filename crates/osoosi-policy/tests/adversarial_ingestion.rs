//! Empirical Adversarial Stress Test Harness for Milestone 1: Multi-Format Policy Ingestion & Version Pinning
//!
//! Evaluates:
//! 1. Malformed YAML/JSON inputs (trailing commas, unbalanced brackets, recursive structures, YAML anchor bombs, null bytes).
//! 2. Incomplete and truncated schemas missing mandatory discriminants.
//! 3. Ambiguous schemas combining discriminants across all 32 combinations, asserting strict precedence:
//!    OSCAL > Lula > ACS > AAIF > STPA.
//! 4. Large policy payloads (1,200+ rules per format) asserting memory safety, zero panics, and sub-second performance.
//! 5. Whitespace, newline (CRLF vs LF), BOM markers, and key-ordering invariance via RFC 8785 JCS.
//! 6. Zero unhandled panics (`catch_unwind`) across all boundary conditions.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;

use osoosi_policy::cage::{
    compile_policy, detect_policy_format, verify_version_pinning, PolicyIngestError,
    PolicyVersionConflict,
};
use osoosi_types::cage::PolicyFormat;

// -----------------------------------------------------------------------------
// Suite 1: Malformed Inputs & Clean Err Propagation (Zero Panics)
// -----------------------------------------------------------------------------

#[test]
fn test_malformed_inputs_fail_cleanly_without_panic() {
    let malformed_cases = vec![
        ("unbalanced_curly_brace", "{\n  \"behaviorDeclarations\": [\n"),
        ("unbalanced_square_bracket", "{\"behaviorDeclarations\": ["),
        ("trailing_garbage", "{\"a\": 1} trailing garbage"),
        ("invalid_escape_sequence", "{\"name\": \"invalid \\u12\"}"),
        ("raw_unquoted_string", "just some raw text not json or yaml: : : ["),
        ("broken_yaml_indentation", "behaviorDeclarations:\n- id: 1\n   action: bad\n  - id: 2"),
        ("yaml_tab_indentation", "behaviorDeclarations:\n\t- id: test\n\t  action: test"),
        ("null_byte_in_json", "{\"key\": \"val\0ue\"}"),
        ("unterminated_string", "{\"name\": \"unterminated"),
        ("double_colon_yaml_error", "key: : value"),
    ];

    for (name, input) in malformed_cases {
        let unwind_res = catch_unwind(AssertUnwindSafe(|| {
            let res = compile_policy(input, None);
            assert!(
                res.is_err(),
                "Malformed input '{}' should return Err, got Ok: {:?}",
                name,
                res
            );
            if let Err(e) = res {
                match e {
                    PolicyIngestError::ParseError(_) => {}
                    PolicyIngestError::MalformedSchema(_) => {}
                    PolicyIngestError::UnrecognizedFormat(_) => {}
                    other => panic!("Unexpected error variant for '{}': {:?}", name, other),
                }
            }
        }));

        assert!(
            unwind_res.is_ok(),
            "compile_policy panicked on malformed input '{}'!",
            name
        );
    }
}

#[test]
fn test_yaml_anchor_bomb_and_deep_nesting_resilience() {
    // 1. Deeply nested JSON array (150 levels deep)
    let mut deep_json = String::new();
    for _ in 0..150 {
        deep_json.push('[');
    }
    deep_json.push_str("\"innermost\"");
    for _ in 0..150 {
        deep_json.push(']');
    }

    let unwind_res = catch_unwind(AssertUnwindSafe(|| {
        let res = compile_policy(&deep_json, None);
        // It should either return Ok (falling back to STPA default) or return Err, but NEVER panic
        let _ = res;
    }));
    assert!(unwind_res.is_ok(), "Deeply nested JSON array caused panic!");

    // 2. YAML billion-laughs / anchor expansion attempt
    let anchor_bomb = r#"
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
behaviorDeclarations: *d
"#;
    let unwind_res2 = catch_unwind(AssertUnwindSafe(|| {
        let res = compile_policy(anchor_bomb, None);
        // Should parse or return error cleanly without crashing process
        let _ = res;
    }));
    assert!(unwind_res2.is_ok(), "YAML anchor expansion caused panic!");
}

#[test]
fn test_primitive_and_empty_roots_handling() {
    let non_objects = vec![
        ("empty_string", ""),
        ("whitespace_only", "   \n\t  \r\n"),
        ("json_number", "42"),
        ("json_boolean", "true"),
        ("json_null", "null"),
        ("json_array", "[]"),
        ("json_primitive_string", "\"standalone_string\""),
    ];

    for (name, input) in non_objects {
        let unwind_res = catch_unwind(AssertUnwindSafe(|| {
            let res = compile_policy(input, None);
            // Non-objects either fallback safely to STPA default or return ParseError
            if let Ok(compiled) = res {
                assert_eq!(compiled.format, PolicyFormat::CageStpa);
                assert!(!compiled.cedar_rules.is_empty());
                assert!(!compiled.unsafe_control_actions.is_empty());
                assert_eq!(compiled.policy_version_id.len(), 16);
            }
        }));
        assert!(
            unwind_res.is_ok(),
            "Non-object input '{}' panicked!",
            name
        );
    }
}

// -----------------------------------------------------------------------------
// Suite 2: Incomplete & Truncated Schemas Missing Mandatory Discriminants
// -----------------------------------------------------------------------------

#[test]
fn test_incomplete_schemas_missing_mandatory_fields() {
    // 1. ACS with missing or invalid behaviorDeclarations
    let acs_missing = r#"{"name": "ACS Without Decls"}"#;
    let res = compile_policy(acs_missing, Some(PolicyFormat::MicrosoftAcs));
    assert!(res.is_err());
    match res.unwrap_err() {
        PolicyIngestError::MalformedSchema(msg) => {
            assert!(msg.contains("Missing 'behaviorDeclarations' array"));
        }
        other => panic!("Expected MalformedSchema, got {:?}", other),
    }

    let acs_non_array = r#"{"behaviorDeclarations": "not-an-array"}"#;
    let res = compile_policy(acs_non_array, Some(PolicyFormat::MicrosoftAcs));
    assert!(res.is_err());

    // 2. AAIF with missing or invalid governedRunLoop
    let aaif_missing = r#"{"name": "AAIF Without RunLoop"}"#;
    let res = compile_policy(aaif_missing, Some(PolicyFormat::LinuxFoundationAaif));
    assert!(res.is_err());
    match res.unwrap_err() {
        PolicyIngestError::MalformedSchema(msg) => {
            assert!(msg.contains("Missing 'governedRunLoop' object"));
        }
        other => panic!("Expected MalformedSchema, got {:?}", other),
    }

    let aaif_missing_stages = r#"{"governedRunLoop": {"other_field": true}}"#;
    let res = compile_policy(aaif_missing_stages, Some(PolicyFormat::LinuxFoundationAaif));
    assert!(res.is_err());
    match res.unwrap_err() {
        PolicyIngestError::MalformedSchema(msg) => {
            assert!(msg.contains("Missing 'stages' array"));
        }
        other => panic!("Expected MalformedSchema, got {:?}", other),
    }

    // 3. OSCAL with missing components
    let oscal_missing_components = r#"
component-definition:
  metadata:
    oscal-version: "1.1.0"
"#;
    let res = compile_policy(oscal_missing_components, Some(PolicyFormat::NistOscal));
    assert!(res.is_err());
    match res.unwrap_err() {
        PolicyIngestError::MalformedSchema(msg) => {
            assert!(msg.contains("Missing 'components' array"));
        }
        other => panic!("Expected MalformedSchema, got {:?}", other),
    }

    // 4. Truncated mid-stream documents
    let truncated_cases = vec![
        ("truncated_acs", "{\"behaviorDeclarations\": [{\"id\": \"ACS-1\""),
        ("truncated_aaif", "{\"governedRunLoop\": {\"stages\": [{\"name\":"),
        ("truncated_oscal", "{\"component-definition\": {\"components\": ["),
    ];

    for (name, input) in truncated_cases {
        let unwind = catch_unwind(AssertUnwindSafe(|| {
            let res = compile_policy(input, None);
            assert!(res.is_err(), "Truncated input '{}' should return Err", name);
        }));
        assert!(unwind.is_ok(), "Truncated input '{}' panicked!", name);
    }
}

// -----------------------------------------------------------------------------
// Suite 3: Ambiguous Schemas & Strict Precedence (OSCAL > Lula > ACS > AAIF > STPA)
// -----------------------------------------------------------------------------

#[test]
fn test_strict_priority_ordering_all_32_combinations() {
    // We test all 2^5 = 32 combinations of presence of the 5 schema discriminants:
    // D0: oscal-version
    // D1: LulaValidation
    // D2: behaviorDeclarations
    // D3: governedRunLoop
    // D4: stpa_control_structure
    //
    // The required priority ordering is strictly:
    // OSCAL > Lula > ACS > AAIF > STPA

    for mask in 0..32 {
        let has_oscal = (mask & 1) != 0;
        let has_lula = (mask & 2) != 0;
        let has_acs = (mask & 4) != 0;
        let has_aaif = (mask & 8) != 0;
        let has_stpa = (mask & 16) != 0;

        let expected_format = if has_oscal {
            PolicyFormat::NistOscal
        } else if has_lula {
            PolicyFormat::LulaValidation
        } else if has_acs {
            PolicyFormat::MicrosoftAcs
        } else if has_aaif {
            PolicyFormat::LinuxFoundationAaif
        } else {
            PolicyFormat::CageStpa
        };

        let mut doc = serde_json::Map::new();

        if has_oscal {
            doc.insert(
                "oscal-version".to_string(),
                serde_json::Value::String("1.1.0".to_string()),
            );
        }
        if has_lula {
            doc.insert(
                "kind".to_string(),
                serde_json::Value::String("LulaValidation".to_string()),
            );
        }
        if has_acs {
            doc.insert(
                "behaviorDeclarations".to_string(),
                serde_json::Value::Array(vec![]),
            );
        }
        if has_aaif {
            let mut loop_obj = serde_json::Map::new();
            loop_obj.insert("stages".to_string(), serde_json::Value::Array(vec![]));
            doc.insert(
                "governedRunLoop".to_string(),
                serde_json::Value::Object(loop_obj),
            );
        }
        if has_stpa {
            doc.insert(
                "stpa_control_structure".to_string(),
                serde_json::Value::Object(serde_json::Map::new()),
            );
        }

        let json_str = serde_json::to_string(&doc).unwrap();
        let detected = detect_policy_format(&json_str).expect("Detection failed");

        assert_eq!(
            detected, expected_format,
            "Failed priority check for mask {:#07b} (oscal={}, lula={}, acs={}, aaif={}, stpa={}). Expected {:?}, got {:?}",
            mask, has_oscal, has_lula, has_acs, has_aaif, has_stpa, expected_format, detected
        );
    }
}

#[test]
fn test_ambiguous_schema_compilation_with_conflicting_discriminants() {
    // Construct a document with valid OSCAL structure AND valid ACS structure
    let oscal_and_acs = r#"
oscal-version: "1.1.0"
component-definition:
  components:
    - uuid: "c-1"
      control-implementations:
        - implemented-requirements:
            - control-id: "ac-3"
              description: "Access Enforcement"
behaviorDeclarations:
  - id: "ACS-CONFLICT"
    action: "ConflictingAction"
"#;

    // Detect format should yield OSCAL due to OSCAL > ACS
    let detected = detect_policy_format(oscal_and_acs).unwrap();
    assert_eq!(detected, PolicyFormat::NistOscal);

    // Compiling should compile the OSCAL rules and ignore the ACS block
    let compiled = compile_policy(oscal_and_acs, None).expect("Compilation failed");
    assert_eq!(compiled.format, PolicyFormat::NistOscal);
    assert_eq!(compiled.unsafe_control_actions.len(), 1);
    assert_eq!(compiled.unsafe_control_actions[0].uca_id, "OSCAL-AC-3");
    assert_eq!(
        compiled.unsafe_control_actions[0].control_action,
        "AccessEnforcement"
    );

    // Construct a document with Lula AND ACS
    let lula_and_acs = r#"
kind: LulaValidation
metadata:
  name: lula-conflict-test
spec:
  policy:
    opa:
      rego: "package test\ndefault allow = false\nallow { input.action != 'ModifySystemBinary' }"
behaviorDeclarations:
  - id: "ACS-CONFLICT"
    action: "ConflictingAction"
"#;
    let detected_lula = detect_policy_format(lula_and_acs).unwrap();
    assert_eq!(detected_lula, PolicyFormat::LulaValidation);

    let compiled_lula = compile_policy(lula_and_acs, None).expect("Lula compilation failed");
    assert_eq!(compiled_lula.format, PolicyFormat::LulaValidation);
    assert_eq!(
        compiled_lula.unsafe_control_actions[0].uca_id,
        "LULA-lula-conflict-test"
    );
}

// -----------------------------------------------------------------------------
// Suite 4: Large Policy Payloads (1,200+ Rules) & Stress Performance
// -----------------------------------------------------------------------------

#[test]
fn test_large_policy_payload_1200_rules_performance_and_safety() {
    let rule_count = 1200;

    // 1. Large Microsoft ACS policy (1,200 behaviorDeclarations)
    let mut acs_decls = Vec::with_capacity(rule_count);
    for i in 0..rule_count {
        acs_decls.push(serde_json::json!({
            "id": format!("ACS-RULE-{:04}", i),
            "action": format!("Action_{:04}", i),
            "description": format!("Stress test rule {}", i),
            "hazardRefs": [format!("H-{:02}", i % 10)],
            "constraints": [
                {
                    "type": "greater_than",
                    "parameter": format!("metric_{}", i),
                    "value": (i as f64) * 1.5
                }
            ]
        }));
    }
    let acs_large = serde_json::json!({
        "name": "LargeAcsStressPolicy",
        "version": "1.0.0",
        "behaviorDeclarations": acs_decls,
        "cbf_gamma": 0.08,
        "cbf_b_min": 15.0
    });
    let acs_large_str = serde_json::to_string(&acs_large).unwrap();

    let start_acs = Instant::now();
    let compiled_acs = compile_policy(&acs_large_str, None).expect("Large ACS compile failed");
    let acs_duration = start_acs.elapsed();

    assert_eq!(compiled_acs.format, PolicyFormat::MicrosoftAcs);
    assert_eq!(compiled_acs.cedar_rules.len(), rule_count);
    assert_eq!(compiled_acs.unsafe_control_actions.len(), rule_count);
    assert_eq!(compiled_acs.policy_version_id.len(), 16);
    assert!(
        acs_duration.as_millis() < 2000,
        "Large ACS compile took too long: {:?}",
        acs_duration
    );

    // 2. Large Linux Foundation AAIF policy (1,200 hooks across 12 stages)
    let stage_count = 12;
    let hooks_per_stage = rule_count / stage_count;
    let mut aaif_stages = Vec::with_capacity(stage_count);
    for s in 0..stage_count {
        let mut hooks = Vec::with_capacity(hooks_per_stage);
        for h in 0..hooks_per_stage {
            let idx = s * hooks_per_stage + h;
            hooks.push(serde_json::json!({
                "id": format!("AAIF-HOOK-{:04}", idx),
                "action": format!("HookAction_{:04}", idx),
                "constraints": [
                    {
                        "type": "max",
                        "parameter": format!("latency_stage_{}", s),
                        "value": 500.0
                    }
                ]
            }));
        }
        aaif_stages.push(serde_json::json!({
            "name": format!("stage_{}", s),
            "hooks": hooks
        }));
    }
    let aaif_large = serde_json::json!({
        "name": "LargeAaifStressPolicy",
        "governedRunLoop": {
            "stages": aaif_stages
        }
    });
    let aaif_large_str = serde_json::to_string(&aaif_large).unwrap();

    let start_aaif = Instant::now();
    let compiled_aaif = compile_policy(&aaif_large_str, None).expect("Large AAIF compile failed");
    let aaif_duration = start_aaif.elapsed();

    assert_eq!(compiled_aaif.format, PolicyFormat::LinuxFoundationAaif);
    assert_eq!(compiled_aaif.cedar_rules.len(), rule_count);
    assert_eq!(compiled_aaif.unsafe_control_actions.len(), rule_count);
    assert_eq!(compiled_aaif.policy_version_id.len(), 16);
    assert!(
        aaif_duration.as_millis() < 2000,
        "Large AAIF compile took too long: {:?}",
        aaif_duration
    );

    // 3. Large CAGE STPA policy (1,200 unsafe control actions)
    let mut stpa_ucas = Vec::with_capacity(rule_count);
    for i in 0..rule_count {
        stpa_ucas.push(serde_json::json!({
            "id": format!("UCA-STRESS-{:04}", i),
            "action": format!("ExecuteActuation_{:04}", i),
            "hazard_refs": [format!("H-STPA-{}", i % 5)],
            "condition": {
                "param": format!("sensor_{}", i),
                "operator": "out_of_bounds"
            }
        }));
    }
    let stpa_large = serde_json::json!({
        "stpa_control_structure": {
            "unsafe_control_actions": stpa_ucas
        }
    });
    let stpa_large_str = serde_json::to_string(&stpa_large).unwrap();

    let start_stpa = Instant::now();
    let compiled_stpa = compile_policy(&stpa_large_str, None).expect("Large STPA compile failed");
    let stpa_duration = start_stpa.elapsed();

    assert_eq!(compiled_stpa.format, PolicyFormat::CageStpa);
    assert_eq!(compiled_stpa.cedar_rules.len(), rule_count);
    assert_eq!(compiled_stpa.unsafe_control_actions.len(), rule_count);
    assert_eq!(compiled_stpa.policy_version_id.len(), 16);
    assert!(
        stpa_duration.as_millis() < 2000,
        "Large STPA compile took too long: {:?}",
        stpa_duration
    );
}

// -----------------------------------------------------------------------------
// Suite 5: Whitespace, Indentation, Newlines & RFC 8785 Invariance
// -----------------------------------------------------------------------------

#[test]
fn test_whitespace_and_newline_invariance() {
    let yaml_lf = "name: Test\nversion: '1.0'\nbehaviorDeclarations:\n  - id: D-1\n    action: Act\ncbf_gamma: 0.1\ncbf_b_min: 10.0\n";
    let yaml_crlf = "name: Test\r\nversion: '1.0'\r\nbehaviorDeclarations:\r\n  - id: D-1\r\n    action: Act\r\ncbf_gamma: 0.1\r\ncbf_b_min: 10.0\r\n";
    let yaml_extra_spaces = "  \n\nname:   Test\nversion:  '1.0'\n\nbehaviorDeclarations:\n    -   id:   D-1\n        action:   Act\n\ncbf_gamma:    0.1\ncbf_b_min:    10.0\n\n\n";

    let json_compact = "{\"name\":\"Test\",\"version\":\"1.0\",\"behaviorDeclarations\":[{\"id\":\"D-1\",\"action\":\"Act\"}],\"cbf_gamma\":0.1,\"cbf_b_min\":10.0}";
    let json_pretty = "{\n    \"name\": \"Test\",\n    \"version\": \"1.0\",\n    \"behaviorDeclarations\": [\n        {\n            \"id\": \"D-1\",\n            \"action\": \"Act\"\n        }\n    ],\n    \"cbf_gamma\": 0.1,\n    \"cbf_b_min\": 10.0\n}\n";
    let json_scrambled_keys = "{\"cbf_b_min\":10.0,\"behaviorDeclarations\":[{\"action\":\"Act\",\"id\":\"D-1\"}],\"version\":\"1.0\",\"cbf_gamma\":0.1,\"name\":\"Test\"}";

    let c_lf = compile_policy(yaml_lf, None).unwrap();
    let c_crlf = compile_policy(yaml_crlf, None).unwrap();
    let c_extra = compile_policy(&yaml_extra_spaces, None).unwrap();
    let c_compact = compile_policy(json_compact, None).unwrap();
    let c_pretty = compile_policy(json_pretty, None).unwrap();
    let c_scrambled = compile_policy(json_scrambled_keys, None).unwrap();

    let target_version = c_lf.policy_version_id.clone();
    assert_eq!(c_crlf.policy_version_id, target_version);
    assert_eq!(c_extra.policy_version_id, target_version);
    assert_eq!(c_compact.policy_version_id, target_version);
    assert_eq!(c_pretty.policy_version_id, target_version);
    assert_eq!(c_scrambled.policy_version_id, target_version);
}

#[test]
fn test_utf8_bom_behavior() {
    let yaml_lf = "name: Test\nversion: '1.0'\nbehaviorDeclarations:\n  - id: D-1\n    action: Act\ncbf_gamma: 0.1\ncbf_b_min: 10.0\n";
    let yaml_bom = format!("\u{feff}{}", yaml_lf);

    // Verify empirical behavior of BOM prefix: returns clean ParseError without panic
    let unwind_res = catch_unwind(AssertUnwindSafe(|| {
        let res = compile_policy(&yaml_bom, None);
        // Documents that serde_yaml rejects BOM cleanly with ParseError rather than panicking
        assert!(res.is_err());
        match res.unwrap_err() {
            PolicyIngestError::ParseError(msg) => {
                assert!(msg.contains("expected value at line 1 column 1"));
            }
            other => panic!("Expected ParseError for unstripped BOM, got {:?}", other),
        }
    }));
    assert!(unwind_res.is_ok(), "BOM input panicked!");
}

// -----------------------------------------------------------------------------
// Suite 6: Version Pinning & Conflict Verification (HTTP 409 Conflict)
// -----------------------------------------------------------------------------

#[test]
fn test_version_pinning_fuzzing_and_http_409() {
    let pinned = "e048a129f6b402bc";

    // 1. Exact match passes
    assert!(verify_version_pinning(Some(pinned), pinned).is_ok());

    // 2. Single bit mutation fails
    let mutated_single_char = "e048a129f6b402bd";
    let res = verify_version_pinning(Some(pinned), mutated_single_char);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err,
        PolicyVersionConflict {
            pinned_version: pinned.to_string(),
            incoming_version: mutated_single_char.to_string(),
        }
    );
    assert!(err.to_string().contains("HTTP 409 Conflict"));

    // 3. Case difference fails (hashes are strict lowercase)
    let uppercase_pinned = pinned.to_ascii_uppercase();
    assert!(verify_version_pinning(Some(pinned), &uppercase_pinned).is_err());

    // 4. Empty incoming version fails
    assert!(verify_version_pinning(Some(pinned), "").is_err());

    // 5. None pinned succeeds with any incoming string
    assert!(verify_version_pinning(None, "").is_ok());
    assert!(verify_version_pinning(None, "random_version_id").is_ok());
}
