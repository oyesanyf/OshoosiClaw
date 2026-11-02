//! Integration tests for Milestone 1: Multi-Format Policy Ingestion & Version Pinning
//!
//! Validates:
//! 1. Auto-detection priority across Microsoft ACS, Linux Foundation AAIF, NIST OSCAL 1.1.x, Lula, and CAGE STPA.
//! 2. Authentic AST parsing and Cedar authorization rule / STPA UCA generation.
//! 3. Deterministic RFC 8785 JCS canonicalization and 16-character lowercase hex SHA-256 version ID derivation.
//! 4. Key-order insensitivity of JCS version ID computation.
//! 5. Version pinning and HTTP 409 Conflict detection.

use osoosi_policy::cage::{
    canonicalize_jcs, compile_policy, detect_policy_format, verify_version_pinning,
    PolicyVersionConflict,
};
use osoosi_types::cage::PolicyFormat;

const ACS_SAMPLE: &str = r#"
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

const AAIF_SAMPLE: &str = r#"
name: "ResearchAgentLoop"
version: "2.1.0"
governedRunLoop:
  stages:
    - name: "input_validation"
      hooks:
        - id: "AAIF-INPUT-001"
          action: "SanitizePrompt"
          constraints:
            - type: "forbidden"
              parameter: "contains_prompt_injection"
    - name: "access_control"
      hooks:
        - id: "AAIF-ACCESS-001"
          action: "FileRead"
          role: "Researcher"
    - name: "rate_limiting"
      hooks:
        - id: "AAIF-RATE-001"
          action: "ReserveInferenceTokens"
          constraints:
            - type: "max"
              parameter: "tokens"
              value: 4096
      cbf_gamma: 0.2
      cbf_b_min: 25.0
"#;

const OSCAL_SAMPLE: &str = r#"
component-definition:
  uuid: "a2b9f840-7e14-4a25-9c51-5c3e0dfb8b21"
  metadata:
    title: "OshoosiClaw Core Engine Component Definition"
    oscal-version: "1.1.0"
    version: "1.0.0"
  components:
    - uuid: "e4d7a123-bc90-4821-99af-0123456789ab"
      type: "software"
      title: "Host Capability Gate"
      description: "Enforces OS process isolation and network mediation"
      control-implementations:
        - uuid: "c1f820aa-4512-4cf1-831e-9876543210fe"
          source: "NIST_SP-800-53_rev5"
          implemented-requirements:
            - uuid: "req-ac-3-001"
              control-id: "ac-3"
              description: "Enforce least privilege access on file writes"
            - uuid: "req-sc-7-001"
              control-id: "sc-7"
              description: "Boundary protection enforcement"
cbf_gamma: 0.05
cbf_b_min: 12.0
"#;

const LULA_SAMPLE: &str = r#"
apiVersion: lula.dev/v1alpha1
kind: LulaValidation
metadata:
  name: system-binary-write-barrier
spec:
  domain:
    type: kubernetes
  policy:
    type: opa
    opa:
      rego: |
        package lula_system_binary_write_barrier
        default allow = false
        allow {
            input.action != "ModifySystemBinary"
        }
cbf:
  gamma: 0.12
  b_min: 14.0
"#;

const STPA_SAMPLE: &str = r#"
system:
  name: "OshoosiClaw Cybernetic Governance Substrate"
  version: "1.2.0"
hazards:
  - id: "H-1"
    description: "Unauthorized state mutation or process launch without routing seal"
    severity: "critical"
control_actions:
  - name: "execute_child_process"
    description: "Spawns an operating system process inside AppContainer/Job Object"
unsafe_control_actions:
  - id: "UCA-1"
    action: "execute_child_process"
    uca_type: "unsafe_action"
    hazard_refs: ["H-1"]
    terminal_classification: "IRREVERSIBLE_TERMINAL"
    condition:
      param: "routing_seal"
      operator: "is_null"
    cedar_rule: |
      forbid (
          principal,
          action == Action::"ChildProcessExec",
          resource
      ) when {
          context.routing_seal == ""
      };
safety_constraints:
  - id: "SC-1"
    uca_ref: "UCA-1"
    description: "The agent must never spawn a child process without an unconsumed routing seal"
cbf:
  gamma: 0.25
  b_min: 15.0
"#;

#[test]
fn test_auto_detection_priority() {
    assert_eq!(
        detect_policy_format(OSCAL_SAMPLE).unwrap(),
        PolicyFormat::NistOscal
    );
    assert_eq!(
        detect_policy_format(LULA_SAMPLE).unwrap(),
        PolicyFormat::LulaValidation
    );
    assert_eq!(
        detect_policy_format(ACS_SAMPLE).unwrap(),
        PolicyFormat::MicrosoftAcs
    );
    assert_eq!(
        detect_policy_format(AAIF_SAMPLE).unwrap(),
        PolicyFormat::LinuxFoundationAaif
    );
    assert_eq!(
        detect_policy_format(STPA_SAMPLE).unwrap(),
        PolicyFormat::CageStpa
    );
}

#[test]
fn test_microsoft_acs_compilation() {
    let compiled = compile_policy(ACS_SAMPLE, None).expect("ACS compilation failed");
    assert_eq!(compiled.format, PolicyFormat::MicrosoftAcs);
    assert_eq!(compiled.policy_version_id.len(), 16);
    assert!(compiled
        .policy_version_id
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

    assert_eq!(compiled.cbf_gamma, 0.15);
    assert_eq!(compiled.cbf_b_min, 50.0);

    assert_eq!(compiled.cedar_rules.len(), 1);
    let rule = &compiled.cedar_rules[0];
    assert!(rule.contains("forbid"));
    assert!(rule.contains("Action::\"ExecuteStockOrder\""));
    assert!(rule.contains("context.order_value_usd > 10000"));

    assert_eq!(compiled.unsafe_control_actions.len(), 1);
    let uca = &compiled.unsafe_control_actions[0];
    assert_eq!(uca.uca_id, "ACS-TRADE-001");
    assert_eq!(uca.hazard_ref, "H-FIN-01");
    assert_eq!(uca.control_action, "ExecuteStockOrder");
    assert!(uca
        .context_condition
        .contains("context.order_value_usd > 10000"));
}

#[test]
fn test_linux_foundation_aaif_compilation() {
    let compiled = compile_policy(AAIF_SAMPLE, None).expect("AAIF compilation failed");
    assert_eq!(compiled.format, PolicyFormat::LinuxFoundationAaif);
    assert_eq!(compiled.policy_version_id.len(), 16);
    assert_eq!(compiled.cbf_gamma, 0.2);
    assert_eq!(compiled.cbf_b_min, 25.0);

    assert_eq!(compiled.cedar_rules.len(), 3);
    assert_eq!(compiled.unsafe_control_actions.len(), 3);

    let access_rule = compiled
        .cedar_rules
        .iter()
        .find(|r| r.contains("Action::\"FileRead\""))
        .expect("Missing FileRead rule");
    assert!(access_rule.contains("permit"));
    assert!(access_rule.contains("Role::\"Researcher\""));

    let rate_rule = compiled
        .cedar_rules
        .iter()
        .find(|r| r.contains("Action::\"ReserveInferenceTokens\""))
        .expect("Missing ReserveInferenceTokens rule");
    assert!(rate_rule.contains("forbid"));
    assert!(rate_rule.contains("context.tokens > 4096"));
}

#[test]
fn test_nist_oscal_compilation() {
    let compiled = compile_policy(OSCAL_SAMPLE, None).expect("OSCAL compilation failed");
    assert_eq!(compiled.format, PolicyFormat::NistOscal);
    assert_eq!(compiled.policy_version_id.len(), 16);
    assert_eq!(compiled.cbf_gamma, 0.05);
    assert_eq!(compiled.cbf_b_min, 12.0);

    assert_eq!(compiled.cedar_rules.len(), 2);
    assert_eq!(compiled.unsafe_control_actions.len(), 2);

    let ac3_uca = compiled
        .unsafe_control_actions
        .iter()
        .find(|u| u.uca_id == "OSCAL-AC-3")
        .expect("Missing OSCAL-AC-3 UCA");
    assert_eq!(ac3_uca.hazard_ref, "H-NIST-AC-3");
    assert_eq!(ac3_uca.control_action, "AccessEnforcement");
}

#[test]
fn test_lula_validation_compilation() {
    let compiled = compile_policy(LULA_SAMPLE, None).expect("Lula compilation failed");
    assert_eq!(compiled.format, PolicyFormat::LulaValidation);
    assert_eq!(compiled.policy_version_id.len(), 16);
    assert_eq!(compiled.cbf_gamma, 0.12);
    assert_eq!(compiled.cbf_b_min, 14.0);

    assert_eq!(compiled.cedar_rules.len(), 1);
    assert!(compiled.cedar_rules[0].contains("Action::\"ModifySystemBinary\""));
    assert!(compiled.cedar_rules[0].contains("context.lula_allow == false"));

    assert_eq!(compiled.unsafe_control_actions.len(), 1);
    assert_eq!(
        compiled.unsafe_control_actions[0].uca_id,
        "LULA-system-binary-write-barrier"
    );
}

#[test]
fn test_native_cage_stpa_compilation() {
    let compiled = compile_policy(STPA_SAMPLE, None).expect("STPA compilation failed");
    assert_eq!(compiled.format, PolicyFormat::CageStpa);
    assert_eq!(compiled.policy_version_id.len(), 16);
    assert_eq!(compiled.cbf_gamma, 0.25);
    assert_eq!(compiled.cbf_b_min, 15.0);

    assert_eq!(compiled.cedar_rules.len(), 1);
    assert!(compiled.cedar_rules[0].contains("Action::\"ChildProcessExec\""));
    assert!(compiled.cedar_rules[0].contains("context.routing_seal == \"\""));

    assert_eq!(compiled.unsafe_control_actions.len(), 1);
    assert_eq!(compiled.unsafe_control_actions[0].uca_id, "UCA-1");
    assert_eq!(compiled.unsafe_control_actions[0].hazard_ref, "H-1");
}

#[test]
fn test_rfc_8785_jcs_canonicalization_and_version_reproducibility() {
    // Test that key ordering in JSON does not change the canonical JCS output
    let json_a = serde_json::json!({
        "zebra": 1,
        "alpha": "hello",
        "beta": [3, 2, 1],
        "delta": {
            "z": true,
            "a": false
        }
    });

    let json_b = serde_json::json!({
        "alpha": "hello",
        "delta": {
            "a": false,
            "z": true
        },
        "beta": [3, 2, 1],
        "zebra": 1
    });

    let canon_a = canonicalize_jcs(&json_a).unwrap();
    let canon_b = canonicalize_jcs(&json_b).unwrap();
    assert_eq!(canon_a, canon_b);
    assert_eq!(
        canon_a,
        r#"{"alpha":"hello","beta":[3,2,1],"delta":{"a":false,"z":true},"zebra":1}"#
    );

    // Compiling the same policy repeatedly yields identical version IDs
    let c1 = compile_policy(ACS_SAMPLE, None).unwrap();
    let c2 = compile_policy(ACS_SAMPLE, None).unwrap();
    assert_eq!(c1.policy_version_id, c2.policy_version_id);
}

#[test]
fn test_version_pinning_and_conflict_detection() {
    let active_version = "c4b8e219fa8201de";

    // Matching version succeeds
    assert!(verify_version_pinning(Some(active_version), "c4b8e219fa8201de").is_ok());

    // Unpinned active version succeeds with any incoming version
    assert!(verify_version_pinning(None, "a1f802bc349911e0").is_ok());

    // Mismatched version fails with PolicyVersionConflict
    let result = verify_version_pinning(Some(active_version), "a1f802bc349911e0");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(
        err,
        PolicyVersionConflict {
            pinned_version: "c4b8e219fa8201de".to_string(),
            incoming_version: "a1f802bc349911e0".to_string(),
        }
    );

    // Error string mentions HTTP 409 Conflict
    let err_msg = err.to_string();
    assert!(err_msg.contains("HTTP 409 Conflict"));
    assert!(err_msg.contains("c4b8e219fa8201de"));
    assert!(err_msg.contains("a1f802bc349911e0"));
}
