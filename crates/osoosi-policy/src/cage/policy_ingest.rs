//! Multi-Format Policy Ingestion & Version Pinning Engine
//!
//! Provides automatic format detection, parsing, and compilation for:
//! 1. Microsoft Agent Control Specification (ACS) (`behaviorDeclarations`)
//! 2. Linux Foundation AAIF (`governedRunLoop`)
//! 3. NIST OSCAL 1.1.x (`oscal-version`)
//! 4. Lula Validation Manifests (`kind: LulaValidation`)
//! 5. Native CAGE STPA Control Structure (`stpa_control_structure`)
//!
//! Implements pure-Rust RFC 8785 JSON Canonicalization Scheme (JCS) for
//! deterministic 16-character hex SHA-256 policy version pinning and HTTP 409
//! version conflict verification.

use osoosi_types::cage::{CbfParameters, PolicyFormat, UnsafeControlAction};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Compiled CAGE governance policy representation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompiledCagePolicy {
    /// Deterministic 16-character lowercase hex SHA-256 version identifier.
    pub policy_version_id: String,

    /// Detected or explicitly specified policy format.
    pub format: PolicyFormat,

    /// Raw input document string.
    pub raw_content: String,

    /// Generated Cedar authorization rules.
    pub cedar_rules: Vec<String>,

    /// Extracted STPA Unsafe Control Actions.
    pub unsafe_control_actions: Vec<UnsafeControlAction>,

    /// Control Barrier Function maximum fractional safety margin decay rate per step (`gamma`).
    pub cbf_gamma: f64,

    /// Control Barrier Function invariant safety floor (`b_min`).
    pub cbf_b_min: f64,
}

/// Version conflict returned when incoming policy version does not match the pinned version.
/// Triggers HTTP 409 Conflict in REST API.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[error("Policy version conflict: active pinned version is '{pinned_version}', but incoming version is '{incoming_version}' (HTTP 409 Conflict)")]
pub struct PolicyVersionConflict {
    pub pinned_version: String,
    pub incoming_version: String,
}

/// Errors occurring during policy ingestion, detection, compilation, or canonicalization.
#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
pub enum PolicyIngestError {
    #[error("Failed to parse policy document as YAML/JSON: {0}")]
    ParseError(String),

    #[error("Policy format could not be determined: {0}")]
    UnrecognizedFormat(String),

    #[error("Required policy fields missing or malformed: {0}")]
    MalformedSchema(String),

    #[error("RFC 8785 canonicalization error: {0}")]
    CanonicalizationError(String),

    #[error(transparent)]
    VersionConflict(#[from] PolicyVersionConflict),
}

/// Auto-detects the policy format from raw YAML or JSON content following the authoritative priority:
/// 1. Check for `oscal-version` -> `PolicyFormat::NistOscal`
/// 2. Check for `kind: LulaValidation` or `rego` inside component-definition -> `PolicyFormat::LulaValidation`
/// 3. Check for `behaviorDeclarations` -> `PolicyFormat::MicrosoftAcs`
/// 4. Check for `governedRunLoop` -> `PolicyFormat::LinuxFoundationAaif`
/// 5. Check for `stpa_control_structure` or fallback YAML/JSON -> `PolicyFormat::CageStpa`
pub fn detect_policy_format(content: &str) -> Result<PolicyFormat, PolicyIngestError> {
    let parsed: serde_json::Value = serde_yaml::from_str(content)
        .or_else(|_| serde_json::from_str(content))
        .map_err(|e| PolicyIngestError::ParseError(e.to_string()))?;

    // Priority 1: Check for oscal-version
    if has_key_recursive(&parsed, "oscal-version") {
        return Ok(PolicyFormat::NistOscal);
    }

    // Priority 2: Check for kind: LulaValidation or rego inside component-definition
    if let Some(kind) = parsed.get("kind").and_then(|k| k.as_str()) {
        if kind.eq_ignore_ascii_case("LulaValidation") || kind.eq_ignore_ascii_case("Validation") {
            return Ok(PolicyFormat::LulaValidation);
        }
    }
    if parsed.get("component-definition").is_some() && has_key_recursive(&parsed, "rego") {
        return Ok(PolicyFormat::LulaValidation);
    }

    // Priority 3: Check for behaviorDeclarations
    if parsed.get("behaviorDeclarations").is_some()
        || has_key_recursive(&parsed, "behaviorDeclarations")
    {
        return Ok(PolicyFormat::MicrosoftAcs);
    }

    // Priority 4: Check for governedRunLoop
    if parsed.get("governedRunLoop").is_some() || has_key_recursive(&parsed, "governedRunLoop") {
        return Ok(PolicyFormat::LinuxFoundationAaif);
    }

    // Priority 5: Native CAGE STPA (or fallback for general valid YAML/JSON)
    Ok(PolicyFormat::CageStpa)
}

/// Helper function to search for a key anywhere in a nested `serde_json::Value`.
fn has_key_recursive(val: &serde_json::Value, target_key: &str) -> bool {
    match val {
        serde_json::Value::Object(map) => {
            if map.contains_key(target_key) {
                return true;
            }
            map.values().any(|v| has_key_recursive(v, target_key))
        }
        serde_json::Value::Array(arr) => arr.iter().any(|v| has_key_recursive(v, target_key)),
        _ => false,
    }
}

/// Compiles a policy document into Cedar authorization rules, STPA Unsafe Control Actions,
/// extracts CBF parameters (or applies defaults), and computes the deterministic 16-hex version ID.
pub fn compile_policy(
    raw_content: &str,
    format_override: Option<PolicyFormat>,
) -> Result<CompiledCagePolicy, PolicyIngestError> {
    let format = match format_override {
        Some(f) => f,
        None => detect_policy_format(raw_content)?,
    };

    let doc: serde_json::Value = serde_yaml::from_str(raw_content)
        .or_else(|_| serde_json::from_str(raw_content))
        .map_err(|e| PolicyIngestError::ParseError(e.to_string()))?;

    let default_cbf = CbfParameters::default();
    let (cedar_rules, unsafe_control_actions, cbf_gamma_opt, cbf_b_min_opt) = match format {
        PolicyFormat::MicrosoftAcs => compile_acs(&doc)?,
        PolicyFormat::LinuxFoundationAaif => compile_aaif(&doc)?,
        PolicyFormat::NistOscal => compile_oscal(&doc)?,
        PolicyFormat::LulaValidation => compile_lula(&doc)?,
        PolicyFormat::CageStpa => compile_stpa(&doc)?,
    };

    // Extract CBF parameters if present in document, or use format result or defaults
    let cbf_gamma = cbf_gamma_opt
        .or_else(|| extract_f64_recursive(&doc, &["cbf_gamma", "gamma"]))
        .unwrap_or(default_cbf.gamma);

    let cbf_b_min = cbf_b_min_opt
        .or_else(|| extract_f64_recursive(&doc, &["cbf_b_min", "b_min"]))
        .unwrap_or(default_cbf.b_min);

    // Build normalized bundle for deterministic RFC 8785 canonicalization
    let normalized = serde_json::json!({
        "format": format.as_str(),
        "cedar_rules": cedar_rules,
        "unsafe_control_actions": unsafe_control_actions,
        "cbf_gamma": cbf_gamma,
        "cbf_b_min": cbf_b_min,
    });

    let canonical_str = canonicalize_jcs(&normalized)?;
    let mut hasher = Sha256::new();
    hasher.update(canonical_str.as_bytes());
    let full_hash = hex::encode(hasher.finalize());
    let policy_version_id = full_hash[..16].to_ascii_lowercase();

    Ok(CompiledCagePolicy {
        policy_version_id,
        format,
        raw_content: raw_content.to_string(),
        cedar_rules,
        unsafe_control_actions,
        cbf_gamma,
        cbf_b_min,
    })
}

/// Verifies whether an incoming policy version matches the active pinned version.
/// Returns `Ok(())` if no active version is pinned or if versions match exactly.
/// Returns `Err(PolicyVersionConflict)` on version mismatch (HTTP 409 Conflict).
pub fn verify_version_pinning(
    active_pinned_version: Option<&str>,
    incoming_version: &str,
) -> Result<(), PolicyVersionConflict> {
    if let Some(pinned) = active_pinned_version {
        if pinned != incoming_version {
            return Err(PolicyVersionConflict {
                pinned_version: pinned.to_string(),
                incoming_version: incoming_version.to_string(),
            });
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Format-Specific Compilers
// -----------------------------------------------------------------------------

/// Compiles Microsoft ACS (`behaviorDeclarations`).
fn compile_acs(
    doc: &serde_json::Value,
) -> Result<
    (
        Vec<String>,
        Vec<UnsafeControlAction>,
        Option<f64>,
        Option<f64>,
    ),
    PolicyIngestError,
> {
    let mut cedar_rules = Vec::new();
    let mut ucas = Vec::new();

    let decls = doc
        .get("behaviorDeclarations")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            PolicyIngestError::MalformedSchema(
                "Missing 'behaviorDeclarations' array in ACS policy".into(),
            )
        })?;

    for decl in decls {
        let id = decl
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("ACS-UNKNOWN")
            .to_string();
        let action = decl
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("ExecuteAction")
            .to_string();
        let description = decl
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let hazard_ref = decl
            .get("hazardRefs")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|h| h.as_str())
            .unwrap_or("H-GENERIC")
            .to_string();

        let mut constraint_conditions = Vec::new();
        if let Some(constraints) = decl.get("constraints").and_then(|v| v.as_array()) {
            for c in constraints {
                let c_type = c.get("type").and_then(|v| v.as_str()).unwrap_or("");
                let param = c
                    .get("parameter")
                    .and_then(|v| v.as_str())
                    .unwrap_or("param");
                let val_str = c
                    .get("value")
                    .map(|v| match v {
                        serde_json::Value::Number(n) => n.to_string(),
                        serde_json::Value::String(s) => format!("\"{}\"", s),
                        serde_json::Value::Bool(b) => b.to_string(),
                        _ => v.to_string(),
                    })
                    .unwrap_or_else(|| "0".into());

                match c_type {
                    "greater_than" | "max_value" => {
                        constraint_conditions.push(format!("context.{} > {}", param, val_str));
                    }
                    "less_than" | "min_value" => {
                        constraint_conditions.push(format!("context.{} < {}", param, val_str));
                    }
                    "equals" => {
                        constraint_conditions.push(format!("context.{} == {}", param, val_str));
                    }
                    "null_check" => {
                        constraint_conditions.push(format!("!context.hasAttr(\"{}\")", param));
                    }
                    "not_null" => {
                        constraint_conditions.push(format!("context.hasAttr(\"{}\")", param));
                    }
                    "boolean_true" => {
                        constraint_conditions.push(format!("context.{} == true", param));
                    }
                    "boolean_false" => {
                        constraint_conditions.push(format!("context.{} == false", param));
                    }
                    _ => {
                        constraint_conditions.push(format!("context.hasAttr(\"{}\")", param));
                    }
                }
            }
        }

        let context_condition = if constraint_conditions.is_empty() {
            "unconditional".to_string()
        } else {
            constraint_conditions.join(" && ")
        };

        let cedar_rule = if constraint_conditions.is_empty() {
            format!(
                "// @id(\"{}\")\nforbid (\n    principal,\n    action == Action::\"{}\",\n    resource\n);",
                id, action
            )
        } else {
            format!(
                "// @id(\"{}\")\nforbid (\n    principal,\n    action == Action::\"{}\",\n    resource\n) when {{\n    {}\n}};",
                id, action, context_condition
            )
        };

        cedar_rules.push(cedar_rule);
        ucas.push(UnsafeControlAction {
            uca_id: id,
            hazard_ref,
            control_action: action,
            context_condition,
            mitigation: if description.is_empty() {
                "Enforced via Cedar policy guard".into()
            } else {
                description
            },
        });
    }

    let gamma = extract_f64(doc, &["cbf_gamma", "gamma"]);
    let b_min = extract_f64(doc, &["cbf_b_min", "b_min"]);

    Ok((cedar_rules, ucas, gamma, b_min))
}

/// Compiles Linux Foundation AAIF (`governedRunLoop`).
fn compile_aaif(
    doc: &serde_json::Value,
) -> Result<
    (
        Vec<String>,
        Vec<UnsafeControlAction>,
        Option<f64>,
        Option<f64>,
    ),
    PolicyIngestError,
> {
    let mut cedar_rules = Vec::new();
    let mut ucas = Vec::new();

    let loop_obj = doc.get("governedRunLoop").ok_or_else(|| {
        PolicyIngestError::MalformedSchema("Missing 'governedRunLoop' object in AAIF policy".into())
    })?;

    let stages = loop_obj
        .get("stages")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            PolicyIngestError::MalformedSchema(
                "Missing 'stages' array in AAIF governedRunLoop".into(),
            )
        })?;

    for stage in stages {
        let stage_name = stage
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown_stage");

        if let Some(hooks) = stage.get("hooks").and_then(|v| v.as_array()) {
            for hook in hooks {
                let hook_id = hook
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("AAIF-HOOK")
                    .to_string();
                let action = hook
                    .get("action")
                    .and_then(|v| v.as_str())
                    .unwrap_or("StageAction")
                    .to_string();

                let mut conditions = Vec::new();
                if let Some(constraints) = hook.get("constraints").and_then(|v| v.as_array()) {
                    for c in constraints {
                        let c_type = c.get("type").and_then(|v| v.as_str()).unwrap_or("");
                        let param = c
                            .get("parameter")
                            .and_then(|v| v.as_str())
                            .unwrap_or("param");
                        if c_type == "forbidden" {
                            conditions.push(format!("context.{} == true", param));
                        } else if c_type == "max" {
                            let val = c.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0);
                            conditions.push(format!("context.{} > {}", param, val));
                        }
                    }
                }

                let (cedar_rule, context_condition) = if stage_name == "access_control" {
                    let role = hook
                        .get("role")
                        .and_then(|v| v.as_str())
                        .unwrap_or("AgentArm");
                    (
                        format!(
                            "// @stage(\"{}\") @hook(\"{}\")\npermit (\n    principal in Role::\"{}\",\n    action == Action::\"{}\",\n    resource\n);",
                            stage_name, hook_id, role, action
                        ),
                        format!("Principal must be member of Role::\"{}\"", role),
                    )
                } else if conditions.is_empty() {
                    (
                        format!(
                            "// @stage(\"{}\") @hook(\"{}\")\nforbid (\n    principal,\n    action == Action::\"{}\",\n    resource\n) when {{\n    context.stage_violation == true\n}};",
                            stage_name, hook_id, action
                        ),
                        format!("AAIF stage '{}' invariant breach", stage_name),
                    )
                } else {
                    let joined_cond = conditions.join(" && ");
                    (
                        format!(
                            "// @stage(\"{}\") @hook(\"{}\")\nforbid (\n    principal,\n    action == Action::\"{}\",\n    resource\n) when {{\n    {}\n}};",
                            stage_name, hook_id, action, joined_cond
                        ),
                        joined_cond,
                    )
                };

                cedar_rules.push(cedar_rule);
                ucas.push(UnsafeControlAction {
                    uca_id: hook_id,
                    hazard_ref: format!("H-AAIF-{}", stage_name.to_ascii_uppercase()),
                    control_action: action,
                    context_condition,
                    mitigation: format!("AAIF stage '{}' lifecycle enforcement", stage_name),
                });
            }
        }
    }

    let gamma = extract_f64(loop_obj, &["cbf_gamma", "gamma"])
        .or_else(|| extract_f64(doc, &["cbf_gamma", "gamma"]));
    let b_min = extract_f64(loop_obj, &["cbf_b_min", "b_min"])
        .or_else(|| extract_f64(doc, &["cbf_b_min", "b_min"]));

    Ok((cedar_rules, ucas, gamma, b_min))
}

/// Compiles NIST OSCAL 1.1.x (`oscal-version`).
fn compile_oscal(
    doc: &serde_json::Value,
) -> Result<
    (
        Vec<String>,
        Vec<UnsafeControlAction>,
        Option<f64>,
        Option<f64>,
    ),
    PolicyIngestError,
> {
    let mut cedar_rules = Vec::new();
    let mut ucas = Vec::new();

    let comp_def = doc.get("component-definition").unwrap_or(doc);
    let components = comp_def
        .get("components")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            PolicyIngestError::MalformedSchema(
                "Missing 'components' array in OSCAL component definition".into(),
            )
        })?;

    for comp in components {
        if let Some(impls) = comp
            .get("control-implementations")
            .and_then(|v| v.as_array())
        {
            for imp in impls {
                if let Some(reqs) = imp
                    .get("implemented-requirements")
                    .and_then(|v| v.as_array())
                {
                    for req in reqs {
                        let control_id = req
                            .get("control-id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("ac-1")
                            .to_ascii_lowercase();

                        let desc = req
                            .get("description")
                            .and_then(|v| v.as_str())
                            .unwrap_or("NIST security control enforcement")
                            .to_string();

                        let action_name = match control_id.as_str() {
                            "ac-3" => "AccessEnforcement".to_string(),
                            "ac-6" => "LeastPrivilege".to_string(),
                            "sc-7" => "BoundaryProtection".to_string(),
                            "si-4" => "InformationSystemMonitoring".to_string(),
                            _ => format!(
                                "Control{}",
                                control_id.replace('-', "_").to_ascii_uppercase()
                            ),
                        };

                        let cedar_rule = format!(
                            "// @nistControl(\"{}\")\nforbid (\n    principal,\n    action == Action::\"{}\",\n    resource\n) when {{\n    context.compliance_violation == true\n}};",
                            control_id, action_name
                        );

                        cedar_rules.push(cedar_rule);
                        ucas.push(UnsafeControlAction {
                            uca_id: format!("OSCAL-{}", control_id.to_ascii_uppercase()),
                            hazard_ref: format!("H-NIST-{}", control_id.to_ascii_uppercase()),
                            control_action: action_name,
                            context_condition: desc.clone(),
                            mitigation: format!("NIST SP 800-53 control {}", control_id),
                        });
                    }
                }
            }
        }
    }

    let gamma = extract_f64(doc, &["cbf_gamma", "gamma"]);
    let b_min = extract_f64(doc, &["cbf_b_min", "b_min"]);

    Ok((cedar_rules, ucas, gamma, b_min))
}

/// Compiles Lula Validation Manifests (`kind: LulaValidation` or Rego).
fn compile_lula(
    doc: &serde_json::Value,
) -> Result<
    (
        Vec<String>,
        Vec<UnsafeControlAction>,
        Option<f64>,
        Option<f64>,
    ),
    PolicyIngestError,
> {
    let mut cedar_rules = Vec::new();
    let mut ucas = Vec::new();

    let name = doc
        .get("metadata")
        .and_then(|m| m.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("lula_validation_barrier");

    // Extract action name from spec policy or use default
    let action_name = if let Some(rego) = doc
        .get("spec")
        .and_then(|s| s.get("policy"))
        .and_then(|p| p.get("opa"))
        .and_then(|o| o.get("rego"))
        .and_then(|r| r.as_str())
    {
        if rego.contains("ModifySystemBinary") {
            "ModifySystemBinary".to_string()
        } else if rego.contains("ExecuteChildProcess") {
            "ExecuteChildProcess".to_string()
        } else {
            "HostActuation".to_string()
        }
    } else {
        "HostActuation".to_string()
    };

    let cedar_rule = format!(
        "// @lulaPolicy(\"{}\")\nforbid (\n    principal,\n    action == Action::\"{}\",\n    resource\n) when {{\n    context.lula_allow == false\n}};",
        name, action_name
    );

    cedar_rules.push(cedar_rule);
    ucas.push(UnsafeControlAction {
        uca_id: format!("LULA-{}", name),
        hazard_ref: "H-LULA-COMPLIANCE".to_string(),
        control_action: action_name,
        context_condition: "OPA Rego validation gate failure".to_string(),
        mitigation: format!("Lula validation gate barrier '{}'", name),
    });

    let gamma = extract_f64(doc, &["cbf_gamma", "gamma"]);
    let b_min = extract_f64(doc, &["cbf_b_min", "b_min"]);

    Ok((cedar_rules, ucas, gamma, b_min))
}

/// Compiles Native CAGE STPA (`stpa_control_structure`).
fn compile_stpa(
    doc: &serde_json::Value,
) -> Result<
    (
        Vec<String>,
        Vec<UnsafeControlAction>,
        Option<f64>,
        Option<f64>,
    ),
    PolicyIngestError,
> {
    let mut cedar_rules = Vec::new();
    let mut ucas = Vec::new();

    let uca_list = doc
        .get("unsafe_control_actions")
        .and_then(|v| v.as_array())
        .or_else(|| {
            doc.get("stpa_control_structure")
                .and_then(|s| s.get("unsafe_control_actions"))
                .and_then(|v| v.as_array())
        });

    if let Some(list) = uca_list {
        for uca in list {
            let uca_id = uca
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("UCA-1")
                .to_string();
            let action = uca
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("ControlAction")
                .to_string();

            let hazard_ref = uca
                .get("hazard_refs")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
                .and_then(|h| h.as_str())
                .unwrap_or("H-1")
                .to_string();

            let condition_str = if let Some(cond) = uca.get("condition") {
                let param = cond
                    .get("param")
                    .and_then(|v| v.as_str())
                    .unwrap_or("param");
                let op = cond
                    .get("operator")
                    .and_then(|v| v.as_str())
                    .unwrap_or("is_null");
                format!("{}:{}", param, op)
            } else {
                "unsafe_condition".to_string()
            };

            // Check if explicit cedar rule provided
            let cedar_rule = if let Some(rule) = uca.get("cedar_rule").and_then(|v| v.as_str()) {
                rule.trim().to_string()
            } else {
                format!(
                    "// @id(\"{}\")\nforbid (\n    principal,\n    action == Action::\"{}\",\n    resource\n) when {{\n    context.unsafe_trigger == true\n}};",
                    uca_id, action
                )
            };

            cedar_rules.push(cedar_rule);
            ucas.push(UnsafeControlAction {
                uca_id,
                hazard_ref,
                control_action: action,
                context_condition: condition_str,
                mitigation: "STPA safety constraint enforcement".to_string(),
            });
        }
    } else {
        // If neither unsafe_control_actions nor stpa_control_structure is explicitly populated,
        // create a root system default UCA to guarantee non-empty safety invariant
        cedar_rules.push(
            "// @id(\"CAGE-ROOT-001\")\nforbid (\n    principal,\n    action == Action::\"ExecuteChildProcess\",\n    resource\n) when {\n    context.routing_seal == \"\"\n};".to_string()
        );
        ucas.push(UnsafeControlAction {
            uca_id: "CAGE-ROOT-001".to_string(),
            hazard_ref: "H-1".to_string(),
            control_action: "ExecuteChildProcess".to_string(),
            context_condition: "context.routing_seal == \"\"".to_string(),
            mitigation: "Routing seal required for child process execution".to_string(),
        });
    }

    let gamma = extract_f64(doc, &["cbf_gamma", "gamma"])
        .or_else(|| {
            doc.get("cbf")
                .and_then(|c| c.get("gamma"))
                .and_then(|v| v.as_f64())
        })
        .or_else(|| {
            doc.get("stpa_control_structure")
                .and_then(|s| s.get("cbf"))
                .and_then(|c| c.get("gamma"))
                .and_then(|v| v.as_f64())
        });

    let b_min = extract_f64(doc, &["cbf_b_min", "b_min"])
        .or_else(|| {
            doc.get("cbf")
                .and_then(|c| c.get("b_min"))
                .and_then(|v| v.as_f64())
        })
        .or_else(|| {
            doc.get("stpa_control_structure")
                .and_then(|s| s.get("cbf"))
                .and_then(|c| c.get("b_min"))
                .and_then(|v| v.as_f64())
        });

    Ok((cedar_rules, ucas, gamma, b_min))
}

/// Helper to extract an `f64` from document using key candidates.
fn extract_f64(doc: &serde_json::Value, keys: &[&str]) -> Option<f64> {
    for k in keys {
        if let Some(val) = doc.get(*k).and_then(|v| v.as_f64()) {
            return Some(val);
        }
    }
    None
}

/// Helper to search recursively for numeric CBF parameters anywhere in a document tree.
fn extract_f64_recursive(val: &serde_json::Value, keys: &[&str]) -> Option<f64> {
    match val {
        serde_json::Value::Object(map) => {
            // Direct keys on this object
            for k in keys {
                if let Some(num) = map.get(*k).and_then(|v| v.as_f64()) {
                    return Some(num);
                }
            }
            // Check under nested "cbf" object
            if let Some(cbf) = map.get("cbf").and_then(|v| v.as_object()) {
                for k in keys {
                    if let Some(num) = cbf.get(*k).and_then(|v| v.as_f64()) {
                        return Some(num);
                    }
                }
            }
            // Recurse into child values
            for child in map.values() {
                if let Some(num) = extract_f64_recursive(child, keys) {
                    return Some(num);
                }
            }
            None
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                if let Some(num) = extract_f64_recursive(item, keys) {
                    return Some(num);
                }
            }
            None
        }
        _ => None,
    }
}

// -----------------------------------------------------------------------------
// Pure-Rust RFC 8785 JSON Canonicalization Scheme (JCS)
// -----------------------------------------------------------------------------

/// Canonicalizes a JSON value strictly adhering to RFC 8785:
/// 1. Object keys sorted lexicographically by UTF-16 code units.
/// 2. Minimal string escaping (only `"` and `\` and control chars `\u0000`..`\u001f`, `/` is unescaped).
/// 3. ECMAScript-compliant canonical number serialization (zero without `-`, integers without `.0`, exponents without `+`).
/// 4. No extraneous whitespace between delimiters.
pub fn canonicalize_jcs(val: &serde_json::Value) -> Result<String, PolicyIngestError> {
    let mut out = String::with_capacity(128);
    write_jcs_value(val, &mut out)?;
    Ok(out)
}

fn write_jcs_value(val: &serde_json::Value, out: &mut String) -> Result<(), PolicyIngestError> {
    match val {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        serde_json::Value::Number(n) => {
            write_jcs_number(n, out);
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

fn write_jcs_number(n: &serde_json::Number, out: &mut String) {
    if let Some(i) = n.as_i64() {
        out.push_str(&i.to_string());
    } else if let Some(u) = n.as_u64() {
        out.push_str(&u.to_string());
    } else if let Some(f) = n.as_f64() {
        if f == 0.0 {
            // ECMAScript: -0 is output as "0"
            out.push('0');
        } else if f.is_finite() {
            // If integer-valued within safe range, output as integer
            if f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0 {
                out.push_str(&(f as i64).to_string());
            } else {
                // Format float without positive '+' in exponent
                let s = f.to_string();
                let s_clean = s.replace("e+", "e");
                out.push_str(&s_clean);
            }
        } else {
            out.push_str("null");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_ingest_detect_and_compile_acs() {
        let yaml = r#"
schemaVersion: "2024-05-01"
behaviorDeclarations:
  - id: "rule-1"
    description: "Allow read access to public resources"
    action: "read"
    resource: "public:/*"
    effect: "allow"
"#;
        let policy = compile_policy(yaml, None).expect("ACS compilation failed");
        assert_eq!(policy.format, PolicyFormat::MicrosoftAcs);
        assert_eq!(policy.policy_version_id.len(), 16);
        assert!(!policy.cedar_rules.is_empty());
    }

    #[test]
    fn test_policy_ingest_version_pinning_and_conflict() {
        let yaml_v1 = r#"
schemaVersion: "2024-05-01"
behaviorDeclarations:
  - id: "rule-1"
    action: "read"
    resource: "public:/*"
    effect: "allow"
"#;
        let yaml_v2 = r#"
schemaVersion: "2024-05-01"
behaviorDeclarations:
  - id: "rule-2"
    action: "write"
    resource: "public:/*"
    effect: "deny"
"#;
        let p1 = compile_policy(yaml_v1, None).unwrap();
        let p2 = compile_policy(yaml_v2, None).unwrap();
        assert_ne!(p1.policy_version_id, p2.policy_version_id);

        assert!(verify_version_pinning(Some(&p1.policy_version_id), &p1.policy_version_id).is_ok());
        let conflict =
            verify_version_pinning(Some(&p1.policy_version_id), &p2.policy_version_id).unwrap_err();
        assert_eq!(conflict.pinned_version, p1.policy_version_id);
        assert_eq!(conflict.incoming_version, p2.policy_version_id);
    }
}
