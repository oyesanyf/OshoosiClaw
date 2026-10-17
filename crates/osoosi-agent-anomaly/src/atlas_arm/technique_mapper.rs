use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Threat realization status distinguishing theoretical flaws from demonstrated attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatFeasibility {
    /// Architecturally possible based on configuration audit, but not yet tested.
    Feasible,
    /// Successfully triggered and verified inside a controlled sandbox test harness.
    Demonstrated,
    /// An actual boundary was bypassed or breached during live execution.
    Realized,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappedThreatRecord {
    pub finding_id: String,
    pub atlas_technique_id: String,
    pub technique_name: String,
    pub feasibility: ThreatFeasibility,
    pub affected_component: String,
    pub rationale: String,
}

/// TechniqueMapper: Maps Agent Octopus vulnerability findings and security events
/// directly to official MITRE ATLAS technique classifications.
pub struct TechniqueMapper {
    mapping_rules: HashMap<String, String>,
}

impl Default for TechniqueMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl TechniqueMapper {
    pub fn new() -> Self {
        let mut rules = HashMap::new();
        rules.insert("OCT-VULN-001".to_string(), "AML.T0042".to_string()); // Fuel limit -> Resource Hijacking
        rules.insert("OCT-VULN-002".to_string(), "AML.T0016".to_string()); // Excessive delegation -> Obtain Capabilities
        rules.insert("OCT-VULN-003".to_string(), "AML.T0001".to_string()); // Token exposure -> Tool Poisoning
        rules.insert("OCT-VULN-004".to_string(), "AML.T0031".to_string()); // Permissive egress -> C2
        rules.insert("OCT-VULN-005".to_string(), "AML.T0042".to_string()); // Memory clamp -> Resource Hijacking
        rules.insert("INJECTION".to_string(), "AML.T0051".to_string()); // Prompt Injection
        rules.insert("ESCAPE".to_string(), "AML.T0000".to_string()); // Host Escape
        rules.insert("REPLAY".to_string(), "AML.T0003".to_string()); // Identity Spoofing
        Self {
            mapping_rules: rules,
        }
    }

    /// Maps an internal Octopus finding to an authoritative MITRE ATLAS technique ID.
    pub fn map_finding(
        &self,
        finding_id: &str,
        component: &str,
        feasibility: ThreatFeasibility,
        rationale: &str,
    ) -> Option<MappedThreatRecord> {
        let tech_id = self.mapping_rules.get(finding_id).cloned().or_else(|| {
            // Check substrings for dynamic findings
            if finding_id.contains("INJECT") {
                Some("AML.T0051".to_string())
            } else if finding_id.contains("ESCAPE") || finding_id.contains("JOB") {
                Some("AML.T0000".to_string())
            } else if finding_id.contains("EGRESS") || finding_id.contains("SSRF") {
                Some("AML.T0024".to_string())
            } else {
                None
            }
        })?;

        let tech_name = match tech_id.as_str() {
            "AML.T0000" => "Escape to Host Operating System",
            "AML.T0051" => "LLM Prompt Injection",
            "AML.T0001" => "Tool Poisoning",
            "AML.T0016" => "Obtain Capabilities",
            "AML.T0031" => "Command and Control",
            "AML.T0024" => "Exfiltration via ML Inference API",
            "AML.T0042" => "Resource Hijacking",
            "AML.T0003" => "Agent Impersonation",
            _ => "Generic ATLAS Technique",
        };

        Some(MappedThreatRecord {
            finding_id: finding_id.to_string(),
            atlas_technique_id: tech_id,
            technique_name: tech_name.to_string(),
            feasibility,
            affected_component: component.to_string(),
            rationale: rationale.to_string(),
        })
    }
}
