//! MITRE ATT&CK Enterprise Framework Data Models.
//!
//! Provides types for Tactics, Techniques, Sub-techniques, Mitigations,
//! Threat Actor Groups (CTI), and Matrix Summaries for OpenỌ̀ṣọ́ọ̀sì Agentic EDR.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// MITRE ATT&CK Tactic (e.g. TA0001: Initial Access)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MitreTactic {
    pub id: String,
    pub name: String,
    pub description: String,
    pub techniques_count: usize,
}

impl MitreTactic {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        techniques_count: usize,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: description.into(),
            techniques_count,
        }
    }
}

/// MITRE ATT&CK Subtechnique (e.g. T1059.001: PowerShell)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MitreSubtechnique {
    pub id: String,
    pub name: String,
    pub description: String,
}

impl MitreSubtechnique {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: description.into(),
        }
    }
}

/// MITRE ATT&CK Technique (e.g. T1059: Command and Scripting Interpreter)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MitreTechnique {
    pub id: String,
    pub name: String,
    pub tactic_id: String,
    pub tactic_name: String,
    pub description: String,
    pub data_sources: Vec<String>,
    pub mitigations: Vec<String>,
    pub groups: Vec<String>,
    pub detection_mechanisms: Vec<String>,
    #[serde(default)]
    pub subtechniques: Vec<MitreSubtechnique>,
}

impl MitreTechnique {
    pub fn is_covered(&self) -> bool {
        !self.detection_mechanisms.is_empty() || !self.mitigations.is_empty()
    }
}

/// MITRE ATT&CK Mitigation (e.g. M1038: Execution Prevention)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MitreMitigation {
    pub id: String,
    pub name: String,
    pub description: String,
    pub techniques: Vec<String>,
    pub defense_type: String,
}

/// MITRE ATT&CK Threat Actor Group / CTI Profile (e.g. G0016: APT29)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MitreGroup {
    pub id: String,
    pub name: String,
    pub description: String,
    pub aliases: Vec<String>,
    pub techniques: Vec<String>,
}

/// MITRE ATT&CK Enterprise Matrix Summary & Posture Stats
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MitreMatrixSummary {
    pub tactics: Vec<MitreTactic>,
    pub techniques: Vec<MitreTechnique>,
    pub total_techniques: usize,
    pub covered_techniques: usize,
    pub coverage_percentage: f32,
    pub active_detections_by_tactic: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mitre_tactic_creation() {
        let tactic = MitreTactic::new(
            "TA0001",
            "Initial Access",
            "Adversaries attempting to gain initial foothold.",
            9,
        );
        assert_eq!(tactic.id, "TA0001");
        assert_eq!(tactic.name, "Initial Access");
        assert_eq!(tactic.techniques_count, 9);
    }

    #[test]
    fn test_mitre_technique_serialization() {
        let tech = MitreTechnique {
            id: "T1059".into(),
            name: "Command and Scripting Interpreter".into(),
            tactic_id: "TA0002".into(),
            tactic_name: "Execution".into(),
            description: "Adversaries may abuse command interpreters".into(),
            data_sources: vec!["Process: Process Creation".into()],
            mitigations: vec!["M1038: Execution Prevention".into()],
            groups: vec!["APT29".into(), "Lazarus Group".into()],
            detection_mechanisms: vec!["Sysmon Event 1".into(), "Sigma Rule".into()],
            subtechniques: vec![MitreSubtechnique::new(
                "T1059.001",
                "PowerShell",
                "Abuse PowerShell commands.",
            )],
        };

        let json = serde_json::to_string(&tech).expect("serialize");
        let deserialized: MitreTechnique = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(tech, deserialized);
        assert!(deserialized.is_covered());
    }

    #[test]
    fn test_mitre_matrix_summary_calculation() {
        let mut active = HashMap::new();
        active.insert("TA0002".into(), 3);

        let summary = MitreMatrixSummary {
            tactics: vec![MitreTactic::new("TA0002", "Execution", "Exec", 5)],
            techniques: vec![],
            total_techniques: 10,
            covered_techniques: 9,
            coverage_percentage: 90.0,
            active_detections_by_tactic: active,
        };

        assert_eq!(summary.total_techniques, 10);
        assert_eq!(summary.covered_techniques, 9);
        assert_eq!(summary.coverage_percentage, 90.0);
        assert_eq!(summary.active_detections_by_tactic.get("TA0002"), Some(&3));
    }

    #[test]
    fn test_mitre_tactics_and_techniques_associations() {
        let expected_tactics = [
            "TA0043", "TA0042", "TA0001", "TA0002", "TA0003",
            "TA0004", "TA0005", "TA0112", "TA0006", "TA0007",
            "TA0008", "TA0009", "TA0011", "TA0010", "TA0040",
        ];
        let tactics: Vec<MitreTactic> = expected_tactics
            .iter()
            .map(|id| MitreTactic::new(*id, format!("Tactic-{}", id), "Description", 1))
            .collect();
        assert_eq!(tactics.len(), 15);
        for id in &expected_tactics {
            assert!(tactics.iter().any(|t| t.id == *id));
        }

        let tech = MitreTechnique {
            id: "T1082".into(),
            name: "System Information Discovery".into(),
            tactic_id: "TA0007".into(),
            tactic_name: "Discovery".into(),
            description: "Adversaries discover host specs".into(),
            data_sources: vec!["Process Creation".into()],
            mitigations: vec!["M1047".into()],
            groups: vec!["APT29".into()],
            detection_mechanisms: vec!["Sysmon Event 1".into()],
            subtechniques: vec![],
        };
        assert_eq!(tech.tactic_id, "TA0007");
        assert_eq!(tech.tactic_name, "Discovery");
        assert!(tech.is_covered());
    }
}
