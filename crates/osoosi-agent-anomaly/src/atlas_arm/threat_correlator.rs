use super::technique_mapper::MappedThreatRecord;
use std::collections::HashMap;

/// Step types in candidate attack chains.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AttackStepType {
    PromptInjection,
    PrivilegeEscalation,
    LateralMovement,
    EgressExfiltration,
    PersistenceAttempt,
    CredentialAccess,
}

/// Attack step record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AttackStep {
    pub step_number: usize,
    pub step_type: AttackStepType,
    pub actor_agent: String,
    pub target_component: String,
    pub payload_vector: String,
    pub associated_vuln_id: Option<String>,
}

/// Candidate attack chain.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CandidateAttackChain {
    pub chain_id: String,
    pub name: String,
    pub target_asset: String,
    pub steps: Vec<AttackStep>,
    pub estimated_blast_radius: String,
}

/// Relationship transition between two ATLAS techniques in a multi-stage attack.
#[derive(Debug, Clone)]
pub struct AtlasTechniqueRelationship {
    pub source_technique_id: String,
    pub target_technique_id: String,
    pub step_type: AttackStepType,
    pub correlation_rationale: String,
}

/// ThreatCorrelator: Bridges the MITRE ATLAS Arm and Attack Chain Arm by correlating
/// documented attack relationships into actionable multi-stage attack graphs.
pub struct ThreatCorrelator {
    known_relationships: Vec<AtlasTechniqueRelationship>,
}

impl Default for ThreatCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatCorrelator {
    pub fn new() -> Self {
        let relationships = vec![
            // Prompt Injection -> Obtain Capabilities
            AtlasTechniqueRelationship {
                source_technique_id: "AML.T0051".to_string(),
                target_technique_id: "AML.T0016".to_string(),
                step_type: AttackStepType::PrivilegeEscalation,
                correlation_rationale:
                    "Prompt injection redirects agent to request elevated delegation".to_string(),
            },
            // Obtain Capabilities -> Lateral Movement
            AtlasTechniqueRelationship {
                source_technique_id: "AML.T0016".to_string(),
                target_technique_id: "AML.T0034".to_string(),
                step_type: AttackStepType::LateralMovement,
                correlation_rationale:
                    "Elevated capability allows invoking peer arm endpoints across the swarm"
                        .to_string(),
            },
            // Lateral Movement -> Exfiltration
            AtlasTechniqueRelationship {
                source_technique_id: "AML.T0034".to_string(),
                target_technique_id: "AML.T0024".to_string(),
                step_type: AttackStepType::EgressExfiltration,
                correlation_rationale:
                    "Compromised peer arm with network capability attempts exfiltration".to_string(),
            },
            // Lateral Movement -> Escape to Host
            AtlasTechniqueRelationship {
                source_technique_id: "AML.T0034".to_string(),
                target_technique_id: "AML.T0000".to_string(),
                step_type: AttackStepType::PersistenceAttempt,
                correlation_rationale:
                    "Compromised arm attempts to escape sandbox into host operating system"
                        .to_string(),
            },
        ];

        Self {
            known_relationships: relationships,
        }
    }

    /// Correlates active threat findings into structured candidate attack chains.
    pub fn correlate_chains(
        &self,
        mapped_records: &[MappedThreatRecord],
    ) -> Vec<CandidateAttackChain> {
        let mut active_techs = HashMap::new();
        for rec in mapped_records {
            active_techs.insert(rec.atlas_technique_id.clone(), rec.clone());
        }

        let mut synthesized_chains = Vec::new();

        // If AML.T0051 (Prompt Injection) is active, build forward paths
        if let Some(initial_rec) = active_techs.get("AML.T0051") {
            let mut steps = Vec::new();
            steps.push(AttackStep {
                step_number: 1,
                step_type: AttackStepType::PromptInjection,
                actor_agent: initial_rec.affected_component.clone(),
                target_component: "doc_extractor".to_string(),
                payload_vector: "Prompt injection in invoice text".to_string(),
                associated_vuln_id: Some(initial_rec.finding_id.clone()),
            });

            // Follow known relationships
            let mut current_tech = "AML.T0051";
            let mut step_num = 2;

            while let Some(rel) = self
                .known_relationships
                .iter()
                .find(|r| r.source_technique_id == current_tech)
            {
                steps.push(AttackStep {
                    step_number: step_num,
                    step_type: rel.step_type.clone(),
                    actor_agent: format!("agent_{}", rel.target_technique_id.replace('.', "_")),
                    target_component: rel.target_technique_id.clone(),
                    payload_vector: rel.correlation_rationale.clone(),
                    associated_vuln_id: None,
                });
                current_tech = &rel.target_technique_id;
                step_num += 1;
                if step_num > 4 {
                    break;
                }
            }

            synthesized_chains.push(CandidateAttackChain {
                chain_id: "CHAIN-ATLAS-CORRELATED-01".to_string(),
                name: "ATLAS Correlated Prompt Injection to Host Escape / Exfiltration".to_string(),
                target_asset: "Host Operating System & Protected Accounting Records".to_string(),
                steps,
                estimated_blast_radius:
                    "Critical: Potential full swarm and host process compromise".to_string(),
            });
        }

        synthesized_chains
    }
}
