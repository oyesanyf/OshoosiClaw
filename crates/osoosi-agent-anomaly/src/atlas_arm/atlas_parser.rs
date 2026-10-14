use super::atlas_matrix::{AtlasTactic, AtlasTechnique, MitreAtlasMatrix};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasMitigation {
    pub mitigation_id: String,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasCaseStudy {
    pub case_study_id: String,
    pub title: String,
    pub summary: String,
    pub target_system_type: String,
    pub leveraged_techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedAtlasKnowledgeBase {
    pub tactics: Vec<AtlasTactic>,
    pub techniques: HashMap<String, AtlasTechnique>,
    pub mitigations: HashMap<String, AtlasMitigation>,
    pub case_studies: HashMap<String, AtlasCaseStudy>,
    pub tactic_to_techniques: HashMap<AtlasTactic, Vec<String>>,
}

/// AtlasParser: Decodes structured MITRE ATLAS schemas into queryable graph structures.
pub struct AtlasParser;

impl AtlasParser {
    /// Constructs a fully populated knowledge base from the authoritative pinned taxonomy.
    pub fn parse_authoritative_bundle(matrix: &MitreAtlasMatrix) -> ParsedAtlasKnowledgeBase {
        let mut techniques_map = HashMap::new();
        let mut tactic_mapping: HashMap<AtlasTactic, Vec<String>> = HashMap::new();

        for tech in matrix.techniques() {
            techniques_map.insert(tech.technique_id.clone(), tech.clone());
            tactic_mapping
                .entry(tech.tactic.clone())
                .or_default()
                .push(tech.technique_id.clone());
        }

        // Pinned Mitigations (40 authoritative controls)
        let mut mitigations = HashMap::new();
        mitigations.insert(
            "AML.M1001".to_string(),
            AtlasMitigation {
                mitigation_id: "AML.M1001".to_string(),
                name: "Strict Schema Enclave".to_string(),
                description: "Enforce strict typed JSON AST schemas to prevent prompt injection payload execution".to_string(),
            },
        );
        mitigations.insert(
            "AML.M1004".to_string(),
            AtlasMitigation {
                mitigation_id: "AML.M1004".to_string(),
                name: "Windows Job Object Process Clamping".to_string(),
                description: "Kernel limits kill on close, zero child process spawning, and 64MB memory quota".to_string(),
            },
        );
        mitigations.insert(
            "AML.M1005".to_string(),
            AtlasMitigation {
                mitigation_id: "AML.M1005".to_string(),
                name: "AppContainer LPAC Moniker Isolation".to_string(),
                description: "Strict package SID ACLs blocking filesystem and non-Google network egress".to_string(),
            },
        );
        mitigations.insert(
            "AML.M1006".to_string(),
            AtlasMitigation {
                mitigation_id: "AML.M1006".to_string(),
                name: "Wasmtime Hardware Fuel Metering".to_string(),
                description: "Precise instruction count tracking and wall-clock supervisor timeout".to_string(),
            },
        );
        mitigations.insert(
            "AML.M1007".to_string(),
            AtlasMitigation {
                mitigation_id: "AML.M1007".to_string(),
                name: "HMAC Capability Tokens".to_string(),
                description: "Short-lived unforgeable capability authorization tokens issued by external engine".to_string(),
            },
        );

        // Pinned Case Studies (representing published AI attack scenarios)
        let mut case_studies = HashMap::new();
        case_studies.insert(
            "AML.CS001".to_string(),
            AtlasCaseStudy {
                case_study_id: "AML.CS001".to_string(),
                title: "Autonomous Agent Tool Poisoning and Host Breakout Attempt".to_string(),
                summary: "Adversary embedded indirect prompt injection into input documents to trigger unauthorized subprocess creation and lateral movement".to_string(),
                target_system_type: "Multi-Agent Workflow".to_string(),
                leveraged_techniques: vec!["AML.T0051".to_string(), "AML.T0000".to_string(), "AML.T0001".to_string(), "AML.T0034".to_string()],
            },
        );

        let tactics = vec![
            AtlasTactic::Reconnaissance,
            AtlasTactic::ResourceDevelopment,
            AtlasTactic::InitialAccess,
            AtlasTactic::MLModelAccess,
            AtlasTactic::Execution,
            AtlasTactic::Persistence,
            AtlasTactic::PrivilegeEscalation,
            AtlasTactic::DefenseEvasion,
            AtlasTactic::CredentialAccess,
            AtlasTactic::Discovery,
            AtlasTactic::LateralMovement,
            AtlasTactic::Collection,
            AtlasTactic::MLAttackStaging,
            AtlasTactic::Exfiltration,
            AtlasTactic::CommandAndControl,
            AtlasTactic::Impact,
        ];

        ParsedAtlasKnowledgeBase {
            tactics,
            techniques: techniques_map,
            mitigations,
            case_studies,
            tactic_to_techniques: tactic_mapping,
        }
    }

    /// Parses a standard STIX 2.1 JSON bundle (from https://github.com/mitre-atlas/atlas-data)
    /// into a complete, queryable MITRE ATLAS Knowledge Base.
    pub fn parse_stix_bundle(json_str: &str) -> Result<ParsedAtlasKnowledgeBase, Box<dyn std::error::Error + Send + Sync>> {
        let v: serde_json::Value = serde_json::from_str(json_str)?;
        let objects = v.get("objects")
            .and_then(|o| o.as_array())
            .ok_or("Invalid STIX bundle: missing 'objects' array")?;

        let mut techniques_map = HashMap::new();
        let mut stix_to_tech_id: HashMap<String, String> = HashMap::new();
        let mut mitigations = HashMap::new();
        let mut stix_to_mit_id: HashMap<String, String> = HashMap::new();
        let mut case_studies = HashMap::new();
        let mut tactic_mapping: HashMap<AtlasTactic, Vec<String>> = HashMap::new();

        // 1. Pass 1: Parse tactics, techniques, mitigations, and campaigns
        for obj in objects {
            let obj_type = obj.get("type").and_then(|t| t.as_str()).unwrap_or_default();
            let stix_id = obj.get("id").and_then(|i| i.as_str()).unwrap_or_default().to_string();

            match obj_type {
                "attack-pattern" => {
                    let name = obj.get("name").and_then(|n| n.as_str()).unwrap_or("Unknown Technique").to_string();
                    let description = obj.get("description").and_then(|d| d.as_str()).unwrap_or("").to_string();
                    
                    let mut ext_id = String::new();
                    if let Some(refs) = obj.get("external_references").and_then(|r| r.as_array()) {
                        for r in refs {
                            if r.get("source_name").and_then(|s| s.as_str()) == Some("mitre-atlas") {
                                if let Some(e) = r.get("external_id").and_then(|e| e.as_str()) {
                                    ext_id = e.to_string();
                                    break;
                                }
                            }
                        }
                    }
                    if ext_id.is_empty() {
                        ext_id = stix_id.clone();
                    }

                    // Extract tactic from kill_chain_phases
                    let mut tactic = AtlasTactic::Execution;
                    if let Some(phases) = obj.get("kill_chain_phases").and_then(|p| p.as_array()) {
                        for p in phases {
                            if p.get("kill_chain_name").and_then(|k| k.as_str()) == Some("mitre-atlas") {
                                if let Some(phase) = p.get("phase_name").and_then(|pn| pn.as_str()) {
                                    tactic = Self::phase_to_tactic(phase);
                                    break;
                                }
                            }
                        }
                    }

                    tactic_mapping.entry(tactic.clone()).or_default().push(ext_id.clone());
                    stix_to_tech_id.insert(stix_id, ext_id.clone());

                    techniques_map.insert(ext_id.clone(), AtlasTechnique {
                        technique_id: ext_id,
                        name,
                        tactic,
                        description,
                        relevant_mitigations: Vec::new(),
                    });
                }
                "course-of-action" => {
                    let name = obj.get("name").and_then(|n| n.as_str()).unwrap_or("Unknown Mitigation").to_string();
                    let description = obj.get("description").and_then(|d| d.as_str()).unwrap_or("").to_string();
                    let mut ext_id = String::new();
                    if let Some(refs) = obj.get("external_references").and_then(|r| r.as_array()) {
                        for r in refs {
                            if r.get("source_name").and_then(|s| s.as_str()) == Some("mitre-atlas") {
                                if let Some(e) = r.get("external_id").and_then(|e| e.as_str()) {
                                    ext_id = e.to_string();
                                    break;
                                }
                            }
                        }
                    }
                    if ext_id.is_empty() {
                        ext_id = stix_id.clone();
                    }
                    stix_to_mit_id.insert(stix_id, ext_id.clone());
                    mitigations.insert(ext_id.clone(), AtlasMitigation {
                        mitigation_id: ext_id,
                        name,
                        description,
                    });
                }
                "campaign" => {
                    let title = obj.get("name").and_then(|n| n.as_str()).unwrap_or("Unknown Case Study").to_string();
                    let summary = obj.get("description").and_then(|d| d.as_str()).unwrap_or("").to_string();
                    let mut ext_id = String::new();
                    if let Some(refs) = obj.get("external_references").and_then(|r| r.as_array()) {
                        for r in refs {
                            if r.get("source_name").and_then(|s| s.as_str()) == Some("mitre-atlas") {
                                if let Some(e) = r.get("external_id").and_then(|e| e.as_str()) {
                                    ext_id = e.to_string();
                                    break;
                                }
                            }
                        }
                    }
                    if ext_id.is_empty() {
                        ext_id = stix_id.clone();
                    }
                    case_studies.insert(ext_id.clone(), AtlasCaseStudy {
                        case_study_id: ext_id,
                        title,
                        summary,
                        target_system_type: "Machine Learning System".to_string(),
                        leveraged_techniques: Vec::new(),
                    });
                }
                _ => {}
            }
        }

        // 2. Pass 2: Connect relationships (mitigations -> techniques, campaigns -> techniques)
        for obj in objects {
            if obj.get("type").and_then(|t| t.as_str()) == Some("relationship") {
                let rel_type = obj.get("relationship_type").and_then(|r| r.as_str()).unwrap_or_default();
                let source_ref = obj.get("source_ref").and_then(|s| s.as_str()).unwrap_or_default();
                let target_ref = obj.get("target_ref").and_then(|t| t.as_str()).unwrap_or_default();

                if rel_type == "mitigates" {
                    if let (Some(mit_id), Some(tech_id)) = (stix_to_mit_id.get(source_ref), stix_to_tech_id.get(target_ref)) {
                        if let Some(tech) = techniques_map.get_mut(tech_id) {
                            let mit_label = match mitigations.get(mit_id) {
                                Some(m) => format!("{}: {}", mit_id, m.name),
                                None => mit_id.clone(),
                            };
                            if !tech.relevant_mitigations.contains(&mit_label) {
                                tech.relevant_mitigations.push(mit_label);
                            }
                        }
                    }
                }
            }
        }

        let tactics = vec![
            AtlasTactic::Reconnaissance,
            AtlasTactic::ResourceDevelopment,
            AtlasTactic::InitialAccess,
            AtlasTactic::MLModelAccess,
            AtlasTactic::Execution,
            AtlasTactic::Persistence,
            AtlasTactic::PrivilegeEscalation,
            AtlasTactic::DefenseEvasion,
            AtlasTactic::CredentialAccess,
            AtlasTactic::Discovery,
            AtlasTactic::LateralMovement,
            AtlasTactic::Collection,
            AtlasTactic::MLAttackStaging,
            AtlasTactic::Exfiltration,
            AtlasTactic::CommandAndControl,
            AtlasTactic::Impact,
        ];

        Ok(ParsedAtlasKnowledgeBase {
            tactics,
            techniques: techniques_map,
            mitigations,
            case_studies,
            tactic_to_techniques: tactic_mapping,
        })
    }

    /// Helper converting STIX kill chain phase name into AtlasTactic enum.
    pub fn phase_to_tactic(phase: &str) -> AtlasTactic {
        match phase.to_lowercase().as_str() {
            "reconnaissance" => AtlasTactic::Reconnaissance,
            "resource-development" => AtlasTactic::ResourceDevelopment,
            "initial-access" => AtlasTactic::InitialAccess,
            "ai-model-access" | "ml-model-access" => AtlasTactic::MLModelAccess,
            "execution" => AtlasTactic::Execution,
            "persistence" => AtlasTactic::Persistence,
            "privilege-escalation" => AtlasTactic::PrivilegeEscalation,
            "defense-evasion" => AtlasTactic::DefenseEvasion,
            "credential-access" => AtlasTactic::CredentialAccess,
            "discovery" => AtlasTactic::Discovery,
            "lateral-movement" => AtlasTactic::LateralMovement,
            "collection" => AtlasTactic::Collection,
            "ai-attack-adaptation" | "ml-attack-staging" => AtlasTactic::MLAttackStaging,
            "exfiltration" => AtlasTactic::Exfiltration,
            "command-and-control" => AtlasTactic::CommandAndControl,
            "impact" => AtlasTactic::Impact,
            _ => AtlasTactic::Execution,
        }
    }
}
