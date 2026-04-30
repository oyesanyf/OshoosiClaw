//! Soft Cluster-Based Dynamic Ensemble Orchestrator
//! Implements Local Weighting and Uncertainty-Aware Risk Control across multiple LLM experts.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn, debug};
use crate::reasoning::AIIntentInsight;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatCluster {
    Evasion,
    Persistence,
    Exfiltration,
    CredentialAccess,
    LateralMovement,
    General,
}

pub struct LLMExpert {
    pub name: String,
    pub model_type: String, // "local", "remote", etc.
}

pub struct EnsembleOrchestrator {
    experts: Vec<LLMExpert>,
    /// cluster -> expert_name -> weight
    weight_matrix: HashMap<ThreatCluster, HashMap<String, f32>>,
}

impl EnsembleOrchestrator {
    pub fn new() -> Self {
        let mut weight_matrix = HashMap::new();

        // Initializing the Soft Cluster Weighting Matrix (Expertise Calibration)
        // DeepSeek-R1 is weighted heavily for Evasion and Lateral Movement (complex reasoning)
        // Gemma is weighted for Persistence and General behavior
        // SmolLM is used as a fast sanity check across all
        
        let mut evasion_weights = HashMap::new();
        evasion_weights.insert("DeepSeek-R1".to_string(), 0.6);
        evasion_weights.insert("Gemma-2".to_string(), 0.3);
        evasion_weights.insert("SmolLM".to_string(), 0.1);
        weight_matrix.insert(ThreatCluster::Evasion, evasion_weights);

        let mut lateral_weights = HashMap::new();
        lateral_weights.insert("DeepSeek-R1".to_string(), 0.7);
        lateral_weights.insert("Gemma-2".to_string(), 0.2);
        lateral_weights.insert("SmolLM".to_string(), 0.1);
        weight_matrix.insert(ThreatCluster::LateralMovement, lateral_weights);

        Self {
            experts: vec![
                LLMExpert { name: "DeepSeek-R1".to_string(), model_type: "remote".to_string() },
                LLMExpert { name: "Gemma-2".to_string(), model_type: "local".to_string() },
                LLMExpert { name: "SmolLM".to_string(), model_type: "local".to_string() },
            ],
            weight_matrix,
        }
    }

    /// Performs a Dynamic Weighted Consensus across all experts.
    /// Implements Uncertainty-Aware Risk Control.
    pub async fn deliberate(&self, insights: Vec<(String, AIIntentInsight)>) -> Result<EnsembleDecision> {
        // 1. Soft Clustering: Determine the dominant cluster for the threat
        let cluster = self.determine_threat_cluster(&insights);
        
        info!("⚖️ [ENSEMBLE] Deliberating in {:?} cluster context...", cluster);

        let mut weighted_risk = 0.0;
        let mut total_weight = 0.0;
        let mut scores = Vec::new();

        // 2. Local Weighting Pass
        let cluster_weights = self.weight_matrix.get(&cluster)
            .cloned()
            .unwrap_or_default();

        for (expert_name, insight) in &insights {
            let weight = cluster_weights.get(expert_name).cloned().unwrap_or(0.33); // Default to equal
            weighted_risk += insight.risk_score * weight;
            total_weight += weight;
            scores.push(insight.risk_score);
            debug!("   - Expert {}: Risk={:.2}, Weight={:.2}", expert_name, insight.risk_score, weight);
        }

        let consensus_risk = if total_weight > 0.0 { weighted_risk / total_weight } else { 0.0 };

        // 3. Uncertainty-Aware Risk Control
        // Calculate Variance/Entropy of the ensemble opinions
        let uncertainty = self.calculate_uncertainty(&scores);
        
        let mut final_action = "observe";
        if consensus_risk > 0.8 && uncertainty < 0.3 {
            final_action = "block";
        } else if consensus_risk > 0.6 {
            final_action = "triage";
        }

        if uncertainty > 0.5 {
            warn!("⚠️ [ENSEMBLE] High uncertainty detected ({:.2}). Consensus is unstable.", uncertainty);
        }

        Ok(EnsembleDecision {
            consensus_risk,
            uncertainty,
            final_action: final_action.to_string(),
            dominant_cluster: cluster,
            reasoning: format!("Ensemble consensus reached with {:.2} risk and {:.2} uncertainty.", consensus_risk, uncertainty),
        })
    }

    fn determine_threat_cluster(&self, insights: &[(String, AIIntentInsight)]) -> ThreatCluster {
        // Simple majority vote or keyword based clustering from AI reasoning
        let mut clusters = HashMap::new();
        for (_, insight) in insights {
            let cat = match insight.intent_category.to_lowercase().as_str() {
                "evasion" | "stealth" => ThreatCluster::Evasion,
                "persistence" => ThreatCluster::Persistence,
                "exfiltration" => ThreatCluster::Exfiltration,
                "lateral" | "moving" => ThreatCluster::LateralMovement,
                _ => ThreatCluster::General,
            };
            *clusters.entry(cat).or_insert(0) += 1;
        }

        clusters.into_iter()
            .max_by_key(|&(_, count)| count)
            .map(|(c, _)| c)
            .unwrap_or(ThreatCluster::General)
    }

    fn calculate_uncertainty(&self, scores: &[f32]) -> f32 {
        if scores.len() < 2 { return 0.0; }
        let mean = scores.iter().sum::<f32>() / scores.len() as f32;
        let variance = scores.iter()
            .map(|&s| (s - mean).powi(2))
            .sum::<f32>() / scores.len() as f32;
        variance.sqrt() // Standard Deviation as simple uncertainty metric
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnsembleDecision {
    pub consensus_risk: f32,
    pub uncertainty: f32,
    pub final_action: String,
    pub dominant_cluster: ThreatCluster,
    pub reasoning: String,
}
