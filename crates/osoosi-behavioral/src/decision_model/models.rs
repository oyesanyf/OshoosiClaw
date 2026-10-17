use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Question answer type for Clef and OpenJev decision models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QuestionType {
    Choice,
    #[serde(alias = "noul", alias = "predicate")]
    Bool,
    Score,
}

/// Computes exact Shannon entropy H(p) = -\sum_{p_k > 1e-12} p_k \ln(p_k).
/// [SEC-OJEV-02] Hardened with finite probability checks to prevent NaN/Inf propagation.
pub fn shannon_entropy(probs: &HashMap<String, f64>) -> f64 {
    let mut h = 0.0;
    for &p in probs.values() {
        if p.is_finite() && p > 1e-12 {
            h -= p * p.ln();
        }
    }
    if !h.is_finite() || h < 0.0 {
        0.0
    } else {
        h
    }
}

/// Computes normalized Shannon entropy confidence 1.0 - (H(p) / \ln(K)) clamped to [0.0, 1.0].
/// [SEC-OJEV-02] Hardened against NaN/Inf and division-by-zero, guaranteeing a finite [0.0, 1.0] return.
pub fn normalized_entropy_confidence(probs: &HashMap<String, f64>) -> f64 {
    let k = probs.len();
    if k <= 1 {
        return 1.0;
    }
    let h = shannon_entropy(probs);
    let max_h = (k as f64).ln();
    if !max_h.is_finite() || max_h <= 1e-12 {
        return 1.0;
    }
    let ratio = h / max_h;
    if !ratio.is_finite() {
        return 1.0;
    }
    let conf = 1.0 - ratio;
    if !conf.is_finite() {
        1.0
    } else {
        conf.clamp(0.0, 1.0)
    }
}

/// Computes expected ordinal score \sum_{i=0}^{K-1} i * p(levels[i]).
/// [SEC-OJEV-02] Hardened against non-finite probabilities.
pub fn expected_ordinal_score(levels: &[String], probs: &HashMap<String, f64>) -> f64 {
    let mut score = 0.0;
    for (i, level) in levels.iter().enumerate() {
        if let Some(&p) = probs.get(level) {
            if p.is_finite() && p >= 0.0 {
                score += (i as f64) * p;
            }
        }
    }
    if !score.is_finite() {
        0.0
    } else {
        score
    }
}

/// Definition of a question posed to the decision model.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QuestionDefinition {
    #[serde(rename = "type")]
    pub question_type: QuestionType,
    pub instructions: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub criteria: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score_levels: Option<Vec<String>>,
}

/// Non-autoregressive decision model request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DecisionRequest {
    pub model: String,
    pub state: String,
    pub questions: HashMap<String, QuestionDefinition>,
}

/// Discrete choice answer with calibrated probability distribution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChoiceAnswer {
    pub value: String,
    pub probabilities: HashMap<String, f64>,
    #[serde(default)]
    pub confidence: Option<f64>,
}

impl ChoiceAnswer {
    pub fn new(value: String, probabilities: HashMap<String, f64>) -> Self {
        let conf = normalized_entropy_confidence(&probabilities);
        Self {
            value,
            probabilities,
            confidence: Some(conf),
        }
    }
}

/// Boolean answer with calibrated probability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BoolAnswer {
    pub value: bool,
    pub probability: f64,
    #[serde(default)]
    pub confidence: Option<f64>,
}

impl BoolAnswer {
    pub fn new(value: bool, probability: f64) -> Self {
        let p = if probability.is_finite() {
            probability.clamp(0.0, 1.0)
        } else if value {
            1.0
        } else {
            0.0
        };
        let mut map = HashMap::new();
        map.insert("true".to_string(), p);
        map.insert("false".to_string(), 1.0 - p);
        let conf = normalized_entropy_confidence(&map);
        Self {
            value,
            probability: p,
            confidence: Some(conf),
        }
    }
}

/// Ordinal score answer with calibrated probability distribution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScoreAnswer {
    pub value: String,
    pub probabilities: HashMap<String, f64>,
    #[serde(default)]
    pub confidence: Option<f64>,
    #[serde(default)]
    pub expected_score: Option<f64>,
}

impl ScoreAnswer {
    pub fn new(
        value: String,
        probabilities: HashMap<String, f64>,
        levels: Option<&[String]>,
    ) -> Self {
        let conf = normalized_entropy_confidence(&probabilities);
        let expected = levels.map(|l| expected_ordinal_score(l, &probabilities));
        Self {
            value,
            probabilities,
            confidence: Some(conf),
            expected_score: expected,
        }
    }
}

/// Strongly-typed or deserialized answer item.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DecisionAnswer {
    pub value: serde_json::Value,
    #[serde(default)]
    pub probability: Option<f64>,
    #[serde(default)]
    pub probabilities: Option<HashMap<String, f64>>,
    #[serde(default)]
    pub confidence: Option<f64>,
    #[serde(default)]
    pub expected_score: Option<f64>,
}

impl DecisionAnswer {
    pub fn from_choice(choice: ChoiceAnswer) -> Self {
        let conf = choice
            .confidence
            .or_else(|| Some(normalized_entropy_confidence(&choice.probabilities)));
        Self {
            value: serde_json::Value::String(choice.value),
            probability: None,
            probabilities: Some(choice.probabilities),
            confidence: conf,
            expected_score: None,
        }
    }

    pub fn from_bool(b: BoolAnswer) -> Self {
        let p = b.probability.clamp(0.0, 1.0);
        let conf = b.confidence.or_else(|| {
            let mut map = HashMap::new();
            map.insert("true".to_string(), p);
            map.insert("false".to_string(), 1.0 - p);
            Some(normalized_entropy_confidence(&map))
        });
        Self {
            value: serde_json::Value::Bool(b.value),
            probability: Some(p),
            probabilities: None,
            confidence: conf,
            expected_score: None,
        }
    }

    pub fn from_score(score: ScoreAnswer) -> Self {
        let conf = score
            .confidence
            .or_else(|| Some(normalized_entropy_confidence(&score.probabilities)));
        Self {
            value: serde_json::Value::String(score.value),
            probability: None,
            probabilities: Some(score.probabilities),
            confidence: conf,
            expected_score: score.expected_score,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        self.value.as_str()
    }

    pub fn as_bool(&self) -> Option<bool> {
        self.value.as_bool()
    }

    pub fn get_probability(&self) -> f64 {
        if let Some(p) = self.probability {
            return p;
        }
        if let (Some(val_str), Some(probs)) = (self.as_str(), &self.probabilities) {
            if let Some(&p) = probs.get(val_str) {
                return p;
            }
        }
        1.0
    }
}

/// Raw or envelope response from Clef / Workers AI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionResponse {
    pub answers: HashMap<String, DecisionAnswer>,
    pub latency_ms: f64,
    pub provider: String,
}

/// High-level structured security verdict synthesized from Clef questions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityIncidentDecision {
    pub verdict: String, // benign, suspicious, malicious, critical_emergency
    pub verdict_probability: f64,
    pub containment_action: String, // allow, alert, tarpit, ghost_tarpit, quarantine, isolate, defer_to_operator
    pub action_probability: f64,
    pub human_escalation_required: bool,
    pub deep_reasoning_required: bool,
    pub threat_severity: String, // None, Low, Medium, High, Critical
    pub latency_ms: f64,
    pub provider_used: String,
}

/// Standardized security incident question schema constructor.
pub fn build_standard_incident_questions() -> HashMap<String, QuestionDefinition> {
    let mut q = HashMap::new();

    let mut verdict_criteria = HashMap::new();
    verdict_criteria.insert(
        "benign",
        "Known legitimate system administration or software operation",
    );
    verdict_criteria.insert(
        "suspicious",
        "Anomalous command or behavior without definitive malicious proof",
    );
    verdict_criteria.insert(
        "malicious",
        "Active credential theft, process injection, ransomware, or persistence",
    );
    verdict_criteria.insert(
        "critical_emergency",
        "Immediate ransomware encryption or boot sector destruction",
    );

    q.insert(
        "verdict".to_string(),
        QuestionDefinition {
            question_type: QuestionType::Choice,
            instructions: "Classify the security nature of this process execution.".to_string(),
            criteria: Some(serde_json::to_value(verdict_criteria).unwrap_or_default()),
            score_levels: None,
        },
    );

    let mut action_criteria = HashMap::new();
    action_criteria.insert(
        "allow",
        "No action needed; allow execution to proceed normally",
    );
    action_criteria.insert(
        "alert",
        "Log alert to telemetry and P2P mesh without process interruption",
    );
    action_criteria.insert(
        "tarpit",
        "Suspend thread pool and starve CPU cycles to inspect further",
    );
    action_criteria.insert(
        "ghost_tarpit",
        "Deploy deception traps and throttle execution",
    );
    action_criteria.insert(
        "isolate",
        "Immediately terminate process and isolate network interface",
    );
    action_criteria.insert(
        "defer_to_operator",
        "Hold for human operator review before containment",
    );

    q.insert(
        "containment_action".to_string(),
        QuestionDefinition {
            question_type: QuestionType::Choice,
            instructions: "Determine the optimal immediate automated containment response."
                .to_string(),
            criteria: Some(serde_json::to_value(action_criteria).unwrap_or_default()),
            score_levels: None,
        },
    );

    q.insert(
        "human_escalation".to_string(),
        QuestionDefinition {
            question_type: QuestionType::Bool,
            instructions:
                "Is human operator sign-off required prior to executing this containment?"
                    .to_string(),
            criteria: None,
            score_levels: None,
        },
    );

    q.insert(
        "deep_reasoning_required".to_string(),
        QuestionDefinition {
            question_type: QuestionType::Bool,
            instructions: "Should the system invoke the heavy generative reasoning model (FoundationSec) to build a multi-hop causal attack graph?".to_string(),
            criteria: None,
            score_levels: None,
        },
    );

    q.insert(
        "threat_severity".to_string(),
        QuestionDefinition {
            question_type: QuestionType::Score,
            instructions: "What is the severity of host risk?".to_string(),
            criteria: Some(serde_json::json!([
                "None", "Low", "Medium", "High", "Critical"
            ])),
            score_levels: Some(vec![
                "None".to_string(),
                "Low".to_string(),
                "Medium".to_string(),
                "High".to_string(),
                "Critical".to_string(),
            ]),
        },
    );

    q
}

/// Convert high-level state text and model into a DecisionRequest.
pub fn build_security_incident_request(model: &str, state: &str) -> DecisionRequest {
    DecisionRequest {
        model: model.to_string(),
        state: state.to_string(),
        questions: build_standard_incident_questions(),
    }
}

/// Parse a raw DecisionResponse into a strongly typed SecurityIncidentDecision.
pub fn parse_security_incident_response(res: &DecisionResponse) -> SecurityIncidentDecision {
    let verdict_ans = res.answers.get("verdict");
    let verdict = verdict_ans
        .and_then(|a| a.as_str())
        .unwrap_or("suspicious")
        .to_string();
    let verdict_probability = verdict_ans.map(|a| a.get_probability()).unwrap_or(0.5);

    let action_ans = res.answers.get("containment_action");
    let containment_action = action_ans
        .and_then(|a| a.as_str())
        .unwrap_or("alert")
        .to_string();
    let action_probability = action_ans.map(|a| a.get_probability()).unwrap_or(0.5);

    let human_ans = res.answers.get("human_escalation");
    let human_escalation_required = human_ans.and_then(|a| a.as_bool()).unwrap_or(false);

    let deep_ans = res.answers.get("deep_reasoning_required");
    let deep_reasoning_required = deep_ans.and_then(|a| a.as_bool()).unwrap_or(false);

    let severity_ans = res.answers.get("threat_severity");
    let threat_severity = severity_ans
        .and_then(|a| a.as_str())
        .unwrap_or("Medium")
        .to_string();

    SecurityIncidentDecision {
        verdict,
        verdict_probability,
        containment_action,
        action_probability,
        human_escalation_required,
        deep_reasoning_required,
        threat_severity,
        latency_ms: res.latency_ms,
        provider_used: res.provider.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sec_ojev_02_finite_probability_and_entropy_guards() {
        let mut probs = HashMap::new();
        probs.insert("option_a".to_string(), f64::NAN);
        probs.insert("option_b".to_string(), f64::INFINITY);
        probs.insert("option_c".to_string(), -1.0);
        probs.insert("option_d".to_string(), 0.5);

        let h = shannon_entropy(&probs);
        assert!(
            h.is_finite(),
            "Entropy must be finite despite NaN/Inf inputs"
        );
        assert!(h >= 0.0);

        let conf = normalized_entropy_confidence(&probs);
        assert!(
            conf.is_finite(),
            "Confidence must be finite despite NaN/Inf inputs"
        );
        assert!(conf >= 0.0 && conf <= 1.0);

        let levels = vec!["option_d".to_string()];
        let score = expected_ordinal_score(&levels, &probs);
        assert!(score.is_finite(), "Score must be finite");

        let bool_ans_nan = BoolAnswer::new(true, f64::NAN);
        assert!(bool_ans_nan.probability.is_finite());
        assert_eq!(bool_ans_nan.probability, 1.0);
        assert!(bool_ans_nan.confidence.unwrap().is_finite());
    }
}
