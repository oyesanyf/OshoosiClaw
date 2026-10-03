use super::models::{
    BoolAnswer, ChoiceAnswer, DecisionAnswer, DecisionRequest, DecisionResponse, QuestionDefinition,
    QuestionType, ScoreAnswer,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Configurable weights for local non-autoregressive Clef scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalClefWeights {
    pub malicious_token_weights: HashMap<String, f64>,
    pub benign_token_weights: HashMap<String, f64>,
    pub mitre_technique_weights: HashMap<String, f64>,
    pub temperature: f64,
    pub label_smoothing_epsilon: f64,
}

impl Default for LocalClefWeights {
    fn default() -> Self {
        let mut malicious = HashMap::new();
        malicious.insert("mimikatz".to_string(), 4.5);
        malicious.insert("sekurlsa".to_string(), 4.5);
        malicious.insert("logonpasswords".to_string(), 4.5);
        malicious.insert("lsass".to_string(), 3.5);
        malicious.insert("vssadmin".to_string(), 4.0);
        malicious.insert("delete shadows".to_string(), 5.5);
        malicious.insert("bcdedit".to_string(), 3.5);
        malicious.insert("recoveryenabled no".to_string(), 5.0);
        malicious.insert("cobalt".to_string(), 4.8);
        malicious.insert("beacon".to_string(), 4.0);
        malicious.insert("meterpreter".to_string(), 4.8);
        malicious.insert("shellcode".to_string(), 4.5);
        malicious.insert("reflective".to_string(), 4.0);
        malicious.insert("inject".to_string(), 3.8);
        malicious.insert("nanodump".to_string(), 4.5);
        malicious.insert("procdump".to_string(), 3.2);
        malicious.insert("rubeus".to_string(), 4.2);
        malicious.insert("safetykatz".to_string(), 4.5);
        malicious.insert("sharpup".to_string(), 3.5);
        malicious.insert("whoami /priv".to_string(), 2.5);
        malicious.insert("certutil -urlcache".to_string(), 3.8);
        malicious.insert("powershell -enc".to_string(), 3.5);
        malicious.insert("rundll32".to_string(), 2.0);
        malicious.insert("regsvr32 /s /u".to_string(), 3.5);
        malicious.insert("ransom".to_string(), 5.0);
        malicious.insert("encrypt".to_string(), 3.0);
        malicious.insert("t1003".to_string(), 4.0);
        malicious.insert("t1055".to_string(), 4.0);
        malicious.insert("t1486".to_string(), 5.5);
        malicious.insert("t1027".to_string(), 3.0);
        malicious.insert("t1059".to_string(), 2.5);
        malicious.insert("t1070".to_string(), 3.5);
        malicious.insert("t1547".to_string(), 3.2);

        let mut benign = HashMap::new();
        benign.insert("issigned: true".to_string(), 2.8);
        benign.insert("signed: true".to_string(), 2.8);
        benign.insert("invariants: nominal".to_string(), 2.0);
        benign.insert("rustc.exe".to_string(), 3.5);
        benign.insert("cargo.exe".to_string(), 3.5);
        benign.insert("git.exe".to_string(), 3.0);
        benign.insert("code.exe".to_string(), 2.5);
        benign.insert("svchost.exe".to_string(), 2.2);
        benign.insert("explorer.exe".to_string(), 2.2);
        benign.insert("msmpeng.exe".to_string(), 3.5);
        benign.insert("sysmon64.exe".to_string(), 4.0);
        benign.insert("osoosi.exe".to_string(), 4.5);

        let mut mitre = HashMap::new();
        mitre.insert("t1003".to_string(), 4.2);
        mitre.insert("t1003.001".to_string(), 4.5);
        mitre.insert("t1055".to_string(), 4.2);
        mitre.insert("t1055.012".to_string(), 4.5);
        mitre.insert("t1486".to_string(), 5.8);
        mitre.insert("t1014".to_string(), 4.8);
        mitre.insert("t1547".to_string(), 3.2);
        mitre.insert("t1059".to_string(), 2.5);

        Self {
            malicious_token_weights: malicious,
            benign_token_weights: benign,
            mitre_technique_weights: mitre,
            temperature: 1.0,
            label_smoothing_epsilon: 0.015,
        }
    }
}

/// Hermetic, sub-5ms local non-autoregressive Clef decision engine with RLCD feedback.
#[derive(Debug, Clone)]
pub struct LocalDecisionEngine {
    weights: LocalClefWeights,
    model_dir: PathBuf,
    rl_feedback_history: Arc<dashmap::DashMap<String, (f64, String)>>,
    rl_feedback_count: Arc<AtomicU64>,
    cumulative_rl_reward_fixed: Arc<AtomicI64>,
    logit_biases: Arc<dashmap::DashMap<String, f64>>,
    temperature_delta: Arc<AtomicI64>,
}

impl LocalDecisionEngine {
    pub fn new(model_dir: impl AsRef<Path>) -> Self {
        let dir = model_dir.as_ref().to_path_buf();
        let weights = Self::load_weights(&dir).unwrap_or_default();
        Self {
            weights,
            model_dir: dir,
            rl_feedback_history: Arc::new(dashmap::DashMap::new()),
            rl_feedback_count: Arc::new(AtomicU64::new(0)),
            cumulative_rl_reward_fixed: Arc::new(AtomicI64::new(0)),
            logit_biases: Arc::new(dashmap::DashMap::new()),
            temperature_delta: Arc::new(AtomicI64::new(0)),
        }
    }

    fn load_weights(dir: &Path) -> Option<LocalClefWeights> {
        let weights_file = dir.join("weights.json");
        if weights_file.exists() {
            if let Ok(content) = std::fs::read_to_string(&weights_file) {
                if let Ok(w) = serde_json::from_str::<LocalClefWeights>(&content) {
                    tracing::info!(
                        "[DECISION] Loaded custom local Clef weights from {:?}",
                        weights_file
                    );
                    return Some(w);
                }
            }
        }
        None
    }

    pub fn model_dir(&self) -> &Path {
        &self.model_dir
    }

    /// Record Reinforcement Learning for Calibrated Decisions (RLCD) feedback.
    /// Implements ordinal partial credit: adjacent choices receive partial credit,
    /// precision receives maximum reward, and distribution drift is penalized.
    pub fn record_rl_feedback(&self, decision_id: &str, reward: f64, actual_outcome: &str) {
        let actual_clean = actual_outcome.trim().to_lowercase();
        let prev_outcome = self.rl_feedback_history.get(decision_id).map(|entry| entry.value().1.clone());

        let verdict_order = ["benign", "suspicious", "malicious", "critical_emergency"];
        let action_order = ["allow", "alert", "tarpit", "ghost_tarpit", "isolate", "defer_to_operator"];

        let multiplier = if let Some(ref prev) = prev_outcome {
            let prev_clean = prev.to_lowercase();
            if prev_clean == actual_clean {
                1.0 // Maximum precision reward
            } else if let (Some(p_idx), Some(a_idx)) = (
                verdict_order.iter().position(|&v| v == prev_clean),
                verdict_order.iter().position(|&v| v == actual_clean),
            ) {
                let dist = (p_idx as isize - a_idx as isize).abs();
                match dist {
                    1 => 0.5,  // Adjacent verdict partial credit
                    2 => 0.1,  // Distant verdict minimal credit
                    _ => -1.0, // Catastrophic verdict inversion penalty
                }
            } else if let (Some(p_idx), Some(a_idx)) = (
                action_order.iter().position(|&a| a == prev_clean),
                action_order.iter().position(|&a| a == actual_clean),
            ) {
                let dist = (p_idx as isize - a_idx as isize).abs();
                match dist {
                    1 => 0.5,
                    2 => 0.1,
                    _ => -0.8,
                }
            } else {
                0.2
            }
        } else {
            1.0
        };

        let effective_reward = if reward >= 0.0 {
            reward * multiplier
        } else {
            -reward.abs() * multiplier.abs().max(0.5)
        };

        // Distribution drift penalization: adjust temperature based on reinforcement outcome
        if effective_reward < 0.0 {
            // Increase temperature to widen entropy (penalize distribution drift)
            self.temperature_delta.fetch_add(15, Ordering::Relaxed);
        } else if effective_reward > 0.0 {
            // Reinforce confidence (sharpen calibration)
            self.temperature_delta.fetch_sub(5, Ordering::Relaxed);
        }

        // Calibrate logit bias for actual outcome
        let mut entry = self.logit_biases.entry(actual_clean.clone()).or_insert(0.0);
        *entry = (*entry + effective_reward * 0.15).clamp(-5.0, 5.0);

        // Bound feedback history cache to prevent memory leak
        if self.rl_feedback_history.len() > 10_000 {
            self.rl_feedback_history.clear();
        }
        self.rl_feedback_history.insert(decision_id.to_string(), (effective_reward, actual_clean));
        self.rl_feedback_count.fetch_add(1, Ordering::Relaxed);
        let fixed_reward = (effective_reward * 1000.0) as i64;
        self.cumulative_rl_reward_fixed.fetch_add(fixed_reward, Ordering::Relaxed);

        tracing::info!(
            "[DECISION-RLCD] Recorded feedback for {}: reward={:.2}, effective={:.2}, outcome='{}'",
            decision_id, reward, effective_reward, actual_outcome
        );
    }

    pub fn rl_feedback_count(&self) -> u64 {
        self.rl_feedback_count.load(Ordering::Relaxed)
    }

    pub fn cumulative_rl_reward(&self) -> f64 {
        self.cumulative_rl_reward_fixed.load(Ordering::Relaxed) as f64 / 1000.0
    }

    /// Primary evaluation method matching the non-autoregressive schema.
    pub fn evaluate(&self, request: &DecisionRequest) -> Result<DecisionResponse> {
        let start = Instant::now();
        let state_lower = request.state.to_lowercase();

        // 1. Compute composite feature evidence
        let mut mal_score = 0.0f64;
        for (token, &weight) in &self.weights.malicious_token_weights {
            if state_lower.contains(token) {
                mal_score += weight;
            }
        }

        let mut ben_score = 0.0f64;
        for (token, &weight) in &self.weights.benign_token_weights {
            if state_lower.contains(token) {
                ben_score += weight;
            }
        }

        let mut mitre_boost = 0.0f64;
        for (tech, &weight) in &self.weights.mitre_technique_weights {
            if state_lower.contains(tech) {
                mitre_boost = mitre_boost.max(weight);
            }
        }
        mal_score += mitre_boost;

        let is_unsigned = state_lower.contains("issigned: false") || state_lower.contains("signed: false");
        let is_signed = state_lower.contains("issigned: true") || state_lower.contains("signed: true");

        if is_unsigned {
            mal_score += 1.5;
        }
        if is_signed {
            ben_score += 2.0;
        }

        let mut answers = HashMap::new();

        // 2. Answer each requested question
        for (q_name, q_def) in &request.questions {
            match q_def.question_type {
                QuestionType::Choice => {
                    let ans = self.evaluate_choice(q_name, q_def, mal_score, ben_score, &state_lower);
                    answers.insert(q_name.clone(), DecisionAnswer::from_choice(ans));
                }
                QuestionType::Bool => {
                    let ans = self.evaluate_bool(q_name, mal_score, ben_score, &state_lower);
                    answers.insert(q_name.clone(), DecisionAnswer::from_bool(ans));
                }
                QuestionType::Score => {
                    let ans = self.evaluate_score(q_name, q_def, mal_score, ben_score);
                    answers.insert(q_name.clone(), DecisionAnswer::from_score(ans));
                }
            }
        }

        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        Ok(DecisionResponse {
            answers,
            latency_ms,
            provider: "local_clef_engine".to_string(),
        })
    }

    fn evaluate_choice(
        &self,
        q_name: &str,
        q_def: &QuestionDefinition,
        mal_score: f64,
        ben_score: f64,
        state_lower: &str,
    ) -> ChoiceAnswer {
        let is_destructive = state_lower.contains("delete shadows")
            || (state_lower.contains("vssadmin") && state_lower.contains("delete"))
            || (state_lower.contains("wbadmin") && state_lower.contains("delete"))
            || state_lower.contains("ransom")
            || state_lower.contains("t1486")
            || state_lower.contains("recoveryenabled no");

        let classes: Vec<String> = if let Some(serde_json::Value::Object(map)) = &q_def.criteria {
            map.keys().cloned().collect()
        } else if q_name == "verdict" {
            vec![
                "benign".to_string(),
                "suspicious".to_string(),
                "malicious".to_string(),
                "critical_emergency".to_string(),
            ]
        } else if q_name == "containment_action" {
            vec![
                "allow".to_string(),
                "alert".to_string(),
                "tarpit".to_string(),
                "ghost_tarpit".to_string(),
                "isolate".to_string(),
                "defer_to_operator".to_string(),
            ]
        } else {
            vec!["option_a".to_string(), "option_b".to_string()]
        };

        let mut logits: Vec<f64> = Vec::with_capacity(classes.len());

        if q_name == "verdict" {
            for c in &classes {
                let logit = match c.as_str() {
                    "benign" => {
                        if mal_score > 3.0 {
                            -mal_score
                        } else {
                            ben_score + 1.0
                        }
                    }
                    "suspicious" => {
                        if mal_score > 6.0 {
                            0.5
                        } else if mal_score > 1.5 {
                            mal_score * 0.8
                        } else {
                            0.0
                        }
                    }
                    "malicious" => {
                        if is_destructive {
                            mal_score * 0.7
                        } else if mal_score > 2.5 {
                            mal_score * 1.4 - ben_score * 0.5
                        } else {
                            -1.0
                        }
                    }
                    "critical_emergency" => {
                        if is_destructive && mal_score > 4.0 {
                            mal_score * 1.8
                        } else if mal_score > 7.0 {
                            mal_score * 1.1
                        } else {
                            -4.0
                        }
                    }
                    _ => 0.0,
                };
                let bias = self.logit_biases.get(c.as_str()).map(|v| *v).unwrap_or(0.0);
                logits.push(logit + bias);
            }
        } else if q_name == "containment_action" {
            for c in &classes {
                let logit = match c.as_str() {
                    "allow" => {
                        if mal_score > 2.0 {
                            -mal_score * 2.0
                        } else {
                            ben_score * 1.5 + 1.0
                        }
                    }
                    "alert" => {
                        if mal_score > 5.0 {
                            -0.5
                        } else if mal_score > 1.0 {
                            1.5

                        } else {
                            0.5
                        }
                    }
                    "tarpit" => {
                        if is_destructive {
                            0.5
                        } else if mal_score > 2.5 && mal_score <= 5.5 {
                            mal_score * 1.2
                        } else {
                            0.0
                        }
                    }
                    "ghost_tarpit" => {
                        if state_lower.contains("deception") || state_lower.contains("recon") {
                            3.5
                        } else if mal_score > 3.0 && !is_destructive {
                            mal_score * 0.9
                        } else {
                            -0.5
                        }
                    }
                    "isolate" => {
                        if is_destructive {
                            mal_score * 2.0
                        } else if mal_score > 4.0 {
                            mal_score * 1.5
                        } else {
                            -2.0
                        }
                    }
                    "defer_to_operator" => {
                        if (mal_score - ben_score).abs() < 1.0 && mal_score > 1.5 {
                            2.5
                        } else {
                            -1.5
                        }
                    }
                    _ => 0.0,
                };
                let bias = self.logit_biases.get(c.as_str()).map(|v| *v).unwrap_or(0.0);
                logits.push(logit + bias);
            }
        } else {
            logits = vec![0.0; classes.len()];
        }

        let probabilities = self.softmax_with_smoothing(&classes, &logits);
        let best_class = probabilities
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(k, _)| k.clone())
            .unwrap_or_else(|| classes[0].clone());

        ChoiceAnswer {
            value: best_class,
            probabilities,
        }
    }

    fn evaluate_bool(
        &self,
        q_name: &str,
        mal_score: f64,
        ben_score: f64,
        state_lower: &str,
    ) -> BoolAnswer {
        let prob: f64 = if q_name == "human_escalation" {
            if state_lower.contains("defer") || (mal_score > 2.0 && mal_score < 4.0 && ben_score > 1.5) {
                0.85
            } else if mal_score >= 6.0 {
                // High confidence automated attack containment does not stall for human
                0.08
            } else {
                0.15
            }
        } else if q_name == "deep_reasoning_required" {
            if mal_score > 3.0 || state_lower.contains("t1055") || state_lower.contains("t1003") {
                0.88
            } else if mal_score > 1.0 {
                0.45
            } else {
                0.05
            }
        } else {
            0.5
        };

        // Calibrate Brier clamp
        let calibrated_prob = prob.clamp(0.01, 0.99);
        let value = calibrated_prob >= 0.50;

        BoolAnswer {
            value,
            probability: calibrated_prob,
        }
    }

    fn evaluate_score(
        &self,
        _q_name: &str,
        q_def: &QuestionDefinition,
        mal_score: f64,
        _ben_score: f64,
    ) -> ScoreAnswer {
        let levels = q_def
            .score_levels
            .clone()
            .unwrap_or_else(|| vec![
                "None".to_string(),
                "Low".to_string(),
                "Medium".to_string(),
                "High".to_string(),
                "Critical".to_string(),
            ]);

        let mut logits = Vec::with_capacity(levels.len());
        for lvl in &levels {
            let logit = match lvl.as_str() {
                "None" => {
                    if mal_score < 1.0 {
                        3.0
                    } else {
                        -mal_score
                    }
                }
                "Low" => {
                    if mal_score >= 1.0 && mal_score < 2.5 {
                        2.5
                    } else {
                        0.0
                    }
                }
                "Medium" => {
                    if mal_score >= 2.5 && mal_score < 4.5 {
                        3.0
                    } else {
                        0.5
                    }
                }
                "High" => {
                    if mal_score >= 4.5 && mal_score < 7.0 {
                        4.0
                    } else {
                        1.0
                    }
                }
                "Critical" => {
                    if mal_score >= 7.0 {
                        5.5
                    } else if mal_score >= 5.0 {
                        2.5
                    } else {
                        -2.0
                    }
                }
                _ => 0.0,
            };
            logits.push(logit);
        }

        let probabilities = self.softmax_with_smoothing(&levels, &logits);
        let best_level = probabilities
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(k, _)| k.clone())
            .unwrap_or_else(|| levels[0].clone());

        ScoreAnswer {
            value: best_level,
            probabilities,
        }
    }

    /// Softmax with label smoothing and strict sum-to-1 normalization.
    fn softmax_with_smoothing(&self, classes: &[String], logits: &[f64]) -> HashMap<String, f64> {
        let k = classes.len() as f64;
        let temp_offset = self.temperature_delta.load(Ordering::Relaxed) as f64 / 1000.0;
        let t = (self.weights.temperature + temp_offset).clamp(0.2, 2.5);
        let eps = self.weights.label_smoothing_epsilon;

        let max_logit = logits.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let exp_sum: f64 = logits.iter().map(|&z| ((z - max_logit) / t).exp()).sum();

        let mut raw_probs: Vec<f64> = logits
            .iter()
            .map(|&z| {
                let p = ((z - max_logit) / t).exp() / exp_sum;
                // Label smoothing: (1 - eps) * p + (eps / k)
                (1.0 - eps) * p + (eps / k)
            })
            .collect();

        // Exact normalization so sum == 1.0
        let total_p: f64 = raw_probs.iter().sum();
        for p in &mut raw_probs {
            *p /= total_p;
        }

        let mut res = HashMap::new();
        for (class_name, prob) in classes.iter().zip(raw_probs) {
            res.insert(class_name.clone(), prob);
        }
        res
    }
}
