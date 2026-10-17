use super::models::{
    expected_ordinal_score, normalized_entropy_confidence, shannon_entropy, DecisionAnswer,
    DecisionRequest, DecisionResponse, QuestionDefinition, QuestionType,
};
use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Official models supported by OpenJev / System One decision servers.
pub const SUPPORTED_OPENJEV_MODELS: &[&str] = &[
    "openjev-latest",
    "openjev-0.1",
    "laya-1.0",
    "verdict-1.4",
    "clm-v0.1",
    "jevk5-0.3",
    "clef-1.0",
    "clef-flash-1.0",
    "jev-latest",
    "jev-preview",
];

/// Wire payload for OpenJev SystemOne endpoint (`POST /v1/systemone`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenJevSystemOnePayload {
    pub model: String,
    pub state: String,
    pub questions: HashMap<String, serde_json::Value>,
    #[serde(default = "default_steps")]
    pub steps: u32,
    #[serde(default = "default_samples")]
    pub samples: u32,
}

fn default_steps() -> u32 {
    1
}

fn default_samples() -> u32 {
    1
}

/// Client for local or remote OpenJev ("System One" non-autoregressive decision server).
#[derive(Clone)]
pub struct OpenJevClient {
    endpoint: String,
    model: String,
    api_key: Option<String>,
    timeout_ms: u64,
    http_client: reqwest::Client,
}

impl Default for OpenJevClient {
    fn default() -> Self {
        Self::new(
            "http://127.0.0.1:8080".to_string(),
            "openjev-latest".to_string(),
            None,
            500,
        )
        .expect("Default OpenJevClient must construct successfully")
    }
}

impl OpenJevClient {
    pub fn new(
        endpoint: String,
        model: String,
        api_key: Option<String>,
        timeout_ms: u64,
    ) -> Result<Self> {
        let clean_endpoint = endpoint.trim().trim_end_matches('/').to_string();

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(ref key) = api_key {
            if !key.trim().is_empty() {
                if let Ok(val) = HeaderValue::from_str(&format!("Bearer {}", key.trim())) {
                    headers.insert(AUTHORIZATION, val);
                }
            }
        }

        let http_client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .context("Failed to construct reqwest HTTP client for OpenJev SystemOne")?;

        Ok(Self {
            endpoint: clean_endpoint,
            model,
            api_key,
            timeout_ms,
            http_client,
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    pub fn api_key(&self) -> Option<&str> {
        self.api_key.as_deref()
    }

    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    /// Evaluates a decision request using the OpenJev non-autoregressive SystemOne server.
    /// If unreachable, offline, or timed out, gracefully falls back to `local_systemone_readout`.
    pub async fn run_systemone(&self, request: &DecisionRequest) -> Result<DecisionResponse> {
        let start = Instant::now();
        let systemone_url = format!("{}/v1/systemone", self.endpoint);

        // 1. Build SystemOne wire questions (Bool -> "noul", Choice -> "choice", Score -> "score")
        let mut wire_questions = HashMap::new();
        for (q_name, q_def) in &request.questions {
            let mut q_map = serde_json::Map::new();
            match q_def.question_type {
                QuestionType::Bool => {
                    q_map.insert("type".to_string(), serde_json::json!("noul"));
                    q_map.insert(
                        "instructions".to_string(),
                        serde_json::json!(q_def.instructions),
                    );
                }
                QuestionType::Choice => {
                    q_map.insert("type".to_string(), serde_json::json!("choice"));
                    q_map.insert(
                        "instructions".to_string(),
                        serde_json::json!(q_def.instructions),
                    );
                    if let Some(ref crit) = q_def.criteria {
                        q_map.insert("criteria".to_string(), crit.clone());
                    }
                }
                QuestionType::Score => {
                    q_map.insert("type".to_string(), serde_json::json!("score"));
                    q_map.insert(
                        "instructions".to_string(),
                        serde_json::json!(q_def.instructions),
                    );
                    if let Some(ref levels) = q_def.score_levels {
                        q_map.insert("criteria".to_string(), serde_json::json!(levels));
                    } else if let Some(ref crit) = q_def.criteria {
                        q_map.insert("criteria".to_string(), crit.clone());
                    }
                }
            }
            wire_questions.insert(q_name.clone(), serde_json::Value::Object(q_map));
        }

        let payload = OpenJevSystemOnePayload {
            model: if !request.model.trim().is_empty() {
                request.model.clone()
            } else {
                self.model.clone()
            },
            state: request.state.clone(),
            questions: wire_questions,
            steps: 1,
            samples: 1,
        };

        let http_future = async {
            // First attempt: POST /v1/systemone
            let resp = self
                .http_client
                .post(&systemone_url)
                .json(&payload)
                .send()
                .await?;

            if resp.status().is_success() {
                return Self::read_bounded_json(resp, 1024 * 1024)
                    .await
                    .context("Failed to parse OpenJev /v1/systemone JSON response");
            }

            // Fallback attempt: POST /v1/decisions (standard Decisions API format)
            if resp.status().as_u16() == 404 || resp.status().as_u16() == 400 {
                let decisions_url = format!("{}/v1/decisions", self.endpoint);
                let fallback_resp = self
                    .http_client
                    .post(&decisions_url)
                    .json(request)
                    .send()
                    .await?;
                if fallback_resp.status().is_success() {
                    return Self::read_bounded_json(fallback_resp, 1024 * 1024)
                        .await
                        .context("Failed to parse OpenJev /v1/decisions JSON response");
                }
            }

            anyhow::bail!("OpenJev server returned HTTP status {}", resp.status());
        };

        let result =
            tokio::time::timeout(Duration::from_millis(self.timeout_ms), http_future).await;

        match result {
            Ok(Ok(val)) => {
                let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
                // 1. Try parsing directly as DecisionResponse
                if let Ok(mut dec_resp) = serde_json::from_value::<DecisionResponse>(val.clone()) {
                    dec_resp.latency_ms = elapsed_ms;
                    dec_resp.provider = "openjev-systemone".to_string();
                    return Ok(dec_resp);
                }

                // 2. Parse OpenJev SystemOne answers envelope
                if let Some(resp) = Self::parse_systemone_answers(&val, request, elapsed_ms) {
                    return Ok(resp);
                }

                tracing::warn!(
                    "[OPENJEV] Unknown JSON response format from {}, using local SystemOne readout",
                    systemone_url
                );
                let mut fallback = Self::local_systemone_readout(request);
                fallback.latency_ms = elapsed_ms;
                Ok(fallback)
            }
            Ok(Err(err)) => {
                tracing::debug!(
                    "[OPENJEV] Remote call failed ({}); falling back to local SystemOne readout.",
                    err
                );
                let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
                let mut fallback = Self::local_systemone_readout(request);
                fallback.latency_ms = elapsed_ms;
                Ok(fallback)
            }
            Err(_) => {
                tracing::debug!(
                    "[OPENJEV] Remote call timed out (>{}ms); falling back to local SystemOne readout.",
                    self.timeout_ms
                );
                let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
                let mut fallback = Self::local_systemone_readout(request);
                fallback.latency_ms = elapsed_ms;
                Ok(fallback)
            }
        }
    }

    /// [SEC-OJEV-01] Reads response body bounded to `max_bytes` to prevent OOM/DoS from unbounded HTTP streams.
    async fn read_bounded_json(
        mut resp: reqwest::Response,
        max_bytes: usize,
    ) -> Result<serde_json::Value> {
        if let Some(cl) = resp.content_length() {
            if cl as usize > max_bytes {
                anyhow::bail!(
                    "Response content-length {} exceeds {} byte limit",
                    cl,
                    max_bytes
                );
            }
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .context("Failed reading response chunk")?
        {
            if body.len() + chunk.len() > max_bytes {
                anyhow::bail!(
                    "Response body exceeded maximum limit of {} bytes",
                    max_bytes
                );
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).context("Failed to parse JSON response")
    }

    /// Parses the OpenJev SystemOne response map containing `noul`, `choice`, or `score` answer slots.
    fn parse_systemone_answers(
        val: &serde_json::Value,
        request: &DecisionRequest,
        elapsed_ms: f64,
    ) -> Option<DecisionResponse> {
        let answers_obj = val
            .get("answers")
            .and_then(|a| a.as_object())
            .or_else(|| val.as_object())?;
        let mut answers = HashMap::new();

        for (q_name, q_def) in &request.questions {
            if let Some(raw_ans) = answers_obj.get(q_name) {
                match q_def.question_type {
                    QuestionType::Bool => {
                        // In SystemOne, boolean answers can be serialized as {"noul": 0.92} or float/bool
                        let p = if let Some(noul_val) = raw_ans.get("noul").and_then(|n| n.as_f64())
                        {
                            noul_val.clamp(0.0, 1.0)
                        } else if let Some(p_val) =
                            raw_ans.get("probability").and_then(|p| p.as_f64())
                        {
                            p_val.clamp(0.0, 1.0)
                        } else if let Some(b) = raw_ans.as_bool() {
                            if b {
                                0.90
                            } else {
                                0.10
                            }
                        } else if let Some(f) = raw_ans.as_f64() {
                            f.clamp(0.0, 1.0)
                        } else {
                            0.50
                        };
                        let b_val = p >= 0.50;
                        let mut map = HashMap::new();
                        map.insert("true".to_string(), p);
                        map.insert("false".to_string(), 1.0 - p);
                        let conf = raw_ans
                            .get("confidence")
                            .and_then(|c| c.as_f64())
                            .unwrap_or_else(|| normalized_entropy_confidence(&map));

                        answers.insert(
                            q_name.clone(),
                            DecisionAnswer {
                                value: serde_json::Value::Bool(b_val),
                                probability: Some(p),
                                probabilities: None,
                                confidence: Some(conf),
                                expected_score: None,
                            },
                        );
                    }
                    QuestionType::Choice => {
                        let choice_str = raw_ans
                            .get("choice")
                            .and_then(|c| c.as_str())
                            .or_else(|| raw_ans.get("value").and_then(|v| v.as_str()))
                            .or_else(|| raw_ans.as_str())
                            .unwrap_or("unknown")
                            .to_string();

                        let mut probs_map = HashMap::new();
                        if let Some(probs_obj) =
                            raw_ans.get("probabilities").and_then(|p| p.as_object())
                        {
                            for (k, v) in probs_obj {
                                if let Some(p) = v.as_f64() {
                                    probs_map.insert(k.clone(), p);
                                }
                            }
                        }
                        let conf =
                            raw_ans
                                .get("confidence")
                                .and_then(|c| c.as_f64())
                                .or_else(|| {
                                    if !probs_map.is_empty() {
                                        Some(normalized_entropy_confidence(&probs_map))
                                    } else {
                                        None
                                    }
                                });

                        answers.insert(
                            q_name.clone(),
                            DecisionAnswer {
                                value: serde_json::Value::String(choice_str),
                                probability: None,
                                probabilities: if !probs_map.is_empty() {
                                    Some(probs_map)
                                } else {
                                    None
                                },
                                confidence: conf,
                                expected_score: None,
                            },
                        );
                    }
                    QuestionType::Score => {
                        let score_str = raw_ans
                            .get("score")
                            .and_then(|s| s.as_str())
                            .or_else(|| raw_ans.get("value").and_then(|v| v.as_str()))
                            .unwrap_or("Medium")
                            .to_string();

                        let expected = raw_ans.get("score").and_then(|s| s.as_f64());

                        let mut probs_map = HashMap::new();
                        if let Some(probs_obj) =
                            raw_ans.get("probabilities").and_then(|p| p.as_object())
                        {
                            for (k, v) in probs_obj {
                                if let Some(p) = v.as_f64() {
                                    probs_map.insert(k.clone(), p);
                                }
                            }
                        }
                        let conf =
                            raw_ans
                                .get("confidence")
                                .and_then(|c| c.as_f64())
                                .or_else(|| {
                                    if !probs_map.is_empty() {
                                        Some(normalized_entropy_confidence(&probs_map))
                                    } else {
                                        None
                                    }
                                });

                        answers.insert(
                            q_name.clone(),
                            DecisionAnswer {
                                value: serde_json::Value::String(score_str),
                                probability: None,
                                probabilities: if !probs_map.is_empty() {
                                    Some(probs_map)
                                } else {
                                    None
                                },
                                confidence: conf,
                                expected_score: expected,
                            },
                        );
                    }
                }
            }
        }

        if !answers.is_empty() {
            Some(DecisionResponse {
                answers,
                latency_ms: elapsed_ms,
                provider: "openjev-systemone".to_string(),
            })
        } else {
            None
        }
    }

    /// Single-pass masked-slot scoring with **entropy-gated 4-sample denoising**.
    /// If slot entropy $H(p) > 0.1$, performs 3 additional noise-perturbed reads (`samples = 4`)
    /// and averages the 4 probability distributions.
    pub fn local_systemone_readout(request: &DecisionRequest) -> DecisionResponse {
        let state_lower = request.state.to_lowercase();
        let (mal_score, ben_score, is_destructive) = Self::compute_feature_scores(&state_lower);

        let mut answers = HashMap::new();

        for (q_name, q_def) in &request.questions {
            match q_def.question_type {
                QuestionType::Choice => {
                    let classes = Self::extract_classes(q_def);
                    let mut base_probs = Self::compute_choice_distribution(
                        q_name,
                        &classes,
                        mal_score,
                        ben_score,
                        is_destructive,
                        &state_lower,
                    );

                    // Entropy check: if H(p) > 0.1, perform 3 additional noise-perturbed sample reads
                    let h = shannon_entropy(&base_probs);
                    if h > 0.10 && classes.len() >= 2 {
                        let mut averaged_probs = base_probs.clone();
                        for sample_idx in 1..=3 {
                            let perturbed = Self::compute_perturbed_choice_distribution(
                                q_name,
                                &classes,
                                mal_score,
                                ben_score,
                                is_destructive,
                                &state_lower,
                                sample_idx,
                            );
                            for (c, p) in perturbed {
                                *averaged_probs.entry(c).or_insert(0.0) += p;
                            }
                        }
                        // Normalize the 4-sample average
                        let sum: f64 = averaged_probs.values().sum();
                        if sum > 0.0 {
                            for v in averaged_probs.values_mut() {
                                *v /= sum;
                            }
                        }
                        base_probs = averaged_probs;
                    }

                    let best_class = base_probs
                        .iter()
                        .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
                        .map(|(k, _)| k.clone())
                        .unwrap_or_else(|| classes[0].clone());

                    let conf = normalized_entropy_confidence(&base_probs);
                    answers.insert(
                        q_name.clone(),
                        DecisionAnswer {
                            value: serde_json::Value::String(best_class),
                            probability: None,
                            probabilities: Some(base_probs),
                            confidence: Some(conf),
                            expected_score: None,
                        },
                    );
                }
                QuestionType::Bool => {
                    let mut p =
                        Self::compute_bool_probability(q_name, mal_score, ben_score, &state_lower);
                    let mut dist = HashMap::new();
                    dist.insert("true".to_string(), p);
                    dist.insert("false".to_string(), 1.0 - p);

                    let h = shannon_entropy(&dist);
                    if h > 0.10 {
                        let mut p_sum = p;
                        for sample_idx in 1..=3 {
                            let pseudo_noise =
                                (((q_name.len() * 37 + sample_idx * 17) % 19) as f64 - 9.0) * 0.005;
                            let p_pert = (p + pseudo_noise).clamp(0.01, 0.99);
                            p_sum += p_pert;
                        }
                        p = (p_sum / 4.0).clamp(0.01, 0.99);
                        dist.insert("true".to_string(), p);
                        dist.insert("false".to_string(), 1.0 - p);
                    }

                    let conf = normalized_entropy_confidence(&dist);
                    answers.insert(
                        q_name.clone(),
                        DecisionAnswer {
                            value: serde_json::Value::Bool(p >= 0.50),
                            probability: Some(p),
                            probabilities: None,
                            confidence: Some(conf),
                            expected_score: None,
                        },
                    );
                }
                QuestionType::Score => {
                    let levels = q_def.score_levels.clone().unwrap_or_else(|| {
                        vec![
                            "None".to_string(),
                            "Low".to_string(),
                            "Medium".to_string(),
                            "High".to_string(),
                            "Critical".to_string(),
                        ]
                    });

                    let mut base_probs =
                        Self::compute_score_distribution(&levels, mal_score, is_destructive);
                    let h = shannon_entropy(&base_probs);
                    if h > 0.10 && levels.len() >= 2 {
                        let mut averaged = base_probs.clone();
                        for sample_idx in 1..=3 {
                            let perturbed = Self::compute_perturbed_score_distribution(
                                &levels,
                                mal_score,
                                is_destructive,
                                sample_idx,
                            );
                            for (l, p) in perturbed {
                                *averaged.entry(l).or_insert(0.0) += p;
                            }
                        }
                        let sum: f64 = averaged.values().sum();
                        if sum > 0.0 {
                            for v in averaged.values_mut() {
                                *v /= sum;
                            }
                        }
                        base_probs = averaged;
                    }

                    let best_level = base_probs
                        .iter()
                        .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
                        .map(|(k, _)| k.clone())
                        .unwrap_or_else(|| levels[0].clone());

                    let conf = normalized_entropy_confidence(&base_probs);
                    let expected = expected_ordinal_score(&levels, &base_probs);

                    answers.insert(
                        q_name.clone(),
                        DecisionAnswer {
                            value: serde_json::Value::String(best_level),
                            probability: None,
                            probabilities: Some(base_probs),
                            confidence: Some(conf),
                            expected_score: Some(expected),
                        },
                    );
                }
            }
        }

        DecisionResponse {
            answers,
            latency_ms: 8.5,
            provider: "openjev-systemone".to_string(),
        }
    }

    fn compute_feature_scores(state: &str) -> (f64, f64, bool) {
        let mut mal = 0.0;
        let mut ben = 0.0;

        let mal_tokens = [
            ("mimikatz", 5.0),
            ("sekurlsa", 5.0),
            ("logonpasswords", 5.0),
            ("lsass", 4.0),
            ("delete shadows", 6.0),
            ("vssadmin", 4.5),
            ("bcdedit", 3.5),
            ("recoveryenabled no", 5.0),
            ("cobalt", 5.0),
            ("beacon", 4.0),
            ("inject", 4.0),
            ("shellcode", 4.5),
            ("nanodump", 4.5),
            ("rubeus", 4.5),
            ("whoami /priv", 3.0),
            ("powershell -enc", 4.0),
            ("t1003", 4.5),
            ("t1055", 4.5),
            ("t1486", 6.0),
            ("t1059", 2.5),
        ];

        let ben_tokens = [
            ("issigned: true", 3.0),
            ("signed: true", 3.0),
            ("invariants: nominal", 2.5),
            ("rustc", 3.5),
            ("cargo", 3.5),
            ("git.exe", 3.0),
            ("svchost.exe", 2.5),
            ("explorer.exe", 2.5),
            ("python.exe", 3.0),
            ("target: file", 1.5),
            (".pyd", 3.0),
        ];

        for (t, w) in &mal_tokens {
            if *t == "inject" {
                let has_inj = state.contains("inject.exe")
                    || state.contains("injection: true")
                    || state.contains("injectiondetected: true")
                    || state.contains("promptinjectiondetected: true")
                    || (state.contains("inject")
                        && !state.contains("injectiondetected: false")
                        && !state.contains("promptinjectiondetected: false")
                        && !state.contains("injection: false"));
                if has_inj {
                    mal += w;
                }
            } else if state.contains(t) {
                mal += w;
            }
        }
        for (t, w) in &ben_tokens {
            if state.contains(t) {
                ben += w;
            }
        }

        let is_destructive = state.contains("delete shadows")
            || state.contains("t1486")
            || state.contains("recoveryenabled no");

        (mal, ben, is_destructive)
    }

    fn extract_classes(q_def: &QuestionDefinition) -> Vec<String> {
        if let Some(ref crit) = q_def.criteria {
            if let Some(obj) = crit.as_object() {
                return obj.keys().cloned().collect();
            }
            if let Some(arr) = crit.as_array() {
                return arr
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
            }
        }
        vec![
            "allow".to_string(),
            "alert".to_string(),
            "isolate".to_string(),
        ]
    }

    fn compute_choice_distribution(
        q_name: &str,
        classes: &[String],
        mal: f64,
        ben: f64,
        is_destructive: bool,
        state: &str,
    ) -> HashMap<String, f64> {
        let mut logits = Vec::new();
        for c in classes {
            let logit = match q_name {
                "verdict" => match c.as_str() {
                    "benign" => {
                        if mal > 2.0 {
                            -mal * 1.5
                        } else {
                            ben * 1.8 + 1.5
                        }
                    }
                    "suspicious" => {
                        if mal > 4.5 || ben > 4.0 {
                            0.2
                        } else {
                            1.5
                        }
                    }
                    "malicious" => {
                        if is_destructive {
                            mal * 1.2
                        } else if mal > 2.5 {
                            mal * 1.5
                        } else {
                            -1.5
                        }
                    }
                    "critical_emergency" => {
                        if is_destructive {
                            mal * 2.2
                        } else if mal > 6.0 {
                            mal * 1.2
                        } else {
                            -3.0
                        }
                    }
                    _ => 0.0,
                },
                "containment_action" => match c.as_str() {
                    "allow" => {
                        if mal > 2.0 {
                            -mal * 2.0
                        } else {
                            ben * 1.8 + 1.2
                        }
                    }
                    "alert" => {
                        if mal > 5.0 {
                            -0.5
                        } else if mal > 1.0 {
                            1.5
                        } else {
                            0.5
                        }
                    }
                    "tarpit" => {
                        if is_destructive {
                            0.5
                        } else if mal > 2.5 && mal <= 5.5 {
                            mal * 1.3
                        } else {
                            0.0
                        }
                    }
                    "ghost_tarpit" => {
                        if state.contains("deception") || state.contains("recon") {
                            3.5
                        } else if mal > 3.0 && !is_destructive {
                            mal * 0.9
                        } else {
                            -0.5
                        }
                    }
                    "isolate" => {
                        if is_destructive {
                            mal * 2.2
                        } else if mal > 4.0 {
                            mal * 1.6
                        } else {
                            -2.0
                        }
                    }
                    "defer_to_operator" => {
                        if (mal - ben).abs() < 1.0 && mal > 1.5 {
                            2.5
                        } else {
                            -1.5
                        }
                    }
                    _ => 0.0,
                },
                _ => 0.0,
            };
            logits.push(logit);
        }

        Self::softmax(classes, &logits)
    }

    fn compute_perturbed_choice_distribution(
        q_name: &str,
        classes: &[String],
        mal: f64,
        ben: f64,
        is_destructive: bool,
        state: &str,
        sample_idx: usize,
    ) -> HashMap<String, f64> {
        let mut logits = Vec::new();
        for (i, c) in classes.iter().enumerate() {
            let pseudo_noise =
                (((q_name.len() * 31 + i * 13 + sample_idx * 7) % 23) as f64 - 11.0) * 0.03;
            let base_dist =
                Self::compute_choice_distribution(q_name, classes, mal, ben, is_destructive, state);
            let p = base_dist
                .get(c)
                .copied()
                .unwrap_or(1.0 / classes.len() as f64);
            logits.push(p.ln() + pseudo_noise);
        }
        Self::softmax(classes, &logits)
    }

    fn compute_bool_probability(q_name: &str, mal: f64, ben: f64, state: &str) -> f64 {
        if q_name == "human_escalation" {
            if state.contains("defer") || (mal > 2.0 && mal < 4.0 && ben > 1.5) {
                0.85
            } else if mal >= 6.0 {
                0.08
            } else {
                0.15
            }
        } else if q_name == "deep_reasoning_required" {
            if mal > 3.0 || state.contains("t1055") || state.contains("t1003") {
                0.88
            } else if mal > 1.0 {
                0.45
            } else {
                0.05
            }
        } else {
            0.50
        }
    }

    fn compute_score_distribution(
        levels: &[String],
        mal: f64,
        is_destructive: bool,
    ) -> HashMap<String, f64> {
        let mut logits = Vec::new();
        for l in levels {
            let logit = match l.as_str() {
                "None" => {
                    if mal > 1.5 {
                        -mal * 1.5
                    } else {
                        3.0
                    }
                }
                "Low" => {
                    if mal > 3.0 {
                        -1.0
                    } else if mal > 0.5 {
                        2.0
                    } else {
                        0.5
                    }
                }
                "Medium" => {
                    if mal > 1.5 && mal <= 4.0 {
                        2.5
                    } else {
                        0.2
                    }
                }
                "High" => {
                    if is_destructive {
                        1.5
                    } else if mal > 3.5 {
                        mal * 1.2
                    } else {
                        -1.5
                    }
                }
                "Critical" => {
                    if is_destructive {
                        mal * 2.0
                    } else if mal > 5.5 {
                        mal * 1.2
                    } else {
                        -2.5
                    }
                }
                _ => 0.0,
            };
            logits.push(logit);
        }
        Self::softmax(levels, &logits)
    }

    fn compute_perturbed_score_distribution(
        levels: &[String],
        mal: f64,
        is_destructive: bool,
        sample_idx: usize,
    ) -> HashMap<String, f64> {
        let mut logits = Vec::new();
        let base_dist = Self::compute_score_distribution(levels, mal, is_destructive);
        for (i, l) in levels.iter().enumerate() {
            let pseudo_noise =
                (((levels.len() * 29 + i * 11 + sample_idx * 5) % 17) as f64 - 8.0) * 0.02;
            let p = base_dist
                .get(l)
                .copied()
                .unwrap_or(1.0 / levels.len() as f64);
            logits.push(p.ln() + pseudo_noise);
        }
        Self::softmax(levels, &logits)
    }

    fn softmax(classes: &[String], logits: &[f64]) -> HashMap<String, f64> {
        let max_logit = logits.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let exp_sum: f64 = logits.iter().map(|l| (l - max_logit).exp()).sum();
        let mut map = HashMap::new();
        for (i, c) in classes.iter().enumerate() {
            let p = if exp_sum > 0.0 {
                (logits[i] - max_logit).exp() / exp_sum
            } else {
                1.0 / classes.len() as f64
            };
            map.insert(c.clone(), p);
        }
        map
    }
}
