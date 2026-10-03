use super::models::{DecisionAnswer, DecisionRequest, DecisionResponse};
use anyhow::{bail, Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Deserialize)]
struct CfWorkersAiEnvelope {
    pub result: Option<serde_json::Value>,
    #[serde(default)]
    pub success: bool,
    #[serde(default)]
    pub errors: Vec<serde_json::Value>,
}

#[derive(Clone)]
pub struct CloudflareClient {
    account_id: String,
    api_token: String,
    default_model: String,
    timeout: Duration,
    http_client: reqwest::Client,
}

impl CloudflareClient {
    pub fn new(
        account_id: String,
        api_token: String,
        default_model: String,
        timeout_ms: u64,
    ) -> Result<Self> {
        if account_id.trim().is_empty() {
            bail!("Cloudflare account_id cannot be empty");
        }
        if api_token.trim().is_empty() {
            bail!("Cloudflare api_token cannot be empty");
        }

        let mut headers = HeaderMap::new();
        let mut token_val = HeaderValue::from_str(&format!("Bearer {}", api_token.trim()))
            .context("Invalid characters in Cloudflare API token")?;
        token_val.set_sensitive(true);
        headers.insert(AUTHORIZATION, token_val);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let http_client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .context("Failed to construct reqwest HTTP client for Cloudflare Workers AI")?;

        Ok(Self {
            account_id: account_id.trim().to_string(),
            api_token: api_token.trim().to_string(),
            default_model,
            timeout: Duration::from_millis(timeout_ms),
            http_client,
        })
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn api_token(&self) -> &str {
        &self.api_token
    }

    pub fn default_model(&self) -> &str {
        &self.default_model
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub async fn run_decision(&self, request: &DecisionRequest) -> Result<DecisionResponse> {
        let model = if !request.model.trim().is_empty() {
            &request.model
        } else {
            &self.default_model
        };

        let url = format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/ai/run/{}",
            self.account_id, model
        );

        let start = Instant::now();
        let response = self
            .http_client
            .post(&url)
            .json(request)
            .send()
            .await
            .context("Cloudflare Workers AI HTTP request failed or timed out")?;

        let status = response.status();
        let body_bytes = response.bytes().await.context("Failed to read response body")?;
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        if !status.is_success() {
            let err_text = String::from_utf8_lossy(&body_bytes);
            bail!(
                "Cloudflare Workers AI API returned HTTP {} ({}): {}",
                status.as_u16(),
                status.canonical_reason().unwrap_or("Unknown"),
                err_text
            );
        }

        // Try envelope format first
        if let Ok(envelope) = serde_json::from_slice::<CfWorkersAiEnvelope>(&body_bytes) {
            if envelope.success {
                if let Some(res_val) = envelope.result {
                    if let Ok(answers) = serde_json::from_value::<HashMap<String, DecisionAnswer>>(
                        res_val.get("answers").cloned().unwrap_or(res_val),
                    ) {
                        return Ok(DecisionResponse {
                            answers,
                            latency_ms,
                            provider: "cloudflare_workers_ai".to_string(),
                        });
                    }
                }
            } else if !envelope.errors.is_empty() {
                bail!("Cloudflare Workers AI error: {:?}", envelope.errors);
            }
        }

        // Try direct answers JSON or raw response
        if let Ok(raw_map) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            let target_answers = if let Some(answers_val) = raw_map.get("answers") {
                answers_val.clone()
            } else {
                raw_map
            };

            if let Ok(answers) = serde_json::from_value::<HashMap<String, DecisionAnswer>>(target_answers) {
                return Ok(DecisionResponse {
                    answers,
                    latency_ms,
                    provider: "cloudflare_workers_ai".to_string(),
                });
            }
        }

        bail!("Failed to parse Cloudflare Workers AI response into expected DecisionResponse schema");
    }
}
