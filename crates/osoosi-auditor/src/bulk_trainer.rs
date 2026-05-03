use anyhow::{Context, Result};
use reqwest::{Client, header};
use serde::{Deserialize, Serialize};
use std::{env, fs, collections::HashMap, time::Duration};
use walkdir::WalkDir;

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct ModelWeights {
    pub features: HashMap<String, f32>,
    pub trained_at: Option<String>,
    pub sample_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct BulkCveRow {
    cve_id: String,
    cvss_score: f64,
    product: String,
    version: String,
    epss_score: f64,
}

#[derive(Debug, Deserialize)]
struct LocalDatasetRow {
    target_cve: Option<String>,
    parent_process: Option<String>,
}

struct RateLimiter {
    next_request_at: std::time::Instant,
}

impl RateLimiter {
    fn new() -> Self {
        Self { next_request_at: std::time::Instant::now() }
    }

    async fn wait_for_slot(&self) {
        let now = std::time::Instant::now();
        if self.next_request_at > now {
            tokio::time::sleep(self.next_request_at - now).await;
        }
    }

    fn update_from_headers(&mut self, headers: &header::HeaderMap) {
        if let Some(retry_after) = headers.get(header::RETRY_AFTER) {
            if let Ok(s) = retry_after.to_str() {
                if let Ok(seconds) = s.parse::<u64>() {
                    println!("⏳ NVD requested wait: {}s", seconds);
                    self.next_request_at = std::time::Instant::now() + Duration::from_secs(seconds + 1);
                }
            }
        }
    }
}

async fn fetch_epss_batch(client: &Client, cve_ids: &[String]) -> Result<HashMap<String, f64>> {
    let mut scores = HashMap::new();
    if cve_ids.is_empty() { return Ok(scores); }
    let cve_list = cve_ids.join(",");
    let url = format!("https://api.first.org/data/v1/epss?cve={}", cve_list);
    let resp = client.get(url).send().await?;
    let json: serde_json::Value = resp.json().await?;
    if let Some(data) = json["data"].as_array() {
        for entry in data {
            if let (Some(cve), Some(epss)) = (entry["cve"].as_str(), entry["epss"].as_str()) {
                if let Ok(val) = epss.parse::<f64>() { scores.insert(cve.to_string(), val); }
            }
        }
    }
    Ok(scores)
}

async fn fetch_nvd_batch(
    client: &Client, 
    start_index: u32, 
    results_per_page: u32, 
    api_key: Option<&str>,
    limiter: &mut RateLimiter
) -> Result<(Vec<BulkCveRow>, bool)> {
    limiter.wait_for_slot().await;
    let url = format!("https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex={}&resultsPerPage={}", start_index, results_per_page);
    let mut request = client.get(url);
    if let Some(key) = api_key { request = request.header("apiKey", key); }
    let response = request.send().await?;
    limiter.update_from_headers(response.headers());
    if response.status().as_u16() == 429 { return Ok((Vec::new(), true)); }
    let json: serde_json::Value = response.json().await.context("Failed to parse NVD JSON")?;
    let mut rows = Vec::new();
    if let Some(vulnerabilities) = json["vulnerabilities"].as_array() {
        for vuln in vulnerabilities {
            let cve = &vuln["cve"];
            let id = cve["id"].as_str().unwrap_or("unknown").to_string();
            let metrics = &cve["metrics"];
            let cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"].as_f64().or_else(|| metrics["cvssMetricV30"][0]["cvssData"]["baseScore"].as_f64()).or_else(|| metrics["cvssMetricV2"][0]["cvssData"]["baseScore"].as_f64()).unwrap_or(0.0);
            let mut product = "generic_vuln".to_string();
            let mut version = "*".to_string();
            if let Some(config) = cve["configurations"].as_array().and_then(|c| c.first()) {
                if let Some(node) = config["nodes"].as_array().and_then(|n| n.first()) {
                    if let Some(cpe_match) = node["cpeMatch"].as_array().and_then(|m| m.first()) {
                        if let Some(criteria) = cpe_match["criteria"].as_str() {
                            let parts: Vec<&str> = criteria.split(':').collect();
                            if parts.len() >= 6 { product = parts[4].to_string(); version = parts[5].to_string(); }
                        }
                    }
                }
            }
            rows.push(BulkCveRow { cve_id: id, cvss_score: cvss, product, version, epss_score: 0.01 });
        }
    }
    Ok((rows, false))
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let target_count = 100000;
    let batch_size = 2000; 
    let nvd_api_key = env::var("NVD_API_KEY").ok();
    let client = Client::builder().user_agent("oshoosi-bulk-trainer/0.1").timeout(Duration::from_secs(60)).build()?;
    let mut model_weights = ModelWeights::default();
    model_weights.trained_at = Some(chrono::Utc::now().to_rfc3339());
    let mut limiter = RateLimiter::new();

    // 1. INGEST LOCAL DATASET (Recursive)
    println!("📂 Phase 1: Ingesting local dataset files...");
    let dataset_folder = "dataset";
    for entry in WalkDir::new(dataset_folder).into_iter().filter_map(|e| e.ok()) {
        if entry.path().is_file() {
            let ext = entry.path().extension().and_then(|s| s.to_str()).unwrap_or("");
            if ext == "jsonl" || ext == "json" {
                let text = fs::read_to_string(entry.path())?;
                let mut local_rows = Vec::new();
                if ext == "jsonl" {
                    for line in text.lines().filter(|l| !l.trim().is_empty()) {
                        if let Ok(r) = serde_json::from_str::<LocalDatasetRow>(line) { local_rows.push(r); }
                    }
                } else {
                    if let Ok(rs) = serde_json::from_str::<Vec<LocalDatasetRow>>(&text) { local_rows.extend(rs); }
                }

                for row in local_rows {
                    if let Some(ref parent) = row.parent_process {
                        let key = format!("parent:{}", parent.to_lowercase());
                        let w = model_weights.features.entry(key).or_insert(0.0);
                        *w = (*w + 0.5).min(1.0); // Baseline risk for parent processes seen in dataset
                    }
                    if let Some(ref cve_id) = row.target_cve {
                        // We will enrich these in the bulk phase if they match
                        model_weights.features.insert(format!("cve:{}", cve_id.to_lowercase()), 0.5);
                    }
                    model_weights.sample_count += 1;
                }
            }
        }
    }
    println!("📈 Phase 1 Complete. Ingested {} local samples.", model_weights.sample_count);

    // 2. BULK API INGESTION
    println!("🚀 Phase 2: Bulk API Training (Target: {})...", target_count);
    let mut current_index = 0;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => { println!("\n🛑 Graceful shutdown. Saving..."); break; }
            result = fetch_nvd_batch(&client, current_index, batch_size, nvd_api_key.as_deref(), &mut limiter) => {
                match result {
                    Ok((mut batch, retry)) => {
                        if retry { tokio::time::sleep(Duration::from_secs(1)).await; continue; }
                        if batch.is_empty() { break; }
                        let ids: Vec<String> = batch.iter().map(|b| b.cve_id.clone()).collect();
                        let mut epss_map = HashMap::new();
                        for chunk in ids.chunks(100) { if let Ok(m) = fetch_epss_batch(&client, chunk).await { epss_map.extend(m); } }
                        for row in &mut batch {
                            if let Some(score) = epss_map.get(&row.cve_id) { row.epss_score = *score; }
                            let risk = ((row.cvss_score as f32 / 10.0) * (row.epss_score as f32 * 10.0)).clamp(0.0, 1.0);
                            model_weights.features.insert(format!("cve:{}", row.cve_id.to_lowercase()), risk);
                            if row.product != "generic_vuln" {
                                let p_low = row.product.to_lowercase();
                                if row.version != "*" { model_weights.features.insert(format!("ver:{}:{}", p_low, row.version.to_lowercase()), risk); }
                                let key = format!("proc:{}", p_low);
                                let w = model_weights.features.entry(key).or_insert(0.0);
                                *w = ((*w + risk) / 2.0).clamp(0.0, 1.0);
                            }
                            model_weights.sample_count += 1;
                        }
                        current_index += batch_size;
                        let progress = (current_index as f32 / target_count as f32 * 100.0).min(100.0);
                        println!("📊 [{:>3.1}%] Samples: {:<6} | Features: {:<6}", progress, model_weights.sample_count, model_weights.features.len());
                    }
                    Err(e) => { println!("❌ Error: {}. Backoff...", e); tokio::time::sleep(Duration::from_secs(10)).await; }
                }
            }
        }
        if model_weights.sample_count >= target_count as usize { break; }
    }

    let model_path = "models/bulk_threat_model.json";
    fs::create_dir_all("models")?;
    fs::write(model_path, serde_json::to_string_pretty(&model_weights)?)?;
    println!("📦 Ultimate Model saved to {}. Total Samples: {}", model_path, model_weights.sample_count);
    Ok(())
}
