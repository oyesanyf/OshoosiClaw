use anyhow::Result;
use regex::Regex;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::{env, fs, path::Path};
use walkdir::WalkDir;

#[derive(Debug, Deserialize, Default, Clone)]
struct ZeroDaySignals {
    fuzzing_crashes: Option<u32>,
    taint_findings: Option<u32>,
    symbolic_paths: Option<u32>,
    crash_duplicates: Option<u32>,
    sandbox_validated: Option<bool>,
    human_review_required: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct DatasetRow {
    prompt: String,
    target_cve: Option<String>,
    completion: Option<String>,
    zero_day_signals: Option<ZeroDaySignals>,
    parent_process: Option<String>,
}

#[derive(Debug, Serialize, Default)]
struct NvdEnrichment {
    cvss_score: f64,
    epss_score: f64,
    product: Option<String>,
    version_range: Option<String>,
}

#[derive(Debug, Serialize, Default)]
struct ScoredRow {
    prompt: String,
    target_cve: Option<String>,
    predicted_score: Option<f64>,
    cvss_score: f64,
    epss_score: f64,
    cve_risk_score: f64,
    zero_day_score: f64,
    final_risk_score: f64,
    format_reward: f64,
    accuracy_reward: f64,
    risk_label: String,
    explanation: String,
    product: Option<String>,
    version: Option<String>,
    parent_process: Option<String>,
}

// =======================================================
// 1. ENRICHMENT & SCORING
// =======================================================
fn get_epss_score(client: &Client, cve_id: &str) -> Result<f64> {
    let url = format!("https://api.first.org/data/v1/epss?cve={}", cve_id);
    let json: serde_json::Value = client.get(url).send()?.json()?;
    let epss = json["data"][0]["epss"].as_str().unwrap_or("0.01").parse::<f64>().unwrap_or(0.01);
    Ok(epss)
}

fn get_nvd_enrichment(client: &Client, cve_id: &str, nvd_api_key: Option<&str>) -> Result<NvdEnrichment> {
    let url = format!("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}", cve_id);
    let mut request = client.get(url);
    if let Some(key) = nvd_api_key { request = request.header("apiKey", key); }
    let json: serde_json::Value = request.send()?.json()?;
    let mut enrichment = NvdEnrichment::default();
    if let Some(vuln) = json["vulnerabilities"].as_array().and_then(|v| v.first()) {
        let cve = &vuln["cve"];
        enrichment.cvss_score = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"].as_f64().unwrap_or(0.0);
        if let Some(config) = cve["configurations"].as_array().and_then(|c| c.first()) {
            if let Some(node) = config["nodes"].as_array().and_then(|n| n.first()) {
                if let Some(cpe) = node["cpeMatch"][0]["criteria"].as_str() {
                    let parts: Vec<&str> = cpe.split(':').collect();
                    if parts.len() >= 6 {
                        enrichment.product = Some(parts[4].to_string());
                        enrichment.version_range = Some(parts[5].to_string());
                    }
                }
            }
        }
    }
    Ok(enrichment)
}

fn reward_reasoning_format(completion: &str) -> f64 {
    let pattern = Regex::new(r"(?s)<reasoning>.*?</reasoning>\s*<score>\s*\d+\.?\d*\s*</score>").unwrap();
    if pattern.is_match(completion) { 1.5 } else { 0.0 }
}

fn extract_score(completion: &str) -> Option<f64> {
    let pattern = Regex::new(r"<score>\s*([0-9.]+)\s*</score>").unwrap();
    pattern.captures(completion)
        .and_then(|captures| captures.get(1))
        .and_then(|matched| matched.as_str().parse::<f64>().ok())
}

fn calculate_zero_day_score(signals: &ZeroDaySignals) -> f64 {
    let mut score: f64 = 0.0;
    if let Some(f) = signals.fuzzing_crashes { if f > 0 { score += 3.0; } }
    if let Some(t) = signals.taint_findings { if t > 0 { score += 2.0; } }
    if let Some(s) = signals.symbolic_paths { if s > 0 { score += 2.0; } }
    if let Some(v) = signals.sandbox_validated { if v { score += 3.0; } }
    if let Some(d) = signals.crash_duplicates { if d > 10 { score -= 1.0; } } // High duplicates might mean lower novelty
    if let Some(h) = signals.human_review_required { if h { score += 1.0; } }
    score.min(10.0)
}

// =======================================================
// 2. MAIN
// =======================================================
fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let client = Client::builder().user_agent("oshoosi-auditor/0.1").build()?;
    
    let dataset_folder = "dataset";
    let output_path = "models/scored_dataset.json";
    let nvd_api_key = env::var("NVD_API_KEY").ok();
    
    if !Path::new(dataset_folder).exists() { fs::create_dir_all(dataset_folder)?; }
    
    println!("🔍 Starting Deep Dataset Crawl in: {}...", dataset_folder);
    
    let mut rows = Vec::new();
    for entry in WalkDir::new(dataset_folder).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
            if ext == "jsonl" || ext == "json" {
                let text = fs::read_to_string(path)?;
                if ext == "jsonl" {
                    for line in text.lines().filter(|l| !l.trim().is_empty()) {
                        if let Ok(row) = serde_json::from_str::<DatasetRow>(line) {
                            rows.push(row);
                        }
                    }
                } else {
                    if let Ok(json_rows) = serde_json::from_str::<Vec<DatasetRow>>(&text) {
                        rows.extend(json_rows);
                    } else if let Ok(row) = serde_json::from_str::<DatasetRow>(&text) {
                        rows.push(row);
                    }
                }
            }
        }
    }

    if rows.is_empty() {
        println!("No dataset rows found.");
        return Ok(());
    }

    let mut scored_rows = Vec::new();
    for row in rows {
        let enrichment = if let Some(ref c) = row.target_cve {
            let mut e = get_nvd_enrichment(&client, c, nvd_api_key.as_deref()).unwrap_or_default();
            e.epss_score = get_epss_score(&client, c).unwrap_or(0.01);
            e
        } else {
            NvdEnrichment::default()
        };

        let zero_day_score = if let Some(ref s) = row.zero_day_signals {
            calculate_zero_day_score(s)
        } else {
            0.0
        };

        let completion = row.completion.as_deref().unwrap_or("");
        let predicted_score = extract_score(completion);
        let format_reward = reward_reasoning_format(completion);
        
        let cve_risk = (enrichment.cvss_score / 10.0) * (enrichment.epss_score * 10.0);
        let final_risk = (cve_risk + (zero_day_score / 10.0)).clamp(0.0, 1.0);

        scored_rows.push(ScoredRow {
            prompt: row.prompt,
            target_cve: row.target_cve,
            predicted_score,
            cvss_score: enrichment.cvss_score,
            epss_score: enrichment.epss_score,
            cve_risk_score: cve_risk,
            zero_day_score,
            final_risk_score: final_risk as f64,
            format_reward,
            risk_label: if final_risk > 0.7 { "CRITICAL".into() } else if final_risk > 0.4 { "HIGH".into() } else { "LOW".into() },
            explanation: "Auto-scored via NVD/EPSS/Signals".into(),
            product: enrichment.product,
            version: enrichment.version_range,
            parent_process: row.parent_process,
            ..Default::default()
        });
    }
    
    fs::create_dir_all("models")?;
    fs::write(output_path, serde_json::to_string_pretty(&scored_rows)?)?;
    println!("✅ Scored {} rows. Clean build complete.", scored_rows.len());
    Ok(())
}
