//! Threat Intelligence Feeds (CISA KEV, OTX).

use osoosi_types::Kev;
use serde_json::Value;
use chrono::{DateTime, Utc};
use std::collections::HashSet;
use std::io::Write;
use tracing::{info, warn, error};
use sysinfo::Disks;

pub const CISA_KEV_FEED_URL: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
pub const OTX_PULSES_SUBSCRIBED_URL: &str = "https://otx.alienvault.com/api/v1/pulses/subscribed";
pub const NVD_CVE_API_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

#[derive(Debug, Clone, Default)]
pub struct OtxIndicators {
    pub ips: HashSet<String>,
    pub domains: HashSet<String>,
    pub urls: HashSet<String>,
    pub hashes: HashSet<String>,
}

impl OtxIndicators {
    pub fn total_count(&self) -> usize {
        self.ips.len() + self.domains.len() + self.urls.len() + self.hashes.len()
    }
}

fn offline_mode() -> bool {
    std::env::var("OSOOSI_OFFLINE_MODE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub struct ThreatFeedFetcher {
    client: reqwest::Client,
}

impl Default for ThreatFeedFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatFeedFetcher {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { client }
    }

    /// Import NSRL records from a NIST .sqlite file (Modern RDA format).
    /// This expects a standard NSRL sqlite schema with a 'FILE' table.
    pub async fn import_nsrl_from_sqlite(&self, path: &std::path::Path) -> anyhow::Result<Vec<osoosi_types::NsrlRecord>> {
        use rusqlite::Connection;
        
        let conn = Connection::open(path)?;
        let mut stmt = conn.prepare("SELECT sha1, md5, sha256, name, size, product, os FROM FILE")?;
        
        let records_iter = stmt.query_map([], |row| {
            Ok(osoosi_types::NsrlRecord {
                sha1: row.get::<_, String>(0)?,
                md5: row.get::<_, Option<String>>(1)?,
                sha256: row.get::<_, Option<String>>(2)?,
                file_name: row.get::<_, String>(3)?,
                file_size: {
                    let s: i64 = row.get(4)?;
                    s as u64
                },
                product_code: row.get::<_, Option<String>>(5)?,
                os_code: row.get::<_, Option<String>>(6)?,
            })
        })?;

        let mut out = Vec::new();
        for record in records_iter {
            out.push(record?);
        }
        
        Ok(out)
    }

    /// Fetch latest CISA KEV list. Returns Err when offline; use cached data.
    pub async fn fetch_kev(&self) -> anyhow::Result<Vec<Kev>> {
        if offline_mode() {
            return Err(anyhow::anyhow!("Offline mode: skipping KEV fetch"));
        }
        let response = self.client.get(CISA_KEV_FEED_URL).send().await?;
        let json_val: Value = response.json().await?;
        
        let mut kevs = Vec::new();
        if let Some(vulnerabilities) = json_val.get("vulnerabilities").and_then(|v| v.as_array()) {
            for v in vulnerabilities {
                let kev = Kev {
                    cve_id: v["cveID"].as_str().unwrap_or_default().to_string(),
                    vendor_project: v["vendorProject"].as_str().unwrap_or_default().to_string(),
                    product: v["product"].as_str().unwrap_or_default().to_string(),
                    vulnerability_name: v["vulnerabilityName"].as_str().unwrap_or_default().to_string(),
                    date_added: v["dateAdded"]
                        .as_str()
                        .and_then(|d| DateTime::parse_from_rfc3339(&format!("{}T00:00:00Z", d)).ok())
                        .map(|dt: DateTime<chrono::FixedOffset>| dt.with_timezone(&Utc))
                        .unwrap_or(Utc::now()),
                    required_action: v["requiredAction"].as_str().unwrap_or_default().to_string(),
                    due_date: v["dueDate"]
                        .as_str()
                        .and_then(|d| DateTime::parse_from_rfc3339(&format!("{}T00:00:00Z", d)).ok())
                        .map(|dt: DateTime<chrono::FixedOffset>| dt.with_timezone(&Utc))
                        .unwrap_or(Utc::now()),
                    known_exploited: true,
                };
                kevs.push(kev);
            }
        }
        
        Ok(kevs)
    }

    /// Fetch OTX indicators — only critical/targeted-attack pulses.
    ///
    /// Uses the subscribed pulses endpoint with `modified_since` to limit scope,
    /// and filters to only high-value adversary/malware pulses.
    pub async fn fetch_otx_indicators(&self, api_key: &str) -> anyhow::Result<OtxIndicators> {
        if offline_mode() {
            return Err(anyhow::anyhow!("Offline mode: skipping OTX fetch"));
        }

        // Build a dedicated client with longer timeout for OTX
        let otx_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .user_agent("OpenOsoosi-Agent/1.0")
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        let mut out = OtxIndicators::default();

        // Only fetch pulses from the last 7 days to keep it focused
        let since = (chrono::Utc::now() - chrono::Duration::days(7))
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string();

        let url = format!(
            "{}?limit=50&modified_since={}",
            OTX_PULSES_SUBSCRIBED_URL, since
        );

        info!("[OTX] Fetching critical pulses (since {})...", since);

        let response = match otx_client
            .get(&url)
            .header("X-OTX-API-KEY", api_key)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                // Network/TLS error — don't crash, just warn
                info!("[OTX] Could not reach OTX API ({}). Will retry next cycle.", e);
                return Ok(out); // Return empty, not an error
            }
        };

        if !response.status().is_success() {
            let status = response.status();
            info!("[OTX] API returned HTTP {}. Check OTX_API_KEY validity.", status);
            return Ok(out); // Return empty, not an error
        }

        let json_val: Value = match response.json().await {
            Ok(v) => v,
            Err(e) => {
                info!("[OTX] Failed to parse response: {}", e);
                return Ok(out);
            }
        };

        if let Some(results) = json_val.get("results").and_then(|v| v.as_array()) {
            for pulse in results {
                // Only process pulses that are critical/targeted
                let adversary = pulse.get("adversary")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let tags: Vec<&str> = pulse.get("tags")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|t| t.as_str()).collect())
                    .unwrap_or_default();
                let tlp = pulse.get("tlp")
                    .and_then(|v| v.as_str())
                    .unwrap_or("white");

                // Filter: only keep pulses with an adversary, or tagged critical/APT/ransomware
                let is_critical = !adversary.is_empty()
                    || tags.iter().any(|t| {
                        let lower = t.to_lowercase();
                        lower.contains("apt") || lower.contains("ransomware")
                            || lower.contains("critical") || lower.contains("0day")
                            || lower.contains("zero-day") || lower.contains("targeted")
                            || lower.contains("nation-state")
                    })
                    || tlp == "red" || tlp == "amber";

                if !is_critical {
                    continue;
                }

                if let Some(indicators) = pulse.get("indicators").and_then(|v| v.as_array()) {
                    for ind in indicators {
                        let kind = ind
                            .get("type")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_lowercase();
                        let raw = ind
                            .get("indicator")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .trim()
                            .to_lowercase();

                        if raw.is_empty() {
                            continue;
                        }

                        if kind.contains("ipv4") || kind.contains("ipv6") || kind == "ip" {
                            out.ips.insert(raw);
                        } else if kind.contains("domain") || kind.contains("hostname") {
                            out.domains.insert(raw);
                        } else if kind.contains("url") || raw.starts_with("http://") || raw.starts_with("https://") {
                            out.urls.insert(raw);
                        } else if kind.contains("filehash")
                            || kind.contains("sha256")
                            || kind.contains("sha1")
                            || kind.contains("md5")
                            || kind == "hash"
                        {
                            out.hashes.insert(raw);
                        }
                    }
                }
            }
        }

        info!("[OTX] Loaded {} critical indicators (IPs: {}, Domains: {}, URLs: {}, Hashes: {})",
            out.total_count(), out.ips.len(), out.domains.len(), out.urls.len(), out.hashes.len());

        Ok(out)
    }

    /// Fetch latest NVD CVEs (Vulnerability metadata).
    ///
    /// NVD API 2.0 recommends an API key for higher rate limits.
    /// Returns a list of CVE results (structured like KEV for now).
    pub async fn fetch_nvd_cves(&self, api_key: Option<&str>) -> anyhow::Result<Vec<osoosi_types::Kev>> {
        if offline_mode() {
            return Err(anyhow::anyhow!("Offline mode: skipping NVD fetch"));
        }

        let mut url = format!("{}?resultsPerPage=50", NVD_CVE_API_URL);
        
        // Add since-date to only get recent updates (optimization)
        // Standard NVD 2.0 uses lastModStartDate
        let since_dt = Utc::now() - chrono::Duration::days(3);
        let since = since_dt.format("%Y-%m-%dT%H:%M:%S").to_string();
        url.push_str(&format!("&lastModStartDate={}", since));

        info!("[NVD] Fetching recent CVEs (since {})...", since);

        let mut req = self.client.get(&url);
        if let Some(key) = api_key {
            req = req.header("apiKey", key);
        }

        let response = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                info!("[NVD] Could not reach NVD API ({}).", e);
                return Ok(Vec::new());
            }
        };

        if !response.status().is_success() {
            info!("[NVD] API returned HTTP {}. Check NVD_API_KEY.", response.status());
            return Ok(Vec::new());
        }

        let json_val: Value = match response.json().await {
            Ok(v) => v,
            Err(e) => {
                info!("[NVD] Failed to parse NVD response: {}", e);
                return Ok(Vec::new());
            }
        };

        let mut out = Vec::new();
        if let Some(vulnerabilities) = json_val.get("vulnerabilities").and_then(|v| v.as_array()) {
            for v in vulnerabilities {
                if let Some(cve) = v.get("cve") {
                    let id = cve.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
                    let kev = osoosi_types::Kev {
                        cve_id: id,
                        vendor_project: "NVD-Sync".to_string(),
                        product: "NVD".to_string(),
                        vulnerability_name: "Imported from NVD".to_string(),
                        date_added: Utc::now(),
                        required_action: "None (Intelligence only)".to_string(),
                        due_date: Utc::now(),
                        known_exploited: false,
                    };
                    out.push(kev);
                }
            }
        }

        info!("[NVD] Loaded {} vulnerability records.", out.len());
        Ok(out)
    }


    /// Validate that there is enough disk space for a download.
    fn check_disk_space(&self, dest_dir: &std::path::Path, required_gb: u64) -> anyhow::Result<()> {
        let disks = Disks::new_with_refreshed_list();
        let target = dest_dir.canonicalize().unwrap_or_else(|_| dest_dir.to_path_buf());
        
        let disk = disks.iter()
            .filter(|d| target.starts_with(d.mount_point()))
            .max_by_key(|d| d.mount_point().as_os_str().len());

        if let Some(d) = disk {
            let available_gb = d.available_space() / (1024 * 1024 * 1024);
            if available_gb < required_gb {
                return Err(anyhow::anyhow!(
                    "Insufficient disk space on {}: need at least {} GB, but only {:.1} GB available.",
                    d.mount_point().display(), required_gb, available_gb
                ));
            }
        }
        Ok(())
    }

    /// Download the latest NIST NSRL Minimal RDS (SQLite) and extract it.
    /// Returns the path to the extracted .db file.
    pub async fn download_and_extract_nsrl(&self, dest_dir: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
        // URLs to try in order — primary and fallback
        let urls = [
            "https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/rds_2025.03.1/RDS_2025.03.1_modern.zip",
        ];

        if !dest_dir.exists() {
            std::fs::create_dir_all(dest_dir)?;
        }

        let zip_path = dest_dir.join("nsrl_minimal.zip");

        // Use a dedicated client with a longer timeout for this large download
        let download_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(600))
            .connect_timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        let mut last_error: Option<anyhow::Error> = None;

        for url in &urls {
            info!("Step 1: Downloading NSRL Minimal Set from {}...", url);
            let response = match download_client.get(*url).send().await {
                Ok(r) => r,
                Err(e) => {
                    info!("Download request failed for {}: {}", url, e);
                    last_error = Some(e.into());
                    continue;
                }
            };

            // Validate HTTP status — S3 returns 403/404 as XML error pages
            let status = response.status();
            if !status.is_success() {
                let body_preview = response.text().await.unwrap_or_default();
                let preview = if body_preview.len() > 200 { &body_preview[..200] } else { &body_preview };
                info!("NSRL download returned HTTP {}: {}", status, preview);
                last_error = Some(anyhow::anyhow!(
                    "NSRL download returned HTTP {} for {}",
                    status, url
                ));
                continue;
            }

            // Check content-type if available — ZIP should not be text/html or text/xml
            if let Some(ct) = response.headers().get(reqwest::header::CONTENT_TYPE) {
                if let Ok(ct_str) = ct.to_str() {
                    let ct_lower = ct_str.to_lowercase();
                    if ct_lower.contains("text/html") || ct_lower.contains("text/xml") || ct_lower.contains("application/xml") {
                        info!("NSRL download returned unexpected content-type '{}' for {}", ct_str, url);
                        last_error = Some(anyhow::anyhow!(
                            "NSRL download returned non-ZIP content-type '{}' for {}",
                            ct_str, url
                        ));
                        continue;
                    }
                }
            }

            let bytes = match response.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    info!("Failed to read response body from {}: {}", url, e);
                    last_error = Some(e.into());
                    continue;
                }
            };

            // Sanity check: ZIP files start with PK magic bytes (0x50 0x4B)
            if bytes.len() < 4 || bytes[0] != 0x50 || bytes[1] != 0x4B {
                let preview: String = bytes.iter().take(100).map(|b| *b as char).collect();
                info!("Downloaded file is not a valid ZIP (bad magic bytes). Preview: {}", preview);
                last_error = Some(anyhow::anyhow!(
                    "Downloaded file from {} is not a valid ZIP archive ({} bytes, bad magic)",
                    url, bytes.len()
                ));
                continue;
            }

            {
                let mut file = std::fs::File::create(&zip_path)?;
                file.write_all(&bytes)?;
            }
            info!("Download complete ({} bytes) from {}.", bytes.len(), url);

            info!("Step 2: Extracting database...");
            let file = std::fs::File::open(&zip_path)?;
            let mut archive = zip::ZipArchive::new(file)?;

            let mut db_path = None;

            for i in 0..archive.len() {
                let mut file = archive.by_index(i)?;
                let outpath = dest_dir.join(file.name());

                if (*file.name()).ends_with('/') {
                    std::fs::create_dir_all(&outpath)?;
                } else {
                    if let Some(p) = outpath.parent() {
                        if !p.exists() { std::fs::create_dir_all(p)?; }
                    }
                    let mut outfile = std::fs::File::create(&outpath)?;
                    std::io::copy(&mut file, &mut outfile)?;

                    if outpath.extension().and_then(|s| s.to_str()) == Some("db") {
                        db_path = Some(outpath.clone());
                    }
                }
            }

            // Cleanup zip file
            let _ = std::fs::remove_file(&zip_path);

            return db_path.ok_or_else(|| anyhow::anyhow!("No .db file found in NSRL zip archive"));
        }

        // All URLs failed
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("All NSRL download URLs failed")))
    }

    /// Resumable, state-persistent streaming download for the NSRL RDS archive.
    ///
    /// Survives process restarts via a `.state.json` checkpoint file.
    /// Root cause fix: removed the global `timeout(7200s)` that was silently
    /// killing S3 streams — replaced with a per-chunk 30s deadman timeout.
    pub async fn download_nsrl_streaming(&self, dest_dir: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
        use futures::StreamExt;
        use tokio::io::AsyncWriteExt;

        let urls = [
            "https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/current/rds_modernm.zip",
            "https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/rds_2025.03.1/RDS_2025.03.1_modern.zip",
        ];

        if !dest_dir.exists() {
            std::fs::create_dir_all(dest_dir)?;
        }

        // Hardening Move: Pre-flight disk space check (Min 5GB for the minimal zip + extraction)
        if let Err(e) = self.check_disk_space(dest_dir, 5) {
            error!("[NSRL] Disk check failed: {}", e);
            return Err(e);
        }

        let zip_path   = dest_dir.join("nsrl_modern_stream.zip");
        let state_path = dest_dir.join("nsrl_modern_stream.state.json");

        // Load persisted checkpoint from previous run if it exists
        let persisted_bytes: u64 = if state_path.exists() {
            std::fs::read_to_string(&state_path)
                .ok()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                .and_then(|v| v["bytes_written"].as_u64())
                .unwrap_or(0)
        } else {
            0
        };

        // No global timeout — S3 silently drops idle TCP after hours.
        // A global timeout kills active downloads. Use per-chunk deadman below.
        let download_client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(60))
            .tcp_keepalive(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        let mut last_error: Option<anyhow::Error> = None;

        for url in &urls {
            let mut retry_count = 0;
            let mut stalled_count = 0;
            let mut last_processed_size = 0;
            let mut download_finished = false;

            while !download_finished {
                if retry_count > 0 {
                    let mut backoff_secs = (15 * retry_count as u64).min(300); // Max 5 mins
                    // Progressive stall backoff
                    if stalled_count > 2 {
                         backoff_secs = (backoff_secs * 2).min(600);
                         warn!("[NSRL Background] Persistent stall detected at same byte offset. Stretching backoff to {}s...", backoff_secs);
                    }
                    info!("[NSRL Background] Retrying download in {}s (Attempt {})...", backoff_secs, retry_count);
                    tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                }

                // Cross-reference state file with actual disk size (trust disk)
                let file_on_disk = if zip_path.exists() {
                    std::fs::metadata(&zip_path).map(|m| m.len()).unwrap_or(0)
                } else {
                    0
                };
                let current_size = if file_on_disk != persisted_bytes && file_on_disk > 0 {
                    warn!("[NSRL Background] State={} B, disk={} B. Trusting disk.", persisted_bytes, file_on_disk);
                    file_on_disk
                } else {
                    file_on_disk
                };

                let mut request = download_client.get(*url);
                if current_size > 0 {
                    request = request.header("Range", format!("bytes={}-", current_size));
                    info!("[NSRL Background] Resuming download from {} (current size: {:.1} MB)...", url, current_size as f64 / 1_048_576.0);
                } else {
                    info!("[NSRL Background] Starting streaming download from {}...", url);
                }

                let response = match request.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        error!("[NSRL Background] Request failed for {}: {}", url, e);
                        last_error = Some(e.into());
                        retry_count += 1;
                        stalled_count += 1;
                        continue;
                    }
                };

                let status = response.status();
                if !status.is_success() {
                    error!("[NSRL Background] HTTP {} (Non-success) for {}.", status, url);
                    last_error = Some(anyhow::anyhow!("NSRL download returned HTTP {} for {}", status, url));
                    if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::NOT_FOUND {
                        break; // Permanent failure
                    }
                    retry_count += 1;
                    stalled_count += 1;
                    continue;
                }

                let is_partial = status == reqwest::StatusCode::PARTIAL_CONTENT;
                let content_len = response.content_length().unwrap_or(0);
                let total_size = if is_partial { content_len + current_size } else { content_len };
                
                if total_size > 0 {
                    let left_gb = (total_size - current_size) as f64 / 1_073_741_824.0;
                    if is_partial {
                         info!("[NSRL Background] Resuming. Dynamic Status: {:.2} GB remaining (Total: {:.1} GB)", 
                            left_gb, total_size as f64 / 1_073_741_824.0);
                    } else {
                         info!("[NSRL Background] Target Payload: {:.1} GB", total_size as f64 / 1_073_741_824.0);
                    }
                }

                // Size limit check
                let max_gb: u64 = std::env::var("OSOOSI_MAX_NSRL_GB")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(200);
                let max_nsrl_size = max_gb * 1024 * 1024 * 1024;

                if total_size > max_nsrl_size {
                    info!("[NSRL Background] File too large ({:.1} GB > {} GB limit). Skipping.", total_size as f64 / 1_073_741_824.0, max_gb);
                    last_error = Some(anyhow::anyhow!("File too large"));
                    break; 
                }

                let mut file = match tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&zip_path).await {
                    Ok(f) => {
                        let mut writer = tokio::io::BufWriter::new(f);
                        if !is_partial && current_size > 0 {
                            let _ = writer.get_mut().set_len(0).await;
                        }
                        writer
                    },
                    Err(e) => {
                        last_error = Some(e.into());
                        retry_count += 1;
                        continue;
                    }
                };

                let mut downloaded: u64 = if is_partial { current_size } else { 0 };
                let mut last_log_pct: u64 = (downloaded * 100) / total_size.max(1);
                let mut stream = response.bytes_stream();
                let mut stream_error = false;

                let chunk_timeout = std::time::Duration::from_secs(30);
                while let Ok(next) = tokio::time::timeout(chunk_timeout, stream.next()).await {
                    let item = match next {
                        Some(v) => v,
                        None => break, // Clean EOF
                    };
                    let chunk = match item {
                        Ok(c) => c,
                        Err(e) => {
                            info!("[NSRL Background] Stream error during chunk: {}", e);
                            last_error = Some(e.into());
                            stream_error = true;
                            break;
                        }
                    };
                    if let Err(e) = file.write_all(&chunk).await {
                        info!("[NSRL Background] Disk write error: {}", e);
                        last_error = Some(e.into());
                        stream_error = true;
                        break;
                    }
                    downloaded += chunk.len() as u64;

                    // Persist checkpoint every 512 MB
                    if downloaded % (512 * 1024 * 1024) < (chunk.len() as u64) {
                        let checkpoint = serde_json::json!({ "url": url, "bytes_written": downloaded });
                        let _ = std::fs::write(&state_path, checkpoint.to_string());
                    }

                    if total_size > 0 {
                        let pct = (downloaded * 100) / total_size;
                        if pct >= last_log_pct + 10 {
                            last_log_pct = pct;
                            info!("[NSRL Background] Download progress: {}% ({:.1} MB / {:.1} MB)",
                                pct, downloaded as f64 / 1_048_576.0, total_size as f64 / 1_048_576.0);
                        }
                    }
                    tokio::task::yield_now().await;
                }
                // If timeout fired (outer while-let failed), mark as stalled stream error
                if !stream_error {
                    // Check if we stopped because of a 30s stall (no more data but not EOF)
                    // The while-let exits on timeout too — check against expected total
                    if total_size > 0 && downloaded < total_size {
                        warn!("[NSRL Background] Stream stalled (30s timeout). Will reconnect.");
                        stream_error = true;
                    }
                }
                let _ = file.flush().await;
                drop(file);

                if !stream_error {
                    download_finished = true;
                    last_error = None;
                } else {
                    retry_count += 1;
                    // Check if we actually made progress this time
                    if downloaded > last_processed_size {
                        stalled_count = 0;
                        last_processed_size = downloaded;
                    } else {
                        stalled_count += 1;
                    }
                }
            }

            if !download_finished {
                continue; // Try next URL if all retries failed
            }

            // Verify ZIP magic bytes
            let header = tokio::fs::read(&zip_path).await.ok().and_then(|b| if b.len() >= 4 { Some((b[0], b[1])) } else { None });
            if header != Some((0x50, 0x4B)) {
                info!("[NSRL Background] Downloaded file from {} is not a valid ZIP", url);
                let _ = tokio::fs::remove_file(&zip_path).await;
                last_error = Some(anyhow::anyhow!("Invalid ZIP header"));
                continue;
            }

            info!("[NSRL Background] Download complete. Extracting in background...");

            let dest_dir_clone = dest_dir.to_path_buf();
            let zip_path_clone = zip_path.clone();
            
            let extract_res = tokio::task::spawn_blocking(move || -> anyhow::Result<std::path::PathBuf> {
                let file = std::fs::File::open(&zip_path_clone)?;
                let mut archive = zip::ZipArchive::new(file)?;
                let mut db_path = None;

                for i in 0..archive.len() {
                    let mut entry = archive.by_index(i)?;
                    let outpath = dest_dir_clone.join(entry.name());

                    if entry.name().ends_with('/') {
                        let _ = std::fs::create_dir_all(&outpath);
                    } else {
                        if let Some(p) = outpath.parent() {
                            if !p.exists() { let _ = std::fs::create_dir_all(p); }
                        }
                        let mut outfile = std::fs::File::create(&outpath)?;
                        std::io::copy(&mut entry, &mut outfile)?;

                        if outpath.extension().and_then(|s| s.to_str()) == Some("db") {
                            db_path = Some(outpath.clone());
                        }
                    }
                }
                let _ = std::fs::remove_file(&zip_path_clone);
                db_path.ok_or_else(|| anyhow::anyhow!("No .db file found in NSRL zip archive"))
            }).await?;

            return extract_res;
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("All NSRL streaming download URLs failed")))
    }

    /// Check NIST S3 bucket for newer NSRL RDS versions and deltas.
    /// Returns a list of (version, url, is_delta) tuples found that are newer
    /// than `current_version` (e.g. "2025.03.1").
    pub async fn check_nsrl_updates(&self, current_version: &str) -> anyhow::Result<Vec<(String, String, bool)>> {
        let bucket_url = "https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/";

        let download_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        info!("[NSRL Update Check] Checking for updates newer than {}...", current_version);

        let response = download_client.get(bucket_url).send().await?;
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Failed to list NSRL bucket: HTTP {}", response.status()));
        }

        let body = response.text().await?;
        let mut updates = Vec::new();

        // Parse S3 XML listing for RDS directories
        // S3 bucket lists keys like: RDS/rds_YYYY.MM.V/ and RDS/RDS_YYYY.MM.V/
        let version_pattern = regex::Regex::new(r"(?i)(?:rds[_/])(\d{4}\.\d{2}\.\d+)")?;
        let mut seen_versions = std::collections::HashSet::new();

        for cap in version_pattern.captures_iter(&body) {
            let version = cap[1].to_string();
            if seen_versions.contains(&version) {
                continue;
            }
            seen_versions.insert(version.clone());

            // Compare versions: YYYY.MM.V
            if version_is_newer(&version, current_version) {
                // Check for full and delta downloads
                let full_url = format!(
                    "https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/rds_{}/RDS_{}_modern.zip",
                    version, version
                );
                let delta_url = format!(
                    "https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/rds_{}/RDS_{}_modern_delta.zip",
                    version, version
                );

                // HEAD request to check if delta exists
                let delta_exists = download_client.head(&delta_url).send().await
                    .map(|r| r.status().is_success())
                    .unwrap_or(false);

                if delta_exists {
                    info!("[NSRL Update Check] Delta update available: v{}", version);
                    updates.push((version.clone(), delta_url, true));
                }

                // Also record full download
                updates.push((version, full_url, false));
            }
        }

        if updates.is_empty() {
            info!("[NSRL Update Check] No updates found. Current version {} is up to date.", current_version);
        } else {
            info!("[NSRL Update Check] Found {} update(s) newer than v{}", updates.len(), current_version);
        }

        Ok(updates)
    }
}

/// Compare two NSRL version strings of the form "YYYY.MM.V".
/// Returns true if `candidate` is newer than `current`.
fn version_is_newer(candidate: &str, current: &str) -> bool {
    let parse = |v: &str| -> (u32, u32, u32) {
        let parts: Vec<&str> = v.split('.').collect();
        let year = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
        let month = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let patch = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
        (year, month, patch)
    };
    parse(candidate) > parse(current)
}
