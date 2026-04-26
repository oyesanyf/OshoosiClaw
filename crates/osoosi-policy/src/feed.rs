//! Threat Intelligence Feeds (CISA KEV, OTX).

use chrono::{DateTime, Utc};
use osoosi_types::{Kev, NsrlRecord};
use serde_json::Value;
use std::collections::HashSet;
use std::io::Write;
use sysinfo::Disks;
use tracing::{debug, error, info, warn};

pub const CISA_KEV_FEED_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
/// Subscribed-pulses feed; often **504s or times out** on AlienVault’s side (see OTX community reports).
pub const OTX_PULSES_SUBSCRIBED_URL: &str = "https://otx.alienvault.com/api/v1/pulses/subscribed/";
/// Activity feed; same JSON shape as `results` pulses, but typically **reliable** when `/subscribed` fails.
pub const OTX_PULSES_ACTIVITY_URL: &str = "https://otx.alienvault.com/api/v1/pulses/activity";
pub const NVD_CVE_API_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
pub const OTX_TAXII_POLL_URL: &str = "https://otx.alienvault.com/taxii/poll";

/// Remote object size from S3 (ETag-style listing); `None` if HEAD fails.
async fn nsrl_s3_content_length(client: &reqwest::Client, url: &str) -> Option<u64> {
    let resp = client
        .head(url)
        .header(reqwest::header::USER_AGENT, "OpenOsoosi-Agent/1.0")
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
}

fn nsrl_local_zip_valid(path: &std::path::Path) -> bool {
    std::fs::File::open(path)
        .ok()
        .and_then(|f| zip::ZipArchive::new(f).ok())
        .map(|a| a.len() > 0)
        .unwrap_or(false)
}

fn nsrl_local_zip_matches_complete(path: &std::path::Path, remote_len: u64) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if meta.len() != remote_len {
        return false;
    }
    nsrl_local_zip_valid(path)
}

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

    pub fn to_vec(&self) -> Vec<osoosi_types::OtxIndicator> {
        let mut out = Vec::new();
        for ip in &self.ips {
            out.push(osoosi_types::OtxIndicator {
                indicator_type: "ipv4".to_string(),
                value: ip.clone(),
                source: "OTX".to_string(),
            });
        }
        for domain in &self.domains {
            out.push(osoosi_types::OtxIndicator {
                indicator_type: "domain".to_string(),
                value: domain.clone(),
                source: "OTX".to_string(),
            });
        }
        for url in &self.urls {
            out.push(osoosi_types::OtxIndicator {
                indicator_type: "url".to_string(),
                value: url.clone(),
                source: "OTX".to_string(),
            });
        }
        for hash in &self.hashes {
            out.push(osoosi_types::OtxIndicator {
                indicator_type: "hash".to_string(),
                value: hash.clone(),
                source: "OTX".to_string(),
            });
        }
        out
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
    /// This loads **all** rows into memory — for large RDS files prefer
    /// `MemoryStore::import_nsrl_from_nist_rds_sqlite` (ATTACH + `INSERT..SELECT`, fast / low RAM).
    pub async fn import_nsrl_from_sqlite(
        &self,
        path: &std::path::Path,
    ) -> anyhow::Result<Vec<NsrlRecord>> {
        use rusqlite::Connection;

        let conn = Connection::open(path)?;
        let mut stmt =
            conn.prepare("SELECT sha1, md5, sha256, name, size, product, os FROM FILE")?;

        let records_iter = stmt.query_map([], |row| {
            Ok(NsrlRecord {
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
            info!("[KEV] Offline mode: Loading from local cache...");
            return self.load_kev_from_cache().await;
        }

        let cache_path = osoosi_types::resolve_kev_cache_path();
        if cache_path.exists() {
            if let Ok(metadata) = std::fs::metadata(&cache_path) {
                if let Ok(modified) = metadata.modified() {
                    if let Ok(elapsed) = modified.elapsed() {
                        if elapsed.as_secs() < 14400 {
                            // 4 hours
                            debug!(
                                "[KEV] Cache is fresh ({}s old), skipping fetch.",
                                elapsed.as_secs()
                            );
                            return self.load_kev_from_cache().await;
                        }
                    }
                }
            }
        }

        info!("[KEV] Fetching latest feed from CISA...");
        let mut request = self.client.get(CISA_KEV_FEED_URL);
        // CISA/Cloudflare may block requests without a proper User-Agent
        request = request.header("User-Agent", "OpenOsoosi-Agent/1.0");

        let response = match request.send().await {
            Ok(r) => r,
            Err(e) => {
                warn!("[KEV] Network fetch failed: {}. Falling back to cache.", e);
                return self.load_kev_from_cache().await;
            }
        };

        if !response.status().is_success() {
            warn!(
                "[KEV] Server returned HTTP {}. Falling back to cache.",
                response.status()
            );
            return self.load_kev_from_cache().await;
        }

        // Fetch as bytes to handle potential decoding issues manually if needed
        let bytes = match response.bytes().await {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    "[KEV] Failed to read response body: {}. Falling back to cache.",
                    e
                );
                return self.load_kev_from_cache().await;
            }
        };

        match serde_json::from_slice::<Value>(&bytes) {
            Ok(json_val) => {
                let kevs = self.parse_kev_json(json_val);
                if !kevs.is_empty() {
                    let _ = self.save_kev_to_cache(&bytes).await;
                }
                Ok(kevs)
            }
            Err(e) => {
                warn!("[KEV] JSON decoding failed: {}. Falling back to cache.", e);
                self.load_kev_from_cache().await
            }
        }
    }

    fn parse_kev_json(&self, json_val: Value) -> Vec<Kev> {
        let mut kevs = Vec::new();
        if let Some(vulnerabilities) = json_val.get("vulnerabilities").and_then(|v| v.as_array()) {
            for v in vulnerabilities {
                let kev = Kev {
                    cve_id: v["cveID"].as_str().unwrap_or_default().to_string(),
                    vendor_project: v["vendorProject"].as_str().unwrap_or_default().to_string(),
                    product: v["product"].as_str().unwrap_or_default().to_string(),
                    vulnerability_name: v["vulnerabilityName"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    date_added: v["dateAdded"]
                        .as_str()
                        .and_then(|d| {
                            DateTime::parse_from_rfc3339(&format!("{}T00:00:00Z", d)).ok()
                        })
                        .map(|dt: DateTime<chrono::FixedOffset>| dt.with_timezone(&Utc))
                        .unwrap_or(Utc::now()),
                    required_action: v["requiredAction"].as_str().unwrap_or_default().to_string(),
                    due_date: v["dueDate"]
                        .as_str()
                        .and_then(|d| {
                            DateTime::parse_from_rfc3339(&format!("{}T00:00:00Z", d)).ok()
                        })
                        .map(|dt: DateTime<chrono::FixedOffset>| dt.with_timezone(&Utc))
                        .unwrap_or(Utc::now()),
                    known_exploited: true,
                };
                kevs.push(kev);
            }
        }
        kevs
    }

    async fn load_kev_from_cache(&self) -> anyhow::Result<Vec<Kev>> {
        let cache_path = osoosi_types::resolve_kev_cache_path();
        if !cache_path.exists() {
            info!("[KEV] No local cache found at {:?}", cache_path);
            return Ok(Vec::new());
        }

        let content = std::fs::read_to_string(&cache_path)?;
        let json_val: Value = serde_json::from_str(&content)?;
        Ok(self.parse_kev_json(json_val))
    }

    async fn save_kev_to_cache(&self, data: &[u8]) -> anyhow::Result<()> {
        let cache_path = osoosi_types::resolve_kev_cache_path();
        if let Some(parent) = cache_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&cache_path, data)?;
        debug!("[KEV] Saved latest feed to cache: {:?}", cache_path);
        Ok(())
    }

    /// Fetch OTX indicators — only critical/targeted-attack pulses.
    ///
    /// Uses the subscribed pulses endpoint with `modified_since` to limit scope,
    /// and filters to only high-value adversary/malware pulses.
    ///
    /// **Default: TAXII 1.1** (same client as `otx-taxii-rs`).
    /// Set `OTX_USE_TAXII=0` to use the JSON REST API instead.
    ///
    /// REST mode uses **`/pulses/activity` by default** (stable). Set `OTX_REST_PULSE_SOURCE=subscribed` to use
    /// `/pulses/subscribed?modified_since=...` (known to 504/timeout for many users).
    pub async fn fetch_otx_indicators(&self, api_key: &str) -> anyhow::Result<OtxIndicators> {
        let use_taxii = std::env::var("OTX_USE_TAXII")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false") && v != "off")
            .unwrap_or(true);
        if use_taxii {
            let collection = std::env::var("OTX_TAXII_COLLECTION")
                .unwrap_or_else(|_| "user_LevelBlue".to_string());
            return self.fetch_otx_taxii_indicators(api_key, &collection).await;
        }

        if offline_mode() {
            return Err(anyhow::anyhow!("Offline mode: skipping OTX fetch"));
        }

        let use_subscribed = std::env::var("OTX_REST_PULSE_SOURCE")
            .map(|v| v.eq_ignore_ascii_case("subscribed"))
            .unwrap_or(false);

        // Longer timeout when hitting the flaky `/subscribed` route.
        let read_secs: u64 = if use_subscribed { 120 } else { 90 };
        let otx_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(read_secs))
            .connect_timeout(std::time::Duration::from_secs(15))
            .user_agent("OpenOsoosi-Agent/1.0")
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        let mut out = OtxIndicators::default();

        let since = (chrono::Utc::now() - chrono::Duration::days(7))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();

        if use_subscribed {
            info!(
                "[OTX] REST: using /pulses/subscribed (modified_since={}) …",
                since
            );
        } else {
            info!("[OTX] REST: using /pulses/activity?limit=100 (set OTX_REST_PULSE_SOURCE=subscribed for legacy) …");
        }

        let mut attempts = 0;
        let mut response = None;
        let max_attempts = 5;
        while attempts < max_attempts {
            let req = if use_subscribed {
                otx_client
                    .get(OTX_PULSES_SUBSCRIBED_URL.trim_end_matches('/'))
                    .query(&[("limit", "100"), ("modified_since", &since)])
                    .header("X-OTX-API-KEY", api_key)
            } else {
                otx_client
                    .get(OTX_PULSES_ACTIVITY_URL)
                    .query(&[("limit", "100")])
                    .header("X-OTX-API-KEY", api_key)
            };
            match req.send().await {
                Ok(r) if r.status().is_success() => {
                    response = Some(r);
                    break;
                }
                Ok(r) => {
                    let status = r.status();
                    let code = status.as_u16();
                    if code == 401 {
                        warn!(
                            "[OTX] Attempt {} HTTP {} — check OTX_API_KEY is valid for AlienVault OTX.",
                            attempts + 1,
                            status
                        );
                    } else if matches!(code, 502 | 503 | 504) {
                        warn!(
                            "[OTX] Attempt {} HTTP {} — gateway/upstream error (often transient). Retrying...",
                            attempts + 1,
                            status
                        );
                    } else {
                        warn!(
                            "[OTX] Attempt {} failed with status {}. Retrying...",
                            attempts + 1,
                            status
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        "[OTX] Attempt {} network error: {}. Retrying...",
                        attempts + 1,
                        e
                    );
                }
            }
            attempts += 1;
            if attempts < max_attempts {
                let backoff = (2u64.pow(attempts as u32) * 1000) + (rand::random::<u64>() % 1000);
                tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
            }
        }
        let response = match response {
            Some(r) => r,
            None => {
                if use_subscribed {
                    warn!("[OTX] /pulses/subscribed failed after {max_attempts} attempts; falling back to /pulses/activity");
                    let r = otx_client
                        .get(OTX_PULSES_ACTIVITY_URL)
                        .query(&[("limit", "100")])
                        .header("X-OTX-API-KEY", api_key)
                        .send()
                        .await?;
                    if !r.status().is_success() {
                        anyhow::bail!(
                            "[OTX] subscribed + activity fallback failed: {}",
                            r.status()
                        );
                    }
                    r
                } else {
                    anyhow::bail!("[OTX] Failed to reach OTX REST API after {attempts} attempts. Will retry next cycle.");
                }
            }
        };

        let json_val: Value = match response.json().await {
            Ok(v) => v,
            Err(e) => {
                info!("[OTX] Failed to parse response: {}", e);
                return Ok(out);
            }
        };

        if let Some(results) = json_val.get("results").and_then(|v| v.as_array()) {
            for pulse in results {
                let adversary = pulse
                    .get("adversary")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let tags: Vec<&str> = pulse
                    .get("tags")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|t| t.as_str()).collect())
                    .unwrap_or_default();
                let tlp = pulse.get("tlp").and_then(|v| v.as_str()).unwrap_or("white");
                let has_indicators = pulse
                    .get("indicators")
                    .and_then(|v| v.as_array())
                    .map(|a| !a.is_empty())
                    .unwrap_or(false);

                // `subscribed`: keep previous strict "critical" gate. `activity` pulses often lack APT tags; allow any pulse that still ships indicators.
                let is_critical = !adversary.is_empty()
                    || tags.iter().any(|t| {
                        let lower = t.to_lowercase();
                        lower.contains("apt")
                            || lower.contains("ransomware")
                            || lower.contains("critical")
                            || lower.contains("0day")
                            || lower.contains("zero-day")
                            || lower.contains("targeted")
                            || lower.contains("nation-state")
                    })
                    || tlp == "red"
                    || tlp == "amber";

                if !is_critical {
                    if use_subscribed {
                        continue;
                    }
                    if !has_indicators {
                        continue;
                    }
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
                        } else if kind.contains("url")
                            || raw.starts_with("http://")
                            || raw.starts_with("https://")
                        {
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

        info!(
            "[OTX] Loaded {} critical indicators (IPs: {}, Domains: {}, URLs: {}, Hashes: {})",
            out.total_count(),
            out.ips.len(),
            out.domains.len(),
            out.urls.len(),
            out.hashes.len()
        );

        Ok(out)
    }

    /// Fetch latest NVD CVEs (Vulnerability metadata).
    ///
    /// NVD API 2.0 recommends an API key for higher rate limits.
    /// Returns a list of CVE results (structured like KEV for now).
    pub async fn fetch_nvd_cves(
        &self,
        api_key: Option<&str>,
    ) -> anyhow::Result<Vec<osoosi_types::Kev>> {
        if offline_mode() {
            return Err(anyhow::anyhow!("Offline mode: skipping NVD fetch"));
        }

        let now_dt = Utc::now();
        let since_dt = now_dt - chrono::Duration::days(3);
        let since = format!("{}Z", since_dt.format("%Y-%m-%dT%H:%M:%S.000"));
        let now = format!("{}Z", now_dt.format("%Y-%m-%dT%H:%M:%S.000"));

        info!("[NVD] Fetching recent CVEs (since {})...", since);

        let mut attempts = 0;
        let mut response = None;
        while attempts < 3 {
            let mut req = self.client.get(NVD_CVE_API_URL).query(&[
                ("resultsPerPage", "50"),
                ("lastModStartDate", &since),
                ("lastModEndDate", &now),
            ]);

            if let Some(key) = api_key {
                req = req.header("apiKey", key);
            }

            match req.send().await {
                Ok(r) if r.status().is_success() => {
                    response = Some(r);
                    break;
                }
                Ok(r) => {
                    let status = r.status();
                    warn!(
                        "[NVD] Attempt {} failed with status {}. Retrying...",
                        attempts + 1,
                        status
                    );
                }
                Err(e) => {
                    warn!(
                        "[NVD] Attempt {} network error: {}. Retrying...",
                        attempts + 1,
                        e
                    );
                }
            }
            attempts += 1;
            if attempts < 3 {
                tokio::time::sleep(std::time::Duration::from_secs(2u64.pow(attempts as u32))).await;
            }
        }

        let response = match response {
            Some(r) => r,
            None => {
                info!(
                    "[NVD] Failed to reach NVD API after {} attempts. Will retry next cycle.",
                    attempts
                );
                return Ok(Vec::new());
            }
        };

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
                    let id = cve
                        .get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
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
        let target = dest_dir
            .canonicalize()
            .unwrap_or_else(|_| dest_dir.to_path_buf());

        let disk = disks
            .iter()
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
    pub async fn download_and_extract_nsrl(
        &self,
        dest_dir: &std::path::Path,
    ) -> anyhow::Result<std::path::PathBuf> {
        // URLs to try in order — primary and fallback
        let urls = [
            "https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/rds_2026.03.1/RDS_2026.03.1_modern.zip",
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
                let preview = if body_preview.len() > 200 {
                    &body_preview[..200]
                } else {
                    &body_preview
                };
                info!("NSRL download returned HTTP {}: {}", status, preview);
                last_error = Some(anyhow::anyhow!(
                    "NSRL download returned HTTP {} for {}",
                    status,
                    url
                ));
                continue;
            }

            // Check content-type if available — ZIP should not be text/html or text/xml
            if let Some(ct) = response.headers().get(reqwest::header::CONTENT_TYPE) {
                if let Ok(ct_str) = ct.to_str() {
                    let ct_lower = ct_str.to_lowercase();
                    if ct_lower.contains("text/html")
                        || ct_lower.contains("text/xml")
                        || ct_lower.contains("application/xml")
                    {
                        info!(
                            "NSRL download returned unexpected content-type '{}' for {}",
                            ct_str, url
                        );
                        last_error = Some(anyhow::anyhow!(
                            "NSRL download returned non-ZIP content-type '{}' for {}",
                            ct_str,
                            url
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
                info!(
                    "Downloaded file is not a valid ZIP (bad magic bytes). Preview: {}",
                    preview
                );
                last_error = Some(anyhow::anyhow!(
                    "Downloaded file from {} is not a valid ZIP archive ({} bytes, bad magic)",
                    url,
                    bytes.len()
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
                        if !p.exists() {
                            std::fs::create_dir_all(p)?;
                        }
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
    pub async fn download_nsrl_streaming(
        &self,
        dest_dir: &std::path::Path,
    ) -> anyhow::Result<std::path::PathBuf> {
        use futures::StreamExt;
        use tokio::io::AsyncWriteExt;

        let urls = [
            "https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/rds_2026.03.1/RDS_2026.03.1_modern.zip",
            "https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/rds_2025.03.1/RDS_2025.03.1_modern.zip",
        ];

        if !dest_dir.exists() {
            std::fs::create_dir_all(dest_dir)?;
        }

        if let Err(e) = self.check_disk_space(dest_dir, 5) {
            error!("[NSRL] Disk check failed: {}", e);
            return Err(e);
        }

        let zip_path = dest_dir.join("nsrl_modern_stream.zip");
        let state_path = dest_dir.join("nsrl_modern_stream.state.json");

        let download_client = reqwest::Client::builder()
            .user_agent("OpenOsoosi-Agent/1.0")
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

            while !download_finished && retry_count < 5 {
                if retry_count > 0 {
                    let backoff = (15 * retry_count as u64).min(300);
                    info!(
                        "[NSRL Background] Retrying download in {}s (Attempt {})...",
                        backoff, retry_count
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
                }

                let current_size = if zip_path.exists() {
                    std::fs::metadata(&zip_path).map(|m| m.len()).unwrap_or(0)
                } else {
                    0
                };

                // Skip Range if we already have the full object (avoids S3 HTTP 416 when offset == file size).
                if current_size > 0 {
                    if let Some(remote_len) = nsrl_s3_content_length(&download_client, url).await {
                        if current_size > remote_len {
                            warn!(
                                "[NSRL Background] Local file ({current_size} B) is larger than remote ({remote_len} B). Removing stale partial."
                            );
                            let _ = std::fs::remove_file(&zip_path);
                            let _ = std::fs::remove_file(&state_path);
                            retry_count += 1;
                            continue;
                        }
                        if current_size == remote_len
                            && nsrl_local_zip_matches_complete(&zip_path, remote_len)
                        {
                            info!(
                                "[NSRL Background] Local ZIP already matches remote ({} B). Resuming to extract.",
                                remote_len
                            );
                            download_finished = true;
                            break;
                        }
                    }
                }

                let mut request = download_client.get(*url);
                if current_size > 0 {
                    request = request.header("Range", format!("bytes={}-", current_size));
                    info!("[NSRL Background] RESUMING: Found existing file ({:.2} GB). Requesting remaining bytes from offset {}...", 
                        current_size as f64 / 1_073_741_824.0, current_size);
                } else {
                    info!(
                        "[NSRL Background] Starting fresh streaming download from {}...",
                        url
                    );
                }

                let response = match request.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        error!("[NSRL Background] Request failed: {}", e);
                        last_error = Some(e.into());
                        retry_count += 1;
                        continue;
                    }
                };

                let status = response.status();
                if !status.is_success() {
                    if status == reqwest::StatusCode::FORBIDDEN
                        || status == reqwest::StatusCode::NOT_FOUND
                    {
                        warn!(
                            "[NSRL Background] URL returned {}. Skipping to next URL.",
                            status
                        );
                        break;
                    }
                    // Range past EOF: treat as "already have full file" or delete stale partial and retry.
                    if status == reqwest::StatusCode::RANGE_NOT_SATISFIABLE {
                        warn!(
                            "[NSRL Background] HTTP 416 for {} (range not satisfiable). Verifying local copy…",
                            url
                        );
                        let local_len = std::fs::metadata(&zip_path).map(|m| m.len()).unwrap_or(0);
                        if let Some(remote_len) =
                            nsrl_s3_content_length(&download_client, url).await
                        {
                            if local_len == remote_len
                                && nsrl_local_zip_matches_complete(&zip_path, remote_len)
                            {
                                info!("[NSRL Background] Local file is complete; continuing to extract.");
                                download_finished = true;
                                break;
                            }
                        } else if local_len > 0 && nsrl_local_zip_valid(&zip_path) {
                            info!(
                                "[NSRL Background] ZIP validates after 416; continuing to extract."
                            );
                            download_finished = true;
                            break;
                        }
                        warn!("[NSRL Background] Discarding partial/stale download and starting over.");
                        let _ = std::fs::remove_file(&zip_path);
                        let _ = std::fs::remove_file(&state_path);
                        retry_count += 1;
                        continue;
                    }
                    error!("[NSRL Background] HTTP {} for {}.", status, url);
                    last_error = Some(anyhow::anyhow!("HTTP error {}", status));
                    retry_count += 1;
                    continue;
                }

                let is_partial = status == reqwest::StatusCode::PARTIAL_CONTENT;
                let content_len = response.content_length().unwrap_or(0);
                let total_size = if is_partial {
                    content_len + current_size
                } else {
                    content_len
                };

                let mut stream = response.bytes_stream();
                let mut first_chunk = None;

                // VALIDATION: Check magic bytes if starting fresh
                if current_size == 0 {
                    if let Some(Ok(chunk)) = stream.next().await {
                        if !chunk.starts_with(b"PK\x03\x04") {
                            error!("[NSRL Background] Download is NOT a valid ZIP (Magic mismatch). Likely an S3 error page.");
                            last_error = Some(anyhow::anyhow!("Invalid ZIP magic"));
                            break;
                        }
                        first_chunk = Some(chunk);
                    }
                }

                let mut file = match tokio::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .append(true)
                    .open(&zip_path)
                    .await
                {
                    Ok(f) => {
                        if !is_partial && current_size > 0 {
                            let _ = f.set_len(0).await;
                        }
                        f
                    }
                    Err(e) => {
                        error!("[NSRL Background] File error: {}", e);
                        last_error = Some(e.into());
                        break;
                    }
                };

                if let Some(ref chunk) = first_chunk {
                    if let Err(e) = file.write_all(chunk).await {
                        error!("[NSRL Background] Write error: {}", e);
                        break;
                    }
                }

                let mut downloaded = if is_partial {
                    current_size
                } else {
                    first_chunk.as_ref().map(|c| c.len() as u64).unwrap_or(0)
                };
                let mut last_log_pct = 0;
                let mut stream_error = false;

                while let Some(item) = stream.next().await {
                    let chunk = match item {
                        Ok(c) => c,
                        Err(e) => {
                            error!("[NSRL Background] Stream error: {}", e);
                            stream_error = true;
                            break;
                        }
                    };

                    if let Err(e) = file.write_all(&chunk).await {
                        error!("[NSRL Background] Write error: {}", e);
                        stream_error = true;
                        break;
                    }

                    downloaded += chunk.len() as u64;
                    if downloaded % (512 * 1024 * 1024) < (chunk.len() as u64) {
                        let _ = std::fs::write(
                            &state_path,
                            serde_json::json!({"bytes_written": downloaded}).to_string(),
                        );
                    }

                    if total_size > 0 {
                        let pct = (downloaded * 100) / total_size;
                        if pct >= last_log_pct + 10 {
                            last_log_pct = pct;
                            info!(
                                "[NSRL Background] Progress: {}% ({:.1} GB / {:.1} GB)",
                                pct,
                                downloaded as f64 / 1e9,
                                total_size as f64 / 1e9
                            );
                        }
                    }
                }

                let _ = file.flush().await;

                if !stream_error {
                    download_finished = true;
                    last_error = None;
                } else {
                    retry_count += 1;
                    if downloaded <= last_processed_size {
                        stalled_count += 1;
                    } else {
                        stalled_count = 0;
                        last_processed_size = downloaded;
                    }
                    if stalled_count > 3 {
                        break;
                    }
                }
            }

            if download_finished {
                info!("[NSRL Background] Download complete. Extracting...");
                let dest_clone = dest_dir.to_path_buf();
                let zip_clone = zip_path.clone();

                let res = tokio::task::spawn_blocking(move || {
                    let f = std::fs::File::open(&zip_clone)?;
                    let mut zip = zip::ZipArchive::new(f)?;
                    let mut db = None;
                    for i in 0..zip.len() {
                        let mut entry = zip.by_index(i)?;
                        let out = dest_clone.join(entry.name());
                        if entry.name().ends_with('/') {
                            std::fs::create_dir_all(&out)?;
                        } else {
                            if let Some(p) = out.parent() {
                                if !p.exists() {
                                    std::fs::create_dir_all(p)?;
                                }
                            }
                            let mut outfile = std::fs::File::create(&out)?;
                            std::io::copy(&mut entry, &mut outfile)?;
                            if out.extension().and_then(|s| s.to_str()) == Some("db") {
                                db = Some(out);
                            }
                        }
                    }
                    let _ = std::fs::remove_file(&zip_clone);
                    db.ok_or_else(|| anyhow::anyhow!("No DB found"))
                })
                .await?;

                return res;
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("All URLs and retries exhausted")))
    }

    /// Check NIST S3 bucket for newer NSRL RDS versions and deltas.
    /// Returns a list of (version, url, is_delta) tuples found that are newer
    /// than `current_version` (e.g. "2025.03.1").
    pub async fn check_nsrl_updates(
        &self,
        current_version: &str,
    ) -> anyhow::Result<Vec<(String, String, bool)>> {
        let bucket_url = "https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/";

        let download_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        info!(
            "[NSRL Update Check] Checking for updates newer than {}...",
            current_version
        );

        let response = download_client.get(bucket_url).send().await?;
        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Failed to list NSRL bucket: HTTP {}",
                response.status()
            ));
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
            if self.version_is_newer(&version, current_version) {
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
                let delta_exists = download_client
                    .head(&delta_url)
                    .send()
                    .await
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
            info!(
                "[NSRL Update Check] No updates found. Current version {} is up to date.",
                current_version
            );
        } else {
            info!(
                "[NSRL Update Check] Found {} update(s) newer than v{}",
                updates.len(),
                current_version
            );
        }

        Ok(updates)
    }

    /// Compare two NSRL version strings of the form "YYYY.MM.V".
    /// Returns true if `candidate` is newer than `current`.
    fn version_is_newer(&self, candidate: &str, current: &str) -> bool {
        let parse = |v: &str| -> (u32, u32, u32) {
            let parts: Vec<&str> = v.split('.').collect();
            let year = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
            let month = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            let patch = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            (year, month, patch)
        };
        parse(candidate) > parse(current)
    }

    /// Fetch OTX indicators via TAXII 1.1 (uses `otx_taxii` — same as `otx-taxii-rs.exe`: correct
    /// `Accept` + `X-TAXII-*` headers and HTTPS protocol URN for AlienVault OTX).
    pub async fn fetch_otx_taxii_indicators(
        &self,
        api_key: &str,
        collection: &str,
    ) -> anyhow::Result<OtxIndicators> {
        info!(
            "[OTX TAXII] Polling collection '{}' (shared otx_taxii client)...",
            collection
        );

        if offline_mode() {
            return Err(anyhow::anyhow!("Offline mode: skipping OTX TAXII fetch"));
        }

        let api_key = api_key.to_string();
        let collection = collection.to_string();

        let xml = tokio::task::spawn_blocking(move || -> anyhow::Result<String> {
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(120))
                .connect_timeout(std::time::Duration::from_secs(30))
                .user_agent("OpenOsoosi-Agent/1.0 (otx_taxii)")
                .build()?;
            let begin = chrono::Utc::now() - chrono::Duration::hours(24);
            let body = otx_taxii::poll_request(&collection, begin);
            otx_taxii::post_taxii(&client, otx_taxii::OTX_POLL_URL, &api_key, &body)
                .map_err(|e| anyhow::anyhow!("{}", e))
        })
        .await
        .map_err(|e| anyhow::anyhow!("[OTX TAXII] join error: {e}"))??;

        if xml.contains("status_type=\"FAILURE\"") || xml.contains("Status_Type=\"FAILURE\"") {
            anyhow::bail!("[OTX TAXII] Server returned TAXII FAILURE status in body (check collection name and API key).");
        }

        let mut out = OtxIndicators::default();
        for ind in otx_taxii::extract_indicators(&xml) {
            let v = ind.value.to_lowercase();
            match ind.indicator_type.as_str() {
                "ipv4" => {
                    out.ips.insert(v);
                }
                "md5" | "sha1" | "sha256" => {
                    out.hashes.insert(v);
                }
                "url" => {
                    out.urls.insert(v);
                }
                "domain" | "email" => {
                    out.domains.insert(v);
                }
                _ => {}
            }
        }

        info!(
            "[OTX TAXII] Loaded {} indicators from TAXII feed.",
            out.total_count()
        );
        Ok(out)
    }
}
