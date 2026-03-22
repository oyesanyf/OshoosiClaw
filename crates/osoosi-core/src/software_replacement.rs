//! Software replacement: search for vuln-free version and replace compromised binaries.
//! Config maps basename -> source descriptor (e.g. github:owner/repo). No hardcoded URLs.
//! At runtime we resolve the source to find the actual download URL.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;
use std::sync::RwLock;
use std::time::Duration;

static SOURCE_MAP: RwLock<Option<HashMap<String, String>>> = RwLock::new(None);

fn replacement_config_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("OSOOSI_SOFTWARE_REPLACEMENT") {
        let path = std::path::PathBuf::from(p.trim());
        if !path.as_os_str().is_empty() {
            return path;
        }
    }
    // Find config: same dir as osoosi.toml, or config/ relative to cwd
    if let Some(config_file) = osoosi_types::resolve_config_path() {
        if let Some(parent) = config_file.parent() {
            let candidate = parent.join("software_replacement.txt");
            if candidate.exists() {
                return candidate;
            }
            let candidate = parent.join("config").join("software_replacement.txt");
            if candidate.exists() {
                return candidate;
            }
        }
    }
    std::path::PathBuf::from("config").join("software_replacement.txt")
}

fn replacement_config_url() -> Option<String> {
    std::env::var("OSOOSI_SOFTWARE_REPLACEMENT_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
}

fn replacement_auto_update_enabled() -> bool {
    std::env::var("OSOOSI_SOFTWARE_REPLACEMENT_AUTO_UPDATE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true)
}

/// Load source map from file. Format: `basename|source`. # = comment.
/// Source examples: github:owner/repo, url:https://...
fn load_source_map_from_file(path: &Path) -> HashMap<String, String> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return HashMap::new(),
    };
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or(line).trim();
        if line.is_empty() {
            continue;
        }
        if let Some((key, val)) = line.split_once('|') {
            let key = key.trim().to_lowercase();
            let val = val.trim().to_string();
            if !key.is_empty() && !val.is_empty() {
                map.insert(key, val);
            }
        }
    }
    map
}

async fn fetch_and_save_config(url: &str, path: &std::path::Path) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("Osoosi-SoftwareReplacement/0.1")
        .build()?;
    let body = client.get(url).send().await?.text().await?;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(path, body)?;
    Ok(())
}

/// Refresh source map: fetch from URL if set (auto-update), save to file, then load.
pub async fn refresh_software_replacement_map() {
    let path = replacement_config_path();
    if replacement_auto_update_enabled() {
        if let Some(url) = replacement_config_url() {
            if let Err(e) = fetch_and_save_config(&url, &path).await {
                tracing::warn!(
                    "Software replacement config auto-update failed: {} (using existing file)",
                    e
                );
            }
        }
    }
    let map = load_source_map_from_file(&path);
    if !map.is_empty() {
        if let Ok(mut guard) = SOURCE_MAP.write() {
            *guard = Some(map.clone());
        }
        tracing::info!(
            "Software replacement config loaded: {} binary(ies) (search-and-replace on malware)",
            map.len()
        );
    }
}

/// Get source descriptor for a basename. Returns None if not in config.
fn get_source_for_basename(basename: &str) -> Option<String> {
    let key = basename.trim().to_lowercase();
    if key.is_empty() {
        return None;
    }
    if let Ok(guard) = SOURCE_MAP.read() {
        if let Some(ref map) = *guard {
            return map.get(&key).cloned();
        }
    }
    None
}

/// Resolve source to actual download URL by searching (GitHub API, etc.). No hardcoded URLs.
async fn resolve_source_to_url(basename: &str, source: &str) -> Result<Option<String>> {
    let source = source.trim();
    if source.is_empty() {
        return Ok(None);
    }
    // Direct URL: url:https://...
    if let Some(url) = source.strip_prefix("url:") {
        let url = url.trim();
        if url.starts_with("https://") || url.starts_with("http://") {
            return Ok(Some(url.to_string()));
        }
    }
    // GitHub releases: github:owner/repo or github:owner/repo:asset_filter
    if let Some(rest) = source.strip_prefix("github:") {
        let (repo, filter): (&str, Option<&str>) = match rest.split_once(':') {
            Some((r, f)) => (r.trim(), Some(f.trim())),
            None => (rest.trim(), None),
        };
        if repo.is_empty() {
            return Ok(None);
        }
        return resolve_github_release(repo, basename, filter).await;
    }
    Ok(None)
}

/// Query GitHub API for latest release and find matching asset.
async fn resolve_github_release(
    repo: &str,
    target_basename: &str,
    asset_filter: Option<&str>,
) -> Result<Option<String>> {
    let parts: Vec<&str> = repo.split('/').collect();
    if parts.len() < 2 {
        return Ok(None);
    }
    let owner = parts[0];
    let repo_name = parts[1];
    let api_url = format!(
        "https://api.github.com/repos/{}/{}/releases/latest",
        owner, repo_name
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("Osoosi-SoftwareReplacement/0.1")
        .build()
        .context("build reqwest client")?;
    let resp = client.get(&api_url).send().await?;
    if !resp.status().is_success() {
        tracing::warn!("GitHub API failed for {}: {}", api_url, resp.status());
        return Ok(None);
    }
    let json: serde_json::Value = resp.json().await?;
    let assets = match json.get("assets").and_then(|a| a.as_array()) {
        Some(a) => a,
        None => return Ok(None),
    };
    let target_lower = target_basename.to_lowercase();
    let ext = Path::new(target_basename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    for asset in assets {
        let name = asset.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let url = asset.get("browser_download_url")
            .and_then(|u| u.as_str())
            .unwrap_or("");
        if url.is_empty() {
            continue;
        }
        let name_lower = name.to_lowercase();
        let matches = if let Some(filter) = asset_filter {
            name_lower.contains(&filter.to_lowercase())
        } else {
            name_lower.ends_with(&target_lower)
                || (ext.len() > 0 && name_lower.ends_with(&format!(".{}", ext)))
        };
        if matches {
            return Ok(Some(url.to_string()));
        }
    }
    Ok(None)
}

/// Search for vuln-free version and return download URL. Resolves at runtime, no hardcoded URLs.
pub async fn resolve_replacement_url(file_path: &str) -> Option<String> {
    let basename = Path::new(file_path)
        .file_name()
        .and_then(|n| n.to_str())?;
    let source = get_source_for_basename(basename)?;
    match resolve_source_to_url(basename, &source).await {
        Ok(Some(url)) => Some(url),
        Ok(None) => {
            tracing::debug!("No download URL resolved for {} (source: {})", basename, source);
            None
        }
        Err(e) => {
            tracing::warn!("Failed to resolve replacement URL for {}: {}", basename, e);
            None
        }
    }
}
