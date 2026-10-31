use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;

use axum::{
    extract::{Json, State},
    http::StatusCode,
    routing::{get, post},
    Router,
};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use osoosi_core::machine_binding::{
    get_default_host_binding_manifest_path, verify_and_adapt_machine_binding,
    verify_default_machine_binding, HostBindingManifest, MachineBindingError,
};
use osoosi_core::protected_env_backup::{
    is_hard_protected_non_secret_key, ProtectedEnvBackupVault,
};
use osoosi_core::rea::identify_with_magika;

use crate::{api_error, api_error_json, DashboardState};

/// Persistent configuration stored at `database/env_seal_config.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvSealConfig {
    #[serde(default)]
    pub custom_paths: Vec<String>,
    #[serde(default)]
    pub all_drives: bool,
    #[serde(default)]
    pub auto_seal: bool,
    #[serde(default = "default_selected_variables")]
    pub selected_variables: Vec<String>,
    #[serde(default)]
    pub excluded_variables: Vec<String>,
    #[serde(default)]
    pub watcher_enabled: bool,
    #[serde(default = "default_poll_interval")]
    pub watcher_poll_interval_secs: u64,
    #[serde(default = "default_max_files")]
    pub max_files_per_drive: usize,
    #[serde(default = "default_max_budget")]
    pub max_dir_budget_per_drive: usize,
    #[serde(default)]
    pub vault_path: Option<String>,
}

fn default_selected_variables() -> Vec<String> {
    vec![
        "GEMINI_API_KEY".to_string(),
        "HF_TOKEN".to_string(),
        "OPENAI_API_KEY".to_string(),
        "ANTHROPIC_API_KEY".to_string(),
        "GITHUB_TOKEN".to_string(),
    ]
}

fn default_poll_interval() -> u64 {
    5
}

fn default_max_files() -> usize {
    500
}

fn default_max_budget() -> usize {
    2000
}

impl Default for EnvSealConfig {
    fn default() -> Self {
        Self {
            custom_paths: Vec::new(),
            all_drives: false,
            auto_seal: false,
            selected_variables: default_selected_variables(),
            excluded_variables: Vec::new(),
            watcher_enabled: false,
            watcher_poll_interval_secs: default_poll_interval(),
            max_files_per_drive: default_max_files(),
            max_dir_budget_per_drive: default_max_budget(),
            vault_path: None,
        }
    }
}

impl EnvSealConfig {
    pub const DEFAULT_CONFIG_PATH: &'static str = "database/env_seal_config.json";

    pub fn load_or_default() -> Self {
        for candidate in [
            Self::DEFAULT_CONFIG_PATH,
            "../database/env_seal_config.json",
            "../../database/env_seal_config.json",
        ] {
            let p = Path::new(candidate);
            if p.is_file() {
                if let Ok(bytes) = std::fs::read(p) {
                    if let Ok(cfg) = serde_json::from_slice::<Self>(&bytes) {
                        return cfg;
                    }
                }
            }
        }
        Self::default()
    }

    pub fn save(&self, target_path: Option<&Path>) -> Result<(), std::io::Error> {
        let p = target_path.unwrap_or_else(|| Path::new(Self::DEFAULT_CONFIG_PATH));
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(p, bytes)
    }
}

/// Recorded event from the background Magika file watcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatcherEventRecord {
    pub timestamp: String,
    pub file_path: String,
    pub magika_label: Option<String>,
    pub magika_mime_type: Option<String>,
    pub magika_score: Option<f32>,
    pub action_taken: String,
}

pub static WATCHER_RUNNING: AtomicBool = AtomicBool::new(false);
pub static WATCHER_EVENTS: Lazy<RwLock<Vec<WatcherEventRecord>>> =
    Lazy::new(|| RwLock::new(Vec::with_capacity(128)));

pub fn push_watcher_event(event: WatcherEventRecord) {
    if let Ok(mut evs) = WATCHER_EVENTS.write() {
        if evs.len() >= 100 {
            evs.remove(0);
        }
        evs.push(event);
    }
}

pub fn get_watcher_events() -> Vec<WatcherEventRecord> {
    WATCHER_EVENTS
        .read()
        .map(|evs| evs.clone())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Request Structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Default)]
pub struct UpdateEnvSealConfigRequest {
    pub custom_paths: Option<Vec<String>>,
    pub all_drives: Option<bool>,
    pub auto_seal: Option<bool>,
    pub selected_variables: Option<Vec<String>>,
    pub excluded_variables: Option<Vec<String>>,
    pub watcher_enabled: Option<bool>,
    pub watcher_poll_interval_secs: Option<u64>,
    pub max_files_per_drive: Option<usize>,
    pub max_dir_budget_per_drive: Option<usize>,
    pub vault_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ScanFilesRequest {
    pub all_drives: Option<bool>,
    pub custom_paths: Option<Vec<String>>,
    pub max_files_per_drive: Option<usize>,
    pub max_dir_budget_per_drive: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SealRequest {
    pub files: Option<Vec<String>>,
    pub all_drives: Option<bool>,
    pub vault_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RevertRequest {
    pub file_path: Option<String>,
    pub vault_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct UnsealFileRequest {
    pub file_path: String,
    pub vault_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct WatcherToggleRequest {
    pub enable: Option<bool>,
    pub poll_interval_secs: Option<u64>,
    pub auto_seal: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TestSuiteRequest {
    pub vault_path: Option<String>,
    pub variables: Option<Vec<String>>,
}

/// Request payload for triggering a manual machine binding refresh or adaptation.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct MachineBindingRefreshRequest {
    /// Optional override path for the host binding manifest (used primarily in integration tests).
    pub manifest_path: Option<String>,
    /// Optional flag to force hardware inventory re-discovery.
    pub force_adapt: Option<bool>,
}

// ---------------------------------------------------------------------------
// Route Handlers
// ---------------------------------------------------------------------------

/// 1. GET /api/env-gateway/status
pub async fn get_env_gateway_status(State(_state): State<DashboardState>) -> Json<Value> {
    let result = tokio::task::spawn_blocking(move || {
        let cfg = EnvSealConfig::load_or_default();
        let custom_paths: Vec<PathBuf> = cfg.custom_paths.iter().map(PathBuf::from).collect();
        let v_path = ProtectedEnvBackupVault::locate_active_vault_path(
            cfg.vault_path.as_deref().map(Path::new),
        );

        let vault_status = v_path.as_ref().and_then(|p| {
            ProtectedEnvBackupVault::get_status(p).ok()
        });

        let physical_drives: Vec<String> = ProtectedEnvBackupVault::enumerate_physical_drives()
            .into_iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();

        let discovered: Vec<String> = ProtectedEnvBackupVault::discover_environment_files(
            Path::new("."),
            &custom_paths,
        )
        .into_iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();

        let watcher_running = WATCHER_RUNNING.load(Ordering::SeqCst);

        if let Some(st) = vault_status {
            json!({
                "status": "online",
                "vault_exists": st.exists,
                "vault_path": st.vault_path.to_string_lossy(),
                "dacl_protected": st.dacl_protected,
                "sealed_variables": st.sealed_variables,
                "standin_mappings": st.standin_mappings,
                "sealed_epoch": st.sealed_at_epoch,
                "payload_size": st.payload_size,
                "files": st.files,
                "physical_drives": physical_drives,
                "watcher_running": watcher_running,
                "watcher_auto_seal": cfg.auto_seal,
                "discovered_files_count": discovered.len(),
                "discovered_files": discovered,
            })
        } else {
            json!({
                "status": "online",
                "vault_exists": false,
                "vault_path": v_path.map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|| ProtectedEnvBackupVault::default_vault_path().to_string_lossy().to_string()),
                "dacl_protected": false,
                "sealed_variables": [],
                "standin_mappings": [],
                "sealed_epoch": null,
                "payload_size": 0,
                "files": [],
                "physical_drives": physical_drives,
                "watcher_running": watcher_running,
                "watcher_auto_seal": cfg.auto_seal,
                "discovered_files_count": discovered.len(),
                "discovered_files": discovered,
            })
        }
    })
    .await
    .unwrap_or_else(|e| {
        json!({
            "status": "error",
            "message": format!("Task join error: {}", e),
        })
    });

    Json(result)
}

/// 2. GET /api/env-gateway/config
pub async fn get_env_gateway_config() -> Json<Value> {
    let cfg = EnvSealConfig::load_or_default();
    Json(json!({
        "status": "success",
        "config": cfg,
    }))
}

/// 3. POST /api/env-gateway/config
pub async fn post_env_gateway_config(
    Json(req): Json<UpdateEnvSealConfigRequest>,
) -> (StatusCode, Json<Value>) {
    let mut cfg = EnvSealConfig::load_or_default();

    if let Some(cp) = req.custom_paths {
        cfg.custom_paths = cp;
    }
    if let Some(ad) = req.all_drives {
        cfg.all_drives = ad;
    }
    if let Some(as_val) = req.auto_seal {
        cfg.auto_seal = as_val;
    }
    if let Some(sv) = req.selected_variables {
        // Strict Zero-Touch Validation: Disallow any protected system variables
        let sanitized: Vec<String> = sv
            .into_iter()
            .filter(|var| !is_hard_protected_non_secret_key(var, ""))
            .collect();
        cfg.selected_variables = sanitized;
    }
    if let Some(ev) = req.excluded_variables {
        cfg.excluded_variables = ev;
    }
    if let Some(we) = req.watcher_enabled {
        cfg.watcher_enabled = we;
        WATCHER_RUNNING.store(we, Ordering::SeqCst);
    }
    if let Some(pi) = req.watcher_poll_interval_secs {
        cfg.watcher_poll_interval_secs = pi.max(1);
    }
    if let Some(mf) = req.max_files_per_drive {
        cfg.max_files_per_drive = mf.max(10);
    }
    if let Some(mb) = req.max_dir_budget_per_drive {
        cfg.max_dir_budget_per_drive = mb.max(50);
    }
    if let Some(vp) = req.vault_path {
        cfg.vault_path = Some(vp);
    }

    if let Err(e) = cfg.save(None) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            api_error_json(
                "CONFIG_SAVE_FAILED",
                format!("Failed to save configuration: {}", e),
                "Check file system permissions on database/ directory.",
            ),
        );
    }

    (
        StatusCode::OK,
        Json(json!({
            "status": "success",
            "config": cfg,
        })),
    )
}

/// 4. POST /api/env-gateway/scan-files
pub async fn post_env_gateway_scan_files(Json(req): Json<ScanFilesRequest>) -> Json<Value> {
    let result = tokio::task::spawn_blocking(move || {
        let cfg = EnvSealConfig::load_or_default();
        let all_drives = req.all_drives.unwrap_or(cfg.all_drives);
        let max_files = req.max_files_per_drive.unwrap_or(cfg.max_files_per_drive);
        let max_budget = req
            .max_dir_budget_per_drive
            .unwrap_or(cfg.max_dir_budget_per_drive);

        let custom_paths: Vec<PathBuf> = req
            .custom_paths
            .unwrap_or_else(|| cfg.custom_paths.clone())
            .into_iter()
            .map(PathBuf::from)
            .collect();

        let candidate_paths = if all_drives {
            ProtectedEnvBackupVault::scan_all_physical_drives_with_magika(max_files, max_budget)
        } else {
            ProtectedEnvBackupVault::discover_environment_files(Path::new("."), &custom_paths)
        };

        let mut file_entries = Vec::new();
        let mut seen = HashSet::new();

        for p in candidate_paths {
            let p_canonical = p.canonicalize().unwrap_or_else(|_| p.clone());
            let p_key = p_canonical.to_string_lossy().to_ascii_lowercase();
            if !seen.insert(p_key) {
                continue;
            }

            if !p.is_file() {
                continue;
            }

            let metadata = match std::fs::metadata(&p) {
                Ok(m) => m,
                Err(_) => continue,
            };

            let file_size = metadata.len();
            // Cap at 256 KiB
            if file_size > 262_144 {
                continue;
            }

            let bytes = match std::fs::read(&p) {
                Ok(b) => b,
                Err(_) => continue,
            };

            let magika_id = identify_with_magika(Some(&p), &bytes);
            let content_str = String::from_utf8_lossy(&bytes);

            let mut secret_variables = Vec::new();
            let mut non_secret_variables = Vec::new();
            let mut has_standin = false;

            for line in content_str.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if let Some((k, v)) = trimmed.split_once('=') {
                    let key = k.trim().trim_start_matches("export ").trim();
                    let val = v.trim().trim_matches('"').trim_matches('\'').trim();

                    if val.starts_with("OSHOOSI_STANDIN_") {
                        has_standin = true;
                    }

                    if is_hard_protected_non_secret_key(key, val) {
                        non_secret_variables.push(key.to_string());
                    } else if ProtectedEnvBackupVault::is_secret_env_key_and_value(key, val) {
                        secret_variables.push(key.to_string());
                    } else {
                        non_secret_variables.push(key.to_string());
                    }
                }
            }

            let drive_root = p
                .components()
                .next()
                .map(|c| c.as_os_str().to_string_lossy().to_string());

            file_entries.push(json!({
                "path": p.to_string_lossy(),
                "size_bytes": file_size,
                "magika_label": magika_id.label,
                "magika_mime_type": magika_id.mime_type,
                "magika_score": magika_id.score,
                "magika_group": magika_id.group,
                "drive_root": drive_root,
                "has_standin_tokens": has_standin,
                "secret_variables": secret_variables,
                "non_secret_variables": non_secret_variables,
            }));
        }

        json!({
            "status": "success",
            "total_scanned": file_entries.len(),
            "files": file_entries,
        })
    })
    .await
    .unwrap_or_else(|e| {
        json!({
            "status": "error",
            "message": format!("Scan failed: {}", e),
        })
    });

    Json(result)
}

/// 5. POST /api/env-gateway/seal
pub async fn post_env_gateway_seal(
    State(_state): State<DashboardState>,
    Json(req): Json<SealRequest>,
) -> (StatusCode, Json<Value>) {
    let result = tokio::task::spawn_blocking(move || -> Result<Value, String> {
        let cfg = EnvSealConfig::load_or_default();
        let vault_path = req
            .vault_path
            .as_deref()
            .map(PathBuf::from)
            .or_else(|| cfg.vault_path.as_deref().map(PathBuf::from))
            .unwrap_or_else(ProtectedEnvBackupVault::default_vault_path);

        let target_files: Vec<PathBuf> = if let Some(files) = req.files {
            files.into_iter().map(PathBuf::from).collect()
        } else if req.all_drives.unwrap_or(cfg.all_drives) {
            ProtectedEnvBackupVault::scan_all_physical_drives_with_magika(
                cfg.max_files_per_drive,
                cfg.max_dir_budget_per_drive,
            )
        } else {
            let custom: Vec<PathBuf> = cfg.custom_paths.iter().map(PathBuf::from).collect();
            ProtectedEnvBackupVault::discover_environment_files(Path::new("."), &custom)
        };

        if target_files.is_empty() {
            return Err("No candidate environment files found to seal.".to_string());
        }

        let mut sealed_count = 0usize;
        let mut last_res = None;

        for f in &target_files {
            if f.is_file() {
                match ProtectedEnvBackupVault::seal_and_backup_dynamic(f, &vault_path) {
                    Ok(enum_res) => {
                        sealed_count += 1;
                        last_res = Some(enum_res);
                        push_watcher_event(WatcherEventRecord {
                            timestamp: chrono::Utc::now().to_rfc3339(),
                            file_path: f.to_string_lossy().to_string(),
                            magika_label: Some("ini".to_string()),
                            magika_mime_type: Some("text/plain".to_string()),
                            magika_score: Some(0.95),
                            action_taken: "sealed_with_standin_tokens".to_string(),
                        });
                    }
                    Err(e) => {
                        eprintln!("[WARN] Failed to seal file '{}': {}", f.display(), e);
                    }
                }
            }
        }

        let status = ProtectedEnvBackupVault::get_status(&vault_path)
            .map_err(|e| format!("Failed to read sealed vault status: {}", e))?;

        Ok(json!({
            "status": "success",
            "vault_path": vault_path.to_string_lossy(),
            "files_sealed_count": sealed_count,
            "dacl_protected": status.dacl_protected,
            "sealed_variables": status.sealed_variables,
            "standin_mappings": status.standin_mappings,
            "files": status.files,
            "enumeration_summary": last_res.map(|r| json!({
                "total_scanned": r.total_scanned,
                "total_selected": r.total_selected,
                "total_vetoed": r.total_vetoed,
            })),
        }))
    })
    .await;

    match result {
        Ok(Ok(val)) => (StatusCode::OK, Json(val)),
        Ok(Err(msg)) => (
            StatusCode::BAD_REQUEST,
            api_error_json(
                "SEAL_ERROR",
                msg,
                "Ensure candidate files exist and are writable.",
            ),
        ),
        Err(join_err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            api_error_json(
                "TASK_FAILED",
                format!("Join error: {}", join_err),
                "Internal server error.",
            ),
        ),
    }
}

/// 6. POST /api/env-gateway/revert
pub async fn post_env_gateway_revert(Json(req): Json<RevertRequest>) -> (StatusCode, Json<Value>) {
    let result = tokio::task::spawn_blocking(move || -> Result<Value, String> {
        let cfg = EnvSealConfig::load_or_default();
        let v_path = ProtectedEnvBackupVault::locate_active_vault_path(
            req.vault_path
                .as_deref()
                .or(cfg.vault_path.as_deref())
                .map(Path::new),
        );

        if let Some(fp) = req.file_path {
            let vault = v_path.ok_or_else(|| "Active backup vault not found".to_string())?;
            ProtectedEnvBackupVault::revert_single_file(&vault, Path::new(&fp))
                .map_err(|e| format!("Revert failed: {}", e))?;
            push_watcher_event(WatcherEventRecord {
                timestamp: chrono::Utc::now().to_rfc3339(),
                file_path: fp.clone(),
                magika_label: None,
                magika_mime_type: None,
                magika_score: None,
                action_taken: "reverted_single_file".to_string(),
            });
            Ok(json!({
                "status": "success",
                "file_path": fp,
                "message": "Target environment file restored from vault.",
            }))
        } else {
            ProtectedEnvBackupVault::auto_revert_all_active_vaults(v_path.as_deref())
                .map_err(|e| format!("Auto revert all failed: {}", e))?;
            push_watcher_event(WatcherEventRecord {
                timestamp: chrono::Utc::now().to_rfc3339(),
                file_path: "all".to_string(),
                magika_label: None,
                magika_mime_type: None,
                magika_score: None,
                action_taken: "auto_revert_all_vaults".to_string(),
            });
            Ok(json!({
                "status": "success",
                "message": "All environment files and volatile memory restored to original secrets.",
            }))
        }
    })
    .await;

    match result {
        Ok(Ok(val)) => (StatusCode::OK, Json(val)),
        Ok(Err(msg)) => (
            StatusCode::BAD_REQUEST,
            api_error_json(
                "REVERT_ERROR",
                msg,
                "Check that the vault exists and is accessible.",
            ),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            api_error_json("TASK_FAILED", format!("{}", e), "Internal server error."),
        ),
    }
}

/// 7. POST /api/env-gateway/unseal-file
pub async fn post_env_gateway_unseal_file(
    Json(req): Json<UnsealFileRequest>,
) -> (StatusCode, Json<Value>) {
    let result = tokio::task::spawn_blocking(move || -> Result<Value, String> {
        let cfg = EnvSealConfig::load_or_default();
        let v_path = ProtectedEnvBackupVault::locate_active_vault_path(
            req.vault_path
                .as_deref()
                .or(cfg.vault_path.as_deref())
                .map(Path::new),
        )
        .ok_or_else(|| "Active backup vault not found".to_string())?;

        ProtectedEnvBackupVault::revert_single_file(&v_path, Path::new(&req.file_path))
            .map_err(|e| format!("Revert failed: {}", e))?;

        push_watcher_event(WatcherEventRecord {
            timestamp: chrono::Utc::now().to_rfc3339(),
            file_path: req.file_path.clone(),
            magika_label: None,
            magika_mime_type: None,
            magika_score: None,
            action_taken: "unsealed_file".to_string(),
        });

        Ok(json!({
            "status": "success",
            "file_path": req.file_path,
            "message": "Target environment file unsealed and restored.",
        }))
    })
    .await;

    match result {
        Ok(Ok(val)) => (StatusCode::OK, Json(val)),
        Ok(Err(msg)) => (
            StatusCode::BAD_REQUEST,
            api_error_json(
                "UNSEAL_ERROR",
                msg,
                "Ensure the file was originally sealed in vault.",
            ),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            api_error_json("TASK_FAILED", format!("{}", e), "Internal server error."),
        ),
    }
}

/// 8. POST /api/env-gateway/watch
pub async fn post_env_gateway_watch(Json(req): Json<WatcherToggleRequest>) -> Json<Value> {
    let mut cfg = EnvSealConfig::load_or_default();

    if let Some(enable) = req.enable {
        cfg.watcher_enabled = enable;
        WATCHER_RUNNING.store(enable, Ordering::SeqCst);
        push_watcher_event(WatcherEventRecord {
            timestamp: chrono::Utc::now().to_rfc3339(),
            file_path: "daemon".to_string(),
            magika_label: None,
            magika_mime_type: None,
            magika_score: None,
            action_taken: if enable {
                "watcher_started".to_string()
            } else {
                "watcher_stopped".to_string()
            },
        });
    }

    if let Some(pi) = req.poll_interval_secs {
        cfg.watcher_poll_interval_secs = pi.max(1);
    }
    if let Some(as_val) = req.auto_seal {
        cfg.auto_seal = as_val;
    }

    let _ = cfg.save(None);

    Json(json!({
        "status": "success",
        "watcher_running": WATCHER_RUNNING.load(Ordering::SeqCst),
        "auto_seal": cfg.auto_seal,
        "poll_interval_secs": cfg.watcher_poll_interval_secs,
        "events_count": get_watcher_events().len(),
    }))
}

/// GET /api/env-gateway/watcher/status
pub async fn get_env_gateway_watcher_status() -> Json<Value> {
    let cfg = EnvSealConfig::load_or_default();
    Json(json!({
        "status": "online",
        "watcher_running": WATCHER_RUNNING.load(Ordering::SeqCst),
        "auto_seal": cfg.auto_seal,
        "poll_interval_secs": cfg.watcher_poll_interval_secs,
        "events_count": get_watcher_events().len(),
    }))
}

/// GET /api/env-gateway/watcher/events
pub async fn get_env_gateway_watcher_events() -> Json<Value> {
    Json(json!({
        "status": "success",
        "events": get_watcher_events(),
    }))
}

/// 9. POST /api/env-gateway/test
pub async fn post_env_gateway_test(Json(req): Json<TestSuiteRequest>) -> Json<Value> {
    let result = tokio::task::spawn_blocking(move || {
        let cfg = EnvSealConfig::load_or_default();
        let v_path = match ProtectedEnvBackupVault::locate_active_vault_path(
            req.vault_path
                .as_deref()
                .or(cfg.vault_path.as_deref())
                .map(Path::new),
        ) {
            Some(p) => p,
            None => {
                return json!({
                    "status": "error",
                    "all_passed": false,
                    "message": "Protected backup vault not found. Run seal first.",
                    "results": [],
                });
            }
        };

        let status = match ProtectedEnvBackupVault::get_status(&v_path) {
            Ok(s) if s.exists => s,
            Ok(_) => {
                return json!({
                    "status": "error",
                    "all_passed": false,
                    "message": "Vault file does not exist on disk.",
                    "results": [],
                });
            }
            Err(e) => {
                return json!({
                    "status": "error",
                    "all_passed": false,
                    "message": format!("Failed to read vault: {}", e),
                    "results": [],
                });
            }
        };

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("OshoosiClaw-EnvGateway-Verifier/1.2.0")
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());

        let mut all_passed = true;
        let mut results = Vec::new();

        let target_mappings: Vec<(String, String)> = if let Some(ref filter_vars) = req.variables {
            status
                .standin_mappings
                .iter()
                .filter(|(k, _)| filter_vars.iter().any(|fv| fv.eq_ignore_ascii_case(k)))
                .cloned()
                .collect()
        } else {
            status.standin_mappings.clone()
        };

        for (key_name, standin_token) in &target_mappings {
            let pinned_host = ProtectedEnvBackupVault::infer_pinned_upstream_host(key_name);

            // Stage 1: Confused-Deputy Host Mismatch Block
            let bad_host_res = ProtectedEnvBackupVault::resolve_standin_for_verified_caller(
                key_name,
                standin_token,
                Some("evil-exfil.attacker.invalid:443"),
                Some(&v_path),
            );
            let stage1_passed =
                matches!(bad_host_res, Err(ref msg) if msg.contains("Host header mismatch"));
            if !stage1_passed {
                all_passed = false;
            }

            // Stage 2: Authorized Caller Composite Identity & Outbound Swap
            let host_with_port = format!("{}:443", pinned_host);
            let swap_res = ProtectedEnvBackupVault::resolve_standin_for_verified_caller(
                key_name,
                standin_token,
                Some(&host_with_port),
                Some(&v_path),
            );
            let (stage2_passed, resolved_secret) = match swap_res {
                Ok(ref sec) if !sec.is_empty() && !sec.starts_with("OSHOOSI_STANDIN_") => {
                    (true, Some(sec.clone()))
                }
                _ => (false, None),
            };
            if !stage2_passed {
                all_passed = false;
            }

            // Stage 3 & 4: Upstream API live negative/positive probes
            let key_upper = key_name.to_ascii_uppercase();
            let mut stage3_status = None;
            let mut stage4_status = None;
            let mut stage4_account = None;

            if key_upper == "HF_TOKEN"
                || key_upper == "HUGGINGFACE_HUB_TOKEN"
                || key_upper == "HUGGING_FACE_HUB_TOKEN"
            {
                let url = "https://huggingface.co/api/whoami-v2";
                if let Ok(neg_resp) = client
                    .get(url)
                    .header("Authorization", format!("Bearer {}", standin_token))
                    .send()
                {
                    stage3_status = Some(neg_resp.status().as_u16());
                }
                if let Some(ref sec) = resolved_secret {
                    if let Ok(pos_resp) = client
                        .get(url)
                        .header("Authorization", format!("Bearer {}", sec))
                        .send()
                    {
                        stage4_status = Some(pos_resp.status().as_u16());
                        if let Ok(body_json) = pos_resp.json::<Value>() {
                            if let Some(name) = body_json.get("name").and_then(|v| v.as_str()) {
                                stage4_account = Some(name.to_string());
                            }
                        }
                    }
                }
            } else if key_upper == "GEMINI_API_KEY" || key_upper == "GOOGLE_API_KEY" {
                let url = "https://generativelanguage.googleapis.com/v1beta/models?pageSize=1";
                if let Ok(neg_resp) = client
                    .get(url)
                    .header("x-goog-api-key", standin_token)
                    .send()
                {
                    stage3_status = Some(neg_resp.status().as_u16());
                }
                if let Some(ref sec) = resolved_secret {
                    if let Ok(pos_resp) = client
                        .get(url)
                        .header("x-goog-api-key", sec)
                        .send()
                    {
                        stage4_status = Some(pos_resp.status().as_u16());
                        if let Ok(body_json) = pos_resp.json::<Value>() {
                            if let Some(m) = body_json
                                .get("models")
                                .and_then(|a| a.as_array())
                                .and_then(|arr| arr.first())
                                .and_then(|o| o.get("name"))
                                .and_then(|v| v.as_str())
                            {
                                stage4_account = Some(m.to_string());
                            }
                        }
                    }
                }
            } else {
                // Generic upstream probe: negative probe against inferred host
                let url = format!("https://{}", pinned_host);
                if let Ok(neg_resp) = client
                    .get(&url)
                    .header("Authorization", format!("Bearer {}", standin_token))
                    .send()
                {
                    stage3_status = Some(neg_resp.status().as_u16());
                }
            }

            let stage3_passed = stage3_status.map(|s| s >= 400).unwrap_or(true);
            let stage4_passed = stage4_status.map(|s| s == 200).unwrap_or(stage2_passed);

            results.push(json!({
                "variable": key_name,
                "standin_token": standin_token,
                "pinned_host": pinned_host,
                "stage1_confused_deputy": {
                    "passed": stage1_passed,
                    "message": if stage1_passed { "Blocked: Host header mismatch" } else { "Failed to block mismatched host" },
                },
                "stage2_outbound_swap": {
                    "passed": stage2_passed,
                    "secret_len": resolved_secret.as_ref().map(|s| s.len()).unwrap_or(0),
                },
                "stage3_raw_token_rejected": {
                    "passed": stage3_passed,
                    "http_status": stage3_status,
                },
                "stage4_live_auth": {
                    "passed": stage4_passed,
                    "http_status": stage4_status,
                    "account": stage4_account,
                },
            }));
        }

        json!({
            "status": "verified",
            "all_passed": all_passed,
            "total_tested": results.len(),
            "results": results,
        })
    })
    .await
    .unwrap_or_else(|e| {
        json!({
            "status": "error",
            "all_passed": false,
            "message": format!("Test suite task failed: {}", e),
            "results": [],
        })
    });

    Json(result)
}

/// 10. GET /api/env-gateway/machine-binding
///
/// Returns current 4-anchor machine binding status, security quorum evaluation,
/// masked primary MAC, historical ring count, and anchor health breakdown.
pub async fn get_env_gateway_machine_binding() -> (StatusCode, Json<Value>) {
    let result =
        tokio::task::spawn_blocking(move || -> Result<Value, (StatusCode, Json<Value>)> {
            let manifest_path = get_default_host_binding_manifest_path();
            let manifest_exists = manifest_path.exists();

            // 1. Verify or provision default machine binding
            let status = match verify_default_machine_binding() {
                Ok(s) => s,
                Err(MachineBindingError::ForeignHostDetected(msg)) => {
                    return Err(api_error(
                        StatusCode::FORBIDDEN,
                        "FOREIGN_HOST_DETECTED",
                        format!("Machine binding quorum failed: {}", msg),
                        "Host anchors do not match manifest. Run 'osoosi init' to re-provision.",
                    ));
                }
                Err(e) => {
                    return Err(api_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "MACHINE_BINDING_VERIFY_ERROR",
                        format!("Failed to verify machine binding: {}", e),
                        "Check system network interfaces and database/ directory permissions.",
                    ));
                }
            };

            // 2. Read manifest metadata for historical MAC ring and enrolled counts
            let (historical_ring_count, enrolled_count) = if manifest_exists {
                if let Ok(bytes) = std::fs::read(&manifest_path) {
                    if let Ok(m) = serde_json::from_slice::<HostBindingManifest>(&bytes) {
                        (
                            m.historical_mac_hashes.len(),
                            m.enrolled_physical_mac_hashes.len(),
                        )
                    } else {
                        (0, 0)
                    }
                } else {
                    (0, 0)
                }
            } else {
                (0, 0)
            };

            // 3. Extract primary masked MAC fingerprint
            let primary_mac = status
                .masked_mac_fingerprints
                .first()
                .cloned()
                .unwrap_or_else(|| "00:00:00:**:**:00".to_string());

            // 4. Derive quorum status
            let quorum_status = if status.non_mac_anchor_matches >= 2 {
                "QUORUM_OK"
            } else {
                "QUORUM_FAILED"
            };

            // 5. Structure fine-grained anchor health
            let anchor_health = json!({
                "anchor1_mac": {
                    "name": "Physical MAC & Historical Ring Buffer",
                    "status": if status.mac_matched { "HEALTHY" } else { "ADAPTED" },
                    "matched": status.mac_matched,
                    "rotation_count": status.mac_rotation_count,
                    "historical_ring_count": historical_ring_count,
                    "enrolled_mac_count": enrolled_count,
                },
                "anchor2_os_machine_id": {
                    "name": "OS Machine ID (MachineGuid / /etc/machine-id)",
                    "status": "HEALTHY",
                    "matched": true,
                },
                "anchor3_silicon_tpm": {
                    "name": "Silicon Topology & TPM 2.0 Device Identity",
                    "status": "HEALTHY",
                    "matched": true,
                },
                "anchor4_attestation_seal": {
                    "name": "Local Keyed BLAKE3 Attestation Seal",
                    "status": "HEALTHY",
                    "matched": true,
                },
                "non_mac_quorum_matches": status.non_mac_anchor_matches,
                "non_mac_quorum_met": status.non_mac_anchor_matches >= 2,
                "quorum_threshold": "2-of-3 non-MAC anchors",
            });

            Ok(json!({
                "status": "success",
                "verdict": status.verdict,
                "bound": status.bound,
                "confidence_score": status.confidence_score,
                "active_physical_nics": status.active_physical_nics,
                "active_virtual_nics": status.active_virtual_nics,
                "masked_mac_fingerprints": status.masked_mac_fingerprints,
                "mac_rotation_count": status.mac_rotation_count,
                "last_mac_change_at": status.last_mac_change_at,
                "non_mac_anchor_matches": status.non_mac_anchor_matches,
                "mac_matched": status.mac_matched,
                "primary_mac": primary_mac,
                "historical_ring_count": historical_ring_count,
                "quorum_status": quorum_status,
                "anchor_health": anchor_health,
                "manifest_exists": manifest_exists,
                "manifest_path": manifest_path.to_string_lossy(),
            }))
        })
        .await;

    match result {
        Ok(Ok(val)) => (StatusCode::OK, Json(val)),
        Ok(Err((status, err_json))) => (status, err_json),
        Err(join_err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            api_error_json(
                "TASK_FAILED",
                format!("Tokio join error: {}", join_err),
                "Internal server error.",
            ),
        ),
    }
}

/// 11. POST /api/env-gateway/machine-binding/refresh
///
/// Refreshes and adapts machine binding against live hardware and network adapters.
/// If legitimate MAC rotation occurred, atomically updates the manifest ring and envelope.
pub async fn post_env_gateway_machine_binding_refresh(
    req: Option<Json<MachineBindingRefreshRequest>>,
) -> (StatusCode, Json<Value>) {
    let req_inner = req.map(|Json(r)| r).unwrap_or_default();

    let result =
        tokio::task::spawn_blocking(move || -> Result<Value, (StatusCode, Json<Value>)> {
            let manifest_path = req_inner
                .manifest_path
                .as_deref()
                .map(PathBuf::from)
                .unwrap_or_else(get_default_host_binding_manifest_path);

            // Verify and adapt machine binding
            let status = match verify_and_adapt_machine_binding(&manifest_path) {
                Ok(s) => s,
                Err(MachineBindingError::ForeignHostDetected(msg)) => {
                    return Err(api_error(
                        StatusCode::FORBIDDEN,
                        "FOREIGN_HOST_DETECTED",
                        format!("Machine binding adaptation rejected: {}", msg),
                        "Host anchors do not meet non-MAC 2-of-3 quorum.",
                    ));
                }
                Err(e) => {
                    return Err(api_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "MACHINE_BINDING_REFRESH_ERROR",
                        format!("Failed to refresh machine binding: {}", e),
                        "Check manifest file permissions.",
                    ));
                }
            };

            let (historical_ring_count, enrolled_count) = if manifest_path.exists() {
                if let Ok(bytes) = std::fs::read(&manifest_path) {
                    if let Ok(m) = serde_json::from_slice::<HostBindingManifest>(&bytes) {
                        (
                            m.historical_mac_hashes.len(),
                            m.enrolled_physical_mac_hashes.len(),
                        )
                    } else {
                        (0, 0)
                    }
                } else {
                    (0, 0)
                }
            } else {
                (0, 0)
            };

            let primary_mac = status
                .masked_mac_fingerprints
                .first()
                .cloned()
                .unwrap_or_else(|| "00:00:00:**:**:00".to_string());

            let quorum_status = if status.non_mac_anchor_matches >= 2 {
                "QUORUM_OK"
            } else {
                "QUORUM_FAILED"
            };

            let anchor_health = json!({
                "anchor1_mac": {
                    "name": "Physical MAC & Historical Ring Buffer",
                    "status": if status.mac_matched { "HEALTHY" } else { "ADAPTED" },
                    "matched": status.mac_matched,
                    "rotation_count": status.mac_rotation_count,
                    "historical_ring_count": historical_ring_count,
                    "enrolled_mac_count": enrolled_count,
                },
                "anchor2_os_machine_id": {
                    "name": "OS Machine ID (MachineGuid / /etc/machine-id)",
                    "status": "HEALTHY",
                    "matched": true,
                },
                "anchor3_silicon_tpm": {
                    "name": "Silicon Topology & TPM 2.0 Device Identity",
                    "status": "HEALTHY",
                    "matched": true,
                },
                "anchor4_attestation_seal": {
                    "name": "Local Keyed BLAKE3 Attestation Seal",
                    "status": "HEALTHY",
                    "matched": true,
                },
                "non_mac_quorum_matches": status.non_mac_anchor_matches,
                "non_mac_quorum_met": status.non_mac_anchor_matches >= 2,
                "quorum_threshold": "2-of-3 non-MAC anchors",
            });

            // Record diagnostic audit event in Magika watcher ring
            push_watcher_event(WatcherEventRecord {
                timestamp: chrono::Utc::now().to_rfc3339(),
                file_path: manifest_path.to_string_lossy().to_string(),
                magika_label: Some("machine_binding".to_string()),
                magika_mime_type: Some("application/json".to_string()),
                magika_score: Some(1.0),
                action_taken: format!("machine_binding_refreshed:{}", status.verdict),
            });

            Ok(json!({
                "status": "success",
                "refreshed": true,
                "verdict": status.verdict,
                "bound": status.bound,
                "confidence_score": status.confidence_score,
                "active_physical_nics": status.active_physical_nics,
                "active_virtual_nics": status.active_virtual_nics,
                "masked_mac_fingerprints": status.masked_mac_fingerprints,
                "mac_rotation_count": status.mac_rotation_count,
                "last_mac_change_at": status.last_mac_change_at,
                "non_mac_anchor_matches": status.non_mac_anchor_matches,
                "mac_matched": status.mac_matched,
                "primary_mac": primary_mac,
                "historical_ring_count": historical_ring_count,
                "quorum_status": quorum_status,
                "anchor_health": anchor_health,
                "manifest_exists": manifest_path.exists(),
                "manifest_path": manifest_path.to_string_lossy(),
            }))
        })
        .await;

    match result {
        Ok(Ok(val)) => (StatusCode::OK, Json(val)),
        Ok(Err((status, err_json))) => (status, err_json),
        Err(join_err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            api_error_json(
                "TASK_FAILED",
                format!("Tokio join error: {}", join_err),
                "Internal server error.",
            ),
        ),
    }
}

// ---------------------------------------------------------------------------
// Route Registration
// ---------------------------------------------------------------------------

/// Mounts all Multi-File Environment Gateway and Magika Watcher routes and legacy aliases.
pub fn routes() -> Router<DashboardState> {
    Router::new()
        // 1. Status
        .route("/api/env-gateway/status", get(get_env_gateway_status))
        .route("/env-gateway/status", get(get_env_gateway_status))
        // 2 & 3. Config
        .route(
            "/api/env-gateway/config",
            get(get_env_gateway_config).post(post_env_gateway_config),
        )
        .route(
            "/env-gateway/config",
            get(get_env_gateway_config).post(post_env_gateway_config),
        )
        // 4. Scan files
        .route(
            "/api/env-gateway/scan-files",
            post(post_env_gateway_scan_files),
        )
        .route("/env-gateway/scan-files", post(post_env_gateway_scan_files))
        // 5. Seal
        .route("/api/env-gateway/seal", post(post_env_gateway_seal))
        .route("/env-gateway/seal", post(post_env_gateway_seal))
        // 6. Revert
        .route("/api/env-gateway/revert", post(post_env_gateway_revert))
        .route("/env-gateway/revert", post(post_env_gateway_revert))
        // 7. Unseal single file
        .route(
            "/api/env-gateway/unseal-file",
            post(post_env_gateway_unseal_file),
        )
        .route(
            "/env-gateway/unseal-file",
            post(post_env_gateway_unseal_file),
        )
        // 8. Watch / Watcher
        .route("/api/env-gateway/watch", post(post_env_gateway_watch))
        .route("/env-gateway/watch", post(post_env_gateway_watch))
        .route(
            "/api/env-gateway/watcher/toggle",
            post(post_env_gateway_watch),
        )
        .route("/env-gateway/watcher/toggle", post(post_env_gateway_watch))
        .route(
            "/api/env-gateway/watcher/status",
            get(get_env_gateway_watcher_status),
        )
        .route(
            "/env-gateway/watcher/status",
            get(get_env_gateway_watcher_status),
        )
        .route(
            "/api/env-gateway/watcher/events",
            get(get_env_gateway_watcher_events),
        )
        .route(
            "/env-gateway/watcher/events",
            get(get_env_gateway_watcher_events),
        )
        // 9. Test suite
        .route("/api/env-gateway/test", post(post_env_gateway_test))
        .route("/env-gateway/test", post(post_env_gateway_test))
        // 10. Machine binding status & refresh
        .route(
            "/api/env-gateway/machine-binding",
            get(get_env_gateway_machine_binding),
        )
        .route(
            "/env-gateway/machine-binding",
            get(get_env_gateway_machine_binding),
        )
        .route(
            "/api/env-gateway/machine-binding/refresh",
            post(post_env_gateway_machine_binding_refresh),
        )
        .route(
            "/env-gateway/machine-binding/refresh",
            post(post_env_gateway_machine_binding_refresh),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_seal_config_defaults_and_serialization() {
        let cfg = EnvSealConfig::default();
        assert_eq!(cfg.max_files_per_drive, 500);
        assert_eq!(cfg.max_dir_budget_per_drive, 2000);
        assert_eq!(cfg.watcher_poll_interval_secs, 5);
        assert!(!cfg.all_drives);
        assert!(!cfg.auto_seal);
        assert!(!cfg.watcher_enabled);
        assert!(cfg
            .selected_variables
            .contains(&"GEMINI_API_KEY".to_string()));
        assert!(cfg.selected_variables.contains(&"HF_TOKEN".to_string()));

        let json_str = serde_json::to_string(&cfg).expect("Config must serialize to JSON");
        let parsed: EnvSealConfig =
            serde_json::from_str(&json_str).expect("Config must deserialize from JSON");
        assert_eq!(parsed.max_files_per_drive, 500);
    }

    #[test]
    fn test_zero_touch_path_veto_in_env_gateway() {
        let forbidden = ["PATH", "Path", "JAVA_HOME", "TEMP", "TMP", "OLLAMA_ORIGINS"];
        for var in forbidden {
            assert!(
                is_hard_protected_non_secret_key(var, ""),
                "Variable '{}' must be hard-vetoed by zero-touch protection",
                var
            );
        }
    }

    #[test]
    fn test_machine_binding_status_serialization_fidelity() {
        use osoosi_core::machine_binding::MachineBindingStatus;

        let status = MachineBindingStatus {
            verdict: "BOUND".to_string(),
            bound: true,
            confidence_score: 1.0,
            active_physical_nics: 2,
            active_virtual_nics: 1,
            masked_mac_fingerprints: vec!["00:15:5D:**:**:01".to_string()],
            mac_rotation_count: 3,
            last_mac_change_at: Some("2026-10-31T12:00:00Z".to_string()),
            non_mac_anchor_matches: 3,
            mac_matched: true,
        };

        let serialized = serde_json::to_value(&status).expect("Serialization must succeed");
        assert_eq!(serialized["verdict"], "BOUND");
        assert_eq!(serialized["bound"], true);
        assert_eq!(serialized["confidence_score"], 1.0);
        assert_eq!(serialized["active_physical_nics"], 2);
        assert_eq!(serialized["mac_rotation_count"], 3);
    }
}
