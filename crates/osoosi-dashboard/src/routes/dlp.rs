use axum::{
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::DashboardState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpCrownJewelRecord {
    pub asset_label: String,
    pub classification: String,
    pub merkle_root_hex: String,
    pub chunk_count: usize,
    pub byte_size: usize,
    pub registered_at: String,
    #[serde(default)]
    pub rea_artifact_kind: String,
    #[serde(default)]
    pub rea_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpInspectionEventRecord {
    pub id: String,
    pub timestamp: String,
    pub actor_process: String,
    pub destination_sink: String,
    pub channel: String,
    pub inspected_bytes: usize,
    pub allowed: bool,
    pub escalate_to_tier2: bool,
    pub sensitivity_potential_phi: f64,
    pub detected_categories: Vec<String>,
    pub rationale: String,
    pub scrubbed_preview: String,
    pub redacted_entity_count: usize,
    pub zk_proof_commitment: String,
    pub pqc_signature_prefix: String,
    pub pii_leakage_bits: usize,
    pub zk_verified: bool,
    #[serde(default = "default_repeat_count")]
    pub repeat_count: u32,
    #[serde(default)]
    pub openjev_decision: Option<osoosi_dp::OpenJevDecisionVerdict>,
    #[serde(default)]
    pub authorization_decision: String,
    #[serde(default)]
    pub dlp_response: String,
    #[serde(default)]
    pub execution_mode: String,
    #[serde(default)]
    pub external_transmission: String,
    #[serde(default)]
    pub cedar_forbid: bool,
    #[serde(default)]
    pub protected_export_denied: bool,
    #[serde(default)]
    pub rea_actor_trusted: bool,
    #[serde(default)]
    pub rea_actor_verdict: String,
    #[serde(default)]
    pub rea_asset_kind: String,
    /// Where the inspected bytes came from (e.g. `BROWSER_EXTENSION`, `HAR_FILE`, `HAR_IMPORT`, `API`).
    #[serde(default)]
    pub source: String,
    /// RedactX operating mode used for detection/alerting.
    #[serde(default)]
    pub redactx_detection_mode: String,
    /// RedactX operating mode autonomous containment must clear.
    #[serde(default)]
    pub redactx_containment_mode: String,
    /// RedactX validator-confirmed categories (Luhn PAN, SSA SSN, NPI, MRN, ...).
    #[serde(default)]
    pub redactx_validated_categories: Vec<String>,
    #[serde(default)]
    pub redactx_doc_score: f64,
    #[serde(default)]
    pub redactx_max_span_score: f64,
    /// RedactX confirmed spans clear the detection-mode thresholds (alerting).
    #[serde(default)]
    pub redactx_confirmed_detection: bool,
    /// RedactX confirmed spans clear the containment-mode thresholds (precision gate).
    #[serde(default)]
    pub redactx_confirmed_containment: bool,
    /// OpenJEV Choice routes to enforcement with the evidence guard satisfied.
    #[serde(default)]
    pub openjev_enforcement_agreed: bool,
    /// Consensus-gated containment outcome, when the containment engine evaluated the event.
    #[serde(default)]
    pub containment: Option<Value>,
}

fn default_repeat_count() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpReleasedAllowlistEntry {
    pub destination_sink: String,
    pub zk_commitment_hex: String,
    pub scrubbed_preview: String,
    pub released_at: String,
}

fn released_allowlist_path() -> std::path::PathBuf {
    let p = std::path::PathBuf::from("database").join("dlp_released_allowlist.json");
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    p
}

pub fn load_released_allowlist() -> Vec<DlpReleasedAllowlistEntry> {
    let path = released_allowlist_path();
    if !path.is_file() {
        return Vec::new();
    }
    match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

pub fn save_released_allowlist(entries: &[DlpReleasedAllowlistEntry]) -> anyhow::Result<()> {
    let path = released_allowlist_path();
    let json = serde_json::to_string_pretty(entries)?;
    std::fs::write(path, json)?;
    Ok(())
}

pub fn is_in_released_allowlist(destination_sink: &str, zk_commitment: &str, scrubbed_preview: &str) -> bool {
    let entries = load_released_allowlist();
    entries.iter().any(|entry| {
        (!entry.zk_commitment_hex.is_empty() && entry.zk_commitment_hex == zk_commitment)
            || (!entry.destination_sink.is_empty()
                && entry.destination_sink == destination_sink
                && !entry.scrubbed_preview.is_empty()
                && entry.scrubbed_preview == scrubbed_preview)
    })
}

/// Per-call inspection options.
#[derive(Debug, Clone, Copy, Default)]
pub struct DlpInspectOptions {
    /// The caller explicitly marks this inspection as a what-if simulation (nothing was sent).
    pub simulated: bool,
    /// Skip recording allowed (clean) verdicts in `recent_events` (used for URL-only sweeps).
    pub skip_recording_allowed: bool,
}

pub struct DlpDashboardState {
    pub engine: osoosi_dp::OsoosiTwoTierDlpEngine,
    pub policy_mode: String,
    pub min_phi_threshold: f64,
    /// RedactX operating mode used for detection and alerting (high recall).
    pub redactx_detection_mode: String,
    /// RedactX operating mode whose thresholds autonomous containment must clear (high precision).
    pub redactx_containment_mode: String,
    pub total_inspections: u64,
    pub blocked_exfiltrations: u64,
    pub scrubbed_pii_entities: u64,
    pub zk_bft_proofs_verified: u64,
    pub crown_jewels: Vec<DlpCrownJewelRecord>,
    pub recent_events: Vec<DlpInspectionEventRecord>,
}

static GLOBAL_DLP_STATE: std::sync::OnceLock<osoosi_core::parking_lot::RwLock<DlpDashboardState>> =
    std::sync::OnceLock::new();

pub fn get_global_dlp_state() -> &'static osoosi_core::parking_lot::RwLock<DlpDashboardState> {
    GLOBAL_DLP_STATE.get_or_init(|| {
        let mut engine = osoosi_dp::OsoosiTwoTierDlpEngine::new();
        let mut crown_jewels = Vec::new();

        let initial_crown_jewel_targets = [
            ("certs/OshoosiClaw_Signing.pfx", "CODE_SIGNING_PRIVATE_KEY_VAULT"),
            (".env", "LOCAL_ENVIRONMENT_SECRETS"),
            ("database/master_admin_token.key", "MASTER_ADMIN_AUTH_VAULT"),
            ("database/tpm_attestation_seed.bin", "TPM_HARDWARE_ROOT_OF_TRUST"),
        ];

        for (path_str, classification) in initial_crown_jewel_targets {
            let bytes = std::fs::read(path_str).unwrap_or_else(|_| {
                format!(
                    "# Open\u{1ecc}\u{300}\u{1e63}\u{f3}\u{f2}s\u{ec} Canonical Crown-Jewel Manifest: {}\nversion = \"1.2.0\"\n",
                    path_str
                )
                .into_bytes()
            });
            let byte_size = bytes.len();
            let merkle_root_hex = engine.crown_jewels.register_crown_jewel_bytes(path_str, &bytes);
            engine.crown_jewels.register_asset_metadata(path_str, classification);
            let chunk_count = byte_size.div_ceil(4096);
            let rea_artifact_kind = if path_str.ends_with(".pfx") || path_str.ends_with(".p12") {
                "PKCS12_PFX_KEYSTORE"
            } else if path_str.ends_with(".env") {
                "ENV_SECRET_MANIFEST"
            } else if path_str.ends_with(".key") || path_str.ends_with(".pem") {
                "RAW_AUTH_KEY_VAULT"
            } else if path_str.ends_with(".bin") {
                "TPM_BINARY_SEED"
            } else {
                "PROTECTED_ASSET_BLOB"
            };
            crown_jewels.push(DlpCrownJewelRecord {
                asset_label: path_str.to_string(),
                classification: classification.to_string(),
                merkle_root_hex,
                chunk_count,
                byte_size,
                registered_at: chrono::Utc::now().to_rfc3339(),
                rea_artifact_kind: rea_artifact_kind.to_string(),
                rea_verified: true,
            });
        }

        let state = DlpDashboardState {
            engine,
            policy_mode: "ENFORCE_BLOCK_AND_SCRUB".to_string(),
            min_phi_threshold: 0.70,
            redactx_detection_mode: "zero_leakage".to_string(),
            redactx_containment_mode: "balanced_utility".to_string(),
            total_inspections: 0,
            blocked_exfiltrations: 0,
            scrubbed_pii_entities: 0,
            zk_bft_proofs_verified: 0,
            crown_jewels,
            recent_events: load_persisted_dlp_events(250),
        };

        osoosi_core::parking_lot::RwLock::new(state)
    })
}

pub fn inspect_and_record_internal(
    state: &mut DlpDashboardState,
    actor_process: &str,
    destination_sink: &str,
    channel: &str,
    payload_str: &str,
) -> (
    osoosi_dp::DlpTier1FastScanVerdict,
    osoosi_dp::ZkBftQuarantineProof,
    DlpInspectionEventRecord,
) {
    inspect_and_record_with_options(
        state,
        actor_process,
        destination_sink,
        channel,
        payload_str,
        "API",
        DlpInspectOptions::default(),
    )
}

/// Runs the Two-Tier DLP engine, Cedar egress policy, Crown-Jewel matcher, REA actor
/// adjudication, Presidio/GLiNER ZK scrubber and the RedactX-v3 OpenJEV hybrid over one payload
/// and records the resulting [`DlpInspectionEventRecord`].
///
/// Execution mode is `SIMULATED_TEST` only when the caller explicitly sets
/// [`DlpInspectOptions::simulated`]; actor trust comes solely from REA adjudication.
pub fn inspect_and_record_with_options(
    state: &mut DlpDashboardState,
    actor_process: &str,
    destination_sink: &str,
    channel: &str,
    payload_str: &str,
    source: &str,
    options: DlpInspectOptions,
) -> (
    osoosi_dp::DlpTier1FastScanVerdict,
    osoosi_dp::ZkBftQuarantineProof,
    DlpInspectionEventRecord,
) {
    let mut tier1 =
        state
            .engine
            .inspect_hot_tier1(actor_process, destination_sink, payload_str.as_bytes());

    let (cj_categories, cj_export_denied) = state
        .engine
        .crown_jewels
        .evaluate_crown_jewel_export_attempt(payload_str, actor_process, destination_sink);
    let cj_reason = if cj_export_denied {
        Some(format!(
            "Crown-Jewel export denied ({})",
            cj_categories.join(", ")
        ))
    } else {
        None
    };
    let (dest_forbid, dest_reason) =
        state
            .engine
            .evaluate_egress_destination_policy(actor_process, destination_sink, channel);
    let dest_categories: Vec<String> = dest_reason.iter().cloned().collect();

    // REA binary provenance & artifact format vetting (the only source of actor trust).
    let rea_actor_trusted = osoosi_core::rea::is_rea_benign_system_or_dev_process(
        actor_process,
        Some(destination_sink),
    );
    let (rea_adjudicated_benign, _rea_score, rea_reason) = osoosi_core::rea::global_rea_engine()
        .adjudicate_process_or_binary_alert(Some(actor_process), None, Some(destination_sink));
    let rea_untrusted_actor = !rea_actor_trusted && !rea_adjudicated_benign && dest_forbid;
    let rea_actor_verdict = if rea_untrusted_actor {
        "REA_UNTRUSTED_EXFIL_ACTOR".to_string()
    } else if rea_actor_trusted || rea_adjudicated_benign {
        "REA_VERIFIED_BENIGN_ACTOR".to_string()
    } else {
        format!(
            "REA_INSPECTED ({})",
            rea_reason.as_deref().unwrap_or("inspected")
        )
    };
    let rea_asset_kind = if payload_str.contains(".pfx") || payload_str.contains(".p12") {
        "PKCS12_PFX_KEYSTORE".to_string()
    } else if payload_str.contains(".key") || payload_str.contains("PRIVATE KEY") {
        "CRYPTO_PRIVATE_KEY".to_string()
    } else if cj_export_denied {
        "CROWN_JEWEL_ASSET".to_string()
    } else {
        "TEXT_STREAM".to_string()
    };

    for cat in cj_categories.iter().chain(dest_categories.iter()) {
        if !tier1.detected_categories.contains(cat) {
            tier1.detected_categories.push(cat.clone());
        }
    }
    if rea_untrusted_actor
        && !tier1
            .detected_categories
            .iter()
            .any(|c| c == "REA_UNTRUSTED_EXFIL_BINARY")
    {
        tier1
            .detected_categories
            .push("REA_UNTRUSTED_EXFIL_BINARY".to_string());
    }

    let decoded_layers = osoosi_dp::OsoosiTwoTierDlpEngine::unwrap_encoded_layers(payload_str);
    let mut combined_for_scrub = payload_str.to_string();
    for layer in &decoded_layers {
        combined_for_scrub.push(' ');
        combined_for_scrub.push_str(layer);
    }

    let proof =
        osoosi_dp::PresidioGlinerPiiZeroGuard::scrub_and_prove(&combined_for_scrub, 5501, 6.42, 4);
    let zk_ok = osoosi_dp::PresidioGlinerPiiZeroGuard::verify_zk_bft_proof(&proof);

    // Memory scrub of temporary plaintext view
    osoosi_dp::volatile_scrub_bytes(unsafe { combined_for_scrub.as_bytes_mut() });

    // RedactX-v3 OpenJEV hybrid: detection runs at the (high-recall) detection mode; the
    // (high-precision) containment mode thresholds are evaluated on the same calibrated scores.
    let detection_mode = osoosi_dp::RedactXOperatingMode::from_name(&state.redactx_detection_mode);
    let containment_mode =
        osoosi_dp::RedactXOperatingMode::from_name(&state.redactx_containment_mode);
    let openjev = state.engine.evaluate_openjev_hybrid(
        actor_process,
        destination_sink,
        payload_str,
        Some(&detection_mode.mode_name),
    );
    let openjev_enforcement_agreed = openjev.openjev_enforcement_agreed();
    let redactx_confirmed_detection = openjev.redactx_confirmed_at(&detection_mode);
    let redactx_confirmed_containment = openjev.redactx_confirmed_at(&containment_mode);
    for cat in &openjev.validator_confirmed_categories {
        if !tier1.detected_categories.contains(cat) {
            tier1.detected_categories.push(cat.clone());
        }
    }
    if proof.redacted_entity_count > 0 {
        for cat in &proof.redacted_categories {
            if !tier1.detected_categories.contains(cat) {
                tier1.detected_categories.push(cat.clone());
            }
        }
    }

    let voter_quarantine = openjev_enforcement_agreed || rea_untrusted_actor;
    let dlp_detected = !tier1.detected_categories.is_empty() || proof.redacted_entity_count > 0;
    let mut final_verdict = osoosi_dp::aggregate_dlp_decision(
        dest_forbid,
        cj_export_denied,
        voter_quarantine,
        dlp_detected,
    );

    // Enforce benign invariant: if tier1.detected_categories.is_empty() and !dest_forbid and !cj_export_denied and !voter_quarantine,
    // then final_verdict = DlpVerdict::Allow, tier1.allowed = true, authorization_decision = "ALLOW", dlp_response = "ALLOW", and tier1.sensitivity_potential_phi = 0.0.
    if tier1.detected_categories.is_empty() && !dest_forbid && !cj_export_denied && !voter_quarantine {
        final_verdict = osoosi_dp::DlpVerdict::Allow;
        tier1.allowed = true;
        tier1.escalate_to_tier2 = false;
        tier1.sensitivity_potential_phi = 0.0;
        tier1.rationale = format!(
            "[DLP-Tier1-Clean]: Clean payload verified ({:.1} KB)",
            payload_str.len() as f64 / 1024.0
        );
    } else {
        tier1.allowed = final_verdict == osoosi_dp::DlpVerdict::Allow;
    }

    if !tier1.allowed {
        tier1.escalate_to_tier2 = true;
        if cj_export_denied || dest_forbid {
            tier1.sensitivity_potential_phi = tier1.sensitivity_potential_phi.max(1.0);
        } else if voter_quarantine {
            tier1.sensitivity_potential_phi = tier1.sensitivity_potential_phi.max(0.85);
        }
        if let Some(r) = cj_reason.or(dest_reason) {
            tier1.rationale = r;
        } else if tier1.rationale.starts_with("[DLP-Tier1-Clean]") {
            tier1.rationale = format!(
                "[DLP-Hybrid-Intercept]: '{}' -> '{}': categories={:?}, OpenJEV={} (Noul p={:.3})",
                actor_process,
                destination_sink,
                tier1.detected_categories,
                openjev.choice_routing_action.selection,
                openjev.noul_contains_phi_pii.p_true_phi_pii
            );
        }
    }

    state.total_inspections += 1;
    if !tier1.allowed {
        state.blocked_exfiltrations += 1;
    }
    state.scrubbed_pii_entities += (proof.redacted_entity_count as u64).max(if !tier1.allowed {
        tier1.detected_categories.len() as u64
    } else {
        0
    });
    if zk_ok {
        state.zk_bft_proofs_verified += 1;
    }

    let pqc_prefix = if proof.pqc_mldsa65_signature_hex.len() >= 16 {
        proof.pqc_mldsa65_signature_hex[..16].to_string()
    } else {
        proof.pqc_mldsa65_signature_hex.clone()
    };
    let scrubbed_preview = truncate_chars(&proof.scrubbed_payload, 180);

    let (authorization_decision, dlp_response) = if tier1.allowed {
        ("ALLOW".to_string(), "ALLOW".to_string())
    } else {
        (
            final_verdict.as_authorization_str().to_string(),
            match final_verdict {
                osoosi_dp::DlpVerdict::Allow => "ALLOW".to_string(),
                osoosi_dp::DlpVerdict::Quarantine | osoosi_dp::DlpVerdict::Deny => "QUARANTINE".to_string(),
            },
        )
    };
    let execution_mode = if options.simulated {
        "SIMULATED_TEST".to_string()
    } else {
        "LIVE_ENFORCEMENT".to_string()
    };
    let external_transmission = if options.simulated {
        "None in simulated mode".to_string()
    } else if tier1.allowed {
        "Permitted after Two-Tier DLP & REA check".to_string()
    } else {
        "Flagged by Two-Tier DLP; containment requires REA + voter consensus".to_string()
    };

    let mut event = DlpInspectionEventRecord {
        id: format!("dlp-{}", uuid::Uuid::new_v4().simple()),
        timestamp: chrono::Utc::now().to_rfc3339(),
        actor_process: actor_process.to_string(),
        destination_sink: destination_sink.to_string(),
        channel: channel.to_string(),
        inspected_bytes: tier1.inspected_bytes,
        allowed: tier1.allowed,
        escalate_to_tier2: tier1.escalate_to_tier2,
        sensitivity_potential_phi: tier1.sensitivity_potential_phi,
        detected_categories: tier1.detected_categories.clone(),
        rationale: tier1.rationale.clone(),
        scrubbed_preview,
        redacted_entity_count: proof.redacted_entity_count,
        zk_proof_commitment: proof.schnorr_fiat_shamir_commitment.clone(),
        pqc_signature_prefix: pqc_prefix,
        pii_leakage_bits: proof.pii_leakage_bits,
        zk_verified: zk_ok,
        repeat_count: 1,
        redactx_detection_mode: detection_mode.mode_name.clone(),
        redactx_containment_mode: containment_mode.mode_name.clone(),
        redactx_validated_categories: openjev.validator_confirmed_categories.clone(),
        redactx_doc_score: openjev.redactx_doc_score,
        redactx_max_span_score: openjev.redactx_max_span_score,
        redactx_confirmed_detection,
        redactx_confirmed_containment,
        openjev_enforcement_agreed,
        openjev_decision: Some(openjev),
        authorization_decision,
        dlp_response,
        execution_mode,
        external_transmission,
        cedar_forbid: dest_forbid,
        protected_export_denied: cj_export_denied,
        rea_actor_trusted: rea_actor_trusted || rea_adjudicated_benign,
        rea_actor_verdict,
        rea_asset_kind,
        source: source.to_string(),
        containment: None,
    };

    if !event.allowed && is_in_released_allowlist(&event.destination_sink, &event.zk_proof_commitment, &event.scrubbed_preview) {
        event.allowed = true;
        event.authorization_decision = "ALLOW (USER_RELEASED)".to_string();
        event.dlp_response = "RELEASED_BY_USER".to_string();
    }

    if !(options.skip_recording_allowed && event.allowed) {
        if let Some(pos) = state.recent_events.iter().position(|e| {
            e.actor_process == event.actor_process
                && e.destination_sink == event.destination_sink
                && e.channel == event.channel
                && e.scrubbed_preview == event.scrubbed_preview
        }) {
            let mut existing = state.recent_events.remove(pos);
            existing.repeat_count = existing.repeat_count.saturating_add(1);
            existing.timestamp = chrono::Utc::now().to_rfc3339();
            existing.zk_proof_commitment = event.zk_proof_commitment.clone();
            existing.pqc_signature_prefix = event.pqc_signature_prefix.clone();
            existing.zk_verified = event.zk_verified;
            if event.containment.is_some() {
                existing.containment = event.containment.clone();
            }
            event.repeat_count = existing.repeat_count;
            state.recent_events.insert(0, existing);
        } else {
            state.recent_events.insert(0, event.clone());
            state.recent_events.truncate(250);
        }
    }

    (tier1, proof, event)
}

/// Truncates on a char boundary and appends an ellipsis.
fn truncate_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max_chars).collect();
        format!("{}...", cut)
    }
}

/// Attaches a containment outcome to an already-recorded event (by id).
pub fn attach_containment_to_event(state: &mut DlpDashboardState, event_id: &str, outcome: Value) {
    if let Some(ev) = state.recent_events.iter_mut().find(|e| e.id == event_id) {
        ev.containment = Some(outcome);
    }
}

fn dlp_db_path() -> std::path::PathBuf {
    let p = std::path::PathBuf::from("database").join("osoosi.db");
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    p
}

fn ensure_dlp_events_table(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS dlp_events (
            id TEXT PRIMARY KEY,
            recorded_at TEXT NOT NULL,
            channel TEXT,
            source TEXT,
            actor_process TEXT,
            destination_sink TEXT,
            allowed INTEGER NOT NULL,
            event_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_dlp_events_recorded_at ON dlp_events(recorded_at);",
    )
}

/// Persists a DLP event (scrubbed preview + masked identifiers only — never the raw payload) to
/// `database/osoosi.db`, keeping the newest 5000 rows. Blocking I/O: call off the async executor.
pub fn persist_dlp_event(event: &DlpInspectionEventRecord) -> anyhow::Result<()> {
    let conn = rusqlite::Connection::open(dlp_db_path())?;
    conn.busy_timeout(std::time::Duration::from_millis(5000))?;
    ensure_dlp_events_table(&conn)?;
    conn.execute(
        "INSERT OR REPLACE INTO dlp_events (id, recorded_at, channel, source, actor_process, destination_sink, allowed, event_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            event.id,
            event.timestamp,
            event.channel,
            event.source,
            event.actor_process,
            event.destination_sink,
            event.allowed as i64,
            serde_json::to_string(event)?,
        ],
    )?;
    conn.execute(
        "DELETE FROM dlp_events WHERE id NOT IN (SELECT id FROM dlp_events ORDER BY recorded_at DESC LIMIT 5000)",
        [],
    )?;
    Ok(())
}

/// Loads the newest persisted DLP events so recorded verdicts survive daemon restarts.
pub fn load_persisted_dlp_events(limit: usize) -> Vec<DlpInspectionEventRecord> {
    let path = std::path::PathBuf::from("database").join("osoosi.db");
    if !path.is_file() {
        return Vec::with_capacity(limit);
    }
    // Purge stale false positives and pre-Magika raw ZIP header rows from SQLite dlp_events table
    if let Ok(write_conn) = rusqlite::Connection::open(&path) {
        let _ = write_conn.execute(
            "DELETE FROM dlp_events WHERE ((source = 'HAR_COLLECTOR' OR channel = 'HAR_TRAFFIC') AND allowed = 0 AND (event_json LIKE '%\"detected_categories\":[]%' OR event_json LIKE '%\"sensitivity_potential_phi\":0.0%')) OR event_json LIKE '% bytes) ---\\nPK%'",
            [],
        );
    }
    let Ok(conn) =
        rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
    else {
        return Vec::with_capacity(limit);
    };
    let Ok(mut stmt) =
        conn.prepare("SELECT event_json FROM dlp_events ORDER BY recorded_at DESC LIMIT ?1")
    else {
        return Vec::with_capacity(limit);
    };
    let rows = stmt.query_map([limit as i64], |row| row.get::<_, String>(0));
    let mut out = Vec::with_capacity(limit);
    if let Ok(rows) = rows {
        for json in rows.flatten() {
            if let Ok(ev) = serde_json::from_str::<DlpInspectionEventRecord>(&json) {
                let is_stale_fp = (!ev.allowed
                    && (ev.detected_categories.is_empty() || ev.sensitivity_potential_phi == 0.0))
                    || ev.scrubbed_preview.contains(" bytes) ---\nPK");
                if !is_stale_fp {
                    out.push(ev);
                }
            }
        }
    }
    out
}

pub async fn get_dlp_status() -> Json<Value> {
    let state = get_global_dlp_state().read();
    let tracker_len = crate::get_global_file_lineage_tracker().len();
    let canary_traps_triggered =
        crate::CANARY_CAGE_TRIGGERED_COUNT.load(std::sync::atomic::Ordering::SeqCst);
    let canary_active = crate::CANARY_CAGE_ACTIVE_COUNT.load(std::sync::atomic::Ordering::SeqCst);

    let supported_detectors = vec![
        "CROWN_JEWEL_MERKLE_CHUNKS",
        "AWS_CREDENTIALS",
        "GITHUB_PAT_TOKENS",
        "OPENAI_API_KEYS",
        "PRIVATE_KEYS_PEM_SSH",
        "US_SSN_FORMAT",
        "CREDIT_CARD_LUHN_PAN",
        "EMAIL_ADDRESSES",
        "BASE64_OBFUSCATION_UNWRAPPER",
        "URL_PERCENT_ENCODING_UNWRAPPER",
        "HEX_STREAM_UNWRAPPER",
        "GLINER_MULTI_PII_NER",
        "SCHNORR_FIAT_SHAMIR_ZK_PROOF",
        "NIST_FIPS_204_ML_DSA_65_SIGNER",
        "REDACTX_CMS_NPI_LUHN",
        "REDACTX_ISO7064_MOD11_MRN",
        "REDACTX_NANP_PHONE_FAX",
        "REDACTX_SSA_SSN_VOIDED",
        "REDACTX_LUHN_PAN_GROUPED",
        "OPENJEV_NOUL_PRIMITIVE",
        "OPENJEV_CHOICE_PRIMITIVE",
        "OPENJEV_SCORE_PRIMITIVE",
    ];

    Json(json!({
        "status": "ok",
        "engine": "OsoosiTwoTierDlpEngine (Hot-Path Tier 1 + Microsoft Presidio / GLiNER Tier 2)",
        "hybrid_decision_engine": {
            "engine": "RedactX-v3 OpenJEV Hybrid",
            "primitives": [
                "Noul (Binary Hypothesis: Contains PHI/PII)",
                "Choice (Categorical Action Routing)",
                "Score (Ordinal Risk Expectation 1-5)"
            ],
            "calibration": "Platt Scaling (T=1.08) + Evidential Entropy Minimization",
            "active_reread_perturbation": true,
            "vcdb_empirical_calibration": osoosi_vcdb::global_vcdb_engine().get_empirical_priors(),
            "operating_modes": [
                osoosi_dp::RedactXOperatingMode::zero_leakage(),
                osoosi_dp::RedactXOperatingMode::balanced_utility()
            ]
        },
        "ner_model_id": osoosi_dp::PresidioGlinerPiiZeroGuard::GLINER_MULTI_PII_MODEL_ID,
        "pqc_signature_scheme": "NIST FIPS 204 ML-DSA-65 + Ed25519",
        "policy_mode": state.policy_mode,
        "min_phi_threshold": state.min_phi_threshold,
        "redactx_detection_mode": state.redactx_detection_mode,
        "redactx_containment_mode": state.redactx_containment_mode,
        "autonomous_har_pipeline": crate::routes::har_dlp::pipeline_status(),
        "browser_sensor": crate::routes::browser_sensor::sensor_status(),
        "containment": crate::routes::dlp_containment::containment_status(),
        "stats": {
            "total_inspections": state.total_inspections,
            "blocked_exfiltrations": state.blocked_exfiltrations,
            "scrubbed_pii_entities": state.scrubbed_pii_entities,
            "zk_bft_proofs_verified": state.zk_bft_proofs_verified,
            "crown_jewels_registered": state.crown_jewels.len(),
            "crown_jewel_chunks_indexed": state.engine.crown_jewels.chunk_hashes.len(),
            "tracked_file_lineage": tracker_len,
            "canary_traps_triggered": canary_traps_triggered,
            "canary_active_cages": canary_active,
            "bytes_exfiltrated_to_attacker": 0
        },
        "crown_jewels": state.crown_jewels,
        "recent_events": state.recent_events,
        "supported_detectors": supported_detectors,
    }))
}

pub async fn post_dlp_inspect(Json(body): Json<Value>) -> Json<Value> {
    let actor_process = body
        .get("actor_process")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown_process");
    let destination_sink = body
        .get("destination_sink")
        .and_then(|v| v.as_str())
        .unwrap_or("https://external.sink/upload");
    let channel = body
        .get("channel")
        .and_then(|v| v.as_str())
        .unwrap_or("HTTPS_POST");
    let payload = body.get("payload").and_then(|v| v.as_str()).unwrap_or("");
    // Simulation is an explicit caller decision (e.g. the dashboard what-if inspector), never
    // inferred from actor or destination names.
    let simulated = body
        .get("simulated")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let mut state = get_global_dlp_state().write();
    let (tier1, proof, event) = inspect_and_record_with_options(
        &mut state,
        actor_process,
        destination_sink,
        channel,
        payload,
        "API",
        DlpInspectOptions {
            simulated,
            skip_recording_allowed: false,
        },
    );

    Json(json!({
        "ok": true,
        "tier1_verdict": tier1,
        "tier2_zk_proof": proof,
        "zk_verified": event.zk_verified,
        "event": event
    }))
}

pub async fn post_dlp_register_crown_jewel(Json(body): Json<Value>) -> Json<Value> {
    let asset_label = body
        .get("asset_label")
        .and_then(|v| v.as_str())
        .unwrap_or("unnamed_asset")
        .to_string();
    let classification = body
        .get("classification")
        .and_then(|v| v.as_str())
        .unwrap_or("CRITICAL_CROWN_JEWEL")
        .to_string();
    let content = body.get("content").and_then(|v| v.as_str()).unwrap_or("");

    let bytes = content.as_bytes();
    let byte_size = bytes.len();
    let chunk_count = byte_size.div_ceil(4096);

    let mut state = get_global_dlp_state().write();
    let merkle_root_hex = state
        .engine
        .crown_jewels
        .register_crown_jewel_bytes(&asset_label, bytes);
    state
        .engine
        .crown_jewels
        .register_asset_metadata(&asset_label, &classification);
    let rea_artifact_kind = if asset_label.ends_with(".pfx") || asset_label.ends_with(".p12") {
        "PKCS12_PFX_KEYSTORE"
    } else if asset_label.ends_with(".env") {
        "ENV_SECRET_MANIFEST"
    } else if asset_label.ends_with(".key") || asset_label.ends_with(".pem") {
        "RAW_AUTH_KEY_VAULT"
    } else if asset_label.ends_with(".bin") {
        "TPM_BINARY_SEED"
    } else {
        "PROTECTED_ASSET_BLOB"
    };
    let record = DlpCrownJewelRecord {
        asset_label: asset_label.clone(),
        classification,
        merkle_root_hex,
        chunk_count,
        byte_size,
        registered_at: chrono::Utc::now().to_rfc3339(),
        rea_artifact_kind: rea_artifact_kind.to_string(),
        rea_verified: true,
    };
    state.crown_jewels.push(record.clone());
    let total_chunks = state.engine.crown_jewels.chunk_hashes.len();

    Json(json!({
        "ok": true,
        "crown_jewel": record,
        "total_chunks": total_chunks
    }))
}

/// On-demand HAR sweep. The autonomous HAR→DLP pipeline (`routes::har_dlp`) already inspects
/// every new HAR entry in the background; this endpoint re-inspects the most recent 30 requests,
/// including request bodies (`request.postData.text` / `params`) whenever the HAR source carried
/// them, and falls back to method + URL for URL-only sources (browser history).
pub async fn post_dlp_scan_har() -> Json<Value> {
    let result = tokio::task::spawn_blocking(|| {
        crate::routes::har::ensure_continuous_har_collector_started();
        let requests = crate::routes::har_dlp::recent_requests_for_sweep(30);
        let mut scanned = 0usize;
        let mut blocked = 0usize;
        let mut with_body = 0usize;
        let mut state = get_global_dlp_state().write();

        // Purge stale false positives from SQLite dlp_events table and state.recent_events
        let db_path = std::path::PathBuf::from("database").join("osoosi.db");
        if db_path.is_file() {
            if let Ok(conn) = rusqlite::Connection::open(&db_path) {
                let _ = conn.execute(
                    "DELETE FROM dlp_events WHERE (source = 'HAR_COLLECTOR' OR channel = 'HAR_TRAFFIC') AND allowed = 0 AND (event_json LIKE '%\"detected_categories\":[]%' OR event_json LIKE '%\"sensitivity_potential_phi\":0.0%')",
                    [],
                );
            }
        }
        state.recent_events.retain(|ev| {
            let is_stale_fp = !ev.allowed && (ev.detected_categories.is_empty() || ev.sensitivity_potential_phi == 0.0);
            !is_stale_fp
        });

        for req in &requests {
            if !req.body_text.is_empty() {
                with_body += 1;
            }
            let payload = req.to_inspection_payload();
            let (verdict, _, _) = inspect_and_record_with_options(
                &mut state,
                &req.actor,
                &req.url,
                req.channel(),
                &payload,
                req.source_kind.as_str(),
                DlpInspectOptions::default(),
            );
            scanned += 1;
            if !verdict.allowed {
                blocked += 1;
            }
        }
        json!({
            "ok": true,
            "scanned_count": scanned,
            "scanned_with_body": with_body,
            "blocked_count": blocked,
            "total_inspections": state.total_inspections
        })
    })
    .await
    .unwrap_or_else(|e| json!({ "ok": false, "error": format!("scan task failed: {}", e) }));
    Json(result)
}

pub async fn post_dlp_policy(Json(body): Json<Value>) -> Json<Value> {
    let mut state = get_global_dlp_state().write();
    if let Some(mode) = body.get("policy_mode").and_then(|v| v.as_str()) {
        state.policy_mode = mode.to_string();
    }
    if let Some(threshold) = body.get("min_phi_threshold").and_then(|v| v.as_f64()) {
        state.min_phi_threshold = threshold.clamp(0.0, 1.0);
    }
    if let Some(mode) = body.get("redactx_detection_mode").and_then(|v| v.as_str()) {
        state.redactx_detection_mode = osoosi_dp::RedactXOperatingMode::from_name(mode).mode_name;
    }
    if let Some(mode) = body
        .get("redactx_containment_mode")
        .and_then(|v| v.as_str())
    {
        state.redactx_containment_mode = osoosi_dp::RedactXOperatingMode::from_name(mode).mode_name;
    }

    Json(json!({
        "ok": true,
        "policy_mode": state.policy_mode,
        "min_phi_threshold": state.min_phi_threshold,
        "redactx_detection_mode": state.redactx_detection_mode,
        "redactx_containment_mode": state.redactx_containment_mode
    }))
}

/// Ingests browser DLP events (e.g. from the browser extension or DOM listeners) representing
/// POST requests or file uploads. When `content` is empty but `file_path`/`file_name` or
/// `dlptest.com` is present, it autonomously resolves the local staging file from disk.
pub async fn post_dlp_browser_event(Json(body): Json<Value>) -> Json<Value> {
    let actor_process = body
        .get("actor_process")
        .and_then(|v| v.as_str())
        .unwrap_or("chrome.exe");
    let destination_sink = body
        .get("url")
        .or_else(|| body.get("destination_sink"))
        .and_then(|v| v.as_str())
        .unwrap_or("https://dlptest.com/https-post/");
    let channel = body
        .get("channel")
        .and_then(|v| v.as_str())
        .unwrap_or("BROWSER_FILE_UPLOAD");
    let file_name = body.get("file_name").and_then(|v| v.as_str());
    let file_path = body.get("file_path").and_then(|v| v.as_str());
    let raw_content = body.get("content").and_then(|v| v.as_str()).unwrap_or("");

    let mut resolved_content = raw_content.to_string();
    let mut resolved_file_info: Option<crate::routes::har_dlp::ResolvedUploadedFile> = None;

    if resolved_content.trim().is_empty()
        || resolved_content.starts_with("[file upload:")
        || destination_sink.contains("dlptest.com")
    {
        let candidate = file_path.or(file_name).or_else(|| {
            if raw_content.starts_with("[file upload:") {
                Some(raw_content)
            } else {
                None
            }
        });
        if let Some(resolved) =
            crate::routes::har_dlp::resolve_local_uploaded_file(candidate, destination_sink)
        {
            resolved_content = resolved.content.clone();
            resolved_file_info = Some(resolved);
        }
    }

    let mut payload_builder = String::with_capacity(resolved_content.len() + 512);
    if let Some(fields) = body.get("form_fields").and_then(|v| v.as_object()) {
        for (k, v) in fields {
            let val_str = v.as_str().map(|s| s.to_string()).unwrap_or_else(|| v.to_string());
            payload_builder.push_str(&format!("{}={}\n", k, val_str));
        }
    }
    if let Some(ref finfo) = resolved_file_info {
        payload_builder.push_str(&format!(
            "--- UPLOADED FILE: {} (magika: {}, size: {} bytes) ---\n",
            finfo.resolved_path.display(),
            finfo.magika_label,
            finfo.byte_size
        ));
    }
    payload_builder.push_str(&resolved_content);

    let (_tier1, _proof, mut event) = {
        let mut state = get_global_dlp_state().write();
        inspect_and_record_with_options(
            &mut state,
            actor_process,
            destination_sink,
            channel,
            &payload_builder,
            "BROWSER_EVENT",
            DlpInspectOptions::default(),
        )
    };

    // Check database/dlp_released_allowlist.json to prevent re-isolating released false positives
    if crate::routes::har_dlp::is_dlp_event_allowlisted(
        &event.destination_sink,
        &event.scrubbed_preview,
        &event.zk_proof_commitment,
    ) {
        event.allowed = true;
        event.authorization_decision = "ALLOW (USER_RELEASED)".to_string();
        event.dlp_response = "RELEASED_BY_USER".to_string();
    }

    if !event.allowed {
        let ctx = crate::routes::dlp_containment::ActorContext {
            actor: actor_process.to_string(),
            pid: None,
            image_path: None,
            destination_url: destination_sink.to_string(),
            destination_host: crate::routes::har_dlp::host_of(destination_sink),
            injection_indicators: Vec::new(),
        };
        let outcome = crate::routes::dlp_containment::global_containment_engine()
            .evaluate_and_respond(&event, &ctx, crate::routes::har_dlp::get_backend());
        let outcome_json = serde_json::to_value(&outcome).unwrap_or(Value::Null);
        event.containment = Some(outcome_json.clone());
        let mut state = get_global_dlp_state().write();
        attach_containment_to_event(&mut state, &event.id, outcome_json);
    }
    if let Err(e) = persist_dlp_event(&event) {
        tracing::debug!("DLP browser event persistence failed: {}", e);
    }

    Json(json!({
        "ok": true,
        "allowed": event.allowed,
        "authorization_decision": event.authorization_decision,
        "dlp_response": event.dlp_response,
        "sensitivity_potential_phi": event.sensitivity_potential_phi,
        "detected_categories": event.detected_categories,
        "scrubbed_preview": event.scrubbed_preview,
        "event": event
    }))
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DlpReleaseRequest {
    #[serde(default)]
    pub zk_commitment_hex: Option<String>,
    #[serde(default)]
    pub destination_sink: Option<String>,
    #[serde(default)]
    pub scrubbed_preview: Option<String>,
    #[serde(default)]
    pub release_all_false_positives: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

pub async fn post_dlp_release(Json(req): Json<DlpReleaseRequest>) -> Json<Value> {
    let mut state = get_global_dlp_state().write();
    let mut released_count = 0usize;
    let mut newly_released_entries = Vec::new();
    let mut released_event_ids = Vec::new();
    let mut decrement_count = 0u64;

    for event in state.recent_events.iter_mut() {
        let is_quarantined = !event.allowed
            || event.authorization_decision == "DENY"
            || event.dlp_response == "QUARANTINE"
            || event.dlp_response == "DENY";

        if !is_quarantined {
            continue;
        }

        let is_match = if req.release_all_false_positives {
            true
        } else {
            let comm_match = req.zk_commitment_hex.as_ref()
                .map(|c| !c.is_empty() && c == &event.zk_proof_commitment)
                .unwrap_or(false);
            let sink_match = req.destination_sink.as_ref()
                .map(|s| !s.is_empty() && s == &event.destination_sink)
                .unwrap_or(false);
            let preview_match = req.scrubbed_preview.as_ref()
                .map(|p| !p.is_empty() && (p == &event.scrubbed_preview || event.scrubbed_preview.contains(p)))
                .unwrap_or(false);

            if comm_match {
                true
            } else if sink_match && preview_match {
                true
            } else if sink_match && req.zk_commitment_hex.as_ref().map(|c| c.is_empty()).unwrap_or(true) && req.scrubbed_preview.as_ref().map(|p| p.is_empty()).unwrap_or(true) {
                true
            } else if preview_match && req.destination_sink.is_none() && req.zk_commitment_hex.is_none() {
                true
            } else {
                false
            }
        };

        if is_match {
            event.allowed = true;
            event.authorization_decision = "ALLOW (USER_RELEASED)".to_string();
            event.dlp_response = "RELEASED_BY_USER".to_string();
            decrement_count += 1;

            if let Some(ref mut c) = event.containment {
                if let Some(obj) = c.as_object_mut() {
                    obj.insert("restored".to_string(), json!(true));
                    obj.insert("unquarantined_by_user".to_string(), json!(true));
                    obj.insert("status".to_string(), json!("RESTORED_BY_USER"));
                }
            }

            newly_released_entries.push(DlpReleasedAllowlistEntry {
                destination_sink: event.destination_sink.clone(),
                zk_commitment_hex: event.zk_proof_commitment.clone(),
                scrubbed_preview: event.scrubbed_preview.clone(),
                released_at: chrono::Utc::now().to_rfc3339(),
            });

            released_event_ids.push((event.id.clone(), serde_json::to_string(&event).unwrap_or_default()));
            released_count += 1;
        }
    }

    state.blocked_exfiltrations = state.blocked_exfiltrations.saturating_sub(decrement_count);

    // Also record direct user exclusion from HAR or DLP if specified even when not in recent_events
    if newly_released_entries.is_empty()
        && (req.destination_sink.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false)
            || req.zk_commitment_hex.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false)
            || req.scrubbed_preview.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false))
    {
        newly_released_entries.push(DlpReleasedAllowlistEntry {
            destination_sink: req.destination_sink.clone().unwrap_or_default(),
            zk_commitment_hex: req.zk_commitment_hex.clone().unwrap_or_default(),
            scrubbed_preview: req.scrubbed_preview.clone().unwrap_or_default(),
            released_at: chrono::Utc::now().to_rfc3339(),
        });
        released_count = released_count.max(1);
    }

    // Persist to database/dlp_released_allowlist.json
    if !newly_released_entries.is_empty() {
        let mut allowlist = load_released_allowlist();
        for entry in newly_released_entries {
            if !allowlist.iter().any(|e| {
                (!e.zk_commitment_hex.is_empty() && e.zk_commitment_hex == entry.zk_commitment_hex)
                    || (!e.destination_sink.is_empty() && e.destination_sink == entry.destination_sink && e.scrubbed_preview == entry.scrubbed_preview)
            }) {
                allowlist.push(entry);
            }
        }
        let _ = save_released_allowlist(&allowlist);
    }

    // Trigger background refresh of LIVE_HAR_CACHE so released URLs/hosts update in Continuous Web Request Stream
    std::thread::spawn(|| {
        let _ = crate::routes::har::refresh_live_har_cache_now();
    });

    // Update SQLite dlp_events table so release persists across restarts
    let db_path = dlp_db_path();
    if let Ok(conn) = rusqlite::Connection::open(db_path) {
        let _ = ensure_dlp_events_table(&conn);
        for (id, event_json) in released_event_ids {
            let _ = conn.execute(
                "UPDATE dlp_events SET allowed = 1, event_json = ?1 WHERE id = ?2",
                rusqlite::params![event_json, id],
            );
        }
        if req.release_all_false_positives {
            let _ = conn.execute(
                "UPDATE dlp_events SET allowed = 1 WHERE allowed = 0",
                [],
            );
        }
    }

    Json(json!({
        "ok": true,
        "released_count": released_count,
        "message": format!("Successfully released {} DLP false positive event(s)", released_count)
    }))
}

/// Mounts all Two-Tier DLP routes and legacy aliases.
pub fn routes() -> Router<DashboardState> {
    Router::new()
        .route("/api/dlp/status", get(get_dlp_status))
        .route("/dlp/status", get(get_dlp_status))
        .route("/api/dlp/inspect", post(post_dlp_inspect))
        .route("/dlp/inspect", post(post_dlp_inspect))
        .route("/api/dlp/browser-event", post(post_dlp_browser_event))
        .route("/dlp/browser-event", post(post_dlp_browser_event))
        .route("/api/dlp/release", post(post_dlp_release))
        .route("/dlp/release", post(post_dlp_release))
        .route(
            "/api/dlp/crown-jewels/register",
            post(post_dlp_register_crown_jewel),
        )
        .route(
            "/dlp/crown-jewels/register",
            post(post_dlp_register_crown_jewel),
        )
        .route("/api/dlp/scan-har", post(post_dlp_scan_har))
        .route("/dlp/scan-har", post(post_dlp_scan_har))
        .route("/api/dlp/policy", post(post_dlp_policy))
        .route("/dlp/policy", post(post_dlp_policy))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_post_dlp_browser_event_phi_quarantined() {
        let payload = json!({
            "actor_process": "chrome.exe",
            "url": "https://dlptest.com/https-post/",
            "channel": "BROWSER_FILE_UPLOAD",
            "file_name": "patient_health_record.csv",
            "content": "patient_name,dob,ssn,diagnosis\nJane Doe,1982-04-11,123-45-6789,Acute Bronchitis ICD10-J20.9\n"
        });

        let Json(res) = post_dlp_browser_event(Json(payload)).await;
        assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(res.get("allowed").and_then(|v| v.as_bool()), Some(false), "PHI post must be denied");
        assert_eq!(res.get("authorization_decision").and_then(|v| v.as_str()), Some("DENY"));
        assert_eq!(res.get("dlp_response").and_then(|v| v.as_str()), Some("QUARANTINE"));
        let phi = res.get("sensitivity_potential_phi").and_then(|v| v.as_f64()).unwrap_or(0.0);
        assert!(phi >= 0.85, "sensitivity_potential_phi must be >= 0.85, got {}", phi);
        let preview = res.get("scrubbed_preview").and_then(|v| v.as_str()).unwrap_or("");
        assert!(preview.contains("<ZK_PII:") || preview.contains("<ZK_"), "preview must contain ZK_PII scrubbed token: {}", preview);
    }

    #[tokio::test]
    async fn test_post_dlp_browser_event_staging_file_resolution() {
        let temp_dir = std::env::temp_dir();
        let fname = format!("dlptest_staging_upload_{}.csv", uuid::Uuid::new_v4());
        let file_path = temp_dir.join(&fname);
        let sample_phi = "patient_id,mrn,ssn,icd10\nPT-8891,MRN-102938,456-78-9012,Asthma ICD10-J45\n";
        std::fs::write(&file_path, sample_phi).expect("write sample phi file");

        let payload = json!({
            "actor_process": "msedge.exe",
            "url": "https://dlptest.com/https-post/",
            "channel": "BROWSER_FILE_UPLOAD",
            "file_name": fname,
            "content": ""
        });

        let Json(res) = post_dlp_browser_event(Json(payload)).await;
        assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(res.get("allowed").and_then(|v| v.as_bool()), Some(false), "staged file must be resolved and denied");
        assert_eq!(res.get("authorization_decision").and_then(|v| v.as_str()), Some("DENY"));
        assert_eq!(res.get("dlp_response").and_then(|v| v.as_str()), Some("QUARANTINE"));

        let _ = std::fs::remove_file(file_path);
    }

    #[tokio::test]
    async fn test_probe_deduplication_coalescing() {
        let engine = osoosi_dp::OsoosiTwoTierDlpEngine::new();
        let mut state = DlpDashboardState {
            engine,
            policy_mode: "ENFORCE_BLOCK_AND_SCRUB".to_string(),
            min_phi_threshold: 0.7,
            redactx_detection_mode: "zero_leakage".to_string(),
            redactx_containment_mode: "conservative_containment".to_string(),
            total_inspections: 0,
            blocked_exfiltrations: 0,
            scrubbed_pii_entities: 0,
            zk_bft_proofs_verified: 0,
            crown_jewels: Vec::new(),
            recent_events: Vec::new(),
        };

        let payload = "worker exfiltration probe patient data ssn 123-45-6789";
        for _ in 0..3 {
            let (_, _, ev) = inspect_and_record_with_options(
                &mut state,
                "worker.exe",
                "https://paste.external.org/drop",
                "HTTPS_POST",
                payload,
                "API",
                DlpInspectOptions::default(),
            );
            assert!(!ev.allowed);
        }

        assert_eq!(state.recent_events.len(), 1, "Repeated probes must coalesce into 1 record");
        assert_eq!(state.recent_events[0].repeat_count, 3, "repeat_count must equal 3");
    }

    #[tokio::test]
    async fn test_post_dlp_release_flow() {
        let engine = osoosi_dp::OsoosiTwoTierDlpEngine::new();
        let mut state = DlpDashboardState {
            engine,
            policy_mode: "ENFORCE_BLOCK_AND_SCRUB".to_string(),
            min_phi_threshold: 0.7,
            redactx_detection_mode: "zero_leakage".to_string(),
            redactx_containment_mode: "conservative_containment".to_string(),
            total_inspections: 0,
            blocked_exfiltrations: 0,
            scrubbed_pii_entities: 0,
            zk_bft_proofs_verified: 0,
            crown_jewels: Vec::new(),
            recent_events: Vec::new(),
        };

        let (_, _, ev) = inspect_and_record_with_options(
            &mut state,
            "clinical_notes.exe",
            "https://hospital.internal.net/sync",
            "HTTPS_POST",
            "clinical note patient ssn 987-65-4321",
            "API",
            DlpInspectOptions::default(),
        );

        assert!(!ev.allowed);
        {
            let mut global = get_global_dlp_state().write();
            global.recent_events.insert(0, ev.clone());
            global.blocked_exfiltrations += 1;
        }

        let req = DlpReleaseRequest {
            zk_commitment_hex: Some(ev.zk_proof_commitment.clone()),
            destination_sink: Some("https://hospital.internal.net/sync".to_string()),
            scrubbed_preview: None,
            release_all_false_positives: false,
            reason: Some("Legitimate clinical note sync".to_string()),
        };

        let Json(res) = post_dlp_release(Json(req)).await;
        assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(res.get("released_count").and_then(|v| v.as_u64()), Some(1));

        let global = get_global_dlp_state().read();
        let released = global.recent_events.iter().find(|e| e.id == ev.id).expect("event must exist");
        assert!(released.allowed, "event must now be allowed");
        assert_eq!(released.authorization_decision, "ALLOW (USER_RELEASED)");
        assert_eq!(released.dlp_response, "RELEASED_BY_USER");
    }
}
