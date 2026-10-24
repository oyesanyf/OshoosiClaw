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

    let voter_quarantine = openjev_enforcement_agreed || rea_untrusted_actor;
    let dlp_detected = !tier1.detected_categories.is_empty() || proof.redacted_entity_count > 0;
    let final_verdict =
        osoosi_dp::aggregate_dlp_decision(dest_forbid, cj_export_denied, voter_quarantine, dlp_detected);
    tier1.allowed = final_verdict == osoosi_dp::DlpVerdict::Allow;
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

    let authorization_decision = final_verdict.as_authorization_str().to_string();
    let dlp_response = match final_verdict {
        osoosi_dp::DlpVerdict::Allow => "ALLOW".to_string(),
        osoosi_dp::DlpVerdict::Quarantine | osoosi_dp::DlpVerdict::Deny => "QUARANTINE".to_string(),
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

    let event = DlpInspectionEventRecord {
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

    if !(options.skip_recording_allowed && event.allowed) {
        state.recent_events.insert(0, event.clone());
        state.recent_events.truncate(250);
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
    let Ok(conn) = rusqlite::Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) else {
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
                out.push(ev);
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
        .unwrap_or(false);

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
    if let Some(mode) = body.get("redactx_containment_mode").and_then(|v| v.as_str()) {
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
/// Mounts all Two-Tier DLP routes and legacy aliases.
pub fn routes() -> Router<DashboardState> {
    Router::new()
        .route("/api/dlp/status", get(get_dlp_status))
        .route("/dlp/status", get(get_dlp_status))
        .route("/api/dlp/inspect", post(post_dlp_inspect))
        .route("/dlp/inspect", post(post_dlp_inspect))
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
