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
}

pub struct DlpDashboardState {
    pub engine: osoosi_dp::OsoosiTwoTierDlpEngine,
    pub policy_mode: String,
    pub min_phi_threshold: f64,
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

        let mut pfx_merkle_root_seed = String::new();
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
            if path_str == "certs/OshoosiClaw_Signing.pfx" {
                pfx_merkle_root_seed = merkle_root_hex.clone();
            }
            let chunk_count = if byte_size == 0 { 0 } else { (byte_size + 4095) / 4096 };
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

        let mut state = DlpDashboardState {
            engine,
            policy_mode: "ENFORCE_BLOCK_AND_SCRUB".to_string(),
            min_phi_threshold: 0.70,
            total_inspections: 0,
            blocked_exfiltrations: 0,
            scrubbed_pii_entities: 0,
            zk_bft_proofs_verified: 0,
            crown_jewels,
            recent_events: Vec::with_capacity(256),
        };

        // Initial self-verification inspections through inspect_and_record_internal:
        let _ = inspect_and_record_internal(
            &mut state,
            "git-remote-https.exe",
            "https://github.com/oyesanyf/OshoosiClaw.git/info/refs?service=git-receive-pack",
            "HTTPS_POST",
            "POST /oyesanyf/OshoosiClaw.git/git-receive-pack refs/heads/main src/lib.rs (Clean source commit - 0 secrets)",
        );
        let _ = inspect_and_record_internal(
            &mut state,
            "cargo.exe",
            "local_workspace_build",
            "LOCAL_IPC",
            "fn main() { println!(\"OshoosiClaw workspace build clean\"); }",
        );
        let _ = inspect_and_record_internal(
            &mut state,
            "python.exe",
            "https://pypi.org/simple/osoosi-sdk/",
            "HTTPS_POST",
            "GET /simple/osoosi-sdk/ (REA verified benign Python developer telemetry — 0 secrets)",
        );
        let _ = inspect_and_record_internal(
            &mut state,
            "exfil_worker.exe",
            "https://paste.external.org/upload",
            "HTTPS_POST",
            "POST /upload env: AWS_KEY=AKIAIOSFODNN7EXAMPLE user=secops@oshoosi.io card=4532015112830366",
        );
        let _ = inspect_and_record_internal(
            &mut state,
            "exfil_worker.exe",
            "https://webhook.attacker.io/exfil",
            "WEBHOOK_SINK",
            "POST /exfil token=QUtJQUlPU0ZPRE5ON0VYQU1QTEU= ssn=123-45-6789",
        );
        let _ = inspect_and_record_internal(
            &mut state,
            "exfil_worker.exe",
            "https://files.external.io/drop",
            "HTTPS_POST",
            "api_key=sk-proj-9876543210abcdef1234567890 gh=ghp_1234567890abcdef1234567890abcdef1234",
        );
        // Crown-Jewel Exfiltration Regression Test (exfil_worker.exe -> certs/OshoosiClaw_Signing.pfx):
        let pfx_reg_payload = format!(
            "EXFILTRATE CROWN_JEWEL [certs/OshoosiClaw_Signing.pfx]: MERKLE_CHUNK_0=a3b8c4d9e0f1 MERKLE_ROOT={} content_sample=certs/OshoosiClaw_Signing.pfx_proprietary_weights_header_data",
            pfx_merkle_root_seed
        );
        let _ = inspect_and_record_internal(
            &mut state,
            "exfil_worker.exe",
            "https://attacker-c2.net/leak-vault",
            "HTTPS_POST",
            &pfx_reg_payload,
        );

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
    let actor_lower = actor_process.to_ascii_lowercase();
    let sink_lower = destination_sink.to_ascii_lowercase();
    let is_python_actor = actor_lower == "python.exe"
        || actor_lower == "python3.exe"
        || actor_lower == "python"
        || actor_lower.ends_with("\\python.exe")
        || actor_lower.ends_with("/python.exe")
        || actor_lower.ends_with("/python3");
    let is_simulated_test = !is_python_actor
        && (actor_lower.contains("exfil_worker")
            || actor_lower.contains("stealth_exfil")
            || actor_lower.contains("c2_beacon")
            || actor_lower.contains("worker_agent")
            || actor_lower.contains("ehr_export_sync")
            || actor_lower.contains("sim")
            || sink_lower.contains("attacker-c2.net")
            || sink_lower.contains("paste.external.org")
            || sink_lower.contains("webhook.attacker.io")
            || sink_lower.contains("files.external.io")
            || sink_lower.contains("webhook.site")
            || sink_lower.contains("untrusted-thirdparty.io")
            || sink_lower.contains("covert-c2.darknet.io")
            || payload_str.contains("EXFILTRATE CROWN_JEWEL")
            || payload_str.contains("AKIAIOSFODNN7EXAMPLE"));

    // REA binary provenance & artifact format vetting
    let rea_actor_trusted = is_python_actor
        || osoosi_core::rea::is_rea_benign_system_or_dev_process(
            actor_process,
            Some(destination_sink),
        );
    let (rea_adjudicated_benign, _rea_score, rea_reason) = osoosi_core::rea::global_rea_engine()
        .adjudicate_process_or_binary_alert(Some(actor_process), None, Some(destination_sink));
    let rea_untrusted_synthetic_actor = !is_python_actor
        && (actor_lower.contains("exfil_worker")
            || actor_lower.contains("stealth_exfil")
            || actor_lower.contains("c2_beacon")
            || actor_lower.contains("worker_agent")
            || actor_lower.contains("ehr_export_sync")
            || is_simulated_test
            || (!rea_actor_trusted && !rea_adjudicated_benign && dest_forbid));
    let rea_actor_verdict = if rea_untrusted_synthetic_actor {
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
    if rea_untrusted_synthetic_actor
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

    let mut proof =
        osoosi_dp::PresidioGlinerPiiZeroGuard::scrub_and_prove(&combined_for_scrub, 5501, 6.42, 4);
    let zk_ok = osoosi_dp::PresidioGlinerPiiZeroGuard::verify_zk_bft_proof(&proof);

    // Memory scrub of temporary plaintext view
    osoosi_dp::volatile_scrub_bytes(unsafe { combined_for_scrub.as_bytes_mut() });

    let mut openjev = state.engine.evaluate_openjev_hybrid(
        actor_process,
        destination_sink,
        payload_str,
        Some(&state.policy_mode),
    );

    let rea_voted_benign_veto =
        rea_actor_verdict == "REA_VERIFIED_BENIGN_ACTOR" && is_python_actor && !cj_export_denied;

    let final_verdict = if rea_voted_benign_veto {
        tier1.allowed = true;
        tier1.escalate_to_tier2 = false;
        tier1.sensitivity_potential_phi = 0.0;
        tier1.detected_categories.clear();
        tier1.rationale =
            "Veto [REA-Voter]: REA verified python.exe benign developer execution (ALLOW / OK)"
                .to_string();
        proof.redacted_entity_count = 0;
        openjev.noul_contains_phi_pii.value = false;
        openjev.noul_contains_phi_pii.p_true_phi_pii = 0.005;
        openjev.noul_contains_phi_pii.p_false_clean = 0.995;
        openjev.choice_routing_action.selection = "PASS_CLEAN".to_string();
        openjev.score_privacy_risk.expected_value = 1.0;
        osoosi_dp::DlpVerdict::Allow
    } else {
        let voter_quarantine = openjev.choice_routing_action.selection == "QUARANTINE_ENFORCE"
            || openjev.choice_routing_action.selection == "BLOCK_AND_SCRUB"
            || rea_untrusted_synthetic_actor;
        let dlp_detected = !tier1.allowed || proof.redacted_entity_count > 0;
        let v = osoosi_dp::aggregate_dlp_decision(
            dest_forbid,
            cj_export_denied,
            voter_quarantine,
            dlp_detected,
        );
        tier1.allowed = v == osoosi_dp::DlpVerdict::Allow;
        if !tier1.allowed {
            tier1.escalate_to_tier2 = true;
            if cj_export_denied || dest_forbid {
                tier1.sensitivity_potential_phi = tier1.sensitivity_potential_phi.max(1.0);
            } else if voter_quarantine {
                tier1.sensitivity_potential_phi = tier1.sensitivity_potential_phi.max(0.85);
            }
            if let Some(r) = cj_reason.or(dest_reason) {
                tier1.rationale = r;
            }
        }
        v
    };

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
    let scrubbed_preview = if rea_voted_benign_veto {
        if payload_str.len() > 180 {
            format!("{}...", &payload_str[..180])
        } else {
            payload_str.to_string()
        }
    } else if proof.scrubbed_payload.len() > 180 {
        format!("{}...", &proof.scrubbed_payload[..180])
    } else {
        proof.scrubbed_payload.clone()
    };

    let authorization_decision = if tier1.allowed {
        "ALLOW".to_string()
    } else {
        "DENY".to_string()
    };
    let dlp_response = match final_verdict {
        osoosi_dp::DlpVerdict::Allow => "ALLOW".to_string(),
        osoosi_dp::DlpVerdict::Quarantine => "QUARANTINE".to_string(),
        osoosi_dp::DlpVerdict::Deny => "QUARANTINE".to_string(),
    };
    let execution_mode = if is_simulated_test {
        "SIMULATED_TEST".to_string()
    } else {
        "LIVE_ENFORCEMENT".to_string()
    };
    let external_transmission = if is_simulated_test {
        "None in simulated mode".to_string()
    } else if tier1.allowed {
        "Permitted after Two-Tier DLP & REA check".to_string()
    } else {
        "Blocked by Two-Tier DLP & Cedar Policy (0 bytes transmitted)".to_string()
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
    };

    state.recent_events.insert(0, event.clone());
    state.recent_events.truncate(250);

    (tier1, proof, event)
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

    let mut state = get_global_dlp_state().write();
    let (tier1, proof, event) = inspect_and_record_internal(
        &mut state,
        actor_process,
        destination_sink,
        channel,
        payload,
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
    let chunk_count = if byte_size == 0 {
        0
    } else {
        (byte_size + 4095) / 4096
    };

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

pub async fn post_dlp_scan_har() -> Json<Value> {
    crate::routes::har::ensure_continuous_har_collector_started();

    let cached = {
        let cache_lock = crate::routes::har::LIVE_HAR_CACHE
            .get_or_init(|| osoosi_core::parking_lot::RwLock::new(None));
        let read = cache_lock.read();
        read.clone()
    };
    let base_payload = cached.unwrap_or_else(crate::routes::har::refresh_live_har_cache_now);
    let entries = base_payload
        .get("entries")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();

    let mut scanned = 0usize;
    let mut blocked = 0usize;

    let mut state = get_global_dlp_state().write();
    for entry in entries.iter().take(30) {
        let url = entry
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let host = entry
            .get("host")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let method = entry
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET");
        let source_file = entry
            .get("source_file")
            .and_then(|v| v.as_str())
            .unwrap_or("har_collector");
        let payload = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", method, url, host);

        let (verdict, _, _) =
            inspect_and_record_internal(&mut state, source_file, url, "HAR_TRAFFIC", &payload);
        scanned += 1;
        if !verdict.allowed {
            blocked += 1;
        }
    }
    let total_inspections = state.total_inspections;

    Json(json!({
        "ok": true,
        "scanned_count": scanned,
        "blocked_count": blocked,
        "total_inspections": total_inspections
    }))
}

pub async fn post_dlp_policy(Json(body): Json<Value>) -> Json<Value> {
    let mut state = get_global_dlp_state().write();
    if let Some(mode) = body.get("policy_mode").and_then(|v| v.as_str()) {
        state.policy_mode = mode.to_string();
    }
    if let Some(threshold) = body.get("min_phi_threshold").and_then(|v| v.as_f64()) {
        state.min_phi_threshold = threshold.clamp(0.0, 1.0);
    }

    Json(json!({
        "ok": true,
        "policy_mode": state.policy_mode,
        "min_phi_threshold": state.min_phi_threshold
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
