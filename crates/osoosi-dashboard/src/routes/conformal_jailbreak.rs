use axum::{
    extract::{Json, State},
    routing::{get, post},
    Router,
};
use once_cell::sync::Lazy;
use osoosi_behavioral::{
    conformal_bounds, embed_prompt_representation_64d, DkwProductSupermartingale,
    MultiSourceCalibration, PersistDetector, SrDetector,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Mutex;

use crate::{api_error_json, DashboardState};

struct ConformalRuntimeState {
    persist: PersistDetector,
    sr_dkw: SrDetector,
    e_mix: DkwProductSupermartingale,
    last_c_fam: f64,
    last_best_source: String,
    last_sr_val: f64,
    last_e_mix: f64,
    total_layered_blocks: usize,
}

impl ConformalRuntimeState {
    fn new() -> Self {
        let cal = MultiSourceCalibration::default_11_sources_32d();
        let persist =
            PersistDetector::persist_3(cal.clone(), PersistDetector::DEFAULT_TAU_ORIGINAL_SPLIT);
        let sr_dkw = SrDetector::new(cal.clone(), 25.0, Some(0.05), None);
        let e_mix = DkwProductSupermartingale::new(cal, 0.01, 0.05);
        Self {
            persist,
            sr_dkw,
            e_mix,
            last_c_fam: 0.0,
            last_best_source: "GCG".to_string(),
            last_sr_val: 0.0,
            last_e_mix: 1.0,
            total_layered_blocks: 0,
        }
    }
}

static CONFORMAL_STATE: Lazy<Mutex<ConformalRuntimeState>> =
    Lazy::new(|| Mutex::new(ConformalRuntimeState::new()));

pub fn routes() -> Router<DashboardState> {
    Router::new()
        .route("/api/conformal-jailbreak/status", get(get_conformal_status))
        .route("/api/conformal-jailbreak/step", post(post_conformal_step))
        .route(
            "/api/conformal-jailbreak/enroll",
            post(post_conformal_enroll),
        )
}

#[derive(Debug, Deserialize)]
pub struct ConformalStepRequest {
    pub prompt: Option<String>,
    pub embedding: Option<Vec<f64>>,
    pub guardrail_blocked: Option<bool>,
    pub reset: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ConformalEnrollRequest {
    pub source_name: String,
    pub train_embeddings: Vec<Vec<f64>>,
    pub calibration_embeddings: Vec<Vec<f64>>,
}

async fn get_conformal_status(State(_state): State<DashboardState>) -> Json<Value> {
    let guard = match CONFORMAL_STATE.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    let w = guard.persist.window_size;
    let l = guard.persist.persistence_length;
    let b = guard.persist.finite_memory_horizon();
    let tau = guard.persist.tau;
    let a_wl = conformal_bounds::overlap_weight_sum_sq(w, l);
    let eff_n = ((l * w) * (l * w)) as f64 / (a_wl as f64);
    let fa_bound = conformal_bounds::stationary_false_alarm_bound(w, l, tau, 1.0, 100);
    let fh_bound = conformal_bounds::finite_horizon_false_alarm_bound(40, w, l, tau, 1.0, 100);
    let source_names: Vec<String> = guard
        .persist
        .calibration
        .sources
        .iter()
        .map(|s| s.name.clone())
        .collect();

    Json(json!({
        "status": "ok",
        "framework": "Multi-Source Conformal Unseen Jailbreak Detection (Persist-3 & SR-DKW)",
        "reference": "Qian et al. (2026), arXiv:2610.09167v1",
        "calibration": {
            "num_known_sources": source_names.len(),
            "known_sources": source_names,
            "pca_input_dim": guard.persist.calibration.pca_mean.len(),
            "pca_projected_dim": guard.persist.calibration.pca_components.ncols(),
            "window_size_w": w,
            "persistence_length_l": l,
            "finite_forgetting_horizon_b": b,
            "tau_original_split": PersistDetector::DEFAULT_TAU_ORIGINAL_SPLIT,
            "tau_robustness_resplit": PersistDetector::DEFAULT_TAU_ROBUSTNESS_RESPLIT,
            "active_tau": tau,
        },
        "theoretical_bounds": {
            "overlap_weight_sum_sq_a_wl": a_wl,
            "effective_sample_size": eff_n,
            "stationary_false_alarm_bound": fa_bound,
            "finite_horizon_40_false_alarm_bound": fh_bound,
        },
        "runtime": {
            "last_c_fam": guard.last_c_fam,
            "last_best_matching_source": guard.last_best_source,
            "sr_dkw_statistic": guard.last_sr_val,
            "dkw_product_e_mix": guard.last_e_mix,
            "total_layered_blocks": guard.total_layered_blocks,
        }
    }))
}

async fn post_conformal_step(
    State(_state): State<DashboardState>,
    Json(req): Json<ConformalStepRequest>,
) -> Json<Value> {
    let mut guard = match CONFORMAL_STATE.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    if req.reset.unwrap_or(false) {
        guard.persist.reset();
        guard.sr_dkw.reset();
        guard.last_c_fam = 0.0;
        guard.last_sr_val = 0.0;
        guard.last_e_mix = 1.0;
    }

    let repr: Vec<f64> = if let Some(emb) = req.embedding {
        if emb.is_empty() {
            return api_error_json(
                "EMPTY_EMBEDDING",
                "embedding vector must not be empty",
                "Provide a non-empty 64-D representation vector or a prompt string.",
            );
        }
        emb
    } else if let Some(prompt) = req.prompt.as_deref() {
        embed_prompt_representation_64d(prompt)
    } else {
        return api_error_json(
            "MISSING_INPUT",
            "Either 'prompt' or 'embedding' must be provided",
            "Pass either a 'prompt' string or an 'embedding' array in the JSON body.",
        );
    };

    let g_t = req.guardrail_blocked.unwrap_or(false);
    let step_res = guard.persist.observe_slice(&repr);
    let (sr_val, sr_escalated) = guard.sr_dkw.observe_slice(&repr);
    let (e_mix_val, e_mix_escalated) = guard.e_mix.observe_slice(&repr);

    let combined_intervention = g_t || step_res.escalated || sr_escalated;
    if combined_intervention {
        guard.total_layered_blocks += 1;
    }
    guard.last_c_fam = step_res.c_fam;
    guard.last_best_source = step_res.best_matching_source_name.clone();
    guard.last_sr_val = sr_val;
    guard.last_e_mix = e_mix_val;

    Json(json!({
        "status": "ok",
        "persist3": step_res,
        "sr_dkw": {
            "r_t": sr_val,
            "escalated": sr_escalated,
        },
        "dkw_product_supermartingale": {
            "e_union_t": e_mix_val,
            "escalated": e_mix_escalated,
        },
        "layered_guardrail": {
            "guardrail_g_t": g_t,
            "monitor_a_t": step_res.escalated,
            "combined_i_t": combined_intervention,
        }
    }))
}

async fn post_conformal_enroll(
    State(_state): State<DashboardState>,
    Json(req): Json<ConformalEnrollRequest>,
) -> Json<Value> {
    if req.source_name.trim().is_empty() {
        return api_error_json(
            "INVALID_SOURCE_NAME",
            "source_name must not be empty",
            "Provide a non-empty name for the newly enrolled jailbreak source.",
        );
    }
    let mut guard = match CONFORMAL_STATE.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    match guard.persist.enroll_detected_source_vecs(
        req.source_name.trim(),
        &req.train_embeddings,
        &req.calibration_embeddings,
    ) {
        Ok(new_k) => {
            guard.sr_dkw.calibration = guard.persist.calibration.clone();
            guard.e_mix =
                DkwProductSupermartingale::new(guard.persist.calibration.clone(), 0.01, 0.05);
            Json(json!({
                "status": "ok",
                "enrolled_source": req.source_name.trim(),
                "total_known_sources": new_k,
                "corollary_b6_mdcp_valid": true,
            }))
        }
        Err(err) => api_error_json(
            "ENROLLMENT_FAILED",
            err,
            "Ensure train_embeddings and calibration_embeddings are non-empty 64-D vectors.",
        ),
    }
}
