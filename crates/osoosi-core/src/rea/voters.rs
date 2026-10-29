#![allow(unused_imports)]
use anyhow::{anyhow, Result};
use chrono::Utc;
use flate2::read::ZlibDecoder;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tracing::{debug, info};

use super::*;

// ============================================================================
// Paired Universal Voters: [REA-Voter] + [OpenJEV-Voter]
// ============================================================================

static GLOBAL_OPENJEV_ENGINE: LazyLock<osoosi_dp::OsoosiTwoTierDlpEngine> =
    LazyLock::new(osoosi_dp::OsoosiTwoTierDlpEngine::new);
static OPENJEV_VOTES_CAST: AtomicU64 = AtomicU64::new(0);
static OPENJEV_ESCALATIONS: AtomicU64 = AtomicU64::new(0);
static OPENJEV_BENIGN_VETOES: AtomicU64 = AtomicU64::new(0);
static OPENJEV_SECRET_INTERCEPTIONS: AtomicU64 = AtomicU64::new(0);

/// Checks if a command line, reason, or event payload contains active Living-Off-The-Land (LOTL),
/// credential theft, memory injection, or canary-trap behavioral indicators that must NEVER be vetoed.
pub fn has_active_lotl_or_exploit_indicators(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    const ACTIVE_ATTACK_MARKERS: &[&str] = &[
        "keymgr",
        "krshowkeymgr",
        "comsvcs",
        "minidump",
        "sekurlsa",
        "lsass",
        "-enc ",
        "-encodedcommand",
        "frombase64string",
        "downloadstring",
        "invoke-expression",
        "iex(",
        "canarytraptripped",
        "canaryalert",
        "canary_honey_pipe",
        "virtualallocex",
        "writeprocessmemory",
        "createremotethread",
        "ntmapviewofsection",
        "queueuserapc",
        "vssadmin delete shadows",
        "wmic shadowcopy delete",
        "ntds.dit",
        "procdump",
        "mimikatz",
        "cobalt",
        "meterpreter",
        "reverse_tcp",
    ];
    ACTIVE_ATTACK_MARKERS.iter().any(|m| lower.contains(m))
}

/// Evaluates a process/command/payload using `OsoosiTwoTierDlpEngine` (`RedactX-v3` + `OpenJEV` Joint Evidence Voting:
/// `Noul` validator/lexical evidence + `Choice` categorical routing + `Score` Platt-calibrated probability $T=1.08$).
pub fn evaluate_openjev_consensus_vote(
    actor_process: &str,
    destination_sink: &str,
    payload_text: &str,
) -> ReaConsensusVote {
    OPENJEV_VOTES_CAST.fetch_add(1, Ordering::Relaxed);
    let tier1 = GLOBAL_OPENJEV_ENGINE.inspect_hot_tier1(
        actor_process,
        destination_sink,
        payload_text.as_bytes(),
    );
    let verdict = GLOBAL_OPENJEV_ENGINE.evaluate_openjev_hybrid(
        actor_process,
        destination_sink,
        payload_text,
        Some("zero_leakage"),
    );

    let mut all_categories = tier1.detected_categories.clone();
    for cat in &verdict.validator_confirmed_categories {
        if !all_categories.contains(cat) {
            all_categories.push(cat.clone());
        }
    }

    let seal = blake3_hex(
        format!(
            "openjev:vote:{}:{}:{}:{:.4}",
            actor_process,
            destination_sink,
            all_categories.join(","),
            verdict.noul_contains_phi_pii.p_true_phi_pii
        )
        .as_bytes(),
    );

    if !all_categories.is_empty()
        || (verdict.noul_contains_phi_pii.p_true_phi_pii >= 0.85
            && !is_rea_benign_system_or_dev_process(actor_process, Some(payload_text)))
    {
        OPENJEV_ESCALATIONS.fetch_add(1, Ordering::Relaxed);
        OPENJEV_SECRET_INTERCEPTIONS.fetch_add(1, Ordering::Relaxed);
        let conf = verdict
            .noul_contains_phi_pii
            .p_true_phi_pii
            .max(0.94)
            .clamp(0.85, 0.999);
        return ReaConsensusVote {
            voter_name: "OpenJEV-Voter".to_string(),
            target: actor_process.to_string(),
            detector_source: destination_sink.to_string(),
            decision: "ESCALATE_MALICIOUS".to_string(),
            weight: 1.75,
            confidence: conf,
            benign_veto: false,
            masquerade_escalated: false,
            prompt_injection_detected: false,
            reason: format!(
                "Escalate [OpenJEV-Voter]: Joint Evidence Voting (Noul p={:.3}, Choice={}, Score={:.2}/5, T=1.08) detected sensitive/exfil tokens [{}]",
                verdict.noul_contains_phi_pii.p_true_phi_pii,
                verdict.choice_routing_action.selection,
                verdict.score_privacy_risk.expected_value,
                all_categories.join(", ")
            ),
            rea_seal_blake3: seal,
            timestamp: Utc::now().to_rfc3339(),
        };
    }

    if !has_active_lotl_or_exploit_indicators(payload_text)
        && (verdict.canonical_git_push_allowed
            || verdict.choice_routing_action.selection == "PASS_CLEAN")
    {
        OPENJEV_BENIGN_VETOES.fetch_add(1, Ordering::Relaxed);
        let conf = verdict
            .noul_contains_phi_pii
            .p_false_clean
            .clamp(0.85, 0.995);
        return ReaConsensusVote {
            voter_name: "OpenJEV-Voter".to_string(),
            target: actor_process.to_string(),
            detector_source: destination_sink.to_string(),
            decision: "VETO_BENIGN".to_string(),
            weight: -1.25,
            confidence: conf,
            benign_veto: true,
            masquerade_escalated: false,
            prompt_injection_detected: false,
            reason: format!(
                "Veto [OpenJEV-Voter]: Joint Evidence Voting (Noul p_clean={:.3}, Choice={}, Score={:.2}/5, T=1.08) attested zero credential/PII exfiltration risk",
                verdict.noul_contains_phi_pii.p_false_clean,
                verdict.choice_routing_action.selection,
                verdict.score_privacy_risk.expected_value
            ),
            rea_seal_blake3: seal,
            timestamp: Utc::now().to_rfc3339(),
        };
    }

    ReaConsensusVote {
        voter_name: "OpenJEV-Voter".to_string(),
        target: actor_process.to_string(),
        detector_source: destination_sink.to_string(),
        decision: "ATTEST_NEUTRAL".to_string(),
        weight: 0.0,
        confidence: verdict.noul_contains_phi_pii.evidential_confidence,
        benign_veto: false,
        masquerade_escalated: false,
        prompt_injection_detected: false,
        reason: format!(
            "[OpenJEV-Voter] Neutral evaluation for '{}' (Choice={})",
            actor_process, verdict.choice_routing_action.selection
        ),
        rea_seal_blake3: seal,
        timestamp: Utc::now().to_rfc3339(),
    }
}

/// Returns live telemetry snapshot for the paired `OpenJevVoter` (`[OpenJEV-Voter]`).
pub fn openjev_voter_stats_snapshot() -> Value {
    json!({
        "voter_name": "OpenJEV-Voter",
        "engine": "RedactX-v3-OpenJEV-Hybrid",
        "primitives": ["Noul (Platt T=1.08)", "Choice (Constrained Routing)", "Score (Ordinal 1..5)"],
        "votes_cast": OPENJEV_VOTES_CAST.load(Ordering::Relaxed),
        "escalations": OPENJEV_ESCALATIONS.load(Ordering::Relaxed),
        "benign_vetoes": OPENJEV_BENIGN_VETOES.load(Ordering::Relaxed),
        "secret_interceptions": OPENJEV_SECRET_INTERCEPTIONS.load(Ordering::Relaxed),
        "crown_jewel_assets": GLOBAL_OPENJEV_ENGINE.crown_jewels.chunk_hashes.len(),
    })
}

/// Universal REA Threat Voter (`[REA-Voter]`) participating in `PolicyEngine` consensus.
pub struct ReaVoter;

pub type ReaForensicVoter = ReaVoter;
pub type ReaUniversalConsensusVoter = ReaVoter;

impl Default for ReaVoter {
    fn default() -> Self {
        Self::new()
    }
}

impl ReaVoter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl osoosi_policy::engine::ThreatVoter for ReaVoter {
    fn name(&self) -> String {
        "REA-Voter".to_string()
    }

    async fn vote(
        &self,
        event: &osoosi_types::HostSecurityEvent,
    ) -> Option<osoosi_policy::engine::VoteResult> {
        let is_image_load_event = event.event_id == 7
            || event.data.get("ImageLoaded").is_some()
            || event.data.get("image_loaded").is_some();

        let image_loaded = event
            .data
            .get("ImageLoaded")
            .or_else(|| event.data.get("image_loaded"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let image = event
            .data
            .get("Image")
            .or_else(|| event.data.get("ImageLoaded"))
            .or_else(|| event.data.get("image_loaded"))
            .or_else(|| event.data.get("NewProcessName"))
            .or_else(|| event.data.get("ProcessName"))
            .or_else(|| event.data.get("ImagePath"))
            .or_else(|| event.data.get("TargetFilename"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let cmdline = event
            .data
            .get("CommandLine")
            .or_else(|| event.data.get("command_line"))
            .or_else(|| event.data.get("Payload"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if image.is_empty() && cmdline.is_empty() && image_loaded.is_empty() {
            return None;
        }

        // Target for evaluation: prioritize the loaded library for Sysmon Event 7
        let target = if is_image_load_event && !image_loaded.is_empty() {
            image_loaded
        } else if !image.is_empty() {
            image
        } else {
            cmdline
        };
        let combined_context = if is_image_load_event && !image_loaded.is_empty() {
            format!("{} {} ImageLoaded: {}", image, cmdline, image_loaded)
        } else {
            format!("{} {}", image, cmdline)
        };

        // Check if session or event carries untrusted taint
        let is_tainted_session = event
            .data
            .get("untrusted_taint")
            .and_then(|v| v.as_bool().or_else(|| v.as_i64().map(|n| n != 0)))
            .unwrap_or(false)
            || event
                .data
                .get("taint_level")
                .and_then(|v| v.as_i64())
                .map(|lvl| lvl > 0)
                .unwrap_or(false)
            || event
                .data
                .get("tainted")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            || event
                .data
                .get("has_crown_jewel_taint")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

        // Check if dynamic load is unsigned, untrusted path, or non-allowlisted
        let is_unsigned_or_untrusted_dynamic_load =
            if is_image_load_event && !image_loaded.is_empty() {
                let signed_field = event
                    .data
                    .get("Signed")
                    .or_else(|| event.data.get("is_signed"));
                let is_signed_false = signed_field
                    .map(|v| {
                        if let Some(b) = v.as_bool() {
                            !b
                        } else if let Some(s) = v.as_str() {
                            s.eq_ignore_ascii_case("false") || s == "0"
                        } else {
                            false
                        }
                    })
                    .unwrap_or(false);

                let sig_status = event
                    .data
                    .get("SignatureStatus")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let sig_invalid = !sig_status.is_empty()
                    && !sig_status.eq_ignore_ascii_case("Valid")
                    && !sig_status.eq_ignore_ascii_case("ValidSignature");

                let is_untrusted_path = is_untrusted_writable_or_temp_path(image_loaded);
                is_signed_false || sig_invalid || is_untrusted_path
            } else {
                false
            };

        // 1. Check Layer 4 counter-AI prompt injection in event image or command line
        let mut dummy_recon = String::new();
        let (pi_findings, _san) = scan_and_sanitize_counter_ai_strings(
            combined_context.as_bytes(),
            &mut dummy_recon,
            false,
        );
        if !pi_findings.is_empty() {
            let engine = global_rea_engine();
            let vote = engine.cast_consensus_vote(
                target,
                "Consensus/HostSecurityEvent",
                &combined_context,
                0.98,
            );
            return Some(osoosi_policy::engine::VoteResult {
                confidence: 0.98,
                weight: 1.85,
                reason: vote.reason,
            });
        }

        // 2. Check Layer 1 binary masquerading (e.g. %TEMP%\cl.exe, \Downloads\svchost.exe)
        let eval_binary = if is_image_load_event && !image_loaded.is_empty() {
            image_loaded
        } else {
            image
        };
        if !eval_binary.is_empty() {
            if let Some(spoof_reason) =
                detect_binary_masquerade_spoof(eval_binary, Some(Path::new(eval_binary)), None)
            {
                let engine = global_rea_engine();
                engine
                    .masquerade_attempts_blocked
                    .fetch_add(1, Ordering::Relaxed);
                engine
                    .malicious_confirmations
                    .fetch_add(1, Ordering::Relaxed);
                let reason = format!("Escalate [REA-Voter]: {}", spoof_reason);
                engine.record_consensus_vote(ReaConsensusVote {
                    voter_name: "REA-Voter".to_string(),
                    target: eval_binary.to_string(),
                    detector_source: "Consensus/HostSecurityEvent".to_string(),
                    decision: "ESCALATE_MALICIOUS".to_string(),
                    weight: 1.85,
                    confidence: 0.98,
                    benign_veto: false,
                    masquerade_escalated: true,
                    prompt_injection_detected: false,
                    reason: reason.clone(),
                    rea_seal_blake3: blake3_hex(reason.as_bytes()),
                    timestamp: Utc::now().to_rfc3339(),
                });
                return Some(osoosi_policy::engine::VoteResult {
                    confidence: 0.98,
                    weight: 1.85,
                    reason,
                });
            }
        }

        // 3. Escalate on untrusted/unsigned dynamic module injection
        if is_unsigned_or_untrusted_dynamic_load {
            let reason = format!(
                "Escalate [REA-Voter]: Untrusted or unsigned dynamic module load: {} in host process {}",
                image_loaded, image
            );
            let engine = global_rea_engine();
            engine
                .malicious_confirmations
                .fetch_add(1, Ordering::Relaxed);
            engine.record_consensus_vote(ReaConsensusVote {
                voter_name: "REA-Voter".to_string(),
                target: image_loaded.to_string(),
                detector_source: "Consensus/HostSecurityEvent/ImageLoad".to_string(),
                decision: "ESCALATE_MALICIOUS".to_string(),
                weight: 1.85,
                confidence: 0.95,
                benign_veto: false,
                masquerade_escalated: false,
                prompt_injection_detected: false,
                reason: reason.clone(),
                rea_seal_blake3: blake3_hex(reason.as_bytes()),
                timestamp: Utc::now().to_rfc3339(),
            });
            return Some(osoosi_policy::engine::VoteResult {
                confidence: 0.95,
                weight: 1.85,
                reason,
            });
        }

        // 4. Escalate if the event carries active LOTL/behavioral indicators or CanaryTrapTripped!
        let canary_tripped = event
            .data
            .get("CanaryTrapTripped")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
            || event.data.get("CanaryAlert").is_some();
        if canary_tripped || has_active_lotl_or_exploit_indicators(&combined_context) {
            let engine = global_rea_engine();
            let target_lbl = if !image.is_empty() {
                image
            } else {
                "host_event"
            };
            let vote = engine.cast_consensus_vote(
                target_lbl,
                "Consensus/HostSecurityEvent",
                &combined_context,
                0.95,
            );
            return Some(osoosi_policy::engine::VoteResult {
                confidence: vote.confidence.max(0.95) as f32,
                weight: 1.85,
                reason: vote.reason,
            });
        }

        // 5. Canonical trusted OS/developer binary veto
        // Strict Invariant: NEVER grant benign veto if:
        // (a) An unsigned, non-allowlisted DLL/module was loaded into the process, or
        // (b) The session carries untrusted_taint == true or positive taint level.
        let static_reason = event
            .data
            .get("StaticReason")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !is_tainted_session && !is_unsigned_or_untrusted_dynamic_load && !image.is_empty() {
            let reason_context = if !static_reason.is_empty() {
                static_reason
            } else if is_image_load_event {
                "image_load"
            } else {
                cmdline
            };
            if is_rea_benign_system_or_dev_process(image, Some(reason_context)) {
                let engine = global_rea_engine();
                let vote = engine.cast_consensus_vote(
                    image,
                    "Consensus/HostSecurityEvent",
                    reason_context,
                    0.05,
                );
                if vote.benign_veto {
                    return Some(osoosi_policy::engine::VoteResult {
                        confidence: vote.confidence as f32,
                        weight: -1.50,
                        reason: vote.reason,
                    });
                }
            } else if !static_reason.is_empty() {
                let engine = global_rea_engine();
                let raw_conf = event
                    .data
                    .get("StaticConfidence")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.85);
                let vote = engine.cast_consensus_vote(
                    image,
                    "Consensus/HostSecurityEvent",
                    static_reason,
                    raw_conf,
                );
                if !vote.benign_veto {
                    return Some(osoosi_policy::engine::VoteResult {
                        confidence: vote.confidence.clamp(0.75, 0.99) as f32,
                        weight: 1.50,
                        reason: vote.reason,
                    });
                }
            }
        }

        None
    }

    fn stats(&self) -> Value {
        global_rea_engine().universal_coverage_snapshot()
    }
}

/// Universal OpenJEV Threat Voter (`[OpenJEV-Voter]`) participating in `PolicyEngine` consensus
/// alongside `[REA-Voter]`. Evaluates command lines, HAR/HTTP payloads, agent tool arguments,
/// and DLP events using `OsoosiTwoTierDlpEngine` (`Noul` + `Choice` + `Score` Platt $T=1.08$).
pub struct OpenJevVoter;

pub type OpenJevUniversalVoter = OpenJevVoter;

impl Default for OpenJevVoter {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenJevVoter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl osoosi_policy::engine::ThreatVoter for OpenJevVoter {
    fn name(&self) -> String {
        "OpenJEV-Voter".to_string()
    }

    async fn vote(
        &self,
        event: &osoosi_types::HostSecurityEvent,
    ) -> Option<osoosi_policy::engine::VoteResult> {
        let image = event
            .data
            .get("Image")
            .or_else(|| event.data.get("ProcessName"))
            .or_else(|| event.data.get("Application"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown_process");
        let sink = event
            .data
            .get("DestinationHostname")
            .or_else(|| event.data.get("DestinationIp"))
            .or_else(|| event.data.get("Url"))
            .or_else(|| event.data.get("TargetFilename"))
            .and_then(|v| v.as_str())
            .unwrap_or("host_telemetry");

        let mut payload_parts = Vec::new();
        for key in [
            "CommandLine",
            "command_line",
            "cmdline",
            "Payload",
            "RequestHeaders",
            "RequestBody",
            "Details",
            "Url",
            "StaticReason",
        ] {
            if let Some(s) = event.data.get(key).and_then(|v| v.as_str()) {
                if !s.trim().is_empty() {
                    payload_parts.push(s.trim());
                }
            }
        }
        if payload_parts.is_empty() {
            return None;
        }
        let payload_text = payload_parts.join(" | ");

        let vote = evaluate_openjev_consensus_vote(image, sink, &payload_text);
        global_rea_engine().record_consensus_vote(vote.clone());

        if vote.decision == "ESCALATE_MALICIOUS" {
            return Some(osoosi_policy::engine::VoteResult {
                confidence: vote.confidence as f32,
                weight: vote.weight as f32,
                reason: vote.reason,
            });
        }

        // Only emit a negative veto weight if the process is a known canonical dev/system binary
        // and there are no active LOTL/behavioral indicators or masquerading spoofs.
        let canary_tripped = event
            .data
            .get("CanaryTrapTripped")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
            || event.data.get("CanaryAlert").is_some();
        if vote.benign_veto
            && !canary_tripped
            && !has_active_lotl_or_exploit_indicators(&payload_text)
            && is_rea_benign_system_or_dev_process(image, Some(&payload_text))
        {
            return Some(osoosi_policy::engine::VoteResult {
                confidence: vote.confidence as f32,
                weight: -1.25,
                reason: vote.reason,
            });
        }

        None
    }

    fn stats(&self) -> Value {
        openjev_voter_stats_snapshot()
    }
}
