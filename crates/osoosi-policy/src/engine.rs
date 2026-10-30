//! Threat Engine (The "Brain").
//!
//! Correlates telemetry events with threat signatures.

use crate::feed::OtxIndicators;
use crate::graph::{GraphCorrelationEngine, Relationship};
use crate::semantic::SemanticEngine;
use dashmap::DashMap;
use osoosi_memory::MemoryStore;
use osoosi_types::{HostSecurityEvent, ProcessInstanceKey, ThreatSignature, VoterQuorumAlert};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::RwLock;
use tracing::{debug, info, warn};

/// `tracing` target for grep-friendly consensus / voting lines (`RUST_LOG=consensus=debug`).
pub const CONSENSUS_LOG_TARGET: &str = "consensus";

#[derive(Debug, Clone)]
pub struct VoteResult {
    pub confidence: f32,
    pub reason: String,
    pub weight: f32,
}

use async_trait::async_trait;

#[allow(clippy::double_must_use)]
#[async_trait]
pub trait ThreatVoter: Send + Sync {
    fn name(&self) -> String;
    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult>;
    /// Returns true if this voter is resource-intensive (AI/Decompile).
    fn is_heavy(&self) -> bool {
        false
    }
    fn stats(&self) -> serde_json::Value {
        serde_json::json!({})
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceClass {
    LiveNetwork,
    Behavior,
    Memory,
    StaticArtifact,
    ThreatIntel,
    Reputation,
}

#[derive(Debug, Clone)]
pub struct EvidenceVote {
    pub result: VoteResult,
    pub class: EvidenceClass,
    pub reliability: f32,
    pub strong_action: bool,
}

#[derive(Debug)]
pub struct EvidenceDecision {
    pub confidence: f32,
    pub action: osoosi_types::ResponseAction,
    pub require_approval: bool,
    pub summary: String,
}

fn process_name_from_event(event: &HostSecurityEvent) -> Option<String> {
    if let Some(p) = event_image_path(event) {
        if let Some(name) = std::path::Path::new(p).file_name().and_then(|n| n.to_str()) {
            let trimmed = name.trim();
            if !trimmed.is_empty()
                && !trimmed.eq_ignore_ascii_case("unknown")
                && !trimmed.eq_ignore_ascii_case("unknown process")
            {
                return Some(trimmed.to_string());
            }
        }
    }

    // Fallback 1: extract executable from CommandLine / command_line / cmdline / Command
    for field in &["CommandLine", "command_line", "cmdline", "Command"] {
        if let Some(cmd) = event.data.get(*field).and_then(|v| v.as_str()) {
            let trimmed = cmd.trim();
            if !trimmed.is_empty() {
                let first_tok = if let Some(stripped) = trimmed.strip_prefix('"') {
                    stripped.split('"').next().unwrap_or(trimmed)
                } else if let Some(stripped) = trimmed.strip_prefix('\'') {
                    stripped.split('\'').next().unwrap_or(trimmed)
                } else {
                    trimmed.split_whitespace().next().unwrap_or(trimmed)
                };
                let fname = std::path::Path::new(first_tok)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(first_tok)
                    .trim();
                if !fname.is_empty()
                    && !fname.eq_ignore_ascii_case("unknown")
                    && !fname.eq_ignore_ascii_case("unknown process")
                {
                    return Some(fname.to_string());
                }
            }
        }
    }

    // Fallback 2: TargetFilename / TargetObject / DestinationIp
    for field in &[
        "TargetFilename",
        "TargetFilename_name",
        "TargetObject",
        "DestinationIp",
        "DestinationHostname",
        "QueryName",
    ] {
        if let Some(val) = event.data.get(*field).and_then(|v| v.as_str()) {
            let trimmed = val.trim();
            if !trimmed.is_empty()
                && !trimmed.eq_ignore_ascii_case("unknown")
                && !trimmed.eq_ignore_ascii_case("unknown process")
            {
                if let Some(fname) = std::path::Path::new(trimmed)
                    .file_name()
                    .and_then(|n| n.to_str())
                {
                    if !fname.trim().is_empty() {
                        return Some(fname.trim().to_string());
                    }
                }
                return Some(trimmed.to_string());
            }
        }
    }

    None
}

fn preferred_hash_from_event(event: &HostSecurityEvent) -> Option<String> {
    let hashes = event.data.get("Hashes")?.as_str()?;
    for prefix in ["SHA256=", "SHA256:", "SHA1=", "SHA1:", "MD5=", "MD5:"] {
        if let Some(value) = hashes
            .split(',')
            .map(str::trim)
            .find_map(|part| part.strip_prefix(prefix))
        {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_ascii_lowercase());
            }
        }
    }
    None
}

fn event_image_path(event: &HostSecurityEvent) -> Option<&str> {
    for field in &[
        "Image",
        "NewProcessName",
        "ProcessName",
        "ImagePath",
        "SourceImage",
        "TargetImage",
        "Application",
    ] {
        if let Some(val) = event.data.get(*field).and_then(|v| v.as_str()) {
            if !val.trim().is_empty() && val != "unknown" {
                return Some(val);
            }
        }
    }
    None
}

/// Normalizes Windows NT device paths (`\Device\HarddiskVolume3\Windows\System32\conhost.exe`)
/// to standard Win32 paths (`C:\Windows\System32\conhost.exe` or `D:\...`) so disk reads,
/// Authenticode checks, and BLAKE3 hashing succeed.
pub fn normalize_nt_device_path(raw: &str) -> String {
    let trimmed = raw.trim().trim_matches('"');
    let lower = trimmed.to_ascii_lowercase();
    for prefix in ["\\device\\harddiskvolume", "/device/harddiskvolume"] {
        if lower.starts_with(prefix) {
            let after = &trimmed[prefix.len()..];
            let digits_len = after.chars().take_while(|c| c.is_ascii_digit()).count();
            let vol_num = &after[..digits_len];
            let rest = after[digits_len..].trim_start_matches(['\\', '/']);
            if !rest.is_empty() {
                let win_rest = rest.replace('/', "\\");
                for drive in ["C", "D", "E", "F"] {
                    let candidate = format!("{}:\\{}", drive, win_rest);
                    if std::path::Path::new(&candidate).exists() {
                        return candidate;
                    }
                }
                let fallback_drive =
                    if vol_num == "4" || win_rest.to_ascii_lowercase().starts_with("harfile") {
                        "D"
                    } else {
                        "C"
                    };
                return format!("{}:\\{}", fallback_drive, win_rest);
            }
        }
    }
    trimmed.to_string()
}

fn resolve_or_compute_event_hash(
    event: &HostSecurityEvent,
    normalized_image_path: &str,
) -> Option<String> {
    if let Some(h) = preferred_hash_from_event(event) {
        if h != "no-hash" && !h.trim().is_empty() {
            return Some(h);
        }
    }
    if !normalized_image_path.is_empty() && normalized_image_path != "unknown" {
        let p = std::path::Path::new(normalized_image_path);
        if p.is_file() {
            if let Ok(bytes) = std::fs::read(p) {
                return Some(blake3::hash(&bytes).to_hex().to_string());
            }
        }
    }
    None
}

fn event_stem(event: &HostSecurityEvent) -> String {
    event_image_path(event)
        .and_then(|p| std::path::Path::new(p).file_stem())
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn is_trusted_operational_tool(
    event: &HostSecurityEvent,
    config: &osoosi_types::PolicyConfig,
) -> bool {
    let image_path = event
        .data
        .get("Image")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if image_path.is_empty() {
        return false;
    }
    let path_lc = image_path.to_lowercase();

    // 1. Check dynamic whitelists from config
    let is_trusted_path = config
        .trusted_paths
        .iter()
        .any(|p| path_lc.contains(&p.to_lowercase()));
    let is_trusted_stem = config.trusted_stems.iter().any(|s| {
        let s_lc = s.to_lowercase();
        path_lc.ends_with(&s_lc)
            || path_lc.contains(&format!("\\{}\\", s_lc))
            || path_lc.ends_with(&format!("\\{}", s_lc))
    });

    if is_trusted_path || is_trusted_stem {
        // 2. Obtain signature from the file on disk (Authenticode)
        if let Some(metadata) = osoosi_types::get_pe_metadata(std::path::Path::new(image_path)) {
            if metadata.is_signed {
                return true;
            }
        }

        // 3. Fallback to Sysmon's own signature check
        let sig_status = event
            .data
            .get("SignatureStatus")
            .or_else(|| event.data.get("Signature Status"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();

        if sig_status == "valid" || sig_status.contains("trusted") {
            return true;
        }

        // 4. Require valid cryptographic signature on disk
        if osoosi_types::is_trusted_signed_binary(std::path::Path::new(image_path)) {
            return true;
        }
    }

    false
}

fn is_event_dev_or_signed(event: &HostSecurityEvent) -> bool {
    for key in ["Image", "TargetImage", "TargetFilename"] {
        if let Some(p) = event.data.get(key).and_then(|v| v.as_str()) {
            let path = std::path::Path::new(p);
            if path.is_file() && osoosi_types::is_trusted_signed_binary(path) {
                return true;
            }
        }
    }
    false
}

fn classify_vote(
    voter: &str,
    result: &VoteResult,
    event: &HostSecurityEvent,
) -> (EvidenceClass, f32, bool) {
    let reason_lc = result.reason.to_ascii_lowercase();
    let is_dev_or_signed = is_event_dev_or_signed(event);

    match voter {
        "OTX-C2" => {
            let live = matches!(
                event.event_id,
                3 | 22 // 3: NetworkConnect, 22: DnsQuery
            );
            if live {
                (EvidenceClass::LiveNetwork, 1.0, true)
            } else {
                (EvidenceClass::ThreatIntel, 0.72, false)
            }
        }
        "CISA-KEV" => (EvidenceClass::ThreatIntel, 0.58, false),
        "NVD-CVE-Lookup" => (EvidenceClass::ThreatIntel, 1.0, true), // High reliability, triggers strong action
        "BehavioralYara" | "Behavioral-Threat-Model" => (EvidenceClass::Behavior, 0.88, true),
        "Foundation-Sec-Reasoning" => (EvidenceClass::Behavior, 0.85, true),
        "Native-Instrumentation" => (EvidenceClass::Memory, 0.94, true),
        "Injection-Telemetry" => (EvidenceClass::Memory, 0.95, true),
        "DNS-Shield" | "Sysmon-DNS-Voter" => (EvidenceClass::LiveNetwork, 0.90, true),
        "CredentialGuard-Memory" | "ProcessInjection-Memory" => (EvidenceClass::Memory, 0.96, true),
        "YaraX-Signatures" => {
            if is_dev_or_signed {
                (EvidenceClass::StaticArtifact, 0.30, false)
            } else {
                (EvidenceClass::StaticArtifact, 0.90, true)
            }
        }
        "YaraX-Memory" | "HollowsHunter-Memory" | "MemoryInspection-Native" => {
            (EvidenceClass::Memory, 1.0, true)
        }
        "SemanticIntent" | "LLM-Reasoning" | "BehavioralAI-Cortex" => {
            if is_dev_or_signed {
                (EvidenceClass::Behavior, 0.35, false)
            } else {
                (EvidenceClass::Behavior, 0.78, true)
            }
        }
        "Decompile" => (EvidenceClass::Behavior, 0.96, true),
        "Capa-Behavior" => {
            if is_dev_or_signed {
                (EvidenceClass::Behavior, 0.35, false)
            } else {
                (EvidenceClass::Behavior, 0.92, true)
            }
        }
        "Floss-Artifact" => {
            if is_dev_or_signed {
                (EvidenceClass::StaticArtifact, 0.25, false)
            } else {
                (EvidenceClass::StaticArtifact, 0.82, false)
            }
        }
        "Dotscope-Forensics" => {
            if is_dev_or_signed {
                (EvidenceClass::StaticArtifact, 0.30, false)
            } else {
                (EvidenceClass::StaticArtifact, 0.85, true)
            }
        }
        name if name.contains("NexusShield") => (EvidenceClass::StaticArtifact, 0.95, true),
        "ZeroDayTracker" => (EvidenceClass::ThreatIntel, 1.0, true),
        "SandboxSurfaceAnalysis" => (EvidenceClass::Behavior, 0.85, true),
        "Agentic-Escape-Detector" => (EvidenceClass::Behavior, 0.95, result.confidence >= 0.85),
        "Agent-Egress-Voter" => (EvidenceClass::LiveNetwork, 1.0, true),
        "HAR-L7-Inspector" => (EvidenceClass::LiveNetwork, 0.94, true),
        "Mercury-Fluid-Dynamics" => (EvidenceClass::Behavior, 0.95, true),
        "SpiderWeb-Containment" => (EvidenceClass::Behavior, 0.96, true),
        "EDR-PhaseLock-Attractor" | "Zero-Physics-Invariant" => {
            (EvidenceClass::Behavior, 0.95, true)
        }
        "Ai-Security-Audit-Voter" => (EvidenceClass::Behavior, 0.95, true),
        "REA-Voter" => {
            if reason_lc.contains("masquerade") || reason_lc.contains("prompt_injection") {
                (EvidenceClass::Behavior, 0.98, true)
            } else {
                (EvidenceClass::StaticArtifact, 0.96, true)
            }
        }
        "OpenJEV-Voter" => (EvidenceClass::Behavior, 0.96, true),
        "Behavioral-Process-Lineage" | "Clef-Decision-Model" => {
            (EvidenceClass::Behavior, 0.95, true)
        }
        "Sigma-Engine" => (EvidenceClass::Behavior, 0.96, true),
        "IOC-Scanner" => (EvidenceClass::ThreatIntel, 1.0, true),
        name if name.contains("MalConv") || name.contains("ML") => {
            let weak_pe_signature =
                reason_lc.contains("ml=0.000") && reason_lc.contains("sig=1.000");
            if weak_pe_signature || is_dev_or_signed {
                (EvidenceClass::StaticArtifact, 0.28, false)
            } else {
                (EvidenceClass::StaticArtifact, 0.78, true)
            }
        }
        _ => (EvidenceClass::Reputation, 0.65, false),
    }
}

/// The 5 Deterministic Invariant Violation Families governed by the Asymmetric Veto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum InvariantViolationFamily {
    /// 1. Cedar Reference Monitor forbid rules & self-protection violations
    CedarForbid,
    /// 2. Ring 0 kernel tamper, BYOVD, ETW/AMSI patch, DKOM differential, or SPRT anomaly
    Ring0Tamper,
    /// 3. Process token manipulation, privilege escalation, or LSASS/credential theft
    ProcessTokenPrivilege,
    /// 4. Cryptographic mesh signature mismatch, epoch replay, or Merkle/TPM row integrity violation
    CryptographicMeshMismatch,
    /// 5. Lateral containment breach, canary trip, or sacrificial fracture
    LateralContainmentBreach,
}

/// Structured assessment of deterministic invariant violations.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DeterministicAsymmetricVeto {
    pub is_violated: bool,
    pub families: Vec<InvariantViolationFamily>,
    pub primary_reason: String,
    pub causal_rule: String,
}

impl DeterministicAsymmetricVeto {
    pub fn none() -> Self {
        Self {
            is_violated: false,
            families: Vec::new(),
            primary_reason: String::new(),
            causal_rule: String::new(),
        }
    }
}

/// Evaluates both event telemetry and evidence votes for deterministic invariant violations across all 5 families.
pub fn detect_deterministic_asymmetric_veto(
    event: &HostSecurityEvent,
    votes: &[EvidenceVote],
) -> DeterministicAsymmetricVeto {
    let mut families = Vec::new();
    let mut reasons = Vec::new();

    // -------------------------------------------------------------
    // Family 1: Cedar Forbid Rules
    // -------------------------------------------------------------
    let has_cedar_forbid = event.data.get("CedarDecision").and_then(|v| v.as_str()) == Some("Deny")
        || event.data.get("CedarDecision").and_then(|v| v.as_str()) == Some("Forbid")
        || event
            .data
            .get("CedarForbidTripped")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        || votes.iter().any(|v| {
            let r = &v.result.reason;
            r.contains("Cedar-Ring7-Forbid")
                || r.contains("CEDAR-FORBID-TEMPORAL-TAINT-FRAGMENTATION")
                || r.contains("CEDAR-FORBID")
                || r.contains("Self-Protection Violation")
                || r.contains("DENY_ESCALATED_OR_FORBIDDEN")
                || r.contains("DENY_MODEL_MANIPULATION_OVERRIDE")
        });

    if has_cedar_forbid {
        families.push(InvariantViolationFamily::CedarForbid);
        reasons.push("Cedar Reference Monitor forbid / self-protection violation");
    }

    // -------------------------------------------------------------
    // Family 2: Ring 0 Tamper Detections
    // -------------------------------------------------------------
    let has_ring0_tamper = event
        .data
        .get("KernelTamperDetected")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        || event
            .data
            .get("HvciTamperDetected")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        || event
            .data
            .get("DkomTamperDetected")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        || (matches!(event.event_id, 8 | 10 | 25)
            && (event
                .data
                .get("KernelTamperDetected")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
                || !votes.is_empty()))
        || votes.iter().any(|v| {
            let r = &v.result.reason;
            r.contains("BYOVD")
                || r.contains("ETW_USERMODE_PATCH_DETECTED")
                || r.contains("AMSI_SCANBUFFER_BYPASS_PATCH_DETECTED")
                || r.contains("NTDLL_DETOUR_UNHOOKED")
                || r.contains("KERNEL_CALLBACK_TAMPER_DETECTED")
                || r.contains("Kernel Callback Self-Integrity")
                || r.contains("DKOM_TAMPER_DETECTED")
                || r.contains("Cross-View DKOM Differential")
                || r.contains("SPRT_REJECT_ANOMALY")
                || r.contains("RejectAnomaly")
                || r.contains("HVCI_INACTIVE_OR_TAMPERED")
                || r.contains("ProcessHollowing")
                || r.contains("VULNERABLE_DRIVER_BLOCKED")
        });

    if has_ring0_tamper {
        families.push(InvariantViolationFamily::Ring0Tamper);
        reasons.push("Ring 0 kernel tamper / BYOVD / watchdog hook alteration detected");
    }

    // -------------------------------------------------------------
    // Family 3: Process Token & Privilege Escalation
    // -------------------------------------------------------------
    let has_token_privilege = event
        .data
        .get("PrivilegeEscalationDetected")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        || event
            .data
            .get("TokenElevationViolation")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        || votes.iter().any(|v| {
            let r = &v.result.reason;
            (v.strong_action
                && v.reliability >= 0.85
                && (matches!(v.class, EvidenceClass::Memory) || v.result.confidence >= 0.85))
                && (r.contains("CredentialGuard")
                    || r.contains("TokenElevation")
                    || r.contains("TokenElevationType")
                    || r.contains("PrivilegeEscalation")
                    || r.contains("Privilege-Escalation")
                    || r.contains("SE_DEBUG_PRIVILEGE_ABUSE")
                    || r.contains("SeDebugPrivilege")
                    || r.contains("LSASSMemoryDump")
                    || r.contains("lsass.dmp")
                    || r.contains("lsass")
                    || r.contains("comsvcs")
                    || r.contains("comsvcs.dll")
                    || r.contains("keymgr")
                    || r.contains("sekurlsa")
                    || r.contains("mimikatz"))
        });

    if has_token_privilege {
        families.push(InvariantViolationFamily::ProcessTokenPrivilege);
        reasons.push("Process token privilege escalation / LSASS credential dump detected");
    }

    // -------------------------------------------------------------
    // Family 4: Cryptographic Signature Mismatch
    // -------------------------------------------------------------
    let has_crypto_mismatch = event
        .data
        .get("CryptoSignatureMismatch")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        || event
            .data
            .get("EpochSpoofingDetected")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        || votes.iter().any(|v| {
            let r = &v.result.reason;
            r.contains("Cryptographic mesh signature mismatch")
                || r.contains("IdentitySpoofingDetected")
                || r.contains("EpochSpoofing")
                || r.contains("MerkleIntegrityViolation")
                || r.contains("RowIntegrityViolation")
                || r.contains("LAW1_STICKY_TAINT_VETO")
                || r.contains("HMAC signature verification failure")
                || r.contains("HMAC_VERIFICATION_FAILED")
                || r.contains("TaintLevel::UntrustedExternal")
        });

    if has_crypto_mismatch {
        families.push(InvariantViolationFamily::CryptographicMeshMismatch);
        reasons.push("Cryptographic mesh HMAC/Merkle/TPM signature or epoch mismatch");
    }

    // -------------------------------------------------------------
    // Family 5: Lateral Containment Breach & Canary Traps
    // -------------------------------------------------------------
    let has_lateral_canary = event
        .data
        .get("CanaryTrapTripped")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        || event.data.get("CanaryAlert").is_some()
        || event
            .data
            .get("LateralMovementBreach")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        || votes.iter().any(|v| {
            let r = &v.result.reason;
            r.contains("CanaryTrapTripped")
                || r.contains("CanaryCage")
                || r.contains("CanaryAlert")
                || r.contains("Canary Trap Breach")
                || r.contains("LateralContainmentBreach")
                || r.contains("LATERAL_SINK_VIOLATION")
                || r.contains("SacrificialFracture")
                || r.contains("PromptInjectionExfil")
                || r.contains("SpiderWeb")
                || r.contains("SpiderWeb-Containment")
                || (v.result.confidence >= 0.85
                    && (r.contains("Escape-Detector") || r.contains("Agentic-Escape-Detector")))
        });

    if has_lateral_canary {
        families.push(InvariantViolationFamily::LateralContainmentBreach);
        reasons.push("Lateral containment breach / honeypot canary trap tripped");
    }

    let is_violated = !families.is_empty();
    let primary_reason = if is_violated {
        format!(
            "AsymmetricVeto [Deterministic Invariant Violation]: {}",
            reasons.join("; ")
        )
    } else {
        String::new()
    };
    let causal_rule = families
        .iter()
        .map(|f| format!("{:?}", f))
        .collect::<Vec<_>>()
        .join("+");

    DeterministicAsymmetricVeto {
        is_violated,
        families,
        primary_reason,
        causal_rule,
    }
}

pub fn orchestrate_evidence(
    votes: &[EvidenceVote],
    event: &HostSecurityEvent,
    config: &osoosi_types::PolicyConfig,
) -> EvidenceDecision {
    use osoosi_types::ResponseAction;

    let mut classes = std::collections::HashSet::new();
    let mut support = 0.0f32;
    let mut mass = 0.0f32;
    let mut max_single = 0.0f32;
    let mut strong_action = false;
    let mut threat_intel_only = true;

    for vote in votes {
        classes.insert(vote.class);
        let weighted =
            vote.result.confidence.clamp(0.0, 1.0) * vote.result.weight.max(0.0) * vote.reliability;
        support += weighted;
        mass += vote.result.weight.max(0.0) * vote.reliability;
        max_single = max_single.max(weighted);
        strong_action |= vote.strong_action;
        threat_intel_only &= vote.class == EvidenceClass::ThreatIntel;
    }

    let independent = classes.len();
    let base = if mass > 0.0 { support / mass } else { 0.0 };
    let corroboration: f32 = match independent {
        0 => 0.0,
        1 => 0.52,
        2 => 0.82,
        _ => 1.0,
    };

    // Evaluate deterministic asymmetric veto across the 5 invariant families
    let asymmetric_veto = detect_deterministic_asymmetric_veto(event, votes);

    let has_deterministic_credential_or_memory_guard = votes.iter().any(|v| {
        v.strong_action
            && v.reliability >= 0.90
            && v.result.confidence >= 0.90
            && (matches!(v.class, EvidenceClass::Memory)
                || v.result.reason.contains("CredentialGuard")
                || v.result.reason.contains("keymgr")
                || v.result.reason.contains("comsvcs"))
    });

    let has_sigma_or_lolbin_guard = votes.iter().any(|v| {
        v.strong_action
            && v.result.confidence >= 0.85
            && (v.result.reason.contains("Sigma Match:")
                || v.result.reason.contains("[Sigma-Engine]")
                || v.result.reason.contains("Suspicious Child Payload Spawn"))
    });

    let has_deterministic_guard = asymmetric_veto.is_violated
        || has_deterministic_credential_or_memory_guard
        || has_sigma_or_lolbin_guard;

    let corroboration =
        if asymmetric_veto.is_violated || has_deterministic_credential_or_memory_guard {
            1.0f32
        } else if has_sigma_or_lolbin_guard {
            corroboration.max(0.96f32)
        } else {
            corroboration
        };

    // INVARIANT F20: When asymmetric_veto or deterministic credential/memory guard is triggered,
    // confidence MUST be saturated to 1.0f32 unconditionally, overriding any benign ML/probabilistic voter scores that diluted `base`.
    let mut confidence =
        if asymmetric_veto.is_violated || has_deterministic_credential_or_memory_guard {
            1.0f32
        } else {
            (base * corroboration + max_single.min(1.0) * 0.12).min(1.0)
        };
    if has_sigma_or_lolbin_guard {
        confidence = confidence.max(0.88);
    }

    let has_live_network = classes.contains(&EvidenceClass::LiveNetwork);
    let has_behavior = classes.contains(&EvidenceClass::Behavior);
    let has_memory = classes.contains(&EvidenceClass::Memory);
    let has_static = classes.contains(&EvidenceClass::StaticArtifact);
    let lifecycle_only = matches!(
        event.event_id,
        1 | 5 // 1: ProcessCreate, 5: ProcessTerminate
    );
    let trusted_operational_tool = is_trusted_operational_tool(event, config);
    let is_dev_or_signed_target = is_event_dev_or_signed(event);

    if threat_intel_only && !asymmetric_veto.is_violated {
        confidence = confidence.min(0.49);
    }
    if !has_deterministic_guard {
        if lifecycle_only && !has_behavior && !has_memory && !has_live_network {
            confidence = confidence.min(0.62);
        }
        if has_static && !has_behavior && !has_memory && !has_live_network && independent < 3 {
            confidence = confidence.min(0.68);
        }
        if (trusted_operational_tool || is_dev_or_signed_target)
            && !has_live_network
            && !has_behavior
            && !has_memory
        {
            confidence = confidence.min(0.18);
        } else if (trusted_operational_tool || is_dev_or_signed_target) && !strong_action {
            confidence = confidence.min(0.40);
        }
    }

    // NVD-Negative Suppression: if the CVE lookup explicitly found NO CVEs, and we only have static/intel evidence,
    // lower the score to ensure we wait for behavioral evidence.
    let nvd_negative = votes
        .iter()
        .any(|v| v.result.reason.contains("No matching CVEs found") && v.result.weight < 0.0);
    if nvd_negative
        && !has_behavior
        && !has_memory
        && !has_live_network
        && !asymmetric_veto.is_violated
    {
        confidence = confidence.min(0.35);
    }

    let require_approval = confidence >= 0.70 && independent < 2 && !has_deterministic_guard;
    let action = if asymmetric_veto.is_violated
        || (confidence >= 0.94 && independent >= 3 && strong_action)
        || (confidence >= 0.90 && has_deterministic_guard)
        || (confidence >= 0.85 && has_sigma_or_lolbin_guard)
    {
        ResponseAction::Isolate
    } else if confidence >= 0.82 && has_live_network && (has_behavior || has_static || has_memory) {
        ResponseAction::GhostTarpit
    } else if confidence >= 0.74 && has_live_network {
        ResponseAction::Tarpit
    } else if confidence >= 0.72 && strong_action && independent >= 2 {
        ResponseAction::Deception
    } else {
        ResponseAction::Alert
    };

    let summary = if asymmetric_veto.is_violated {
        format!(
            "EvidenceOrchestrator: ASYMMETRIC_VETO_ISOLATE (families=[{}]) confidence=1.00 action=Isolate reason={}",
            asymmetric_veto.causal_rule,
            asymmetric_veto.primary_reason
        )
    } else {
        format!(
            "EvidenceOrchestrator: classes={} independent={} strong_action={} base={:.2} confidence={:.2}",
            classes
                .iter()
                .map(|c| format!("{:?}", c))
                .collect::<Vec<_>>()
                .join("+"),
            independent,
            strong_action,
            base,
            confidence
        )
    };

    EvidenceDecision {
        confidence,
        action,
        require_approval: if asymmetric_veto.is_violated {
            false
        } else {
            require_approval
        },
        summary,
    }
}

pub struct PolicyEngine {
    /// Local persistence store
    memory: Arc<MemoryStore>,
    /// Semantic Intent Filter
    _semantic: SemanticEngine,
    /// Relationship Graph
    graph: GraphCorrelationEngine,
    /// Custom threat signatures (Hash -> Signature)
    #[allow(dead_code)]
    signatures: Arc<DashMap<String, ThreatSignature>>,
    /// OTX indicators cached in-memory from feed fetch loop.
    otx_indicators: Arc<RwLock<OtxIndicators>>,

    /// Learned Zero-Day defenses from the mesh (CVE -> Learned Rule)
    global_intel_rules: Arc<DashMap<String, String>>,
    /// Consensus cache to prevent duplicate notifications (Key: EventID+Path+Hash -> (Signature, Time))
    consensus_cache: Arc<DashMap<String, (ThreatSignature, std::time::Instant)>>,
    /// Multi-tool consensus voters
    voters: Arc<tokio::sync::RwLock<Vec<Box<dyn ThreatVoter + Send + Sync>>>>,
    /// Reinforcement Learning dynamic weight multipliers for individual voters
    pub voter_weight_multipliers: Arc<DashMap<String, f32>>,
    /// Global policy config (noise suppression, trusted paths)
    pub config: osoosi_types::PolicyConfig,
    /// Shared threat feed fetcher
    pub fetcher: Arc<crate::feed::ThreatFeedFetcher>,
    /// Optional callback to broadcast discoveries to the mesh
    pub intel_broadcaster: Arc<
        tokio::sync::RwLock<Option<Arc<dyn Fn(osoosi_types::GlobalIntelligence) + Send + Sync>>>,
    >,
    /// Local SQLite cache for NVD CVEs
    pub cve_cache: Option<Arc<tokio::sync::Mutex<crate::cve_cache::CveCache>>>,
    /// Optional resource controller to skip heavy tasks during load
    pub telemetry_controller: Option<Arc<dyn osoosi_types::TelemetryControllerInterface>>,
    /// Optional voter quorum alert sink (e.g. ReaVoterEnvGateway::ingest_voter_quorum)
    pub voter_quorum_sink:
        Arc<tokio::sync::RwLock<Option<Arc<dyn Fn(VoterQuorumAlert) + Send + Sync>>>>,
    /// Runtime override flag to strictly enforce 100% voter quorum participation
    pub enforce_all_voters_participate: AtomicBool,
}

impl PolicyEngine {
    pub fn new(memory: Arc<MemoryStore>, config: osoosi_types::PolicyConfig) -> Self {
        let voter_weight_multipliers = Arc::new(DashMap::new());
        if let Ok(weights) = memory.load_voter_weights() {
            for (voter_name, weight) in weights {
                voter_weight_multipliers.insert(voter_name, weight.clamp(0.50, 2.5));
            }
        }
        let enforce_all = config.enforce_all_voters_participate;
        Self {
            memory,
            _semantic: SemanticEngine::new(),
            graph: GraphCorrelationEngine::new(),
            signatures: Arc::new(DashMap::new()),
            otx_indicators: Arc::new(RwLock::new(OtxIndicators::default())),
            global_intel_rules: Arc::new(DashMap::new()),
            consensus_cache: Arc::new(DashMap::new()),
            voters: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            voter_weight_multipliers,
            config,
            fetcher: Arc::new(crate::feed::ThreatFeedFetcher::new()),
            intel_broadcaster: Arc::new(tokio::sync::RwLock::new(None)),
            cve_cache: {
                let local_path = std::path::Path::new("database").join("nvd_cache.db");
                let db_path = if local_path.parent().map(|p| p.exists()).unwrap_or(false)
                    || std::fs::create_dir_all("database").is_ok()
                {
                    local_path
                } else {
                    std::path::PathBuf::from("C:\\ProgramData\\OshoosiClaw\\nvd_cache.db")
                };
                if let Some(parent) = db_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                match crate::cve_cache::CveCache::new(&db_path) {
                    Ok(cache) => Some(Arc::new(tokio::sync::Mutex::new(cache))),
                    Err(e) => {
                        warn!(
                            "Failed to initialize NVD SQLite cache at {:?}: {}",
                            db_path, e
                        );
                        None
                    }
                }
            },
            telemetry_controller: None,
            voter_quorum_sink: Arc::new(tokio::sync::RwLock::new(None)),
            enforce_all_voters_participate: AtomicBool::new(enforce_all),
        }
    }

    pub fn new_with_memory(memory: Arc<MemoryStore>, config: osoosi_types::PolicyConfig) -> Self {
        Self::new(memory, config)
    }

    pub async fn set_intel_broadcaster(
        &self,
        broadcaster: Arc<dyn Fn(osoosi_types::GlobalIntelligence) + Send + Sync>,
    ) {
        let mut guard = self.intel_broadcaster.write().await;
        *guard = Some(broadcaster);
    }

    pub async fn set_voter_quorum_sink(
        &self,
        sink: Arc<dyn Fn(VoterQuorumAlert) + Send + Sync>,
    ) {
        let mut guard = self.voter_quorum_sink.write().await;
        *guard = Some(sink);
    }

    pub fn set_enforce_all_voters_participate(&self, enforce: bool) {
        self.enforce_all_voters_participate.store(enforce, Ordering::SeqCst);
    }

    pub fn is_enforce_all_voters_participate(&self) -> bool {
        self.config.enforce_all_voters_participate
            || self.enforce_all_voters_participate.load(Ordering::Relaxed)
    }

    /// Evaluates whether the event requires 100% voter quorum participation
    /// (no heavy voter skipping during silent mode).
    #[inline]
    pub fn is_security_or_gateway_eval(&self, event: &HostSecurityEvent) -> bool {
        if self.is_enforce_all_voters_participate() {
            return true;
        }

        let check_flag = |key: &str| -> bool {
            if let Some(val) = event.data.get(key) {
                if val.as_bool() == Some(true) {
                    return true;
                }
                if let Some(s) = val.as_str() {
                    if s.eq_ignore_ascii_case("true") || s == "1" {
                        return true;
                    }
                }
                if let Some(n) = val.as_i64() {
                    if n == 1 {
                        return true;
                    }
                }
            }
            false
        };

        // 1. Checks if event data contains explicit gateway/security enforcement flags
        if check_flag("EnforceCedarGate")
            || check_flag("GatewayEvaluation")
            || check_flag("SecurityEvaluation")
            || check_flag("RequireAllVoters")
            || check_flag("EnforceSecurityGateway")
        {
            return true;
        }

        // 2. Checks if session tracking is active (autonomous agent / gateway session)
        if event.data.get("SessionId").is_some()
            || event.data.get("session_id").is_some()
            || event.data.get("AgentSessionId").is_some()
            || event.data.get("origin_session_id").is_some()
        {
            return true;
        }

        // 3. Checks if behavioral / runtime event matches with invariant flags or gateway context
        let has_invariant_flags = check_flag("InvariantCheck")
            || check_flag("SelfProtection")
            || check_flag("MemoryScan")
            || check_flag("TaintViolation")
            || check_flag("BreakoutAttempt")
            || check_flag("AsymmetricVeto")
            || event.data.get("invariant").is_some()
            || event.data.get("invariants").is_some()
            || event.data.get("invariant_flags").is_some();

        let has_gateway_context = event.data.get("gateway").is_some()
            || event.data.get("Gateway").is_some()
            || event.data.get("SecurityGateway").is_some()
            || event.data.get("ReaGateway").is_some()
            || event.data.get("ReaVoter").is_some()
            || event.data.get("standin_token").is_some()
            || event.data.get("StandinToken").is_some()
            || event.data.get("TargetUrl").is_some()
            || event.data.get("UpstreamHost").is_some()
            || event.data.get("DestinationHost").is_some();

        if matches!(event.event_id, 1 | 3 | 7 | 8 | 10 | 12 | 13 | 22 | 25 | 4688)
            && (has_invariant_flags || has_gateway_context)
        {
            return true;
        }

        false
    }

    pub async fn add_voter(&self, voter: Box<dyn ThreatVoter + Send + Sync>) {
        let mut guard = self.voters.write().await;
        let name = voter.name();
        guard.push(voter);
        info!(
            target: CONSENSUS_LOG_TARGET,
            voter = %name,
            total = guard.len(),
            "[CONSENSUS] registered threat voter"
        );
    }

    /// Evaluates any downstream operating-system or agent event (`HostSecurityEvent`) against the
    /// 7-Ring Cedar Reference Monitor, `CausalSecurityGraph`, and `RevocationBoundCapabilityCache`.
    /// Emits a deterministic `PolicyDecisionRecord` containing `(policy_decision_id, causal_event_id, policy_version)`.
    pub fn evaluate(
        &self,
        event: &HostSecurityEvent,
    ) -> crate::breakout_gate::PolicyDecisionRecord {
        crate::breakout_gate::global_ring7_authorizer().evaluate_os_event(event)
    }

    /// Spawns long-running background tasks for threat intelligence synchronization.
    pub fn start_background_tasks(&self) {
        let fetcher = self.fetcher.clone();
        let cache = self.cve_cache.clone();

        tokio::spawn(async move {
            info!("[PolicyEngine] NVD Background Sync Task started (Cycle: 24h).");
            loop {
                if let Some(ref cache_ref) = cache {
                    let api_key = osoosi_types::resolve_nvd_api_key();
                    info!("[PolicyEngine] Running scheduled NVD bulk synchronization...");
                    match fetcher.fetch_nvd_cves(api_key.as_deref()).await {
                        Ok(kevs) => {
                            let cache_guard = cache_ref.lock().await;
                            if let Err(e) = cache_guard.bulk_import(&kevs) {
                                warn!(
                                    "[PolicyEngine] Failed to import NVD CVEs into local cache: {}",
                                    e
                                );
                            } else {
                                info!(
                                    "[PolicyEngine] NVD Local Cache updated with {} new records.",
                                    kevs.len()
                                );
                            }
                        }
                        Err(e) => {
                            warn!("[PolicyEngine] NVD Background Sync failed: {}", e);
                        }
                    }
                }
                // Sleep for 24 hours
                tokio::time::sleep(std::time::Duration::from_secs(86400)).await;
            }
        });
    }

    pub fn otx_indicators_ref(&self) -> &Arc<RwLock<OtxIndicators>> {
        &self.otx_indicators
    }

    /// Return all graph relationships for attack graph construction.
    pub fn graph_relationships(&self) -> Vec<Relationship> {
        self.graph.relationships()
    }

    pub fn update_otx_indicators(&self, indicators: OtxIndicators) {
        if let Ok(mut guard) = self.otx_indicators.write() {
            *guard = indicators;
        }
    }

    /// Returns a match reason if this Sysmon event hits an OTX IoC.
    ///
    /// IOCs are populated by the background `ThreatFeedFetcher::fetch_otx_indicators` (which uses
    /// **TAXII 1.1** when `OTX_USE_TAXII` is left at default) and persisted in SQLite. This is a
    /// **local lookup** — not a live TAXII poll per connection.
    pub fn otx_ioc_match_for_event(&self, event: &HostSecurityEvent) -> Option<String> {
        let otx = self.otx_indicators.read().ok()?;
        crate::otx_connection::otx_match_sysmon_event_normalized(&otx, &self.memory, event)
    }

    /// Check a single outbound (or inbound) IP from a connection against OTX state (memory + SQLite).
    pub fn otx_ioc_match_for_ip(&self, ip: &str) -> Option<String> {
        let otx = self.otx_indicators.read().ok()?;
        crate::otx_connection::otx_match_destination_ip(&otx, &self.memory, ip)
    }

    /// Register a temporary learned defense (Zero-Day defense from mesh gossip).
    pub fn register_temporary_rule(&self, cve_id: &str, rule: &str, _severity: f32) {
        info!(
            "PolicyEngine: Learning new defense for {} from mesh gossip.",
            cve_id
        );
        self.global_intel_rules
            .insert(cve_id.to_string(), rule.to_string());
    }

    /// Process a Sysmon event and check for threats.
    ///
    /// OTX / TAXII (or REST) **IoCs participate in the same weighted vote** as all other
    /// [`ThreatVoter`]s, typically through [`crate::voters::OtxVoter`]. If that voter is not
    /// registered, a matching [`Self::otx_ioc_match_for_event`] is merged in so TAXII-backed IOCs
    /// still affect consensus.
    pub async fn voter_stats(&self) -> serde_json::Value {
        let mut out = serde_json::Map::new();
        let voters = self.voters.read().await;
        for voter in &*voters {
            let mut s = voter.stats();
            let mult = self
                .voter_weight_multipliers
                .get(&voter.name())
                .map(|v| *v)
                .unwrap_or(1.0)
                .clamp(0.50, 2.5);
            if let serde_json::Value::Object(ref mut map) = s {
                map.insert("weight_multiplier".to_string(), serde_json::json!(mult));
            } else {
                s = serde_json::json!({
                    "raw": s,
                    "weight_multiplier": mult,
                });
            }
            out.insert(voter.name(), s);
        }
        serde_json::Value::Object(out)
    }

    /// Adjust voter weights based on feedback (+delta for TP, -delta for FP, clamped to safe floor [0.50, 2.5]) and persist to SQLite.
    /// Anti-Reward-Hacking Invariant: Negative RL rewards can never mute a voter below `0.50`.
    pub fn update_voter_weights_from_feedback(&self, is_true_positive: bool, delta: f32) {
        let mut names: std::collections::HashSet<String> = self
            .voter_weight_multipliers
            .iter()
            .map(|kv| kv.key().clone())
            .collect();
        if let Ok(voters) = self.voters.try_read() {
            for v in voters.iter() {
                names.insert(v.name());
            }
        }
        for name in names {
            let current = self
                .voter_weight_multipliers
                .get(&name)
                .map(|v| *v)
                .unwrap_or(1.0);
            let next = if is_true_positive {
                (current + delta).clamp(0.50, 2.5)
            } else {
                (current - delta).clamp(0.50, 2.5)
            };
            self.voter_weight_multipliers.insert(name.clone(), next);
            let _ = self.memory.save_voter_weight(&name, next);
        }
    }

    /// Updates voter weights ONLY when `observer_confidence == "VERIFIED"`, enforcing the
    /// Separate-Learning-from-Authority anti-reward-hacking safeguard (`floor = 0.50`).
    pub fn update_voter_weights_from_verified_feedback(
        &self,
        is_true_positive: bool,
        delta: f32,
        observer_confidence: &str,
    ) -> bool {
        if !observer_confidence.eq_ignore_ascii_case("VERIFIED") {
            return false;
        }
        self.update_voter_weights_from_feedback(is_true_positive, delta);
        true
    }

    /// Calibrate specific voter weights based on consensus feedback (+delta for TP, -delta for FP, clamped [0.50, 2.5]) and persist to SQLite.
    pub fn update_specific_voter_weights(
        &self,
        voter_names: &[String],
        is_true_positive: bool,
        delta: f32,
    ) {
        for name in voter_names {
            let current = self
                .voter_weight_multipliers
                .get(name)
                .map(|v| *v)
                .unwrap_or(1.0);
            let next = if is_true_positive {
                (current + delta).clamp(0.50, 2.5)
            } else {
                (current - delta).clamp(0.50, 2.5)
            };
            self.voter_weight_multipliers.insert(name.clone(), next);
            let _ = self.memory.save_voter_weight(name, next);
        }
    }

    /// Sets and clamps a voter's dynamic weight multiplier to [0.50, 2.50], handling NaN / infinite inputs.
    pub fn set_voter_weight(&self, name: &str, weight: f32) -> f32 {
        let clamped = if weight.is_nan() {
            1.0f32
        } else {
            weight.clamp(0.50, 2.50)
        };
        self.voter_weight_multipliers
            .insert(name.to_string(), clamped);
        let _ = self.memory.save_voter_weight(name, clamped);
        clamped
    }

    pub async fn scan_event(&self, raw_event: &HostSecurityEvent) -> Option<ThreatSignature> {
        use osoosi_types::ResponseAction;

        let mut normalized_event_storage: Option<HostSecurityEvent> = None;
        if let serde_json::Value::Object(ref map) = raw_event.data {
            let path_keys = [
                "Image",
                "NewProcessName",
                "ImagePath",
                "SourceImage",
                "TargetImage",
                "ParentImage",
                "ImageLoaded",
            ];
            let needs_norm = path_keys.iter().any(|k| {
                map.get(*k)
                    .and_then(|v| v.as_str())
                    .map(|s| {
                        s.to_ascii_lowercase()
                            .starts_with("\\device\\harddiskvolume")
                    })
                    .unwrap_or(false)
            });
            if needs_norm {
                let mut cloned = raw_event.clone();
                if let serde_json::Value::Object(ref mut cmap) = cloned.data {
                    for k in &path_keys {
                        if let Some(val) =
                            cmap.get(*k).and_then(|v| v.as_str()).map(|s| s.to_string())
                        {
                            let norm = normalize_nt_device_path(&val);
                            if norm != val {
                                cmap.insert((*k).to_string(), serde_json::Value::String(norm));
                            }
                        }
                    }
                }
                normalized_event_storage = Some(cloned);
            }
        }
        let event: &HostSecurityEvent = normalized_event_storage.as_ref().unwrap_or(raw_event);

        let raw_image_path = event_image_path(event).unwrap_or("unknown");
        let normalized_image_owned = normalize_nt_device_path(raw_image_path);
        let image_path = normalized_image_owned.as_str();
        let hash = resolve_or_compute_event_hash(event, image_path)
            .unwrap_or_else(|| "no-hash".to_string());
        let cmdline = event
            .data
            .get("CommandLine")
            .or_else(|| event.data.get("command_line"))
            .or_else(|| event.data.get("cmdline"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let target_file = event
            .data
            .get("TargetFilename")
            .or_else(|| event.data.get("TargetFile"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // 0. Canonical Path Exclusions: Only skip if canonical path strictly equals or is within verified directory
        // Never allow loose substring matches like path_lc.contains(ex) which allow attackers to evade detection
        if !image_path.is_empty() && !self.config.consensus_exclude_paths.is_empty() {
            if let Ok(canon_target) = std::path::Path::new(image_path).canonicalize() {
                let is_excluded = self.config.consensus_exclude_paths.iter().any(|ex| {
                    let trimmed = ex.trim();
                    if trimmed.is_empty() {
                        return false;
                    }
                    if let Ok(canon_ex) = std::path::Path::new(trimmed).canonicalize() {
                        let ex_str = canon_ex.to_string_lossy().to_ascii_lowercase();
                        if canon_ex.as_os_str().len() > 3
                            && !ex_str.contains("\\temp")
                            && !ex_str.contains("/tmp")
                        {
                            canon_target == canon_ex || canon_target.starts_with(&canon_ex)
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                });
                if is_excluded {
                    debug!(
                        target: CONSENSUS_LOG_TARGET,
                        path = %image_path,
                        "[CONSENSUS] round skipped (path in canonical consensus_exclude_paths)"
                    );
                    return None;
                }
            }
        }

        // Fast clean-ignored hash bypass: If hash is in the clean ignore list, skip round
        // Invariant: Do NOT skip scan_event via is_hash_clean_ignored for behavioral/command/process/injection/registry events
        let is_behavioral_or_runtime_event = matches!(
            event.event_id,
            1 | 3 | 7 | 8 | 10 | 12 | 13 | 22 | 25 | 4688
        );
        if !is_behavioral_or_runtime_event {
            if let Some(h) = preferred_hash_from_event(event) {
                if self.memory.is_hash_clean_ignored(&h) {
                    debug!(
                        target: CONSENSUS_LOG_TARGET,
                        hash = %h,
                        "[CONSENSUS] round bypassed (Hash is in clean ignore list)"
                    );
                    return None;
                }
            }
        }

        // NEW: Known-Good Bypass (Analyst False Positives)
        // If the binary has been explicitly marked as a false positive by an analyst,
        // we bypass the consensus engine entirely to save CPU and stop log spam.
        if let Some(h) = preferred_hash_from_event(event) {
            let proc_name = process_name_from_event(event);
            let is_fp = self
                .memory
                .is_false_positive_pattern(proc_name.as_deref(), Some(&h))
                .unwrap_or(false);

            if is_fp {
                debug!(
                    target: CONSENSUS_LOG_TARGET,
                    path = %image_path,
                    hash = %h,
                    is_fp,
                    "[CONSENSUS] round bypassed (Analyst False-Positive match)"
                );
                return None;
            }
        }

        // 0.1 Trusted Paths & Noisy Stems: Reduce sensitivity for known noise
        let path_lc = image_path.to_ascii_lowercase();
        let stem = event_stem(event);
        let is_noisy = self
            .config
            .consensus_noisy_stems
            .iter()
            .any(|s| s.eq_ignore_ascii_case(&stem))
            || self
                .config
                .consensus_trusted_paths
                .iter()
                .any(|p| path_lc.contains(&p.to_lowercase()));

        let cache_key = format!(
            "{:?}:{:?}:{}:{}:{}",
            event.event_id, image_path, hash, cmdline, target_file
        );

        // Deduplication: Avoid re-running consensus for the same event in a short window (30s)
        if let Some(cached) = self.consensus_cache.get(&cache_key) {
            let (sig, timestamp) = cached.value();
            if timestamp.elapsed() < std::time::Duration::from_secs(30) {
                return Some(sig.clone());
            }
        }

        let voters_len = self.voters.read().await.len();
        debug!(
            target: CONSENSUS_LOG_TARGET,
            event_id = ?event.event_id,
            voters = voters_len,
            path = %image_path,
            "[CONSENSUS] round start"
        );

        let mut signature = ThreatSignature::new(event.computer.clone());
        let mut total_score: f32 = 0.0;
        let mut vote_count: u32 = 0;
        let mut is_threat = false;
        let mut vetoed = false;
        let mut nsrl_vetoed = false;
        let mut otx_voted = false;
        let mut evidence_votes: Vec<EvidenceVote> = Vec::new();
        const OTX_VOTER: &str = "OTX-C2";

        // Check if this evaluation is a security or gateway evaluation requiring 100% voter participation
        let is_sec_or_gw = self.is_security_or_gateway_eval(event);

        // ADAPTIVE THREADING: Run all voters concurrently with per-voter timeouts.
        // Each voter gets a strict 30-second SLA (increased for LLM inference on CPU).
        const VOTER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
        let results = {
            let voters_guard = self.voters.read().await;
            let mut timeout_futs = Vec::with_capacity(voters_guard.len());
            let mut names = Vec::with_capacity(voters_guard.len());
            for voter in voters_guard.iter() {
                let name = voter.name();

                // DRASTIC OPTIMIZATION: Skip heavy voters (LLM, Decompile) during resource pressure (Silent Mode)
                // BUT: On security and gateway evaluations, strictly enforce 100% voter quorum participation!
                if let Some(ref controller) = self.telemetry_controller {
                    if !is_sec_or_gw && voter.is_heavy() && controller.is_silent_mode() {
                        debug!(
                            target: CONSENSUS_LOG_TARGET,
                            voter = %name,
                            "[CONSENSUS] skipping heavy voter due to SILENT mode (resource pressure)"
                        );
                        continue;
                    }
                }

                let vote_fut = voter.vote(event);
                // Wrap each voter future in an individual timeout
                timeout_futs.push(tokio::time::timeout(VOTER_TIMEOUT, vote_fut));
                names.push(name);
            }
            let raw_results = futures::future::join_all(timeout_futs).await;
            drop(voters_guard); // Release read lock immediately

            names
                .into_iter()
                .zip(raw_results)
                .map(|(name, res)| match res {
                    Ok(vote_opt) => (name, vote_opt),
                    Err(_elapsed) => {
                        debug!(
                            target: CONSENSUS_LOG_TARGET,
                            voter = %name,
                            timeout_ms = VOTER_TIMEOUT.as_millis() as u64,
                            "[CONSENSUS] voter TIMEOUT — treating as abstain"
                        );
                        (name, None)
                    }
                })
                .collect::<Vec<_>>()
        };

        for (vname, res_opt) in results {
            if let Some(mut res) = res_opt {
                let raw_mult = self
                    .voter_weight_multipliers
                    .get(&vname)
                    .map(|v| *v)
                    .unwrap_or(1.0);
                let mult = if raw_mult.is_nan() {
                    1.0f32
                } else {
                    raw_mult.clamp(0.50, 2.5)
                };
                if res.weight > 0.0 {
                    res.weight *= mult;
                }
                if res.weight < 0.0 {
                    if vname == "NSRL-Veto"
                        || vname == "Trusted-Vendor"
                        || vname == "Git-Noise-Filter"
                    {
                        nsrl_vetoed = true;
                    } else {
                        vetoed = true;
                    }
                    debug!(
                        target: CONSENSUS_LOG_TARGET,
                        voter = %vname,
                        reason = %res.reason,
                        "[CONSENSUS] veto — detection blocked"
                    );
                    signature.add_reason(format!("Veto [{}]: {}", vname, res.reason));
                }

                if res.weight > 0.0 && res.confidence > 0.0 {
                    let contribution = res.confidence * res.weight;
                    debug!(
                        target: CONSENSUS_LOG_TARGET,
                        voter = %vname,
                        conf = res.confidence,
                        weight = res.weight,
                        contribution,
                        reason = %res.reason,
                        "[CONSENSUS] voter YIELD"
                    );
                    total_score += contribution;
                    vote_count += 1;
                    signature.add_reason(format!("[{}]: {}", vname, res.reason));
                    is_threat = true;
                    if vname == OTX_VOTER {
                        otx_voted = true;
                    }
                    let (class, reliability, strong_action) = classify_vote(&vname, &res, event);
                    evidence_votes.push(EvidenceVote {
                        result: res,
                        class,
                        reliability,
                        strong_action,
                    });
                }
            } else {
                debug!(
                    target: CONSENSUS_LOG_TARGET,
                    voter = %vname,
                    event_id = ?event.event_id,
                    "[CONSENSUS] voter abstain (no match)"
                );
            }
        }

        // Mandatory Continuous Cedar & Ring 7 Capability Gate for agent-originated OS effects:
        // A compromised, spoofed (weight < 0.0), or timed-out voter can NEVER turn a Cedar forbid into permission.
        if event.data.get("SessionId").is_some()
            || event.data.get("AgentSessionId").is_some()
            || event
                .data
                .get("EnforceCedarGate")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        {
            let cedar_dec = self.evaluate(event);
            if !cedar_dec.allowed {
                let reason = format!(
                    "[Cedar-Ring7-Forbid ({} / {})]: {}",
                    cedar_dec.policy_decision_id, cedar_dec.causal_event_id, cedar_dec.reason
                );
                total_score += 2.97;
                vote_count += 1;
                signature.add_reason(reason.clone());
                is_threat = true;
                evidence_votes.push(EvidenceVote {
                    result: VoteResult {
                        confidence: 0.99,
                        reason,
                        weight: 3.0,
                    },
                    class: EvidenceClass::Behavior,
                    reliability: 1.0,
                    strong_action: true,
                });
            }
        }

        // Evaluate deterministic asymmetric veto across the 5 invariant families early
        let early_veto_analysis = detect_deterministic_asymmetric_veto(event, &evidence_votes);
        if early_veto_analysis.is_violated
            && !evidence_votes
                .iter()
                .any(|v| v.result.reason.contains("Asymmetric-Veto"))
        {
            let reason = format!("[Asymmetric-Veto]: {}", early_veto_analysis.primary_reason);
            total_score += 3.0;
            vote_count += 1;
            signature.add_reason(reason.clone());
            is_threat = true;
            evidence_votes.push(EvidenceVote {
                result: VoteResult {
                    confidence: 1.0,
                    reason,
                    weight: 3.0,
                },
                class: EvidenceClass::Behavior,
                reliability: 1.0,
                strong_action: true,
            });
        }

        // Deterministic active behavioral/exploit threats (Sigma, CredentialGuard, ProcessInjection, live C2 network, Cedar forbid)
        // override NSRL/Trusted-Vendor/Merkle/REA static known-good, whereas uncorroborated statistical heuristics alone do not.
        let is_statistical_only_vote = |reason: &str| -> bool {
            let rl = reason.to_ascii_lowercase();
            let has_active_lotl = rl.contains("-enc")
                || rl.contains("downloadstring")
                || rl.contains("invoke-expression")
                || rl.contains("iex(")
                || rl.contains("frombase64string")
                || rl.contains("sekurlsa")
                || rl.contains("comsvcs")
                || rl.contains("minidump")
                || rl.contains("lsass")
                || rl.contains("keymgr");
            rl.contains("behavioral threat model: high-risk pattern detected")
                || rl.contains("chaotic phase-space trajectory breakout")
                || rl.contains("diverged from benign limit cycle")
                || rl.contains("agentic trajectory escape threshold exceeded")
                || rl.contains("denial of ml service & sponge attack")
                || rl.contains("sponge attack warning")
                || (!has_active_lotl
                    && (rl.contains("non interactive powershell process spawned")
                        || rl.contains("usage of web request commands")))
        };
        let non_statistical_attack_votes = evidence_votes
            .iter()
            .filter(|v| !is_statistical_only_vote(&v.result.reason))
            .count();
        let has_deterministic_active_attack = early_veto_analysis.is_violated
            || matches!(event.event_id, 8 | 10 | 25)
            || evidence_votes.iter().any(|v| {
                !is_statistical_only_vote(&v.result.reason)
                    && v.strong_action
                    && (matches!(
                        v.class,
                        EvidenceClass::Memory
                            | EvidenceClass::LiveNetwork
                            | EvidenceClass::Behavior
                    ) || v.result.confidence >= 0.85
                        || v.reliability >= 0.90)
            })
            || (non_statistical_attack_votes >= 1 && evidence_votes.len() >= 2)
            || evidence_votes.iter().any(|v| {
                let r = &v.result.reason;
                r.contains("Cedar-Ring7-Forbid")
                    || r.contains("CEDAR-FORBID-TEMPORAL-TAINT-FRAGMENTATION")
                    || r.contains("Self-Protection Violation")
                    || r.contains("Cryptographic mesh signature mismatch")
                    || r.contains("IdentitySpoofingDetected")
                    || r.contains("BYOVD")
                    || r.contains("ETW_USERMODE_PATCH_DETECTED")
                    || r.contains("AMSI_SCANBUFFER_BYPASS_PATCH_DETECTED")
                    || r.contains("NTDLL_DETOUR_UNHOOKED")
                    || r.contains("prompt_injection")
                    || r.contains("masquerade")
            });

        if has_deterministic_active_attack && (vetoed || nsrl_vetoed) {
            if let Some(ref mut r) = signature.reason {
                *r = r.replace("Veto [", "OverriddenVeto [");
            }
            // Asymmetric Veto: Reset veto flags so NSRL cannot abort the round
            vetoed = false;
            nsrl_vetoed = false;
        }

        if (vetoed || nsrl_vetoed) && !has_deterministic_active_attack {
            debug!(target: CONSENSUS_LOG_TARGET, "[CONSENSUS] round aborted (veto)");
            if hash != "no-hash" && !hash.trim().is_empty() {
                let proc_name = process_name_from_event(event);
                let _ = self.memory.mark_hash_clean_ignored(
                    &hash,
                    proc_name.as_deref(),
                    Some(image_path),
                    "consensus_veto_clean",
                );
                let finding = osoosi_types::ConsensusFinding {
                    id: format!("CONS-VETO-{}", &hash[..hash.len().min(12)]),
                    hash_blake3: hash.clone(),
                    process_name: proc_name,
                    file_path: Some(image_path.to_string()),
                    verdict: "benign".to_string(),
                    confidence: 0.99,
                    detector_count: vote_count,
                    voters_summary: signature.reason.clone().unwrap_or_else(|| {
                        "Veto [Trusted-Vendor / NSRL / Merkle Allowlist]: Verified clean binary"
                            .to_string()
                    }),
                    action_taken: "ignored_and_allowed".to_string(),
                    evaluated_at: chrono::Utc::now(),
                };
                let _ = self.memory.record_consensus_finding(&finding);
            }
            return None;
        }

        // Safety net: TAXII/REST IoCs must count toward voting even if OtxVoter was not registered.
        if !otx_voted {
            if let Some(otx_reason) = self.otx_ioc_match_for_event(event) {
                let w = crate::otx_connection::otx_consensus_weight(event);
                let c = crate::otx_connection::OTX_CONSENSUS_CONFIDENCE;
                info!(
                    target: CONSENSUS_LOG_TARGET,
                    voter = OTX_VOTER,
                    conf = c,
                    weight = w,
                    contribution = c * w,
                    reason = %otx_reason,
                    "[CONSENSUS] OTX safety-net YIELD"
                );
                total_score += c * w;
                vote_count += 1;
                signature.add_reason(format!("[{}]: {}", OTX_VOTER, otx_reason));
                is_threat = true;
                let res = VoteResult {
                    confidence: c,
                    reason: otx_reason,
                    weight: w,
                };
                let (class, reliability, strong_action) = classify_vote(OTX_VOTER, &res, event);
                evidence_votes.push(EvidenceVote {
                    result: res,
                    class,
                    reliability,
                    strong_action,
                });
            }
        }

        if !is_threat {
            debug!(
                target: CONSENSUS_LOG_TARGET,
                path = %image_path,
                "[CONSENSUS] clean (all voters abstained)"
            );
            if hash != "no-hash" && !hash.trim().is_empty() {
                let proc_name = process_name_from_event(event);
                let _ = self.memory.mark_hash_clean_ignored(
                    &hash,
                    proc_name.as_deref(),
                    Some(image_path),
                    "consensus_clean",
                );
                let finding = osoosi_types::ConsensusFinding {
                    id: format!("CONS-BENIGN-{}", &hash[..hash.len().min(12)]),
                    hash_blake3: hash.clone(),
                    process_name: proc_name,
                    file_path: Some(image_path.to_string()),
                    verdict: "benign".to_string(),
                    confidence: 0.98,
                    detector_count: 0,
                    voters_summary: "All voters abstained / nominal behavior".to_string(),
                    action_taken: "ignored_and_allowed".to_string(),
                    evaluated_at: chrono::Utc::now(),
                };
                let _ = self.memory.record_consensus_finding(&finding);
            }
            return None;
        }

        signature.detector_count = vote_count;
        signature.process_name = process_name_from_event(event);
        signature.hash_blake3 = if hash != "no-hash" {
            Some(hash.clone())
        } else {
            preferred_hash_from_event(event)
        };
        signature.parent_process = event
            .data
            .get("ParentImage")
            .and_then(|v| v.as_str())
            .and_then(|p| std::path::Path::new(p).file_name())
            .and_then(|n| n.to_str())
            .map(|s| s.to_string());
        signature.version = event
            .data
            .get("ProductVersion")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);

        if signature.mitre_technique.is_none() {
            if let Some(ref reason_str) = signature.reason {
                static MITRE_RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
                let re = MITRE_RE
                    .get_or_init(|| regex::Regex::new(r"\b(T1\d{3}(?:\.\d{1,4})?)\b").unwrap());
                if let Some(caps) = re.captures(reason_str) {
                    if let Some(m) = caps.get(1) {
                        let tech_id = m.as_str().to_string();
                        if let Some(tech) = crate::mitre_kb::lookup_technique(&tech_id) {
                            signature.mitre_tactic = Some(tech.tactic_name);
                            signature.mitre_technique_name = Some(tech.name);
                        }
                        signature.mitre_technique = Some(tech_id);
                    }
                }
            }
        }

        let decision = orchestrate_evidence(&evidence_votes, event, &self.config);
        let is_asymmetric_veto =
            detect_deterministic_asymmetric_veto(event, &evidence_votes).is_violated;
        signature.confidence = decision.confidence;

        // Apply suppression for noisy/trusted paths by capping confidence
        let has_strong_behavioral_or_memory = evidence_votes.iter().any(|v| {
            v.strong_action
                && v.result.confidence >= 0.85
                && matches!(
                    v.class,
                    EvidenceClass::Memory | EvidenceClass::Behavior | EvidenceClass::LiveNetwork
                )
        });
        if is_noisy && !has_strong_behavioral_or_memory && !is_asymmetric_veto {
            signature.confidence = signature.confidence.min(0.15);
            signature
                .add_reason("Suppressed: Matches consensus_noisy_stems or consensus_trusted_paths");
        }

        signature.recommended_action = decision.action;
        signature.require_approval = decision.require_approval;
        signature.add_reason(decision.summary);

        if !is_asymmetric_veto
            && signature.confidence < 0.20
            && is_trusted_operational_tool(event, &self.config)
        {
            info!(
                target: CONSENSUS_LOG_TARGET,
                event_id = ?event.event_id,
                process = ?signature.process_name,
                confidence = signature.confidence,
                "[CONSENSUS] trusted operational tool observed; no threat emitted without independent malicious behavior"
            );
            return None;
        }

        // Federated learning: adjust confidence based on known true/false positive patterns
        if is_threat {
            let proc_owned = signature.process_name.clone();
            let hash_owned = signature.hash_blake3.clone();
            let proc = proc_owned.as_deref();
            let hash = hash_owned.as_deref();

            // 1. If it's a confirmed TRUE positive, boost to 1.0
            if let Ok(true) = self.memory.is_true_positive_pattern(proc, hash) {
                signature.confidence = 1.0;
                signature.add_reason("Reinforced: matches confirmed federated threat pattern");
                // Ensure action is at least GhostTarpit
                if signature.recommended_action == ResponseAction::Alert
                    || signature.recommended_action == ResponseAction::Tarpit
                {
                    signature.recommended_action = ResponseAction::GhostTarpit;
                }
            }
            // 2. If it's a known FALSE positive, suppress
            else if let Ok(true) = self.memory.is_false_positive_pattern(proc, hash) {
                if !is_asymmetric_veto {
                    signature.confidence = (signature.confidence * 0.05).max(0.0);
                    signature.add_reason("Suppressed: matches federated false positive pattern");
                    // If confidence is now very low, drop the finding completely.
                    if signature.confidence < 0.2 {
                        info!(
                            target: CONSENSUS_LOG_TARGET,
                            event_id = ?event.event_id,
                            process = ?proc,
                            hash = ?hash,
                            "[CONSENSUS] suppressed false-positive pattern"
                        );
                        return None;
                    }
                } else {
                    signature.add_reason("Preserved: federated false-positive suppression rejected by deterministic asymmetric veto");
                }
            }
        }

        // Enrich signature with MITRE ATT&CK Framework metadata if missing or generic
        let reason_str = signature.reason.as_deref().unwrap_or("");
        if let Some((tac, tech, name)) = crate::mitre_kb::extract_mitre_from_text(reason_str) {
            let cur_tech = signature.mitre_technique.as_deref().unwrap_or("");
            if cur_tech.is_empty()
                || cur_tech == "T1006"
                || (cur_tech == "T1059" && !tech.starts_with("T1059"))
            {
                signature.mitre_tactic = Some(tac);
                signature.mitre_technique = Some(tech);
                signature.mitre_technique_name = Some(name);
            }
        } else if signature.mitre_technique.is_none() {
            if let Some((tac, tech, name)) =
                crate::mitre_kb::infer_mitre_from_event(event.event_id, image_path, cmdline)
            {
                signature.mitre_tactic = Some(tac);
                signature.mitre_technique = Some(tech);
                signature.mitre_technique_name = Some(name);
            }
        }

        // Align consensus response action with authoritative MITRE technique designation
        if let Some(ref tech_id) = signature.mitre_technique {
            let tech_upper = tech_id.to_ascii_uppercase();
            let is_system_tampering_or_critical = tech_upper.starts_with("T1006")
                || tech_upper.starts_with("T1003")
                || tech_upper.starts_with("T1055")
                || tech_upper.starts_with("T1136")
                || tech_upper.starts_with("T1485")
                || tech_upper.starts_with("T1486")
                || tech_upper.starts_with("T1489")
                || tech_upper.starts_with("T1490")
                || tech_upper.starts_with("T1542")
                || tech_upper.starts_with("T1543")
                || tech_upper.starts_with("T1546")
                || tech_upper.starts_with("T1547")
                || tech_upper.starts_with("T1552")
                || tech_upper.starts_with("T1553")
                || tech_upper.starts_with("T1555")
                || tech_upper.starts_with("T1556")
                || tech_upper.starts_with("T1562")
                || tech_upper.starts_with("T1574")
                || tech_upper.starts_with("T1601");

            if is_system_tampering_or_critical && signature.confidence >= 0.35 {
                signature.recommended_action = ResponseAction::Isolate;
                if signature.confidence >= 0.85 {
                    signature.require_approval = false;
                }
            } else if let Some(tech_meta) = crate::mitre_kb::lookup_technique(tech_id) {
                match tech_meta.consensus_action.as_str() {
                    "Isolate" => {
                        if signature.confidence >= 0.50 {
                            signature.recommended_action = ResponseAction::Isolate;
                        }
                    }
                    "Tarpit" => {
                        if signature.recommended_action == ResponseAction::Alert
                            && signature.confidence >= 0.40
                        {
                            signature.recommended_action = ResponseAction::Tarpit;
                        }
                    }
                    "MemoryScan" if signature.recommended_action == ResponseAction::Alert => {
                        signature.recommended_action = ResponseAction::MemoryScan;
                    }
                    _ => {}
                }
            }
        }

        let is_explicit_alert = signature
            .mitre_technique
            .as_deref()
            .and_then(crate::mitre_kb::lookup_technique)
            .map(|m| m.consensus_action == "Alert")
            .unwrap_or(false);

        let autonomy = osoosi_types::load_autonomy_config();
        let is_lockdown_mode =
            autonomy.auto_quarantine_malware && autonomy.quarantine_confidence_threshold <= 0.60;
        if is_lockdown_mode && signature.confidence >= autonomy.quarantine_confidence_threshold {
            if signature.recommended_action == ResponseAction::Alert && !is_explicit_alert {
                signature.recommended_action = ResponseAction::Isolate;
            }
            signature.require_approval = false;
        } else if autonomy.auto_quarantine_malware
            && signature.confidence >= autonomy.quarantine_confidence_threshold
            && signature.mitre_technique.is_some()
            && signature.recommended_action == ResponseAction::Alert
            && !is_explicit_alert
        {
            signature.recommended_action = ResponseAction::Isolate;
        }

        // Zero-"Unknown Process" Alert Invariant & Noise Gate:
        // Never emit an alert for an unknown process, non-existing file heuristic artifacts, or confidence below floor.
        let min_confidence_floor = if is_sec_or_gw {
            0.0
        } else if is_lockdown_mode {
            autonomy.action_confidence_threshold.min(0.35)
        } else {
            0.50
        };
        let proc_clean = signature.process_name.as_deref().unwrap_or("").trim();
        let combined_reason = signature.reason.as_deref().unwrap_or("");
        if (proc_clean.is_empty()
            || proc_clean.eq_ignore_ascii_case("unknown")
            || proc_clean.eq_ignore_ascii_case("unknown process"))
            && is_asymmetric_veto
        {
            // Guarantee process name for invariant isolation to prevent dropping
            signature.process_name = Some("[Deterministic-Containment-Veto]".to_string());
        } else if (proc_clean.is_empty()
            || proc_clean.eq_ignore_ascii_case("unknown")
            || proc_clean.eq_ignore_ascii_case("unknown process"))
            && is_sec_or_gw
        {
            // Guarantee process name for security/gateway evaluation to prevent dropping
            signature.process_name = Some("[Security-Gateway-Evaluation]".to_string());
        } else if proc_clean.is_empty()
            || proc_clean.eq_ignore_ascii_case("unknown")
            || proc_clean.eq_ignore_ascii_case("unknown process")
            || combined_reason.contains("Execution Of Non-Existing File")
            || signature.confidence < min_confidence_floor
        {
            debug!(
                target: CONSENSUS_LOG_TARGET,
                proc = %proc_clean,
                confidence = signature.confidence,
                "[CONSENSUS] threat suppressed: unknown process, execution of non-existing file, or confidence < 0.50"
            );
            return None;
        }

        info!(
            target: CONSENSUS_LOG_TARGET,
            event_id = ?event.event_id,
            votes = vote_count,
            weighted_score = total_score,
            confidence = signature.confidence,
            action = ?signature.recommended_action,
            "[CONSENSUS] round COMPLETE — threat signature emitted"
        );

        // Record malicious consensus finding in ledger
        let finding = osoosi_types::ConsensusFinding {
            id: signature.id.clone(),
            hash_blake3: signature
                .hash_blake3
                .clone()
                .unwrap_or_else(|| hash.clone()),
            process_name: signature.process_name.clone(),
            file_path: Some(image_path.to_string()),
            verdict: "malicious".to_string(),
            confidence: signature.confidence,
            detector_count: signature.detector_count,
            voters_summary: signature.reason.clone().unwrap_or_default(),
            action_taken: format!("{:?}", signature.recommended_action),
            evaluated_at: chrono::Utc::now(),
        };
        let _ = self.memory.record_consensus_finding(&finding);

        // Compute voter confidence in basis points (0..=10000 bp)
        let voter_confidence_bp =
            (signature.confidence * 10_000.0).round().clamp(0.0, 10_000.0) as u16;

        let pid: u32 = event
            .data
            .get("ProcessId")
            .or_else(|| event.data.get("process_id"))
            .or_else(|| event.data.get("pid"))
            .or_else(|| event.data.get("PID"))
            .or_else(|| event.data.get("NewProcessId"))
            .or_else(|| event.data.get("TargetProcessId"))
            .and_then(|v| {
                v.as_u64()
                    .map(|n| n as u32)
                    .or_else(|| {
                        v.as_str().and_then(|s| {
                            if s.starts_with("0x") || s.starts_with("0X") {
                                u32::from_str_radix(&s[2..], 16).ok()
                            } else {
                                s.parse::<u32>().ok()
                            }
                        })
                    })
            })
            .unwrap_or(0);

        let start_time_ticks: u64 = event
            .data
            .get("ProcessStartTime")
            .or_else(|| event.data.get("process_start_time"))
            .or_else(|| event.data.get("ProcessStartTimeTicks"))
            .or_else(|| event.data.get("StartTime"))
            .or_else(|| event.data.get("start_time_ticks"))
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
            })
            .unwrap_or_else(|| {
                (event.timestamp.timestamp_nanos_opt().unwrap_or(0) / 100) as u64
            });

        let target = ProcessInstanceKey::new(pid, start_time_ticks);
        let trigger_reason = signature
            .reason
            .clone()
            .or_else(|| signature.process_name.clone())
            .unwrap_or_else(|| "Consensus Quorum Alert".to_string());

        let alert = VoterQuorumAlert::new(target, voter_confidence_bp, trigger_reason);

        if let Some(ref sink) = *self.voter_quorum_sink.read().await {
            sink(alert);
        }

        self.consensus_cache
            .insert(cache_key, (signature.clone(), std::time::Instant::now()));
        Some(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed::OtxIndicators;
    use crate::voters::{OtxVoter, SemanticVoter};
    use chrono::Utc;
    use osoosi_types::{HostSecurityEvent, ResponseAction};
    use serde_json::json;
    use std::sync::Arc;

    fn make_event(image: &str, cmd_line: &str) -> osoosi_types::HostSecurityEvent {
        osoosi_types::HostSecurityEvent {
            source: osoosi_types::HostEventSource::WindowsEventLog,
            event_id: 1, // ProcessCreate
            timestamp: Utc::now(),
            computer: "test-host".to_string(),
            data: serde_json::json!({
                "Image": image,
                "CommandLine": cmd_line,
                "ProcessId": 1234,
            }),
            causal_parent: None,
        }
    }

    #[test]
    fn test_scan_event_discovery_ttp() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let config = osoosi_types::PolicyConfig::default();
        let engine = PolicyEngine::new(memory, config);

        // Add a basic semantic voter for testing
        let semantic_voter = Box::new(SemanticVoter {
            engine: crate::semantic::SemanticEngine::new(),
        });

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            engine.add_voter(semantic_voter).await;
            let event = make_event("C:\\Windows\\System32\\whoami.exe", "whoami");
            let sig = engine.scan_event(&event).await;
            // Note: semantic drift might not hit on 'whoami' without training,
            // but this confirms the loop runs.
            let _ = sig;
        });
    }

    #[test]
    fn test_scan_event_benign() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let config = osoosi_types::PolicyConfig::default();
        let engine = PolicyEngine::new(memory, config);
        let event = make_event("C:\\Program Files\\notepad.exe", "notepad");
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let sig = engine.scan_event(&event).await;
            let _ = sig; // just ensure it doesn't panic
        });
    }

    /// OTX IoCs merge into voting via safety-net when `OtxVoter` is not registered.
    #[test]
    fn test_otx_ioc_safety_net_participates_in_consensus() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory"));
        let config = osoosi_types::PolicyConfig::default();
        let engine = PolicyEngine::new(memory, config);
        let mut otx = OtxIndicators::default();
        otx.ips.insert("198.51.100.2".to_string());
        engine.update_otx_indicators(otx);

        let event = HostSecurityEvent {
            source: osoosi_types::HostEventSource::WindowsEventLog,
            event_id: 3, // NetworkConnect
            timestamp: Utc::now(),
            computer: "h".to_string(),
            data: json!({
                "Image": "C:\\\\Windows\\\\System32\\\\curl.exe",
                "DestinationIp": "198.51.100.2",
                "DestinationPort": 443,
                "ProcessId": 1,
            }),
            causal_parent: None,
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let sig = engine
                .scan_event(&event)
                .await
                .expect("OTX should vote via safety-net");
            let reason = sig.reason.as_deref().unwrap();
            assert!(reason.contains("OTX-C2"), "reason was: {}", reason);
            assert_eq!(sig.detector_count, 1);
        });
    }

    /// When `OtxVoter` is present, the same OTX reason must not be applied twice.
    #[test]
    fn test_otx_voter_no_double_votes() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory"));
        let config = osoosi_types::PolicyConfig::default();
        let engine = PolicyEngine::new(memory.clone(), config);
        let mut otx = OtxIndicators::default();
        otx.ips.insert("198.51.100.3".to_string());
        engine.update_otx_indicators(otx);

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            engine
                .add_voter(Box::new(OtxVoter {
                    indicators: engine.otx_indicators_ref().clone(),
                    memory: memory.clone(),
                }))
                .await;

            let event = HostSecurityEvent {
                source: osoosi_types::HostEventSource::WindowsEventLog,
                event_id: 3, // NetworkConnect
                timestamp: Utc::now(),
                computer: "h".to_string(),
                data: json!({
                    "Image": "C:\\\\Windows\\\\System32\\\\curl.exe",
                    "DestinationIp": "198.51.100.3",
                    "ProcessId": 1,
                }),
                causal_parent: None,
            };

            let sig = engine.scan_event(&event).await.expect("OtxVoter + OTX");
            let reason = sig.reason.as_deref().unwrap();
            assert_eq!(
                reason.matches("OTX-C2").count(),
                1,
                "expected single OTX block in reasons: {}",
                reason
            );
            assert_eq!(sig.detector_count, 1);
        });
    }

    #[test]
    fn evidence_orchestrator_caps_kev_plus_weak_static_noise() {
        let event = make_event("C:\\tools\\git\\cmd\\git.exe", "git status");
        let config = osoosi_types::PolicyConfig::default();
        let votes = vec![
            EvidenceVote {
                result: VoteResult {
                    confidence: 0.85,
                    reason: "CISA KEV: git.exe matches product Git".to_string(),
                    weight: 1.0,
                },
                class: EvidenceClass::ThreatIntel,
                reliability: 0.58,
                strong_action: false,
            },
            EvidenceVote {
                result: VoteResult {
                    confidence: 1.0,
                    reason: "MalwareScanner: combined=1.000 ml=0.000 sig=1.000 magika=pebin"
                        .to_string(),
                    weight: 0.88,
                },
                class: EvidenceClass::StaticArtifact,
                reliability: 0.42,
                strong_action: false,
            },
        ];

        let decision = orchestrate_evidence(&votes, &event, &config);
        assert!(decision.confidence <= 0.68, "decision={decision:?}");
        assert_eq!(decision.action, osoosi_types::ResponseAction::Alert);
    }

    #[test]
    fn evidence_orchestrator_tarpits_correlated_live_network_findings() {
        let mut event = make_event("C:\\Temp\\payload.exe", "payload.exe");
        let config = osoosi_types::PolicyConfig::default();
        event.event_id = 3; // NetworkConnect
        event.data = json!({
            "Image": "C:\\Temp\\payload.exe",
            "CommandLine": "payload.exe",
            "DestinationIp": "203.0.113.50",
            "ProcessId": 4321
        });
        let votes = vec![
            EvidenceVote {
                result: VoteResult {
                    confidence: 0.93,
                    reason: "OTX: destination IP matched pulse".to_string(),
                    weight: 1.0,
                },
                class: EvidenceClass::LiveNetwork,
                reliability: 1.0,
                strong_action: true,
            },
            EvidenceVote {
                result: VoteResult {
                    confidence: 0.86,
                    reason: "BehavioralYara: suspicious outbound connection".to_string(),
                    weight: 0.8,
                },
                class: EvidenceClass::Behavior,
                reliability: 0.88,
                strong_action: true,
            },
        ];

        let decision = orchestrate_evidence(&votes, &event, &config);
        assert!(decision.confidence >= 0.74, "decision={decision:?}");
        assert!(matches!(
            decision.action,
            osoosi_types::ResponseAction::Tarpit | osoosi_types::ResponseAction::GhostTarpit
        ));
    }

    #[tokio::test]
    async fn test_mitre_atlas_voters_consensus_emission() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let config = osoosi_types::PolicyConfig::default();
        let engine = PolicyEngine::new(memory, config);

        // Register AiSecurityAuditVoter and AgenticPolicyVoter
        engine
            .add_voter(Box::new(crate::ai_audit_voter::AiSecurityAuditVoter::new()))
            .await;
        engine
            .add_voter(Box::new(crate::agentic_voter::AgenticPolicyVoter::new()))
            .await;

        // 1. Tool-argument injection: AML.T0043 (Execution, Tarpit)
        let mut event_tool_inject = make_event(
            "C:\\Python311\\python.exe",
            "python.exe -c \"import os; os.system('whoami && calc.exe')\"",
        );
        event_tool_inject.data = json!({
            "Image": "C:\\Python311\\python.exe",
            "CommandLine": "python.exe -c \"import os; os.system('whoami && calc.exe')\"",
            "ParentImage": "C:\\Program Files\\Modelfusion\\agent.exe",
            "ProcessId": 5566,
        });

        let sig_opt = engine.scan_event(&event_tool_inject).await;
        assert!(
            sig_opt.is_some(),
            "Expected threat signature for tool argument injection"
        );
        let sig = sig_opt.unwrap();
        assert_eq!(sig.mitre_technique.as_deref(), Some("AML.T0043"));
        assert_eq!(sig.mitre_tactic.as_deref(), Some("Execution"));
        assert!(sig
            .mitre_technique_name
            .as_deref()
            .unwrap()
            .contains("Adversarial Prompt Injection"));
        assert_eq!(sig.recommended_action, ResponseAction::Tarpit);

        // 2. Canary credential breach: AML.T0054 (Exfiltration, Alert)
        let mut event_canary = make_event(
            "C:\\Python311\\python.exe",
            "python.exe script.py --key AWS_SECRET_ACCESS_KEY_CANARY",
        );
        event_canary.data = json!({
            "Image": "C:\\Python311\\python.exe",
            "CommandLine": "python.exe script.py --key AWS_SECRET_ACCESS_KEY_CANARY",
            "ParentImage": "C:\\Program Files\\Modelfusion\\agent.exe",
            "ProcessId": 5567,
        });

        let sig_opt2 = engine.scan_event(&event_canary).await;
        assert!(
            sig_opt2.is_some(),
            "Expected threat signature for canary breach"
        );
        let sig2 = sig_opt2.unwrap();
        assert_eq!(sig2.mitre_technique.as_deref(), Some("AML.T0054"));
        assert_eq!(sig2.mitre_tactic.as_deref(), Some("Exfiltration"));
        assert_eq!(sig2.recommended_action, ResponseAction::Isolate);

        // 3. Agent memory tampering: AML.T0048 (Persistence, Isolate)
        let event_memory_tamper = HostSecurityEvent {
            source: osoosi_types::HostEventSource::WindowsEventLog,
            event_id: 11, // FileCreate / FileModification
            timestamp: Utc::now(),
            computer: "test-host".to_string(),
            data: json!({
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "TargetFilename": "D:\\harfile\\OshoosiClaw\\.agents\\memory.md",
                "ProcessId": 5568,
            }),
            causal_parent: None,
        };

        let sig_opt3 = engine.scan_event(&event_memory_tamper).await;
        assert!(
            sig_opt3.is_some(),
            "Expected threat signature for agent memory tampering"
        );
        let sig3 = sig_opt3.unwrap();
        assert_eq!(sig3.mitre_technique.as_deref(), Some("AML.T0048"));
        assert_eq!(sig3.mitre_tactic.as_deref(), Some("Persistence"));
        assert_eq!(sig3.recommended_action, ResponseAction::Isolate);
    }

    #[tokio::test]
    async fn test_voter_timeout_demoted_and_treated_as_abstain() {
        struct TimedOutVoter;
        #[async_trait]
        impl ThreatVoter for TimedOutVoter {
            fn name(&self) -> String {
                "TimedOutVoter".to_string()
            }
            async fn vote(&self, _event: &HostSecurityEvent) -> Option<VoteResult> {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                Some(VoteResult {
                    confidence: 0.99,
                    reason: "Late detection".to_string(),
                    weight: 1.0,
                })
            }
        }

        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let config = osoosi_types::PolicyConfig::default();
        let engine = PolicyEngine::new(memory, config);
        engine.add_voter(Box::new(TimedOutVoter)).await;

        let event = make_event("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c dir");

        tokio::time::pause();
        let scan_fut = tokio::spawn(async move { engine.scan_event(&event).await });
        tokio::time::advance(std::time::Duration::from_secs(31)).await;
        let res = scan_fut.await.unwrap();
        assert!(
            res.is_none(),
            "Timed out voter should be treated as abstain"
        );
    }

    #[tokio::test]
    async fn test_credential_guard_voter_and_persistent_weights() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        memory
            .save_voter_weight("CredentialGuard-Memory", 1.25)
            .unwrap();

        let config = osoosi_types::PolicyConfig::default();
        let engine = PolicyEngine::new(memory.clone(), config);
        assert!(
            (engine
                .voter_weight_multipliers
                .get("CredentialGuard-Memory")
                .unwrap()
                .value()
                - 1.25)
                .abs()
                < 1e-4
        );

        // Update specific weight
        engine.update_specific_voter_weights(&["CredentialGuard-Memory".to_string()], true, 0.05);
        assert!(
            (engine
                .voter_weight_multipliers
                .get("CredentialGuard-Memory")
                .unwrap()
                .value()
                - 1.30)
                .abs()
                < 1e-4
        );

        // Verify persisted to SQLite
        let reloaded = memory.load_voter_weights().unwrap();
        assert!((reloaded.get("CredentialGuard-Memory").unwrap() - 1.30).abs() < 1e-4);

        // Test CredentialGuardVoter on comsvcs minidump
        let voter = crate::voters::CredentialGuardVoter;
        let event = HostSecurityEvent {
            source: osoosi_types::HostEventSource::WindowsEventLog,
            event_id: 1,
            computer: "TEST-HOST".to_string(),
            data: serde_json::json!({
                "CommandLine": "rundll32.exe C:\\windows\\System32\\comsvcs.dll, #24 672 C:\\temp\\lsass.dmp full",
                "Image": "C:\\Windows\\System32\\rundll32.exe",
            }),
            timestamp: chrono::Utc::now(),
            causal_parent: None,
        };

        let vote = voter.vote(&event).await;
        assert!(vote.is_some());
        let res = vote.unwrap();
        assert!(res.confidence >= 0.95);
        assert!(res.reason.contains("comsvcs.dll"));
    }

    #[tokio::test]
    async fn test_rundll32_keymgr_isolated() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let config = osoosi_types::PolicyConfig::default();
        let engine = PolicyEngine::new(memory, config);

        engine
            .add_voter(Box::new(crate::voters::TrustedVendorVoter))
            .await;
        engine
            .add_voter(Box::new(crate::voters::CredentialGuardVoter))
            .await;

        let event = HostSecurityEvent {
            source: osoosi_types::HostEventSource::WindowsEventLog,
            event_id: 1,
            computer: "TEST-HOST".to_string(),
            data: serde_json::json!({
                "Image": r"C:\WINDOWS\system32\rundll32.exe",
                "CommandLine": r"C:\WINDOWS\system32\rundll32.exe keymgr,KRShowKeyMgr",
            }),
            timestamp: chrono::Utc::now(),
            causal_parent: None,
        };

        let sig_opt = engine.scan_event(&event).await;
        assert!(
            sig_opt.is_some(),
            "Expected threat signature for rundll32 keymgr"
        );
        let sig = sig_opt.unwrap();
        assert!(
            sig.confidence >= 0.90,
            "Expected confidence >= 0.90, got: {}",
            sig.confidence
        );
        assert_eq!(
            sig.recommended_action,
            osoosi_types::ResponseAction::Isolate,
            "Expected Isolate action"
        );
        assert!(
            !sig.require_approval,
            "Expected require_approval to be false"
        );
        assert_eq!(
            sig.mitre_technique.as_deref(),
            Some("T1003.007"),
            "Expected MITRE technique T1003.007 to be extracted"
        );
    }

    #[tokio::test]
    async fn test_sigma_lolbin_sc_exe_elevated_above_085_and_isolated() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let config = osoosi_types::PolicyConfig::default();
        let engine = PolicyEngine::new(memory, config);

        engine
            .add_voter(Box::new(crate::voters::TrustedVendorVoter))
            .await;

        let yaml_rule = r#"
title: Service Security Descriptor Modification Via Sc.EXE
id: b925e012-70be-41ec-b12e-13c544e31121
status: test
description: Detects modification of service DACL via sc.exe sdset
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1543.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\sc.exe'
        CommandLine|contains: 'sdset'
    condition: selection
level: high
ruletype: Sigma
"#;
        let rule: crate::sigma::SigmaRule =
            serde_yaml::from_str(yaml_rule).expect("Must deserialize SigmaRule");
        let mut sigma_engine = crate::sigma::SigmaEngine::new();
        sigma_engine.add_rule(rule).expect("Must add rule");

        let sigma_voter = crate::voters::SigmaVoter {
            engine: Arc::new(sigma_engine),
        };
        engine.add_voter(Box::new(sigma_voter)).await;

        let event = HostSecurityEvent {
            source: osoosi_types::HostEventSource::WindowsEventLog,
            event_id: 1,
            computer: "TEST-HOST".to_string(),
            data: serde_json::json!({
                "Image": r"C:\Windows\System32\sc.exe",
                "CommandLine": r"C:\Windows\System32\sc.exe sdset TrustedService D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)",
            }),
            timestamp: chrono::Utc::now(),
            causal_parent: None,
        };

        let sig_opt = engine.scan_event(&event).await;
        assert!(
            sig_opt.is_some(),
            "Expected threat signature for sc.exe sdset Sigma match"
        );
        let sig = sig_opt.unwrap();
        assert!(
            sig.confidence >= 0.85,
            "Expected confidence >= 0.85, got: {}",
            sig.confidence
        );
        assert_eq!(
            sig.recommended_action,
            osoosi_types::ResponseAction::Isolate,
            "Expected Isolate action"
        );
        assert!(
            !sig.require_approval,
            "Expected require_approval to be false"
        );
    }

    #[tokio::test]
    async fn test_atomic_calc_payload_spawn_detected_and_transient_pid_eligible() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let config = osoosi_types::PolicyConfig::default();
        let engine = PolicyEngine::new(memory, config);

        let sigma_engine = crate::sigma::SigmaEngine::new();
        let sigma_voter = crate::voters::SigmaVoter {
            engine: Arc::new(sigma_engine),
        };
        engine.add_voter(Box::new(sigma_voter)).await;

        let event = HostSecurityEvent {
            source: osoosi_types::HostEventSource::WindowsEventLog,
            event_id: 1,
            computer: "TEST-HOST".to_string(),
            data: serde_json::json!({
                "Image": r"C:\Windows\System32\calc.exe",
                "CommandLine": r"calc.exe",
                "ParentImage": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "ParentCommandLine": r"powershell.exe -ExecutionPolicy Bypass -Command calc.exe",
            }),
            timestamp: chrono::Utc::now(),
            causal_parent: None,
        };

        let sig_opt = engine.scan_event(&event).await;
        assert!(
            sig_opt.is_some(),
            "Expected threat signature for calc.exe spawned by PowerShell"
        );
        let sig = sig_opt.unwrap();
        assert!(
            sig.confidence >= 0.85,
            "Expected composite confidence >= 0.85, got: {}",
            sig.confidence
        );
    }
}

#[cfg(test)]
mod tests_m7_asymmetric_veto {
    use super::*;
    use chrono::Utc;
    use osoosi_types::{HostEventSource, HostSecurityEvent, ResponseAction};
    use serde_json::json;
    use std::sync::Arc;

    fn make_test_event(image: &str, cmdline: &str) -> HostSecurityEvent {
        HostSecurityEvent {
            source: HostEventSource::WindowsEventLog,
            event_id: 1,
            timestamp: Utc::now(),
            computer: "TEST-HOST".to_string(),
            data: json!({
                "Image": image,
                "CommandLine": cmdline,
                "ProcessId": 4412,
            }),
            causal_parent: None,
        }
    }

    /// Mock benign ML voter reporting very low confidence (0.05) with normal weight
    struct BenignMlVoter;
    #[async_trait::async_trait]
    impl ThreatVoter for BenignMlVoter {
        fn name(&self) -> String {
            "MalConv-ML".to_string()
        }
        async fn vote(&self, _event: &HostSecurityEvent) -> Option<VoteResult> {
            Some(VoteResult {
                confidence: 0.05,
                reason: "MalConv: Model predicts benign executable (score=0.05)".to_string(),
                weight: 1.0,
            })
        }
    }

    /// R7. Tier 1: test_r7_tc01 (Deterministic guard commands ResponseAction::Isolate)
    #[tokio::test]
    async fn test_r7_tc01_deterministic_guard_commands_isolate() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let config = osoosi_types::PolicyConfig::default();
        let engine = PolicyEngine::new(memory, config);

        let mut event = make_test_event("C:\\Windows\\System32\\cmd.exe", "cmd.exe");
        event.data["CanaryTrapTripped"] = json!(true);

        let sig = engine
            .scan_event(&event)
            .await
            .expect("Expected threat signature");
        assert_eq!(sig.recommended_action, ResponseAction::Isolate);
        assert_eq!(sig.confidence, 1.0f32);
        assert!(!sig.require_approval);
    }

    /// R7. Tier 1: test_r7_tc02 (Asymmetric veto overrides static PE ML dilution)
    #[tokio::test]
    async fn test_r7_tc02_asymmetric_veto_overrides_static_pe_ml() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let config = osoosi_types::PolicyConfig::default();
        let engine = PolicyEngine::new(memory, config);

        // Register Benign ML voter which would otherwise dilute base = support / mass
        engine.add_voter(Box::new(BenignMlVoter)).await;

        let mut event = make_test_event(
            "C:\\Windows\\System32\\rundll32.exe",
            "rundll32.exe keymgr,KRShowKeyMgr",
        );
        event.data["PrivilegeEscalationDetected"] = json!(true);
        engine
            .add_voter(Box::new(crate::voters::CredentialGuardVoter))
            .await;

        let sig = engine
            .scan_event(&event)
            .await
            .expect("Expected threat signature");
        // ML voter cannot dilute deterministic invariant violation
        assert_eq!(sig.recommended_action, ResponseAction::Isolate);
        assert_eq!(sig.confidence, 1.0f32);
        assert!(!sig.require_approval);
    }

    /// R7. Tier 1: test_r7_tc03 (Asymmetric veto overrides NSRL whitelist)
    #[tokio::test]
    async fn test_r7_tc03_asymmetric_veto_overrides_nsrl_whitelist() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let config = osoosi_types::PolicyConfig::default();
        let engine = PolicyEngine::new(memory, config);

        // Trusted-Vendor voter returns weight -1.0 attempting to veto
        engine
            .add_voter(Box::new(crate::voters::TrustedVendorVoter))
            .await;

        let mut event = make_test_event(
            "C:\\Windows\\System32\\svchost.exe",
            "svchost.exe -k netsvcs",
        );
        event.data["KernelTamperDetected"] = json!(true);
        event.event_id = 10; // ProcessAccess

        let sig = engine
            .scan_event(&event)
            .await
            .expect("NSRL whitelist must be overridden");
        assert_eq!(sig.recommended_action, ResponseAction::Isolate);
        assert_eq!(sig.confidence, 1.0f32);
    }

    /// R7. Tier 1: test_r7_tc04 (Benign workload retains normal consensus)
    #[tokio::test]
    async fn test_r7_tc04_benign_workload_retains_normal_consensus() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let config = osoosi_types::PolicyConfig::default();
        let engine = PolicyEngine::new(memory, config);

        engine.add_voter(Box::new(BenignMlVoter)).await;
        let event = make_test_event(
            "C:\\Program Files\\Notepad++\\notepad++.exe",
            "notepad++.exe",
        );

        let sig_opt = engine.scan_event(&event).await;
        assert!(
            sig_opt.is_none(),
            "Benign executable should retain zero false positives"
        );
    }

    /// R7. Tier 1: test_r7_tc05 (Voter weight clamping [0.50, 2.50])
    #[tokio::test]
    async fn test_r7_tc05_voter_weight_clamping() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let config = osoosi_types::PolicyConfig::default();
        let engine = PolicyEngine::new(memory, config);

        let c1 = engine.set_voter_weight("VoterLow", 0.10);
        assert_eq!(c1, 0.50);

        let c2 = engine.set_voter_weight("VoterHigh", 5.00);
        assert_eq!(c2, 2.50);
    }

    /// R7. Tier 1: test_r7_tc06 (Contention-free concurrency lock hygiene)
    #[tokio::test]
    async fn test_r7_tc06_contention_free_concurrency_lock_hygiene() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let config = osoosi_types::PolicyConfig::default();
        let engine = Arc::new(PolicyEngine::new(memory, config));

        let mut handles = Vec::new();
        for i in 0..10 {
            let eng = engine.clone();
            handles.push(tokio::spawn(async move {
                let event = make_test_event(
                    "C:\\Windows\\System32\\cmd.exe",
                    &format!("cmd.exe /c echo {}", i),
                );
                let _ = eng.scan_event(&event).await;
                eng.set_voter_weight(&format!("Voter_{}", i), 1.25);
            }));
        }

        for h in handles {
            h.await.expect("Task must complete without deadlock");
        }
    }

    /// R7. Tier 2: test_r7_b01 (Negative infinity voter weights clamped to 0.50)
    #[tokio::test]
    async fn test_r7_b01_negative_infinity_voter_weights_clamped() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let config = osoosi_types::PolicyConfig::default();
        let engine = PolicyEngine::new(memory, config);

        let c = engine.set_voter_weight("BadVoter", -f32::INFINITY);
        assert_eq!(c, 0.50);

        let c2 = engine.set_voter_weight("BadVoter2", -999.0);
        assert_eq!(c2, 0.50);
    }

    /// R7. Tier 2: test_r7_b02 (Positive infinity voter weights clamped to 2.50)
    #[tokio::test]
    async fn test_r7_b02_positive_infinity_voter_weights_clamped() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let config = osoosi_types::PolicyConfig::default();
        let engine = PolicyEngine::new(memory, config);

        let c = engine.set_voter_weight("HighVoter", f32::INFINITY);
        assert_eq!(c, 2.50);

        let c2 = engine.set_voter_weight("HighVoter2", 999.0);
        assert_eq!(c2, 2.50);
    }

    /// R7. Tier 2: test_r7_b03 (Empty voter list handling)
    #[tokio::test]
    async fn test_r7_b03_empty_voter_list_handling() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let config = osoosi_types::PolicyConfig::default();
        let engine = PolicyEngine::new(memory, config);

        // Empty voter list does not panic
        let event = make_test_event("C:\\Windows\\System32\\calc.exe", "calc.exe");
        let sig = engine.scan_event(&event).await;
        assert!(sig.is_none());
    }

    /// R7. Tier 2: test_r7_b04 (Deterministic guard with both ML and NSRL veto)
    #[tokio::test]
    async fn test_r7_b04_deterministic_guard_with_both_ml_and_nsrl_veto() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let config = osoosi_types::PolicyConfig::default();
        let engine = PolicyEngine::new(memory, config);

        engine
            .add_voter(Box::new(crate::voters::TrustedVendorVoter))
            .await;
        engine.add_voter(Box::new(BenignMlVoter)).await;

        let mut event = make_test_event(
            "C:\\Windows\\System32\\rundll32.exe",
            "rundll32.exe comsvcs.dll, #24 672 C:\\temp\\lsass.dmp full",
        );
        event.data["TokenElevationViolation"] = json!(true);
        engine
            .add_voter(Box::new(crate::voters::CredentialGuardVoter))
            .await;

        let sig = engine
            .scan_event(&event)
            .await
            .expect("Both NSRL and ML must be overridden by asymmetric veto");
        assert_eq!(sig.recommended_action, ResponseAction::Isolate);
        assert_eq!(sig.confidence, 1.0f32);
        assert!(!sig.require_approval);
    }

    /// R7. Tier 2: test_r7_b05 (Threshold boundary 0.8499 vs 0.8500)
    #[test]
    fn test_r7_b05_threshold_boundary_08499_vs_08500() {
        let config = osoosi_types::PolicyConfig::default();
        let event = make_test_event("C:\\Temp\\heuristic.exe", "heuristic.exe");

        // Below 0.85 (0.8499) -> Alert
        let votes_low = vec![EvidenceVote {
            result: VoteResult {
                confidence: 0.8499,
                reason: "Statistical anomaly".to_string(),
                weight: 1.0,
            },
            class: EvidenceClass::Behavior,
            reliability: 1.0,
            strong_action: false,
        }];
        let d_low = orchestrate_evidence(&votes_low, &event, &config);
        assert_eq!(d_low.action, ResponseAction::Alert);

        // At 0.8500 with Sigma/Lolbin guard -> Isolate
        let votes_high = vec![EvidenceVote {
            result: VoteResult {
                confidence: 0.8500,
                reason: "Sigma Match: Suspicious Child Payload Spawn".to_string(),
                weight: 1.0,
            },
            class: EvidenceClass::Behavior,
            reliability: 1.0,
            strong_action: true,
        }];
        let d_high = orchestrate_evidence(&votes_high, &event, &config);
        assert_eq!(d_high.action, ResponseAction::Isolate);
    }

    /// R7. Tier 2: test_r7_b06 (Zero confidence benign consensus)
    #[tokio::test]
    async fn test_r7_b06_zero_confidence_benign_consensus() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let config = osoosi_types::PolicyConfig::default();
        let engine = PolicyEngine::new(memory, config);

        struct ZeroVoter;
        #[async_trait::async_trait]
        impl ThreatVoter for ZeroVoter {
            fn name(&self) -> String {
                "ZeroVoter".to_string()
            }
            async fn vote(&self, _event: &HostSecurityEvent) -> Option<VoteResult> {
                Some(VoteResult {
                    confidence: 0.0,
                    reason: "Zero confidence".to_string(),
                    weight: 1.0,
                })
            }
        }
        engine.add_voter(Box::new(ZeroVoter)).await;

        let event = make_test_event("C:\\Windows\\System32\\cmd.exe", "cmd.exe");
        let sig = engine.scan_event(&event).await;
        assert!(sig.is_none());
    }

    struct MockSilentController;
    impl osoosi_types::TelemetryControllerInterface for MockSilentController {
        fn spawn_adaptive(
            &self,
            _cat: osoosi_types::ResourceCategory,
            _prio: osoosi_types::Priority,
            _task: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>,
        ) {}
        fn report_event(&self) {}
        fn is_burst_mode(&self) -> bool {
            false
        }
        fn is_silent_mode(&self) -> bool {
            true
        }
        fn is_socket_exhaustion(&self) -> bool {
            false
        }
        fn set_socket_exhaustion(&self, _v: bool) {}
        fn get_concurrency_limit(
            &self,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = usize> + Send + '_>> {
            Box::pin(async { 4 })
        }
    }

    struct MockCountingHeavyVoter {
        name: String,
        invocations: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ThreatVoter for MockCountingHeavyVoter {
        fn name(&self) -> String {
            self.name.clone()
        }
        fn is_heavy(&self) -> bool {
            true
        }
        async fn vote(&self, _event: &HostSecurityEvent) -> Option<VoteResult> {
            self.invocations
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Some(VoteResult {
                confidence: 0.95,
                reason: "Heavy voter detected high-risk activity".to_string(),
                weight: 2.0,
            })
        }
    }

    #[tokio::test]
    async fn test_m6_silent_mode_skips_heavy_voters_on_routine_noise() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let config = osoosi_types::PolicyConfig::default();
        let mut engine = PolicyEngine::new(memory, config);
        engine.telemetry_controller = Some(Arc::new(MockSilentController));

        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let heavy_voter = Box::new(MockCountingHeavyVoter {
            name: "MockHeavyLLM".to_string(),
            invocations: counter.clone(),
        });
        engine.add_voter(heavy_voter).await;

        // Routine event with no security/gateway flags
        let routine_event = osoosi_types::HostSecurityEvent {
            source: osoosi_types::HostEventSource::WindowsEventLog,
            event_id: 1,
            timestamp: Utc::now(),
            computer: "test-workstation".to_string(),
            data: serde_json::json!({
                "Image": "C:\\Windows\\System32\\whoami.exe",
                "CommandLine": "whoami.exe /groups",
                "ProcessId": 1234,
            }),
            causal_parent: None,
        };

        let verdict = engine.scan_event(&routine_event).await;
        // In silent mode on routine noise, heavy voter is skipped
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(verdict.is_none());
    }

    #[tokio::test]
    async fn test_m6_silent_mode_executes_100pct_voters_on_security_gateway_eval() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let config = osoosi_types::PolicyConfig::default();
        let mut engine = PolicyEngine::new(memory, config);
        engine.telemetry_controller = Some(Arc::new(MockSilentController));

        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let heavy_voter = Box::new(MockCountingHeavyVoter {
            name: "MockHeavyDecompiler".to_string(),
            invocations: counter.clone(),
        });
        engine.add_voter(heavy_voter).await;

        // Security/Gateway evaluation event with EnforceCedarGate
        let gateway_event = osoosi_types::HostSecurityEvent {
            source: osoosi_types::HostEventSource::WindowsEventLog,
            event_id: 1,
            timestamp: Utc::now(),
            computer: "test-workstation".to_string(),
            data: serde_json::json!({
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe /c curl https://malicious.c2",
                "ProcessId": 5678,
                "ProcessStartTime": 12345678901234u64,
                "EnforceCedarGate": true,
            }),
            causal_parent: None,
        };

        let verdict = engine.scan_event(&gateway_event).await;
        // Heavy voter MUST participate (100% quorum participation)
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(verdict.is_some());

        // Also verify engine.set_enforce_all_voters_participate(true) enforces 100% participation
        let counter2 = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let heavy_voter2 = Box::new(MockCountingHeavyVoter {
            name: "MockHeavyLLM2".to_string(),
            invocations: counter2.clone(),
        });
        let mut engine2 = PolicyEngine::new(Arc::new(MemoryStore::new(":memory:").unwrap()), osoosi_types::PolicyConfig::default());
        engine2.telemetry_controller = Some(Arc::new(MockSilentController));
        engine2.set_enforce_all_voters_participate(true);
        engine2.add_voter(heavy_voter2).await;

        let plain_event = osoosi_types::HostSecurityEvent {
            source: osoosi_types::HostEventSource::WindowsEventLog,
            event_id: 1,
            timestamp: Utc::now(),
            computer: "test-workstation".to_string(),
            data: serde_json::json!({
                "Image": "C:\\Windows\\System32\\whoami.exe",
                "CommandLine": "whoami.exe",
                "ProcessId": 9999,
            }),
            causal_parent: None,
        };
        let _ = engine2.scan_event(&plain_event).await;
        assert_eq!(counter2.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_m6_voter_quorum_alert_emitted_with_exact_basis_points() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let config = osoosi_types::PolicyConfig::default();
        let engine = PolicyEngine::new(memory, config);

        struct HighConfidenceVoter;
        #[async_trait::async_trait]
        impl ThreatVoter for HighConfidenceVoter {
            fn name(&self) -> String {
                "HighConfidenceDetector".to_string()
            }
            async fn vote(&self, _event: &HostSecurityEvent) -> Option<VoteResult> {
                Some(VoteResult {
                    confidence: 0.85,
                    reason: "Asymmetric Invariant Breakout Vector Detected".to_string(),
                    weight: 2.0,
                })
            }
        }
        engine.add_voter(Box::new(HighConfidenceVoter)).await;

        let alerts_received = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let sink_collector = alerts_received.clone();
        engine
            .set_voter_quorum_sink(Arc::new(move |alert| {
                let col = sink_collector.clone();
                tokio::spawn(async move {
                    col.lock().await.push(alert);
                });
            }))
            .await;

        let event = osoosi_types::HostSecurityEvent {
            source: osoosi_types::HostEventSource::WindowsEventLog,
            event_id: 1,
            timestamp: Utc::now(),
            computer: "test-workstation".to_string(),
            data: serde_json::json!({
                "Image": "C:\\Program Files\\Malware\\dropper.exe",
                "CommandLine": "dropper.exe --stage2",
                "ProcessId": 8812,
                "ProcessStartTime": 9876543210u64,
                "GatewayEvaluation": true,
            }),
            causal_parent: None,
        };

        let verdict = engine.scan_event(&event).await;
        assert!(verdict.is_some());
        let sig = verdict.unwrap();

        // Give async spawn small tick to flush sink
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let alerts = alerts_received.lock().await;
        assert_eq!(alerts.len(), 1);
        let alert = &alerts[0];
        assert_eq!(alert.target.pid, 8812);
        assert_eq!(alert.target.start_time_ticks, 9876543210);
        let expected_bp = (sig.confidence * 10_000.0).round() as u16;
        assert_eq!(alert.voter_confidence_bp, expected_bp);
        assert!(alert.voter_confidence_bp >= 6667);
        assert!(alert.trigger_reason.contains("Asymmetric Invariant Breakout Vector Detected"));
    }
}
